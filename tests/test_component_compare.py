"""Malformed tool output must never silently become a benchmark true negative."""

import hashlib
import json
from collections import Counter
from itertools import permutations
from pathlib import Path

import httpx
import pytest

from benchmarks.component_cases import dependency_cases, generate, secret_cases
from benchmarks.component_compare import (
    _version_matches,
    apsa_secrets,
    parse_apsa_osv,
    parse_gitleaks,
    parse_osv,
    score,
    summarize,
    verify_source_manifest,
)
from mobile_audit.intel import _normalize_osv, query_dependencies


def _execution(status=0, **changes):
    return {"status": status, "incomplete": False, "stdout": "", "stderr": "", **changes}


def _osv(case, vulnerabilities=None):
    return {
        "results": [
            {
                "source": {"path": "bom.json", "type": "sbom"},
                "packages": [{"package": case["coordinate"], "vulnerabilities": vulnerabilities or []}],
            }
        ]
    }


@pytest.mark.parametrize("status", [1, 2, 10, 127, 128, 129, 130, -9])
def test_gitleaks_errors_never_true_negative(status):
    case = secret_cases()[1]
    observation = parse_gitleaks(_execution(status), "[]", case, Path("/fresh/Probe.kt"))
    assert observation["state"] == "failed"
    assert score(False, observation) is None


@pytest.mark.parametrize(
    "raw",
    [
        None,
        "",
        "[",
        "{}",
        "null",
        "[null]",
        '[{"RuleID":"github-pat","File":"elsewhere.kt","StartLine":2}]',
        '[{"RuleID":"github-pat","File":"Probe.kt","StartLine":true}]',
    ],
)
def test_gitleaks_malformed_never_true_negative(raw):
    observation = parse_gitleaks(_execution(10), raw, secret_cases()[1], Path("/fresh/Probe.kt"))
    assert score(False, observation) is None


def test_gitleaks_exact_rule_path_line_and_exit_required():
    case = secret_cases()[2]
    hit = {"RuleID": "github-pat", "File": "/fresh/Probe.kt", "StartLine": 2, "Secret": "REDACTED"}
    observation = parse_gitleaks(_execution(10), json.dumps([hit]), case, Path("/fresh/Probe.kt"))
    assert score(True, observation) == "TP"
    hit["RuleID"] = "unrelated-rule"
    observation = parse_gitleaks(_execution(10), json.dumps([hit]), case, Path("/fresh/Probe.kt"))
    assert score(True, observation) == "FN"
    assert observation["other_findings"]


@pytest.mark.parametrize("status", [2, 10, 127, 128, 129, 130, -9])
def test_osv_failure_status_never_true_negative(status):
    case = dependency_cases()[1]
    observation = parse_osv(_execution(status, stdout=json.dumps(_osv(case))), case, Path("/fresh/bom.json"))
    assert score(False, observation) is None


@pytest.mark.parametrize(
    "raw", ["", "{", "null", "[]", "{}", '{"results":[]}', '{"results":[{}]}', '{"results":[null]}']
)
def test_osv_missing_malformed_or_empty_inventory_never_true_negative(raw):
    case = dependency_cases()[1]
    assert score(False, parse_osv(_execution(stdout=raw), case, Path("/fresh/bom.json"))) is None


@pytest.mark.parametrize(
    "mutation",
    ["coordinate", "source", "packages", "aliases", "vulnerability", "exit", "stderr", "truncated"],
)
def test_osv_invalid_completion_never_true_negative(mutation):
    case = dependency_cases()[1]
    body = _osv(case)
    execution = _execution()
    if mutation == "coordinate":
        body["results"][0]["packages"][0]["package"] = {**case["coordinate"], "version": "0"}
    elif mutation == "source":
        body["results"][0]["source"]["path"] = "/different/bom.json"
    elif mutation == "packages":
        body["results"][0]["packages"] = []
    elif mutation in ("aliases", "vulnerability"):
        body["results"][0]["packages"][0]["vulnerabilities"] = (
            [{"id": "GHSA-synthetic", "aliases": None}] if mutation == "aliases" else [None]
        )
    elif mutation == "exit":
        execution["status"] = 1
    elif mutation == "stderr":
        execution["stderr"] = "ERROR: public feed failed"
    else:
        execution["incomplete"] = True
    execution["stdout"] = json.dumps(body)
    assert score(False, parse_osv(execution, case, Path("/fresh/bom.json"))) is None


def test_osv_target_specific_scoring_preserves_other_advisories():
    case = dependency_cases()[1]
    body = _osv(case, [{"id": "GHSA-unrelated", "aliases": ["CVE-2099-0001"]}])
    observation = parse_osv(_execution(1, stdout=json.dumps(body)), case, Path("/fresh/bom.json"))
    assert score(False, observation) == "TN"
    assert observation["other_findings"] == ["GHSA-unrelated"]
    assert observation["records"][0]["secondary_ids"] == ["CVE-2099-0001"]
    body["results"][0]["packages"][0]["vulnerabilities"].append({"id": case["target_advisories"][0]})
    assert (
        score(False, parse_osv(_execution(1, stdout=json.dumps(body)), case, Path("/fresh/bom.json"))) == "FP"
    )


def test_fresh_cases_predeclare_scope_and_apsa_matches_exact_lines(tmp_path):
    cases = generate(tmp_path / "inputs")
    assert len(cases) == 16
    for case in cases:
        assert "content" not in case and len(case["sha256"]) == 64
        if case["kind"] == "secret":
            observation = apsa_secrets(case, tmp_path / "inputs" / case["id"] / case["path"])
            assert score(case["expected"], observation) == ("TP" if case["expected"] else "TN")
    with pytest.raises(FileExistsError):
        generate(tmp_path / "inputs")


def test_original_secret_inputs_and_labels_remain_frozen():
    hashes = {
        "secret-aws-present": "9d2ea5f158879c21e0aa342854cf52c7d4a812fa99c0284155242543e40ca3a0",
        "secret-aws-absent": "99450274464352fd0d749487ff3733416f164cd90832cc153c7aa2643f0725dd",
        "secret-github-present": "6cfd4ea7dec13bd8a56966c415f7685d5b248c860ab5e42b84316ea343ff9f6a",
        "secret-github-absent": "1b5b88d01666145ce5b41a6f013345c72ef79e247f4117c0695b56263b2bdc9c",
        "secret-slack-present": "6b7395bfe7a61bff16f31e8d9235212fba3c51b6d4befa70dc4979a7ca3ad56b",
        "secret-slack-absent": "676bfbb68ca57fcf8e55eed3285025b68f4b5ae2d5c5a05dc6acdc59adadae7a",
        "secret-stripe-present": "5be9e47ed743651ca5f75774372f594bd03110e3551bb062b7e939bf5dd4c61e",
        "secret-stripe-absent": "c3a21808fb2e271310597444a82235c5e03fb8c3d8d44148c51e60448be79422",
    }
    originals = secret_cases()[:8]
    assert [case["id"] for case in originals] == list(hashes)
    for case in originals:
        assert hashlib.sha256(case["content"].encode()).hexdigest() == hashes[case["id"]]
        assert case["expected"] is case["id"].endswith("-present")


@pytest.mark.parametrize("provider", ["aws", "github", "slack", "stripe"])
def test_permuted_secret_negatives_preserve_character_frequencies(provider):
    cases = {case["id"]: case for case in secret_cases()}
    positive = cases[f"secret-{provider}-present"]
    negative = cases[f"secret-{provider}-prefix-permuted"]
    assert positive["content"] != negative["content"]
    assert len(positive["content"]) == len(negative["content"])
    assert Counter(positive["content"]) == Counter(negative["content"])
    assert positive["expected"] is True and negative["expected"] is False
    assert positive["supported"] == negative["supported"]


def test_unstable_and_partial_cases_are_excluded_not_averaged():
    values = []
    for repetition, detected in enumerate((True, False, True)):
        observation = {"state": "completed", "detected": detected, "matched": []}
        values.append(
            {
                "case": "pair",
                "tool": "tool",
                "observation": observation,
                "classification": score(True, observation),
                "repetition": repetition,
            }
        )
    result = summarize(values, 3)["tool"]
    assert not result["stable"] and result["excluded_cases"] == 1
    assert not any(result["case_counts"].values())


@pytest.mark.parametrize(
    "indices",
    [
        [0, 0, 0],
        [0, 1, 1],
        [0, 1],
        [0, 1, 3],
        [-1, 0, 1],
        [0, 1, True],
        [0, 1, "2"],
        [0, 1, None],
        [0, 1, []],
        [0, 1, 2, 2],
    ],
)
def test_repetition_identity_not_just_trial_count_is_required(indices):
    trials = [
        {
            "tool": "synthetic",
            "case": "control",
            "repetition": index,
            "observation": {"state": "completed", "detected": False},
            "classification": "TN",
        }
        for index in indices
    ]
    result = summarize(trials, 3)["synthetic"]
    assert result["case_repetition_complete"] == {"control": False}
    assert not result["stable"] and result["excluded_cases"] == 1
    assert not any(result["case_counts"].values())


def test_unique_repetitions_may_arrive_in_any_order():
    trials = [
        {
            "tool": "synthetic",
            "case": "control",
            "repetition": index,
            "observation": {"state": "completed", "detected": False},
            "classification": "TN",
        }
        for index in (2, 0, 1)
    ]
    result = summarize(trials, 3)["synthetic"]
    assert result["case_repetition_complete"] == {"control": True}
    assert result["stable"] and result["excluded_cases"] == 0
    assert result["case_counts"]["TN"] == 1


@pytest.mark.parametrize("state", ["partial", "error", "not-checked", "cached", "excluded", "unsupported"])
def test_apsa_nontransmitted_or_incomplete_query_never_true_negative(state):
    case = dependency_cases()[1]
    states = [{**case["coordinate"], "state": state, "checked": True, "transmitted": True}]
    assert score(False, parse_apsa_osv(case, [], [], states)) is None


@pytest.mark.parametrize("mutation", ["coordinate", "checked", "transmitted", "missing", "finding", "errors"])
def test_apsa_live_completion_bound_to_exact_coordinate(mutation):
    case = dependency_cases()[1]
    states = [{**case["coordinate"], "state": "complete", "checked": True, "transmitted": True}]
    findings, errors = [], []
    if mutation == "coordinate":
        states[0]["version"] = "0"
    elif mutation in {"checked", "transmitted"}:
        states[0][mutation] = False
    elif mutation == "missing":
        states = []
    elif mutation == "finding":
        findings = [{"id": "unexpected", "osv_id": "unexpected", "query_match": {}}]
    else:
        errors = ["feed incomplete"]
    assert score(False, parse_apsa_osv(case, findings, errors, states)) is None


@pytest.mark.parametrize(
    "tool,valid,invalid",
    [
        ("gitleaks", "8.30.1\n", "8.30.10\n"),
        (
            "osv-scanner",
            "osv-scanner version: 2.7.0\ncommit: synthetic\n",
            "osv-scanner version: 2.7.0-dev\n",
        ),
    ],
)
def test_binary_version_is_exact(tool, valid, invalid):
    assert _version_matches(tool, valid)
    assert not _version_matches(tool, invalid)


@pytest.mark.parametrize(
    "manifest",
    [
        {},
        {"source_commit": "not-a-commit"},
        {"source_commit": "a" * 40, "source_sha256": {}},
        {"source_commit": "a" * 40, "source_sha256": {"../outside.py": "b" * 64}},
    ],
)
def test_source_binding_fails_before_any_tool_execution(manifest, tmp_path, monkeypatch):
    monkeypatch.delenv("GITHUB_SHA", raising=False)
    with pytest.raises(ValueError):
        verify_source_manifest(manifest, tmp_path)


@pytest.mark.parametrize("apsa", [False, True])
def test_shared_alias_with_different_primary_is_ambiguous_not_false_positive_or_negative(apsa):
    case = dependency_cases()[3]
    other = "GHSA-r5fr-rjxr-66jc"
    affected = [
        {
            "package": {"name": "lodash", "ecosystem": "npm"},
            "ranges": [{"type": "SEMVER", "events": [{"introduced": "4.0.0"}, {"fixed": "4.18.0"}]}],
        }
    ]
    if apsa:
        findings = [
            {
                "id": "CVE-2021-23337",
                "osv_id": other,
                "aliases": ["CVE-2021-23337"],
                "query_match": case["coordinate"],
                "affected": affected,
            }
        ]
        states = [{**case["coordinate"], "state": "complete", "checked": True, "transmitted": True}]
        observation = parse_apsa_osv(case, findings, [], states)
    else:
        findings = [
            {
                "id": other,
                "aliases": ["CVE-2021-23337", "CVE-2026-4800", case["target_record_id"]],
                "affected": affected,
            }
        ]
        observation = parse_osv(
            _execution(1, stdout=json.dumps(_osv(case, findings))), case, Path("/fresh/bom.json")
        )
    assert observation["state"] == "ambiguous"
    assert observation["detected"] is None and observation["matched"] == []
    assert score(False, observation) is None and score(True, observation) is None
    assert observation["other_findings"] == [other]
    assert observation["alias_overlaps"][0]["primary_id"] == other
    assert observation["records"][0]["affected_package_ranges"][0]["ranges"] == affected[0]["ranges"]


@pytest.mark.parametrize("apsa", [False, True])
@pytest.mark.parametrize("primary", [None, "", [], "invalid id"])
def test_missing_or_malformed_primary_never_falls_back_to_alias(apsa, primary):
    case = dependency_cases()[3]
    if apsa:
        findings = [
            {"id": case["target_advisories"][1], "osv_id": primary, "query_match": case["coordinate"]}
        ]
        states = [{**case["coordinate"], "state": "complete", "checked": True, "transmitted": True}]
        observation = parse_apsa_osv(case, findings, [], states)
    else:
        findings = [{"id": primary, "aliases": case["target_advisories"]}]
        observation = parse_osv(
            _execution(1, stdout=json.dumps(_osv(case, findings))), case, Path("/fresh/bom.json")
        )
    assert observation["state"] == "failed"
    assert score(False, observation) is None


@pytest.mark.parametrize("apsa", [False, True])
def test_conflicting_duplicate_primary_fails_closed(apsa):
    case = dependency_cases()[0]
    if apsa:
        first = {
            "id": case["target_advisories"][1],
            "osv_id": case["target_record_id"],
            "aliases": case["target_advisories"][1:],
            "query_match": case["coordinate"],
        }
        second = {**first, "id": "CVE-2099-0001"}
        states = [{**case["coordinate"], "state": "complete", "checked": True, "transmitted": True}]
        observation = parse_apsa_osv(case, [first, second], [], states)
    else:
        first = {"id": case["target_record_id"], "aliases": case["target_advisories"][1:]}
        second = {**first, "aliases": ["CVE-2099-0001"]}
        observation = parse_osv(
            _execution(1, stdout=json.dumps(_osv(case, [first, second]))), case, Path("/fresh/bom.json")
        )
    assert observation["state"] == "failed"
    assert score(True, observation) is None


def test_exact_primary_hit_is_retained_with_different_record_alias_overlap():
    case = dependency_cases()[2]
    records = [
        {"id": case["target_record_id"]},
        {"id": "GHSA-r5fr-rjxr-66jc", "aliases": case["target_advisories"]},
    ]
    observation = parse_osv(
        _execution(1, stdout=json.dumps(_osv(case, records))), case, Path("/fresh/bom.json")
    )
    assert score(True, observation) == "TP"
    assert observation["matched"] == [case["target_record_id"]]
    assert observation["alias_overlaps"] and len(observation["records"]) == 2


@pytest.mark.parametrize("apsa", [False, True])
def test_target_alias_as_other_primary_is_ambiguous_without_secondary_aliases(apsa):
    case = dependency_cases()[3]
    alias = case["target_advisories"][1]
    assert alias != case["target_record_id"]
    if apsa:
        findings = [{"id": alias, "osv_id": alias, "aliases": [], "query_match": case["coordinate"]}]
        states = [{**case["coordinate"], "state": "complete", "checked": True, "transmitted": True}]
        observation = parse_apsa_osv(case, findings, [], states)
    else:
        findings = [{"id": alias, "aliases": []}]
        observation = parse_osv(
            _execution(1, stdout=json.dumps(_osv(case, findings))), case, Path("/fresh/bom.json")
        )
    assert observation["state"] == "ambiguous"
    assert observation["detected"] is None and observation["matched"] == []
    assert score(False, observation) is None and score(True, observation) is None
    assert observation["other_findings"] == [alias]
    assert observation["alias_overlaps"] == [{"primary_id": alias, "overlapping_identifiers": [alias]}]
    assert observation["records"][0]["secondary_ids"] == []


@pytest.mark.parametrize(
    "aliases",
    [list(items) for items in permutations(["CVE-2099-0001", "GHSA-35jh-r3h4-6jhm", "CVE-2021-23337"])]
    + [["GHSA-35jh-r3h4-6jhm"]],
)
def test_live_normalization_preserves_later_and_ghsa_only_alias_overlap(store, aliases):
    case = dependency_cases()[3]
    raw = {"id": "GHSA-other-record", "aliases": aliases}
    states = []
    with httpx.Client(
        transport=httpx.MockTransport(lambda request: httpx.Response(200, json={"vulns": [raw]}))
    ) as client:
        findings, errors = query_dependencies(
            store,
            [{**case["coordinate"], "confidence": "exact"}],
            client,
            query_mode="legacy",
            package_states=states,
        )
    assert not errors and findings[0]["aliases"] == aliases
    assert findings[0]["osv_id"] == raw["id"]
    assert findings[0]["id"] == min(
        (alias for alias in aliases if alias.startswith("CVE-")), default=raw["id"]
    )
    apsa = parse_apsa_osv(case, findings, errors, states)
    scanner = parse_osv(_execution(1, stdout=json.dumps(_osv(case, [raw]))), case, Path("/fresh/bom.json"))
    assert apsa["state"] == scanner["state"] == "ambiguous"
    assert apsa["alias_overlaps"] == scanner["alias_overlaps"]
    assert apsa["records"][0]["secondary_ids"] == scanner["records"][0]["secondary_ids"]
    assert score(False, apsa) is None and score(False, scanner) is None
    assert store.intel_by_id(findings[0]["id"])[0]["aliases"] == aliases


@pytest.mark.parametrize("aliases", [None, "CVE-2021-23337", [None], [7], [""], ["bad alias"]])
def test_malformed_alias_metadata_never_establishes_clean_result(aliases):
    case = dependency_cases()[3]
    raw = {"id": "GHSA-other-record", "aliases": aliases}
    with pytest.raises(ValueError):
        _normalize_osv(raw, case["coordinate"])
    finding = {
        "id": "CVE-2099-0001",
        "osv_id": raw["id"],
        "aliases": aliases,
        "query_match": case["coordinate"],
    }
    states = [{**case["coordinate"], "state": "complete", "checked": True, "transmitted": True}]
    assert score(False, parse_apsa_osv(case, [finding], [], states)) is None
    scanner = parse_osv(_execution(1, stdout=json.dumps(_osv(case, [raw]))), case, Path("/fresh/bom.json"))
    assert score(False, scanner) is None


def test_legacy_normalized_record_without_alias_metadata_is_incomplete():
    case = dependency_cases()[3]
    finding = {"id": "CVE-2099-0001", "osv_id": "GHSA-other-record", "query_match": case["coordinate"]}
    states = [{**case["coordinate"], "state": "complete", "checked": True, "transmitted": True}]
    observation = parse_apsa_osv(case, [finding], [], states)
    assert observation["state"] == "partial"
    assert "unavailable" in observation["reason"]
    assert score(False, observation) is None


def test_normalized_exact_primary_remains_positive_without_aliases():
    case = dependency_cases()[2]
    raw = {"id": case["target_record_id"]}
    normalized = _normalize_osv(raw, case["coordinate"])
    assert normalized["aliases"] == []
    states = [{**case["coordinate"], "state": "complete", "checked": True, "transmitted": True}]
    observation = parse_apsa_osv(case, [normalized], [], states)
    assert score(True, observation) == "TP"
    assert observation["matched"] == [case["target_record_id"]]


def test_apsa_display_id_remains_in_overlap_evidence():
    case = dependency_cases()[3]
    finding = {
        "id": case["target_advisories"][1],
        "osv_id": "GHSA-other-record",
        "aliases": [],
        "query_match": case["coordinate"],
    }
    states = [{**case["coordinate"], "state": "complete", "checked": True, "transmitted": True}]
    observation = parse_apsa_osv(case, [finding], [], states)
    assert observation["state"] == "ambiguous"
    assert observation["records"][0]["secondary_ids"] == [case["target_advisories"][1]]
