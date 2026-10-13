"""Malformed tool output must never silently become a benchmark true negative."""

import json
from pathlib import Path

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
    assert observation["other_findings"] == ["CVE-2099-0001", "GHSA-unrelated"]
    body["results"][0]["packages"][0]["vulnerabilities"].append({"id": case["target_advisories"][0]})
    assert (
        score(False, parse_osv(_execution(1, stdout=json.dumps(body)), case, Path("/fresh/bom.json"))) == "FP"
    )


def test_fresh_cases_predeclare_scope_and_apsa_matches_exact_lines(tmp_path):
    cases = generate(tmp_path / "inputs")
    assert len(cases) == 12
    for case in cases:
        assert "content" not in case and len(case["sha256"]) == 64
        if case["kind"] == "secret":
            observation = apsa_secrets(case, tmp_path / "inputs" / case["id"] / case["path"])
            assert score(case["expected"], observation) == ("TP" if case["expected"] else "TN")
    with pytest.raises(FileExistsError):
        generate(tmp_path / "inputs")


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
