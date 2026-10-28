"""Adversarial continuity checks over newly constructed synthetic reports only."""

from __future__ import annotations

import copy
import json
import os
import subprocess
import sys

import pytest

from mobile_audit.core import canonical_json, digest
from mobile_audit.followup import MAX_OUTPUT_BYTES, assess_finding_followup


def pair():
    before = {
        "id": "synthetic-before",
        "target": "/synthetic/source",
        "tool_version": "1",
        "rule_version": "1",
        "inventory": {
            "input_kind": "source",
            "platforms": ["android"],
            "fingerprint": "a" * 64,
            "fingerprint_complete": True,
            "source_selection": {"module": "app"},
            "source_analysis": {"files": [{"path": "app/Probe.kt", "state": "checked"}]},
        },
        "coverage": [
            {"rule_id": "AST-PATH-TRAVERSAL", "state": "checked", "method": "source-ast-local-flow"}
        ],
        "findings": [
            {
                "id": "synthetic-finding",
                "rule_id": "AST-PATH-TRAVERSAL",
                "status": "candidate",
                "origin": "source-analysis",
                "evidence": [
                    {
                        "path": "app/Probe.kt",
                        "line": 3,
                        "function": "unpack",
                        "sink": "File",
                        "excerpt": "PRIVATE SYNTHETIC EXCERPT",
                    }
                ],
            }
        ],
    }
    after = copy.deepcopy(before)
    after.update(id="synthetic-after", findings=[])
    after["inventory"]["fingerprint"] = "b" * 64
    return before, after


def assess(before, after):
    return assess_finding_followup(before, after, before["findings"][0]["id"])


def test_complete_changed_source_absence_is_comparable_observation_not_remediation():
    before, after = pair()
    result = assess(before, after)
    assert result["comparability"]["state"] == "comparable"
    assert result["observation"]["state"] == "no-compatible-observation"
    assert result["build_pairing"]["state"] == "different-builds"
    assert result["remediation_proven"] is False
    assert result["comparability"]["execution_provenance"] == "not-established"


def test_multiple_evidence_locations_are_stable_across_process_hash_seeds():
    before, after = pair()
    paths = [f"app/Probe{index}.kt" for index in range(8)]
    before["findings"][0]["evidence"] = [{"path": path, "line": 3} for path in paths]
    for report in (before, after):
        report["inventory"]["source_analysis"]["files"] = [
            {"path": path, "state": "checked"} for path in paths
        ]
    script = (
        "import json,sys; from mobile_audit.followup import assess_finding_followup; "
        "from mobile_audit.core import canonical_json; a,b=json.load(sys.stdin); "
        "print(canonical_json(assess_finding_followup(a,b,a['findings'][0]['id'])))"
    )
    outputs = [
        subprocess.run(
            [sys.executable, "-c", script],
            input=json.dumps([before, after]),
            text=True,
            capture_output=True,
            check=True,
            env={**os.environ, "PYTHONHASHSEED": seed},
        ).stdout
        for seed in ("1", "2", "17")
    ]
    assert outputs[0] == outputs[1] == outputs[2]


@pytest.mark.parametrize("mutation", ["exact", "line", "offset", "other-file", "other-sink", "ambiguous"])
def test_exact_ids_and_semantic_continuity_are_distinct_and_ambiguity_is_retained(mutation):
    before, after = pair()
    item = copy.deepcopy(before["findings"][0])
    after["findings"] = [item]
    if mutation != "exact":
        item["id"] = "new-id"
    if mutation == "line":
        item["evidence"][0]["line"] = 103
    elif mutation == "offset":
        item["evidence"][0]["instruction_offset"] = 100
    elif mutation == "other-file":
        item["evidence"][0]["path"] = "other/Probe.kt"
    elif mutation == "other-sink":
        item["evidence"][0]["sink"] = "OtherFile"
    elif mutation == "ambiguous":
        after["findings"].append({**copy.deepcopy(item), "id": "second-id"})
    result = assess(before, after)
    expected = (
        "exact-id-observed"
        if mutation == "exact"
        else "same-rule-elsewhere"
        if mutation in {"other-file", "other-sink"}
        else "possible-continuation"
    )
    assert result["observation"]["state"] == expected
    assert result["observation"]["ambiguous"] is (mutation == "ambiguous")
    if mutation in {"ambiguous", "other-file", "other-sink"}:
        assert result["comparability"]["state"] == "limited"
    assert result["remediation_proven"] is False


def test_path_only_continuation_is_explicit_and_does_not_ignore_conflicting_anchors():
    before, after = pair()
    before["findings"][0]["evidence"] = [{"path": "app/Probe.kt", "line": 3}]
    after["findings"] = [{**copy.deepcopy(before["findings"][0]), "id": "new-id"}]
    after["findings"][0]["evidence"][0]["line"] = 30
    result = assess(before, after)
    assert result["observation"]["state"] == "possible-continuation"
    assert result["observation"]["candidates"][0]["match_basis"] == "path-only-unconfirmed"
    after["findings"][0]["evidence"][0]["function"] = "different"
    assert assess(before, after)["observation"]["state"] == "same-rule-elsewhere"


@pytest.mark.parametrize(
    "field,value", [("rule_id", "AST-SQL-CONCAT"), ("origin", "external"), ("scope", "environment")]
)
def test_same_id_never_overrides_rule_origin_or_scope(field, value):
    before, after = pair()
    after["findings"] = [{**copy.deepcopy(before["findings"][0]), field: value}]
    result = assess(before, after)
    assert result["observation"]["state"] == "no-compatible-observation"
    assert {"code": "finding-identity-conflict", "side": "after"} in result["comparability"]["blockers"]


@pytest.mark.parametrize("side", ["before", "after"])
@pytest.mark.parametrize(
    "mutation",
    [
        "partial",
        "no-coverage",
        "partial-coverage",
        "no-files",
        "skipped-file",
        "fingerprint",
        "incomplete-fingerprint",
        "no-version",
        "malformed-scope",
    ],
)
def test_missing_evidence_on_either_side_prevents_comparability(side, mutation):
    before, after = pair()
    report = before if side == "before" else after
    inventory = report["inventory"]
    if mutation == "partial":
        report["partial"] = True
    elif mutation == "no-coverage":
        report["coverage"] = []
    elif mutation == "partial-coverage":
        report["coverage"][0]["state"] = "partial"
    elif mutation == "no-files":
        inventory.pop("source_analysis")
    elif mutation == "skipped-file":
        inventory["source_analysis"]["files"][0]["state"] = "skipped"
    elif mutation == "fingerprint":
        inventory["fingerprint"] = "legacy"
    elif mutation == "incomplete-fingerprint":
        inventory["fingerprint_complete"] = 1
    elif mutation == "no-version":
        report.pop("tool_version")
    else:
        inventory["platforms"] = "android"
    result = assess(before, after)
    assert result["comparability"]["state"] == "limited"
    assert result["comparability"]["blockers"] and result["remediation_proven"] is False


@pytest.mark.parametrize("side", ["before", "after"])
@pytest.mark.parametrize("state", ["not-run", "failed", "partial", "not-applicable", None, False, []])
def test_explicit_global_source_state_cannot_override_checked_file_rows(side, state):
    before, after = pair()
    report = before if side == "before" else after
    report["inventory"]["source_analysis"]["state"] = state
    result = assess(before, after)
    assert result["comparability"]["state"] == "limited"
    assert {"code": "source-analysis-not-complete", "side": side} in result["comparability"]["blockers"]
    assert result["location_coverage"][side][0]["state"] == "not-covered"
    assert "complete-source-analysis" in result["next_steps"]


def test_explicit_checked_source_state_preserves_comparability():
    before, after = pair()
    for report in (before, after):
        report["inventory"]["source_analysis"]["state"] = "checked"
    assert assess(before, after)["comparability"]["state"] == "comparable"


@pytest.mark.parametrize("side", ["before", "after"])
@pytest.mark.parametrize("method", ["source-pattern", None, "", [], False])
def test_rule_analysis_method_drift_or_malformed_method_prevents_comparable_absence(side, method):
    before, after = pair()
    report = before if side == "before" else after
    report["coverage"][0]["method"] = method
    result = assess(before, after)
    assert result["comparability"]["state"] == "limited"
    assert {"code": "rule-method-differs", "side": "pair"} in result["comparability"]["blockers"]
    assert "align-and-document-rule-analysis-methods" in result["next_steps"]


def test_missing_method_on_both_sides_does_not_establish_method_compatibility():
    before, after = pair()
    for report in (before, after):
        report["coverage"][0].pop("method")
    result = assess(before, after)
    assert result["comparability"]["state"] == "limited"
    for side in ("before", "after"):
        assert {"code": "rule-method-unavailable", "side": side} in result["comparability"]["blockers"]


@pytest.mark.parametrize("side", ["before", "after"])
@pytest.mark.parametrize("value", [None, [], {}, "", 0])
@pytest.mark.parametrize(
    "path",
    [
        ("partial",),
        ("inventory", "partial"),
        ("inventory", "input_snapshot", "partial"),
        ("inventory", "input_snapshot", "app_scope_complete"),
        ("inventory", "input_snapshot", "hybrid_inputs_truncated"),
        ("inventory", "hybrid_inputs_truncated"),
        ("inventory", "hybrid_input_inventory_complete"),
        ("inventory", "source_analysis", "partial"),
        ("inventory", "source_analysis", "function_inventory_complete"),
        ("inventory", "source_analysis", "files", 0, "partial"),
        ("inventory", "hybrid_analysis", "input_observations_truncated"),
        ("coverage", 0, "function_inventory_complete"),
    ],
)
def test_falsey_malformed_completeness_flags_never_mean_complete(side, value, path):
    before, after = pair()
    holder = before if side == "before" else after
    for key in path[:-1]:
        if isinstance(holder, dict):
            holder = holder.setdefault(key, {})
        else:
            holder = holder[key]
    holder[path[-1]] = value
    result = assess(before, after)
    assert result["comparability"]["state"] == "limited"
    assert any(row["side"] == side for row in result["comparability"]["blockers"])
    assert result["remediation_proven"] is False


@pytest.mark.parametrize("side", ["before", "after"])
@pytest.mark.parametrize(
    "omitted",
    [
        None,
        [],
        "",
        False,
        {"app": {}},
        {"app": {"files": 0}},
        *[{"app": {"files": value, "bytes": 0}} for value in (None, False, "0", [], -1, 0.0)],
        *[{"app": {"files": 0, "bytes": value}} for value in (None, False, "0", [], -1, 0.0)],
    ],
)
def test_malformed_omission_objects_and_counters_fail_closed(side, omitted):
    before, after = pair()
    report = before if side == "before" else after
    report["inventory"]["input_snapshot"] = {"partial": False, "omitted": omitted}
    result = assess(before, after)
    assert result["comparability"]["state"] == "limited"
    assert {"code": "input-scope-incomplete", "side": side} in result["comparability"]["blockers"]


def test_producer_shaped_complete_snapshot_fields_remain_comparable():
    before, after = pair()
    for report in (before, after):
        report["partial"] = report["inventory"]["partial"] = False
        report["inventory"]["input_snapshot"] = {
            "partial": False,
            "app_scope_complete": True,
            "hybrid_input_inventory_complete": True,
            "hybrid_inputs_truncated": False,
            "omitted": {"app": {"files": 0, "bytes": 0}},
            "omitted_by_module": {},
            "omitted_module_groups": 0,
            "omitted_by_module_truncated": False,
            "omitted_other_modules": {},
        }
    assert assess(before, after)["comparability"]["state"] == "comparable"


@pytest.mark.parametrize(
    "container,key",
    [
        ("report", "analysis_specs"),
        ("report", "specs"),
        ("report", "spec_hash"),
        ("inventory", "analysis_specs"),
    ],
)
def test_fallback_scope_does_not_hide_other_declared_specifications(container, key):
    before, after = pair()
    for report in (before, after):
        report["inventory"]["project_specification"] = {"sha256": "c" * 64}
    (after if container == "report" else after["inventory"])[key] = "changed"
    result = assess(before, after)
    assert result["comparability"]["state"] == "limited"
    assert result["specification_pairing"]["state"] == "changed"


@pytest.mark.parametrize("kind", ["unknown", "external", "runtime", "intelligence", "apk"])
def test_unsupported_evidence_keeps_observations_but_never_interprets_absence(kind):
    before, after = pair()
    selected = before["findings"][0]
    if kind == "unknown":
        selected["rule_id"] = "AST-NOT-A-REAL-RULE"
    elif kind in {"external", "intelligence"}:
        selected["origin"] = kind
    elif kind == "runtime":
        selected["status"] = "runtime-confirmed"
        selected["evidence"][0]["runtime_id"] = "runtime-bound-to-prior-build"
    else:
        before["inventory"]["input_kind"] = "apk"
    after["findings"] = [copy.deepcopy(selected)]
    result = assess(before, after)
    assert result["observation"]["state"] == "exact-id-observed"
    assert result["comparability"]["state"] == "unsupported"
    assert result["remediation_proven"] is False


def test_configuration_coverage_alias_does_not_require_ast_manifest_record():
    before, after = pair()
    before["findings"][0].update(rule_id="ANDROID-DEBUG", evidence=[{"path": "AndroidManifest.xml"}])
    for report in (before, after):
        report["coverage"] = [{"rule_id": "ANDROID-CONFIG", "state": "checked", "method": "configuration"}]
        report["inventory"].pop("source_analysis")
        report["inventory"]["android_config"] = [{"path": "AndroidManifest.xml"}]
    assert assess(before, after)["comparability"]["state"] == "comparable"
    after["inventory"]["android_config"] = [{"path": "different/AndroidManifest.xml"}]
    assert assess(before, after)["comparability"]["state"] == "limited"
    after["inventory"]["android_config"] = None
    assert assess(before, after)["comparability"]["state"] == "limited"


@pytest.mark.parametrize("kind", ["privacy", "network-security"])
@pytest.mark.parametrize("observation", ["present", "absent"])
def test_real_producer_privacy_and_network_security_evidence_have_explicit_unsupported_loci(
    kind, observation
):
    from mobile_audit.platform_checks import _network_security_config, _privacy_manifest

    before, after = pair()
    inventory = before["inventory"]
    inventory.pop("source_analysis")
    if kind == "privacy":
        inventory["platforms"] = ["ios"]
        inventory["ios_config"] = [{"path": "Info.plist"}]
        findings, coverage = _privacy_manifest(inventory, [("App/Probe.swift", "UserDefaults.standard")])
        action = "validate-privacy-manifest-declarations-and-api-use"
        locus = "privacy-manifest-and-source"
    else:
        inventory["android_config"] = [
            {"path": "app/src/main/AndroidManifest.xml", "network_security_config": "@xml/network_security"}
        ]
        findings, coverage = _network_security_config(
            inventory,
            [
                (
                    "app/src/main/res/xml/network_security.xml",
                    '<network-security-config><base-config><trust-anchors><certificates src="user"/></trust-anchors></base-config></network-security-config>',
                )
            ],
        )
        action = "validate-resolved-network-security-resources"
        locus = "resolved-network-security-resource"
    assert len(findings) == 1
    before.update(findings=findings, coverage=coverage)
    after.update(
        inventory=copy.deepcopy(inventory),
        findings=copy.deepcopy(findings) if observation == "present" else [],
        coverage=copy.deepcopy(coverage),
    )
    result = assess(before, after)
    assert result["comparability"]["state"] == "unsupported"
    assert {"code": "unsupported-evidence-locus", "side": "before"} in result["comparability"]["blockers"]
    assert result["observation"]["state"] == (
        "exact-id-observed" if observation == "present" else "no-compatible-observation"
    )
    assert not any(
        row["code"] == "configuration-location-not-covered" for row in result["comparability"]["blockers"]
    )
    for side in ("before", "after"):
        assert result["location_coverage"][side][0] == {
            "path": findings[0]["evidence"][0]["path"],
            "state": "unsupported",
            "analysis": locus,
        }
    assert action in result["next_steps"]


@pytest.mark.parametrize(
    "key,value",
    [("input_snapshot", []), ("source_analysis", None), ("source_analysis", {"files": None}), ("apps", [{}])],
)
def test_malformed_nested_scope_is_reported_without_tracebacks(key, value):
    before, after = pair()
    after["inventory"][key] = value
    result = assess(before, after)
    assert result["comparability"]["state"] == "limited"
    assert result["remediation_proven"] is False


def test_portable_pairing_only_relaxes_target_for_identical_complete_source():
    before, after = pair()
    after["target"] = "/synthetic/relocated"
    assert (
        assess_finding_followup(before, after, "synthetic-finding", portable_inputs=True)["comparability"][
            "state"
        ]
        == "limited"
    )
    after["inventory"]["fingerprint"] = before["inventory"]["fingerprint"]
    result = assess_finding_followup(before, after, "synthetic-finding", portable_inputs=True)
    assert result["comparability"]["state"] == "comparable"
    assert result["path_pairing"]["normalized"] is True


def test_output_is_deterministic_content_addressed_and_excludes_excerpts_without_mutating_inputs():
    before, after = pair()
    unchanged = copy.deepcopy((before, after))
    first = assess(before, after)
    reordered = json.loads(json.dumps(before, sort_keys=True))
    assert assess(reordered, after) == first
    assert (before, after) == unchanged
    assert first["before"]["report_sha256"] == digest(canonical_json(before).encode())
    assert first["artifact_sha256"] == digest(
        canonical_json({key: value for key, value in first.items() if key != "artifact_sha256"}).encode()
    )
    assert "PRIVATE SYNTHETIC EXCERPT" not in canonical_json(first)
    after["unrelated_metadata"] = "new"
    assert assess(before, after)["artifact_sha256"] != first["artifact_sha256"]


def test_large_candidate_set_is_counted_before_bounding_and_never_becomes_absence():
    before, after = pair()
    after["findings"] = [
        {**copy.deepcopy(before["findings"][0]), "id": f"candidate-{index:04d}"} for index in range(2000)
    ]
    after["findings"][0]["evidence"][0]["function"] = "🧪" * 10000
    result = assess(before, after)
    assert result["observation"]["state"] == "possible-continuation"
    assert result["observation"]["candidate_count"] == 1999
    assert result["observation"]["ambiguous"] and result["observation"]["truncated"]
    assert result["omissions"]["candidates"] > 0
    assert len(canonical_json(result).encode()) <= MAX_OUTPUT_BYTES


def test_oversized_numeric_metadata_is_bounded_without_depending_on_interpreter_digit_limit():
    before, after = pair()
    script = (
        "import json,sys; from mobile_audit.followup import assess_finding_followup; "
        "sys.set_int_max_str_digits(0); a,b=json.load(sys.stdin); "
        "a['findings'][0]['evidence'][0]['line']=10**70000; "
        "r=assess_finding_followup(a,b,a['findings'][0]['id']); "
        "print(json.dumps(r))"
    )
    completed = subprocess.run(
        [sys.executable, "-c", script],
        input=json.dumps([before, after]),
        text=True,
        capture_output=True,
        check=True,
        timeout=10,
    )
    result = json.loads(completed.stdout)
    assert result["selected_finding"]["evidence"][0]["line"] is None
    assert result["omissions"]["metadata_fields"] == 1
    assert len(canonical_json(result).encode()) <= MAX_OUTPUT_BYTES


def test_invalid_numeric_severity_fails_before_output_projection():
    before, after = pair()
    before["findings"][0]["severity"] = 12
    with pytest.raises(ValueError, match="severity"):
        assess(before, after)


def test_output_bounding_fails_if_no_remaining_metadata_can_be_removed(monkeypatch):
    import mobile_audit.followup as followup

    monkeypatch.setattr(followup, "MAX_OUTPUT_BYTES", 100)
    with pytest.raises(ValueError, match="output byte limit"):
        assess(*pair())


@pytest.mark.parametrize("mutation", ["duplicate-before", "duplicate-after", "missing", "evidence", "nan"])
def test_structurally_invalid_inputs_fail_with_value_error(mutation):
    before, after = pair()
    if mutation == "duplicate-before":
        before["findings"] *= 2
    elif mutation == "duplicate-after":
        after["findings"] = before["findings"] * 2
    elif mutation == "missing":
        before["findings"] = []
    elif mutation == "evidence":
        before["findings"][0]["evidence"] = "bad"
    else:
        after["number"] = float("nan")
    with pytest.raises(ValueError):
        assess_finding_followup(before, after, "synthetic-finding")
