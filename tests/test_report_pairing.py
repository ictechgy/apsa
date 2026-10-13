"""Fresh synthetic source/report pairs; no retained inputs or live runtime."""

from __future__ import annotations

import ast
import copy
import hashlib
import json
from contextlib import contextmanager
from pathlib import Path
from typing import Any

import pytest

from mobile_audit.audit import compare
from mobile_audit.cli import main
from mobile_audit.core import canonical_json, digest
from mobile_audit.verify import compare_reports


def report_pair():
    fingerprint = hashlib.sha256(b"new synthetic canonical source bytes").hexdigest()
    before = {
        "id": "new-before",
        "created": "2026-10-12T00:00:00Z",
        "target": "/new-synthetic/first/source",
        "tool_version": "synthetic-version",
        "rule_version": "synthetic-rules",
        "partial": False,
        "inventory": {
            "input_kind": "source",
            "platforms": ["android"],
            "package": "synthetic.app",
            "apps": [{"platform": "android", "package": "synthetic.app"}],
            "fingerprint": fingerprint,
            "fingerprint_complete": True,
            "partial": False,
            "source_selection": {"module": "app"},
            "project_specification": {"sha256": "a" * 64},
            "input_snapshot": {"partial": False, "app_scope_complete": True},
        },
        "coverage": [{"rule_id": "AST-PATH-TRAVERSAL", "state": "checked"}],
        "findings": [
            {
                "id": "new-finding",
                "rule_id": "AST-PATH-TRAVERSAL",
                "status": "candidate",
                "severity": "medium",
                "evidence": [{"path": "app/Probe.kt", "line": 3}],
            }
        ],
        "runtime": [],
    }
    after = copy.deepcopy(before)
    after.update(id="new-after", target="/new-synthetic/relocated/source", findings=[])
    return before, after


def assert_not_normalized(before, after):
    result = compare_reports(before, after, portable_inputs=True)
    assert result["scope_pairing"]["state"] != "unchanged"
    assert result["normalization_basis"] == "none" and not result["path_pairing"]["normalized"]
    assert result["finding_transitions"][0]["verification"] == "inconclusive"
    assert result["scope_pairing"]["before_sha256"] == result["scope_pairing"]["comparison_before_sha256"]
    assert result["scope_pairing"]["after_sha256"] == result["scope_pairing"]["comparison_after_sha256"]
    return result


def test_portable_source_pairing_is_explicit_and_retains_original_targets_and_hashes():
    before, after = report_pair()
    snapshots = copy.deepcopy((before, after))
    strict = compare_reports(before, after)
    assert strict["scope_pairing"]["state"] == "changed"
    assert strict["finding_transitions"][0]["verification"] == "inconclusive"
    result = compare_reports(before, after, portable_inputs=True)
    scope = result["scope_pairing"]
    assert scope["state"] == "unchanged" and scope["original_state"] == "changed"
    assert scope["normalized_fields"] == ["target"]
    assert result["path_pairing"]["state"] == "portable-source-target"
    assert result["normalization_basis"] == "identical-complete-canonical-source-sha256"
    assert result["path_pairing"]["before_target"] == scope["before"]["target"] == before["target"]
    assert result["path_pairing"]["after_target"] == scope["after"]["target"] == after["target"]
    assert scope["before_sha256"] == digest(canonical_json(scope["before"]).encode())
    assert scope["after_sha256"] == digest(canonical_json(scope["after"]).encode())
    assert scope["before_sha256"] != scope["after_sha256"]
    assert scope["comparison_before_sha256"] == scope["comparison_after_sha256"]
    assert result["build_pairing"]["state"] == "same-build"
    assert result["finding_transitions"][0]["observation"] == "no-longer-observed"
    assert result["finding_transitions"][0]["verification"] == "comparable-observation"
    assert "not proof of remediation" in result["note"]
    assert (before, after) == snapshots


def test_relocated_changed_source_content_stays_inconclusive():
    before, after = report_pair()
    after["inventory"]["fingerprint"] = hashlib.sha256(b"new changed source content").hexdigest()
    result = assert_not_normalized(before, after)
    assert result["build_pairing"]["state"] == "different-builds"
    assert "fingerprints differ" in result["path_pairing"]["reason"]


@pytest.mark.parametrize(
    "holder,field,value",
    [
        ("report", "tool_version", "another-version"),
        ("report", "rule_version", "another-rule-version"),
        ("inventory", "input_kind", "apk"),
        ("inventory", "platforms", ["ios"]),
        ("inventory", "apps", [{"platform": "android", "package": "other.app"}]),
        ("inventory", "apps", [{"platform": "android", "package": "synthetic.app", "version": "other"}]),
        ("inventory", "package", "other.app"),
        ("inventory", "source_selection", {"module": "other-module"}),
        ("inventory", "project_specification", {"sha256": "b" * 64}),
        ("inventory", "analysis_specs", {"sources": ["other-source"]}),
        ("report", "spec_hash", "b" * 64),
        ("report", "specs", {"sources": ["other-source"]}),
        ("report", "analysis_specs", {"sources": ["other-source"]}),
        ("report", "coverage", [{"rule_id": "OTHER-RULE", "state": "checked"}]),
    ],
)
def test_portable_pairing_cannot_normalize_any_other_scope(holder, field, value):
    before, after = report_pair()
    (after if holder == "report" else after["inventory"])[field] = value
    assert_not_normalized(before, after)


@pytest.mark.parametrize("fingerprint", [None, "", "legacy-input", "0" * 63, "g" * 64, "A" * 64, 1])
def test_missing_and_noncanonical_fingerprints_do_not_authorize_normalization(fingerprint):
    before, after = report_pair()
    before["inventory"]["fingerprint"] = after["inventory"]["fingerprint"] = fingerprint
    assert_not_normalized(before, after)


@pytest.mark.parametrize("complete", [None, False, 1, "true"])
def test_fingerprint_completeness_must_be_exactly_true(complete):
    before, after = report_pair()
    after["inventory"]["fingerprint_complete"] = complete
    assert_not_normalized(before, after)


@pytest.mark.parametrize(
    "partial",
    [
        {"partial": True},
        {"inventory": {"partial": True}},
        {"inventory": {"input_snapshot": {"partial": True}}},
        {"inventory": {"input_snapshot": {"app_scope_complete": False}}},
        {"inventory": {"source_analysis": {"partial": True}}},
        {"inventory": {"source_analysis": {"files": [{"state": "partial"}]}}},
        {"inventory": {"hybrid_analysis": {"files": [{"state": "partial"}]}}},
        {"coverage": [{"rule_id": "AST-PATH-TRAVERSAL", "state": "partial"}]},
    ],
)
def test_partial_source_or_input_scopes_cannot_be_portable(partial):
    before, after = report_pair()
    if "inventory" in partial:
        after["inventory"].update(partial["inventory"])
    else:
        after.update(partial)
    assert_not_normalized(before, after)


@pytest.mark.parametrize("kind", ["apk", "aab", "apks", "ipa"])
def test_binary_pairing_remains_strict_even_with_identical_complete_hash(kind):
    before, after = report_pair()
    before["inventory"]["input_kind"] = after["inventory"]["input_kind"] = kind
    assert_not_normalized(before, after)


def test_compiled_app_bundle_cannot_use_source_kind_to_normalize_target():
    before, after = report_pair()
    before["target"] += ".app"
    after["target"] += ".app"
    assert_not_normalized(before, after)


@pytest.mark.parametrize("target", ["relative/source", "", None])
def test_only_absolute_targets_are_eligible(target):
    before, after = report_pair()
    after["target"] = target
    assert_not_normalized(before, after)


def test_same_path_revisions_retain_default_behavior_without_normalization():
    before, after = report_pair()
    after["target"] = before["target"]
    after["inventory"]["fingerprint"] = "legacy-different-input"
    for portable in (False, True):
        result = compare_reports(before, after, portable_inputs=portable)
        assert result["scope_pairing"]["state"] == "unchanged"
        assert result["build_pairing"]["state"] == "different-builds"
        assert result["path_pairing"]["state"] == "exact-target" and not result["path_pairing"]["normalized"]
        assert result["normalization_basis"] == "none"


@pytest.mark.parametrize("side", ["before", "after"])
@pytest.mark.parametrize("portable", [False, True])
@pytest.mark.parametrize(
    "partial_inventory",
    [
        {"partial": True},
        {"input_snapshot": {"partial": True}},
        {"input_snapshot": {"app_scope_complete": False}},
        {"source_analysis": {"partial": True}},
        {"source_analysis": "malformed"},
        {"source_analysis": {"files": [{"state": "partial"}]}},
        {"hybrid_analysis": {"files": [{"state": "partial"}]}},
        {"hybrid_inputs_truncated": True},
        {"hybrid_input_inventory_complete": False},
    ],
)
def test_same_target_partial_analysis_cannot_verify_finding_disappearance(side, portable, partial_inventory):
    before, after = report_pair()
    after["target"] = before["target"]
    (before if side == "before" else after)["inventory"].update(partial_inventory)
    snapshots = copy.deepcopy((before, after))

    result = compare_reports(before, after, portable_inputs=portable)

    assert result["scope_pairing"]["state"] == "unchanged"
    assert result["path_pairing"]["state"] == "exact-target"
    transition = result["finding_transitions"][0]
    assert transition["observation"] == "no-longer-observed"
    assert transition["verification"] == "inconclusive"
    assert "not proof of remediation" in result["note"]
    assert (before, after) == snapshots


def runtime_record(identifier):
    return {
        "id": identifier,
        "partial": False,
        "scenario_scope": "scenario-scope",
        "scenario_identity": "assertion-identity",
        "assertions": [],
        "app_binding": {"state": "bound", "identity": "1" * 64},
    }


def test_portable_source_pairing_never_normalizes_runtime_target_binding():
    before, after = report_pair()
    before["runtime"] = [runtime_record("new-runtime-before")]
    after["runtime"] = [*copy.deepcopy(before["runtime"]), runtime_record("new-runtime-after")]
    result = compare_reports(before, after, portable_inputs=True)
    assert result["scope_pairing"]["state"] == "unchanged"
    assert result["runtime_pairs"][0]["verification"] == "inconclusive"
    after["target"] = before["target"]
    assert (
        compare_reports(before, after, portable_inputs=True)["runtime_pairs"][0]["verification"]
        == "comparable-observation"
    )


@pytest.mark.parametrize("mutation", ["build", "missing-build", "scenario", "assertion", "partial"])
def test_exact_runtime_build_scenario_and_assertions_still_required(mutation):
    before, after = report_pair()
    after["target"] = before["target"]
    before["runtime"] = [runtime_record("new-runtime-before")]
    after["runtime"] = [runtime_record("new-runtime-after")]
    if mutation == "build":
        after["runtime"][0]["app_binding"]["identity"] = "2" * 64
    elif mutation == "missing-build":
        for report in (before, after):
            del report["runtime"][0]["app_binding"]["identity"]
    elif mutation == "scenario":
        after["runtime"][0]["scenario_scope"] = "another-scenario"
    elif mutation == "assertion":
        after["runtime"][0]["scenario_identity"] = "another-assertion"
    else:
        after["runtime"][0]["partial"] = True
    assert (
        compare_reports(before, after, portable_inputs=True)["runtime_pairs"][0]["verification"]
        == "inconclusive"
    )


def test_cli_portable_flag_requires_verification_before_loading_reports(tmp_path, capsys):
    code = main(
        [
            "--json",
            "--home",
            str(tmp_path / "new-flag-state"),
            "reports",
            "compare",
            "new-missing-before",
            "new-missing-after",
            "--portable-inputs",
        ]
    )
    result = json.loads(capsys.readouterr().out)
    assert code == 2 and result["error"]["type"] == "UsageError"
    assert "--portable-inputs requires --verification" in result["error"]["message"]


def test_cli_compare_passes_explicit_portable_source_option(store, capsys):
    before, after = report_pair()
    store.save_report(before)
    store.save_report(after)
    code = main(
        [
            "--json",
            "--home",
            str(store.home),
            "reports",
            "compare",
            before["id"],
            after["id"],
            "--verification",
            "--portable-inputs",
        ]
    )
    result = json.loads(capsys.readouterr().out)
    assert code == 0 and result["data"]["verification"]["path_pairing"]["normalized"]


def test_mcp_source_handler_flag_dependency_and_pass_through(store, tmp_path):
    # Exercise the real public source handler without importing SDK prompt modules.
    # SDK schema/discovery contracts are exercised separately in the CI matrix.
    source = Path(__file__).parents[1] / "src/mobile_audit/mcp_server.py"
    tree = ast.parse(source.read_text())
    declaration = next(
        node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "create_server"
    )
    function = next(
        node
        for node in declaration.body
        if isinstance(node, ast.FunctionDef) and node.name == "reports_compare"
    )
    function.decorator_list = []

    @contextmanager
    def database():
        yield store

    namespace = {
        "__package__": "mobile_audit",
        "Any": Any,
        "database": database,
        "load_report": lambda db, identifier: db.report(identifier),
        "compare": compare,
    }
    exec(
        compile(ast.fix_missing_locations(ast.Module(body=[function], type_ignores=[])), str(source), "exec"),
        namespace,
    )
    handler = namespace["reports_compare"]
    before, after = report_pair()
    before["target"] = str(tmp_path / "new-source-first")
    after["target"] = str(tmp_path / "new-source-second")
    store.save_report(before)
    store.save_report(after)
    with pytest.raises(ValueError, match="portable_inputs requires verification"):
        handler("new-missing-before", "new-missing-after", portable_inputs=True)
    result = handler(before["id"], after["id"], verification=True, portable_inputs=True)
    assert result["verification"]["path_pairing"]["normalized"]
    strict = handler(before["id"], after["id"], verification=True)
    assert strict["verification"]["scope_pairing"]["state"] == "changed"


@pytest.mark.parametrize(
    "scope",
    [
        {
            "input_snapshot": {
                "partial": False,
                "app_scope_complete": True,
                "omitted": {"code_and_config": {"files": 1, "bytes": 20}},
            }
        },
        {"source_analysis": {"state": "partial"}},
        {"hybrid_analysis": {"state": "partial"}},
    ],
)
def test_explicit_omissions_or_partial_analysis_cannot_hide_behind_complete_fingerprint(scope):
    before, after = report_pair()
    after["inventory"].update(scope)
    assert_not_normalized(before, after)


def test_runtime_finding_disappearance_stays_inconclusive_after_source_relocation():
    before, after = report_pair()
    before["runtime"] = [runtime_record("new-runtime-before")]
    after["runtime"] = [runtime_record("new-runtime-after")]
    before["findings"][0]["status"] = "runtime-confirmed"
    before["findings"][0]["evidence"].append({"runtime_id": "new-runtime-before"})
    result = compare_reports(before, after, portable_inputs=True)
    change = result["finding_transitions"][0]
    assert result["scope_pairing"]["state"] == "unchanged"
    assert change["observation"] == "no-longer-observed" and change["verification"] == "inconclusive"
    assert "not proof of remediation" in result["note"]


@pytest.mark.parametrize("option", [None, "false", "true", "", 0, 1, [], {}])
def test_direct_api_portable_option_must_be_boolean(option):
    before, after = report_pair()
    with pytest.raises(ValueError, match="portable_inputs must be a boolean"):
        compare_reports(before, after, portable_inputs=option)


def test_fresh_source_inspection_fingerprints_are_portable_only_for_same_content(tmp_path):
    from mobile_audit.inputs import inspect_target

    directories = [tmp_path / "new-first-source", tmp_path / "new-relocated-source"]
    for directory in directories:
        directory.mkdir()
        (directory / "Probe.java").write_text("package synthetic; class Probe { int value = 1; }\n")
    first_inventory, _ = inspect_target(directories[0])
    second_inventory, _ = inspect_target(directories[1])
    assert (
        first_inventory["fingerprint_complete"] is True and second_inventory["fingerprint_complete"] is True
    )
    before, after = report_pair()
    before.update(target=str(directories[0]), inventory=first_inventory)
    after.update(target=str(directories[1]), inventory=second_inventory)
    assert compare_reports(before, after, portable_inputs=True)["path_pairing"]["normalized"]
    (directories[1] / "Probe.java").write_text("package synthetic; class Probe { int value = 2; }\n")
    after["inventory"], _ = inspect_target(directories[1])
    assert_not_normalized(before, after)
