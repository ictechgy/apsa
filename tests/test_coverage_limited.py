"""Execution gaps (partial) stay incomplete; precision limits (limited) do not, unless strict.

Every fixture is new and synthetic; no retained report, corpus or device is read.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import cast

import pytest

from mobile_audit import cli
from mobile_audit.checklists import checklist_view
from mobile_audit.completeness import analysis_incomplete, report_incomplete, report_limited
from mobile_audit.core import finding
from mobile_audit.engine import PARSER_COVERAGE_STATES, _worker_schema
from mobile_audit.hybrid_analysis import analyze_hybrid
from mobile_audit.maswe import aggregate_states, rule_state
from mobile_audit.native_flow import NativeFlow
from mobile_audit.output import markdown, sarif
from mobile_audit.policy import evaluate, load_policy, template
from mobile_audit.source_analysis import RULES, TRACE_PARTIAL, Analyzer, Trace, analyze_sources

ROOT = Path(__file__).resolve().parents[1]
URL = "AST-WEBVIEW-UNTRUSTED-URL"
AMBIGUOUS_JAVA = """class Handler {
void entry(Intent input) { write(input.getStringExtra("name")); }
void write(String name) { if (name.contains("..")) return; new FileOutputStream(name); }
void write(Object name) { new FileOutputStream(name); }
}"""
OBJC = """#import <CommonCrypto/CommonDigest.h>
@implementation NewSyntheticHandler
- (void)digest:(const void *)data size:(CC_LONG)size {
    unsigned char output[16];
    CC_MD5(data, size, output);
}
@end
"""


def as_report(analysis: dict, key: str = "source_analysis", **extra) -> dict:
    return {
        "id": "audit_new_synthetic",
        "findings": analysis["findings"],
        "coverage": analysis["coverage"],
        "inventory": {"partial": False, "fingerprint_complete": True, key: analysis["metadata"]},
        **extra,
    }


def states(analysis: dict, rules=RULES) -> set[str]:
    return {row["state"] for row in analysis["coverage"] if row["rule_id"] in rules}


# --- producers --------------------------------------------------------------------------


def test_only_precision_native_reasons_make_ast_rules_limited_not_incomplete():
    analysis = analyze_sources([("Handler.java", AMBIGUOUS_JAVA)])
    flow = analysis["metadata"]["native_flow"]
    assert flow["state"] == "partial"  # Diagnostic state is unchanged.
    assert flow["budget_reasons"] == [] and "ambiguous direct call" in flow["precision_reasons"]
    assert flow["reasons"] == sorted(flow["budget_reasons"] + flow["precision_reasons"])
    assert {detail["kind"] for detail in flow["partial_details"]} == {"precision"}
    assert states(analysis) == {"limited"}
    assert any(warning.startswith("Native flow remains limited:") for warning in analysis["warnings"])
    report = as_report(analysis)
    assert not report_incomplete(report)
    assert report_incomplete(report, strict=True)
    assert report_limited(report)


def test_a_budget_native_reason_keeps_ast_rules_partial(monkeypatch):
    import mobile_audit.native_flow as module

    monkeypatch.setattr(module, "MAX_CALL_EVALUATIONS", 0)
    analysis = analyze_sources(
        [
            (
                "Handler.java",
                'class Handler { void entry(Intent input) { write(input.getStringExtra("n")); }'
                " void write(String name) { new FileOutputStream(name); } }",
            )
        ]
    )
    flow = analysis["metadata"]["native_flow"]
    assert flow["budget_reasons"], flow
    assert all(
        detail["kind"] == ("budget" if "budget" in detail["reason"] else "precision")
        for detail in flow["partial_details"]
    )
    assert states(analysis) == {"partial"}
    assert any(warning.startswith("Native flow remains partial:") for warning in analysis["warnings"])
    assert report_incomplete(as_report(analysis))


def test_native_partial_routes_budget_and_precision_to_separate_rule_sets():
    flow = NativeFlow([])
    budget = SimpleNamespace(path="A.java", function=None, truncated_rules=set(), limited_rules=set())
    precision = SimpleNamespace(path="B.java", function=None, truncated_rules=set(), limited_rules=set())
    flow.partial("source trace budget", cast(Analyzer, budget))
    flow.partial("receiver runtime dispatch unresolved", cast(Analyzer, precision))
    assert budget.truncated_rules == set(RULES) and not budget.limited_rules
    assert precision.limited_rules == set(RULES) and not precision.truncated_rules
    metadata = flow.metadata()
    assert metadata["budget_reasons"] == ["source trace budget"]
    assert metadata["precision_reasons"] == ["receiver runtime dispatch unresolved"]
    assert {(row["path"], row["kind"]) for row in metadata["partial_details"]} == {
        ("A.java", "budget"),
        ("B.java", "precision"),
    }


def _analyzer(path: str, text: str, language: str) -> tuple[Analyzer, object, list]:
    import importlib

    import tree_sitter

    grammar = importlib.import_module(f"tree_sitter_{language}")
    tree = tree_sitter.Parser(tree_sitter.Language(grammar.language())).parse(text.encode())
    analyzer = Analyzer(path, text, language)
    root = tree.root_node
    stack, nodes = [root], []
    while stack:
        node = stack.pop()
        nodes.append(node)
        stack.extend(reversed(node.named_children))
    return analyzer, root, nodes


def test_trace_partial_emission_is_a_precision_limit_and_finding_budget_is_a_gap(monkeypatch):
    analyzer, root, _ = _analyzer("A.java", "class A { void f() {} }", "java")
    analyzer.emit(URL, root, traces=(Trace(1, root, "input" + TRACE_PARTIAL),))
    assert analyzer.limited_rules == {URL} and not analyzer.truncated_rules
    import mobile_audit.source_analysis as module

    monkeypatch.setattr(module, "MAX_AST_FINDINGS", 0)
    analyzer.emit("AST-SQL-CONCAT", root)
    assert analyzer.truncated_rules == {"AST-SQL-CONCAT"}


def test_unresolved_kotlin_import_withdrawal_is_limited_without_native_flow():
    source = 'package fresh\nimport custom /* opaque */ . with\nfun safe(): String = "x"\n'
    analyzer, root, nodes = _analyzer("Entry.kt", source, "kotlin")
    analyzer.prepare(root, nodes)
    assert analyzer.limited_rules == set(RULES) and not analyzer.truncated_rules


def test_objc_files_are_limited_unless_their_parse_is_partial():
    analysis = analyze_sources([("NewSynthetic.m", OBJC)])
    (metric,) = analysis["metadata"]["files"]
    assert metric["state"] == "limited"
    assert analysis["coverage"][0]["skipped_files"] == 0
    assert states(analysis, {"OBJC-WEBVIEW-UNTRUSTED-REQUEST", "OBJC-CRYPTO-WEAK-HASH"}) == {"limited"}
    assert states(analysis) == {"limited"}  # AST rules see ObjC only through the reduced model.
    # Unexpanded macros can hide declarations; the inventory is not claimed complete.
    assert analysis["metadata"]["function_inventory_complete"] is False
    report = as_report(analysis)
    assert not report_incomplete(report) and report_incomplete(report, strict=True)
    broken = analyze_sources([("NewSynthetic.m", OBJC.replace("@end", "@end )))"))])
    assert broken["metadata"]["files"][0]["state"] == "partial"
    assert states(broken, {"OBJC-CRYPTO-WEAK-HASH"}) == {"partial"}
    assert report_incomplete(as_report(broken))


def test_objc_with_java_keeps_java_checked_files_and_limited_rules():
    analysis = analyze_sources([("A.m", OBJC), ("B.java", "class B { void idle() {} }")])
    files = {row["path"]: row["state"] for row in analysis["metadata"]["files"]}
    assert files == {"A.m": "limited", "B.java": "checked"}
    assert states(analysis) == {"limited"}


def test_swift_declared_sql_spec_only_is_limited():
    specs = {
        "sha256": "synthetic",
        "source": [{"id": "input", "method": "incoming", "returns": "text"}],
        "sink": [{"id": "query", "method": "query", "kind": "sql", "argument": 0}],
    }
    analysis = analyze_sources([("Handler.swift", "func f() { query(incoming()) }")], specs=specs)
    assert states(analysis, {"AST-SQL-CONCAT"}) == {"limited"}


def test_analyzed_hybrid_file_is_limited_and_gaps_stay_partial():
    analysis = analyze_hybrid([("App.ts", "const value = route.params.url; web.loadUrl(value);")])
    assert {row["state"] for row in analysis["coverage"]} == {"limited"}
    assert analysis["metadata"]["files"][0]["state"] == "limited"
    report = as_report(analysis, "hybrid_analysis")
    assert not report_incomplete(report)
    assert report_incomplete(report, strict=True)
    assert analysis_incomplete(report["inventory"], strict=True)
    skipped = analyze_hybrid([("App.ts", "const value = 1;"), ("random.bundle", "not a recognized bundle")])
    assert {row["state"] for row in skipped["coverage"]} == {"partial"}
    truncated = analyze_hybrid([("App.ts", "const value = 1;")], observations_truncated=True)
    assert {row["state"] for row in truncated["coverage"]} == {"partial"}
    assert {row["state"] for row in analyze_hybrid([])["coverage"]} == {"not-applicable"}


def test_hybrid_flow_budget_is_an_execution_gap(monkeypatch):
    import mobile_audit.hybrid_analysis as module

    monkeypatch.setattr(module, "MAX_OPERATIONS", 2)
    analysis = analyze_hybrid([("App.ts", "const value = route.params.url; web.loadUrl(value);")])
    assert {row["state"] for row in analysis["coverage"]} == {"partial"}
    assert analysis["metadata"]["files"][0]["state"] == "partial"


# --- aggregation and consumers ----------------------------------------------------------


def test_state_precedence_is_partial_then_limited_then_checked():
    assert "limited" in PARSER_COVERAGE_STATES
    assert rule_state({"checked", "limited"}) == "limited"
    assert rule_state({"limited", "partial"}) == "partial"
    assert rule_state({"limited", "not-run"}) == "partial"
    assert rule_state({"limited", "not-applicable"}) == "limited"
    assert aggregate_states(["checked", "limited"]) == "limited"
    assert aggregate_states(["limited", "partial"]) == "partial"
    assert aggregate_states(["limited", "not-run"]) == "partial"
    assert aggregate_states(["checked", "not-applicable"]) == "checked"


def test_worker_schema_accepts_limited_coverage():
    result = {
        "inventory": {
            "warnings": [],
            "platforms": [],
            "fingerprint": "x",
            "partial": False,
            "fingerprint_complete": True,
            "dependencies": [],
        },
        "findings": [],
        "coverage": [{"rule_id": URL, "state": "limited"}],
    }
    assert _worker_schema(result)
    result["coverage"][0]["state"] = "unknown"
    assert not _worker_schema(result)


def limited_report(**extra) -> dict:
    return {
        "id": "audit_new_limited",
        "created": "2026-11-01T00:00:00+00:00",
        "target": "/synthetic/new",
        "rule_version": "synthetic",
        "scope": "synthetic",
        "summary": {"incomplete": False, "limited": True},
        "findings": [],
        "coverage": [{"rule_id": URL, "state": "limited", "note": "bounded model"}],
        "inventory": {"partial": False, "fingerprint_complete": True, "fingerprint": "f" * 64},
        "intel_snapshot": [],
        "warnings": [],
        **extra,
    }


def test_reports_surface_limited_without_calling_the_audit_incomplete():
    report = limited_report()
    text = markdown(report)
    assert "Audit execution: **complete for the stated scope** (some coverage is limited" in text
    run = sarif(report)["runs"][0]
    assert run["invocations"][0]["executionSuccessful"] is True
    assert run["properties"]["auditIncomplete"] is False and run["properties"]["auditLimited"] is True
    (notice,) = run["invocations"][0]["toolExecutionNotifications"]
    assert notice["level"] == "note" and notice["message"]["text"].startswith(f"{URL}: limited")


def test_checklist_reports_a_limited_status():
    view = checklist_view(
        limited_report(), {"name": "new", "items": [{"id": "N-1", "title": "x", "maswe": [], "rules": [URL]}]}
    )
    assert view["items"][0]["status"] == "limited"


# --- policy -----------------------------------------------------------------------------


def test_policy_strict_coverage_controls_limited_and_required_rules(tmp_path):
    report = limited_report()
    lenient = evaluate(report, {"schema_version": 1, "required_rules": [URL]})
    assert lenient["state"] == "passed" and lenient["exit_code"] == 0
    assert lenient["policy"]["strict_coverage"] is False
    strict = evaluate(report, {"schema_version": 1, "strict_coverage": True, "required_rules": [URL]})
    assert strict["state"] == "incomplete" and strict["exit_code"] == 3
    assert strict["policy"]["strict_coverage"] is True
    codes = {reason["code"]: reason for reason in strict["reasons"]}
    assert codes["partial-audit"]["rules"] == [URL]
    assert codes["required-rule-incomplete"]["states"] == ["limited"]
    unpartial = evaluate(report, {"schema_version": 1, "strict_coverage": True, "fail_on_partial": False})
    assert unpartial["state"] == "passed"
    with pytest.raises(ValueError, match="strict_coverage must be a boolean"):
        evaluate(report, {"schema_version": 1, "strict_coverage": "true"})
    path = tmp_path / "apsa.toml"
    path.write_text(template())
    assert "strict_coverage = false" in path.read_text()
    assert load_policy(path)["strict_coverage"] is False


def test_policy_threshold_failure_outranks_an_incomplete_audit():
    item = finding(
        "TEST", "Example", "high", "configuration-confirmed", [{"path": "A.java", "line": 1}], "Fix"
    )
    report = limited_report(findings=[item], coverage=[{"rule_id": "TEST", "state": "partial"}])
    gate = evaluate(report, {"schema_version": 1})
    assert gate["state"] == "failed" and gate["exit_code"] == 4
    assert {reason["code"] for reason in gate["reasons"]} == {"partial-audit", "severity-threshold"}


# --- CLI --------------------------------------------------------------------------------


def _run(monkeypatch, capsys, report: dict, *arguments: str, home: Path) -> tuple[int, dict]:
    monkeypatch.setattr(cli, "scan", lambda *args, **kwargs: report)
    code = cli.main(["--json", "--home", str(home), "scan", str(home), *arguments])
    return code, json.loads(capsys.readouterr().out)


def test_cli_fail_on_threshold_outranks_incomplete(monkeypatch, capsys, tmp_path):
    item = finding(
        "TEST", "Example", "high", "configuration-confirmed", [{"path": "A.java", "line": 1}], "Fix"
    )
    report = limited_report(findings=[item], coverage=[{"rule_id": "TEST", "state": "partial"}])
    code, envelope = _run(monkeypatch, capsys, report, "--fail-on", "high", home=tmp_path)
    assert code == 4 and envelope["exit_code"] == 4
    code, _ = _run(monkeypatch, capsys, report, home=tmp_path)
    assert code == 3


def test_cli_strict_coverage_turns_limited_into_exit_3(monkeypatch, capsys, tmp_path):
    report = limited_report()
    assert _run(monkeypatch, capsys, report, home=tmp_path)[0] == 0
    assert _run(monkeypatch, capsys, report, "--strict-coverage", home=tmp_path)[0] == 3
    policy = tmp_path / "policy.json"
    policy.write_text(json.dumps({"schema_version": 1}))
    code, envelope = _run(monkeypatch, capsys, report, "--policy", str(policy), home=tmp_path)
    assert code == 0 and envelope["data"]["gate"]["policy"]["strict_coverage"] is False
    code, envelope = _run(
        monkeypatch, capsys, report, "--policy", str(policy), "--strict-coverage", home=tmp_path
    )
    assert code == 3 and envelope["data"]["decision"]["policy"]["strict_coverage"] is True
    assert (
        cli.main(
            ["--json", "--home", str(tmp_path), "scan", str(tmp_path), "--background", "--strict-coverage"]
        )
        == 2
    )


def test_cli_scan_of_objc_project_is_complete_but_limited(tmp_path, capsys):
    source = tmp_path / "new-objc-source"
    source.mkdir()
    (source / "Handler.m").write_text(OBJC)
    (source / "Info.plist").write_text(
        '<?xml version="1.0" encoding="UTF-8"?><plist version="1.0"><dict>'
        "<key>CFBundleIdentifier</key><string>new.synthetic.objc</string></dict></plist>"
    )
    home = tmp_path / "home"
    assert cli.main(["--json", "--home", str(home), "scan", str(source)]) == 0
    report = json.loads(capsys.readouterr().out)["data"]
    assert report["summary"]["incomplete"] is False and report["summary"]["limited"] is True
    objc = {row["state"] for row in report["coverage"] if row["rule_id"].startswith("OBJC-")}
    assert objc == {"limited"}
    assert cli.main(["--json", "--home", str(home), "scan", str(source), "--strict-coverage"]) == 3
    capsys.readouterr()
    policy = tmp_path / "policy.json"
    policy.write_text(json.dumps({"schema_version": 1}))
    evaluate_args = ["--json", "--home", str(home), "policy", "evaluate", "latest", "--policy", str(policy)]
    assert cli.main(evaluate_args) == 0
    assert cli.main([*evaluate_args, "--strict-coverage"]) == 3
    capsys.readouterr()


# --- Action helper ----------------------------------------------------------------------


def _helper(*arguments: str) -> str:
    return subprocess.run(
        [sys.executable, "-I", str(ROOT / "scripts/action_summary.py"), *arguments],
        capture_output=True,
        text=True,
        check=True,
    ).stdout


def test_action_helper_honors_strict_coverage(tmp_path):
    fixture = tmp_path / "new-limited-result.json"
    fixture.write_text(json.dumps({"ok": True, "data": limited_report()}))
    assert _helper("--incomplete", str(fixture)) == "incomplete=false\n"
    assert _helper("--incomplete", str(fixture), "false") == "incomplete=false\n"
    assert _helper("--incomplete", str(fixture), "true") == "incomplete=true\n"
    lenient = _helper("--summary", str(fixture), "0")
    assert "Audit execution: **complete for the stated scope**" in lenient
    assert "Limited coverage:" in lenient and "unless strict-coverage is set" in lenient
    strict = _helper("--summary", str(fixture), "3", "true")
    assert "Audit execution: **incomplete**" in strict and "strict coverage counts" in strict
    invalid = subprocess.run(
        [sys.executable, "-I", str(ROOT / "scripts/action_summary.py"), "--incomplete", str(fixture), "yes"],
        capture_output=True,
        text=True,
    )
    assert invalid.returncode != 0


def test_action_declares_strict_coverage_and_exit_precedence():
    import yaml

    action = yaml.safe_load((ROOT / "action.yml").read_text())
    assert action["inputs"]["strict-coverage"]["default"] == "false"
    assert "takes precedence" in action["outputs"]["exit-code"]["description"]
    audit = next(step for step in action["runs"]["steps"] if step.get("id") == "scan")
    assert audit["env"]["APSA_STRICT_COVERAGE"] == "${{ inputs.strict-coverage }}"
    assert "args+=(--strict-coverage)" in audit["run"]
    assert '--incomplete "$RUNNER_TEMP/apsa-result.json" "$APSA_STRICT_COVERAGE"' in audit["run"]
