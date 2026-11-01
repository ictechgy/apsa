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
from mobile_audit.native_flow import REASON_KINDS, NativeFlow
from mobile_audit.output import markdown, sarif
from mobile_audit.policy import evaluate, load_policy, template
from mobile_audit.source_analysis import (
    ANDROID_ONLY,
    RULES,
    TRACE_LIMITED,
    TRACE_PARTIAL,
    Analyzer,
    Trace,
    analyze_sources,
)

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


OBJC_RULES = {"OBJC-WEBVIEW-UNTRUSTED-REQUEST", "OBJC-CRYPTO-WEAK-HASH"}
ANDROID_AST_RULES = {rule for rule in RULES if rule.endswith(ANDROID_ONLY)}


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
    assert all(detail["kind"] == REASON_KINDS[detail["reason"]] for detail in flow["partial_details"])
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


def test_trace_cut_kind_routes_emission_and_finding_budget_is_a_gap(monkeypatch):
    analyzer, root, _ = _analyzer("A.java", "class A { void f() {} }", "java")
    analyzer.emit(URL, root, traces=(Trace(1, root, "input" + TRACE_LIMITED),))
    assert analyzer.limited_rules == {URL} and not analyzer.truncated_rules
    # A trace cut by the trace cap is an execution gap, not a precision limit.
    analyzer.emit("AST-PATH-TRAVERSAL", root, traces=(Trace(2, root, "input" + TRACE_PARTIAL),))
    assert analyzer.truncated_rules == {"AST-PATH-TRAVERSAL"} and analyzer.limited_rules == {URL}
    import mobile_audit.source_analysis as module

    monkeypatch.setattr(module, "MAX_AST_FINDINGS", 0)
    analyzer.emit("AST-SQL-CONCAT", root)
    assert analyzer.truncated_rules == {"AST-PATH-TRAVERSAL", "AST-SQL-CONCAT"}


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
    assert states(analysis, OBJC_RULES) == {"limited"}
    # AST rules never examine ObjC: alone it leaves them not-run (Android-only: not-applicable).
    assert states(analysis, ANDROID_AST_RULES) == {"not-applicable"}
    assert states(analysis, set(RULES) - ANDROID_AST_RULES) == {"not-run"}
    assert all(
        "AST rules do not examine Objective-C" in row["note"]
        for row in analysis["coverage"]
        if row["rule_id"] in set(RULES) - ANDROID_AST_RULES
    )
    # Unexpanded macros can hide declarations; the inventory is not claimed complete.
    assert analysis["metadata"]["function_inventory_complete"] is False
    report = as_report(analysis)
    assert not report_incomplete(report) and report_incomplete(report, strict=True)
    broken = analyze_sources([("NewSynthetic.m", OBJC.replace("@end", "@end )))"))])
    assert broken["metadata"]["files"][0]["state"] == "partial"
    assert states(broken, {"OBJC-CRYPTO-WEAK-HASH"}) == {"partial"}
    assert report_incomplete(as_report(broken))


def test_objc_with_java_leaves_ast_rules_partial_except_android_only_rules():
    analysis = analyze_sources([("A.m", OBJC), ("B.java", "class B { void idle() {} }")])
    files = {row["path"]: row["state"] for row in analysis["metadata"]["files"]}
    assert files == {"A.m": "limited", "B.java": "checked"}
    # ObjC sources in scope were not examined by AST rules: an execution gap.
    assert states(analysis, set(RULES) - ANDROID_AST_RULES) == {"partial"}
    # Android-only rules do not apply to ObjC; the Java file alone decides them.
    assert states(analysis, ANDROID_AST_RULES) == {"checked"}
    assert states(analysis, OBJC_RULES) == {"limited"}
    assert report_incomplete(as_report(analysis))


SWIFT_UNIMPLEMENTED_RULES = {"AST-CRYPTO-ECB", "AST-CRYPTO-WEAK-CIPHER", "AST-SQL-CONCAT"}
KOTLIN = 'package n\n\nclass Greeter {\n    fun greet(): String {\n        return "hi"\n    }\n}\n'


@pytest.mark.parametrize(
    "other", [("Greeter.kt", KOTLIN), ("Greeter.java", "class Greeter { void idle() {} }")]
)
def test_swift_unimplemented_rules_are_limited_beside_another_ast_language(other):
    mixed = analyze_sources([other, ("Fixed.swift", SWIFT)])
    # The Swift files are examined, but these rules have no Swift model: a precision limit.
    assert states(mixed, SWIFT_UNIMPLEMENTED_RULES) == {"limited"}
    assert states(mixed, set(RULES) - SWIFT_UNIMPLEMENTED_RULES) == {"checked"}
    assert all(
        "not implemented for Swift" in row["note"]
        for row in mixed["coverage"]
        if row["rule_id"] in SWIFT_UNIMPLEMENTED_RULES
    )
    assert not report_incomplete(as_report(mixed)) and report_incomplete(as_report(mixed), strict=True)
    assert states(analyze_sources([("Fixed.swift", SWIFT)]), SWIFT_UNIMPLEMENTED_RULES) == {"not-run"}
    assert states(analyze_sources([other]), SWIFT_UNIMPLEMENTED_RULES) == {"checked"}


def test_swift_unimplemented_limit_never_hides_an_execution_gap(monkeypatch):
    with_objc = analyze_sources([("Greeter.kt", KOTLIN), ("Fixed.swift", SWIFT), ("Handler.m", OBJC)])
    assert states(with_objc, SWIFT_UNIMPLEMENTED_RULES) == {"partial"}
    broken = analyze_sources(
        [("Greeter.kt", KOTLIN), ("Fixed.swift", SWIFT), ("Broken.java", "class B { void f( {")]
    )
    assert states(broken, SWIFT_UNIMPLEMENTED_RULES) == {"partial"}
    import mobile_audit.native_flow as module

    monkeypatch.setattr(module, "MAX_CALL_EVALUATIONS", 0)
    budget = analyze_sources(
        [
            ("Fixed.swift", SWIFT),
            (
                "Handler.java",
                'class Handler { void entry(Intent input) { write(input.getStringExtra("n")); }'
                " void write(String name) { new FileOutputStream(name); } }",
            ),
        ]
    )
    assert budget["metadata"]["native_flow"]["budget_reasons"]
    assert states(budget, SWIFT_UNIMPLEMENTED_RULES) == {"partial"}


def test_cli_kotlin_and_swift_project_is_limited_and_strict_exits_3(tmp_path, capsys):
    root = tmp_path.resolve() / "new-kmp-source"
    android = root / "androidApp/src/main"
    (android / "java/n").mkdir(parents=True)
    (android / "java/n/Greeter.kt").write_text(KOTLIN)
    (android / "AndroidManifest.xml").write_text(
        '<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="new.synthetic">'
        '<application android:allowBackup="false"/></manifest>'
    )
    (root / "iosApp").mkdir()
    (root / "iosApp/Fixed.swift").write_text(SWIFT)
    (root / "iosApp/Info.plist").write_text(
        '<?xml version="1.0" encoding="UTF-8"?><plist version="1.0"><dict>'
        "<key>CFBundleIdentifier</key><string>new.synthetic.ios</string></dict></plist>"
    )
    code, envelope = _scan(root, capsys)
    report = envelope["data"]
    assert code == 0 and report["summary"]["incomplete"] is False and report["summary"]["limited"] is True
    # Nothing else in the fixture is limited or partial: these rules alone carry the limit.
    limited = {row["rule_id"] for row in report["coverage"] if row["state"] in {"limited", "partial"}}
    assert limited == SWIFT_UNIMPLEMENTED_RULES
    assert states(report, SWIFT_UNIMPLEMENTED_RULES) == {"limited"}
    # Strict coverage counts the precision limit (the stored summary stays non-strict).
    assert _scan(root, capsys, "--strict-coverage")[0] == 3


def test_swift_declared_sql_spec_beside_kotlin_stays_limited():
    specs = {
        "sha256": "synthetic",
        "source": [{"id": "input", "method": "incoming", "returns": "text"}],
        "sink": [{"id": "query", "method": "query", "kind": "sql", "argument": 0}],
    }
    mixed = analyze_sources(
        [("Greeter.kt", KOTLIN), ("Handler.swift", "func f() { query(incoming()) }")], specs=specs
    )
    # Swift is examined for the exact declared sinks: a precision limit, as for Swift alone.
    assert states(mixed, SWIFT_UNIMPLEMENTED_RULES) == {"limited"}


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
    assert states(report, set(RULES) - ANDROID_AST_RULES) == {"not-run"}
    assert cli.main(["--json", "--home", str(home), "scan", str(source), "--strict-coverage"]) == 3
    capsys.readouterr()
    policy = tmp_path / "policy.json"
    policy.write_text(json.dumps({"schema_version": 1}))
    evaluate_args = ["--json", "--home", str(home), "policy", "evaluate", "latest", "--policy", str(policy)]
    assert cli.main(evaluate_args) == 0
    assert cli.main([*evaluate_args, "--strict-coverage"]) == 3
    capsys.readouterr()


SWIFT = 'import Foundation\nfunc fixedName() -> String { return "fixed" }\n'
CONDITIONAL_OBJC = """#import <CommonCrypto/CommonDigest.h>
@implementation NewSyntheticConditional
#if TARGET_OS_IOS
- (void)digest:(const void *)data size:(CC_LONG)size {
    unsigned char output[16];
    CC_MD5(data, size, output);
}
#endif
@end
"""


def _ios_source(root: Path, files: dict[str, str]) -> Path:
    # Resolve: hosted macOS runners expose TMPDIR through a symlink.
    source = root.resolve() / "new-ios-source"
    source.mkdir()
    for name, text in files.items():
        (source / name).write_text(text)
    (source / "Info.plist").write_text(
        '<?xml version="1.0" encoding="UTF-8"?><plist version="1.0"><dict>'
        "<key>CFBundleIdentifier</key><string>new.synthetic.ios</string></dict></plist>"
    )
    return source


def _scan(source: Path, capsys, *arguments: str) -> tuple[int, dict]:
    code = cli.main(["--json", "--home", str(source.parent / "home"), "scan", str(source), *arguments])
    return code, json.loads(capsys.readouterr().out)


def test_swift_with_objc_leaves_ast_rules_partial_and_exits_3(tmp_path, capsys):
    analysis = analyze_sources([("Fixed.swift", SWIFT), ("Handler.m", OBJC)])
    assert states(analysis, ANDROID_AST_RULES) == {"not-applicable"}  # iOS-only sources.
    assert states(analysis, {"AST-CRYPTO-ECB", "AST-CRYPTO-WEAK-CIPHER", "AST-SQL-CONCAT"}) == {"not-run"}
    examined = set(RULES) - ANDROID_AST_RULES - {"AST-CRYPTO-ECB", "AST-CRYPTO-WEAK-CIPHER", "AST-SQL-CONCAT"}
    assert states(analysis, examined) == {"partial"}
    assert states(analysis, OBJC_RULES) == {"limited"}
    code, envelope = _scan(_ios_source(tmp_path, {"Fixed.swift": SWIFT, "Handler.m": OBJC}), capsys)
    report = envelope["data"]
    assert code == 3 and envelope["ok"] is False and report["summary"]["incomplete"] is True
    assert states(report, examined) == {"partial"}
    assert states(report, OBJC_RULES) == {"limited"}


def test_conditionally_compiled_objc_method_is_an_execution_gap(tmp_path, capsys):
    analysis = analyze_sources([("Conditional.m", CONDITIONAL_OBJC)])
    (metric,) = analysis["metadata"]["files"]
    assert metric["functions"]["skipped"] == 1 and metric["functions"]["analyzed"] == 0
    assert metric["state"] == "partial" and analysis["coverage"][0]["skipped_files"] == 1
    assert states(analysis, OBJC_RULES) == {"partial"}
    assert any("conditionally compiled function" in warning for warning in analysis["warnings"])
    assert report_incomplete(as_report(analysis))
    code, envelope = _scan(_ios_source(tmp_path, {"Conditional.m": CONDITIONAL_OBJC}), capsys)
    report = envelope["data"]
    assert code == 3 and report["summary"]["incomplete"] is True
    assert states(report, OBJC_RULES) == {"partial"}
    files = report["inventory"]["source_analysis"]["files"]
    assert [row["state"] for row in files if row["language"] == "objc"] == ["partial"]


@pytest.mark.parametrize(
    "sources",
    [
        [("Bridge.mm", "@implementation B @end")],
        [("Handler.m", OBJC), ("Bridge.mm", "@implementation B @end")],
    ],
)
def test_objective_c_plus_plus_is_an_execution_gap_for_objc_rules(sources):
    analysis = analyze_sources(sources)
    assert states(analysis, OBJC_RULES) == {"partial"}
    # Neither AST nor OBJC rules examine .mm; ObjC-family sources alone leave AST rules not-run.
    assert states(analysis, set(RULES) - ANDROID_AST_RULES) == {"not-run"}
    assert states(analysis, ANDROID_AST_RULES) == {"not-applicable"}
    assert report_incomplete(as_report(analysis))
    with_swift = analyze_sources([*sources, ("Fixed.swift", SWIFT)])
    assert states(with_swift, OBJC_RULES) == {"partial"}
    assert "partial" in states(with_swift)


def test_every_source_dropped_before_parsing_is_partial(monkeypatch):
    import mobile_audit.source_analysis as module

    monkeypatch.setattr(module, "MAX_AST_BYTES", 4)
    java = analyze_sources([("A.java", "class A { void f() {} }"), ("B.kt", "class B")])
    assert states(java) == {"partial"} and java["coverage"][0]["parsed_files"] == 0
    assert report_incomplete(as_report(java))
    objc = analyze_sources([("A.m", OBJC)])
    assert states(objc, OBJC_RULES) == {"partial"}  # Not "not-run": the file was dropped.
    assert report_incomplete(as_report(objc))
    # Unsupported-language files alone remain an absent check, not a dropped source.
    assert states(analyze_sources([("App.js", "const a = 1;")])) == {"not-run"}


def test_cli_exits_3_when_every_source_exceeds_the_byte_budget(tmp_path, capsys):
    from mobile_audit.source_analysis import MAX_AST_BYTES

    root = tmp_path.resolve() / "new-oversized-source"
    java = root / "app/src/main/java/n"
    java.mkdir(parents=True)
    (java / "Oversized.java").write_text(
        "class Oversized {\n" + "// padding\n" * (MAX_AST_BYTES // 11 + 1) + "}\n"
    )
    (root / "app/src/main/AndroidManifest.xml").write_text(
        '<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="new.synthetic">'
        '<application android:allowBackup="false"/></manifest>'
    )
    code, envelope = _scan(root, capsys)
    report = envelope["data"]
    (row,) = report["inventory"]["source_analysis"]["files"]
    assert row["state"] == "skipped" and row["reason"] == "parser byte budget exceeded"
    assert code == 3 and report["summary"]["incomplete"] is True
    assert states(report) == {"partial"}


def test_unobserved_macro_functions_stay_a_precision_limit():
    macro = """#import <CommonCrypto/CommonDigest.h>
#define DIGEST(name) - (void)name:(const void *)data { unsigned char o[16]; CC_MD5(data, 1, o); }
@implementation NewSyntheticMacro
DIGEST(digest)
@end
"""
    analysis = analyze_sources([("Macro.m", macro)])
    (metric,) = analysis["metadata"]["files"]
    assert metric["functions"]["skipped"] == 0 and metric["state"] == "limited"
    assert states(analysis, OBJC_RULES) == {"limited"}
    assert analysis["metadata"]["function_inventory_complete"] is False


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


def _write_envelope(path: Path, envelope: dict) -> Path:
    path.write_text(json.dumps(envelope))
    return path


def test_action_helper_honors_policy_strict_coverage(tmp_path, capsys):
    # Policy strict_coverage = true with fail_on_partial = false exits 0 for a limited-only
    # report, yet the Action (strict-coverage input false) must still report it incomplete.
    source = _ios_source(tmp_path, {"Handler.m": OBJC})
    policy = source.parent / "new-strict-policy.json"
    policy.write_text(json.dumps({"schema_version": 1, "strict_coverage": True, "fail_on_partial": False}))
    code, envelope = _scan(source, capsys, "--policy", str(policy))
    assert code == 0 and envelope["data"]["gate"]["policy"]["strict_coverage"] is True
    assert report_limited(envelope["data"]["report"])
    fixture = _write_envelope(source.parent / "new-policy-result.json", envelope)
    assert _helper("--incomplete", str(fixture), "false") == "incomplete=true\n"
    assert _helper("--incomplete", str(fixture)) == "incomplete=true\n"
    text = _helper("--summary", str(fixture), "0", "false")
    assert "Audit execution: **incomplete** (exit code 0)" in text
    assert "strict coverage counts this as incomplete" in text
    # A lenient policy leaves limited coverage complete for the stated scope.
    policy.write_text(json.dumps({"schema_version": 1}))
    code, envelope = _scan(source, capsys, "--policy", str(policy))
    lenient = _write_envelope(source.parent / "new-lenient-result.json", envelope)
    assert code == 0 and _helper("--incomplete", str(lenient), "false") == "incomplete=false\n"
    assert "Audit execution: **complete for the stated scope**" in _helper("--summary", str(lenient), "0")


def test_action_helper_reports_a_partial_audit_reason_beside_exit_4(tmp_path, capsys):
    source = _ios_source(tmp_path, {"Handler.m": OBJC})
    policy = source.parent / "new-blocking-policy.json"
    policy.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "strict_coverage": True,
                "allowed_statuses": ["candidate"],
                "thresholds": {"critical": 0, "high": 0, "medium": 0, "low": -1, "info": -1},
            }
        )
    )
    code, envelope = _scan(source, capsys, "--policy", str(policy))
    codes = {reason["code"] for reason in envelope["data"]["gate"]["reasons"]}
    assert code == 4 and {"partial-audit", "severity-threshold"} <= codes
    fixture = _write_envelope(source.parent / "new-exit4-result.json", envelope)
    assert _helper("--incomplete", str(fixture), "false") == "incomplete=true\n"
    text = _helper("--summary", str(fixture), "4", "false")
    assert "Audit execution: **incomplete** (exit code 4)" in text
    assert "complete for the stated scope" not in text and "Execution error" not in text


def test_action_summary_treats_a_real_exit_3_envelope_as_incomplete_not_failed(tmp_path, capsys):
    root = tmp_path.resolve() / "new-android-source"
    java = root / "app/src/main/java/n"
    java.mkdir(parents=True)
    (java / "Broken.java").write_text("class Broken { void f( { int x = ; } }\n")
    (root / "app/src/main/AndroidManifest.xml").write_text(
        '<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="new.synthetic">'
        '<application android:allowBackup="false"/></manifest>'
    )
    code, envelope = _scan(root, capsys)
    assert code == 3 and envelope["ok"] is False and envelope["exit_code"] == 3
    assert "error" not in envelope and envelope["data"]["summary"]["incomplete"] is True
    fixture = _write_envelope(root.parent / "new-exit3-result.json", envelope)
    text = _helper("--summary", str(fixture), "3")
    assert "Audit execution: **incomplete** (exit code 3)" in text
    assert "failed" not in text and "Execution error" not in text
    assert _helper("--incomplete", str(fixture)) == "incomplete=true\n"
    # A genuine execution failure keeps its label.
    error = _write_envelope(root.parent / "new-error.json", {"ok": False, "data": envelope["data"]})
    assert "Audit execution: **failed** (exit code 1)" in _helper("--summary", str(error), "1")


def test_action_fails_on_policy_strict_coverage_without_the_strict_input(tmp_path, capsys):
    from tests.test_interface_review_fixes import _run_action

    source = _ios_source(tmp_path, {"Handler.m": OBJC})
    policy = source.parent / "new-strict-policy.json"
    policy.write_text(json.dumps({"schema_version": 1, "strict_coverage": True, "fail_on_partial": False}))
    code, envelope = _scan(source, capsys, "--policy", str(policy))
    assert code == 0
    inputs = {"policy": "apsa.toml", "fail-on-incomplete": "true", "strict-coverage": "false"}
    code, text, outputs = _run_action(tmp_path.resolve() / "new-action", envelope, 0, **inputs)
    assert outputs["incomplete"] == "true" and outputs["exit-code"] == "0"
    assert code == 3 and "partial or incomplete" in text
