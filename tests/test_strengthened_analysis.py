"""Coverage diagnostics using new in-memory source and temporary synthetic inputs."""

from pathlib import Path
from types import SimpleNamespace
from typing import cast
from zipfile import ZipFile

import pytest

from mobile_audit.hybrid_analysis import (
    HERMES_HEADERS,
    analyze_hybrid,
    compiled_hybrid_input,
    hybrid_source_input,
)
from mobile_audit.input_snapshot import stage_input, staging_rank, staging_tier
from mobile_audit.inputs import inspect_target
from mobile_audit.native_flow import NativeFlow
from mobile_audit.source_analysis import RULES, Analyzer, analyze_sources


def test_native_partial_details_scope_call_and_keep_unrelated_rules_partial():
    source = """class Handler {
    void entry(Intent input) { write(input.getStringExtra("name")); }
    void write(String name) { if (name.contains("..")) return; new FileOutputStream(name); }
    void write(Object name) { new FileOutputStream(name); }
    }"""
    sources = [("Handler.java", source), ("Unrelated.java", "class Unrelated { void idle() {} }")]
    report = analyze_sources(sources)
    assert report == analyze_sources(list(reversed(sources)))
    assert any(item["rule_id"] == "AST-PATH-TRAVERSAL" for item in report["findings"])
    details = report["metadata"]["native_flow"]["partial_details"]
    ambiguity = next(item for item in details if item["reason"] == "ambiguous direct call")
    assert ambiguity == {
        "reason": "ambiguous direct call",
        "path": "Handler.java",
        "line": 2,
        "column": source.splitlines()[1].index("write(") + 1,
        "call": "write",
        "category": "dispatch",
        "scope": "file-call",
        "rule_ids": sorted(RULES),
        "rule_scope": "conservative-all-native-rules",
    }
    files = {item["path"]: item for item in report["metadata"]["files"]}
    assert "ambiguous direct call" in files["Handler.java"]["native_flow_reasons"]
    assert files["Unrelated.java"]["native_flow_reasons"] == []
    assert all(item["state"] == "partial" for item in report["coverage"])


def test_native_unknown_call_budget_retains_tainted_candidate(monkeypatch):
    import mobile_audit.native_flow as module

    monkeypatch.setattr(module, "MAX_CALL_EVALUATIONS", 0)
    report = analyze_sources(
        [
            (
                "New.java",
                """class Handler {
      void entry(Intent input) { new FileOutputStream(clean(input.getStringExtra("name"))); }
      String clean(String name) { return "safe"; }
    }""",
            )
        ]
    )
    assert any(item["rule_id"] == "AST-PATH-TRAVERSAL" for item in report["findings"])
    details = report["metadata"]["native_flow"]["partial_details"]
    assert any(item["call"] == "clean" and item["category"] == "budget" for item in details)
    assert all(item["state"] == "partial" for item in report["coverage"])


def test_native_negative_literal_helper_remains_checked():
    report = analyze_sources(
        [
            (
                "New.java",
                """class Handler {
      void entry() { new FileOutputStream(clean()); }
      String clean() { return "fixed.txt"; }
    }""",
            )
        ]
    )
    assert not report["findings"]
    assert report["metadata"]["native_flow"]["partial_details"] == []
    assert report["metadata"]["native_flow"]["state"] == "checked"


def test_native_diagnostics_are_bounded_deduplicated_and_order_independent(monkeypatch):
    import mobile_audit.native_flow as module

    monkeypatch.setattr(module, "MAX_PARTIAL_DETAILS", 2)
    reports = []
    for paths in (["C.java", "A.java", "B.java"], ["B.java", "A.java", "C.java"]):
        flow = NativeFlow([])
        for path in paths:
            analyzer = cast(Analyzer, SimpleNamespace(path=path, function=None, truncated_rules=set()))
            for _ in range(2):
                flow.partial("source trace budget", analyzer)
        reports.append(flow.metadata())
    assert reports[0] == reports[1]
    assert [item["path"] for item in reports[0]["partial_details"]] == ["A.java", "B.java"]
    assert reports[0]["partial_details_truncated"]
    assert reports[0]["state"] == "partial"


@pytest.mark.parametrize("path", ["assets/index.android.bundle", "main.bundle", "main.jsbundle"])
def test_text_bundles_are_analyzed_but_framework_coverage_remains_partial(path):
    report = analyze_hybrid([(path, "const value = route.params.url; web.loadUrl(value);")])
    assert report["findings"][0]["rule_id"] == "HYBRID-UNTRUSTED-URL"
    assert report["metadata"]["files"][0]["analysis_state"] == "analyzed"
    framework = report["metadata"]["frameworks"][0]
    assert framework["framework"] == "react-native"
    assert framework["analyzed_text_files"] == 1 and framework["skipped_files"] == 0
    assert all(item["state"] == "partial" for item in report["coverage"])


def test_unknown_bundle_requires_metro_marker_and_keeps_literal_control():
    sources = [("random.bundle", "const value = route.params.url; web.loadUrl(value);")]
    report = analyze_hybrid(sources)
    assert not report["findings"]
    assert report["metadata"]["files"][0]["analysis_state"] == "skipped"
    assert "not recognized" in report["metadata"]["files"][0]["reason"]
    sources[0] = ("random.bundle", '__d(function() { web.loadUrl("https://safe.example"); });')
    report = analyze_hybrid(sources)
    assert not report["findings"]
    assert report["metadata"]["files"][0]["analysis_state"] == "analyzed"
    assert report["metadata"]["files"][0]["basis"] == "metro-bundle-marker"


@pytest.mark.parametrize("text", ['const marker = "__d(";', "// __d(function() {});", "/* __r(1); */"])
def test_unknown_bundle_markers_in_comments_or_literals_are_not_source_admission(text):
    report = analyze_hybrid([("random.bundle", text)])
    assert report["metadata"]["files"][0]["analysis_state"] == "skipped"
    assert report["metadata"]["files"][0]["framework"] == "unknown"


@pytest.mark.parametrize("raw", [*HERMES_HEADERS, b"\x00synthetic", b"\xffsynthetic"])
def test_nontext_bundle_cannot_enter_source_flow(raw):
    record, text = hybrid_source_input("index.android.bundle", raw)
    assert record is not None
    assert text is None and record["state"] == "skipped"
    if raw in HERMES_HEADERS:
        assert "unavailable" in record["reason"]
    else:
        assert "non-text" in record["reason"]


@pytest.mark.parametrize("budget", ["MAX_BYTES", "MAX_TOKENS", "MAX_FUNCTIONS"])
def test_bundle_resource_budgets_report_skipped_content(monkeypatch, budget):
    import mobile_audit.hybrid_analysis as module

    monkeypatch.setattr(module, budget, 0)
    report = analyze_hybrid([("main.bundle", "const value = route.params.url; web.loadUrl(value);")])
    assert not report["findings"]
    assert report["metadata"]["files"][0]["analysis_state"] == "skipped"
    assert "budget" in report["metadata"]["files"][0]["reason"]
    assert report["metadata"]["frameworks"][0]["analyzed_text_files"] == 0
    assert all(item["state"] == "partial" for item in report["coverage"])


def test_compiled_presence_is_skipped_and_empty_observation_budget_is_unknown():
    flutter = compiled_hybrid_input("lib/arm64-v8a/libapp.so")
    hermes = compiled_hybrid_input("assets/main.hbc")
    assert flutter is not None and hermes is not None
    observed = [flutter, hermes]
    report = analyze_hybrid([], observed)
    assert not report["findings"]
    assert all(item["analysis_state"] == "skipped" for item in report["metadata"]["files"])
    assert {item["framework"] for item in report["metadata"]["frameworks"]} == {"flutter", "react-native"}
    assert all(item["analyzed_text_files"] == 0 for item in report["metadata"]["frameworks"])
    assert all(item["state"] == "partial" for item in report["coverage"])
    unknown = analyze_hybrid([], observations_truncated=True)
    assert not unknown["metadata"]["complete"]
    assert all(item["state"] == "partial" for item in unknown["coverage"])


def test_synthetic_archive_inventory_reports_text_and_compiled_separately(tmp_path, monkeypatch):
    archive_path = tmp_path / "new.apk"
    with ZipFile(archive_path, "w") as archive:
        archive.writestr("AndroidManifest.xml", '<manifest package="example.new"><application /></manifest>')
        archive.writestr("assets/index.android.bundle", "const value = route.params.url; web.loadUrl(value);")
        archive.writestr("assets/main.jsbundle", HERMES_HEADERS[0] + b"synthetic-bytecode")
        archive.writestr("lib/arm64-v8a/libapp.so", b"synthetic-aot-not-analyzed")
        archive.writestr("assets/other.bundle", "unrecognized text")
    original_read = ZipFile.read

    def read_text_only(archive, member, *args, **kwargs):
        name = member.filename if hasattr(member, "filename") else member
        assert name != "lib/arm64-v8a/libapp.so", "AOT presence must not read content"
        return original_read(archive, member, *args, **kwargs)

    monkeypatch.setattr(ZipFile, "read", read_text_only)
    inventory, sources = inspect_target(archive_path)
    assert [path for path, _ in sources if path.endswith((".bundle", ".jsbundle"))] == [
        "assets/index.android.bundle"
    ]
    report = analyze_hybrid(sources, inventory["hybrid_inputs"])
    assert report["findings"]
    frameworks = {item["framework"]: item for item in report["metadata"]["frameworks"]}
    assert frameworks["react-native"]["analyzed_text_files"] == 1
    assert frameworks["react-native"]["skipped_files"] == 1
    assert frameworks["flutter"]["analyzed_text_files"] == 0
    assert inventory["partial"]


def test_compiled_source_presence_stages_names_only_and_excludes_symlinks(tmp_path, monkeypatch):
    import mobile_audit.input_snapshot as module

    # stage_input obtains the shared constant at call time.
    monkeypatch.setattr("mobile_audit.hybrid_analysis.MAX_INPUT_DETAILS", 1)
    target = tmp_path / "new-input"
    target.mkdir()
    (target / "main.dart").write_text("void main() {}")
    (target / "libapp.so").write_bytes(b"new-aot-never-read")
    (target / "main.hbc").write_bytes(b"new-bytecode-never-read")
    (target / "other.hbc").symlink_to(target / "main.hbc")
    original_open = module.os.open

    def open_source_only(path, *args, **kwargs):
        assert str(path) not in {"libapp.so", "main.hbc", "other.hbc"}, "compiled bytes must not be opened"
        return original_open(path, *args, **kwargs)

    monkeypatch.setattr(module.os, "open", open_source_only)
    snapshot = stage_input(target, tmp_path / "new-staged")
    assert (tmp_path / "new-staged/main.dart").exists()
    assert not (tmp_path / "new-staged/libapp.so").exists()
    assert not (tmp_path / "new-staged/main.hbc").exists()
    assert snapshot["files"] == 1
    assert snapshot["hybrid_inputs"][0]["path"] == "libapp.so"
    assert snapshot["hybrid_inputs_truncated"]
    assert not snapshot["hybrid_input_inventory_complete"]


@pytest.mark.parametrize(
    "path", ["MyAppTests/Test.swift", "ios/MyAppUITests/Test.swift", "My-AppTests/Info.plist"]
)
def test_xcode_named_test_targets_receive_low_priority(path):
    assert staging_tier(Path(path)) == 3


@pytest.mark.parametrize(
    "path",
    [
        "MyAppTestsSupport/App.swift",
        "LatestResults/App.swift",
        "protests/App.swift",
        "Contest/App.swift",
        "BusinessTests/Checkout.swift",
        "AppTests/Helpers.swift",
    ],
)
def test_test_like_production_names_keep_priority(path):
    assert staging_tier(Path(path)) == 0


def test_repeated_uppercase_production_name_does_not_trigger_test_heuristic():
    # Avoid nested ambiguous repetitions on long component names.
    assert staging_tier(Path("My" + "A" * 20_000 + "TestsSupport/App.swift")) == 0


def test_bundle_staging_priority_and_xcode_budget_do_not_delete_inputs(tmp_path, monkeypatch):
    import mobile_audit.input_snapshot as module

    target = tmp_path / "new-source"
    (target / "MyAppTests").mkdir(parents=True)
    (target / "MyAppTests/Test.swift").write_text("func testExample() {}")
    (target / "App.swift").write_text("func run() {}")
    (target / "main.bundle").write_text("const x = 1;")
    assert staging_rank(Path("main.bundle")) == (0, 2)
    monkeypatch.setattr(module, "MAX_FILES", 2)
    snapshot = stage_input(target, tmp_path / "new-copy")
    assert (tmp_path / "new-copy/App.swift").exists()
    assert (tmp_path / "new-copy/main.bundle").exists()
    assert snapshot["omitted"]["tests"]["files"] == 1
    assert (target / "MyAppTests/Test.swift").exists()
