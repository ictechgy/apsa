"""Source trees over the staging budgets are staged code first and audited partially, not refused."""

from __future__ import annotations

import time
from pathlib import Path

import pytest

from mobile_audit import input_snapshot
from mobile_audit.audit import scan
from mobile_audit.input_snapshot import TIERS, stage_input, staging_tier
from mobile_audit.output import assistant_context, sarif
from mobile_audit.policy import evaluate
from mobile_audit.rules import strip_comments, strip_xml_comments


def tree(root: Path) -> Path:
    (root / "app/src/main/java/com/example").mkdir(parents=True)
    (root / "app/src/main/AndroidManifest.xml").write_text(
        '<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.example.big">'
        "<application /></manifest>"
    )
    (root / "app/src/main/java/com/example/Main.kt").write_text("class Main\n" * 20)
    (root / "app/src/test/java/com/example").mkdir(parents=True)
    (root / "app/src/test/java/com/example/MainTest.kt").write_text("class MainTest\n" * 20)
    for language in ("fr", "de", "it"):
        values = root / f"app/src/main/res/values-{language}"
        values.mkdir(parents=True)
        (values / "strings.xml").write_text(
            "<resources>" + "<string name='a'>l\\'app</string>" * 40 + "</resources>"
        )
    (root / "app/src/main/res/values").mkdir(parents=True)
    (root / "app/src/main/res/values/strings.xml").write_text(
        "<resources><string name='a'>app</string></resources>"
    )
    return root


def test_staging_tiers():
    def kind(path):
        return TIERS[staging_tier(Path(path))]

    for path in (
        "app/src/main/java/A.kt",
        "app/src/main/AndroidManifest.xml",
        "app/src/main/res/xml/network_security_config.xml",
        "app/build.gradle.kts",
        "App/Info.plist",
        "lib/main.dart",
        "src/App.ts",
        "package-lock.json",
        "app/google-services.json",
        "app/src/main/res/xml-v25/shortcuts.xml",
        "sbom.json",
        "app/bom.cdx.json",
    ):
        assert kind(path) == "code_and_config", path
    for path in ("app/src/main/res/layout/main.xml", "app/src/main/res/values/strings.xml", "config.yaml"):
        assert kind(path) == "other_text", path
    assert kind("app/src/main/res/values-fr/strings.xml") == "localized_values"
    for path in (
        "app/src/test/java/ATest.kt",
        "app/src/androidTest/java/ATest.kt",
        "shared/src/commonTest/kotlin/ATest.kt",
        "AppTests/AppTests.swift",
        "app/src/test/res/values-fr/strings.xml",
        "My-AppTests/AppTests.swift",
        "test/java/ATest.kt",
        "src/__tests__/app.ts",
        "src/app.test.ts",
        "mobile/test/widget_test.dart",
        "integration_test/app_test.dart",
    ):
        assert kind(path) == "tests", path


def test_over_budget_trees_keep_code_and_omit_translations_first(tmp_path, monkeypatch):
    target = tree(tmp_path / "input")
    sizes = {path.relative_to(target): path.stat().st_size for path in target.rglob("*") if path.is_file()}
    localized = sum(size for path, size in sizes.items() if TIERS[staging_tier(path)] == "localized_values")
    # Room for everything but the three translation files; the smaller test file still fits after them.
    monkeypatch.setattr(input_snapshot, "MAX_SOURCE_TOTAL", sum(sizes.values()) - localized + 10)
    staged = tmp_path / "staged"
    result = stage_input(target, staged)
    assert (staged / "app/src/main/java/com/example/Main.kt").exists()
    assert (staged / "app/src/main/res/values/strings.xml").exists()
    assert (staged / "app/src/test/java/com/example/MainTest.kt").exists()
    assert not list(staged.rglob("values-*/strings.xml"))
    assert result["omitted"] == {"localized_values": {"files": 3, "bytes": localized}}
    assert result["app_scope_complete"] is True
    assert result["warnings"] == [
        "Input staging omitted 3 file(s) of localized or qualified Android values "
        f"({input_snapshot.size_label(localized)}); coverage partial"
    ]


def test_file_count_budget_prefers_app_code(tmp_path, monkeypatch):
    target = tree(tmp_path / "input")
    monkeypatch.setattr(input_snapshot, "MAX_FILES", 2)
    staged = tmp_path / "staged"
    result = stage_input(target, staged)
    assert sorted(path.name for path in staged.rglob("*") if path.is_file()) == [
        "AndroidManifest.xml",
        "Main.kt",
    ]
    assert set(result["omitted"]) == {"other_text", "localized_values", "tests"}
    # Base resources are shipped text, so rules that look not-applicable may not be.
    assert result["app_scope_complete"] is False


def test_partial_audit_instead_of_refusal(store, tmp_path, monkeypatch):
    monkeypatch.setenv("APSA_PARSER_SANDBOX", "off")
    target = tree(tmp_path / "input")
    monkeypatch.setattr(input_snapshot, "MAX_FILES", 3)
    report = scan(store, target)
    snapshot = report["inventory"]["input_snapshot"]
    assert snapshot["partial"] is True and snapshot["files"] == 3
    assert set(snapshot["omitted"]) == {"localized_values", "tests"} and snapshot["app_scope_complete"]
    assert any("Input staging omitted" in warning for warning in report["inventory"]["warnings"])
    assert report["inventory"]["partial"] is True
    assert assistant_context(report)["input"]["input_snapshot"] == snapshot
    run = sarif(report)["runs"][0]
    assert run["properties"]["inputSnapshot"] == snapshot
    first = run["invocations"][0]["toolExecutionNotifications"][0]["message"]["text"]
    assert first.startswith("Input staging left files out of this audit (3 localized_values, 1 tests files)")


def test_escaped_apostrophes_in_prose_do_not_backtrack():
    # The 1.5.0 pattern took seconds on this shape (double-quoted attributes, no closing apostrophe).
    prose = (
        "<resources>" + "<string name=\"s\">l\\'application d\\'un\\'</string>\n" * 20_000 + "</resources>"
    )
    started = time.monotonic()
    assert strip_comments(prose) == prose
    assert time.monotonic() - started < 2


@pytest.mark.parametrize(
    ("text", "strip"),
    [
        ("x " + "\\'" * 20_000 + "\n", strip_comments),
        ("'" + "\\'" * 20_000 + "\\\n", strip_comments),
        ('a\\"' * 20_000 + "\\", strip_comments),
        ('"a\n' * 20_000, strip_comments),
        ("/* a\n" * 20_000, strip_comments),
        ("<!-- a\n" * 20_000, strip_xml_comments),
    ],
)
def test_unterminated_literals_and_comments_are_linear(text, strip):
    started = time.monotonic()
    cleaned = strip(text)
    assert len(cleaned) == len(text) and cleaned.count("\n") == text.count("\n")
    assert time.monotonic() - started < 2


def test_comment_stripping_keeps_literals_and_blanks_comments():
    assert strip_comments('val c = \'"\' // x\nval s = "a//b" /* c */\n') == (
        'val c = \'"\'     \nval s = "a//b"        \n'
    )
    # Triple-quoted strings keep their // and /* text; the code after them is still cleaned.
    assert strip_comments("s = '''\na /* b\n'''\nx // y\n") == "s = '''\na /* b\n'''\nx     \n"
    assert strip_comments('q = """a "b" // c\n"""\n') == 'q = """a "b" // c\n"""\n'
    # A /* with no */ after it (here a JS regex literal) stays text, so later code is still read.
    js = "const re = /\\/*/;\nconsole.log('token', password) // log\n"
    assert strip_comments(js) == "const re = /\\/*/;\nconsole.log('token', password)       \n"
    assert strip_comments("/* a */ x /* b") == "        x /* b"
    # The same holds for a " with no closing quote: later comments are still cleaned.
    assert (
        strip_comments('s.replace(/"/g, x) // a\ny = 1 /* b */\n')
        == 's.replace(/"/g, x)     \ny = 1        \n'
    )


def test_xml_rules_ignore_xml_comments(store, tmp_path, monkeypatch):
    monkeypatch.setenv("APSA_PARSER_SANDBOX", "off")
    root = tmp_path / "xml"
    root.mkdir()
    (root / "AndroidManifest.xml").write_text(
        '<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.example.x">'
        "<application>"
        '<!-- <meta-data android:name="android.webkit.WebView.EnableSafeBrowsing" android:value="false" /> -->'
        '<meta-data android:name="https://example.com/x" android:value="//not a comment" />'
        "</application></manifest>"
    )
    report = scan(store, root)
    assert not [f for f in report["findings"] if f["rule_id"] == "WEBVIEW-SAFE-BROWSING-OFF"]


def test_entry_and_depth_budgets_stop_reading_instead_of_refusing(tmp_path, monkeypatch):
    target = tmp_path / "input"
    # More deep directories than the 128-warning error budget still yield one warning, and the
    # skipped directories leave the app scope unknown.
    for branch in range(200):
        deep = target / f"b{branch}" / "/".join(["d"] * 66)
        deep.mkdir(parents=True)
        (deep / "Deep.kt").write_text("class Deep")
    (target / "Main.kt").write_text("class Main")
    result = stage_input(target, tmp_path / "staged")
    assert (tmp_path / "staged/Main.kt").exists()
    assert not list((tmp_path / "staged").rglob("Deep.kt"))
    assert len(result["warnings"]) == 1
    assert result["warnings"][0].startswith("200 directories deeper than 64 levels not staged")
    assert result["app_scope_complete"] is False


def test_entry_budget_reads_what_it_can(tmp_path, monkeypatch):
    target = tmp_path / "input"
    target.mkdir()
    (target / "Main.kt").write_text("class Main")
    for index in range(10):
        (target / f"image{index}.png").write_bytes(b"png")
    (target / "zz.kt").write_text("class Last")
    monkeypatch.setattr(input_snapshot, "MAX_ENTRIES", 4)
    result = stage_input(target, tmp_path / "staged")
    assert any("entry budget reached (4 entries, in path order)" in warning for warning in result["warnings"])
    assert result["app_scope_complete"] is False
    # Entries are read in name order on every filesystem, so the same files are cut.
    assert (tmp_path / "staged/Main.kt").exists() and not (tmp_path / "staged/zz.kt").exists()

    class Reversed:
        def __init__(self, fd):
            self.entries = sorted(original(fd), key=lambda e: e.name, reverse=True)

        def __enter__(self):
            return iter(self.entries)

        def __exit__(self, *_):
            return False

    original = input_snapshot.os.scandir
    monkeypatch.setattr(input_snapshot.os, "scandir", Reversed)
    reverse = stage_input(target, tmp_path / "reverse")
    assert (tmp_path / "reverse/Main.kt").exists() and not (tmp_path / "reverse/zz.kt").exists()
    assert reverse["files"] == result["files"]


def test_oversized_files_share_one_warning(tmp_path, monkeypatch):
    target = tmp_path / "input"
    target.mkdir()
    for index in range(200):
        (target / f"data{index}.json").write_text("x" * 64)
    (target / "Main.kt").write_text("class Main")
    monkeypatch.setattr(input_snapshot, "MAX_FILE", 32)
    result = stage_input(target, tmp_path / "staged")
    assert (tmp_path / "staged/Main.kt").exists()
    assert result["omitted"] == {"other_text": {"files": 200, "bytes": 200 * 64}}
    assert result["warnings"][0].startswith(
        "200 file(s) over the 1 KiB file limit not staged (first: data0.json)"
    )
    assert len(result["warnings"]) == 2


def test_a_file_replaced_after_listing_is_left_out_unread(tmp_path, monkeypatch):
    target = tmp_path / "input"
    target.mkdir()
    (target / "Main.kt").write_text("class Main")
    # The reopen lands on a different file of the same name (an editor's save or a swapped store).
    (tmp_path / "Main.kt").write_text("class Elsewhere")
    elsewhere = input_snapshot.os.open(tmp_path, input_snapshot.os.O_RDONLY)
    monkeypatch.setattr(
        input_snapshot, "open_parent", lambda root, directory: input_snapshot.os.dup(elsewhere)
    )
    try:
        result = stage_input(target, tmp_path / "staged")
    finally:
        input_snapshot.os.close(elsewhere)
    assert result["files"] == 0 and not (tmp_path / "staged/Main.kt").exists()
    assert result["app_scope_complete"] is False
    assert result["warnings"][0] == (
        "Source staging could not read or stage 1 entry (first: Main.kt: replaced during staging); coverage partial"
    )


def test_copy_errors_omit_the_file_not_the_audit(tmp_path, monkeypatch):
    import errno

    target = tmp_path / "input"
    target.mkdir()
    for name in ("A.kt", "B.kt", "C.kt"):
        (target / name).write_text(f"class {name[0]}")
    original = input_snapshot.os.read
    calls = {"n": 0}

    def failing(fd, size):
        calls["n"] += 1
        if calls["n"] == 1:
            raise OSError(errno.EIO, "Input/output error")
        return original(fd, size)

    monkeypatch.setattr(input_snapshot.os, "read", failing)
    result = stage_input(target, tmp_path / "staged")
    assert result["files"] == 2 and not (tmp_path / "staged/A.kt").exists()
    assert result["omitted"] == {"code_and_config": {"files": 1, "bytes": len("class A")}}
    assert result["app_scope_complete"] is False
    assert result["warnings"][0] == (
        "Source staging could not read or stage 1 entry (first: A.kt: OSError); coverage partial"
    )


def test_unreadable_files_share_one_warning(tmp_path):
    import os

    target = tmp_path / "input"
    target.mkdir()
    for index in range(130):
        locked = target / f"Locked{index:03}.kt"
        locked.write_text("class Locked")
        locked.chmod(0)
    (target / "Main.kt").write_text("class Main")
    try:
        if os.access(target / "Locked000.kt", os.R_OK):
            pytest.skip("running with privileges that ignore file modes")
        result = stage_input(target, tmp_path / "staged")
    finally:
        for locked in target.glob("Locked*.kt"):
            locked.chmod(0o600)
    assert (tmp_path / "staged/Main.kt").exists()
    assert result["warnings"][0].startswith(
        "Source staging could not read or stage 130 entries (first: Locked000.kt"
    )
    assert result["omitted"]["code_and_config"]["files"] == 130 and result["app_scope_complete"] is False


def test_configuration_and_app_code_go_before_vendored_code(tmp_path, monkeypatch):
    target = tmp_path / "input"
    for path in (
        ".build/checkouts/swift-nio/Sources/Channel.swift",
        "Vendor/Lib/Lib.m",
        "THIRDPARTY/Kit/Kit.swift",
        "MyApp/AppDelegate.swift",
        "MyApp/Controllers/Home.swift",
        "MyApp/Info.plist",
        "MyApp/Bridging.h",
    ):
        (target / path).parent.mkdir(parents=True, exist_ok=True)
        (target / path).write_text("x")
    monkeypatch.setattr(input_snapshot, "MAX_FILES", 3)
    staged = tmp_path / "staged"
    stage_input(target, staged)
    assert sorted(p.relative_to(staged).as_posix() for p in staged.rglob("*") if p.is_file()) == [
        "MyApp/AppDelegate.swift",
        "MyApp/Controllers/Home.swift",
        "MyApp/Info.plist",
    ]


def test_native_code_goes_before_web_assets(tmp_path, monkeypatch):
    target = tmp_path / "input"
    for path in (
        "app/src/main/assets/www/lib/angular.js",
        "app/src/main/assets/www/app.js",
        "app/src/main/java/com/example/Main.kt",
        "app/src/main/AndroidManifest.xml",
        "lib/main.dart",
    ):
        (target / path).parent.mkdir(parents=True, exist_ok=True)
        (target / path).write_text("x")
    monkeypatch.setattr(input_snapshot, "MAX_FILES", 3)
    staged = tmp_path / "staged"
    stage_input(target, staged)
    assert sorted(p.relative_to(staged).as_posix() for p in staged.rglob("*") if p.is_file()) == [
        "app/src/main/AndroidManifest.xml",
        "app/src/main/java/com/example/Main.kt",
        "lib/main.dart",
    ]


def test_unreadable_directory_leaves_the_app_scope_unknown(tmp_path):
    import os

    target = tmp_path / "input"
    (target / "android").mkdir(parents=True)
    (target / "android/Main.kt").write_text("class Main")
    ios = target / "ios"
    ios.mkdir()
    (ios / "View.swift").write_text("let web = UIWebView()")
    ios.chmod(0)
    try:
        if os.access(ios, os.R_OK):
            pytest.skip("running with privileges that ignore directory modes")
        result = stage_input(target, tmp_path / "staged")
    finally:
        ios.chmod(0o700)
    assert result["app_scope_complete"] is False
    assert result["warnings"] == [
        "Source staging could not read or stage 1 entry (first: ios: PermissionError); coverage partial"
    ]


def test_ast_budget_analyzes_shipped_code_before_tests(monkeypatch):
    from mobile_audit import source_analysis

    test_code = "class ATest { fun t() { val x = 1 } }\n" * 50
    main_code = "class Main { fun m() { val y = 2 } }\n"
    monkeypatch.setattr(source_analysis, "MAX_AST_TOTAL", len(main_code) + 1)
    result = source_analysis.analyze_sources(
        [("app/src/androidTest/java/ATest.kt", test_code), ("app/src/main/java/Main.kt", main_code)]
    )
    assert any("skipped app/src/androidTest/java/ATest.kt" in warning for warning in result["warnings"])
    assert not any("skipped app/src/main/java/Main.kt" in warning for warning in result["warnings"])


def test_omitted_platform_cannot_pass_required_rules(store, tmp_path, monkeypatch):
    monkeypatch.setenv("APSA_PARSER_SANDBOX", "off")
    target = tmp_path / "mixed"
    android = target / "android/app/src/main"
    (android / "java/com/example").mkdir(parents=True)
    (android / "AndroidManifest.xml").write_text(
        '<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.example.mixed">'
        "<application /></manifest>"
    )
    (android / "java/com/example/Main.kt").write_text("class Main\n")
    ios = target / "ios/App"
    ios.mkdir(parents=True)
    (ios / "Info.plist").write_text(
        '<?xml version="1.0" encoding="UTF-8"?><plist version="1.0"><dict>'
        "<key>CFBundleIdentifier</key><string>com.example.mixed</string>"
        "<key>NSAppTransportSecurity</key><dict><key>NSAllowsArbitraryLoads</key><true/></dict>"
        "</dict></plist>"
    )
    (ios / "View.swift").write_text("import UIKit\nlet web = UIWebView()\n")
    full = scan(store, target)
    assert "IOS-UIWEBVIEW" in {f["rule_id"] for f in full["findings"]}
    # Only the Android manifest fits: the iOS app is never seen.
    monkeypatch.setattr(input_snapshot, "MAX_FILES", 1)
    report = scan(store, target)
    assert report["inventory"]["input_snapshot"]["app_scope_complete"] is False
    assert "IOS-UIWEBVIEW" not in {f["rule_id"] for f in report["findings"]}
    assert {c["state"] for c in report["coverage"] if c["rule_id"] == "IOS-UIWEBVIEW"} == {"partial"}
    assert any(c["rule_id"] == "DEPENDENCY-CVE" and c["state"] == "partial" for c in report["coverage"])
    policy = {"schema_version": 1, "fail_on_partial": False, "required_rules": ["IOS-UIWEBVIEW"]}
    decision = evaluate(report, policy)
    assert decision["state"] == "incomplete" and decision["exit_code"] == 3
    # A supplied SBOM is the dependency source, so omitted lockfiles do not make it partial.
    sbom = tmp_path / "sbom.json"
    sbom.write_text('{"bomFormat": "CycloneDX", "specVersion": "1.5", "components": []}')
    with_sbom = scan(store, target, sbom=sbom)
    assert not any(
        c["rule_id"] == "DEPENDENCY-CVE" and c["state"] == "partial" for c in with_sbom["coverage"]
    )
