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
        f"({localized / 1024 / 1024:.1f} MiB); coverage partial"
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
    prose = "<resources>" + "<string name='s'>l\\'application d\\'un\\'</string>\n" * 20_000 + "</resources>"
    started = time.monotonic()
    assert strip_comments(prose) == prose
    assert time.monotonic() - started < 2


@pytest.mark.parametrize(
    ("text", "strip"),
    [
        ("x " + "\\'" * 20_000 + "\n", strip_comments),
        ("'" + "\\'" * 20_000 + "\\\n", strip_comments),
        ('a\\"' * 20_000 + "\\", strip_comments),
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
    # An unterminated block comment runs to the end of the file, as compilers read it.
    assert strip_comments("/* open\nval x = 1\n").strip() == ""


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
        "200 file(s) over the 0 MiB file limit not staged (first: data0.json)"
    )
    assert len(result["warnings"]) == 2


def test_reopened_file_must_be_the_listed_file(tmp_path, monkeypatch):
    target = tmp_path / "input"
    target.mkdir()
    (target / "Main.kt").write_text("class Main")
    other = tmp_path / "Other.kt"
    other.write_text("class Other")
    monkeypatch.setattr(
        input_snapshot, "open_relative", lambda root, relative: input_snapshot.os.open(other, 0)
    )
    with pytest.raises(ValueError, match="Input changed during staging"):
        stage_input(target, tmp_path / "staged")


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
    monkeypatch.setattr(input_snapshot, "MAX_FILES", 2)
    report = scan(store, target)
    assert report["inventory"]["input_snapshot"]["app_scope_complete"] is False
    assert "IOS-UIWEBVIEW" not in {f["rule_id"] for f in report["findings"]}
    assert {c["state"] for c in report["coverage"] if c["rule_id"] == "IOS-UIWEBVIEW"} == {"partial"}
    assert any(c["rule_id"] == "DEPENDENCY-CVE" and c["state"] == "partial" for c in report["coverage"])
    policy = {"schema_version": 1, "fail_on_partial": False, "required_rules": ["IOS-UIWEBVIEW"]}
    decision = evaluate(report, policy)
    assert decision["state"] == "incomplete" and decision["exit_code"] == 3
