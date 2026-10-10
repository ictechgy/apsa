"""Source trees over the staging budgets are staged code first and audited partially, not refused."""

from __future__ import annotations

import time
from pathlib import Path

from mobile_audit import input_snapshot
from mobile_audit.audit import scan
from mobile_audit.input_snapshot import stage_input, staging_tier
from mobile_audit.rules import strip_comments


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
    assert staging_tier(Path("app/src/main/java/A.kt")) == 0
    assert staging_tier(Path("app/src/main/AndroidManifest.xml")) == 0
    assert staging_tier(Path("app/src/main/res/xml/network_security_config.xml")) == 0
    assert staging_tier(Path("app/build.gradle.kts")) == 0
    assert staging_tier(Path("App/Info.plist")) == 0
    assert staging_tier(Path("app/src/test/java/ATest.kt")) == 1
    assert staging_tier(Path("app/src/androidTest/java/ATest.kt")) == 1
    assert staging_tier(Path("AppTests/AppTests.swift")) == 1
    assert staging_tier(Path("app/src/main/res/layout/main.xml")) == 1
    assert staging_tier(Path("app/src/main/res/values/strings.xml")) == 1
    assert staging_tier(Path("app/src/main/res/values-fr/strings.xml")) == 2


def test_over_budget_trees_keep_code_and_omit_translations_first(tmp_path, monkeypatch):
    target = tree(tmp_path / "input")
    sizes = {path.relative_to(target): path.stat().st_size for path in target.rglob("*") if path.is_file()}
    code = sum(size for path, size in sizes.items() if staging_tier(path) == 0)
    others = sum(size for path, size in sizes.items() if staging_tier(path) == 1)
    # Room for code and tests but not for the three translation files.
    monkeypatch.setattr(input_snapshot, "MAX_SOURCE_TOTAL", code + others + 10)
    staged = tmp_path / "staged"
    result = stage_input(target, staged)
    assert (staged / "app/src/main/java/com/example/Main.kt").exists()
    assert (staged / "app/src/test/java/com/example/MainTest.kt").exists()
    assert not list(staged.rglob("values-*/strings.xml"))
    assert result["omitted"] == {
        "localized or qualified Android values": {
            "files": 3,
            "bytes": sum(size for path, size in sizes.items() if staging_tier(path) == 2),
        }
    }
    assert result["warnings"] == [
        f"Input staging budget reached: 3 file(s) of localized or qualified Android values "
        f"({result['omitted']['localized or qualified Android values']['bytes'] / 1024 / 1024:.1f} MiB) "
        "omitted; coverage partial"
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
    assert set(result["omitted"]) == {
        "test code and other text resources",
        "localized or qualified Android values",
    }


def test_partial_audit_instead_of_refusal(store, tmp_path, monkeypatch):
    monkeypatch.setenv("APSA_PARSER_SANDBOX", "off")
    target = tree(tmp_path / "input")
    monkeypatch.setattr(input_snapshot, "MAX_FILES", 3)
    report = scan(store, target)
    snapshot = report["inventory"]["input_snapshot"]
    assert snapshot["partial"] is True and snapshot["files"] == 3
    assert "localized or qualified Android values" in snapshot["omitted"]
    assert any("Input staging budget reached" in warning for warning in report["inventory"]["warnings"])
    assert report["inventory"]["partial"] is True


def test_escaped_apostrophes_in_prose_do_not_backtrack():
    prose = "<resources>" + "<string name='s'>l\\'application d\\'un\\'</string>\n" * 20_000 + "</resources>"
    started = time.monotonic()
    assert strip_comments(prose) == prose
    assert time.monotonic() - started < 2


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
    # More deep directories than the 128-warning error budget still yield one warning.
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


def test_entry_budget_reads_what_it_can(tmp_path, monkeypatch):
    target = tmp_path / "input"
    target.mkdir()
    for index in range(10):
        (target / f"image{index}.png").write_bytes(b"png")
    (target / "Main.kt").write_text("class Main")
    monkeypatch.setattr(input_snapshot, "MAX_ENTRIES", 4)
    result = stage_input(target, tmp_path / "staged")
    assert any("entry budget reached (4 entries)" in warning for warning in result["warnings"])
