"""Fresh in-memory source/configuration text; no retained package artifacts."""

from __future__ import annotations

import pytest

from mobile_audit.rules import static_checks


@pytest.mark.parametrize(
    "kind,platform,native_path,native_text,rule_id",
    [
        (
            "apk",
            "android",
            "AndroidManifest.xml",
            '<manifest><meta-data android:name="android.webkit.WebView.EnableSafeBrowsing" '
            'android:value="false" /></manifest>',
            "WEBVIEW-SAFE-BROWSING-OFF",
        ),
        (
            "ipa",
            "ios",
            "Payload/New.app/Debug.swift",
            "let view = UIWebView()",
            "IOS-UIWEBVIEW",
        ),
    ],
)
def test_packaged_native_plaintext_does_not_claim_source_inspection(
    kind,
    platform,
    native_path,
    native_text,
    rule_id,
):
    inventory = {"input_kind": kind, "platforms": [platform], "android_config": [], "ios_config": []}
    findings, coverage = static_checks(inventory, [(native_path, native_text)])
    row = next(item for item in coverage if item["rule_id"] == rule_id)
    assert row["state"] == "not-run"
    assert not any(item["rule_id"] == rule_id for item in findings)
    assert "Native source and manifest members" in row["note"]


@pytest.mark.parametrize("kind", ["apk", "ipa"])
def test_packaged_hybrid_text_remains_inspected(kind):
    inventory = {"input_kind": kind, "platforms": ["android", "ios"], "android_config": [], "ios_config": []}
    sources = [("assets/new.js", 'console.log("token:", token);')]
    findings, coverage = static_checks(inventory, sources)
    assert any(item["rule_id"] == "STORAGE-SENSITIVE-LOG" for item in findings)
    assert next(item for item in coverage if item["rule_id"] == "STORAGE-SENSITIVE-LOG")["state"] == "checked"


def test_source_manifest_keeps_safe_browsing_detection():
    inventory = {"input_kind": "source", "platforms": ["android"], "android_config": [], "ios_config": []}
    sources = [
        (
            "AndroidManifest.xml",
            '<meta-data android:name="android.webkit.WebView.EnableSafeBrowsing" android:value="false" />',
        )
    ]
    findings, coverage = static_checks(inventory, sources)
    assert any(item["rule_id"] == "WEBVIEW-SAFE-BROWSING-OFF" for item in findings)
    assert (
        next(item for item in coverage if item["rule_id"] == "WEBVIEW-SAFE-BROWSING-OFF")["state"]
        == "checked"
    )


def test_direct_package_parser_separates_native_text_from_bundled_js(tmp_path):
    import zipfile

    from mobile_audit._parser_worker import analyze

    target = tmp_path / "new-plaintext.apk"
    manifest = (
        '<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="org.synthetic.new">'
        '<application><meta-data android:name="android.webkit.WebView.EnableSafeBrowsing" '
        'android:value="false" /></application></manifest>'
    )
    with zipfile.ZipFile(target, "x") as archive:
        archive.writestr("AndroidManifest.xml", manifest)
        archive.writestr("assets/Native.java", "view.setSafeBrowsingEnabled(false);")
        archive.writestr("assets/new.js", 'console.log("token:", token);')
    report = analyze(target, None)
    assert report["inventory"]["input_kind"] == "apk"
    checks = {item["rule_id"]: item["state"] for item in report["coverage"]}
    assert checks["WEBVIEW-SAFE-BROWSING-OFF"] == "not-run"
    assert checks["STORAGE-SENSITIVE-LOG"] == "checked"
    assert not any(item["rule_id"] == "WEBVIEW-SAFE-BROWSING-OFF" for item in report["findings"])
    assert any(item["rule_id"] == "STORAGE-SENSITIVE-LOG" for item in report["findings"])
