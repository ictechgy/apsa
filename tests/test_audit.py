import json
import plistlib
import zipfile

import pytest

from mobile_audit.audit import compare, correlate, in_cve_range, scan
from mobile_audit.inputs import inspect_target, parse_dependencies
from mobile_audit.output import assistant_context, sarif


def test_real_binary_android_manifest_and_dex(store, apk):
    report = scan(store, apk)
    assert report["inventory"]["package"] == "org.t0t0.androguard.test"
    assert report["inventory"]["platforms"] == ["android"]
    assert report["inventory"]["files_scanned"] == 3
    assert any(c["state"] == "not-run" and c["method"] == "source-pattern" for c in report["coverage"])
    assert (
        report["inventory"]["fingerprint"]
        == "e79de7f2597a64b618984cbae941f20dbdd8bc4b97a9cc39165a98daa9181b89"
    )


def test_ipa_binary_plist_and_ats(store, tmp_path):
    path = tmp_path / "App.ipa"
    plist = {
        "CFBundleIdentifier": "com.example.ios",
        "CFBundleURLTypes": [{"CFBundleURLSchemes": ["example"]}],
        "NSAppTransportSecurity": {"NSAllowsArbitraryLoads": True},
    }
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("Payload/App.app/Info.plist", plistlib.dumps(plist, fmt=plistlib.FMT_BINARY))
    report = scan(store, path)
    assert report["inventory"]["package"] == "com.example.ios"
    assert report["inventory"]["deep_links"][0]["scheme"] == "example"
    assert report["findings"][0]["rule_id"] == "IOS-ATS"
    assert report["findings"][0]["status"] == "configuration-confirmed"


def test_android_data_elements_merge_within_each_intent_filter(tmp_path):
    (tmp_path / "AndroidManifest.xml").write_text(
        """<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.example.app"><application><activity android:name=".Main"><intent-filter><action android:name="android.intent.action.VIEW"/><data android:scheme="a" android:host="one.example"/><data android:scheme="b"/><data android:host="two.example" android:port="8080"/><data android:pathPrefix="/private"/></intent-filter></activity></application></manifest>"""
    )
    inventory, _ = inspect_target(tmp_path)
    links = inventory["deep_links"]
    assert {(x["scheme"], x["host"]) for x in links} == {
        ("a", "one.example"),
        ("a", "two.example"),
        ("b", "one.example"),
        ("b", "two.example"),
    }
    assert all(x["path"] == "/private" and x["path_kind"] == "pathPrefix" for x in links)
    assert next(x for x in links if x["host"] == "two.example")["port"] == "8080"


def test_archive_traversal_is_rejected_without_extraction(store, tmp_path):
    path = tmp_path / "bad.apk"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("../stolen.xml", "x")
    with pytest.raises(ValueError, match="Unsafe archive"):
        scan(store, path)
    assert not (tmp_path.parent / "stolen.xml").exists()


def test_source_rules_fixed_variant_and_comments(store, demo):
    before = scan(store, demo)
    assert "WEBVIEW-SSL-BYPASS" in {f["rule_id"] for f in before["findings"]}
    assert all(f["status"] != "runtime-confirmed" for f in before["findings"])
    (demo / "MainActivity.kt").write_text("""class Test {
    // fun onReceivedSslError(handler: Any) { handler.proceed() }
    val page = "https://trusted.example"
    fun onReceivedSslError(handler: Any) { handler.cancel() }
    fun display() { webView.loadUrl(page) }
}""")
    after = scan(store, demo)
    assert "WEBVIEW-SSL-BYPASS" not in {f["rule_id"] for f in after["findings"]}
    delta = compare(store, before["id"], after["id"])
    assert any(f["rule_id"] == "WEBVIEW-SSL-BYPASS" for f in delta["no_longer_observed"])
    assert "not proof" in delta["note"]


def test_symlink_source_is_not_followed(store, tmp_path):
    outside = tmp_path / "outside.kt"
    outside.write_text('Log.d("password", password)')
    project = tmp_path / "source"
    project.mkdir()
    (project / "safe.kt").write_text("class Safe {}")
    (project / "link.kt").symlink_to(outside)
    report = scan(store, project)
    assert report["inventory"]["files_scanned"] == 1
    assert not report["findings"]


def test_dependencies_declared_unknown_and_resolved():
    text = b'implementation("a:b:1.2.3")\nimplementation("c:d:$version")'
    values = parse_dependencies("build.gradle.kts", text)
    assert [(v["version"], v["confidence"]) for v in values] == [
        ("1.2.3", "declared"),
        ("$version", "unknown"),
    ]
    values = parse_dependencies(
        "gradle/libs.versions.toml", b'[versions]\nx="2.0"\n[libraries]\nx={module="a:b",version.ref="x"}'
    )
    assert values[0]["name"] == "a:b" and values[0]["version"] == "2.0"
    pins = {
        "pins": [
            {"identity": "foo", "location": "https://github.com/a/foo.git", "state": {"version": "3.0.0"}}
        ]
    }
    assert parse_dependencies("Package.resolved", json.dumps(pins).encode())[0]["ecosystem"] == "SwiftURL"


def test_osv_match_does_not_follow_different_dependency_version(demo):
    inventory, _ = inspect_target(demo)
    dep = inventory["dependencies"][0]
    record = {
        "id": "CVE-2025-12345",
        "source": "osv",
        "title": "Example",
        "query_match": dep,
        "references": [],
    }
    result, _ = correlate(inventory, [record])
    assert result[0]["status"] == "candidate"
    assert result[0]["reachability"] == "unknown"
    inventory["dependencies"][0] = dict(dep, version="99.0.0")
    assert correlate(inventory, [record])[0] == []


def test_os_environment_never_inferred_from_target_sdk(demo):
    inventory, _ = inspect_target(demo)
    record = {
        "id": "CVE-2026-12345",
        "source": "android",
        "platform": "android",
        "title": "System issue",
        "fixed_patch_level": "2026-09-05",
        "updated_aosp_versions": "14, 15, 16",
        "references": [],
    }
    assert correlate(inventory, [record])[1][0]["state"] == "device-info-required"
    env = {"platform": "android", "version": "16", "security_patch": "2026-09-05"}
    assert correlate(inventory, [record], env)[1][0]["state"] == "vendor-patch-level-satisfied"
    env["security_patch"] = "2026-08-05"
    assert correlate(inventory, [record], env)[1][0]["state"] == "potentially-affected"


def test_unknown_cna_ranges_stay_unknown():
    assert (
        in_cve_range(
            "18.5",
            {
                "defaultStatus": "unaffected",
                "versions": [
                    {"version": "n/a", "lessThan": "18.6", "status": "affected", "versionType": "custom"}
                ],
            },
        )
        is None
    )
    assert (
        in_cve_range(
            "18.5",
            {
                "versions": [
                    {"version": "18.0", "lessThan": "18.6", "status": "affected", "versionType": "semver"}
                ]
            },
        )
        is True
    )


def test_context_omits_source_excerpts_and_sarif_preserves_status(store, demo):
    report = scan(store, demo)
    context = assistant_context(report)
    assert "excerpt" not in json.dumps(context)
    exported = sarif(report)
    assert exported["version"] == "2.1.0"
    assert all("status" in r["properties"] for r in exported["runs"][0]["results"])
