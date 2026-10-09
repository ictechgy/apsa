"""CycloneDX SBOM with embedded VEX (1.4)."""

from __future__ import annotations

import json

import pytest

from mobile_audit.audit import scan
from mobile_audit.cli import first_observed, main
from mobile_audit.sbom import cyclonedx, purl

GSON = {"ecosystem": "Maven", "name": "com.google.code.gson:gson", "version": "2.8.8"}


@pytest.mark.parametrize(
    ("dep", "expected"),
    [
        (GSON, "pkg:maven/com.google.code.gson/gson@2.8.8"),
        ({"ecosystem": "npm", "name": "@scope/pkg", "version": "1.0.0"}, "pkg:npm/%40scope/pkg@1.0.0"),
        (
            {"ecosystem": "CocoaPods", "name": "Alamofire", "version": "5.4.0"},
            "pkg:cocoapods/Alamofire@5.4.0",
        ),
        (
            {"ecosystem": "SwiftURL", "name": "https://github.com/apple/swift-nio.git", "version": "2.40.0"},
            "pkg:swift/github.com/apple/swift-nio@2.40.0",
        ),
        ({"ecosystem": "SwiftURL", "name": "swift-nio", "version": "2.40.0"}, None),
        (
            {"ecosystem": "Go", "name": "github.com/gorilla/mux", "version": "v1.8.0"},
            "pkg:golang/github.com/gorilla/mux@v1.8.0",
        ),
        (
            {"ecosystem": "CocoaPods", "name": "GoogleUtilities/Environment", "version": "7.11.0"},
            "pkg:cocoapods/GoogleUtilities@7.11.0#Environment",
        ),
        ({"ecosystem": "Maven", "name": "a:b", "version": ""}, None),
        ({"ecosystem": "Unknown", "name": "x", "version": "1"}, None),
    ],
)
def test_package_urls(dep, expected):
    assert purl(dep) == expected


@pytest.fixture
def project(tmp_path, store, monkeypatch):
    monkeypatch.setenv("APSA_PARSER_SANDBOX", "off")
    app = tmp_path / "app"
    app.mkdir()
    (app / "build.gradle").write_text(
        'plugins { id "com.android.application" }\ndependencies { implementation "com.google.code.gson:gson:2.8.8" }\n'
    )
    (app / "Podfile.lock").write_text("PODS:\n  - Alamofire (5.4.0)\n")
    store.upsert_intel(
        [
            {
                "id": "CVE-2022-25647",
                "source": "osv",
                "title": "gson deserialization",
                "severity": "high",
                "query_match": GSON,
                "references": [],
                "affected": [],
                "known_exploited": False,
            }
        ]
    )
    return app


def test_sbom_lists_dependencies_and_never_decides_exploitability(store, project):
    first = scan(store, project)
    second = scan(store, project)
    bom = cyclonedx(second, first_observed(store, second))
    assert bom["bomFormat"] == "CycloneDX" and bom["specVersion"] == "1.6"
    refs = {c["bom-ref"] for c in bom["components"]}
    assert {"pkg:maven/com.google.code.gson/gson@2.8.8", "pkg:cocoapods/Alamofire@5.4.0"} <= refs
    assert bom["dependencies"] == [{"ref": "app", "dependsOn": [c["bom-ref"] for c in bom["components"]]}]
    [vulnerability] = bom["vulnerabilities"]
    assert vulnerability["id"] == "CVE-2022-25647"
    assert vulnerability["analysis"]["state"] == "in_triage"
    assert vulnerability["affects"] == [{"ref": "pkg:maven/com.google.code.gson/gson@2.8.8"}]
    properties = {p["name"]: p["value"] for p in vulnerability["properties"]}
    assert properties["apsa:first-observed"] == first["created"]
    assert properties["apsa:known-exploited"] == "false"
    assert bom["serialNumber"] == cyclonedx(second)["serialNumber"]
    assert not any(v["id"].startswith(("WEBVIEW", "AST-")) for v in bom["vulnerabilities"])


def test_cli_exports_cyclonedx(tmp_path, store, project, capsys):
    home = str(store.home)
    assert main(["--json", "--home", home, "scan", str(project)]) == 0
    out = tmp_path / "bom.json"
    capsys.readouterr()
    assert (
        main(
            [
                "--json",
                "--home",
                home,
                "reports",
                "export",
                "latest",
                "--format",
                "cyclonedx",
                "--out",
                str(out),
            ]
        )
        == 0
    )
    assert json.loads(out.read_text())["metadata"]["component"]["bom-ref"] == "app"
    assert (
        main(
            [
                "--json",
                "--home",
                home,
                "reports",
                "export",
                "latest",
                "--format",
                "cyclonedx",
                "--out",
                str(out),
                "--sarif-root",
                "x",
            ]
        )
        == 2
    )


def test_first_observed_reads_only_the_exact_target_before_limiting(store, project):
    nested = project / "nested"
    nested.mkdir()
    (nested / "build.gradle").write_text((project / "build.gradle").read_text())
    first = scan(store, project)
    # Reports of a target inside this one are newer and must not crowd out the target's own.
    for _ in range(3):
        scan(store, nested)
    latest = scan(store, project)
    window = first_observed(store, latest, limit=2)
    seen = window["times"]
    assert seen and set(seen.values()) == {first["created"]} and window["complete"] is True
    truncated = first_observed(store, latest, limit=1)
    assert truncated["complete"] is False and truncated["reports"] == 1
    properties = {p["name"]: p["value"] for p in cyclonedx(latest, truncated)["metadata"]["properties"]}
    assert (
        properties["apsa:first-observed-window"]
        == "1 saved reports of this target; older reports were not read"
    )
    assert all(item["target"] == str(project) for item in store.target_reports(str(project)))
    assert [item["id"] for item in store.target_reports(str(project))] == [latest["id"], first["id"]]
