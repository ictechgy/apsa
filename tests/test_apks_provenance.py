"""APK-set aggregation distinguishes semantic origins from path provenance."""

import zipfile
from xml.etree import ElementTree

from mobile_audit.apks_analysis import analyze_apks
from mobile_audit.core import finding, finding_identity
from tests.apks_fixture import DEFAULT_DEVICE, write_split_apks


def test_finding_categories_and_nested_paths_survive_member_aggregation(tmp_path):
    target = tmp_path / "new.apks"
    write_split_apks(target)

    def analyze_member(path, sbom, *, specs):
        with zipfile.ZipFile(path) as archive:
            manifest = ElementTree.fromstring(archive.read("AndroidManifest.xml"))
        inventory = {
            "apps": [
                {
                    "basis": "manifest",
                    "package": "org.synthetic.apks",
                    "version_code": "1",
                    "split": manifest.get("split", ""),
                }
            ],
            "dependencies": [
                {"origin": "META-INF/dependency.properties", "path": "META-INF/dependency.properties"}
            ],
            "deep_links": [{"origin": "AndroidManifest.xml", "scheme": "synthetic"}],
        }
        evidence = [
            {
                "path": "classes.dex",
                "archive_entry": "classes.dex",
                "dependency": {"origin": "META-INF/dependency.properties"},
            }
        ]
        return {
            "inventory": inventory,
            "findings": [
                finding(
                    "BINARY-WEBVIEW-SSL-BYPASS",
                    "Synthetic check",
                    "high",
                    "candidate",
                    evidence,
                    "Review",
                    origin=origin,
                )
                for origin in ("binary", "source-analysis", "quaygate-lint")
            ],
            "coverage": [],
        }

    result = analyze_apks(target, DEFAULT_DEVICE, analyze_member)
    assert {item["origin"] for item in result["findings"]} == {"binary", "source-analysis", "quaygate-lint"}
    for item in result["findings"]:
        prefix = item["apk_set_member"] + "!/"
        evidence = item["evidence"][0]
        assert evidence["path"] == evidence["archive_entry"] == prefix + "classes.dex"
        assert evidence["dependency"]["origin"] == prefix + "META-INF/dependency.properties"
        assert item["id"] == finding_identity(item["rule_id"], item["evidence"])
    for item in result["inventory"]["dependencies"]:
        assert "!/META-INF/dependency.properties" in item["origin"]
        assert item["origin"] == item["path"]
    assert all("!/AndroidManifest.xml" in item["origin"] for item in result["inventory"]["deep_links"])
