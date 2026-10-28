"""Input-boundary regressions confirmed by the external whole-source review."""

import datetime as dt
import json
import plistlib
import sys
import zipfile

import pytest

from mobile_audit import _parser_worker as worker
from mobile_audit import inputs
from mobile_audit.platform_checks import _ats_exceptions


@pytest.mark.parametrize(
    "document",
    [
        [],
        "not-an-object",
        {"components": None},
        {"components": {}},
        {"components": [[]]},
        {"components": ["bad"]},
        {"components": [{"purl": []}]},
        {"components": [{"purl": 7}]},
    ],
)
def test_malformed_external_sbom_has_actionable_schema_error(document):
    with pytest.raises(ValueError, match="SBOM"):
        inputs.parse_dependencies("sbom.json", json.dumps(document).encode())


def test_deep_external_sbom_has_actionable_error():
    with pytest.raises(ValueError, match="SBOM.*nesting"):
        inputs.parse_dependencies("sbom.json", b"[" * 20000 + b"0" + b"]" * 20000)


def test_supported_sbom_keeps_exact_coordinates_and_empty_document_is_supported():
    raw = json.dumps(
        {
            "components": [
                {"purl": "pkg:maven/com.example/lib@1.2.3?type=jar"},
                {"purl": "pkg:npm/%40example/lib@2.0.0"},
                {"name": "unversioned"},
            ]
        }
    ).encode()
    assert [
        (d["name"], d["version"], d["confidence"]) for d in inputs.parse_dependencies("sbom.json", raw)
    ] == [("com.example:lib", "1.2.3", "exact"), ("@example/lib", "2.0.0", "exact")]
    assert inputs.parse_dependencies("sbom.json", b"{}") == []


@pytest.mark.parametrize("version", ["1.2.3@aar", "1.2.3:jdk8", "1.2.3:jdk8@jar"])
def test_extended_gradle_coordinates_do_not_claim_exact_query_version(version):
    found = inputs.parse_dependencies("build.gradle", f'implementation "g:a:{version}"'.encode())
    assert found[0]["version"] == version
    assert found[0]["confidence"] == "unknown"


def test_plain_gradle_coordinate_remains_declared():
    assert (
        inputs.parse_dependencies("build.gradle", b'implementation "g:a:1.2.3"')[0]["confidence"]
        == "declared"
    )


def test_interpolated_extended_gradle_coordinate_remains_unknown(tmp_path):
    (tmp_path / "build.gradle").write_text(
        'ext { libraryVersion = "1.2.3@aar" }\nimplementation "g:a:$libraryVersion"'
    )
    inventory, _ = inputs.inspect_target(tmp_path)
    assert inventory["dependencies"][0]["version"] == "$libraryVersion"
    assert inventory["dependencies"][0]["confidence"] == "unknown"


@pytest.mark.parametrize("member", ["assets/blob.png", "lib/arm64-v8a/liblarge.so", "classes.dex"])
@pytest.mark.parametrize("suffix", [".zip", ".apk"])
def test_irrelevant_large_archive_member_does_not_disable_source_resolution(tmp_path, member, suffix):
    target = tmp_path / ("app" + suffix)
    with zipfile.ZipFile(target, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("AndroidManifest.xml", '<manifest package="example.app"><application/></manifest>')
        archive.writestr(
            "build.gradle", 'ext { libraryVersion = "1.2.3" }\nimplementation "g:a:$libraryVersion"'
        )
        archive.writestr(member, b"\0" * (inputs.MAX_FILE + 1))
    inventory, _ = inputs.inspect_target(target)
    assert inventory["partial"] is False
    assert not any("Oversized archive member" in w for w in inventory["warnings"])
    if suffix == ".zip":
        assert inventory["dependencies"][0]["version"] == "1.2.3"
        assert inventory["dependencies"][0]["confidence"] == "declared"


def test_consumed_large_archive_member_still_marks_partial(tmp_path):
    target = tmp_path / "source.zip"
    with zipfile.ZipFile(target, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("AndroidManifest.xml", '<manifest package="example.app"><application/></manifest>')
        archive.writestr("large.json", b" " * (inputs.MAX_FILE + 1))
    inventory, _ = inputs.inspect_target(target)
    assert inventory["partial"] is True
    assert "Oversized archive member omitted: large.json" in inventory["warnings"]


def test_irrelevant_archive_members_remain_subject_to_global_caps_and_path_checks(tmp_path, monkeypatch):
    target = tmp_path / "source.zip"
    with zipfile.ZipFile(target, "w") as archive:
        archive.writestr("Main.java", "class Main {}")
        archive.writestr("../irrelevant.png", b"bad")
    with pytest.raises(ValueError, match="Unsafe archive"):
        inputs.inspect_target(target)
    with zipfile.ZipFile(target, "w") as archive:
        archive.writestr("Main.java", "class Main {}")
        archive.writestr("large.png", b"x" * 128)
    monkeypatch.setattr(inputs, "MAX_ARCHIVE_TOTAL", 64)
    with pytest.raises(ValueError, match="safe size/file-count"):
        inputs.inspect_target(target)


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("MinimumOSVersion", dt.datetime(2020, 1, 1)),
        ("CFBundleShortVersionString", b"secret"),
        ("CFBundleIdentifier", b"example.app"),
        ("NSAppTransportSecurity", []),
        ("NSAppTransportSecurity", {"NSAllowsArbitraryLoads": "false"}),
        ("NSAppTransportSecurity", {"unknown": dt.datetime(2020, 1, 1)}),
        ("NSAppTransportSecurity", {"unknown": b"data"}),
        ("NSAppTransportSecurity", {"NSExceptionDomains": {"example.test": []}}),
        (
            "NSAppTransportSecurity",
            {"NSExceptionDomains": {"example.test": {"NSExceptionMinimumTLSVersion": []}}},
        ),
        ("CFBundleURLTypes", ["bad"]),
        ("CFBundleURLTypes", {}),
        ("CFBundleURLTypes", [{"CFBundleURLSchemes": "bad"}]),
        ("CFBundleURLTypes", [{"CFBundleURLSchemes": [b"bad"]}]),
    ],
)
def test_invalid_plist_inventory_fields_are_rejected_before_mutation(key, value):
    inventory = {"platforms": [], "package": "", "apps": [], "ios_config": [], "deep_links": []}
    raw = plistlib.dumps({"CFBundleIdentifier": "example.app", key: value})
    with pytest.raises(ValueError, match="Info.plist"):
        inputs.ios_plist(raw, "Info.plist", inventory)
    assert inventory == {"platforms": [], "package": "", "apps": [], "ios_config": [], "deep_links": []}


def test_valid_plist_security_values_are_preserved_as_observed(tmp_path):
    value = {
        "CFBundleIdentifier": "example.app",
        "MinimumOSVersion": "17.0",
        "CFBundleShortVersionString": "1.2",
        "NSAppTransportSecurity": {
            "NSAllowsArbitraryLoads": True,
            "NSExceptionDomains": {
                "example.test": {
                    "NSExceptionAllowsInsecureHTTPLoads": True,
                    "NSExceptionMinimumTLSVersion": "TLSv1.0",
                }
            },
        },
        "CFBundleURLTypes": [{"CFBundleURLSchemes": ["example"]}],
        "unusedDate": dt.datetime(2020, 1, 1),
    }
    (tmp_path / "Info.plist").write_bytes(plistlib.dumps(value))
    inventory, _ = inputs.inspect_target(tmp_path)
    assert inventory["partial"] is False
    assert inventory["ios_config"][0]["ats"] == value["NSAppTransportSecurity"]
    assert inventory["deep_links"][0]["scheme"] == "example"
    assert _ats_exceptions(inventory)[0][0]["status"] == "configuration-confirmed"
    json.dumps(inventory, allow_nan=False)


def test_invalid_referenced_plist_remains_partial_and_json_safe(tmp_path):
    (tmp_path / "A.xcodeproj").mkdir()
    (tmp_path / "A.xcodeproj/project.pbxproj").write_text("INFOPLIST_FILE = Named.plist;")
    (tmp_path / "Named.plist").write_bytes(
        plistlib.dumps({"CFBundleIdentifier": "example.app", "CFBundleURLTypes": ["bad"]})
    )
    inventory, _ = inputs.inspect_target(tmp_path)
    assert inventory["partial"] is True
    assert inventory["ios_config"] == []
    assert inventory["configuration_references"][0]["state"] == "unavailable"
    json.dumps(inventory, allow_nan=False)


@pytest.mark.parametrize("failure", [AttributeError("bad parser state"), RuntimeError("parser defect")])
def test_worker_analysis_failure_returns_error_envelope(tmp_path, monkeypatch, capsys, failure):
    monkeypatch.setattr(worker, "limits", lambda: None)
    monkeypatch.setattr(sys, "argv", ["worker", str(tmp_path)])

    def fail(*args, **kwargs):
        raise failure

    monkeypatch.setattr(worker, "analyze", fail)
    worker.main()
    result = json.loads(capsys.readouterr().out)
    assert result["error"].startswith("Parser analysis failed")
    assert type(failure).__name__ in result["error"]
    assert "Sandboxed parser failed" not in result["error"]


def test_worker_serialization_failure_returns_error_envelope(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(worker, "limits", lambda: None)
    monkeypatch.setattr(sys, "argv", ["worker", str(tmp_path)])
    monkeypatch.setattr(
        worker, "analyze", lambda *a, **k: {"inventory": {"unexpected": dt.datetime(2020, 1, 1)}}
    )
    worker.main()
    assert "TypeError" in json.loads(capsys.readouterr().out)["error"]


@pytest.mark.parametrize("failure", [SystemExit(7), KeyboardInterrupt(), MemoryError()])
def test_worker_does_not_convert_resource_or_base_exceptions(tmp_path, monkeypatch, failure):
    monkeypatch.setattr(worker, "limits", lambda: None)
    monkeypatch.setattr(sys, "argv", ["worker", str(tmp_path)])

    def fail(*args, **kwargs):
        raise failure

    monkeypatch.setattr(worker, "analyze", fail)
    with pytest.raises(type(failure)):
        worker.main()
