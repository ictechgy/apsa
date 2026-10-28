"""Fresh synthetic binary structures for confirmed external-review regressions."""

import plistlib
import struct
import zipfile

import pytest

from mobile_audit import binary_analysis as binary
from mobile_audit import quaygate_analysis as lint
from quaygate.checks import Finding
from tests.test_code_signature_scope import DER_BLOB, INFO, XML_BLOB, superblob
from tests.test_ipa_trust import directory_fixture


def signed_image(mode="bound", *, reverse=False, resources=None, debug=True):
    xml = XML_BLOB
    if not debug:
        value = plistlib.dumps({"get-task-allow": False})
        xml = struct.pack(">II", 0xFADE7171, len(value) + 8) + value

    def signature(code):
        if mode == "bare":
            return xml
        special = {1: INFO, 5: xml}
        if resources is not None:
            special[3] = resources
        if mode == "unsealed":
            special.pop(5)
        elif mode == "modified":
            special[5] = b"a different XML blob"
        if mode in {"der", "der-missing"}:
            special[7] = DER_BLOB
        entries = [(0, directory_fixture(code, special=special)), (5, xml)]
        if mode == "der":
            entries.append((7, DER_BLOB))
        if mode == "unsupported":
            entries.append((2, xml))
        if mode == "alternate-unbound":
            entries.append((0x1000, directory_fixture(code, special={1: INFO})))
        if mode == "alternate-bound":
            entries.append((0x1000, directory_fixture(code, special=special)))
        if mode == "unsupported-directory":
            entries.append((0x2000, directory_fixture(code, special=special)))
        return superblob(list(reversed(entries)) if reverse else entries)

    code = bytearray(b"x" * 8192)
    signing_size = len(signature(code))
    commands = struct.pack("<II16sQQQQiiII", 0x19, 72, b"__TEXT", 0, 8192, 0, 8192, 7, 5, 0, 0)
    commands += struct.pack("<IIII", 0x1D, 16, 8192, signing_size)
    struct.pack_into("<IIIIIIII", code, 0, 0xFEEDFACF, 0x01000007, 3, 2, 2, len(commands), 0, 0)
    code[32 : 32 + len(commands)] = commands
    return bytes(code) + signature(code)


def ipa(tmp_path, raw, *, embedded=False, resources=None):
    target = tmp_path / "new-synthetic.ipa"
    with zipfile.ZipFile(target, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("Payload/App.app/Info.plist", INFO)
        archive.writestr("Payload/App.app/App", signed_image(debug=False) if embedded else raw)
        if embedded:
            archive.writestr("Payload/App.app/PlugIns/Extra.appex/Info.plist", INFO)
            archive.writestr("Payload/App.app/PlugIns/Extra.appex/App", raw)
        if resources is not None:
            archive.writestr("Payload/App.app/_CodeSignature/CodeResources", resources)
    return target


@pytest.mark.parametrize("embedded", [False, True])
@pytest.mark.parametrize("reverse", [False, True])
@pytest.mark.parametrize(
    "mode",
    [
        "bare",
        "unsealed",
        "modified",
        "der",
        "der-missing",
        "unsupported",
        "unsupported-directory",
        "alternate-unbound",
    ],
)
def test_debug_xml_needs_all_supported_directory_bindings(tmp_path, embedded, reverse, mode):
    report = binary.analyze_binary(ipa(tmp_path, signed_image(mode, reverse=reverse), embedded=embedded), {})
    matches = [f for f in report["findings"] if f["rule_id"] == "BINARY-IOS-DEBUG-ENTITLEMENT"]
    assert len(matches) == 1
    assert matches[0]["status"] == "candidate"
    assert matches[0]["evidence"][0]["entitlements_binding_state"] == "unverifiable"
    assert matches[0]["evidence"][0]["signature_verified"] is False
    if not embedded:
        assert (
            next(c for c in report["coverage"] if c["rule_id"] == "BINARY-IOS-ENTITLEMENTS")["state"]
            == "partial"
        )


@pytest.mark.parametrize("embedded", [False, True])
@pytest.mark.parametrize("mode", ["bound", "alternate-bound"])
@pytest.mark.parametrize("reverse", [False, True])
def test_bound_xml_confirms_observation_without_authenticity_claim(tmp_path, embedded, mode, reverse):
    report = binary.analyze_binary(ipa(tmp_path, signed_image(mode, reverse=reverse), embedded=embedded), {})
    match = next(f for f in report["findings"] if f["rule_id"] == "BINARY-IOS-DEBUG-ENTITLEMENT")
    assert match["status"] == "configuration-confirmed"
    assert match["evidence"][0]["entitlements_binding_state"] == "bound"
    assert match["evidence"][0]["signature_verified"] is False
    assert report["metadata"]["apps"][0]["app_authenticity_verified"] is False
    if not embedded:
        assert (
            next(c for c in report["coverage"] if c["rule_id"] == "BINARY-IOS-ENTITLEMENTS")["state"]
            == "checked"
        )


@pytest.mark.parametrize("embedded", [False, True])
def test_false_debug_entitlement_does_not_emit_debug_finding(tmp_path, embedded):
    report = binary.analyze_binary(ipa(tmp_path, signed_image(debug=False), embedded=embedded), {})
    assert not any(f["rule_id"] == "BINARY-IOS-DEBUG-ENTITLEMENT" for f in report["findings"])


@pytest.mark.parametrize("kind", ["oversized", "malformed", "raises"])
def test_resource_envelope_failure_keeps_independent_macho_evidence(tmp_path, monkeypatch, kind):
    resources = b"x" * (binary.MAX_PLIST_BYTES + 1) if kind == "oversized" else b"not a plist"
    if kind == "raises":

        def fail(*args):
            raise RuntimeError("synthetic verifier failure")

        monkeypatch.setattr(binary, "verify_resource_seal", fail)
    report = binary.analyze_binary(ipa(tmp_path, signed_image(resources=resources), resources=resources), {})
    app = report["metadata"]["apps"][0]
    assert app["slices"] and app["complete"]
    assert app["resource_seal"]["state"] in {"unsupported", "unverifiable"}
    raw_available = kind != "oversized"
    assert app["resource_seal"]["code_directory_bound"] is raw_available
    assert app["resource_seal"]["signed_resources_verified"] is False
    directory = app["slices"][0]["code_signature"]["code_directories"][0]
    assert directory["resource_envelope_state"] == ("consistent" if raw_available else "missing")
    assert {f["rule_id"] for f in report["findings"]} == {"BINARY-IOS-PIE", "BINARY-IOS-DEBUG-ENTITLEMENT"}
    coverage = {c["rule_id"]: c["state"] for c in report["coverage"]}
    assert coverage["BINARY-IOS-MACHO"] == "checked"
    assert coverage["BINARY-IOS-RESOURCE-SEAL"] == "partial"
    assert coverage["BINARY-IOS-CODE-INTEGRITY"] == ("checked" if raw_available else "partial")


def test_valid_resource_envelope_binding_is_preserved(tmp_path):
    resources = plistlib.dumps({"files2": {}, "rules2": {"^.*": True}})
    report = binary.analyze_binary(ipa(tmp_path, signed_image(resources=resources), resources=resources), {})
    seal = report["metadata"]["apps"][0]["resource_seal"]
    assert seal["state"] == "consistent" and seal["code_directory_bound"] is True
    assert seal["signed_resources_verified"] is False


@pytest.mark.parametrize("limit", [0, 1])
def test_main_finding_cap_marks_only_affected_main_coverage_partial(tmp_path, monkeypatch, limit):
    monkeypatch.setattr(binary, "MAX_FINDINGS", limit)
    report = binary.analyze_binary(ipa(tmp_path, signed_image()), {})
    assert [f["rule_id"] for f in report["findings"]] == (["BINARY-IOS-PIE"] if limit else [])
    coverage = {c["rule_id"]: c["state"] for c in report["coverage"]}
    assert coverage["BINARY-IOS-MACHO"] == ("checked" if limit else "partial")
    assert coverage["BINARY-IOS-ENTITLEMENTS"] == "partial"
    assert coverage["BINARY-IOS-EMBEDDED-MACHO"] == "not-run"


def test_embedded_finding_cap_does_not_downgrade_unaffected_main_coverage(tmp_path, monkeypatch):
    monkeypatch.setattr(binary, "MAX_FINDINGS", 1)
    report = binary.analyze_binary(ipa(tmp_path, signed_image(), embedded=True), {})
    assert len(report["findings"]) == 1
    coverage = {c["rule_id"]: c["state"] for c in report["coverage"]}
    assert coverage["BINARY-IOS-MACHO"] == "checked"
    assert coverage["BINARY-IOS-ENTITLEMENTS"] == "checked"
    assert coverage["BINARY-IOS-EMBEDDED-MACHO"] == "partial"


@pytest.mark.parametrize("kind", [".apk", ".aab"])
@pytest.mark.parametrize("name", ["classes_dex", "classes2Xdex", "classes.dex", "classes12.dex"])
def test_only_literal_dex_member_suffix_is_analyzed(tmp_path, monkeypatch, kind, name):
    calls = []

    def fake(raw, path, remaining):
        calls.append(path)
        return {"findings": [], "warnings": [], "metadata": {"path": path, "complete": True}}

    monkeypatch.setattr(binary, "_analyze_dex", fake)
    target = tmp_path / ("app" + kind)
    with zipfile.ZipFile(target, "w") as archive:
        if kind == ".aab":
            archive.writestr("base/manifest/AndroidManifest.xml", b"fixture")
        archive.writestr(("base/dex/" if kind == ".aab" else "") + name, b"fixture")
    report = binary.analyze_binary(target, {})
    assert bool(calls) == name.endswith(".dex")
    assert all(c["state"] == ("checked" if calls else "not-run") for c in report["coverage"])


@pytest.mark.parametrize("check", ["ipa-file-sharing", "bin-secrets", "dex-secrets"])
@pytest.mark.parametrize("statuses", [("na", "fail"), ("na", "warn"), ("na", "info")])
def test_quaygate_mixed_unavailable_and_issue_is_partial(tmp_path, monkeypatch, check, statuses):
    target = tmp_path / ("app.apk" if check.startswith("dex-") else "app.ipa")
    target.write_bytes(b"new synthetic adapter input")
    records = [Finding(check, "Observation", status, "MEDIUM", "synthetic detail") for status in statuses]
    monkeypatch.setattr(lint, "_audit", lambda _: ({"dex_entries": 1}, records))
    report = lint.analyze(target)
    assert next(c for c in report["coverage"] if c["rule_id"] == lint.rule_id(check))["state"] == "partial"
    assert report["metadata"]["complete"] is False
    assert len(report["findings"]) == 1 and report["findings"][0]["status"] == "candidate"


@pytest.mark.parametrize("check", ["ipa-file-sharing", "bin-secrets", "dex-secrets", "app-debuggable"])
def test_quaygate_synthetic_scope_is_explicit_and_real_manifest_is_distinct(tmp_path, monkeypatch, check):
    target = tmp_path / ("app.apk" if check.startswith(("dex-", "app-")) else "app.ipa")
    target.write_bytes(b"new synthetic adapter input")
    monkeypatch.setattr(
        lint,
        "_audit",
        lambda _: ({"dex_entries": 1}, [Finding(check, "Observation", "fail", "MEDIUM", "synthetic detail")]),
    )
    evidence = lint.analyze(target)["findings"][0]["evidence"][0]
    assert evidence["path_kind"] == ("archive-member" if check.startswith("app-") else "engine-scope")


def test_quaygate_unavailable_without_observation_remains_not_run(tmp_path, monkeypatch):
    target = tmp_path / "app.ipa"
    target.write_bytes(b"new synthetic adapter input")
    monkeypatch.setattr(
        lint, "_audit", lambda _: ({}, [Finding("bin-secrets", "Unavailable", "na", None, "no input")])
    )
    report = lint.analyze(target)
    assert next(c for c in report["coverage"] if c["rule_id"] == "QG-BIN-SECRETS")["state"] == "not-run"
    assert report["findings"] == []


@pytest.mark.parametrize("check", ["dex-secrets", "bin-secrets"])
def test_quaygate_scope_unavailable_with_positive_evidence_stays_partial(tmp_path, monkeypatch, check):
    target = tmp_path / ("app.apk" if check.startswith("dex-") else "app.ipa")
    target.write_bytes(b"new synthetic adapter input")
    records = [Finding(check, "Observation", "fail", "MEDIUM", "synthetic detail")]
    if check.startswith("bin-"):
        records.append(Finding("bin-scan", "Unavailable", "na", None, "no input"))
    monkeypatch.setattr(lint, "_audit", lambda _: ({"dex_entries": 0}, records))
    report = lint.analyze(target)
    assert next(c for c in report["coverage"] if c["rule_id"] == lint.rule_id(check))["state"] == "partial"
    assert len(report["findings"]) == 1


def test_quaygate_mixed_pass_and_unavailable_never_claims_complete(tmp_path, monkeypatch):
    target = tmp_path / "app.ipa"
    target.write_bytes(b"new synthetic adapter input")
    records = [
        Finding("ipa-file-sharing", "Observation", status, None, "synthetic detail")
        for status in ("pass", "na")
    ]
    monkeypatch.setattr(lint, "_audit", lambda _: ({}, records))
    report = lint.analyze(target)
    assert next(c for c in report["coverage"] if c["rule_id"] == "QG-IPA-FILE-SHARING")["state"] == "partial"
    assert report["metadata"]["complete"] is False and report["findings"] == []
