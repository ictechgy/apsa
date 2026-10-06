from __future__ import annotations

import json
import plistlib
import struct
import zipfile
from pathlib import Path

import pytest

import mobile_audit.binary_analysis as binary
from mobile_audit.binary_analysis import BinaryFormatError, analyze_binary, inspect_macho

FIXTURES = Path(__file__).parent / "fixtures" / "binary_analysis"


def _macho(
    *, pie=True, encrypted=False, entitlements=None, der=False, cpu=0x100000C, endian="<", signature_padding=0
):
    name = b"/usr/lib/libSystem.B.dylib\0"
    dylib_size = (24 + len(name) + 7) // 8 * 8
    dylib = struct.pack(endian + "IIIIII", 0xC, dylib_size, 24, 0, 0x10000, 0x10000)
    dylib += name + bytes(dylib_size - 24 - len(name))
    blobs = []
    if entitlements is not None:
        xml = plistlib.dumps(entitlements)
        blobs.append(struct.pack(">II", 0xFADE7171, len(xml) + 8) + xml)
    if der:
        blobs.append(struct.pack(">II", 0xFADE7172, 10) + b"\x30\x00")
    signature = b""
    if blobs:
        start = 12 + len(blobs) * 8
        indexes = b""
        for index, blob in enumerate(blobs):
            indexes += struct.pack(">II", 5 if index == 0 else 7, start)
            start += len(blob)
        signature = struct.pack(">III", 0xFADE0CC0, start, len(blobs)) + indexes + b"".join(blobs)
        signature += bytes(signature_padding)
    command_size = len(dylib) + 24 + (16 if signature else 0)
    payload_start = 32 + command_size
    encryption = struct.pack(endian + "IIIIII", 0x2C, 24, payload_start, 16, int(encrypted), 0)
    signing = struct.pack(endian + "IIII", 0x1D, 16, payload_start + 16, len(signature)) if signature else b""
    header = struct.pack(
        endian + "IiiIIIII",
        0xFEEDFACF,
        cpu,
        0,
        2,
        3 if signature else 2,
        command_size,
        0x200000 if pie else 0,
        0,
    )
    return header + dylib + encryption + signing + bytes(16) + signature


def _ipa(tmp_path, raw, *, profile=None, executable="Main"):
    path = tmp_path / "App.ipa"
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        info = {"CFBundleIdentifier": "audit.fixture"}
        if executable is not None:
            info["CFBundleExecutable"] = executable
        archive.writestr(
            "Payload/App.app/Info.plist",
            plistlib.dumps(info),
        )
        if raw is not None:
            archive.writestr("Payload/App.app/Main", raw)
        if profile is not None:
            archive.writestr(
                "Payload/App.app/embedded.mobileprovision", b"CMS-PAYLOAD" + plistlib.dumps(profile)
            )
    return path


def _fat(*slices):
    table_end = 8 + len(slices) * 20
    offset = (table_end + 15) // 16 * 16
    table = b""
    payload = bytes(offset - table_end)
    for raw in slices:
        cpu, subtype = struct.unpack_from("<ii", raw, 4)
        table += struct.pack(">iiIII", cpu, subtype, offset, len(raw), 4)
        payload += raw
        next_offset = (offset + len(raw) + 15) // 16 * 16
        payload += bytes(next_offset - offset - len(raw))
        offset = next_offset
    return struct.pack(">II", 0xCAFEBABE, len(slices)) + table + payload


def test_compiled_real_dex_call_arguments_and_local_sensitive_value_flow():
    report = analyze_binary(FIXTURES / "unsafe.apk", {})
    assert report["warnings"] == []
    assert {finding["rule_id"] for finding in report["findings"]} == set(binary.DEX_RULES)
    assert len(report["findings"]) == 7
    file_calls = [
        finding for finding in report["findings"] if finding["rule_id"] == "BINARY-WEBVIEW-FILE-ACCESS"
    ]
    assert all(finding["evidence"][0]["argument"] is True for finding in file_calls)
    log = next(
        finding for finding in report["findings"] if finding["rule_id"] == "BINARY-STORAGE-SENSITIVE-LOG"
    )
    assert "SharedPreferences;->getString" in log["evidence"][0]["source_api"]
    assert all(finding["status"] == "candidate" for finding in report["findings"])
    assert all(finding["evidence"][0]["path"] == "classes.dex" for finding in report["findings"])
    assert all(isinstance(finding["evidence"][0]["offset"], int) for finding in report["findings"])
    assert all(row["state"] == "checked" for row in report["coverage"])
    serialized = json.dumps(report)
    assert "access_token" not in serialized
    assert "FixtureBridge" not in serialized


def test_same_api_names_in_literals_disabled_arguments_and_branch_join_do_not_find():
    report = analyze_binary(FIXTURES / "safe.apk", {})
    assert report["warnings"] == []
    assert report["findings"] == []
    calls = report["metadata"]["dex"][0]["calls"]
    assert calls["Landroid/webkit/WebSettings;->setAllowUniversalAccessFromFileURLs(Z)V"] == 3
    assert calls["Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I"] == 4
    assert "Landroid/webkit/SslErrorHandler;->proceed()V" not in calls


def test_upstream_binary_apk_supported_without_security_false_positives():
    report = analyze_binary(Path(__file__).parent / "fixtures" / "Test-debug.apk", {})
    assert report["warnings"] == []
    assert report["findings"] == []
    assert report["metadata"]["dex"][0]["methods"] > 0
    assert report["metadata"]["dex"][0]["instructions"] > 0


def test_corrupted_dex_does_not_invoke_heavy_parser(tmp_path, monkeypatch):
    import androguard.core.dex

    invoked = False

    def parser(_):
        nonlocal invoked
        invoked = True
        raise AssertionError("invalid header reached parser")

    monkeypatch.setattr(androguard.core.dex, "DEX", parser)
    with zipfile.ZipFile(FIXTURES / "unsafe.apk") as source:
        raw = bytearray(source.read("classes.dex"))
    raw[-1] ^= 1
    path = tmp_path / "bad.apk"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("classes.dex", raw)
    report = analyze_binary(path, {})
    assert not invoked
    assert report["findings"] == []
    assert report["warnings"] and all(row["state"] == "partial" for row in report["coverage"])


@pytest.mark.parametrize("budget", ["MAX_DEX_BYTES", "MAX_METHODS", "MAX_INSTRUCTIONS", "MAX_FINDINGS"])
def test_binary_budgets_surface_incomplete_coverage(monkeypatch, budget):
    monkeypatch.setattr(binary, budget, 1)
    report = analyze_binary(FIXTURES / "unsafe.apk", {})
    assert any(row["state"] == "partial" for row in report["coverage"])
    assert report["warnings"]


@pytest.mark.parametrize("member", ["../escape.dex", "/absolute.dex", "Payload\\App.app\\Main"])
def test_archive_paths_rejected_without_extraction(tmp_path, member):
    path = tmp_path / "bad.apk"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr(member, b"no")
    with pytest.raises(ValueError, match="Unsafe archive"):
        analyze_binary(path, {})
    assert not (tmp_path.parent / "escape.dex").exists()


def test_duplicate_members_rejected(tmp_path):
    path = tmp_path / "bad.apk"
    with zipfile.ZipFile(path, "w") as archive, pytest.warns(UserWarning, match="Duplicate"):
        archive.writestr("classes.dex", b"one")
        archive.writestr("classes.dex", b"two")
    with pytest.raises(ValueError, match="Duplicate archive"):
        analyze_binary(path, {})


def test_no_dex_is_not_an_absence_of_vulnerabilities(tmp_path):
    path = tmp_path / "native.apk"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("lib/arm64-v8a/libapp.so", b"native")
    report = analyze_binary(path, {})
    assert all(row["state"] == "not-run" for row in report["coverage"])
    assert report["warnings"]


def test_thin_macho_metadata_does_not_claim_native_code_security(tmp_path):
    path = _ipa(tmp_path, _macho(encrypted=True))
    report = analyze_binary(path, {"package": "audit.fixture"})
    slice_ = report["metadata"]["apps"][0]["slices"][0]
    assert slice_["bits"] == 64 and slice_["pie"] is True
    assert slice_["encryption"]["state"] == "encrypted"
    assert slice_["linked_libraries"][0]["path"] == "/usr/lib/libSystem.B.dylib"
    assert report["findings"] == []
    assert any(
        row["rule_id"] == "BINARY-IOS-CODE-PATHS" and row["state"] == "not-run" for row in report["coverage"]
    )
    assert any("encrypted code" in warning for warning in report["warnings"])


def test_entitlements_and_pie_are_observations_with_signature_limit(tmp_path):
    raw = _macho(
        pie=False,
        entitlements={"get-task-allow": True, "keychain-access-groups": ["private.identifier"]},
        signature_padding=16,
    )
    report = analyze_binary(_ipa(tmp_path, raw), {})
    assert {finding["rule_id"] for finding in report["findings"]} == {
        "BINARY-IOS-PIE",
        "BINARY-IOS-DEBUG-ENTITLEMENT",
    }
    assert all(finding["status"] == "configuration-confirmed" for finding in report["findings"])
    signature = report["metadata"]["apps"][0]["slices"][0]["code_signature"]
    assert signature["entitlements"]["get-task-allow"] is True
    assert signature["entitlements"]["keychain-access-groups-count"] == 1
    assert signature["signature_verified"] is False
    assert "private.identifier" not in json.dumps(report)


def test_der_entitlements_prevent_effective_xml_configuration_claim(tmp_path):
    report = analyze_binary(_ipa(tmp_path, _macho(entitlements={"get-task-allow": True}, der=True)), {})
    assert report["findings"][0]["status"] == "candidate"
    assert any(
        row["rule_id"] == "BINARY-IOS-ENTITLEMENTS" and row["state"] == "partial"
        for row in report["coverage"]
    )


def test_profile_permitted_entitlement_is_not_a_signed_app_entitlement(tmp_path):
    path = _ipa(tmp_path, _macho(), profile={"Entitlements": {"get-task-allow": True}})
    report = analyze_binary(path, {})
    assert report["findings"] == []
    profile = report["metadata"]["apps"][0]["provisioning"]
    assert profile["permitted_entitlements"]["get-task-allow"] is True
    assert profile["effective_app_entitlements"] is False
    assert profile["signature_verified"] is False


def test_fat_macho_inspects_each_architecture_and_big_endian_thin():
    result = inspect_macho(_fat(_macho(), _macho(cpu=0x1000007)))
    assert len(result) == 2
    assert {slice_["cpu_type"] for slice_ in result} == {0x100000C, 0x1000007}
    assert inspect_macho(_macho(endian=">"))[0]["bits"] == 64


@pytest.mark.parametrize(
    "malformation",
    [
        "truncated",
        "commands",
        "command-size",
        "encryption-region",
        "signature-region",
        "fat-count",
        "fat-overlap",
    ],
)
def test_malformed_macho_bounds_fail_closed(malformation):
    raw = bytearray(_macho(entitlements={"get-task-allow": False}))
    if malformation == "truncated":
        raw = raw[:20]
    elif malformation == "commands":
        struct.pack_into("<I", raw, 16, 4097)
    elif malformation == "command-size":
        struct.pack_into("<I", raw, 36, 0xFFFFFFF8)
    elif malformation == "encryption-region":
        dylib_size = struct.unpack_from("<I", raw, 36)[0]
        struct.pack_into("<I", raw, 32 + dylib_size + 8, len(raw) + 1)
    elif malformation == "signature-region":
        dylib_size = struct.unpack_from("<I", raw, 36)[0]
        struct.pack_into("<I", raw, 32 + dylib_size + 24 + 8, len(raw) + 1)
    elif malformation == "fat-count":
        raw = bytearray(struct.pack(">II", 0xCAFEBABE, 0xFFFFFFFF))
    else:
        raw = bytearray(_fat(_macho(), _macho()))
        first_offset = struct.unpack_from(">I", raw, 16)[0]
        struct.pack_into(">I", raw, 36, first_offset)
    with pytest.raises(BinaryFormatError):
        inspect_macho(bytes(raw))


@pytest.mark.parametrize("executable", ["../Main", "/Main", "nested/Main", None])
def test_missing_or_unsafe_ipa_executable_is_incomplete(tmp_path, executable):
    report = analyze_binary(_ipa(tmp_path, None, executable=executable), {})
    assert report["findings"] == []
    assert report["warnings"]
    assert (
        next(row for row in report["coverage"] if row["rule_id"] == "BINARY-IOS-MACHO")["state"] == "partial"
    )


def test_source_input_does_not_claim_binary_coverage(tmp_path):
    assert analyze_binary(tmp_path, {})["coverage"] == []


def test_linked_library_output_budget_reports_partial_metadata(tmp_path, monkeypatch):
    monkeypatch.setattr(binary, "MAX_LIBRARIES", 0)
    report = analyze_binary(_ipa(tmp_path, _macho()), {})
    slice_ = report["metadata"]["apps"][0]["slices"][0]
    assert slice_["linked_libraries"] == []
    assert slice_["linked_libraries_omitted"] == 1
    assert (
        next(row for row in report["coverage"] if row["rule_id"] == "BINARY-IOS-MACHO")["state"] == "partial"
    )
    assert report["warnings"]
