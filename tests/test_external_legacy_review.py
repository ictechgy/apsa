"""Boundary controls for independently reviewed legacy parsing findings."""

from __future__ import annotations

import io
import os
import plistlib
import struct
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

from quaygate import apk as apkmod
from quaygate import axml, dex, dexcode
from quaygate import ipa as ipamod
from quaygate.apk import Apk, ApkError
from quaygate.appchecks import audit_apk
from quaygate.arsc import parse_resource_names
from quaygate.checks import check_lock_screen
from quaygate.ipa import Ipa, IpaError, audit_ipa
from quaygate.network_security import UNKNOWN, analyze, resolve_bool_attr
from quaygate.report import render_text
from tests.helpers import (
    _start_element,
    build_arsc,
    build_axml,
    build_code_dex,
    build_dex,
    build_macho,
    temp_apk,
    temp_ipa,
)


def _by_id(findings, name):
    return next(item for item in findings if item.check_id == name)


def test_zip_member_declared_bomb_rejected_before_open(tmp_path, monkeypatch):
    path = tmp_path / "bomb.apk"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("classes.dex", b"small")
    raw = bytearray(path.read_bytes())
    struct.pack_into("<I", raw, 22, 0x7FFFFFFF)
    central = raw.index(b"PK\x01\x02")
    struct.pack_into("<I", raw, central + 24, 0x7FFFFFFF)
    path.write_bytes(raw)
    with Apk(str(path)) as archive:
        monkeypatch.setattr(archive.zipf, "open", lambda *a: pytest.fail("oversized member opened"))
        with pytest.raises(ApkError, match="상한"):
            archive.read("classes.dex")


def test_zip_cumulative_budget_preserves_read_bound(tmp_path, monkeypatch):
    path = tmp_path / "aggregate.apk"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("one", b"123456")
        archive.writestr("two", b"abcdef")
    monkeypatch.setattr(apkmod, "MAX_TOTAL_BYTES", 10)
    with Apk(str(path)) as archive:
        assert archive.read("one") == b"123456"
        with pytest.raises(ApkError, match="누적"):
            archive.read("two")


def test_zip_directory_budget_before_zipfile_allocation(tmp_path, monkeypatch):
    path = tmp_path / "entries.apk"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("one", b"x")
    monkeypatch.setattr(apkmod, "MAX_ZIP_DIRECTORY_BYTES", 1)
    with pytest.raises(ApkError, match="directory"):
        Apk(str(path))


def test_dex_alias_strings_decoded_once():
    raw = bytearray(build_dex(["x" * 4000] * 256))
    _, offset = struct.unpack_from("<II", raw, 0x38)
    first = struct.unpack_from("<I", raw, offset)[0]
    for index in range(256):
        struct.pack_into("<I", raw, offset + 4 * index, first)
    values = dex.dex_strings(bytes(raw))
    assert len(values) == 256
    assert all(value is values[0] for value in values)


def test_dex_oversized_count_is_bounded(monkeypatch):
    monkeypatch.setattr(dex, "MAX_STRINGS", 2)
    with pytest.raises(ValueError, match="개수"):
        dex.dex_strings(build_dex(["one", "two", "three"]))


def test_dex_unterminated_string_rejected():
    raw = build_dex(["abc"])[:-1]
    with pytest.raises(ValueError, match="Unterminated"):
        dex.dex_strings(raw)


def test_dex_unique_string_output_budget(monkeypatch):
    monkeypatch.setattr(dex, "MAX_STRING_BYTES", 6)
    with pytest.raises(ValueError, match="budget"):
        dex.dex_strings(build_dex(["abcd", "efgh"]))


def test_dex_aliased_class_data_not_rewalked():
    raw = bytearray(
        build_code_dex(
            [
                ("Lcom/A;", "m", "Ljavax/crypto/Cipher;", "getInstance", "AES/GCM/NoPadding"),
            ]
        )
    )
    count, offset = struct.unpack_from("<II", raw, 0x60)
    assert count == 1
    definition = raw[offset : offset + 32]
    struct.pack_into("<II", raw, 0x60, 2, len(raw))
    raw.extend(definition * 2)
    result = dexcode.analyze_dex(bytes(raw))
    assert result is not None
    assert result["complete"] is False
    assert result["scanned"] == 1
    assert "aliased class-data block" in result["reasons"]


def test_dex_instruction_budget_is_partial(monkeypatch):
    monkeypatch.setattr(dexcode, "MAX_INSTRUCTIONS", 1)
    result = dexcode.analyze_dex(
        build_code_dex(
            [
                ("Lcom/A;", "m", "Ljavax/crypto/Cipher;", "getInstance", "DES/ECB"),
            ]
        )
    )
    assert result is not None
    assert result["complete"] is False
    assert result["weak_crypto"] == []


def test_partial_bytecode_keeps_other_dex_string_fallback():
    broken = bytearray(build_dex(["DES/ECB", "setJavaScriptEnabled"]))
    struct.pack_into("<II", broken, 0x60, 1, len(broken) - 4)
    clean = build_code_dex([("Lcom/A;", "m", "Ljavax/crypto/Cipher;", "getInstance", "AES/GCM/NoPadding")])
    with temp_apk(files={"classes.dex": clean, "classes2.dex": bytes(broken)}) as path:
        with Apk(path) as archive:
            _, findings = audit_apk(archive)
    assert _by_id(findings, "dex-weak-crypto").status == "warn"
    assert _by_id(findings, "dex-webview").status == "info"
    assert _by_id(findings, "dex-bytecode-scope").status == "na"


def test_partial_bytecode_no_indicator_cannot_pass():
    broken = bytearray(build_dex(["clean"]))
    struct.pack_into("<II", broken, 0x60, 1, len(broken) - 4)
    with temp_apk(files={"classes.dex": bytes(broken)}) as path:
        _, findings = audit_apk(Apk(path))
    assert _by_id(findings, "dex-weak-crypto").status == "na"
    assert _by_id(findings, "dex-webview").status == "na"


def test_default_aes_cipher_is_ecb_candidate():
    result = dexcode.analyze_dex(
        build_code_dex(
            [
                ("Lcom/A;", "m", "Ljavax/crypto/Cipher;", "getInstance", "AES"),
            ]
        )
    )
    assert result is not None
    assert result["complete"] is True
    assert len(result["weak_crypto"]) == 1


def test_axml_typed_boolean_overrides_deceptive_raw_string():
    chunk = _start_element(0, [(0xFFFFFFFF, 1, 2, 0x12, 0xFFFFFFFF)])
    events = axml.parse_axml(build_axml(["application", "debuggable", "false"], [chunk]))
    assert events[0][2]["debuggable"] == "true"


def test_axml_android_resource_id_overrides_deceptive_name():
    values = ["application", "renamed", "false", axml.ANDROID_NS]
    ids = [0, 0x0101000F, 0, 0]
    mapping = struct.pack("<HHI", 0x180, 8, 8 + len(ids) * 4) + struct.pack("<4I", *ids)
    chunk = _start_element(0, [(3, 1, 2, 0x12, 1)])
    attrs = axml.parse_axml(build_axml(values, [mapping, chunk]))[0][2]
    assert attrs["debuggable"] == "true"
    assert "renamed" not in attrs


def test_axml_foreign_namespace_cannot_overwrite_android_boolean():
    values = ["application", "debuggable", "false", axml.ANDROID_NS, "urn:foreign"]
    chunk = _start_element(0, [(3, 1, 2, 0x12, 1), (4, 1, 2, 0x12, 0)])
    assert axml.parse_axml(build_axml(values, [chunk]))[0][2]["debuggable"] == "true"


def test_axml_zero_attribute_stride_rejected():
    chunk = bytearray(_start_element(0, [(0xFFFFFFFF, 1, 2, 3, 2)]))
    struct.pack_into("<H", chunk, 16 + 10, 0)
    with pytest.raises(axml.AxmlError, match="attribute"):
        axml.parse_axml(build_axml(["app", "flag", "false"], [chunk]))


@pytest.mark.parametrize(
    "value,expected", [("TRUE", True), ("1", True), ("false", False), ("0", False), ("nonsense", UNKNOWN)]
)
def test_bool_coercion_cannot_turn_unknown_into_absence(value, expected):
    assert resolve_bool_attr(None, value) == expected


def test_unresolved_domain_config_makes_cleartext_inconclusive():
    events = [
        ("start", "base-config", {"cleartextTrafficPermitted": "false"}),
        ("end", "base-config", None),
        ("start", "domain-config", {"cleartextTrafficPermitted": "@2131034113"}),
        ("start", "domain", {}),
        ("text", "example.test", None),
        ("end", "domain", None),
        ("end", "domain-config", None),
    ]
    result = analyze(events)
    assert result["base_cleartext"] is False
    assert result["domain_unknown"] is True


def test_arsc_offset_table_cannot_escape_chunk():
    raw = bytearray(build_arsc([("bool", ["flag"])]))
    offset = raw.index(struct.pack("<HH", 0x201, 28))
    struct.pack_into("<I", raw, offset + 12, 20000)
    with pytest.raises(ValueError, match="offset table"):
        parse_resource_names(bytes(raw))


def test_arsc_conflicting_configurations_are_unknown():
    raw = bytearray(build_arsc([("bool", ["flag"])], bool_true_refs=["flag"]))
    offset = raw.index(struct.pack("<HH", 0x201, 28))
    size = struct.unpack_from("<I", raw, offset + 4)[0]
    other = bytearray(raw[offset : offset + size])
    struct.pack_into("<I", other, size - 4, 0)
    package = raw.index(struct.pack("<HH", 0x200, 288))
    struct.pack_into("<I", raw, package + 4, struct.unpack_from("<I", raw, package + 4)[0] + size)
    raw.extend(other)
    struct.pack_into("<I", raw, 4, len(raw))
    assert parse_resource_names(bytes(raw))[0x7F010000][2] is None


class _ChunkReader:
    def __init__(self, data, chunk):
        self.stream, self.chunk = io.BytesIO(data), chunk

    def read(self, size):
        return self.stream.read(min(size, self.chunk))


def test_ipa_tail_cross_chunk_long_string_and_canary_retained():
    payload = b"\0" * 16 + b"prefix " + b"AKIAIOSFODNN7EXAMPLE" + b" x" * 100 + b"\0___stack_chk_fail\0"
    _, strings, canary, truncated, partial = ipamod._read_streaming(_ChunkReader(payload, 128), 16)
    assert any("AKIAIOSFODNN7EXAMPLE" in value for value in strings)
    assert canary is True
    assert truncated is True
    assert partial is False


def test_ipa_tail_run_carry_budget_is_explicit(monkeypatch):
    monkeypatch.setattr(ipamod, "MAX_ASCII_CARRY", 64)
    result = ipamod._read_streaming(_ChunkReader(b"\0" * 16 + b"x" * 1000, 128), 16)
    assert result[-1] is True


def test_ipa_decompression_budget_is_explicit(monkeypatch):
    monkeypatch.setattr(ipamod, "MAX_BINARY_BYTES", 256)
    result = ipamod._read_streaming(_ChunkReader(b"\0" * 1000, 128), 16)
    assert result[-1] is True


def test_ipa_partial_negative_indicators_cannot_pass(monkeypatch):
    monkeypatch.setattr(ipamod, "BINARY_SCAN_LIMIT", 32)
    monkeypatch.setattr(ipamod, "MAX_BINARY_BYTES", 128)
    with temp_ipa(binary=build_macho() + b"\0" * 1024) as path:
        _, findings = audit_ipa(Ipa(path))
    assert _by_id(findings, "bin-secrets").status == "na"
    assert _by_id(findings, "bin-cleartext-urls").status == "na"
    assert _by_id(findings, "bin-scan-scope").status == "na"


@pytest.mark.parametrize(
    "invalid",
    [
        {"NSAppTransportSecurity": "bad"},
        {"NSAppTransportSecurity": {"NSExceptionDomains": "bad"}},
        {"CFBundleURLTypes": ["bad"]},
    ],
)
def test_ipa_malformed_scoped_settings_are_inconclusive(invalid):
    with temp_ipa(plist_over=invalid) as path:
        _, findings = audit_ipa(Ipa(path))
    name = "ipa-url-schemes" if "CFBundleURLTypes" in invalid else "ipa-ats"
    assert _by_id(findings, name).status == "na"


def test_ipa_non_dictionary_plist_rejected(tmp_path):
    path = tmp_path / "root.ipa"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("Payload/A.app/Info.plist", plistlib.dumps(["bad"]))
    with pytest.raises(IpaError, match="dictionary"):
        Ipa(str(path)).info_plist()


def test_native_member_cap_applies_before_decompression(monkeypatch):
    with temp_apk(files={"lib/arm64-v8a/large.so": b"x" * 1024}) as path:
        with Apk(path) as archive:
            calls, original = [], archive.read

            def read(name, limit=apkmod.MAX_MEMBER_BYTES):
                calls.append((name, limit))
                return original(name, limit)

            monkeypatch.setattr(archive, "read", read)
            audit_apk(archive)
    assert ("lib/arm64-v8a/large.so", 16 * 1024 * 1024) in calls


def test_target_description_cannot_forge_log_lines():
    text = render_text("app\n요약: fake\x1b[31m", [])
    assert text.splitlines()[0] == "대상: app 요약: fake"
    assert text.count("\n요약:") == 1


def test_lock_screen_swipe_compatible_output_not_pass():
    class Runner:
        def shell(self, *args):
            assert args == ("locksettings", "get-disabled")
            return "false\n"

    assert check_lock_screen(Runner()).status == "na"


def test_actual_legacy_cli_error_exit_is_bounded(tmp_path):
    path = tmp_path / "manifest-bomb.apk"
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("AndroidManifest.xml", b"x" * 128)
    raw = bytearray(path.read_bytes())
    central = raw.index(b"PK\x01\x02")
    struct.pack_into("<I", raw, 22, 0x7FFFFFFF)
    struct.pack_into("<I", raw, central + 24, 0x7FFFFFFF)
    path.write_bytes(raw)
    root = Path(apkmod.__file__).resolve().parents[1]
    code = (
        "import sys;sys.path[:0]="
        + repr([str(root / "src"), str(root)])
        + ";from quaygate.cli import main;raise SystemExit(main(sys.argv[1:]))"
    )
    result = subprocess.run(
        [sys.executable, "-I", "-c", code, "apk", str(path), "--json"],
        capture_output=True,
        text=True,
        timeout=5,
        env=dict(os.environ),
    )
    assert result.returncode == 2
    assert "상한" in result.stderr
    assert result.stdout == ""


def test_dex_instruction_budget_shared_across_archive(monkeypatch):
    monkeypatch.setattr(dexcode, "MAX_INSTRUCTIONS", 8)
    value = build_code_dex([("Lcom/A;", "m", "Ljavax/crypto/Cipher;", "getInstance", "AES/GCM/NoPadding")])
    with temp_apk(files={"classes.dex": value, "classes2.dex": value, "classes3.dex": value}) as path:
        result = dexcode.scan_apk(Apk(path))
    assert result["complete"] is False
    assert result["failed"] >= 1
    assert result["entries"] == 3


def test_ipa_secret_crossing_head_tail_boundary_retained():
    payload = b"\0" * 16 + b"AKIAIOSFODNN7EXAMPLE\0"
    _, strings, _, _, partial = ipamod._read_streaming(_ChunkReader(payload, 128), 26)
    assert any("AKIAIOSFODNN7EXAMPLE" in value for value in strings)
    assert partial is False


def test_dex_repeated_invokes_do_not_multiply_string_comparisons(monkeypatch):
    monkeypatch.setattr(dexcode.DexCode, "scan_code", lambda self, offset: ([0] * 5000, ["DES/ECB"] * 5000))
    calls = []
    weak = dexcode._weak_algo
    monkeypatch.setattr(dexcode, "_weak_algo", lambda value: (calls.append(value), weak(value))[1])
    result = dexcode.analyze_dex(
        build_code_dex([("Lcom/A;", "m", "Ljavax/crypto/Cipher;", "getInstance", "DES/ECB")])
    )
    assert result is not None
    assert calls == ["DES/ECB"]


def test_nsc_unresolved_domain_is_not_a_cleartext_pass():
    tree = [
        (
            "network-security-config",
            {},
            [
                ("base-config", {"cleartextTrafficPermitted": "false"}, []),
                (
                    "domain-config",
                    {"cleartextTrafficPermitted": "@2131034113"},
                    [
                        ("domain", {}, ["unknown.example"]),
                    ],
                ),
            ],
        )
    ]
    with temp_apk(app_over={"networkSecurityConfig": "@xml/network_security_config"}, nsc=tree) as path:
        _, findings = audit_apk(Apk(path))
    assert _by_id(findings, "app-cleartext").status == "na"


@pytest.mark.parametrize("debuggable,expected", [("false", 0), ("true", 1)])
def test_actual_legacy_cli_preserves_success_and_findings_exits(debuggable, expected):
    with temp_apk(app_over={"debuggable": debuggable}) as path:
        root = Path(apkmod.__file__).resolve().parents[1]
        code = (
            "import sys;sys.path[:0]="
            + repr([str(root / "src"), str(root)])
            + ";from quaygate.cli import main;raise SystemExit(main(sys.argv[1:]))"
        )
        result = subprocess.run(
            [sys.executable, "-I", "-c", code, "apk", path, "--json"],
            capture_output=True,
            text=True,
            timeout=5,
        )
    assert result.returncode == expected
    assert '"findings"' in result.stdout
    assert result.stderr == ""
