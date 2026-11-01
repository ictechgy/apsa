"""Bzip2/LZMA, encrypted and over-ratio ZIP members are never decompressed.

CPython inflates a whole bzip2/LZMA read before truncating it to the declared
size, so these fresh synthetic members declare 100 bytes and expand to 64 MiB.
"""

from __future__ import annotations

import functools
import io
import plistlib
import struct
import tracemalloc
import zipfile
import zlib
from contextlib import redirect_stderr, redirect_stdout

import pytest

from mobile_audit import engine
from mobile_audit.apks_analysis import analyze_apks
from mobile_audit.binary_analysis import analyze_binary
from mobile_audit.inputs import inspect_target
from mobile_audit.ipa_resource_seal import verify_resource_seal
from quaygate import cli
from quaygate.apk import Apk, ApkError, unsafe_member
from quaygate.ipa import Ipa, IpaError
from tests.apks_fixture import DEFAULT_DEVICE, write_split_apks
from tests.test_next_hardening import manifest as aab_manifest

EXPANDED = 64 * 1024 * 1024
MEMORY_BUDGET = EXPANDED // 2
MANIFEST = b'<manifest package="org.synthetic.bomb"><application/></manifest>'
AAB_MANIFEST = ("base/manifest/AndroidManifest.xml", 0, aab_manifest())
PLIST = plistlib.dumps({"CFBundleIdentifier": "org.synthetic.bomb", "CFBundleExecutable": "App"})


@pytest.fixture(params=[zipfile.ZIP_BZIP2, zipfile.ZIP_LZMA], ids=["bzip2", "lzma"])
def method(request):
    return request.param


@functools.cache
def bomb(method: int) -> bytes:
    """Raw member data: EXPANDED zero bytes compressed (and framed) by zipfile itself."""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", method) as output, output.open("zeros", "w") as stream:
        for _ in range(EXPANDED // (1024 * 1024)):
            stream.write(bytes(1024 * 1024))
    with zipfile.ZipFile(buffer) as source:
        info = source.getinfo("zeros")
    raw = buffer.getvalue()
    name_length, extra_length = struct.unpack_from("<HH", raw, info.header_offset + 26)
    start = info.header_offset + 30 + name_length + extra_length
    return raw[start : start + info.compress_size]


def archive(members: list[tuple[str, int, bytes]]) -> bytes:
    """Raw ZIP; compressed members declare a tiny size, as a hostile archive would."""
    local, central = bytearray(), bytearray()
    for name, method, payload in members:
        encoded = name.encode()
        stored = method == zipfile.ZIP_STORED
        crc = zlib.crc32(payload) if stored else 0
        size = len(payload) if stored else 100
        # flags, method, time, date, CRC, compressed size, declared size, name length, extra length
        fields = (0, method, 0, 0x21, crc, len(payload), size, len(encoded), 0)
        offset = len(local)
        local += struct.pack("<IHHHHHIIIHH", 0x04034B50, 63, *fields) + encoded + payload
        central += struct.pack(
            "<IHHHHHHIIIHHHHHII", 0x02014B50, 0x0314, 63, *fields, 0, 0, 0, 0o100644 << 16, offset
        )
        central += encoded
    count = len(members)
    end = struct.pack("<IHHHHIIH", 0x06054B50, 0, 0, count, count, len(central), len(local), 0)
    return bytes(local + central + end)


def write(path, members):
    path.write_bytes(archive(members))
    return path


def peak(call):
    """Run call under tracemalloc; return (result or raised error, peak traced bytes)."""
    tracemalloc.start()
    try:
        try:
            result = call()
        except Exception as error:
            result = error
        return result, tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()


def test_member_check_allows_only_bounded_unencrypted_stored_or_deflate():
    def info(compress_type=zipfile.ZIP_DEFLATED, file_size=100, compress_size=100, flag_bits=0):
        value = zipfile.ZipInfo("member")
        value.compress_type, value.file_size, value.compress_size = compress_type, file_size, compress_size
        value.flag_bits = flag_bits
        return value

    assert unsafe_member(info(zipfile.ZIP_STORED)) is None
    assert unsafe_member(info()) is None
    # Small members may compress arbitrarily well; the ratio budget starts at 1 MiB.
    assert unsafe_member(info(file_size=1024 * 1024, compress_size=1)) is None
    assert unsafe_member(info(zipfile.ZIP_BZIP2)) == "unsupported compression method 12"
    assert unsafe_member(info(zipfile.ZIP_LZMA)) == "unsupported compression method 14"
    assert unsafe_member(info(flag_bits=1)) == "encrypted member"
    over_ratio = info(file_size=2 * 1024 * 1024, compress_size=2 * 1024)
    assert unsafe_member(over_ratio) == "compression ratio budget exceeded"


@pytest.mark.parametrize(
    ("suffix", "prefix", "victim"),
    [
        (".apk", [("AndroidManifest.xml", 0, MANIFEST)], "res/raw/config.json"),
        (".ipa", [("Payload/App.app/Info.plist", 0, PLIST)], "Payload/App.app/config.json"),
        (".aab", [AAB_MANIFEST], "base/assets/settings.json"),
        (".zip", [("app/src/main/Main.java", 0, b"class Main {}")], "app/build.gradle"),
    ],
)
def test_unified_inputs_omit_unsafe_member_without_inflating(tmp_path, method, suffix, prefix, victim):
    target = write(tmp_path / f"synthetic{suffix}", [*prefix, (victim, method, bomb(method))])
    result, used = peak(lambda: inspect_target(target))
    assert not isinstance(result, Exception), result
    inventory, _ = result
    assert used < MEMORY_BUDGET
    assert inventory["partial"] is True
    assert (
        f"Archive member omitted without decompressing (unsupported compression method {method}): {victim}"
        in inventory["warnings"]
    )


def test_aab_resource_table_with_unsafe_compression_is_omitted(tmp_path, method):
    target = write(
        tmp_path / "synthetic.aab",
        [AAB_MANIFEST, ("base/resources.pb", method, bomb(method))],
    )
    result, used = peak(lambda: inspect_target(target))
    assert not isinstance(result, Exception), result
    inventory, _ = result
    assert used < MEMORY_BUDGET
    assert inventory["aab_resources"]["inventory_partial"] is True
    assert (
        "AAB resource member omitted without decompressing "
        f"(unsupported compression method {method}): base/resources.pb"
    ) in inventory["warnings"]


def test_binary_analysis_reports_unsafe_dex_and_executable_incomplete(tmp_path, method):
    apk = write(
        tmp_path / "synthetic.apk",
        [("AndroidManifest.xml", 0, MANIFEST), ("classes.dex", method, bomb(method))],
    )
    result, used = peak(lambda: analyze_binary(apk, {}))
    assert not isinstance(result, Exception), result
    assert used < MEMORY_BUDGET
    assert result["metadata"]["dex"] == [
        {"path": "classes.dex", "complete": False, "error": "BinaryFormatError"}
    ]
    assert all(row["state"] == "partial" for row in result["coverage"])
    ipa = write(
        tmp_path / "synthetic.ipa",
        [("Payload/App.app/Info.plist", 0, PLIST), ("Payload/App.app/App", method, bomb(method))],
    )
    result, used = peak(lambda: analyze_binary(ipa, {}))
    assert not isinstance(result, Exception), result
    assert used < MEMORY_BUDGET
    assert result["metadata"]["apps"][0]["error"] == "BinaryFormatError"
    assert (
        "IPA executable inspection incomplete for Payload/App.app/Info.plist: BinaryFormatError"
        in (result["warnings"])
    )


def test_resource_seal_counts_unsafe_member_as_unsupported(tmp_path, method):
    envelope = plistlib.dumps({"files2": {"blob.bin": {"hash2": bytes(32)}}, "rules2": {"^.*": True}})
    path = write(tmp_path / "synthetic.ipa", [("Payload/App.app/blob.bin", method, bomb(method))])
    with zipfile.ZipFile(path) as source:
        result, used = peak(lambda: verify_resource_seal(source, "Payload/App.app", "App", envelope))
    assert not isinstance(result, Exception), result
    assert used < MEMORY_BUDGET
    assert result["unsupported_entries"] == 1 and result["checked_files"] == 0
    assert result["state"] == "partial" and result["hashes_verified"] is False


def test_apk_set_rejects_unsafe_member_before_reading_toc(tmp_path, method):
    original = tmp_path / "original.apks"
    write_split_apks(original)
    target = tmp_path / "synthetic.apks"
    with zipfile.ZipFile(original) as source, zipfile.ZipFile(target, "w", zipfile.ZIP_DEFLATED) as output:
        for item in source.infolist():
            output.writestr(
                item.filename, source.read(item), compress_type=method if item.filename == "toc.pb" else None
            )

    def unexpected(*args, **kwargs):
        pytest.fail("APK-set member analyzed after an unsafe member was found")

    with pytest.raises(ValueError, match=f"not decompressed: unsupported compression method {method}"):
        analyze_apks(target, DEFAULT_DEVICE, unexpected)


def run_legacy(argv):
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = cli.main(argv)
    return code, err.getvalue()


def test_legacy_apk_reader_refuses_unsafe_member_without_inflating(tmp_path, method):
    path = write(tmp_path / "synthetic.apk", [("AndroidManifest.xml", method, bomb(method))])

    def read():
        with Apk(str(path)) as apk:
            return apk.read("AndroidManifest.xml")

    error, used = peak(read)
    assert isinstance(error, ApkError) and "압축 해제 거부" in str(error)
    assert f"unsupported compression method {method}" in str(error)
    assert used < MEMORY_BUDGET
    code, err = run_legacy(["apk", str(path), "--json"])
    assert code == 2 and "압축 해제 거부" in err


def test_legacy_ipa_reader_refuses_unsafe_metadata_and_executable(tmp_path, method):
    plist = write(tmp_path / "plist.ipa", [("Payload/App.app/Info.plist", method, bomb(method))])
    with Ipa(str(plist)) as ipa:
        error, used = peak(ipa.info_plist)
    assert isinstance(error, IpaError) and "IPA metadata not decompressed" in str(error)
    assert used < MEMORY_BUDGET
    binary = write(
        tmp_path / "binary.ipa",
        [("Payload/App.app/Info.plist", 0, PLIST), ("Payload/App.app/App", method, bomb(method))],
    )
    with Ipa(str(binary)) as ipa:
        error, used = peak(ipa.app_binary)
    assert isinstance(error, IpaError) and "압축 해제 거부" in str(error)
    assert used < MEMORY_BUDGET
    code, err = run_legacy(["ipa", str(binary), "--json"])
    assert code == 2 and "압축 해제 거부" in err


def test_unified_scan_completes_and_records_unsafe_member(tmp_path, monkeypatch, method):
    monkeypatch.setenv("APSA_PARSER_LOCK_DIR", str(tmp_path / "locks"))
    target = write(
        tmp_path / "synthetic.apk",
        [("AndroidManifest.xml", 0, MANIFEST), ("res/raw/config.json", method, bomb(method))],
    )
    inventory = engine.analyze_target(target)["inventory"]
    assert inventory["package"] == "org.synthetic.bomb"
    assert inventory["partial"] is True
    assert (
        f"Archive member omitted without decompressing (unsupported compression method {method}): "
        "res/raw/config.json"
    ) in inventory["warnings"]


def test_stored_and_deflate_members_are_still_read(tmp_path):
    target = tmp_path / "synthetic.apk"
    with zipfile.ZipFile(target, "w") as output:
        output.writestr("AndroidManifest.xml", MANIFEST, compress_type=zipfile.ZIP_STORED)
        output.writestr("res/raw/config.json", b'{"zeros": "' + b"0" * 4096 + b'"}', zipfile.ZIP_DEFLATED)
        output.writestr("assets/zeros.json", b"0" * (1024 * 1024), zipfile.ZIP_DEFLATED)
    inventory, sources = inspect_target(target)
    assert inventory["partial"] is False
    assert not any("omitted" in warning for warning in inventory["warnings"])
    assert {name for name, _ in sources} >= {"res/raw/config.json", "assets/zeros.json"}
    with Apk(str(target)) as apk:
        assert apk.read("AndroidManifest.xml") == MANIFEST
        assert apk.read("assets/zeros.json") == b"0" * (1024 * 1024)
