"""R5 closure boundaries: pre-allocation ZIP guards and partial IPA URL facts."""

from __future__ import annotations

import io
import struct
import zipfile
from pathlib import Path

import pytest

from mobile_audit import quaygate_analysis
from quaygate import apk as apkmod
from quaygate.apk import Apk, ApkError, bounded_zip
from quaygate.ipa import Ipa, IpaError, audit_ipa
from tests.helpers import temp_apk, temp_ipa


def directory_archive(count=1, *, declared=None, zip64=False, comment=b""):
    """Small synthetic local member; CD entries alias it, with no decompression."""
    local = struct.pack("<4s5H3I2H", b"PK\x03\x04", 20, 0, 0, 0, 0, 0, 0, 0, 1, 0) + b"x"
    central = (
        struct.pack("<4s6H3I5H2I", b"PK\x01\x02", 20, 20, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0) + b"x"
    )
    directory = central * count
    trailer = b""
    if zip64:
        trailer = struct.pack(
            "<4sQ2H2I4Q", b"PK\x06\x06", 44, 45, 45, 0, 0, count, count, len(directory), len(local)
        ) + struct.pack("<4sIQI", b"PK\x06\x07", 0, len(local) + len(directory), 1)
    declared = count if declared is None else declared
    # The benign 32-bit view deliberately hides the true ZIP64 directory size.
    end = struct.pack(
        "<4s4H2IH",
        b"PK\x05\x06",
        0,
        0,
        declared,
        declared,
        len(central) if zip64 else len(directory),
        len(local),
        len(comment),
    )
    return local + directory + trailer + end + comment


def no_zipfile_construction(monkeypatch):
    def unexpected(*args, **kwargs):
        pytest.fail("ZipFile constructed before unsupported directory was rejected")

    monkeypatch.setattr(apkmod.zipfile, "ZipFile", unexpected)


@pytest.mark.parametrize("count", [3, apkmod.MAX_ZIP_ENTRIES + 1])
@pytest.mark.parametrize("zip64", [False, True])
def test_hidden_directory_entries_rejected_before_zipinfo_allocation(tmp_path, monkeypatch, count, zip64):
    path = tmp_path / "hidden.apk"
    path.write_bytes(directory_archive(count, declared=1, zip64=zip64))
    no_zipfile_construction(monkeypatch)
    with pytest.raises(ValueError, match="ZIP"):
        bounded_zip(path)


def test_zip64_locator_outside_max_comment_tail_is_rejected_before_zipfile(tmp_path, monkeypatch):
    path = tmp_path / "locator.ipa"
    path.write_bytes(directory_archive(1, zip64=True, comment=b"c" * 65535))
    no_zipfile_construction(monkeypatch)
    with pytest.raises(ValueError, match="ZIP"):
        bounded_zip(path)


def test_zip64_fixture_really_overrides_benign_32bit_count():
    # Three entries suffice to prove the parser differential; never allocate a
    # large ZipInfo population in a reproducer.
    with zipfile.ZipFile(io.BytesIO(directory_archive(3, declared=1, zip64=True))) as archive:
        assert len(archive.infolist()) == 3


@pytest.mark.parametrize("field,value", [(8, 0xFFFF), (10, 0xFFFF), (12, 0xFFFFFFFF), (16, 0xFFFFFFFF)])
def test_zip64_eocd_sentinels_rejected_before_zipfile(tmp_path, monkeypatch, field, value):
    raw = bytearray(directory_archive())
    end = raw.rfind(b"PK\x05\x06")
    struct.pack_into("<H" if field < 12 else "<I", raw, end + field, value)
    path = tmp_path / "sentinel.apk"
    path.write_bytes(raw)
    no_zipfile_construction(monkeypatch)
    with pytest.raises(ValueError, match="ZIP"):
        bounded_zip(path)


@pytest.mark.parametrize(
    "kind",
    [
        "concat-prefix",
        "adjusted-prefix",
        "cd-gap",
        "cd-short",
        "variable-overrun",
        "local-offset",
        "local-header",
        "zip64-extra",
    ],
)
def test_malformed_directory_layout_rejected_before_zipfile(tmp_path, monkeypatch, kind):
    raw = bytearray(directory_archive())
    central = raw.index(b"PK\x01\x02")
    end = raw.rfind(b"PK\x05\x06")
    if kind in {"concat-prefix", "adjusted-prefix"}:
        if kind == "adjusted-prefix":
            struct.pack_into("<I", raw, central + 42, 3)
            struct.pack_into("<I", raw, end + 16, central + 3)
        raw[:0] = b"pre"
    elif kind == "cd-gap":
        raw[end:end] = b"gap"
    elif kind == "cd-short":
        struct.pack_into("<I", raw, end + 12, 45)
        struct.pack_into("<I", raw, end + 16, central + 2)
    elif kind == "variable-overrun":
        struct.pack_into("<H", raw, central + 28, 0xFFFF)
    elif kind == "local-offset":
        struct.pack_into("<I", raw, central + 42, central)
    elif kind == "local-header":
        raw[:4] = b"bad!"
    else:
        extra = struct.pack("<HH", 1, 0)
        struct.pack_into("<H", raw, central + 30, len(extra))
        raw[end:end] = extra
        end += len(extra)
        struct.pack_into("<I", raw, end + 12, len(raw) - central - 22)
    path = tmp_path / "malformed.apk"
    path.write_bytes(raw)
    no_zipfile_construction(monkeypatch)
    with pytest.raises(ValueError, match="ZIP"):
        bounded_zip(path)


@pytest.mark.parametrize("factory,error", [(Apk, ApkError), (Ipa, IpaError)])
def test_unsupported_directory_is_typed_error_in_both_legacy_entrypoints(tmp_path, factory, error):
    path = tmp_path / "app.zip"
    path.write_bytes(directory_archive(3, declared=1))
    with pytest.raises(error, match="ZIP"):
        factory(str(path))


def test_standard_zip_and_max_comment_roundtrip(tmp_path):
    path = tmp_path / "standard.zip"
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("one", b"first")
        archive.writestr("two", b"second")
        archive.comment = b"c" * 65535
    with bounded_zip(path) as archive:
        assert archive.read("one") == b"first"
        assert archive.read("two") == b"second"


def test_empty_zip_is_supported(tmp_path):
    path = tmp_path / "empty.zip"
    with zipfile.ZipFile(path, "w"):
        pass
    with bounded_zip(path) as archive:
        assert archive.infolist() == []


def test_local_zip64_form_is_rejected_before_zipfile(tmp_path, monkeypatch):
    path = tmp_path / "local-zip64.apk"
    with zipfile.ZipFile(path, "w") as archive:
        with archive.open("small", "w", force_zip64=True) as handle:
            handle.write(b"small")
    no_zipfile_construction(monkeypatch)
    with pytest.raises(ValueError, match="ZIP"):
        bounded_zip(path)


def test_unknown_well_formed_extra_field_is_supported(tmp_path):
    path = tmp_path / "extra.zip"
    member = zipfile.ZipInfo("one")
    member.extra = struct.pack("<HH", 0xCAFE, 3) + b"abc"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr(member, b"safe")
    with bounded_zip(path) as archive:
        assert archive.read("one") == b"safe"


def test_local_metadata_work_is_bounded_before_zipfile(tmp_path, monkeypatch):
    raw = bytearray(directory_archive())
    central = raw.index(b"PK\x01\x02")
    extra = struct.pack("<HH", 0xCAFE, 60) + b"x" * 60
    struct.pack_into("<H", raw, 28, len(extra))
    raw[central:central] = extra
    end = raw.rfind(b"PK\x05\x06")
    struct.pack_into("<I", raw, end + 16, central + len(extra))
    path = tmp_path / "metadata.apk"
    path.write_bytes(raw)
    monkeypatch.setattr(apkmod, "MAX_ZIP_DIRECTORY_BYTES", 47)
    no_zipfile_construction(monkeypatch)
    with pytest.raises(ValueError, match="ZIP"):
        bounded_zip(path)


def test_exact_directory_entry_limit_is_supported(tmp_path, monkeypatch):
    path = tmp_path / "exact.apk"
    path.write_bytes(directory_archive(3))
    monkeypatch.setattr(apkmod, "MAX_ZIP_ENTRIES", 3)
    with bounded_zip(path) as archive:
        assert len(archive.infolist()) == 3


def test_data_descriptor_member_is_supported(tmp_path):
    class Unseekable(io.BytesIO):
        def seekable(self):
            return False

        def seek(self, *args):
            raise io.UnsupportedOperation

    buffer = Unseekable()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("one", b"descriptor data")
    path = tmp_path / "descriptor.zip"
    path.write_bytes(buffer.getvalue())
    with bounded_zip(path) as archive:
        assert archive.getinfo("one").flag_bits & 8
        assert archive.read("one") == b"descriptor data"


def test_apk_signing_block_before_directory_remains_supported():
    with temp_apk(v1=False, v2=True) as path:
        with Apk(path) as archive:
            assert archive.has_v2_plus_signature() is True
            assert archive.read("AndroidManifest.xml")


@pytest.mark.parametrize(
    "url_types",
    [
        [{"CFBundleURLSchemes": ["myapp"]}, "bad-sibling"],
        [{"CFBundleURLSchemes": ["myapp"]}, {"CFBundleURLSchemes": "bad-list"}],
        [{"CFBundleURLSchemes": ["myapp", 42]}],
        [{"CFBundleURLSchemes": ["myapp", b"bad"]}],
    ],
)
def test_mixed_url_scheme_facts_survive_in_legacy_and_unified_reports(url_types):
    with temp_ipa(plist_over={"CFBundleURLTypes": url_types}) as path:
        with Ipa(path) as archive:
            _, findings = audit_ipa(archive)
        result = quaygate_analysis.analyze(Path(path).resolve())
    rows = [row for row in findings if row.check_id == "ipa-url-schemes"]
    assert {row.status for row in rows} == {"info", "na"}
    assert len(rows) == 2
    assert "myapp" in next(row.detail for row in rows if row.status == "info")
    finding = next(row for row in result["findings"] if row["rule_id"] == "QG-IPA-URL-SCHEMES")
    assert finding["status"] == "candidate"
    assert "myapp" in str(finding["evidence"])
    assert (
        next(row for row in result["coverage"] if row["rule_id"] == "QG-IPA-URL-SCHEMES")["state"]
        == "partial"
    )
    assert result["metadata"]["complete"] is False


@pytest.mark.parametrize(
    "url_types",
    [["bad"], [{"CFBundleURLSchemes": [42]}], {"bad": True}, {}, False, [{"CFBundleURLSchemes": {}}]],
)
def test_unknown_only_url_scheme_never_creates_a_candidate(url_types):
    with temp_ipa(plist_over={"CFBundleURLTypes": url_types}) as path:
        with Ipa(path) as archive:
            _, findings = audit_ipa(archive)
        result = quaygate_analysis.analyze(Path(path).resolve())
    assert [row.status for row in findings if row.check_id == "ipa-url-schemes"] == ["na"]
    assert not any(row["rule_id"] == "QG-IPA-URL-SCHEMES" for row in result["findings"])
    assert (
        next(row for row in result["coverage"] if row["rule_id"] == "QG-IPA-URL-SCHEMES")["state"]
        == "not-run"
    )


def test_healthy_url_scheme_is_still_checked_and_preserved():
    with temp_ipa(plist_over={"CFBundleURLTypes": [{"CFBundleURLSchemes": ["myapp"]}]}) as path:
        result = quaygate_analysis.analyze(Path(path).resolve())
    assert (
        next(row for row in result["findings"] if row["rule_id"] == "QG-IPA-URL-SCHEMES")["status"]
        == "candidate"
    )
    assert (
        next(row for row in result["coverage"] if row["rule_id"] == "QG-IPA-URL-SCHEMES")["state"]
        == "checked"
    )


def stored_archive():
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w") as archive:
        archive.writestr("one", b"fresh frozen bytes")
    return output.getvalue()


@pytest.mark.parametrize("mutation", ["replace", "in-place"])
def test_source_change_after_snapshot_cannot_change_preflighted_zip(tmp_path, monkeypatch, mutation):
    path = tmp_path / "fresh.zip"
    path.write_bytes(stored_archive())
    original = zipfile.ZipFile

    def change_input_then_construct(source, *args, **kwargs):
        if mutation == "replace":
            path.rename(tmp_path / "old-input.zip")
        path.write_bytes(b"source changed after its bounded read")
        return original(source, *args, **kwargs)

    monkeypatch.setattr(apkmod.zipfile, "ZipFile", change_input_then_construct)
    with bounded_zip(path) as archive:
        assert archive.read("one") == b"fresh frozen bytes"


def test_local_zero_alignment_padding_remains_supported(tmp_path):
    raw = bytearray(stored_archive())
    (name_length,) = struct.unpack_from("<H", raw, 26)
    position = 30 + name_length
    raw[position:position] = b"\0" * 3
    struct.pack_into("<H", raw, 28, 3)
    end = raw.rfind(b"PK\x05\x06")
    (offset,) = struct.unpack_from("<I", raw, end + 16)
    struct.pack_into("<I", raw, end + 16, offset + 3)
    path = tmp_path / "aligned.zip"
    path.write_bytes(raw)
    with bounded_zip(path) as archive:
        assert archive.read("one") == b"fresh frozen bytes"


@pytest.mark.parametrize("overflow", [False, True])
def test_snapshot_byte_limit_is_checked_before_zip_construction(tmp_path, monkeypatch, overflow):
    raw = stored_archive()
    path = tmp_path / "bounded.zip"
    path.write_bytes(raw)
    monkeypatch.setattr(apkmod, "MAX_ARCHIVE_BYTES", len(raw) - int(overflow))
    if overflow:
        no_zipfile_construction(monkeypatch)
        with pytest.raises(ValueError, match="snapshot byte limit"):
            bounded_zip(path)
    else:
        with bounded_zip(path) as archive:
            assert archive.read("one") == b"fresh frozen bytes"


def test_snapshot_follows_zipfile_shared_member_lifetime(tmp_path):
    path = tmp_path / "lifecycle.zip"
    path.write_bytes(stored_archive())
    archive = bounded_zip(path)
    snapshot = archive.fp
    assert snapshot is not None
    member = archive.open("one")
    archive.close()
    assert not snapshot.closed
    assert member.read() == b"fresh frozen bytes"
    member.close()
    assert snapshot.closed


@pytest.mark.parametrize("stage", ["preflight", "construction"])
def test_snapshot_is_closed_on_failure(tmp_path, monkeypatch, stage):
    path = tmp_path / "failure.zip"
    path.write_bytes(b"not a ZIP" if stage == "preflight" else stored_archive())
    created = []
    original = apkmod.tempfile.TemporaryFile

    def capture_snapshot(*args, **kwargs):
        handle = original(*args, **kwargs)
        created.append(handle)
        return handle

    monkeypatch.setattr(apkmod.tempfile, "TemporaryFile", capture_snapshot)
    if stage == "construction":

        def fail(*args, **kwargs):
            raise RuntimeError("fresh synthetic construction failure")

        monkeypatch.setattr(apkmod.zipfile, "ZipFile", fail)
    with pytest.raises((ValueError, RuntimeError)):
        bounded_zip(path)
    assert len(created) == 1 and created[0].closed
