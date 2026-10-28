"""Fresh ZIP directory metadata cannot silently erase supported file candidates."""

from __future__ import annotations

import hashlib
import plistlib
import stat
import zipfile
from pathlib import Path

import pytest

from mobile_audit import inputs

MANIFEST = b'<manifest package="fresh.zip.metadata"><application/></manifest>'
MEMBERS = (
    ("assets/app.properties", b"api_key=fresh-synthetic-value\n", True, False),
    ("src/Main.kt", b"class FreshSyntheticSource", True, False),
    ("assets/index.android.bundle", b"const freshSynthetic = 1;", True, False),
    ("assets/main.jsbundle", b"const freshSynthetic = 1;", True, False),
    ("assets/main.hbc", b"fresh-synthetic-bytecode", False, True),
    ("lib/arm64-v8a/libapp.so", b"fresh-synthetic-aot", False, True),
)


def _fixture(
    tmp_path: Path, suffix: str, member: str, payload: bytes, mode: int, *, slash: bool = False
) -> tuple[Path, str]:
    target = tmp_path / ("fresh-zip-metadata" + suffix)
    prefix = "Payload/Fresh.app/" if suffix == ".ipa" else ""
    name = prefix + member + ("/" if slash else "")
    with zipfile.ZipFile(target, "w") as archive:
        if suffix == ".ipa":
            archive.writestr(
                prefix + "Info.plist", plistlib.dumps({"CFBundleIdentifier": "fresh.zip.metadata"})
            )
        else:
            archive.writestr("AndroidManifest.xml", MANIFEST)
        entry = zipfile.ZipInfo(name)
        entry.create_system = 3
        entry.external_attr = (mode | 0o644) << 16
        archive.writestr(entry, payload)
    return target, name


def _forbid_member_read_and_extraction(monkeypatch: pytest.MonkeyPatch, blocked: str) -> None:
    original_read = zipfile.ZipFile.read

    def read_regular_only(self, member, *args, **kwargs):
        name = member.filename if isinstance(member, zipfile.ZipInfo) else member
        assert name != blocked, "nonregular archive member must never be read"
        return original_read(self, member, *args, **kwargs)

    def no_extract(*args, **kwargs):
        raise AssertionError("archive source inspection must never extract")

    monkeypatch.setattr(zipfile.ZipFile, "read", read_regular_only)
    monkeypatch.setattr(zipfile.ZipFile, "extract", no_extract)
    monkeypatch.setattr(zipfile.ZipFile, "extractall", no_extract)


@pytest.mark.parametrize("suffix", [".zip", ".apk", ".ipa"])
@pytest.mark.parametrize("member,payload,credential,compiled", MEMBERS)
@pytest.mark.parametrize("empty", [False, True])
def test_slashless_directory_mode_reports_supported_member_omission_without_reading(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    suffix: str,
    member: str,
    payload: bytes,
    credential: bool,
    compiled: bool,
    empty: bool,
) -> None:
    target, name = _fixture(tmp_path, suffix, member, b"" if empty else payload, stat.S_IFDIR)
    _forbid_member_read_and_extraction(monkeypatch, name)
    credential_text = []
    inventory, sources = inputs.inspect_target(target, credential_text=credential_text)

    assert inventory["partial"] is True
    assert f"Archive non-regular member omitted without reading: {name}" in inventory["warnings"]
    assert name not in dict(sources)
    assert name not in dict(credential_text)
    assert inventory["credential_text"]["omitted_files"] == int(credential)
    assert inventory["credential_text"]["partial"] is credential
    assert inventory["package"] == "fresh.zip.metadata"
    assert inventory["fingerprint_complete"] is True
    assert inventory["fingerprint"] == hashlib.sha256(target.read_bytes()).hexdigest()
    hybrid = [record for record in inventory["hybrid_inputs"] if record["path"] == name]
    if compiled:
        assert len(hybrid) == 1
        assert hybrid[0]["state"] == "skipped"
        assert hybrid[0]["basis"] == "recognized-artifact-name"
        assert hybrid[0]["representation"].endswith("candidate")
        assert "non-regular" in hybrid[0]["reason"]
    else:
        assert not hybrid


@pytest.mark.parametrize("suffix", [".zip", ".apk", ".ipa"])
@pytest.mark.parametrize("member,payload,credential,compiled", MEMBERS)
def test_trailing_slash_directories_are_quiet_without_file_or_compiled_claims(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    suffix: str,
    member: str,
    payload: bytes,
    credential: bool,
    compiled: bool,
) -> None:
    target, name = _fixture(tmp_path, suffix, member, b"", stat.S_IFDIR, slash=True)
    _forbid_member_read_and_extraction(monkeypatch, name)
    inventory, sources = inputs.inspect_target(target, credential_text=[])

    assert inventory["partial"] is False
    assert inventory["credential_text"]["omitted_files"] == 0
    assert inventory["credential_text"]["partial"] is False
    assert not any(name in warning for warning in inventory["warnings"])
    assert name not in dict(sources)
    assert not inventory["hybrid_inputs"]


@pytest.mark.parametrize("suffix", [".zip", ".apk", ".ipa"])
@pytest.mark.parametrize("member,payload,credential,compiled", MEMBERS)
@pytest.mark.parametrize("mode", [stat.S_IFREG, 0])
def test_regular_and_untyped_archive_members_keep_existing_admission(
    tmp_path: Path,
    suffix: str,
    member: str,
    payload: bytes,
    credential: bool,
    compiled: bool,
    mode: int,
) -> None:
    target, name = _fixture(tmp_path, suffix, member, payload, mode)
    credential_text = []
    inventory, sources = inputs.inspect_target(target, credential_text=credential_text)

    assert inventory["partial"] is compiled
    assert inventory["credential_text"]["omitted_files"] == 0
    assert inventory["credential_text"]["partial"] is False
    assert not any(name in warning for warning in inventory["warnings"])
    if credential:
        assert dict(credential_text)[name] == payload.decode()
    if Path(member).suffix not in {".properties", ".hbc", ".so"}:
        assert dict(sources)[name] == payload.decode()
    if compiled:
        assert any(row["path"] == name and row["state"] == "skipped" for row in inventory["hybrid_inputs"])


@pytest.mark.parametrize("suffix", [".zip", ".apk", ".ipa"])
def test_unadmitted_directory_mode_member_does_not_expand_analysis_scope(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, suffix: str
) -> None:
    target, name = _fixture(tmp_path, suffix, "assets/fresh.unknown", b"synthetic", stat.S_IFDIR)
    _forbid_member_read_and_extraction(monkeypatch, name)
    inventory, sources = inputs.inspect_target(target, credential_text=[])

    assert inventory["partial"] is False
    assert inventory["credential_text"]["omitted_files"] == 0
    assert not any(name in warning for warning in inventory["warnings"])
    assert name not in dict(sources)
    assert not inventory["hybrid_inputs"]
