"""Fresh ZIP metadata keeps nonregular Gradle context opaque, not absent."""

from __future__ import annotations

import hashlib
import stat
import zipfile
from pathlib import Path

import pytest

from mobile_audit import inputs

ROOT = b"ext { releaseVersion = '1.0' }"
LEAF = (
    b"plugins { id 'com.android.application' }\n"
    b'implementation "fresh:derived:$releaseVersion"\nimplementation "fresh:literal:3.0"'
)
HEALTHY = b'ext { healthyVersion = "9.0" }\nimplementation "fresh:healthy:$healthyVersion"'
KEEP = b"class KeptFreshSource"
MANIFEST = b'<manifest package="fresh.archive.context"><application/></manifest>'
GRADLE_NAMES = ("build.gradle", "build.gradle.kts", "settings.gradle", "settings.gradle.kts")


def _fixture(tmp_path: Path, prefix: str, script: str, kind: str) -> tuple[Path, str]:
    target = tmp_path / "fresh-gradle-context.zip"
    blocked = prefix + script
    with zipfile.ZipFile(target, "w") as archive:
        archive.writestr("AndroidManifest.xml", MANIFEST)
        archive.writestr("build.gradle", ROOT)
        archive.writestr("libs/app/build.gradle", LEAF)
        archive.writestr("healthy/build.gradle", HEALTHY)
        archive.writestr("libs/app/gradle.lockfile", b"fresh:locked:4.0=releaseRuntimeClasspath\n")
        if kind in {"symlink", "directory-mode", "fifo"}:
            entry = zipfile.ZipInfo(blocked)
            entry.create_system = 3
            mode = {"symlink": stat.S_IFLNK, "directory-mode": stat.S_IFDIR, "fifo": stat.S_IFIFO}[kind]
            entry.external_attr = (mode | 0o777) << 16
            archive.writestr(entry, b"../fresh-unread-target.gradle")
        else:
            if kind == "directory":
                archive.writestr(blocked + "/", b"")
            archive.writestr(blocked + "/Keep.kt", KEEP)
    return target, blocked


def _dep(inventory: dict, name: str) -> dict:
    return next(row for row in inventory["dependencies"] if row["name"] == name)


@pytest.mark.parametrize("prefix", ["libs/", "./libs/", "libs//"])
@pytest.mark.parametrize("script", GRADLE_NAMES)
@pytest.mark.parametrize("kind", ["symlink", "directory", "implicit-directory", "directory-mode", "fifo"])
def test_nonregular_archive_ancestor_is_opaque_without_member_or_target_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, prefix: str, script: str, kind: str
) -> None:
    target, blocked = _fixture(tmp_path, prefix, script, kind)
    canonical = Path(blocked).as_posix()
    original_read = zipfile.ZipFile.read

    def read_regular_only(self, member, *args, **kwargs):
        name = member.filename if isinstance(member, zipfile.ZipInfo) else member
        assert Path(name).as_posix() != canonical, "nonregular context member must never be read"
        return original_read(self, member, *args, **kwargs)

    def no_extract(*args, **kwargs):
        raise AssertionError("archive source inspection must never extract")

    monkeypatch.setattr(zipfile.ZipFile, "read", read_regular_only)
    monkeypatch.setattr(zipfile.ZipFile, "extract", no_extract)
    monkeypatch.setattr(zipfile.ZipFile, "extractall", no_extract)
    inventory, sources = inputs.inspect_target(target)

    derived = _dep(inventory, "fresh:derived")
    assert derived["version"] == "$releaseVersion", derived
    assert derived["confidence"] == "unknown", derived
    assert "version_source" not in derived
    assert _dep(inventory, "fresh:healthy")["version"] == "9.0"
    literal = _dep(inventory, "fresh:literal")
    assert literal["version"] == "3.0" and literal["confidence"] == "declared"
    locked = _dep(inventory, "fresh:locked")
    assert locked["version"] == "4.0" and locked["confidence"] == "exact"
    assert locked["version_source"] == "gradle-lockfile-resolved"
    assert inventory["partial"] is True
    assert inventory["fingerprint_complete"] is True
    assert inventory["fingerprint"] == hashlib.sha256(target.read_bytes()).hexdigest()
    assert any(
        "Non-regular Gradle context omitted without reading: " + canonical == warning
        for warning in inventory["warnings"]
    )
    assert canonical not in {Path(name).as_posix() for name, _ in sources}
    if kind in {"directory", "implicit-directory"}:
        assert dict(sources)[blocked + "/Keep.kt"] == KEEP.decode()


def test_ordinary_implicit_directory_does_not_make_gradle_context_opaque(tmp_path: Path) -> None:
    target = tmp_path / "fresh-ordinary-directory.zip"
    with zipfile.ZipFile(target, "w") as archive:
        archive.writestr("AndroidManifest.xml", MANIFEST)
        archive.writestr("build.gradle", ROOT)
        archive.writestr("libs/app/build.gradle", LEAF)
        archive.writestr("libs/ordinary/Keep.kt", KEEP)
    inventory, sources = inputs.inspect_target(target)
    assert _dep(inventory, "fresh:derived")["version"] == "1.0"
    assert inventory["partial"] is False
    assert dict(sources)["libs/ordinary/Keep.kt"] == KEEP.decode()


@pytest.mark.parametrize("name", ["../libs/build.gradle/Keep.kt", "/libs/build.gradle/Keep.kt"])
def test_directory_inference_does_not_admit_unsafe_archive_paths(tmp_path: Path, name: str) -> None:
    target = tmp_path / "fresh-unsafe-directory.zip"
    with zipfile.ZipFile(target, "w") as archive:
        archive.writestr(name, KEEP)
    with pytest.raises(ValueError, match="Unsafe archive member path"):
        inputs.inspect_target(target)
