"""Fresh source fixtures keep omitted Gradle scripts opaque, not absent."""

from __future__ import annotations

import hashlib
import plistlib
import zipfile
from pathlib import Path

import pytest

from mobile_audit import inputs

ROOT = b"ext { releaseVersion = '1.0' }"
LEAF = b'implementation "fresh:leaf:$releaseVersion"'
GOOD = b'ext { healthyVersion = "9.0" }\nimplementation "fresh:healthy:$healthyVersion"'
MANIFEST = b'<manifest package="fresh.fixture"><application/></manifest>'


def _write(tmp_path: Path, files: dict[str, bytes], zipped: bool) -> Path:
    if zipped:
        target = tmp_path / "new-source.zip"
        with zipfile.ZipFile(target, "w") as archive:
            for name, raw in {"AndroidManifest.xml": MANIFEST, **files}.items():
                archive.writestr(name, raw)
        return target
    target = tmp_path / "new-source"
    target.mkdir()
    for name, raw in files.items():
        path = target / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
    return target


def _dep(inventory: dict, name: str = "fresh:leaf") -> dict:
    return next(row for row in inventory["dependencies"] if row["name"] == name)


def _unresolved(inventory: dict) -> None:
    found = _dep(inventory)
    assert found["version"] == "$releaseVersion", found
    assert found["confidence"] == "unknown", found
    assert "version_source" not in found


@pytest.mark.parametrize("suffix", [".gradle", ".gradle.kts"])
@pytest.mark.parametrize("omission", ["oversized", "binary-plist"])
def test_source_zip_omitted_ancestor_cannot_supply_wrong_root_version(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, suffix: str, omission: str
) -> None:
    cap = 128
    monkeypatch.setattr(inputs, "MAX_FILE", cap)
    hidden = (
        b"ext { releaseVersion = '2.0' }" + b" " * cap
        if omission == "oversized"
        else plistlib.dumps({"releaseVersion": "2.0"}, fmt=plistlib.FMT_BINARY)
    )
    target = _write(
        tmp_path,
        {
            "build.gradle": ROOT,
            "libs/build" + suffix: hidden,
            "libs/app/build.gradle": LEAF,
            "healthy/build.gradle": GOOD,
        },
        True,
    )
    inventory, sources = inputs.inspect_target(target)
    _unresolved(inventory)
    assert _dep(inventory, "fresh:healthy")["version"] == "9.0"
    assert inventory["partial"] is True
    assert inventory["fingerprint_complete"] is True
    assert inventory["fingerprint"] == hashlib.sha256(target.read_bytes()).hexdigest()
    assert "libs/build" + suffix not in dict(sources)


@pytest.mark.parametrize("zipped", [False, True])
@pytest.mark.parametrize("via", ["root", "import"])
def test_binary_gradle_context_is_opaque_for_root_and_importers(
    tmp_path: Path, zipped: bool, via: str
) -> None:
    binary = plistlib.dumps({"synthetic": "context"}, fmt=plistlib.FMT_BINARY)
    if via == "root":
        files = {"build.gradle": binary, "app/build.gradle": ROOT + b"\n" + LEAF}
    else:
        files = {
            "build.gradle": ROOT,
            "versions.gradle": binary,
            "app/build.gradle": b"apply from: '../versions.gradle'\n" + LEAF,
        }
    inventory, _ = inputs.inspect_target(_write(tmp_path, files, zipped))
    _unresolved(inventory)
    assert inventory["partial"] is True
    assert inventory["fingerprint_complete"] is True
    assert any("Non-text Gradle context omitted:" in note for note in inventory["warnings"])


@pytest.mark.parametrize("zipped", [False, True])
def test_oversized_root_context_cannot_be_skipped(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, zipped: bool
) -> None:
    monkeypatch.setattr(inputs, "MAX_FILE", 128)
    target = _write(
        tmp_path,
        {"build.gradle": b"evaluate(other)" + b" " * 128, "app/build.gradle": ROOT + b"\n" + LEAF},
        zipped,
    )
    inventory, _ = inputs.inspect_target(target)
    _unresolved(inventory)
    assert inventory["partial"] is True
    assert inventory["fingerprint_complete"] is zipped


@pytest.mark.parametrize("zipped", [False, True])
def test_fully_read_parse_failure_keeps_independent_healthy_context(tmp_path: Path, zipped: bool) -> None:
    target = _write(tmp_path, {"bad/build.gradle": b"/* never closed", "healthy/build.gradle": GOOD}, zipped)
    inventory, _ = inputs.inspect_target(target)
    assert _dep(inventory, "fresh:healthy")["version"] == "9.0"
    assert inventory["partial"] is True
    assert inventory["fingerprint_complete"] is True


@pytest.mark.parametrize("zipped", [False, True])
def test_exact_file_limit_is_read_and_resolves(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, zipped: bool
) -> None:
    script = ROOT + b"\n" + LEAF
    monkeypatch.setattr(inputs, "MAX_FILE", len(script))
    inventory, _ = inputs.inspect_target(_write(tmp_path, {"build.gradle": script}, zipped))
    assert _dep(inventory)["version"] == "1.0"
    assert _dep(inventory)["version_source"]["path"] == "build.gradle"
    assert inventory["partial"] is False


@pytest.mark.parametrize("zipped", [False, True])
def test_source_total_budget_still_blocks_unknown_membership(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, zipped: bool
) -> None:
    script = ROOT + b"\n" + LEAF
    monkeypatch.setattr(inputs, "MAX_SOURCE_TOTAL", len(script) + (len(MANIFEST) if zipped else 0))
    target = _write(tmp_path, {"build.gradle": script, "later.gradle": b" "}, zipped)
    inventory, _ = inputs.inspect_target(target)
    _unresolved(inventory)
    assert inventory["partial"] is True
    assert inventory["fingerprint_complete"] is False


def test_directory_enumeration_omission_does_not_authorize_context(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(inputs, "MAX_FILES", 1)
    target = _write(tmp_path, {"build.gradle": ROOT + b"\n" + LEAF, "later.gradle": b" "}, False)
    inventory, _ = inputs.inspect_target(target)
    _unresolved(inventory)
    assert inventory["fingerprint_complete"] is False


def test_policy_pruned_directory_does_not_create_a_missing_ancestor(tmp_path: Path) -> None:
    target = _write(
        tmp_path,
        {"build.gradle": ROOT + b"\n" + LEAF, "build/build.gradle": b"ext { releaseVersion = 'ignored' }"},
        False,
    )
    inventory, sources = inputs.inspect_target(target)
    assert _dep(inventory)["version"] == "1.0"
    assert "build/build.gradle" not in dict(sources)
    assert inventory["partial"] is False


def test_irrelevant_zip_binary_omission_does_not_block_gradle(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(inputs, "MAX_FILE", 128)
    target = _write(tmp_path, {"build.gradle": ROOT + b"\n" + LEAF, "asset.png": b"x" * 129}, True)
    inventory, _ = inputs.inspect_target(target)
    assert _dep(inventory)["version"] == "1.0"
    assert inventory["partial"] is False


@pytest.mark.parametrize("suffix", [".gradle", ".gradle.kts"])
@pytest.mark.parametrize("omission", ["oversized", "binary-plist"])
def test_omitted_settings_retains_nested_project_boundary(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, suffix: str, omission: str
) -> None:
    monkeypatch.setattr(inputs, "MAX_FILE", 128)
    hidden = b" " * 129 if omission == "oversized" else plistlib.dumps({}, fmt=plistlib.FMT_BINARY)
    target = _write(
        tmp_path,
        {
            "build.gradle": ROOT,
            "nested/settings" + suffix: hidden,
            "nested/app/build.gradle": LEAF,
            "healthy/build.gradle": GOOD,
        },
        True,
    )
    inventory, _ = inputs.inspect_target(target)
    _unresolved(inventory)
    assert _dep(inventory, "fresh:healthy")["version"] == "9.0"
    assert inventory["partial"] is True
    assert inventory["fingerprint_complete"] is True


@pytest.mark.parametrize("suffix", [".gradle", ".gradle.kts"])
def test_available_settings_retains_same_project_boundary(tmp_path: Path, suffix: str) -> None:
    target = _write(
        tmp_path,
        {"build.gradle": ROOT, "nested/settings" + suffix: b"", "nested/app/build.gradle": LEAF},
        True,
    )
    inventory, _ = inputs.inspect_target(target)
    _unresolved(inventory)
    assert inventory["partial"] is False


@pytest.mark.parametrize("name", ["./libs/build.gradle", "libs//build.gradle"])
def test_omitted_archive_ancestor_name_matches_canonical_lookup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, name: str
) -> None:
    monkeypatch.setattr(inputs, "MAX_FILE", 128)
    target = _write(tmp_path, {"build.gradle": ROOT, name: b" " * 129, "libs/app/build.gradle": LEAF}, True)
    inventory, _ = inputs.inspect_target(target)
    _unresolved(inventory)
    assert inventory["partial"] is True
