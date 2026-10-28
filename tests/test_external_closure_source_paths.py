"""Fresh public inventory/scan paths retain canonical Gradle context identity."""

from __future__ import annotations

import os
import zipfile
from pathlib import Path

import pytest

from mobile_audit import inputs
from mobile_audit.audit import scan

MANIFEST = b'<manifest package="fresh.paths"><application/></manifest>'
ROOT = b"ext { releaseVersion = '1.0' }"
NEAR = b"ext { releaseVersion = '2.0' }"
LEAF = b'implementation "fresh:leaf:$releaseVersion"'
HEALTHY = b'ext { healthyVersion = "9.0" }\nimplementation "fresh:healthy:$healthyVersion"'


def _zip(tmp_path: Path, files: dict[str, bytes]) -> Path:
    target = tmp_path / "fresh-source.zip"
    with zipfile.ZipFile(target, "w") as archive:
        for name, raw in {"AndroidManifest.xml": MANIFEST, **files}.items():
            archive.writestr(name, raw)
    return target


def _dep(inventory: dict, name: str = "fresh:leaf") -> dict:
    return next(row for row in inventory["dependencies"] if row["name"] == name)


def _unresolved(inventory: dict) -> None:
    row = _dep(inventory)
    assert row["version"] == "$releaseVersion", row
    assert row["confidence"] == "unknown", row
    assert "version_source" not in row


@pytest.mark.parametrize("name", ["libs/build.gradle", "./libs/build.gradle", "libs//build.gradle"])
def test_readable_ancestor_alias_has_same_conservative_inventory_result(tmp_path: Path, name: str) -> None:
    target = _zip(tmp_path, {"build.gradle": ROOT, name: NEAR, "libs/app/build.gradle": LEAF})
    inventory, _ = inputs.inspect_target(target)
    # Both declarations are observed; bounded resolution never chooses a guessed
    # winner among competing ancestor values, regardless of archive spelling.
    _unresolved(inventory)
    assert inventory["partial"] is False


@pytest.mark.parametrize("name", ["./libs/build.gradle", "libs//build.gradle"])
def test_readable_alias_full_scan_does_not_publish_wrong_declared_version(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, store, name: str
) -> None:
    monkeypatch.setenv("APSA_PARSER_SANDBOX", "off")
    target = _zip(tmp_path, {"build.gradle": ROOT, name: NEAR, "libs/app/build.gradle": LEAF})
    report = scan(store, target, online=False)
    _unresolved(report["inventory"])
    assert report["inventory"]["input_snapshot"]["partial"] is False


@pytest.mark.parametrize("name", ["libs/build.gradle", "./libs/build.gradle", "libs//build.gradle"])
def test_unique_nearby_literal_resolves_and_retains_raw_evidence_path(tmp_path: Path, name: str) -> None:
    target = _zip(tmp_path, {name: NEAR, "libs/app/build.gradle": LEAF})
    inventory, _ = inputs.inspect_target(target)
    row = _dep(inventory)
    assert row["version"] == "2.0" and row["confidence"] == "declared"
    assert row["version_source"] == {"path": name, "line": 1, "property": "releaseVersion", "value": "2.0"}


@pytest.mark.parametrize("name", ["build.gradle", "./build.gradle"])
def test_root_interpolation_and_literal_provenance_are_preserved(tmp_path: Path, name: str) -> None:
    target = _zip(tmp_path, {name: ROOT + b'\nimplementation "fresh:literal:4.0"', "app/build.gradle": LEAF})
    inventory, _ = inputs.inspect_target(target)
    assert _dep(inventory)["version"] == "1.0"
    assert _dep(inventory)["version_source"]["path"] == name
    literal = _dep(inventory, "fresh:literal")
    assert literal["version"] == "4.0" and literal["confidence"] == "declared"
    assert literal["path"] == name and "version_source" not in literal


@pytest.mark.parametrize(
    "name", ["libs/app/build.gradle", "./libs/app/build.gradle", "libs//app/build.gradle"]
)
def test_dependency_can_use_its_own_context_under_any_accepted_spelling(tmp_path: Path, name: str) -> None:
    inventory, _ = inputs.inspect_target(_zip(tmp_path, {name: NEAR + b"\n" + LEAF}))
    assert _dep(inventory)["version"] == "2.0"
    assert _dep(inventory)["version_source"]["path"] == name


@pytest.mark.parametrize("imported", ["versions.gradle", "./versions.gradle", "tools//versions.gradle"])
@pytest.mark.parametrize("caller", ["app/build.gradle", "./app/build.gradle"])
def test_import_keys_match_source_keys_without_rewriting_provenance(
    tmp_path: Path, imported: str, caller: str
) -> None:
    reference = "../tools/versions.gradle" if "tools" in imported else "../versions.gradle"
    body = f"apply from: '{reference}'\n".encode() + LEAF
    inventory, _ = inputs.inspect_target(_zip(tmp_path, {imported: NEAR, caller: body}))
    assert _dep(inventory)["version"] == "2.0"
    assert _dep(inventory)["version_source"]["path"] == imported


@pytest.mark.parametrize("same_bytes", [False, True])
def test_canonical_collision_is_opaque_and_does_not_block_healthy_sibling(
    tmp_path: Path, same_bytes: bool
) -> None:
    target = _zip(
        tmp_path,
        {
            "build.gradle": ROOT,
            "libs/build.gradle": NEAR,
            "./libs/build.gradle": NEAR if same_bytes else ROOT,
            "libs/app/build.gradle": LEAF,
            "healthy/build.gradle": HEALTHY,
        },
    )
    inventory, _ = inputs.inspect_target(target)
    _unresolved(inventory)
    assert inventory["partial"] is True
    assert any(
        "Gradle declaration context path collision: libs/build.gradle" in note
        for note in inventory["warnings"]
    )
    assert _dep(inventory, "fresh:healthy")["version"] == "9.0"


def test_opaque_alias_and_readable_alias_cannot_overwrite_each_other(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(inputs, "MAX_FILE", 128)
    target = _zip(
        tmp_path,
        {
            "build.gradle": ROOT,
            "libs/build.gradle": b" " * 129,
            "./libs/build.gradle": NEAR,
            "libs/app/build.gradle": LEAF,
            "healthy/build.gradle": HEALTHY,
        },
    )
    inventory, _ = inputs.inspect_target(target)
    _unresolved(inventory)
    assert inventory["partial"] is True
    assert _dep(inventory, "fresh:healthy")["version"] == "9.0"


@pytest.mark.parametrize("kind", ["symlink", "fifo", "directory"])
def test_known_nonregular_gradle_entry_is_opaque_without_being_opened(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, kind: str
) -> None:
    target = tmp_path / "fresh-directory"
    (target / "libs/app").mkdir(parents=True)
    (target / "healthy").mkdir()
    (target / "build.gradle").write_bytes(ROOT)
    (target / "libs/app/build.gradle").write_bytes(LEAF)
    (target / "healthy/build.gradle").write_bytes(HEALTHY)
    blocked = target / "libs/build.gradle"
    if kind == "symlink":
        outside = tmp_path / "fresh-outside.gradle"
        outside.write_bytes(NEAR)
        blocked.symlink_to(outside)
    elif kind == "fifo":
        os.mkfifo(blocked)
    else:
        blocked.mkdir()
        (blocked / "Keep.kt").write_text("class KeptFreshSource")
    original = inputs.read_under

    def no_entry_read(root: Path, relative: Path) -> bytes:
        assert relative.as_posix() != "libs/build.gradle"
        return original(root, relative)

    monkeypatch.setattr(inputs, "read_under", no_entry_read)
    inventory, sources = inputs.inspect_target(target)
    _unresolved(inventory)
    assert inventory["partial"] is True
    assert any(
        "Non-regular Gradle context omitted without reading: libs/build.gradle" in note
        for note in inventory["warnings"]
    )
    assert _dep(inventory, "fresh:healthy")["version"] == "9.0"
    if kind == "directory":
        assert "libs/build.gradle/Keep.kt" in dict(sources)
