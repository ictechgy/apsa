"""Inspect explicitly selected APK-set members without claiming installation."""

from __future__ import annotations

import copy
import hashlib
import stat
import tempfile
import zipfile
from collections.abc import Callable
from io import BytesIO
from pathlib import Path, PurePosixPath
from typing import overload

from .core import MAX_ARCHIVE_TOTAL, MAX_FILES, file_digest, finding_identity

MAX_SELECTED_APKS = 64
MAX_APK_BYTES = 128 * 1024 * 1024
MAX_MERGED_RECORDS = 50_000
MAX_COMPRESSION_RATIO = 1000
MAX_TOC_BYTES = 8 * 1024 * 1024


def _members(archive: zipfile.ZipFile) -> list[zipfile.ZipInfo]:
    items = archive.infolist()
    if len(items) > MAX_FILES or sum(item.file_size for item in items) > MAX_ARCHIVE_TOTAL:
        raise ValueError("APK-set archive file/expanded-byte budget exceeded")
    names = set()
    for item in items:
        name = item.filename
        path = PurePosixPath(name.rstrip("/"))
        if (
            not name
            or name.startswith("/")
            or "\\" in name
            or ".." in path.parts
            or str(path) != name.rstrip("/")
            or ":" in name
            or any(ord(char) < 32 for char in name)
            or name in names
        ):
            raise ValueError("APK-set archive has unsafe or duplicate member paths")
        names.add(name)
        mode = item.external_attr >> 16
        if stat.S_ISLNK(mode) or (stat.S_IFMT(mode) and not (stat.S_ISREG(mode) or stat.S_ISDIR(mode))):
            raise ValueError("APK-set archive has a special-file member")
        if item.flag_bits & 1 or item.compress_type not in {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED}:
            raise ValueError("APK-set encrypted or unsupported compressed member")
        if item.file_size > max(1024 * 1024, item.compress_size * MAX_COMPRESSION_RATIO):
            raise ValueError("APK-set archive compression ratio budget exceeded")
    return items


def _read(archive: zipfile.ZipFile, item: zipfile.ZipInfo, limit: int) -> bytes:
    if item.file_size > limit:
        raise ValueError("APK-set member byte budget exceeded")
    with archive.open(item) as stream:
        raw = stream.read(limit + 1)
    if len(raw) != item.file_size or len(raw) > limit:
        raise ValueError("APK-set member differs from its bounded archive declaration")
    return raw


@overload
def _rebase(value: dict, prefix: str) -> dict: ...


@overload
def _rebase(value: list, prefix: str) -> list: ...


@overload
def _rebase(value: object, prefix: str) -> object: ...


def _rebase(value: object, prefix: str) -> object:
    if isinstance(value, list):
        return [_rebase(entry, prefix) for entry in value]
    if not isinstance(value, dict):
        return value
    result = {}
    for key, entry in value.items():
        if key in {"path", "origin", "archive_entry"} and isinstance(entry, str) and entry:
            result[key] = prefix + entry
        else:
            result[key] = _rebase(entry, prefix)
    return result


def analyze_apks(
    target: Path,
    device_spec: dict | None,
    analyze_apk: Callable[..., dict],
    *,
    sbom: Path | None = None,
    specs: dict | None = None,
) -> dict:
    from .apks_selection import DeviceSpec, SelectedApk, select_apks

    if device_spec is None:
        raise ValueError("APK-set inspection requires an explicit device specification")
    device = DeviceSpec.from_dict(device_spec)
    records: list[tuple[SelectedApk, dict, dict, str]] = []
    nested_entries = 0
    expanded_bytes = 0
    with zipfile.ZipFile(target) as archive, tempfile.TemporaryDirectory(prefix="apsa-apks-") as temporary:
        items = _members(archive)
        by_name = {item.filename: item for item in items}
        if "toc.pb" not in by_name or by_name["toc.pb"].is_dir():
            raise ValueError("APK-set archive has no toc.pb")
        selection = select_apks(_read(archive, by_name["toc.pb"], MAX_TOC_BYTES), device, by_name)
        if not selection.selected_apks or len(selection.selected_apks) > MAX_SELECTED_APKS:
            raise ValueError("APK-set selected member count is empty or exceeds the scan budget")
        for index, entry in enumerate(selection.selected_apks):
            item = by_name[entry.path]
            if item.is_dir():
                raise ValueError("APK-set selected member is a directory")
            raw = _read(archive, item, MAX_APK_BYTES)
            with zipfile.ZipFile(BytesIO(raw)) as nested:
                nested_items = _members(nested)
                if "AndroidManifest.xml" not in {member.filename for member in nested_items}:
                    raise ValueError("Selected APK has no AndroidManifest.xml")
                nested_entries += len(nested_items)
                expanded_bytes += sum(member.file_size for member in nested_items)
                if nested_entries > MAX_FILES or expanded_bytes > MAX_ARCHIVE_TOTAL:
                    raise ValueError("Selected APK aggregate expanded-byte/file budget exceeded")
            # Only our generated filenames are materialized; archive paths remain provenance.
            selected_path = Path(temporary).resolve() / f"selected-{index}.apk"
            with selected_path.open("xb") as output:
                selected_path.chmod(0o600)
                output.write(raw)
            report = analyze_apk(selected_path, sbom if index == 0 else None, specs=specs)
            inventory = report["inventory"]
            manifests = [app for app in inventory.get("apps", []) if app.get("basis") == "manifest"]
            if len(manifests) != 1 or not manifests[0].get("package"):
                raise ValueError("Selected APK identity is missing or ambiguous")
            if entry.kind == "split" and manifests[0].get("split", "") != entry.split_id:
                raise ValueError("Selected APK manifest split differs from its TOC identity")
            records.append((entry, report, manifests[0], hashlib.sha256(raw).hexdigest()))
    base = [record for record in records if record[0].module_name == "base" and record[0].is_master_split]
    if not base:
        base = [record for record in records if record[0].kind == "standalone"]
    if len(base) != 1:
        raise ValueError("Selected APK-set has no unique base/standalone identity")
    identity = base[0][2]
    for _, _, observed, _ in records:
        if any(observed.get(key, "") != identity.get(key, "") for key in ("package", "version_code")):
            raise ValueError("Selected APK package/version identities disagree")
    if selection.package_name and selection.package_name != identity["package"]:
        raise ValueError("APK-set TOC package does not match selected APK identity")
    inventory = _rebase(copy.deepcopy(base[0][1]["inventory"]), base[0][0].path + "!/")
    inventory.update(
        target=str(target),
        input_kind="apks",
        fingerprint=file_digest(target),
        fingerprint_complete=True,
        partial=True,
        package=identity["package"],
        archive_role="explicit-device-apk-set",
        apk_set={
            **selection.as_dict(),
            "installed_split_verified": False,
            "manifest_merge_verified": False,
            "selection_basis": "explicit-device-spec-and-bounded-toc",
            "selected_apk_sha256": {entry.path: sha for entry, _, _, sha in records},
        },
        warnings=[],
    )
    list_keys = (
        "apps",
        "deep_links",
        "components",
        "dependencies",
        "android_config",
        "ios_config",
        "features",
    )
    for key in list_keys:
        inventory[key] = []
    inventory["files_scanned"] = 0
    inventory["bytes_scanned"] = 0
    inventory["selected_apk_analysis"] = []
    findings = []
    coverage = []
    total_records = 0
    for entry, report, _, sha in records:
        prefix = entry.path + "!/"
        child = report["inventory"]
        for key in list_keys:
            values = child.get(key, [])
            total_records += len(values)
            inventory[key].extend(_rebase(values, prefix))
        inventory["files_scanned"] += child.get("files_scanned", 0)
        inventory["bytes_scanned"] += child.get("bytes_scanned", 0)
        inventory["warnings"].extend(prefix + note for note in child.get("warnings", []))
        inventory["selected_apk_analysis"].append(
            {
                "path": entry.path,
                "module": entry.module_name,
                "input_sha256": sha,
                "partial": bool(child.get("partial")),
                "binary": _rebase(child.get("binary", {}), prefix),
                "quaygate": _rebase(child.get("quaygate", {}), prefix),
            }
        )
        for item in report["findings"]:
            rebased = _rebase(item, prefix)
            rebased["apk_set_member"] = entry.path
            rebased["module"] = entry.module_name
            rebased["id"] = finding_identity(
                rebased["rule_id"], rebased["evidence"], rebased.get("scope", "app")
            )
            findings.append(rebased)
        for check in report["coverage"]:
            rebased = _rebase(check, prefix)
            rebased["apk_set_member"] = entry.path
            if rebased["state"] == "checked":
                rebased["state"] = "partial"
            coverage.append(rebased)
        total_records += len(report["findings"]) + len(report["coverage"])
        if total_records > MAX_MERGED_RECORDS or len(inventory["warnings"]) > 1024:
            raise ValueError("APK-set report aggregation budget exceeded")
    inventory["features"] = sorted(set(inventory["features"]))
    inventory["warnings"].extend(selection.warnings)
    inventory["warnings"].append(
        "Selected APK members were inspected independently; Android manifest/resource merging and actual installation are unverified."
    )
    inventory["engines"] = sorted(
        {engine for _, report, _, _ in records for engine in report["inventory"].get("engines", [])}
    )
    # Per-member metadata above carries every binary analysis; base-only metadata must not look global.
    for key in ("binary", "quaygate", "source_analysis", "hybrid_analysis"):
        inventory.pop(key, None)
    return {"inventory": inventory, "findings": findings, "coverage": coverage}
