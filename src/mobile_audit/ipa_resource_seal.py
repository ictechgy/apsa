"""Bounded archive resource hash concordance, separate from signing authenticity."""

from __future__ import annotations

import hashlib
import plistlib
import stat
import zipfile
from pathlib import PurePosixPath

MAX_RESOURCE_BYTES = 128 * 1024 * 1024
MAX_RESOURCE_FILES = 4096
MAX_ENVELOPE_BYTES = 2 * 1024 * 1024
RESOURCE_HASHES = {
    "hash": ("sha1", 20),
    "hash2": ("sha256", 32),
    "hash3": ("sha256", 20),
    "hash4": ("sha384", 48),
}


class _UniqueKeys(dict):
    def __setitem__(self, key, value):
        if key in self:
            raise ValueError("duplicate resource dictionary key")
        super().__setitem__(key, value)


def _safe_relative(name: object) -> bool:
    return (
        isinstance(name, str)
        and bool(name)
        and len(name) <= 4096
        and "\\" not in name
        and "\0" not in name
        and not name.startswith("/")
        and all(part not in {"", ".", ".."} for part in name.split("/"))
    )


def verify_resource_seal(
    archive: zipfile.ZipFile, root: str, executable: str, envelope: bytes | None
) -> dict:
    result = {
        "state": "missing",
        "hashes_verified": False,
        "rules_state": "not-run",
        "app_authenticity_verified": False,
        "checked_files": 0,
        "modified_files": 0,
        "missing_files": 0,
        "unsupported_entries": 0,
    }

    def incomplete(reason: str) -> dict:
        # A later coverage gap cannot erase a hash mismatch, missing sealed file
        # or modeled catch-all violation that this inspection already observed.
        modified = (
            result["modified_files"]
            or result["missing_files"]
            or (result["rules_state"] == "checked" and result.get("unsealed_files", 0))
        )
        return {**result, "state": "modified" if modified else "partial", "partial": True, "reason": reason}

    if envelope is None:
        return result
    if len(envelope) > MAX_ENVELOPE_BYTES:
        return {**result, "state": "unsupported", "reason": "resource envelope byte budget"}
    try:
        value = plistlib.loads(envelope, dict_type=_UniqueKeys)
    except Exception:
        return {**result, "state": "unsupported", "reason": "malformed resource envelope"}
    if not isinstance(value, dict):
        return {**result, "state": "unsupported", "reason": "resource envelope is not a dictionary"}
    version = 2 if "files2" in value else 1
    files, rules = (
        value.get("files2" if version == 2 else "files"),
        value.get("rules2" if version == 2 else "rules"),
    )
    result["envelope_version"] = version
    # Do not run attacker-selected regexes. Only a plain catch-all is modeled.
    modeled_rules = (
        version == 2 and isinstance(rules, dict) and set(rules) == {"^.*"} and rules["^.*"] is True
    )
    result["rules_state"] = "checked" if modeled_rules else "unsupported"
    if not isinstance(files, dict) or len(files) > MAX_RESOURCE_FILES:
        return {**result, "state": "unsupported", "reason": "invalid resource map or file budget"}
    bundle_members = [i for i in archive.infolist() if i.filename.startswith(root + "/") and not i.is_dir()]
    if len(bundle_members) > MAX_RESOURCE_FILES:
        return incomplete("bundle member budget")
    members = {i.filename[len(root) + 1 :]: i for i in bundle_members}
    if len(members) != len(bundle_members) or any(not _safe_relative(name) for name in members):
        return {**result, "state": "unsupported", "reason": "ambiguous or unsafe resource member paths"}
    excluded = {"Info.plist", PurePosixPath(executable).name}
    unsealed = sum(
        name not in files and name not in excluded and not name.startswith("_CodeSignature/")
        for name in members
    )
    result["unsealed_files"] = unsealed
    total = 0
    for name, seal in files.items():
        if not _safe_relative(name):
            result["unsupported_entries"] += 1
            continue
        if isinstance(seal, bytes):
            seal = {"hash": seal}
        if (
            not isinstance(seal, dict)
            or not seal
            or set(seal) - {*RESOURCE_HASHES, "optional"}
            or ("optional" in seal and not isinstance(seal["optional"], bool))
        ):
            result["unsupported_entries"] += 1
            continue
        hashes = [(key, descriptor) for key, descriptor in RESOURCE_HASHES.items() if key in seal]
        if not hashes or any(not isinstance(seal[k], bytes) or len(seal[k]) != d[1] for k, d in hashes):
            result["unsupported_entries"] += 1
            continue
        member = members.get(name)
        if member is None:
            if not seal.get("optional", False):
                result["missing_files"] += 1
            continue
        mode = member.external_attr >> 16
        if stat.S_ISLNK(mode) or (stat.S_IFMT(mode) and not stat.S_ISREG(mode)):
            result["unsupported_entries"] += 1
            continue
        if total + member.file_size > MAX_RESOURCE_BYTES:
            return incomplete("resource byte budget")
        digests = {k: hashlib.new(d[0]) for k, d in hashes}
        count = 0
        try:
            with archive.open(member) as stream:
                while chunk := stream.read(65536):
                    count += len(chunk)
                    if count > member.file_size or total + count > MAX_RESOURCE_BYTES:
                        return incomplete("resource stream budget")
                    for digest in digests.values():
                        digest.update(chunk)
        except (OSError, ValueError, RuntimeError, NotImplementedError, zipfile.BadZipFile):
            return incomplete("resource member unreadable")
        total += count
        result["checked_files"] += 1
        if count != member.file_size or any(digests[k].digest()[: d[1]] != seal[k] for k, d in hashes):
            result["modified_files"] += 1
    result["hashes_verified"] = not (
        result["modified_files"] or result["missing_files"] or result["unsupported_entries"]
    )
    result["state"] = (
        "modified"
        if result["modified_files"] or result["missing_files"] or (modeled_rules and unsealed)
        else "partial"
        if not modeled_rules or result["unsupported_entries"]
        else "consistent"
    )
    result["reason"] = (
        "Resource hashes only; CodeDirectory binding and nested-code/signing policy are separate"
    )
    return result
