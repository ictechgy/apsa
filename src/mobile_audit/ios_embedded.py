"""Inspect declared embedded iOS executables without promoting them to main identity."""

from __future__ import annotations

import plistlib
import re
from pathlib import PurePosixPath
from typing import Any

from .core import digest, finding

MAX_EMBEDDED = 128


def analyze_embedded(archive, main_apps: list[dict], names: set[str], byte_budget: int) -> dict:
    from .binary_analysis import (
        ENTITLEMENTS_FORMAT,
        MACHO_FORMAT,
        MAX_BINARY_BYTES,
        MAX_PLIST_BYTES,
        BinaryFormatError,
        _read_member,
        inspect_macho,
    )

    roots = {str(PurePosixPath(app["plist"]).parent) for app in main_apps}
    metadata: list[dict] = []
    findings: list[dict] = []
    warnings = []
    candidates = []
    declared_executables = set()
    for item in archive.infolist():
        parent = next((root for root in sorted(roots) if item.filename.startswith(root + "/")), None)
        if not parent:
            continue
        if (
            item.filename.endswith("/Info.plist")
            and re.search(r"\.(?:framework|appex|app)/Info\.plist$", item.filename)
            and item.filename != parent + "/Info.plist"
        ):
            candidates.append((item.filename, parent, "bundle"))
        elif item.filename.endswith(".dylib") and item.filename.startswith(parent + "/Frameworks/"):
            candidates.append((item.filename, parent, "dylib"))
    if len(candidates) > MAX_EMBEDDED:
        warnings.append("IPA embedded executable count exceeds metadata budget")
    for path, parent, kind in sorted(candidates)[:MAX_EMBEDDED]:
        entry: dict[str, Any] = {"path": path, "parent_app": parent, "kind": kind, "complete": False}
        try:
            if kind == "bundle":
                info_raw = _read_member(archive, archive.getinfo(path), MAX_PLIST_BYTES)
                info = plistlib.loads(info_raw)
                if not isinstance(info, dict):
                    raise BinaryFormatError("Embedded plist is not a dictionary")
                executable = info.get("CFBundleExecutable")
                if (
                    not isinstance(executable, str)
                    or not executable
                    or executable in {".", ".."}
                    or "/" in executable
                    or "\\" in executable
                ):
                    raise BinaryFormatError("Embedded executable name is unsafe or unavailable")
                executable_path = str(PurePosixPath(path).parent / executable)
                entry["info_plist_sha256"] = digest(info_raw)
                entry["kind"] = PurePosixPath(path).parent.suffix.removeprefix(".")
            else:
                executable_path = path
            if executable_path in declared_executables:
                raise BinaryFormatError("Duplicate embedded executable declaration")
            declared_executables.add(executable_path)
            item = archive.getinfo(executable_path)
            if item.file_size > byte_budget:
                raise BinaryFormatError("Cumulative executable byte budget reached")
            raw = _read_member(archive, item, MAX_BINARY_BYTES)
            byte_budget -= len(raw)
            entry.update({"executable": executable_path, "sha256": digest(raw), "slices": inspect_macho(raw)})
            for index, slice_ in enumerate(entry["slices"]):
                evidence = {
                    "path": executable_path,
                    "parent_app": parent,
                    "embedded_kind": entry["kind"],
                    "slice": index,
                    "architecture": slice_["cpu_type"],
                    "basis": "macho-header",
                }
                if slice_["filetype"] == 2 and not slice_["pie"]:
                    findings.append(
                        finding(
                            "BINARY-IOS-PIE",
                            "Embedded executable does not declare position-independent loading",
                            "medium",
                            "configuration-confirmed",
                            [{**evidence, "pie": False}],
                            "Enable PIE for the intended embedded executable build configuration.",
                            "MASVS-RESILIENCE",
                            [MACHO_FORMAT],
                            origin="binary",
                            confidence="header-observation",
                        )
                    )
                signature = slice_["code_signature"]
                if signature.get("entitlements", {}).get("get-task-allow") is True:
                    findings.append(
                        finding(
                            "BINARY-IOS-DEBUG-ENTITLEMENT",
                            "Embedded executable XML entitlements request debugging",
                            "medium",
                            "candidate"
                            if signature.get("der_entitlements_present")
                            else "configuration-confirmed",
                            [
                                {
                                    **evidence,
                                    "basis": "codesign-entitlement-observed",
                                    "get-task-allow": True,
                                    "signature_verified": False,
                                }
                            ],
                            "Remove debugging entitlement from the embedded distribution build; verify its signature.",
                            "MASVS-RESILIENCE",
                            [ENTITLEMENTS_FORMAT],
                            origin="binary",
                            confidence="embedded-entitlement-observation",
                        )
                    )
            entry["complete"] = all(s["linked_libraries_omitted"] == 0 for s in entry["slices"])
            if any(s["encryption"]["state"] == "encrypted" for s in entry["slices"]):
                warnings.append(
                    "IPA embedded executable declares encryption; native code paths were not inspected: "
                    + executable_path
                )
            if not entry["complete"]:
                warnings.append("IPA embedded linked library metadata exceeds budget: " + executable_path)
        except Exception as error:
            entry["error"] = type(error).__name__
            warnings.append(
                "IPA embedded executable inspection incomplete: " + path + ": " + type(error).__name__
            )
        metadata.append(entry)
    complete = len(candidates) <= MAX_EMBEDDED and all(entry["complete"] for entry in metadata)
    return {"metadata": metadata, "findings": findings, "warnings": warnings, "complete": complete}
