from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import sys
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

MAX_FILE = 8 * 1024 * 1024
MAX_ARCHIVE_TOTAL = 512 * 1024 * 1024
MAX_FILES = 12000
MAX_SOURCE_TOTAL = 64 * 1024 * 1024
RULE_VERSION = "2026.10.09.apsa.140"


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def uid(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:16]}"


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def redact(text: str) -> str:
    text = re.sub(r"\b(?:sk-[A-Za-z0-9_-]{8,}|gh[pousr]_[A-Za-z0-9_]+)\b", "[REDACTED]", text)
    text = re.sub(r"(?i)(bearer\s+)[A-Za-z0-9._~+/=-]+", r"\1[REDACTED]", text)
    text = re.sub(
        r"(?i)((?:api[_-]?key|password|secret|access[_-]?token|refresh[_-]?token)\s*[=:]\s*)[^\s,;]+",
        r"\1[REDACTED]",
        text,
    )
    return re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", text)


def code_excerpt(line: str) -> str:
    # Literal contents are unnecessary for locating an unsafe API and may contain credentials.
    return redact(re.sub(r"""(["'])(?:\\.|(?!\1).)*?\1""", '"…"', line))[:240]


def read_json(path: Path, *, authorized: bool = False) -> Any:
    # A caller-bound path must keep its authorized spelling: resolving again
    # would follow an ancestor replaced after the caller's root check.
    source = path if authorized else path.expanduser().parent.resolve() / path.name
    return json.loads(read_bounded(source).decode("utf-8"))


def read_bounded(path: Path, limit: int = MAX_FILE) -> bytes:
    fd = open_file(path)
    with os.fdopen(fd, "rb") as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise ValueError("Input must be a regular file")
        value = stream.read(limit + 1)
    if len(value) > limit:
        raise ValueError(f"File exceeds {limit} bytes: {path.name}")
    return value


def file_digest(path: Path, limit: int = MAX_ARCHIVE_TOTAL) -> str:
    hasher = hashlib.sha256()
    size = 0
    fd = open_file(path)
    with os.fdopen(fd, "rb") as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise ValueError("Input must be a regular file")
        while chunk := stream.read(1024 * 1024):
            size += len(chunk)
            if size > limit:
                raise ValueError("Input exceeds safe size limit")
            hasher.update(chunk)
    return hasher.hexdigest()


def open_directory(path: Path) -> int:
    """Open every directory component without following a replaced ancestor symlink."""
    if os.name != "posix":
        raise ValueError("Secure input traversal currently requires macOS or Linux")
    path = path.expanduser().absolute()
    if ".." in path.parts:
        raise ValueError("Input path must be normalized before inspection")
    if sys.platform == "darwin":
        # XNU O_NOFOLLOW_ANY atomically rejects ancestor symlinks. Opening the
        # authorized full path also respects macOS grants limited to a project
        # folder, where opening its Desktop/Documents ancestor can be denied.
        return os.open(path, os.O_RDONLY | os.O_DIRECTORY | 0x20000000)
    current = os.open(path.anchor, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in path.parts[1:]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=current)
            os.close(current)
            current = child
        return current
    except BaseException:
        os.close(current)
        raise


def open_file(path: Path) -> int:
    directory = open_directory(path.parent)
    try:
        return os.open(path.name, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW, dir_fd=directory)
    finally:
        os.close(directory)


def read_under(root: Path, relative: Path, limit: int = MAX_FILE) -> bytes:
    """Walk a source/container path through directory descriptors without symlinks."""
    if relative.is_absolute() or any(part in {"..", "."} for part in relative.parts) or not relative.parts:
        raise ValueError("Invalid relative input path")
    if os.name != "posix":
        raise ValueError("Secure source traversal currently requires macOS or Linux")
    current = open_directory(root)
    try:
        for part in relative.parts[:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=current)
            os.close(current)
            current = child
        fd = os.open(relative.parts[-1], os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW, dir_fd=current)
        with os.fdopen(fd, "rb") as stream:
            before = os.fstat(stream.fileno())
            if not stat.S_ISREG(before.st_mode):
                raise ValueError("Input must be a regular file")
            raw = stream.read(limit + 1)
            after = os.fstat(stream.fileno())
            if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
                raise ValueError("Input changed during inspection; rerun with a stable build")
        if len(raw) > limit:
            raise ValueError("File exceeds input limit")
        return raw
    finally:
        os.close(current)


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def finding_identity(rule: str, evidence: list[dict], scope: str = "app") -> str:
    locations = []
    for entry in evidence:
        location = {
            k: entry[k]
            for k in (
                "path",
                "line",
                "function",
                "class",
                "method",
                "instruction_offset",
                "offset",
                "platform",
                "component",
                "slice",
                "architecture",
                "source",
                "sink",
                "scenario_identity",
            )
            if k in entry
        }
        if dep := entry.get("dependency"):
            location["dependency"] = {k: dep.get(k, "") for k in ("name", "ecosystem", "path")}
        if assertion := entry.get("assertion"):
            location["assertion"] = {
                k: assertion.get(k, "")
                for k in ("baseline", "snapshot", "marker", "surface", "kind", "expected")
            }
        locations.append(location)
    return f"F-{digest(canonical_json([rule, scope, locations]).encode())[:20]}"


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as output:
            json.dump(value, output, ensure_ascii=False, indent=2)
            output.write("\n")
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def finding(
    rule: str,
    title: str,
    severity: str,
    status: str,
    evidence: list[dict],
    remediation: str,
    masvs: str = "",
    references: list[str] | None = None,
    **extra: Any,
) -> dict:
    return {
        "id": finding_identity(rule, evidence, extra.get("scope", "app")),
        "identity_version": 1,
        "rule_id": rule,
        "title": title,
        "severity": severity,
        "status": status,
        "evidence": evidence,
        "remediation": remediation,
        "masvs": masvs,
        "references": references or [],
        **extra,
    }


def severity_rank(value: str) -> int:
    return {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}.get(value, 0)


def report_incomplete(report: dict) -> bool:
    """Explicitly partial work is incomplete; optional not-run checks remain visible."""
    runtime = report.get("runtime", [])
    online = report.get("online_query", {})
    inventory = report.get("inventory", {})
    return bool(
        report.get("partial") is True
        or (isinstance(inventory, dict) and inventory.get("partial") is True)
        or any(check.get("state") == "partial" for check in report.get("coverage", []))
        or (
            isinstance(runtime, list)
            and runtime
            and isinstance(runtime[-1], dict)
            and runtime[-1].get("partial") is True
        )
        or (isinstance(online, dict) and online.get("requested") and online.get("errors"))
    )
