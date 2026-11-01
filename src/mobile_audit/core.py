from __future__ import annotations

import hashlib
import json
import os
import plistlib
import re
import stat
import sys
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .completeness import report_incomplete as report_incomplete
from .completeness import report_limited as report_limited

MAX_FILE = 8 * 1024 * 1024
MAX_REPORT_BYTES = 32 * 1024 * 1024
MAX_ARCHIVE_TOTAL = 512 * 1024 * 1024
MAX_FILES = 12000
MAX_SOURCE_TOTAL = 64 * 1024 * 1024
RULE_VERSION = "2026.11.01.apsa.170"


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


def read_json(path: Path, *, authorized: bool = False, limit: int = MAX_FILE) -> Any:
    # A caller-bound path must keep its authorized spelling: resolving again
    # would follow an ancestor replaced after the caller's root check.
    source = path if authorized else path.expanduser().parent.resolve() / path.name
    return json.loads(read_bounded(source, limit=limit).decode("utf-8"))


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


def load_plist(raw: bytes) -> Any:
    """``plistlib.loads`` for untrusted input: every parser failure becomes ValueError.

    Malformed property lists raise AttributeError, IndexError, LookupError,
    ExpatError and others besides InvalidFileException; none may abort an audit.
    """
    try:
        return plistlib.loads(raw)
    except Exception as error:
        raise ValueError(f"invalid property list ({type(error).__name__})") from None


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


# A dependency advisory finding records at most this many equivalent advisory
# identifiers: its display ID plus the lexicographically first others. Real OSV
# alias sets are far smaller; an omitted alias only means a renamed finding can
# look new again (fail-safe), never that an unrelated one matches.
MAX_ADVISORY_IDS = 32
MAX_ADVISORY_ID_LENGTH = 200


def _advisory_id(value: Any) -> bool:
    return (
        isinstance(value, str)
        and 0 < len(value) <= MAX_ADVISORY_ID_LENGTH
        and not any(character.isspace() for character in value)
    )


def bounded_advisory_ids(display: str, identifiers: Any) -> list[str]:
    """Sorted, deduplicated advisory IDs: the display ID first, then the first others up to the cap."""
    others = sorted({value for value in identifiers if _advisory_id(value)} - {display})
    selected = ([display] if _advisory_id(display) else []) + others
    return sorted(selected[:MAX_ADVISORY_IDS])


def dependency_advisory(item: dict) -> bool:
    """Whether every evidence row locates a dependency (and the finding is not an OS advisory)."""
    evidence = item.get("evidence")
    return (
        item.get("scope", "app") != "environment"
        and isinstance(evidence, list)
        and bool(evidence)
        and all(isinstance(row, dict) and isinstance(row.get("dependency"), dict) for row in evidence)
    )


def advisory_ids(item: dict) -> list[str]:
    """Validated ``advisory_ids`` of a dependency advisory finding; empty for every other finding.

    Reports may come from files, older releases or other tools, so malformed
    entries are dropped and the list is bounded rather than trusted.
    """
    values = item.get("advisory_ids")
    if not isinstance(values, list) or not dependency_advisory(item):
        return []
    return sorted({value for value in values[: MAX_ADVISORY_IDS * 4] if _advisory_id(value)})[
        :MAX_ADVISORY_IDS
    ]


def own_identities(item: dict) -> set[str]:
    """The reported finding ID and the rule/location identity it was derived from."""
    return {item["id"], finding_identity(item["rule_id"], item["evidence"], item.get("scope", "app"))}


def finding_identities(item: dict) -> set[str]:
    """Every identity under which a finding is the same finding across reports and policy.

    Beyond its own identities, a dependency advisory finding is also identified
    by each equivalent advisory ID at the same dependency location, so a display
    ID change (a GHSA advisory gaining a CVE alias, or a lower CVE alias) still
    matches baselines, waivers and comparisons written against the earlier ID.
    ``match_identities`` uses these only against the other side's display ID.
    Reports without ``advisory_ids`` (1.6.4 and earlier) keep their own identities.
    """
    identities = own_identities(item)
    scope = item.get("scope", "app")
    identities.update(finding_identity(alias, item["evidence"], scope) for alias in advisory_ids(item))
    return identities


def match_identities(
    current: list[tuple[set[str], set[str]]], previous: list[tuple[set[str], set[str]]]
) -> list[dict[int, str]]:
    """Map each current entry to the previous entries it is the same finding as.

    Entries are ``(own identities, every identity)`` pairs; own identities derive
    from the display ID (a waiver's own identity is its finding ID). A shared own
    identity matches as it always has (``"identity"``). An entry reaches another by
    advisory alias only through a display ID: one entry's own identity is among the
    other's equivalent identities. Two entries that merely share a third alias (for
    example an umbrella PYSEC or GHSA record listing several CVEs) never reach each
    other. An alias match (``"advisory-alias"``) is accepted only one-to-one: the
    current entry has no identity match and reaches exactly one previous entry, and
    no other current entry reaches that previous entry, by identity or alias.
    Anything else is ambiguous and matches nothing, so the finding is reopened:
    an alias never adds a second prior finding or waiver to an identity match,
    never merges several prior findings into one, and never lets one prior
    finding or waiver cover two current findings.
    """
    own_index: dict[str, list[int]] = {}
    every_index: dict[str, list[int]] = {}
    for index, (own, every) in enumerate(previous):
        for identity in own:
            own_index.setdefault(identity, []).append(index)
        for identity in every | own:
            every_index.setdefault(identity, []).append(index)
    direct: list[set[int]] = []
    aliased: list[set[int]] = []
    reached: dict[int, set[int]] = {}
    for position, (own, every) in enumerate(current):
        exact = {index for identity in own for index in own_index.get(identity, ())}
        # The previous display ID is an equivalent ID of the current entry, or the reverse.
        alias = (
            {index for identity in every | own for index in own_index.get(identity, ())}
            | {index for identity in own for index in every_index.get(identity, ())}
        ) - exact
        direct.append(exact)
        aliased.append(alias)
        for index in exact | alias:
            reached.setdefault(index, set()).add(position)
    matches: list[dict[int, str]] = []
    for position, (exact, alias) in enumerate(zip(direct, aliased, strict=True)):
        if exact:
            matches.append({index: "identity" for index in sorted(exact)})
        elif len(alias) == 1 and reached[min(alias)] == {position}:
            matches.append({min(alias): "advisory-alias"})
        else:
            matches.append({})
    return matches


def match_findings(current: list[dict], previous: list[dict]) -> list[dict[int, str]]:
    """``match_identities`` for two finding lists; see ``finding_identities``."""
    return match_identities(
        [(own_identities(item), finding_identities(item)) for item in current],
        [(own_identities(item), finding_identities(item)) for item in previous],
    )


def advisory_alias_pairs(current: list[dict], previous: list[dict]) -> list[tuple[int, int]]:
    """``(current, previous)`` index pairs that are one dependency advisory under different display IDs.

    Only dependency advisory findings take part, so other (possibly malformed)
    findings are never hashed here.
    """
    after = [index for index, item in enumerate(current) if dependency_advisory(item)]
    before = [index for index, item in enumerate(previous) if dependency_advisory(item)]
    matches = match_findings([current[index] for index in after], [previous[index] for index in before])
    return [
        (after[position], before[index])
        for position, found in enumerate(matches)
        for index, basis in found.items()
        if basis == "advisory-alias"
    ]


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
