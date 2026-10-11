"""Conservative scalar AAPT2 Resources.proto resolution across modeled tables."""

from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping
from dataclasses import dataclass

from .aab_manifest import REFERENCE, _bytes, _fields, _one, _string
from .selection import relative_source_path

MAX_RESOURCE_BYTES = 8 * 1024 * 1024
MAX_RESOURCE_ENTRIES = 50_000
MAX_RESOURCE_DEPTH = 32


@dataclass(frozen=True)
class Candidate:
    module: str
    identifier: int
    name: str
    config_hash: str
    qualified: bool
    item: bytes | None
    blocked: str = ""


class ResourceResolver:
    def __init__(self, *, max_entries=MAX_RESOURCE_ENTRIES, max_depth=MAX_RESOURCE_DEPTH):
        self.by_id: dict[int, list[Candidate]] = {}
        self.by_name: dict[str, list[Candidate]] = {}
        self.warnings: list[str] = []
        self.evidence: list[dict] = []
        self.partial = False
        self.remaining = max_entries
        self.max_depth = max_depth
        self.resolution_remaining = max_entries * 8

    def fields(self, raw: bytes) -> dict:
        result = _fields(raw)
        self.remaining -= sum(len(values) for values in result.values()) + 1
        if self.remaining < 0:
            raise ValueError("AAB resource cumulative entry/field budget exceeded")
        return result

    def resolution_fields(self, raw: bytes) -> dict:
        result = _fields(raw)
        self.resolution_remaining -= sum(len(values) for values in result.values()) + 1
        if self.resolution_remaining < 0:
            raise ValueError("AAB resource resolution field budget exceeded")
        return result

    def _id(self, fields: dict, number: int, maximum: int) -> int:
        body = self.fields(_bytes(fields, number))
        if set(body) - {1}:
            raise ValueError("Unknown resource ID fields")
        value = _one(body, 1, 0, 0)
        if not isinstance(value, int) or not 0 <= value <= maximum:
            raise ValueError("Invalid resource ID")
        return value

    def _messages(self, fields, number):
        for wire, raw in fields.get(number, []):
            if wire != 2 or not isinstance(raw, bytes):
                raise ValueError("Mistyped resource message")
            yield raw

    def add(self, module: str, raw: bytes):
        table = self.fields(raw)
        if set(table) - {1, 2, 3, 4, 5}:
            raise ValueError("Unknown resource table fields")
        if 5 in table:
            raise ValueError("Dynamic resource table references remain unresolved")
        for package_raw in self._messages(table, 2):
            package = self.fields(package_raw)
            if set(package) - {1, 2, 3}:
                raise ValueError("Unknown resource package fields")
            package_id = self._id(package, 1, 255)
            package_name = _string(package, 2)
            for type_raw in self._messages(package, 3):
                type_ = self.fields(type_raw)
                if set(type_) - {1, 2, 3}:
                    raise ValueError("Unknown resource type fields")
                type_id = self._id(type_, 1, 255)
                type_name = _string(type_, 2)
                if type_id == 0:
                    raise ValueError("Unassigned resource type ID")
                for entry_raw in self._messages(type_, 3):
                    entry = self.fields(entry_raw)
                    if set(entry) - set(range(1, 9)):
                        raise ValueError("Unknown resource entry fields")
                    entry_id = self._id(entry, 1, 65535)
                    entry_name = _string(entry, 2)
                    identifier = package_id << 24 | type_id << 16 | entry_id
                    name = f"{package_name}:{type_name}/{entry_name}"
                    blocked = ""
                    if package_id < 127:
                        blocked = "framework/shared/runtime-assigned package"
                    if 5 in entry or 7 in entry or 8 in entry:
                        blocked = "overlay/staged/flag-dependent resource"
                    values = list(self._messages(entry, 6))
                    if not values:
                        values = [b""]
                    for config_raw in values:
                        config_value = self.fields(config_raw)
                        if set(config_value) - {1, 2}:
                            raise ValueError("Unknown resource configuration/value fields")
                        configuration = _one(config_value, 1, default=b"")
                        if not isinstance(configuration, bytes):
                            raise ValueError("Mistyped resource configuration")
                        # No device specification is available. Nonempty configuration
                        # qualifiers cannot stand for the installed device's choice.
                        if configuration:
                            self.fields(configuration)
                        value_raw = _one(config_value, 2)
                        value = self.fields(value_raw) if isinstance(value_raw, bytes) else {}
                        item = _one(value, 4)
                        reason = blocked
                        if set(value) - {1, 2, 3, 4, 5} or 5 in value or _one(value, 3, 0, 0):
                            reason = "unsupported compound/weak resource value"
                        if not isinstance(item, bytes):
                            reason = "missing scalar resource value"
                            item = None
                        candidate = Candidate(
                            module,
                            identifier,
                            name,
                            hashlib.sha256(configuration).hexdigest(),
                            bool(configuration),
                            item,
                            reason,
                        )
                        self.by_id.setdefault(identifier, []).append(candidate)
                        self.by_name.setdefault(name, []).append(candidate)
                        self.by_name.setdefault(f"{type_name}/{entry_name}", []).append(candidate)

    def _scalar(self, raw: bytes, seen: frozenset[int], depth: int):
        self.resolution_remaining -= 1
        if self.resolution_remaining < 0 or depth > self.max_depth:
            return None, "resource resolution depth/work budget reached", []
        fields = self.resolution_fields(raw)
        variants = [number for number in range(1, 8) if number in fields]
        if len(variants) != 1 or set(fields) - set(range(1, 11)):
            return None, "unsupported scalar item schema", []
        if any(_one(fields, field, 0, 0) for field in (8, 9)) or _string(fields, 10):
            return None, "flag-dependent scalar value", []
        kind = variants[0]
        body = self.resolution_fields(_bytes(fields, kind))
        if kind == 1:
            if set(body) - set(range(1, 8)) or _one(body, 1, 0, 0) != 0 or _one(body, 6, 0, 0):
                return None, "theme/unknown reference flags", []
            dynamic = _one(body, 5)
            if dynamic is not None:
                flags = self.resolution_fields(dynamic)
                if set(flags) - {1} or _one(flags, 1, 0, 0):
                    return None, "dynamic resource reference", []
            identifier = _one(body, 2, 0, 0)
            name = _string(body, 3).lstrip("@")
            candidates = self.by_id.get(identifier, []) if identifier else self.by_name.get(name, [])
            if name and identifier:
                named = self.by_name.get(name, [])
                if not named or {c.identifier for c in named} != {identifier}:
                    return None, "conflicting reference ID/name", []
            if not candidates:
                return None, "referenced scalar is absent", []
            if any(c.identifier in seen for c in candidates):
                return None, "resource alias cycle", candidates
            if any(c.blocked or c.qualified for c in candidates):
                return None, "device-qualified/unsupported resource value", candidates
            values = []
            provenance = list(candidates)
            for candidate in candidates:
                if candidate.item is None:
                    return None, "missing scalar resource value", provenance
                value, reason, nested = self._scalar(candidate.item, seen | {candidate.identifier}, depth + 1)
                provenance.extend(nested[: max(0, 128 - len(provenance))])
                if value is None:
                    return None, reason, provenance
                values.append(value)
            if len(set(values)) != 1:
                return None, "resource values conflict across modules/configurations", provenance
            return values[0], "", provenance
        if kind in {2, 3}:
            if set(body) - {1}:
                return None, "unsupported string fields", []
            return _string(body, 1), "", []
        if kind == 5:
            if set(body) - {1, 2} or _one(body, 2, 0, 0) not in {0, 1, 2, 3}:
                return None, "unknown FileReference type", []
            path = _string(body, 1)
            try:
                relative_source_path(path)
            except ValueError:
                return None, "unsafe FileReference path", []
            return path, "", []
        if kind == 7:
            variants = list(body)
            if len(variants) != 1 or variants[0] not in {6, 7, 8}:
                return None, "unsupported resource primitive", []
            primitive = variants[0]
            number = _one(body, primitive, 0)
            if not isinstance(number, int):
                return None, "missing or mistyped resource integer", []
            if primitive == 8:
                if number not in {0, 1}:
                    return None, "noncanonical resource boolean", []
                return "true" if number else "false", "", []
            if primitive == 6 and 0xFFFFFFFF80000000 <= number <= 0xFFFFFFFFFFFFFFFF:
                number -= 1 << 64
            elif not 0 <= number <= 0xFFFFFFFF:
                return None, "resource integer outside 32-bit range", []
            if primitive == 6 and number >= 1 << 31:
                number -= 1 << 32
            return str(number), "", []
        return None, "unsupported resource scalar", []

    def resolve_item(self, raw: bytes) -> str | None:
        try:
            value, reason, candidates = (
                (None, "resource table inventory is partial", [])
                if self.partial
                else self._scalar(raw, frozenset(), 0)
            )
        except (ValueError, TypeError, UnicodeError):
            value, reason, candidates = None, "malformed scalar resource value", []
        if len(self.evidence) < 256:
            self.evidence.append(
                {
                    "state": "resolved" if value is not None else "unresolved",
                    "reason": reason,
                    "schema": REFERENCE,
                    "candidates": [
                        {
                            "module": c.module,
                            "resource_id": f"0x{c.identifier:08x}",
                            "name": c.name,
                            "configuration_hash": c.config_hash,
                            "qualified": c.qualified,
                        }
                        for c in candidates[:64]
                    ],
                }
            )
        if reason and len(self.warnings) < 128:
            self.warnings.append("AAB scalar resource unresolved: " + reason)
        return value


def build_resources(
    tables: Mapping[str, bytes],
    *,
    max_bytes: int = MAX_RESOURCE_BYTES,
    max_entries: int = MAX_RESOURCE_ENTRIES,
    max_depth: int = MAX_RESOURCE_DEPTH,
) -> ResourceResolver:
    for budget, ceiling in (
        (max_bytes, MAX_RESOURCE_BYTES),
        (max_entries, MAX_RESOURCE_ENTRIES),
        (max_depth, MAX_RESOURCE_DEPTH),
    ):
        if isinstance(budget, bool) or not isinstance(budget, int) or not 1 <= budget <= ceiling:
            raise ValueError("Resource budgets must be positive bounded integers")
    resolver = ResourceResolver(max_entries=max_entries, max_depth=max_depth)
    if len(tables) > 128:
        raise ValueError("AAB resource module budget exceeded")
    total = 0
    for module, raw in sorted(tables.items()):
        if (
            not isinstance(module, str)
            or not re.fullmatch(r"[A-Za-z0-9_.-]+", module)
            or module in {".", ".."}
        ):
            raise ValueError("Invalid AAB resource module name")
        if not isinstance(raw, bytes) or not raw:
            raise ValueError("AAB resource table must contain bytes")
        total += len(raw)
        if total > max_bytes:
            raise ValueError("AAB resource cumulative byte budget exceeded")
        try:
            resolver.add(module, raw)
        except (ValueError, UnicodeError):
            resolver.partial = True
            resolver.warnings.append("AAB resource table malformed, unsupported or over budget: " + module)
    return resolver
