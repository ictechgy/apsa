"""Bounded package-query snapshots retain distinct upstream advisory revisions."""

from __future__ import annotations

import json
from datetime import datetime

from .core import canonical_json, digest, severity_rank
from .store import Store

MAX_MEMBERS = 1000
MAX_MEMBER_BYTES = 16 * 1024 * 1024
PROJECTIONS = {"snapshot_hash", "branch_id", "observed_at", "osv_records", "osv_ids", "osv_legacy_records"}


def _flatten(
    rows: list[dict], source: str, *, legacy: bool = False
) -> tuple[dict[str, dict], dict[str, dict]]:
    if len(rows) > MAX_MEMBERS:
        raise ValueError("OSV member count budget exceeded")
    result: dict[str, dict] = {}
    opaque: dict[str, dict] = {}
    for row in rows:
        if not isinstance(row, dict):
            raise ValueError("Invalid OSV member row")
        members = row.get("osv_records", [row])
        retained = row.get("osv_legacy_records", []) if legacy else []
        if any(not isinstance(items, list) or len(items) > MAX_MEMBERS for items in (members, retained)):
            raise ValueError("Invalid OSV member collection")
        for value in [*members, *retained]:
            if not isinstance(value, dict) or value.get("source") != source:
                raise ValueError("OSV member source mismatch")
            if not isinstance(value.get("id"), str) or not value["id"]:
                raise ValueError("OSV display identity unavailable")
            member = {key: item for key, item in value.items() if key not in PROJECTIONS}
            identifier = value.get("osv_id")
            if identifier is None and legacy:
                # An old display CVE cannot be invented as an upstream ID.
                opaque[digest(canonical_json(member).encode())] = member
            elif not isinstance(identifier, str) or not identifier or len(identifier) > 200:
                raise ValueError("OSV upstream identity unavailable")
            else:
                previous = result.get(identifier)
                result[identifier] = _revision(previous, member) if previous else member
            if len(result) + len(opaque) > MAX_MEMBERS:
                raise ValueError("OSV member count budget exceeded")
    return result, opaque


def _semantic(value: dict, *, aliases_known: bool) -> str:
    set_fields = {"aliases", "references", "affected", "versions", "ranges", "severity_metrics"}

    def normalize(item, field=""):
        if isinstance(item, dict):
            return {key: normalize(child, key) for key, child in item.items()}
        if isinstance(item, list):
            values = [normalize(child) for child in item]
            if field in set_fields:
                unique = {canonical_json(child): child for child in values}
                return [unique[key] for key in sorted(unique)]
            return values  # In particular, OSV range event order is semantic.
        return item

    omitted = {"provenance", "modified", "id"}
    if not aliases_known:
        omitted.add("aliases")
    return canonical_json(normalize({key: item for key, item in value.items() if key not in omitted}))


def _same_revision(previous: dict, current: dict) -> dict:
    # Pre-alias-schema singleton rows genuinely lack this observation. Missing
    # metadata is unknown; a validated new response may enrich it, not erase it.
    known = "aliases" in previous and "aliases" in current
    if _semantic(previous, aliases_known=known) != _semantic(current, aliases_known=known):
        raise ValueError("Conflicting OSV member at the same revision")
    if "aliases" not in current and "aliases" in previous:
        current = {**current, "aliases": previous["aliases"]}
    return current


def _revision(previous: dict, current: dict) -> dict:
    old, new = previous.get("modified", ""), current.get("modified", "")
    if not isinstance(old, str) or not isinstance(new, str):
        raise ValueError("Invalid OSV member revision")
    if old == new:
        # Retrieval hashes can change when identical advisories occur in differently
        # ordered responses. They are not upstream semantic revisions.
        return _same_revision(previous, current)
    if not old:
        return current
    if not new:
        return previous
    old_time = datetime.fromisoformat(old.replace("Z", "+00:00"))
    new_time = datetime.fromisoformat(new.replace("Z", "+00:00"))
    if old_time.tzinfo is None or new_time.tzinfo is None:
        raise ValueError("OSV member revisions require timezones")
    if old_time == new_time:
        return _same_revision(previous, current)
    return current if new_time > old_time else previous


def aggregate_osv_query(records: list[dict], *, source: str, cached: list[dict] | None = None) -> list[dict]:
    members, opaque = _flatten(cached or [], source, legacy=True)
    incoming, _ = _flatten(records, source)
    for identifier, current in incoming.items():
        previous = members.get(identifier)
        members[identifier] = _revision(previous, current) if previous else current
    if (
        len(members) + len(opaque) > MAX_MEMBERS
        or len(canonical_json([members, opaque]).encode()) > MAX_MEMBER_BYTES
    ):
        raise ValueError("OSV combined member budget exceeded")
    groups: dict[str, list[dict]] = {}
    for identifier in sorted(members):
        member = members[identifier]
        groups.setdefault(member["id"], []).append(member)
    for identifier in sorted(opaque):
        member = opaque[identifier]
        groups.setdefault(member["id"], []).append(member)
    result = []
    for group in groups.values():
        known = [member for member in group if member.get("osv_id") is not None]
        legacy = [member for member in group if member.get("osv_id") is None]
        if len({canonical_json(member.get("query_match")) for member in known}) > 1:
            raise ValueError("OSV member package identity mismatch")
        # Unknown legacy coordinates cannot be borrowed from a new advisory.
        # Keep that observation, but do not let it hide an identified finding.
        scoped = known + [
            member
            for member in legacy
            if not known or member.get("query_match") == known[0].get("query_match")
        ]
        active = [member for member in scoped if not member.get("withdrawn")]
        selected = max(
            active or scoped,
            key=lambda item: (severity_rank(item.get("severity") or "medium"), item.get("osv_id") or ""),
        )
        record = dict(selected)
        record["osv_ids"] = [member["osv_id"] for member in known]
        record["osv_records"] = known
        if legacy:
            record["osv_legacy_records"] = legacy
        if len(group) > 1:
            # A singleton keeps its original upstream metadata/order. Only a
            # true multi-advisory row needs a synthetic deterministic union.
            record["aliases"] = sorted({alias for member in group for alias in member.get("aliases", [])})
            record["references"] = sorted({url for member in group for url in member.get("references", [])})
            affected = {
                canonical_json(item): item for member in active for item in member.get("affected", [])
            }
            record["affected"] = [affected[key] for key in sorted(affected)]
            record["withdrawn"] = None if active else max(member["withdrawn"] for member in scoped)
        result.append(record)
    return sorted(result, key=lambda item: item["id"])


def persist_osv_query(store: Store, source: str, records: list[dict], *, complete: bool) -> None:
    # No network operation occurs under this lock. A partial response must not
    # delete members installed by another writer after an unlocked cache read.
    if store.db.in_transaction:
        raise ValueError("OSV snapshot requires an independent transaction")
    store.db.execute("BEGIN IMMEDIATE")
    try:
        cached = []
        if not complete:
            size = 0
            for row in store.db.execute(
                "SELECT body FROM intel WHERE source=? LIMIT ?", (source, MAX_MEMBERS + 1)
            ):
                size += len(row["body"].encode())
                if len(cached) >= MAX_MEMBERS or size > MAX_MEMBER_BYTES:
                    raise ValueError("OSV cached member budget exceeded")
                cached.append(json.loads(row["body"]))
        grouped = aggregate_osv_query(records, source=source, cached=cached)
        store.replace_source(source, grouped)
    except BaseException:
        store.db.rollback()
        raise
