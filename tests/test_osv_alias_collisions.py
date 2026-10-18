"""Synthetic OSV cache alias regressions; MockTransport and in-memory SQLite only.

The query-layer aggregate schema: osv_ids and flat osv_records contain
exact upstream identities; canonical id remains the existing display identifier.
No app source, SDK, process, listener, network, or retained state is used.
"""

from __future__ import annotations

import copy
import json
import sqlite3
from unittest.mock import patch

import httpx
import pytest

from mobile_audit import intel
from mobile_audit import store as store_module
from mobile_audit.audit import correlate
from mobile_audit.core import canonical_json, finding_identity
from mobile_audit.policy import evaluate

CVE = "CVE-2099-4242"
STRONG = "GHSA-synthetic-critical"
WEAK = "PYSEC-synthetic-unrated"
DEP = {
    "ecosystem": "Maven",
    "name": "synthetic.public:alias-library",
    "version": "1.0",
    "confidence": "exact",
    "path": "app/gradle.lockfile",
}
SOURCE = f"osv:{DEP['ecosystem']}:{DEP['name']}:{DEP['version']}"
MODIFIED = "2026-10-18T00:00:00Z"
WITHDRAWN = "2026-10-18T01:00:00Z"


@pytest.fixture
def memory_store(tmp_path):
    real_connect = sqlite3.connect
    # Run the real Store initializer/migrations while the database stays in memory.
    # New immutable snapshot JSON files remain solely below this test's tmp_path.
    with patch.object(
        store_module.sqlite3,
        "connect",
        side_effect=lambda *args, **kwargs: real_connect(":memory:", timeout=30),
    ):
        database = store_module.Store(tmp_path / "memory-home")
    try:
        yield database
    finally:
        database.close()


def advisory(identifier, *, critical=False, withdrawn=False, older=False):
    value = {
        "id": identifier,
        "aliases": [CVE, f"SYNTHETIC-ALIAS-{identifier}"],
        "modified": "2026-10-17T00:00:00Z" if older else MODIFIED,
        "summary": f"Synthetic advisory {identifier}",
        "affected": [
            {
                "package": {"ecosystem": DEP["ecosystem"], "name": DEP["name"]},
                "versions": [DEP["version"]] if identifier == STRONG else [DEP["version"], "2.0"],
            }
        ],
        "references": [{"url": f"https://example.invalid/{identifier}"}],
    }
    if critical:
        value["severity"] = [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]
    if withdrawn:
        value["withdrawn"] = WITHDRAWN
    return value


def query(database, monkeypatch, mode, records, *, partial=False):
    records = copy.deepcopy(records)
    by_id = {value["id"]: value for value in records}
    assert len(by_id) == len(records)
    calls = []
    if partial:
        # Legacy stops at a real bounded pagination boundary, not a transport
        # exception that discards all records from its current query.
        monkeypatch.setattr(intel, "MAX_OSV_PAGES", 1)

    def respond(request):
        calls.append((request.method, request.url.path))
        if request.url.path == "/v1/query":
            return httpx.Response(
                200,
                json={"vulns": records, **({"next_page_token": "unread-next"} if partial else {})},
            )
        if request.url.path == "/v1/querybatch":
            payload = json.loads(request.content)
            assert len(payload["queries"]) == 1
            stubs = [{"id": value["id"], "modified": value["modified"]} for value in records]
            if partial:
                stubs.append({"id": "GHSA-synthetic-unavailable", "modified": MODIFIED})
            return httpx.Response(200, json={"results": [{"vulns": stubs}]})
        identifier = request.url.path.rsplit("/", 1)[-1]
        if request.method == "GET" and identifier in by_id:
            return httpx.Response(200, json=by_id[identifier])
        if request.method == "GET" and identifier == "GHSA-synthetic-unavailable":
            return httpx.Response(503)
        raise AssertionError("Unexpected synthetic request")

    states = []
    with httpx.Client(transport=httpx.MockTransport(respond), trust_env=False) as client:
        found, errors = intel.query_dependencies(
            database, [copy.deepcopy(DEP)], client, query_mode=mode, package_states=states
        )
    cached = [row for row in database.intelligence(limit=100) if row["source"] == SOURCE]
    findings, _ = correlate({"dependencies": [copy.deepcopy(DEP)], "platforms": []}, cached)
    assert states[0]["checked"] is (not partial)
    assert states[0]["state"] == ("partial" if partial else "complete")
    assert bool(errors) is partial
    assert calls
    return found, cached, findings


def members(row):
    assert isinstance(row["osv_records"], list)
    result = {record["osv_id"]: record for record in row["osv_records"]}
    assert len(result) == len(row["osv_records"])
    assert row["osv_ids"] == sorted(result)
    assert [record["osv_id"] for record in row["osv_records"]] == sorted(result)
    assert all(not record.get("osv_records") for record in result.values())
    return result


def refresh_again(database):
    # A complete first query creates a fresh feed; force a synthetic refresh so
    # batch caching cannot skip the second response under test.
    database.feed(SOURCE, "error", error="Synthetic refresh requested")


def critical_policy(findings):
    return evaluate(
        {"target": "/synthetic/osv-alias", "findings": findings, "coverage": [], "inventory": {}},
        {
            "schema_version": 1,
            "thresholds": {"critical": 0, "high": -1, "medium": -1, "low": -1, "info": -1},
            "fail_on_partial": False,
        },
    )


@pytest.mark.parametrize("mode", ["legacy", "batch"])
@pytest.mark.parametrize("reverse", [False, True])
@pytest.mark.parametrize("withdrawn_alias", [False, True])
def test_alias_order_preserves_live_maximum_and_every_upstream_identity(
    memory_store, monkeypatch, mode, reverse, withdrawn_alias
):
    values = [advisory(STRONG, critical=True), advisory(WEAK, withdrawn=withdrawn_alias)]
    found, cached, findings = query(
        memory_store, monkeypatch, mode, list(reversed(values)) if reverse else values
    )
    assert len(cached) == 1 and len(findings) == 1
    row = cached[0]
    assert row["id"] == CVE and row["severity"] == "critical"
    assert row["osv_id"] == STRONG  # Deterministic highest-active-severity representative.
    assert row["severity_basis"] == "CVSS_V3" and not row.get("withdrawn")
    exact = members(row)
    assert set(exact) == {STRONG, WEAK}
    assert bool(exact[WEAK].get("withdrawn")) is withdrawn_alias
    assert set(row["aliases"]) >= {CVE, *[f"SYNTHETIC-ALIAS-{identifier}" for identifier in exact]}
    assert set(row["references"]) == {f"https://example.invalid/{identifier}" for identifier in exact}
    assert [item["severity"] for item in findings] == ["critical"]
    assert findings[0]["id"] == finding_identity(CVE, [{"dependency": DEP}])
    active = [member for member in exact.values() if not member.get("withdrawn")]
    assert {canonical_json(item) for item in row["affected"]} == {
        canonical_json(item) for member in active for item in member["affected"]
    }
    assert critical_policy(findings)["state"] == "failed"
    # Return values retain exact primary records for component retrieval scoring.
    assert {item["osv_id"] for item in found} == {STRONG, WEAK}


@pytest.mark.parametrize("mode", ["legacy", "batch"])
@pytest.mark.parametrize("withdrawn_alias", [False, True])
def test_partial_query_preserves_absent_cached_upstream_member(
    memory_store, monkeypatch, mode, withdrawn_alias
):
    # Exercise migration from an existing singleton normalized cache record.
    memory_store.upsert_intel([intel._normalize_osv(advisory(STRONG, critical=True, older=True), DEP)])
    _, cached, findings = query(
        memory_store, monkeypatch, mode, [advisory(WEAK, withdrawn=withdrawn_alias)], partial=True
    )
    assert len(cached) == 1 and len(findings) == 1
    assert set(members(cached[0])) == {STRONG, WEAK}
    assert cached[0]["severity"] == "critical" and not cached[0].get("withdrawn")
    assert critical_policy(findings)["state"] == "failed"


@pytest.mark.parametrize("mode", ["legacy", "batch"])
def test_partial_new_withdrawal_replaces_only_that_upstreams_old_live_revision(
    memory_store, monkeypatch, mode
):
    query(memory_store, monkeypatch, mode, [advisory(STRONG, critical=True, older=True), advisory(WEAK)])
    refresh_again(memory_store)
    _, cached, findings = query(
        memory_store, monkeypatch, mode, [advisory(STRONG, critical=True, withdrawn=True)], partial=True
    )
    assert len(cached) == 1 and len(findings) == 1
    row = cached[0]
    exact = members(row)
    assert set(exact) == {STRONG, WEAK} and exact[STRONG]["withdrawn"] == WITHDRAWN
    assert row["severity"] is None and row["severity_basis"] == "unknown"
    assert not row.get("withdrawn") and findings[0]["severity"] == "medium"


@pytest.mark.parametrize("mode", ["legacy", "batch"])
def test_partial_singleton_withdrawal_cannot_union_its_own_old_live_revision(memory_store, monkeypatch, mode):
    memory_store.upsert_intel([intel._normalize_osv(advisory(STRONG, critical=True, older=True), DEP)])
    _, cached, findings = query(
        memory_store, monkeypatch, mode, [advisory(STRONG, critical=True, withdrawn=True)], partial=True
    )
    assert len(cached) == 1 and not findings
    assert set(members(cached[0])) == {STRONG} and cached[0].get("withdrawn")


@pytest.mark.parametrize("mode", ["legacy", "batch"])
def test_complete_snapshot_retires_absent_upstream_members(memory_store, monkeypatch, mode):
    query(memory_store, monkeypatch, mode, [advisory(STRONG, critical=True), advisory(WEAK)])
    refresh_again(memory_store)
    _, cached, findings = query(memory_store, monkeypatch, mode, [advisory(WEAK)])
    assert len(cached) == 1 and len(findings) == 1
    row = cached[0]
    assert set(members(row)) == {WEAK}
    assert row["severity"] is None and findings[0]["severity"] == "medium"
    assert row["references"] == [f"https://example.invalid/{WEAK}"]
    assert f"SYNTHETIC-ALIAS-{STRONG}" not in row["aliases"]


@pytest.mark.parametrize("mode", ["legacy", "batch"])
@pytest.mark.parametrize("reverse", [False, True])
def test_all_withdrawn_group_remains_visible_without_an_active_finding(
    memory_store, monkeypatch, mode, reverse
):
    values = [advisory(STRONG, critical=True, withdrawn=True), advisory(WEAK, withdrawn=True)]
    _, cached, findings = query(
        memory_store, monkeypatch, mode, list(reversed(values)) if reverse else values
    )
    assert len(cached) == 1 and not findings
    assert cached[0].get("withdrawn") and set(members(cached[0])) == {STRONG, WEAK}


@pytest.mark.parametrize("mode", ["legacy", "batch"])
def test_partial_upstream_alias_change_retires_its_prior_display_group_member(
    memory_store, monkeypatch, mode
):
    query(memory_store, monkeypatch, mode, [advisory(STRONG, critical=True, older=True), advisory(WEAK)])
    refresh_again(memory_store)
    changed = advisory(STRONG, critical=True)
    changed["aliases"] = ["CVE-2099-4243", f"SYNTHETIC-ALIAS-{STRONG}"]
    _, cached, findings = query(memory_store, monkeypatch, mode, [changed], partial=True)
    assert len(cached) == len(findings) == 2
    groups = {row["id"]: row for row in cached}
    assert set(members(groups[CVE])) == {WEAK}
    assert set(members(groups["CVE-2099-4243"])) == {STRONG}
    assert groups[CVE]["severity"] is None
    assert groups["CVE-2099-4243"]["severity"] == "critical"


@pytest.mark.parametrize("defect", ["revision-conflict", "member-budget", "byte-budget"])
def test_partial_merge_failure_preserves_cache_and_releases_transaction(memory_store, monkeypatch, defect):
    from mobile_audit import osv_records

    previous = intel._normalize_osv(advisory(STRONG, critical=True, older=True), DEP)
    memory_store.upsert_intel([previous])
    before = memory_store.intelligence(limit=100)
    incoming = [intel._normalize_osv(advisory(WEAK), DEP)]
    if defect == "revision-conflict":
        incoming = [intel._normalize_osv(advisory(STRONG, older=True), DEP)]
    elif defect == "member-budget":
        monkeypatch.setattr(osv_records, "MAX_MEMBERS", 1)
    elif defect == "byte-budget":
        monkeypatch.setattr(osv_records, "MAX_MEMBER_BYTES", 128)
    with pytest.raises(ValueError):
        osv_records.persist_osv_query(memory_store, SOURCE, incoming, complete=False)
    assert not memory_store.db.in_transaction
    assert memory_store.intelligence(limit=100) == before


@pytest.mark.parametrize("mode", ["legacy", "batch"])
@pytest.mark.parametrize("change", ["alias-order", "reference-order", "legacy-alias-metadata"])
def test_partial_same_revision_reordering_and_legacy_enrichment_keep_new_members(
    memory_store, monkeypatch, mode, change
):
    previous = advisory(STRONG, critical=True)
    previous["references"].append({"url": "https://example.invalid/second-reference"})
    old = intel._normalize_osv(previous, DEP)
    if change == "legacy-alias-metadata":
        old.pop("aliases")
    memory_store.upsert_intel([old])
    current = copy.deepcopy(previous)
    if change == "alias-order":
        current["aliases"].reverse()
    elif change == "reference-order":
        current["references"].reverse()
    found, cached, findings = query(memory_store, monkeypatch, mode, [current, advisory(WEAK)], partial=True)
    assert len(found) == 2 and len(cached) == len(findings) == 1
    assert set(members(cached[0])) == {STRONG, WEAK}
    assert findings[0]["severity"] == "critical"
    assert members(cached[0])[STRONG]["aliases"]


@pytest.mark.parametrize("mode", ["legacy", "batch"])
def test_partial_opaque_legacy_collision_never_invents_an_upstream_identity(memory_store, monkeypatch, mode):
    old = intel._normalize_osv(advisory(STRONG, critical=True, older=True), DEP)
    old.pop("osv_id")
    memory_store.upsert_intel([old])
    _, cached, findings = query(
        memory_store, monkeypatch, mode, [advisory(WEAK, withdrawn=True)], partial=True
    )
    row = cached[0]
    assert row["severity"] == "critical" and findings[0]["severity"] == "critical"
    assert row["osv_ids"] == [WEAK] and len(row["osv_legacy_records"]) == 1
    assert "osv_id" not in row["osv_legacy_records"][0]
    assert row["osv_records"][0]["osv_id"] == WEAK
    refresh_again(memory_store)
    _, repeated, _ = query(memory_store, monkeypatch, mode, [advisory(WEAK, withdrawn=True)], partial=True)
    assert len(repeated[0]["osv_legacy_records"]) == 1
    assert not repeated[0]["osv_legacy_records"][0].get("osv_legacy_records")
    refresh_again(memory_store)
    _, complete, current = query(memory_store, monkeypatch, mode, [advisory(WEAK, withdrawn=True)])
    assert not current and complete[0].get("withdrawn")
    assert "osv_legacy_records" not in complete[0]


@pytest.mark.parametrize("mode", ["legacy", "batch"])
def test_opaque_unknown_coordinates_cannot_hide_a_new_identified_finding(memory_store, monkeypatch, mode):
    memory_store.upsert_intel(
        [{"id": CVE, "source": SOURCE, "title": "Opaque legacy", "severity": "critical"}]
    )
    _, cached, findings = query(memory_store, monkeypatch, mode, [advisory(WEAK)], partial=True)
    assert findings and findings[0]["severity"] == "medium"
    assert cached[0]["osv_id"] == WEAK
    assert "query_match" not in cached[0]["osv_legacy_records"][0]
