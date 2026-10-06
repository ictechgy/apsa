from __future__ import annotations

import copy
import json
import sqlite3
from datetime import datetime, timedelta, timezone

import httpx
import pytest

import mobile_audit.intel as intel
import mobile_audit.store as storage
from mobile_audit.core import canonical_json, digest
from mobile_audit.intel import (
    Fetcher,
    normalize_cve,
    parse_android,
    parse_apple,
    query_dependencies,
    source_health,
    sync,
)
from mobile_audit.store import Store

IDENTIFIER = "CVE-2026-12345"
DEPENDENCY = {
    "name": "a:b",
    "ecosystem": "Maven",
    "version": "1.0.0",
    "confidence": "exact",
    "path": "private/lock",
}


def _cve(identifier=IDENTIFIER):
    return {
        "cveMetadata": {"cveId": identifier, "state": "PUBLISHED"},
        "containers": {
            "cna": {
                "title": "Android issue",
                "descriptions": [{"lang": "en", "value": "Android vulnerability"}],
                "affected": [
                    {
                        "vendor": "Google",
                        "product": "Android",
                        "versions": [{"version": "16", "status": "affected"}],
                    }
                ],
                "references": [{"url": "https://example.org/advisory"}],
            }
        },
    }


def _delta(*identifiers):
    stamp = datetime.now(timezone.utc).isoformat()
    return [
        {
            "fetchTime": stamp,
            "new": [{"cveId": identifier, "dateUpdated": stamp} for identifier in identifiers],
            "updated": [],
        }
    ]


def _client(handler):
    return httpx.Client(transport=httpx.MockTransport(handler))


def _cache_dependency(store):
    record = {
        "id": IDENTIFIER,
        "source": "osv:Maven:a:b:1.0.0",
        "title": "old",
        "query_match": {key: DEPENDENCY[key] for key in ("name", "ecosystem", "version")},
    }
    store.upsert_intel([record])
    store.feed(record["source"], "ok", 1, content_hash="previous")
    return store.intel_by_id(IDENTIFIER)[0]


def test_multiple_apple_components_and_release_branches_survive_cache_updates(store):
    html = b"<article><h3>WebKit</h3><p>CVE-2026-12345: one</p><h3>Kernel</h3><p>CVE-2026-12345: two</p></article>"
    first = parse_apple(html, "https://support.apple.com/100001", "iOS 18.7")
    second = parse_apple(html, "https://support.apple.com/100002", "iOS 26.1")
    assert len(first) == 2
    store.upsert_intel(first + second)
    rows = store.intel_by_id(IDENTIFIER)
    assert len(rows) == 4
    assert {(row["component"], row["fixed_release"]) for row in rows} == {
        ("WebKit", "iOS 18.7"),
        ("WebKit", "iOS 26.1"),
        ("Kernel", "iOS 18.7"),
        ("Kernel", "iOS 26.1"),
    }
    assert all(row["source"] == "apple" for row in rows)
    assert len({row["branch_id"] for row in rows}) == 4
    assert store.upsert_intel(first + second) == []
    old = next(row for row in rows if row["component"] == "WebKit" and row["fixed_release"] == "iOS 18.7")
    store.upsert_intel([{**first[0], "description": "updated attribution"}])
    assert len(store.intel_by_id(IDENTIFIER)) == 4
    assert len(store.intel_history(IDENTIFIER)) == 5
    snapshot = store.home / "intel-records" / f"{old['snapshot_hash']}.json"
    assert json.loads(snapshot.read_text())["description"] != "updated attribution"


def test_android_same_cve_patch_component_and_version_rows_not_deduplicated(store):
    html = b"<h2>2026-09-01</h2><h3>System</h3><table><tr><th>CVE</th><th>Severity</th><th>Updated AOSP versions</th></tr><tr><td>CVE-2026-12345</td><td>High</td><td>14</td></tr><tr><td>CVE-2026-12345</td><td>High</td><td>15, 16</td></tr></table><h2>2026-09-05</h2><h3>Kernel</h3><table><tr><th>CVE</th><th>Severity</th><th>Updated AOSP versions</th></tr><tr><td>CVE-2026-12345</td><td>Critical</td><td>16</td></tr></table>"
    records = parse_android(html, "https://source.android.com/security/bulletin/2026-09-01")
    assert len(records) == 3
    store.upsert_intel(records)
    rows = store.intel_by_id(IDENTIFIER)
    assert len(rows) == 3
    assert {(row["fixed_patch_level"], row["component"], row["updated_aosp_versions"]) for row in rows} == {
        ("2026-09-01", "System", "14"),
        ("2026-09-01", "System", "15, 16"),
        ("2026-09-05", "Kernel", "16"),
    }


def test_vendor_sync_preserves_each_branch_and_document_provenance(store):
    index = b'<a href="https://support.apple.com/100001">iOS 18.7</a><a href="https://support.apple.com/100002">iOS 26.1</a>'
    advisory = b"<article><h3>WebKit</h3><p>CVE-2026-12345</p></article>"

    def handler(request):
        return httpx.Response(200, content=index if request.url.path.endswith("100100") else advisory)

    with _client(handler) as client:
        first = sync(store, ["apple"], limit=2, client=client)
        second = sync(store, ["apple"], limit=2, client=client)
    assert first["changed_ids"] == [IDENTIFIER]
    assert second["changed_ids"] == []
    rows = store.intel_by_id(IDENTIFIER)
    assert len(rows) == 2
    assert {row["provenance"]["document_url"] for row in rows} == {
        "https://support.apple.com/100001",
        "https://support.apple.com/100002",
    }
    assert all(row["provenance"]["content_hash"] == digest(advisory) for row in rows)
    for row in rows:
        body = json.loads((store.home / "intel-records" / f"{row['snapshot_hash']}.json").read_text())
        assert digest(canonical_json(body).encode()) == row["snapshot_hash"]


def test_old_vendor_and_queue_migration_preserves_report_bytes(tmp_path):
    home = tmp_path / "state"
    home.mkdir()
    db = sqlite3.connect(home / "audit.sqlite3")
    db.executescript(
        "CREATE TABLE reports(id TEXT PRIMARY KEY,created TEXT,target TEXT,body TEXT); CREATE TABLE intel(id TEXT,source TEXT,modified TEXT,body TEXT,PRIMARY KEY(id,source)); CREATE TABLE cve_queue(id TEXT,revision TEXT,priority INTEGER,state TEXT,PRIMARY KEY(id,revision)); PRAGMA user_version=1;"
    )
    report_body = json.dumps({"id": "old", "created": "old", "target": "/old"})
    vendor = {
        "id": IDENTIFIER,
        "source": "apple",
        "title": "old",
        "fixed_release": "iOS 18.7",
        "component": "WebKit",
    }
    db.execute("INSERT INTO reports VALUES(?,?,?,?)", ("old", "old", "/old", report_body))
    db.execute("INSERT INTO intel VALUES(?,?,?,?)", (IDENTIFIER, "apple", "", json.dumps(vendor)))
    db.execute("INSERT INTO cve_queue VALUES(?,?,?,'pending')", (IDENTIFIER, "old", 1))
    db.commit()
    db.close()
    migrated = Store(home)
    try:
        assert migrated.db.execute("PRAGMA user_version").fetchone()[0] == 2
        assert migrated.db.execute("SELECT body FROM reports").fetchone()[0] == report_body
        assert migrated.report("old")["target"] == "/old"
        row = migrated.intel_by_id(IDENTIFIER)[0]
        assert row["source"] == "apple" and row["fixed_release"] == "iOS 18.7"
        assert (home / "intel-records" / f"{row['snapshot_hash']}.json").exists()
        assert migrated.intel_history(IDENTIFIER)[0]["snapshot_hash"] == row["snapshot_hash"]
        pending = migrated.pending_cves(10)
        assert pending[0]["attempts"] == 0 and pending[0]["queued_at"]
    finally:
        migrated.close()


def test_missing_required_feeds_are_visible_and_failure_preserves_success_metadata(store):
    health = source_health(store)
    assert {feed["source"] for feed in health} == set(intel.DEFAULT_SOURCES)
    assert all(feed["required"] and feed["stale"] and feed["status"] == "never-synced" for feed in health)
    store.feed("kev", "ok", 10, content_hash="previous-success")
    succeeded = next(feed for feed in source_health(store) if feed["source"] == "kev")["succeeded"]
    store.feed("kev", "error", error="network failed")
    current = next(feed for feed in source_health(store) if feed["source"] == "kev")
    assert current["succeeded"] == succeeded
    assert current["status"] == "error" and current["count"] == 10
    assert current["content_hash"] == "previous-success"
    assert len([feed for feed in source_health(store) if feed["status"] == "never-synced"]) == 4


def test_cve_404_is_retryable_and_later_disclosure_completes(store, monkeypatch):
    delta = _delta(IDENTIFIER)
    requests = []
    disclosed = False

    def handler(request):
        if request.url.path.endswith("deltaLog.json"):
            return httpx.Response(200, json=delta)
        requests.append(str(request.url))
        return httpx.Response(200, json=_cve()) if disclosed else httpx.Response(404)

    with _client(handler) as client:
        first = sync(store, ["cve"], limit=1, client=client)
        assert first["partial"] and store.pending_count() == 1
        waiting = store.db.execute("SELECT * FROM cve_queue").fetchone()
        assert waiting["state"] == "pending" and waiting["attempts"] == 1
        assert datetime.fromisoformat(waiting["next_attempt"]) > datetime.now(timezone.utc)
        second = sync(store, ["cve"], limit=1, client=client)
        assert second["partial"] and len(requests) == 1
        assert next(feed for feed in source_health(store) if feed["source"] == "cve")["pending"] == 1
        future = (datetime.fromisoformat(waiting["next_attempt"]) + timedelta(seconds=1)).isoformat()
        monkeypatch.setattr(storage, "now", lambda: future)
        disclosed = True
        final = sync(store, ["cve"], limit=1, client=client)
    assert not final["partial"] and store.pending_count() == 0
    assert store.intel_by_id(IDENTIFIER)[0]["title"] == "Android issue"
    assert store.db.execute("SELECT attempts FROM cve_queue").fetchone()[0] == 2


def test_one_transient_failure_does_not_discard_other_successful_jobs(store):
    second_id = "CVE-2026-12346"
    delta = _delta(IDENTIFIER, second_id)
    store.upsert_intel([{"id": IDENTIFIER, "source": "cve", "title": "cached"}])

    def handler(request):
        if request.url.path.endswith("deltaLog.json"):
            return httpx.Response(200, json=delta)
        if request.url.path.endswith(IDENTIFIER + ".json"):
            return httpx.Response(503, headers={"Retry-After": "600"})
        return httpx.Response(200, json=_cve(second_id))

    with _client(handler) as client:
        result = sync(store, ["cve"], limit=1, client=client)
    assert result["partial"] and result["sources"][0]["retried"] == 1
    assert store.pending_count() == 1
    assert store.intel_by_id(IDENTIFIER)[0]["title"] == "cached"
    assert store.intel_by_id(second_id)[0]["title"] == "Android issue"
    row = store.db.execute("SELECT * FROM cve_queue WHERE id=?", (IDENTIFIER,)).fetchone()
    assert (
        datetime.fromisoformat(row["next_attempt"]) - datetime.fromisoformat(row["last_attempt"])
    ).total_seconds() >= 600


def test_queue_fifo_and_lane_quota_prevent_new_work_starving_old_work(store):
    old_ids = [f"CVE-2026-{80000 + index}" for index in range(8)]
    store.enqueue_cves([(identifier, "2026-01-01", 1) for identifier in old_ids])
    completed = set()
    for cycle in range(4):
        store.enqueue_cves(
            [(f"CVE-2026-{90000 + cycle * 10 + index}", "2026-10-04", 0) for index in range(10)]
        )
        jobs = store.pending_cves(4)
        assert len([job for job in jobs if job["priority"] == 1]) == 2
        for job in jobs:
            completed.add(job["id"])
            store.finish_cve(job["id"], job["revision"])
    assert set(old_ids) <= completed


def test_queue_backoff_grows_and_pauses_only_due_work(store):
    store.enqueue_cves([(IDENTIFIER, "revision", 1)])
    at = "2026-10-04T00:00:00+00:00"
    store.retry_cve(IDENTIFIER, "revision", "error", at=at)
    assert store.pending_cves(1, at="2026-10-04T00:00:59Z") == []
    assert store.pending_cves(1, at="2026-10-04T00:01:00Z")[0]["attempts"] == 1
    store.retry_cve(IDENTIFIER, "revision", "again", at="2026-10-04T00:01:00Z")
    row = store.db.execute("SELECT * FROM cve_queue").fetchone()
    assert row["attempts"] == 2 and row["next_attempt"] == "2026-10-04T00:03:00+00:00"


@pytest.mark.parametrize(
    "field,value",
    [
        ("descriptions", [{"lang": 7, "value": "text"}]),
        ("descriptions", [{"lang": "en", "value": {}}]),
        ("references", [{"url": []}]),
        ("affected", [{"product": None}]),
        ("affected", [{"versions": "16"}]),
        ("affected", [{"versions": [None]}]),
        ("affected", [{"versions": [{"version": 16}]}]),
        ("affected", [{"versions": [{"changes": [{"at": []}]}]}]),
    ],
)
def test_cve_nested_schema_failures_are_controlled(field, value):
    document = _cve()
    document["containers"]["cna"][field] = value
    with pytest.raises(ValueError, match="Malformed"):
        normalize_cve(document)


@pytest.mark.parametrize(
    "document",
    [
        ["not-an-object"],
        [{"fetchTime": "bad", "new": []}],
        [{"fetchTime": "2026-10-04T00:00:00Z", "new": {}}],
        [{"fetchTime": "2026-10-04T00:00:00Z", "new": [None]}],
        [{"fetchTime": "2026-10-04T00:00:00Z", "new": [{"cveId": IDENTIFIER, "dateUpdated": []}]}],
    ],
)
def test_malformed_delta_never_advances_cursor_or_discards_cache(store, document):
    store.upsert_intel([{"id": IDENTIFIER, "source": "cve", "title": "cached"}])
    with _client(lambda request: httpx.Response(200, json=document)) as client:
        result = sync(store, ["cve"], limit=1, client=client)
    assert result["partial"]
    assert store.cursor("cve-delta") is None and store.pending_count() == 0
    assert store.intel_by_id(IDENTIFIER)[0]["title"] == "cached"


@pytest.mark.parametrize(
    "document",
    [
        [],
        {},
        {"vulnerabilities": [None]},
        {"vulnerabilities": [{"cveID": IDENTIFIER, "vulnerabilityName": "test", "vendorProject": []}]},
    ],
)
def test_malformed_kev_preserves_cache(store, document):
    store.upsert_intel([{"id": IDENTIFIER, "source": "kev", "title": "cached"}])
    with _client(lambda request: httpx.Response(200, json=document)) as client:
        result = sync(store, ["kev"], client=client)
    assert result["partial"] and store.intel_by_id(IDENTIFIER)[0]["title"] == "cached"


@pytest.mark.parametrize(
    "document",
    [
        [],
        {"vulns": "bad"},
        {"vulns": [None]},
        {"vulns": [{"id": "OSV-test", "aliases": [7]}]},
        {"vulns": [{"id": "OSV-test", "affected": {}}]},
        {"vulns": [{"id": "OSV-test", "references": [None]}]},
        {"vulns": [{"id": "OSV-test", "affected": [{"ranges": [{"events": [None]}]}]}]},
    ],
)
def test_malformed_osv_never_retires_prior_matches(store, document):
    old = _cache_dependency(store)
    with _client(lambda request: httpx.Response(200, json=document)) as client:
        found, errors = query_dependencies(store, [DEPENDENCY], client)
    assert found == [] and errors
    assert store.intel_by_id(IDENTIFIER)[0]["snapshot_hash"] == old["snapshot_hash"]
    assert (
        next(feed for feed in store.feeds() if feed["source"].startswith("osv:"))["content_hash"]
        == "previous"
    )


class _Chunks(httpx.SyncByteStream):
    def __init__(self, count=20):
        self.count = count
        self.yielded = 0
        self.closed = False

    def __iter__(self):
        for _ in range(self.count):
            self.yielded += 1
            yield b"x" * 65536

    def close(self):
        self.closed = True


def test_osv_stream_limit_stops_before_reading_or_parsing_full_body(store, monkeypatch):
    old = _cache_dependency(store)
    monkeypatch.setattr(intel, "MAX_REMOTE_BYTES", 128 * 1024)
    stream = _Chunks()
    with _client(lambda request: httpx.Response(200, stream=stream)) as client:
        found, errors = query_dependencies(store, [DEPENDENCY], client)
    assert found == [] and errors
    assert stream.yielded <= 3 and stream.closed
    assert store.intel_by_id(IDENTIFIER)[0]["snapshot_hash"] == old["snapshot_hash"]


def test_fetcher_declared_size_rejected_without_consuming_stream():
    stream = _Chunks()
    with _client(
        lambda request: httpx.Response(200, stream=stream, headers={"Content-Length": str(1024 * 1024)})
    ) as client:
        with pytest.raises(ValueError, match="size limit"):
            Fetcher(client).get("https://example.org/data", max_bytes=1024)
    assert stream.yielded == 0 and stream.closed


def test_remote_json_nesting_and_nonfinite_numbers_rejected():
    deep = {"vulns": []}
    for _ in range(40):
        deep = {"nested": deep}
    for raw in (json.dumps(deep).encode(), b'{"value": NaN}'):
        with _client(lambda request, document=raw: httpx.Response(200, content=document)) as client:
            with pytest.raises(ValueError):
                Fetcher(client).json("https://example.org/data")


def test_complete_osv_pagination_retires_old_match_and_keeps_all_new_pages(store):
    _cache_dependency(store)
    requests = []

    def handler(request):
        body = json.loads(request.content)
        requests.append(body)
        assert "path" not in body
        if "page_token" not in body:
            return httpx.Response(200, json={"vulns": [{"id": "OSV-one"}], "next_page_token": "next"})
        assert body["page_token"] == "next"
        return httpx.Response(200, json={"vulns": [{"id": "OSV-two"}]})

    with _client(handler) as client:
        found, errors = query_dependencies(store, [DEPENDENCY], client)
    assert errors == [] and {record["id"] for record in found} == {"OSV-one", "OSV-two"}
    assert len(requests) == 2 and store.intel_by_id(IDENTIFIER) == []
    assert len(store.intelligence(limit=100)) == 2
    assert "private/lock" not in json.dumps(found)


def test_osv_later_page_failure_preserves_prior_full_cache(store):
    old = _cache_dependency(store)
    responses = [
        httpx.Response(200, json={"vulns": [{"id": "OSV-one"}], "next_page_token": "next"}),
        httpx.Response(503),
    ]
    with _client(lambda request: responses.pop(0)) as client:
        found, errors = query_dependencies(store, [DEPENDENCY], client)
    assert found == [] and errors
    assert store.intel_by_id(IDENTIFIER)[0]["snapshot_hash"] == old["snapshot_hash"]
    assert store.intel_by_id("OSV-one") == []


@pytest.mark.parametrize("budget", ["MAX_OSV_PAGES", "MAX_OSV_RECORDS"])
def test_bounded_osv_subsets_keep_prior_matches(store, monkeypatch, budget):
    _cache_dependency(store)
    monkeypatch.setattr(intel, budget, 1)
    response = {"vulns": [{"id": "OSV-one"}, {"id": "OSV-two"}], "next_page_token": "more"}
    with _client(lambda request: httpx.Response(200, json=response)) as client:
        found, errors = query_dependencies(store, [DEPENDENCY], client)
    assert found and errors
    assert store.intel_by_id(IDENTIFIER)
    assert store.intel_by_id("OSV-one")
    assert next(feed for feed in store.feeds() if feed["source"].startswith("osv:"))["status"] == "partial"


def test_repeated_osv_page_token_is_error_and_keeps_cache(store):
    old = _cache_dependency(store)
    with _client(lambda request: httpx.Response(200, json={"next_page_token": "same"})) as client:
        found, errors = query_dependencies(store, [DEPENDENCY], client)
    assert found == [] and errors
    assert store.intel_by_id(IDENTIFIER)[0]["snapshot_hash"] == old["snapshot_hash"]


def test_malformed_dependency_input_is_controlled_and_valid_queries_continue(store):
    with _client(lambda request: httpx.Response(200, json={})) as client:
        # Deliberately cross the typed boundary with a corrupt imported inventory.
        found, errors = query_dependencies(store, [None, {"name": []}, copy.deepcopy(DEPENDENCY)], client)  # pyright: ignore[reportArgumentType]
    assert found == [] and len(errors) == 2


def test_android_link_discovery_never_fetches_non_vendor_hosts(store):
    requests = []

    def handler(request):
        requests.append(str(request.url))
        return httpx.Response(
            200, content=b'<a href="https://other.example/bulletin/2026-10-01">bulletin</a>'
        )

    with _client(handler) as client:
        result = sync(store, ["android"], limit=1, client=client)
    assert result["partial"] and requests == [intel.SOURCES["android"]]


def test_complete_vendor_document_correction_retires_only_that_documents_old_branch(store):
    index = b'<a href="https://support.apple.com/100001">iOS 18.7</a><a href="https://support.apple.com/100002">iOS 26.1</a>'
    corrected = False

    def handler(request):
        if request.url.path.endswith("100100"):
            return httpx.Response(200, content=index)
        component = "Kernel" if corrected and request.url.path.endswith("100001") else "WebKit"
        return httpx.Response(
            200, content=f"<article><h3>{component}</h3><p>{IDENTIFIER}</p></article>".encode()
        )

    with _client(handler) as client:
        sync(store, ["apple"], limit=2, client=client)
        old = next(row for row in store.intel_by_id(IDENTIFIER) if row["fixed_release"] == "iOS 18.7")
        corrected = True
        sync(store, ["apple"], limit=2, client=client)
    rows = store.intel_by_id(IDENTIFIER)
    assert {(row["fixed_release"], row["component"]) for row in rows} == {
        ("iOS 18.7", "Kernel"),
        ("iOS 26.1", "WebKit"),
    }
    assert len(store.intel_history(IDENTIFIER)) == 3
    assert (store.home / "intel-records" / f"{old['snapshot_hash']}.json").exists()


def test_catalog_retirement_keeps_other_sources_and_immutable_history(store):
    catalog = {
        "vulnerabilities": [
            {"cveID": IDENTIFIER, "vulnerabilityName": "issue", "vendorProject": "Apple", "product": "iOS"}
        ]
    }
    store.upsert_intel([{"id": IDENTIFIER, "source": "apple", "title": "vendor"}])
    with _client(lambda request: httpx.Response(200, json=catalog)) as client:
        sync(store, ["kev"], client=client)
        old = next(row for row in store.intel_by_id(IDENTIFIER) if row["source"] == "kev")
        catalog["vulnerabilities"] = []
        result = sync(store, ["kev"], client=client)
    assert result["changed_ids"] == [IDENTIFIER]
    assert {row["source"] for row in store.intel_by_id(IDENTIFIER)} == {"apple"}
    assert (store.home / "intel-records" / f"{old['snapshot_hash']}.json").exists()
    assert any(row["source"] == "kev" for row in store.intel_history(IDENTIFIER))


def test_unexpected_200_osv_error_object_never_retires_cache(store):
    old = _cache_dependency(store)
    with _client(lambda request: httpx.Response(200, json={"error": "unexpected upstream error"})) as client:
        found, errors = query_dependencies(store, [DEPENDENCY], client)
    assert found == [] and errors
    assert store.intel_by_id(IDENTIFIER)[0]["snapshot_hash"] == old["snapshot_hash"]


def test_unexpected_apple_page_is_failure_and_explicit_no_cve_statement_is_valid():
    with pytest.raises(ValueError, match="format changed"):
        parse_apple(b"<html><p>upstream unavailable</p></html>", "https://support.apple.com/1", "iOS 26.1")
    assert (
        parse_apple(
            b"<article><p>This update has no published CVE entries.</p></article>",
            "https://support.apple.com/1",
            "iOS 26.1",
        )
        == []
    )


def test_delta_catalog_uses_per_entry_json_budgets_without_dropping_updates(store, monkeypatch):
    monkeypatch.setattr(intel, "MAX_JSON_NODES", 30)
    identifiers = [f"CVE-2026-{71000 + index}" for index in range(8)]
    delta = [_delta(identifier)[0] for identifier in identifiers]

    def handler(request):
        if request.url.path.endswith("deltaLog.json"):
            return httpx.Response(200, json=delta)
        identifier = request.url.path.rsplit("/", 1)[-1].removesuffix(".json")
        return httpx.Response(
            200,
            json={"cveMetadata": {"cveId": identifier}, "containers": {"cna": {"title": "Android issue"}}},
        )

    with _client(handler) as client:
        result = sync(store, ["cve"], limit=1, client=client)
    assert not result["partial"] and len(store.intelligence(limit=100)) == 8
    assert store.pending_count() == 0


@pytest.mark.parametrize("suffix", [b",]", b"] trailing", b""])
def test_malformed_delta_envelope_after_valid_entry_never_commits_cursor(store, suffix):
    entry = json.dumps(_delta(IDENTIFIER)[0]).encode()
    raw = b"[" + entry + suffix
    with _client(lambda request: httpx.Response(200, content=raw)) as client:
        result = sync(store, ["cve"], limit=1, client=client)
    assert result["partial"] and store.cursor("cve-delta") is None
    assert store.pending_count() == 0
