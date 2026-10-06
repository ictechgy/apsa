import json
from datetime import datetime, timezone

import httpx
import pytest

from mobile_audit.intel import (
    cve_url,
    fetch_record,
    normalize_cve,
    parse_android,
    parse_apple,
    parse_owasp,
    query_dependencies,
    sync,
)


def test_vendor_parsers_preserve_component_and_patch_semantics():
    apple = b"<article><h2>iOS 18.6</h2><h3>CoreGraphics</h3><p>Impact: a file may execute code. This issue may have been exploited.</p><p>CVE-2025-12345: researcher</p></article>"
    record = parse_apple(apple, "https://support.apple.com/1", "iOS 18.6")[0]
    assert record["component"] == "CoreGraphics"
    assert record["exploitation_reported"] is True
    assert record["affected"] == []
    android = b"<h2>2026-09-01 security patch level</h2><h3>System</h3><table><tr><th>CVE</th><th>Severity</th><th>Updated AOSP versions</th></tr><tr><td>CVE-2026-12345</td><td>Critical</td><td>14, 15, 16</td></tr></table>"
    record = parse_android(android, "https://source.android.com/1")[0]
    assert record["severity"] == "critical"
    assert record["fixed_patch_level"] == "2026-09-01"
    assert record["updated_aosp_versions"] == "14, 15, 16"


def test_owasp_preserves_deprecated_tests():
    raw = b'<table><tr><td>MASTG-TEST-0028</td><td><a href="/test">Deep links</a></td><td>deprecated</td></tr></table>'
    assert parse_owasp(raw, "https://mas.owasp.org/MASTG/tests/")[0]["status"] == "deprecated"


def test_cve_rejected_and_url_namespace():
    value = {"cveMetadata": {"cveId": "CVE-2026-86950", "state": "REJECTED"}, "containers": {"cna": {}}}
    assert normalize_cve(value)["state"] == "REJECTED"
    assert cve_url("CVE-2026-86950").endswith("/2026/86xxx/CVE-2026-86950.json")


def test_malformed_cve_response_is_controlled_and_preserves_cache(store):
    identifier = "CVE-2026-12345"
    store.upsert_intel([{"id": identifier, "source": "cve", "title": "cached"}])
    client = httpx.Client(transport=httpx.MockTransport(lambda request: httpx.Response(200, json=[])))
    with pytest.raises(ValueError, match="JSON object"):
        fetch_record(store, identifier, client)
    assert store.intel_by_id(identifier)[0]["title"] == "cached"
    with pytest.raises(ValueError, match="metadata"):
        normalize_cve({"cveMetadata": []})
    client.close()


def test_failed_feed_keeps_cache_and_reports_failure(store):
    store.upsert_intel([{"id": "CVE-2026-12345", "source": "kev", "title": "old"}])
    store.feed("kev", "ok", 1)
    previous = store.feeds()[0]["succeeded"]
    client = httpx.Client(transport=httpx.MockTransport(lambda request: httpx.Response(503)))
    result = sync(store, ["kev"], client=client)
    assert result["partial"] is True
    assert store.intel_by_id("CVE-2026-12345")
    assert store.feeds()[0]["succeeded"] == previous
    client.close()


def test_osv_empty_success_retires_prior_match_but_failure_keeps_it(store):
    dep = {"name": "a:b", "ecosystem": "Maven", "version": "1.0.0", "confidence": "exact", "path": "lock"}
    answers = [
        {
            "vulns": [
                {"id": "OSV-example", "aliases": ["CVE-2026-12345"], "modified": "2026-09-01", "affected": []}
            ]
        },
        {"vulns": []},
    ]

    def handler(request):
        assert json.loads(request.content)["version"] == "1.0.0"
        return httpx.Response(200, json=answers.pop(0))

    client = httpx.Client(transport=httpx.MockTransport(handler))
    query_dependencies(store, [dep], client)
    assert store.intel_by_id("CVE-2026-12345")
    query_dependencies(store, [dep], client)
    assert store.intel_by_id("CVE-2026-12345") == []
    client.close()


def test_snapshot_file_matches_record_hash(store):
    record = {"id": "CVE-2026-12345", "source": "cve", "title": "original"}
    store.upsert_intel([record])
    first = store.intel_by_id(record["id"])[0]
    store.upsert_intel([dict(record, title="changed")])
    path = store.home / "intel-records" / f"{first['snapshot_hash']}.json"
    assert json.loads(path.read_text())["title"] == "original"


def test_cve_pending_queue_survives_bounded_polls(store):
    stamp = datetime.now(timezone.utc).isoformat()
    ids = [f"CVE-2026-{90000 + n}" for n in range(23)]
    delta = [{"fetchTime": stamp, "new": [{"cveId": i, "dateUpdated": stamp} for i in ids], "updated": []}]

    def handler(request):
        if request.url.path.endswith("deltaLog.json"):
            return httpx.Response(200, json=delta)
        identifier = request.url.path.rsplit("/", 1)[-1].removesuffix(".json")
        return httpx.Response(
            200,
            json={
                "cveMetadata": {"cveId": identifier, "dateUpdated": stamp},
                "containers": {"cna": {"title": "Android issue"}},
            },
        )

    client = httpx.Client(transport=httpx.MockTransport(handler))
    sync(store, ["cve"], limit=1, client=client)
    assert store.pending_count() == 13
    sync(store, ["cve"], limit=1, client=client)
    assert store.pending_count() == 3
    sync(store, ["cve"], limit=1, client=client)
    assert store.pending_count() == 0
    assert len(store.intelligence(limit=100)) == 23
    client.close()
