"""Validated OSV pages survive later failures without becoming complete coverage."""

import hashlib
import json

import httpx
import pytest

from mobile_audit.audit import correlate
from mobile_audit.intel import query_dependencies


def dependency():
    return {
        "ecosystem": "Maven",
        "name": "synthetic.public:pagination",
        "version": "1.0",
        "confidence": "exact",
        "path": "app/gradle.lockfile",
    }


def advisory(identifier="GHSA-synthetic-first"):
    return {
        "id": identifier,
        "modified": "2026-10-22T00:00:00Z",
        "summary": "Synthetic pagination advisory",
        "affected": [{"package": {"ecosystem": "Maven", "name": dependency()["name"]}, "versions": ["1.0"]}],
    }


@pytest.mark.parametrize("mode", ["auto", "legacy"])
@pytest.mark.parametrize("failure", ["http", "json", "record", "token", "loop"])
def test_later_page_failure_preserves_validated_findings_and_prior_cache(store, mode, failure):
    dep = dependency()
    source = f"osv:Maven:{dep['name']}:1.0"
    store.upsert_intel([{"id": "SYNTHETIC-CACHED", "source": source, "title": "Prior cached evidence"}])
    first_hash = ""
    calls = []

    def respond(request):
        nonlocal first_hash
        payload = json.loads(request.content)
        calls.append(payload)
        if "page_token" not in payload:
            response = httpx.Response(200, json={"vulns": [advisory()], "next_page_token": "page2"})
            first_hash = hashlib.sha256(response.content).hexdigest()
            return response
        assert payload["page_token"] == "page2"
        if failure == "http":
            return httpx.Response(503)
        if failure == "json":
            return httpx.Response(200, content=b"{malformed")
        if failure == "record":
            return httpx.Response(200, json={"vulns": [advisory("GHSA-untrusted-prefix"), {"id": 42}]})
        if failure == "token":
            return httpx.Response(
                200, json={"vulns": [advisory("GHSA-untrusted-prefix")], "next_page_token": []}
            )
        return httpx.Response(
            200, json={"vulns": [advisory("GHSA-untrusted-prefix")], "next_page_token": "page2"}
        )

    with httpx.Client(transport=httpx.MockTransport(respond), trust_env=False) as client:
        found, errors = query_dependencies(store, [dep], client, query_mode=mode)
    assert len(calls) == 2 and errors
    assert [record["id"] for record in found] == ["GHSA-synthetic-first"]
    assert found[0]["provenance"]["content_hash"] == first_hash
    assert dep["osv_query"] == {"state": "partial", "checked": False, "transmitted": True}
    assert next(row for row in store.feeds() if row["source"] == source)["status"] == "partial"
    assert store.intel_by_id("SYNTHETIC-CACHED")
    assert not store.intel_by_id("GHSA-untrusted-prefix")
    cached = store.correlation_intelligence([dep])
    findings, _ = correlate({"dependencies": [dep], "platforms": []}, cached)
    assert any(finding["rule_id"] == "GHSA-synthetic-first" for finding in findings)

    # A later complete package snapshot remains authoritative, including no matches.
    with httpx.Client(transport=httpx.MockTransport(lambda request: httpx.Response(200, json={}))) as client:
        found, errors = query_dependencies(store, [dep], client, query_mode=mode)
    assert not found and not errors
    assert dep["osv_query"] == {"state": "complete", "checked": True, "transmitted": True}
    assert not store.correlation_intelligence([dep])


@pytest.mark.parametrize("mode", ["auto", "legacy"])
def test_malformed_first_page_never_persists_its_valid_prefix(store, mode):
    dep = dependency()
    response = {"vulns": [advisory(), {"id": 42}], "next_page_token": "page2"}
    with httpx.Client(
        transport=httpx.MockTransport(lambda request: httpx.Response(200, json=response))
    ) as client:
        found, errors = query_dependencies(store, [dep], client, query_mode=mode)
    assert not found and errors
    assert not store.correlation_intelligence([dep])
    assert dep["osv_query"] == {"state": "error", "checked": False, "transmitted": True}
