"""Protocol-independent limits use synthetic coordinates and mock HTTP only."""

import json
from datetime import datetime, timezone

import httpx
import pytest

from mobile_audit.dependency_policy import DependencyTransmissionPolicy
from mobile_audit.intel import query_dependencies


def dependencies(count=3) -> list[dict]:
    return [
        {"ecosystem": "Maven", "name": f"synthetic.public:lib{i}", "version": "1.0", "confidence": "exact"}
        for i in range(count)
    ]


@pytest.mark.parametrize("mode", ["auto", "legacy", "batch"])
@pytest.mark.parametrize("budget", [{"max_packages": 1}, {"max_requests": 1}])
def test_budget_caps_transmission_and_never_marks_untouched_packages_checked(store, mode, budget):
    deps, calls = dependencies(), []

    def handler(request):
        calls.append(request)
        value = {"results": [{}]} if request.url.path.endswith("querybatch") else {}
        return httpx.Response(200, json=value)

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        _, errors = query_dependencies(store, deps, client, query_mode=mode, batch_size=1, **budget)
    assert len(calls) == 1 and errors
    assert deps[0]["osv_query"]["checked"] is True
    assert all(dep["osv_query"]["checked"] is False for dep in deps[1:])
    assert all(dep["osv_query"]["transmitted"] is False for dep in deps[1:])


@pytest.mark.parametrize("mode", ["auto", "legacy"])
def test_legacy_pagination_request_cap_retains_cached_matches(store, mode):
    deps, calls = dependencies(), []
    source = "osv:Maven:synthetic.public:lib0:1.0"
    store.upsert_intel([{"id": "SYNTHETIC-OLD", "source": source, "title": "Synthetic cached result"}])

    def handler(request):
        calls.append(json.loads(request.content))
        return httpx.Response(200, json={"next_page_token": f"page-{len(calls)}"})

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        _, errors = query_dependencies(store, deps, client, query_mode=mode, max_requests=2)
    assert len(calls) == 2 and calls[1]["page_token"] == "page-1"
    assert errors and store.intel_by_id("SYNTHETIC-OLD")
    assert deps[0]["osv_query"]["state"] == "partial"
    assert deps[0]["osv_query"]["transmitted"] is True
    assert all(dep["osv_query"]["state"] == "not-checked" for dep in deps[1:])
    assert all(dep["osv_query"]["transmitted"] is False for dep in deps[1:])


@pytest.mark.parametrize("mode", ["auto", "legacy", "batch"])
@pytest.mark.parametrize("budget", [{"max_packages": 0}, {"batch_size": True}, {"max_requests": 10001}])
def test_invalid_budgets_rejected_before_dependency_mutation_or_http(store, mode, budget):
    deps = dependencies()

    def handler(request):
        pytest.fail("Invalid budgets must fail before HTTP")

    with httpx.Client(transport=httpx.MockTransport(handler)) as client, pytest.raises(ValueError):
        query_dependencies(
            store,
            deps,
            client,
            query_mode=mode,
            exclusion_policy=DependencyTransmissionPolicy(exclude_ecosystems=("Maven",)),
            **budget,
        )
    assert all("osv_query" not in dep for dep in deps)
    assert store.feeds() == []


def test_legacy_transmission_state_does_not_depend_on_clock_resolution(store, monkeypatch):
    timestamp = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
    monkeypatch.setattr("mobile_audit.store.now", lambda: timestamp)
    deps = dependencies(1)
    store.feed("osv:Maven:synthetic.public:lib0:1.0", "error")
    with httpx.Client(transport=httpx.MockTransport(lambda request: httpx.Response(200, json={}))) as client:
        _, errors = query_dependencies(store, deps, client, query_mode="legacy")
    assert not errors
    assert deps[0]["osv_query"] == {"state": "complete", "checked": True, "transmitted": True}
