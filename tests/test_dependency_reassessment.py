"""Dependency reassessments retain transmission decisions and fresh query state."""

import copy
import json

import httpx
import pytest

from mobile_audit import watch
from mobile_audit.audit import refresh_report, summarize
from mobile_audit.core import now, uid
from mobile_audit.intel import query_dependencies


def saved_report(store, target, *, state="error", exclusions=None, mode="auto", errors=None):
    dep = {
        "name": "private-owned",
        "ecosystem": "PyPI",
        "version": "1.0.0",
        "confidence": "exact",
        "path": "owned.lock",
        "osv_query": {"state": state, "checked": state == "complete", "transmitted": True},
    }
    report = {
        "id": uid("audit"),
        "created": now(),
        "target": str(target),
        "inventory": {
            "target": str(target),
            "platforms": [],
            "input_kind": "source",
            "dependencies": [dep],
            "dependency_query": {
                "mode": mode,
                "packages": [
                    {**{key: dep[key] for key in ("name", "ecosystem", "version")}, **dep["osv_query"]}
                ],
                "transmission_exclusions": exclusions or {},
            },
        },
        "findings": [],
        "coverage": [{"rule_id": "DEPENDENCY-CVE", "dependency": copy.deepcopy(dep), "state": "partial"}],
        "environment_advisories": [],
        "intel_snapshot": [],
        "runtime": [],
        "warnings": ["Owned inventory notice", *(errors or [])],
        "online_query": {"requested": bool(errors), "errors": errors or []},
    }
    report["summary"] = summarize(report)
    return store.save_report(report)


def mocked_query(monkeypatch, module, *, status=200):
    requests = []

    def respond(request):
        requests.append(request)
        if request.url.path.endswith("querybatch"):
            size = len(json.loads(request.content)["queries"])
            return httpx.Response(status, json={"results": [{} for _ in range(size)]})
        return httpx.Response(status, json={"vulns": []})

    client = httpx.Client(transport=httpx.MockTransport(respond))

    def query(database, dependencies, **options):
        return query_dependencies(database, dependencies, client=client, **options)

    monkeypatch.setattr(module, "query_dependencies", query)
    return requests, client


@pytest.mark.parametrize("mode", ["legacy", "batch"])
def test_watch_online_records_its_documented_default_query(store, tmp_path, monkeypatch, mode):
    saved_report(store, tmp_path, state="excluded", exclusions={"exclude_names": ["private-*"]}, mode=mode)
    requests, client = mocked_query(monkeypatch, watch)
    try:
        result = watch.reassess_targets(store, online=True)
        # Watch explicitly uses default options rather than inheriting scan exclusions.
        assert len(requests) == 1
        current = store.report(result["reaudited_reports"][0])
        assert current["inventory"]["dependency_query"]["mode"] == "auto"
        assert current["inventory"]["dependency_query"]["transmission_exclusions"] == {}
        assert current["inventory"]["dependencies"][0]["osv_query"]["state"] == "complete"
        assert current["coverage"][0]["state"] == "checked"
    finally:
        client.close()


@pytest.mark.parametrize(
    ("initial", "status", "expected"), [("error", 200, "complete"), ("complete", 503, "error")]
)
def test_watch_online_persists_new_package_states(store, tmp_path, monkeypatch, initial, status, expected):
    prior = saved_report(store, tmp_path, state=initial, errors=["Owned prior OSV failure"])
    requests, client = mocked_query(monkeypatch, watch, status=status)
    try:
        result = watch.reassess_targets(store, online=True)
        assert len(requests) == 1
        current = store.report(result["reaudited_reports"][0])
        assert current["inventory"]["dependencies"][0]["osv_query"]["state"] == expected
        assert current["coverage"][0]["dependency"]["osv_query"]["state"] == expected
        assert current["inventory"]["dependency_query"]["packages"][0]["state"] == expected
        assert current["coverage"][0]["state"] == ("checked" if status == 200 else "partial")
        assert current["online_query"]["requested"] is True
        assert bool(current["online_query"]["errors"]) == (status != 200)
        assert "Owned prior OSV failure" not in current["warnings"]
        assert "Owned inventory notice" in current["warnings"]
        assert all(error in current["warnings"] for error in current["online_query"]["errors"])
        assert store.report(prior["id"]) == prior
    finally:
        client.close()


@pytest.mark.parametrize("status", [200, 503])
def test_mcp_dependency_query_persists_online_attempt(store, tmp_path, monkeypatch, status):
    from mobile_audit import mcp_server

    prior = saved_report(store, tmp_path, errors=["Owned prior OSV failure"])
    requests, client = mocked_query(monkeypatch, mcp_server, status=status)
    try:
        server = mcp_server.create_server(store.home, roots=[tmp_path])
        tool = server._tool_manager.get_tool("dependency_check")
        assert tool is not None
        response = tool.fn(report_id=prior["id"])
        assert len(requests) == 1
        current = store.report(response["report_id"])
        assert current["online_query"]["requested"] is True
        assert bool(current["online_query"]["errors"]) == (status != 200)
        assert response["dependency_query_error_count"] == len(current["online_query"]["errors"])
        assert "Owned prior OSV failure" not in current["warnings"]
        assert "Owned inventory notice" in current["warnings"]
        assert all(error in current["warnings"] for error in current["online_query"]["errors"])
        assert store.report(prior["id"]) == prior
    finally:
        client.close()


def test_offline_refresh_retains_last_query_errors(store, tmp_path):
    prior = saved_report(store, tmp_path, errors=["Owned prior OSV failure"])
    current = refresh_report(store, prior["id"], save=False)
    assert current["online_query"] == prior["online_query"]
    assert "Owned prior OSV failure" in current["warnings"]
    assert "Owned inventory notice" in current["warnings"]


def test_watch_saves_changed_query_metadata_then_deduplicates(store, tmp_path, monkeypatch):
    saved_report(store, tmp_path)
    _, client = mocked_query(monkeypatch, watch)
    try:
        warm = watch.reassess_targets(store, online=True)
        prior = store.report(warm["reaudited_reports"][0])
        prior["id"], prior["created"] = uid("audit"), now()
        prior["inventory"]["dependency_query"]["mode"] = "batch"
        store.save_report(prior)
        changed = watch.reassess_targets(store, online=True)
        assert len(changed["reaudited_reports"]) == 1
        current = store.report(changed["reaudited_reports"][0])
        assert current["inventory"]["dependency_query"]["mode"] == "auto"
        assert watch.reassess_targets(store, online=True)["reaudited_reports"] == []
    finally:
        client.close()
