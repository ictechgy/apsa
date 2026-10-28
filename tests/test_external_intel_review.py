"""Fresh synthetic OSV cache/provenance and selection review regressions."""

import copy
import json

import httpx
import pytest

from mobile_audit import intel
from mobile_audit.audit import correlate
from mobile_audit.inputs import inspect_target
from tests.test_osv_pagination_recovery import advisory, dependency


def source_for(dep):
    return f"osv:{dep['ecosystem']}:{dep['name']}:{dep['version']}"


def cached_snapshot(store):
    return [tuple(row) for row in store.db.execute("SELECT * FROM intel ORDER BY source,id")]


@pytest.mark.parametrize("failure", ["http", "malformed-prefix", "hydration"])
@pytest.mark.parametrize("mode", ["batch", "auto"])
def test_no_hydrated_observation_preserves_exact_cached_snapshot(store, monkeypatch, failure, mode):
    dep: dict = dependency()
    old = advisory("GHSA-synthetic-cached")
    store.upsert_intel([intel._normalize_osv(old, dep)])
    before = cached_snapshot(store)
    replaced = []
    original_replace = store.replace_source

    def replace(*args, **kwargs):
        replaced.append(args[0])
        return original_replace(*args, **kwargs)

    monkeypatch.setattr(store, "replace_source", replace)
    dependencies = [dep]
    if mode == "auto":
        dependencies.extend({**dep, "name": f"synthetic.public:auto-{n}"} for n in range(100))
    calls = []

    def respond(request):
        calls.append((request.method, request.url.path))
        if request.method == "GET" or failure == "http":
            return httpx.Response(503)
        queries = json.loads(request.content)["queries"]
        item = {"vulns": [{"id": "GHSA-synthetic-new", "modified": old["modified"]}]}
        if failure == "malformed-prefix":
            item["vulns"].append({"id": 42})
        return httpx.Response(200, json={"results": [item for _ in queries]})

    states = []
    with httpx.Client(transport=httpx.MockTransport(respond), trust_env=False) as client:
        found, errors = intel.query_dependencies(
            store, dependencies, client, query_mode=mode, package_states=states
        )
    assert calls and not found and errors
    assert replaced == []
    assert cached_snapshot(store) == before
    assert all(row["state"] == ("partial" if failure == "hydration" else "error") for row in states)
    assert all(row["pages"] == (1 if failure == "hydration" else 0) for row in states)
    assert all(not row["checked"] for row in states)


def test_complete_empty_batch_is_a_real_observation_that_clears_prior_matches(store):
    dep: dict = dependency()
    store.upsert_intel([intel._normalize_osv(advisory(), dep)])
    with httpx.Client(
        transport=httpx.MockTransport(lambda _: httpx.Response(200, json={"results": [{}]})), trust_env=False
    ) as client:
        found, errors = intel.query_dependencies(store, [dep], client, query_mode="batch")
    assert found == [] and errors == []
    assert cached_snapshot(store) == []
    assert dep["osv_query"]["state"] == "complete" and dep["osv_query"]["checked"] is True


@pytest.mark.parametrize("failure", ["http", "malformed-prefix", "bad-token"])
def test_batch_later_invalid_page_retains_only_prior_valid_observation(store, failure):
    dep: dict = dependency()
    prior = intel._normalize_osv(advisory("GHSA-synthetic-cached"), dep)
    store.upsert_intel([prior])
    seen_get = []

    def respond(request):
        if request.method == "GET":
            identifier = request.url.path.rsplit("/", 1)[-1]
            seen_get.append(identifier)
            return httpx.Response(200, json=advisory(identifier))
        queries = json.loads(request.content)["queries"]
        if "page_token" not in queries[0]:
            return httpx.Response(
                200,
                json={
                    "results": [
                        {
                            "vulns": [{"id": "GHSA-synthetic-first", "modified": advisory()["modified"]}],
                            "next_page_token": "next",
                        }
                    ]
                },
            )
        if failure == "http":
            return httpx.Response(503)
        item = {"vulns": [{"id": "GHSA-synthetic-untrusted", "modified": advisory()["modified"]}]}
        if failure == "malformed-prefix":
            item["vulns"].append({"id": 42})
        else:
            item["next_page_token"] = []
        return httpx.Response(200, json={"results": [item]})

    with httpx.Client(transport=httpx.MockTransport(respond), trust_env=False) as client:
        found, errors = intel.query_dependencies(store, [dep], client, query_mode="batch")
    assert errors and [r["osv_id"] for r in found] == ["GHSA-synthetic-first"]
    assert seen_get == ["GHSA-synthetic-first"]
    assert dep["osv_query"]["pages"] == 1 and dep["osv_query"]["state"] == "partial"
    rows = store.correlation_intelligence([dep])
    assert {member["osv_id"] for row in rows for member in row.get("osv_records", [row])} == {
        "GHSA-synthetic-cached",
        "GHSA-synthetic-first",
    }


@pytest.mark.parametrize("mode", ["legacy", "batch"])
def test_multiple_cve_alias_order_keeps_display_and_finding_identity(store, mode):
    dep: dict = dependency()
    identifiers = []
    for aliases in (["CVE-2099-9002", "CVE-2099-1001"], ["CVE-2099-1001", "CVE-2099-9002"]):
        value = {**advisory(), "aliases": aliases}
        store.feed(source_for(dep), "error", error="Fresh synthetic refresh requested")

        def respond(request, value=value):
            if request.url.path == "/v1/querybatch":
                return httpx.Response(
                    200, json={"results": [{"vulns": [{"id": value["id"], "modified": value["modified"]}]}]}
                )
            return httpx.Response(200, json=value if request.method == "GET" else {"vulns": [value]})

        with httpx.Client(transport=httpx.MockTransport(respond), trust_env=False) as client:
            found, errors = intel.query_dependencies(store, [copy.deepcopy(dep)], client, query_mode=mode)
        assert not errors and len(found) == 1
        rows = store.correlation_intelligence([dep])
        findings, _ = correlate({"dependencies": [dep], "platforms": []}, rows)
        assert len(rows) == len(findings) == 1
        identifiers.append((rows[0]["id"], findings[0]["id"]))
        assert set(rows[0]["aliases"]) == set(aliases)
    assert identifiers[0] == identifiers[1]
    assert identifiers[0][0] == "CVE-2099-1001"


@pytest.mark.parametrize("aliases", [[], ["GHSA-synthetic-alias"], ["CVE-invalid", "CVE-2099-1001"]])
def test_display_identity_falls_back_only_when_no_valid_cve(aliases):
    normalized = intel._normalize_osv({**advisory(), "aliases": aliases}, dependency())
    assert normalized["id"] == ("CVE-2099-1001" if "CVE-2099-1001" in aliases else advisory()["id"])


@pytest.mark.parametrize("selection", ["configuration-missing", "path-missing", "matching", "unselected"])
def test_scan_selection_precedes_supersession_and_keeps_uncovered_declaration(tmp_path, store, selection):
    app = tmp_path / "app"
    app.mkdir()
    (app / "build.gradle.kts").write_text(
        'plugins { id("com.android.application") }\ndependencies { implementation("com.squareup.okhttp3:okhttp:3.12.0") }'
    )
    (app / "gradle.lockfile").write_text("com.squareup.okhttp3:okhttp:4.12.0=fossReleaseRuntimeClasspath\n")
    selected = None
    if selection != "unselected":
        selected = {
            "application_module": "app",
            "runtime_configuration": "playReleaseRuntimeClasspath"
            if selection == "configuration-missing"
            else "fossReleaseRuntimeClasspath",
            "evidence_paths": ["app/other.lockfile"] if selection == "path-missing" else [],
        }
    inventory, _ = inspect_target(tmp_path, dependency_selection=selected)
    declaration = next(d for d in inventory["dependencies"] if d["path"] == "app/build.gradle.kts")
    locks = [d for d in inventory["dependencies"] if d["path"] == "app/gradle.lockfile"]
    if selection in {"configuration-missing", "path-missing"}:
        assert locks == []
        assert declaration["confidence"] == "declared" and "resolution" not in declaration
        requests = []

        def respond(request):
            requests.append(json.loads(request.content))
            return httpx.Response(200, json={"results": [{}]})

        with httpx.Client(transport=httpx.MockTransport(respond), trust_env=False) as client:
            _, errors = intel.query_dependencies(store, inventory["dependencies"], client, query_mode="batch")
        assert not errors and requests[0]["queries"][0]["version"] == "3.12.0"
        assert declaration["osv_query"]["state"] == "complete"
    else:
        assert len(locks) == 1
        assert declaration["resolution"]["state"] == "superseded-by-resolved-build"
