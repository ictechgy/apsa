"""New synthetic dependency fixtures; no service/network or retained inputs."""

import json
from typing import cast

import httpx
import pytest

from mobile_audit.dependency_evidence import ResolvedBuildSelection, select_dependency_evidence
from mobile_audit.dependency_policy import DependencyTransmissionPolicy
from mobile_audit.intel import query_dependencies
from mobile_audit.source_context import ModuleGraph


def dependency(index=0, **extra):
    return {
        "ecosystem": "Maven",
        "name": f"synthetic.public:library{index}",
        "version": "1.0",
        "confidence": "exact",
        "path": "app/gradle.lockfile",
        "version_source": "gradle-lockfile-resolved",
        "resolved_configurations": ["releaseRuntimeClasspath"],
        **extra,
    }


def record(identifier="SYNTHETIC-1", **extra):
    return {
        "id": identifier,
        "modified": "2026-10-11T00:00:00Z",
        "summary": "Synthetic record",
        "affected": [],
        **extra,
    }


def test_large_batch_coverage_and_order(store):
    deps = [dependency(index) for index in range(251)]
    calls, states = [], []

    def handler(request):
        assert request.url.path == "/v1/querybatch"
        payload = json.loads(request.content)
        calls.append(payload)
        return httpx.Response(200, json={"results": [{} for _ in payload["queries"]]})

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        found, errors = query_dependencies(store, deps, client, package_states=states)
    assert found == errors == []
    assert [len(call["queries"]) for call in calls] == [100, 100, 51]
    assert [q["package"]["name"] for c in calls for q in c["queries"]] == [d["name"] for d in deps]
    assert all(s["state"] == "complete" and s["checked"] for s in states)
    assert len(store.feeds()) == 251


def test_batch_paginates_only_affected_items_and_hydrates_ids(store):
    deps = [dependency(0), dependency(1)]
    calls = []

    def handler(request):
        calls.append(
            (request.method, request.url.path, json.loads(request.content) if request.content else None)
        )
        if request.method == "GET":
            return httpx.Response(200, json=record(request.url.path.rsplit("/", 1)[-1]))
        if len(calls) == 1:
            return httpx.Response(
                200,
                json={
                    "results": [
                        {
                            "vulns": [{"id": "SYNTHETIC-1", "modified": record()["modified"]}],
                            "next_page_token": "page-two",
                        },
                        {},
                    ]
                },
            )
        assert len(json.loads(request.content)["queries"]) == 1
        assert json.loads(request.content)["queries"][0]["page_token"] == "page-two"
        return httpx.Response(
            200, json={"results": [{"vulns": [{"id": "SYNTHETIC-2", "modified": record()["modified"]}]}]}
        )

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        found, errors = query_dependencies(store, deps, client, query_mode="batch")
    assert not errors and len(found) == 2
    assert deps[0]["osv_query"]["pages"] == 2 and deps[1]["osv_query"]["pages"] == 1
    assert found[0]["provenance"]["document_url"].endswith("/v1/vulns/SYNTHETIC-1")
    assert found[0]["provenance"]["query_url"].endswith("/v1/querybatch")


@pytest.mark.parametrize(
    "bad", [{"results": []}, {"results": [{}] * 3}, {"results": None}, {"results": [], "extra": 1}]
)
def test_malformed_batch_count_never_shifts_package_association(store, bad):
    deps = [dependency(0), dependency(1)]
    with httpx.Client(transport=httpx.MockTransport(lambda request: httpx.Response(200, json=bad))) as client:
        found, errors = query_dependencies(store, deps, client, query_mode="batch")
    assert not found and errors
    assert all(not d["osv_query"]["checked"] for d in deps)
    assert all(feed["status"] == "error" for feed in store.feeds())


def test_bad_individual_item_does_not_poison_other_success(store):
    deps = [dependency(0), dependency(1)]
    with httpx.Client(
        transport=httpx.MockTransport(
            lambda request: httpx.Response(200, json={"results": [{"vulns": "bad"}, {}]})
        )
    ) as client:
        _, errors = query_dependencies(store, deps, client, query_mode="batch")
    assert errors and deps[0]["osv_query"]["state"] == "partial"
    assert deps[1]["osv_query"]["state"] == "complete"


def test_hydration_failure_preserves_cache_and_marks_partial(store):
    dep = dependency()
    source = f"osv:Maven:{dep['name']}:1.0"
    store.upsert_intel([{"id": "SYNTHETIC-OLD", "source": source, "title": "Synthetic prior"}])

    def handler(request):
        if request.method == "GET":
            return httpx.Response(503)
        return httpx.Response(
            200, json={"results": [{"vulns": [{"id": "SYNTHETIC-1", "modified": record()["modified"]}]}]}
        )

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        found, errors = query_dependencies(store, [dep], client, query_mode="batch")
    assert found == [] and errors and store.intel_by_id("SYNTHETIC-OLD")
    assert dep["osv_query"]["state"] == "partial" and not dep["osv_query"]["checked"]


def test_excluded_coordinates_never_transmitted_or_checked_despite_cached_success(store):
    deps = [dependency(0, name="synthetic.private:secret"), dependency(1), dependency(2, ecosystem="npm")]
    prior_source = "osv:Maven:synthetic.private:secret:1.0"
    store.feed(prior_source, "ok")
    calls = []

    def handler(request):
        payload = json.loads(request.content)
        calls.extend(payload["queries"])
        return httpx.Response(200, json={"results": [{} for _ in payload["queries"]]})

    policy = DependencyTransmissionPolicy(exclude_ecosystems=("npm",), exclude_names=("synthetic.private:*",))
    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        _, errors = query_dependencies(store, deps, client, query_mode="batch", exclusion_policy=policy)
    assert len(calls) == 1 and calls[0]["package"]["name"] == deps[1]["name"]
    assert deps[0]["osv_query"]["state"] == deps[2]["osv_query"]["state"] == "excluded"
    assert not deps[0]["osv_query"]["checked"] and not deps[0]["osv_query"]["transmitted"]
    assert "excluded" in errors[-1]
    assert next(feed for feed in store.feeds() if feed["source"] == prior_source)["status"] == "ok"


def test_repeated_page_and_request_budget_are_bounded(store):
    deps = [dependency(0), dependency(1)]
    calls = []

    def handler(request):
        calls.append(request)
        queries = json.loads(request.content)["queries"]
        return httpx.Response(200, json={"results": [{"next_page_token": "repeat"} for _ in queries]})

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        _, errors = query_dependencies(store, deps, client, query_mode="batch", max_requests=2)
    assert len(calls) == 2 and errors
    assert all(d["osv_query"]["state"] == "partial" for d in deps)


def test_literal_projectdir_remapping_preserves_shipped_reach():
    graph = ModuleGraph(
        [
            (
                "settings.gradle.kts",
                'include(":app", ":core")\nproject(":core").projectDir = file("modules/engine")',
            ),
            (
                "app/build.gradle.kts",
                'plugins { id("com.android.application") }\ndependencies { implementation(project(":core")) }',
            ),
            ("modules/engine/build.gradle.kts", 'plugins { id("com.android.library") }'),
        ]
    )
    assert not graph.partial
    assert graph.module_directories["core"] == "modules/engine"
    assert graph.reach["app"] == {"app", "modules/engine"}


@pytest.mark.parametrize(
    "mapping",
    [
        'file("../outside")',
        'file("/absolute")',
        'file("missing")',
        "file(directory)",
        'file("modules/engine") + suffix',
    ],
)
def test_unsafe_or_computed_remapping_marks_graph_partial(mapping):
    graph = ModuleGraph(
        [
            ("settings.gradle.kts", f'project(":core").projectDir = {mapping}'),
            ("modules/engine/build.gradle.kts", 'plugins { id("com.android.library") }'),
        ]
    )
    assert graph.partial and graph.unresolved_project_references and graph.warnings


def test_selected_app_and_variant_filters_other_lockfiles_without_freshness_claim():
    graph = ModuleGraph(
        [(f"{app}/build.gradle.kts", 'plugins { id("com.android.application") }') for app in ("a", "b")]
    )
    deps = [
        dependency(0, path="a/gradle.lockfile", resolved_configurations=["paidReleaseRuntimeClasspath"]),
        dependency(1, path="a/gradle.lockfile", resolved_configurations=["freeReleaseRuntimeClasspath"]),
        dependency(2, path="b/gradle.lockfile", resolved_configurations=["paidReleaseRuntimeClasspath"]),
    ]
    selected, warnings = select_dependency_evidence(
        deps, graph, selection=ResolvedBuildSelection("a", "paidReleaseRuntimeClasspath")
    )
    assert [d["name"] for d in selected] == [deps[0]["name"]]
    assert selected[0]["build_evidence"]["freshness"] == "unverified"
    assert not selected[0]["build_evidence"]["installed_build_verified"] and warnings
    assert "build_evidence" not in deps[0]


def test_missing_selection_remains_explicit_and_partial():
    graph = ModuleGraph([])
    selected, warnings = select_dependency_evidence(
        [dependency()], graph, selection=ResolvedBuildSelection("app", "releaseRuntimeClasspath")
    )
    assert selected[0]["confidence"] == "declared"
    assert selected[0]["build_evidence"]["selection"] == "partial" and warnings


def test_conditional_mapping_cannot_establish_graph_resolution():
    graph = ModuleGraph(
        [
            ("settings.gradle.kts", 'if (flag) project(":core").projectDir = file("modules/engine")'),
            ("modules/engine/build.gradle.kts", 'plugins { id("com.android.library") }'),
        ]
    )
    assert graph.partial and graph.warnings


def test_conflicting_selected_evidence_is_partial():
    graph = ModuleGraph([("app/build.gradle.kts", 'plugins { id("com.android.application") }')])
    selected, warnings = select_dependency_evidence(
        [dependency(), dependency(version="2.0")],
        graph,
        selection=ResolvedBuildSelection("app", "releaseRuntimeClasspath"),
    )
    assert all(dep["build_evidence"]["selection"] == "partial" for dep in selected)
    assert all(dep["confidence"] == "declared" for dep in selected)
    assert any("conflicting" in warning for warning in warnings)


def test_rate_limit_is_not_retried_or_counted_checked(store):
    calls = []

    def handler(request):
        calls.append(request)
        return httpx.Response(429, headers={"Retry-After": "3600"})

    dep = dependency()
    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        _, errors = query_dependencies(store, [dep], client, query_mode="batch")
    assert len(calls) == 1 and errors
    assert dep["osv_query"]["state"] == "error" and not dep["osv_query"]["checked"]


def test_cache_freshness_avoids_repeat_batch_transmission(store):
    calls = []

    def handler(request):
        calls.append(request)
        return httpx.Response(200, json={"results": [{}]})

    dep = dependency()
    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        query_dependencies(store, [dep], client, query_mode="batch")
        query_dependencies(store, [dep], client, query_mode="batch")
    assert len(calls) == 1
    assert dep["osv_query"]["state"] == "cached" and not dep["osv_query"]["transmitted"]


def test_policy_patterns_are_validated_and_frozen():
    patterns = ["synthetic.private:*"]
    # Exercise normalization of a mutable caller input at the runtime boundary.
    policy = DependencyTransmissionPolicy(exclude_names=cast(tuple[str, ...], patterns))
    patterns.clear()
    assert policy.excludes(dependency(name="synthetic.private:secret"))
    with pytest.raises(ValueError):
        DependencyTransmissionPolicy(exclude_names=("bad\x00pattern",))
