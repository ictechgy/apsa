"""Exact dependency evidence survives unrelated recent-cache growth."""

import copy
import json
from pathlib import Path

from mobile_audit import audit
from mobile_audit.core import canonical_json, uid

DEP = {"ecosystem": "PyPI", "name": "synthetic-target", "version": "1.0", "confidence": "exact"}
SOURCE = "osv:PyPI:synthetic-target:1.0"


def insert_record(store, identifier, source=SOURCE, *, branch="", withdrawn=False):
    record = {
        "id": identifier,
        "source": source,
        "modified": "2000-01-01T00:00:00Z",
        "title": "Synthetic dependency advisory",
        "severity": "high",
        "query_match": {key: DEP[key] for key in ("ecosystem", "name", "version")},
    }
    if withdrawn:
        record["withdrawn"] = "2001-01-01T00:00:00Z"
    body = canonical_json(record)
    if branch:
        store.db.execute(
            "INSERT INTO intel_branches VALUES(?,?,?,?,?)",
            (identifier, source, branch, record["modified"], body),
        )
    else:
        store.db.execute("INSERT INTO intel VALUES(?,?,?,?)", (identifier, source, record["modified"], body))
    store.db.commit()


def test_scan_and_refresh_retain_exact_dependency_after_global_window_is_full(store, monkeypatch):
    insert_record(store, "CVE-2099-1234")
    # Upstream advisory modification time can precede its fresh OSV query.
    store.db.executemany(
        "INSERT INTO intel VALUES(?,?,?,?)",
        (
            (
                f"NOISE-{i}",
                "cve",
                "2099-01-01T00:00:00Z",
                json.dumps({"id": f"NOISE-{i}", "source": "cve"}),
            )
            for i in range(100000)
        ),
    )
    store.db.commit()
    inventory = {
        "target": "/synthetic-target",
        "input_kind": "source",
        "platforms": [],
        "dependencies": [DEP],
        "warnings": [],
        "partial": False,
    }
    monkeypatch.setattr(
        audit,
        "analyze_target",
        lambda *args, **kwargs: {"inventory": copy.deepcopy(inventory), "findings": [], "coverage": []},
    )
    monkeypatch.setattr(
        audit, "source_health", lambda _: [{"source": SOURCE, "status": "ok", "stale": False, "count": 1}]
    )
    assert all(record["source"] != SOURCE for record in store.intelligence(limit=100000))
    original = audit.scan(store, Path("/synthetic-target"))
    refreshed = audit.refresh_report(store, original["id"])
    for report in (original, refreshed):
        assert [finding["rule_id"] for finding in report["findings"]] == ["CVE-2099-1234"]
        assert report["coverage"][0]["state"] == "checked"
        assert report["findings"][0]["evidence"][0]["intel_snapshot_hash"]


def test_exact_sources_keep_branches_and_do_not_duplicate_recent_records(store):
    insert_record(store, "CVE-2099-1234")
    insert_record(store, "CVE-2099-1234", branch="distinct-advisory")
    insert_record(store, "CVE-2099-5678", withdrawn=True)
    unrelated = "osv:PyPI:synthetic-target-extra:1.0"
    insert_record(store, "CVE-2099-9999", unrelated)
    exact = store.correlation_intelligence([DEP, DEP], limit=0)
    assert len(exact) == 3
    assert all(row["source"] == SOURCE and row["snapshot_hash"] for row in exact)
    assert {row.get("branch_id", "") for row in exact} == {"", "distinct-advisory"}
    assert len(store.correlation_intelligence([DEP], limit=100)) == 4
    findings, _ = audit.correlate({"dependencies": [DEP], "platforms": []}, exact)
    assert {finding["rule_id"] for finding in findings} == {"CVE-2099-1234"}


def test_exact_source_lookup_chunks_variables_and_retains_excluded_positive(store):
    deps = [{**DEP, "name": f"unused-{i}"} for i in range(1001)]
    excluded = {**DEP, "osv_query": {"state": "excluded", "checked": False}}
    insert_record(store, "CVE-2099-1234")
    records = store.correlation_intelligence([*deps, excluded], limit=0)
    assert len(records) == 1
    findings, _ = audit.correlate({"dependencies": [excluded], "platforms": []}, records)
    assert len(findings) == 1
    assert audit.dependency_coverage_state(excluded, {"status": "ok", "stale": False}) == "not-run"


def test_runtime_reassessment_uses_exact_dependency_reader(store, demo, tmp_path, monkeypatch):
    from mobile_audit.runtime import run

    report = audit.scan(store, demo)
    report["id"] = uid("audit")
    report["inventory"]["dependencies"] = [DEP]
    report = store.save_report(report)
    insert_record(store, "CVE-2099-1234")
    # The recent general window contains no relevant package evidence.
    monkeypatch.setattr(store, "intelligence", lambda **kwargs: [])

    class SyntheticDevice:
        def environment(self):
            return {"platform": "android", "version": "16", "security_patch": "2026-09-05"}

        def storage(self):
            return [("synthetic.txt", b"fresh-public-canary")]

        def ui(self):
            return b"Synthetic screen"

        def logs(self):
            return b"Synthetic output"

    scenario = {
        "platform": "android",
        "package": "com.example.mobileauditdemo",
        "precondition": "Fresh synthetic device adapter",
        "markers": {"account_a": "fresh-public-canary"},
        "steps": [{"action": "snapshot", "label": "before"}, {"action": "snapshot", "label": "after"}],
        "assertions": [
            {"snapshot": "after", "baseline": "before", "marker": "account_a", "surface": "storage"}
        ],
    }
    result = run(
        store, tmp_path / "unused-scenario.json", report["id"], adapter=SyntheticDevice(), scenario=scenario
    )
    assert any(finding["rule_id"] == "CVE-2099-1234" for finding in result["findings"])
