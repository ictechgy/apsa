"""Boundary and correctness regressions for the 1.0.4 product review."""

import copy
import json
import os
import stat
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx
import pytest

from mobile_audit import engine, inputs, jobs, mcp_server
from mobile_audit._parser_worker import analyze
from mobile_audit.audit import correlate, scan
from mobile_audit.core import finding_identity, read_json
from mobile_audit.intel import normalize_kev, sync
from mobile_audit.policy import evaluate, load_policy
from mobile_audit.runtime import plan
from mobile_audit.skills import install_skill, skill_status
from mobile_audit.store import Store
from tests.test_jobs import terminal


@pytest.mark.parametrize("worker", ["parser", "job"])
@pytest.mark.parametrize("module", ["json.py", "sitecustomize.py"])
def test_workers_ignore_untrusted_cwd_and_pythonpath(store, demo, tmp_path, monkeypatch, worker, module):
    hostile = tmp_path / "hostile"
    hostile.mkdir()
    marker = tmp_path / "import-marker"
    (hostile / module).write_text(
        f"from pathlib import Path\nPath({str(marker)!r}).write_text('executed')\n"
        "raise RuntimeError('unexpected workspace import')\n"
    )
    monkeypatch.chdir(hostile)
    monkeypatch.setenv("PYTHONPATH", str(hostile))
    if worker == "parser":
        assert engine.analyze_target(demo)["inventory"]["package"]
    else:
        queued = jobs.start(store, {"kind": "scan", "target": str(demo)})
        result = terminal(store, queued["id"])
        assert result["state"] == "completed", result
        assert store.report(result["report_id"])["inventory"]["package"]
    assert not marker.exists()


@pytest.mark.parametrize("reader", [read_json, load_policy])
@pytest.mark.parametrize("replacement", ["parent", "leaf"])
def test_bound_readers_refuse_replaced_paths(tmp_path, reader, replacement):
    folder = tmp_path / "authorized"
    folder.mkdir()
    path = folder / "config.json"
    path.write_text('{"schema_version":1}')
    assert reader(path, authorized=True)["schema_version"] == 1
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / path.name).write_text('{"schema_version":1,"canary":"outside"}')
    if replacement == "parent":
        folder.rename(tmp_path / "original")
        folder.symlink_to(outside, target_is_directory=True)
    else:
        path.unlink()
        path.symlink_to(outside / path.name)
    with pytest.raises(OSError):
        reader(path, authorized=True)


@pytest.mark.parametrize(
    "tool_name", ["audit_scan", "audit_start", "policy_evaluate", "runtime_start", "runtime_execute"]
)
def test_mcp_reads_reject_parent_swap_after_authorization(store, demo, tmp_path, monkeypatch, tool_name):
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    project = allowed / "project"
    demo.rename(project)
    report = scan(store, project)
    folder = allowed / "config"
    folder.mkdir()
    path = folder / "input.json"
    policy = tool_name == "policy_evaluate"
    value = (
        {"schema_version": 1}
        if policy
        else plan(report)
        if tool_name.startswith("runtime")
        else {"platform": "android", "model": "owned"}
    )
    path.write_text(json.dumps(value))
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / path.name).write_text(json.dumps({**value, "model": "OUTSIDE_ROOT_CANARY"}))
    server = mcp_server.create_server(store.home, roots=[allowed], allow_runtime=True)
    tool = server._tool_manager.get_tool(tool_name)
    assert tool is not None
    arguments = (
        {"policy_path": str(path), "report_id": report["id"]}
        if policy
        else {"scenario_path": str(path), "report_id": report["id"], "execute": False}
        if tool_name.startswith("runtime")
        else {"target": str(project), "device_info": str(path)}
    )
    original = mcp_server.load_policy if policy else mcp_server.read_json

    def swapped(source, **options):
        folder.rename(allowed / "original-config")
        folder.symlink_to(outside, target_is_directory=True)
        return original(source, **options)

    monkeypatch.setattr(mcp_server, "load_policy" if policy else "read_json", swapped)
    with pytest.raises(OSError):
        tool.fn(**arguments)


@pytest.mark.parametrize("tool_name", ["runtime_start", "runtime_execute"])
def test_mcp_runtime_uses_the_validated_scenario_value(store, demo, tmp_path, monkeypatch, tool_name):
    report = scan(store, demo)
    value = plan(report)
    path = tmp_path / "scenario.json"
    path.write_text(json.dumps(value))
    server = mcp_server.create_server(store.home, roots=[tmp_path], allow_runtime=True)
    tool = server._tool_manager.get_tool(tool_name)
    assert tool is not None

    def start(database, payload):
        path.write_text("replaced after validation")
        assert payload["scenario_value"] == value
        return {"frozen": True}

    def run(database, source, identifier, *, scenario):
        path.write_text("replaced after validation")
        assert scenario == value
        return {"frozen": True}

    monkeypatch.setattr(mcp_server.jobs, "start", start)
    monkeypatch.setattr(mcp_server, "run", run)
    monkeypatch.setattr(mcp_server, "assistant_context", lambda result: {**result, "runtime": [{}]})
    result = tool.fn(scenario_path=str(path), report_id=report["id"], execute=True)
    assert result["frozen"] if tool_name == "runtime_start" else result["report"]["frozen"]


def test_runtime_job_keeps_supplied_scenario_without_rereading(store, demo, tmp_path):
    report = scan(store, demo)
    scenario = plan(report)
    path = tmp_path / "scenario.json"
    path.write_text("invalid replacement")
    queued = jobs.start(
        store,
        {
            "kind": "runtime",
            "target": str(demo),
            "report_id": report["id"],
            "scenario": str(path),
            "scenario_value": scenario,
        },
    )
    result = terminal(store, queued["id"])
    assert result["state"] == "failed" and "Customize the scenario" in result["error"]
    assert jobs.get(store, queued["id"], private=True)["payload"]["scenario_value"] == scenario


def test_worker_inspection_never_reresolves_a_replaced_source(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    (project / "App.java").write_text("class App {}")
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "Other.java").write_text("class Other {}")
    project.rename(tmp_path / "original")
    project.symlink_to(outside, target_is_directory=True)
    with pytest.raises(ValueError, match="No supported source"):
        analyze(project, None)
    assert inputs.inspect_target(project)[0]["files_scanned"] == 1


@pytest.mark.parametrize("early_symlink", [False, True])
def test_truncated_enumeration_is_partial_even_when_skipped_entries_reduce_count(
    tmp_path, monkeypatch, early_symlink
):
    monkeypatch.setattr(inputs, "MAX_FILES", 3)
    for name in ("b", "c", "d", "e", "f"):
        (tmp_path / f"{name}.java").write_text(f"class {name.upper()} {{}}")
    if early_symlink:
        (tmp_path / "a.java").symlink_to(tmp_path / "b.java")
    inventory, _ = inputs.inspect_target(tmp_path)
    assert inventory["files_scanned"] == 3
    assert inventory["partial"] and not inventory["fingerprint_complete"]
    assert any("enumeration limit" in warning for warning in inventory["warnings"])


def test_exact_source_limit_keeps_complete_fingerprint(tmp_path, monkeypatch):
    monkeypatch.setattr(inputs, "MAX_FILES", 3)
    for name in ("a", "b", "c"):
        (tmp_path / f"{name}.java").write_text(f"class {name.upper()} {{}}")
    inventory, _ = inputs.inspect_target(tmp_path)
    assert inventory["files_scanned"] == 3
    assert not inventory["partial"] and inventory["fingerprint_complete"]


@pytest.mark.parametrize("existing", [False, True])
def test_database_and_sidecars_are_private_in_an_existing_shared_home(tmp_path, existing):
    home = tmp_path / "shared-home"
    home.mkdir(mode=0o755)
    # A zero-byte database simulates initial SQLite creation under umask 022.
    if existing:
        (home / "audit.sqlite3").touch(mode=0o644)
    database = Store(home)
    try:
        for name in ("audit.sqlite3", "audit.sqlite3-wal", "audit.sqlite3-shm"):
            path = home / name
            assert stat.S_IMODE(path.stat().st_mode) == 0o600
            path.chmod(0o644)
        reopened = Store(home)
        try:
            assert all(stat.S_IMODE(path.stat().st_mode) == 0o600 for path in home.glob("audit.sqlite3*"))
            assert reopened.db.execute("PRAGMA user_version").fetchone()[0] == 2
            assert reopened.db.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
        finally:
            reopened.close()
    finally:
        database.close()


@pytest.mark.parametrize("name", ["audit.sqlite3", "audit.sqlite3-wal", "audit.sqlite3-shm"])
def test_database_permission_repair_refuses_symlinks(tmp_path, name):
    home = tmp_path / "state"
    home.mkdir()
    outside = tmp_path / "outside"
    outside.write_text("do not modify")
    outside.chmod(0o644)
    (home / name).symlink_to(outside)
    with pytest.raises(OSError):
        Store(home)
    assert outside.read_text() == "do not modify"
    assert stat.S_IMODE(outside.stat().st_mode) == 0o644


@pytest.mark.parametrize("field", ["vendorProject", "product"])
@pytest.mark.parametrize("invalid", [None, "", "  ", [], 7])
def test_malformed_kev_routing_fields_preserve_cache_and_fail_sync(store, field, invalid):
    record = {
        "cveID": "CVE-2026-12345",
        "vulnerabilityName": "Synthetic issue",
        "vendorProject": "Apple",
        "product": "iOS",
    }
    response = {"vulnerabilities": [record]}
    with httpx.Client(
        transport=httpx.MockTransport(lambda request: httpx.Response(200, json=response))
    ) as client:
        assert not sync(store, ["kev"], client=client)["partial"]
        before = store.intel_by_id(record["cveID"])
        if invalid is None:
            del record[field]
        else:
            record[field] = invalid
        result = sync(store, ["kev"], client=client)
    assert result["partial"] and store.feeds()[0]["status"] == "error"
    assert store.intel_by_id("CVE-2026-12345") == before


def test_valid_nonmobile_and_authoritative_empty_kev_catalogs_remain_valid():
    assert normalize_kev({"vulnerabilities": []}) == []
    assert (
        normalize_kev(
            {
                "vulnerabilities": [
                    {
                        "cveID": "CVE-2026-12345",
                        "vulnerabilityName": "issue",
                        "vendorProject": "Other",
                        "product": "Server",
                    }
                ]
            }
        )
        == []
    )


@pytest.mark.parametrize(
    "max_age,age,expected",
    [(72, 48, "passed"), (24, 48, "incomplete"), (2, 3, "incomplete"), (72, -1, "incomplete")],
)
def test_policy_age_uses_project_limit_instead_of_display_staleness(monkeypatch, max_age, age, expected):
    current = datetime(2026, 10, 6, 12, tzinfo=timezone.utc)
    monkeypatch.setattr("mobile_audit.policy._now", lambda: current)
    report = {
        "findings": [],
        "coverage": [],
        "intel_snapshot": [
            {
                "source": "apple",
                "status": "ok",
                "stale": age > 24,
                "succeeded": (current - timedelta(hours=age)).isoformat(),
            }
        ],
    }
    policy = {
        "schema_version": 1,
        "require_fresh_intel": True,
        "required_feeds": ["apple"],
        "intel_max_age_hours": max_age,
    }
    assert evaluate(report, policy)["state"] == expected


def test_advisories_keep_each_branch_and_snapshot_provenance():
    first = {
        "id": "CVE-2026-12345",
        "source": "android",
        "title": "issue",
        "platform": "android",
        "component": "Framework",
        "fixed_patch_level": "2026-10-01",
        "updated_aosp_versions": "17",
        "snapshot_hash": "a" * 64,
        "references": ["https://source.android.com/one"],
    }
    second = {
        **first,
        "component": "System",
        "fixed_patch_level": "2026-10-05",
        "snapshot_hash": "b" * 64,
        "references": ["https://source.android.com/two"],
    }
    third = {**first, "component": "Framework", "fixed_patch_level": "2026-10-05", "snapshot_hash": "c" * 64}
    ios = {
        **first,
        "source": "apple",
        "platform": "ios",
        "fixed_release": "iOS 27.1",
        "snapshot_hash": "d" * 64,
    }
    records = [first, second, third, ios, copy.deepcopy(first)]
    inventory = {"dependencies": [], "platforms": ["android", "ios"]}
    environment = {"platform": "android", "version": "17", "security_patch": "2026-09-01"}
    before = copy.deepcopy(records)
    findings, advisories = correlate(inventory, records, environment)
    assert findings == [] and len(advisories) == 4
    assert {entry["intel_snapshot_hash"] for entry in advisories} == {"a" * 64, "b" * 64, "c" * 64, "d" * 64}
    assert (
        next(entry for entry in advisories if entry["component"] == "System")["references"]
        == second["references"]
    )
    assert records == before


def test_affected_ios_finding_keeps_all_branches_and_stable_identity():
    first = {
        "id": "CVE-2026-12345",
        "source": "apple",
        "title": "issue",
        "platform": "ios",
        "component": "Kernel",
        "fixed_release": "iOS 18.7",
        "snapshot_hash": "a" * 64,
        "references": ["https://support.apple.com/one"],
    }
    second = {
        **first,
        "fixed_release": "iOS 26.1",
        "snapshot_hash": "b" * 64,
        "references": ["https://support.apple.com/two"],
    }
    cve = {
        "id": first["id"],
        "source": "cve",
        "title": "CNA",
        "affected": [
            {"product": "iOS", "versions": [{"version": "18.0", "lessThan": "18.7", "status": "affected"}]}
        ],
    }
    inventory = {"dependencies": [], "platforms": ["ios"]}
    environment = {"platform": "ios", "version": "18.6"}
    records = [first, second, copy.deepcopy(first), cve]
    before = copy.deepcopy(records)
    findings, advisories = correlate(inventory, records, environment)
    assert len(findings) == 1 and len(advisories) == 2
    item = findings[0]
    branches = item["evidence"][0]["advisory_branches"]
    assert {branch["intel_snapshot_hash"] for branch in branches} == {"a" * 64, "b" * 64}
    assert {branch["fixed_release"] for branch in branches} == {"iOS 18.7", "iOS 26.1"}
    assert len(branches) == 2
    assert item["references"] == sorted(first["references"] + second["references"])
    assert item["id"] == finding_identity(
        "OS-" + first["id"], [{"platform": "ios", "component": "Kernel"}], "environment"
    )
    assert finding_identity(item["rule_id"], item["evidence"], "environment") == item["id"]
    assert correlate(inventory, list(reversed(records)), environment)[0] == findings
    assert correlate(inventory, [first, cve], environment)[0][0]["id"] == item["id"]
    assert correlate(inventory, records, {"platform": "ios", "version": "18.7"})[0] == []
    assert records == before


@pytest.mark.parametrize("name", ["apsa", "quaygate", "mobile-audit"])
def test_public_103_skills_upgrade_without_overwriting_customizations(tmp_path, name):
    folder = tmp_path / name
    folder.mkdir()
    released = Path(__file__).parent / "fixtures/skills" / f"{name}-1.0.3.md"
    (folder / "SKILL.md").write_bytes(released.read_bytes())
    assert skill_status(name, folder) == "outdated"
    assert install_skill(name, folder)["status"] == "installed"
    assert skill_status(name, folder) == "current"
    (folder / "SKILL.md").write_text("user customization")
    with pytest.raises(FileExistsError):
        install_skill(name, folder)


def test_database_nonregular_file_is_rejected(tmp_path):
    os.mkfifo(tmp_path / "audit.sqlite3")
    with pytest.raises(ValueError, match="regular files"):
        Store(tmp_path)
