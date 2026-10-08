"""Boundary and correctness regressions for the 1.0.4 and 1.0.5 reviews."""

import copy
import errno
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
from mobile_audit.runtime import evaluate_assertions, local_storage, plan, run, snapshot
from mobile_audit.skills import install_skill, skill_status
from mobile_audit.store import Store
from tests.test_jobs import terminal


@pytest.fixture
def permission_guard():
    if os.name != "posix" or os.geteuid() == 0:
        pytest.skip("Permission-denied controls require a non-root POSIX user")


@pytest.fixture
def permission_project(tmp_path):
    project = tmp_path / "owned-project"
    project.mkdir()
    (project / "AndroidManifest.xml").write_text(
        '<manifest xmlns:android="http://schemas.android.com/apk/res/android" '
        'package="com.example.owned"><application android:debuggable="false"/></manifest>'
    )
    (project / "Root.java").write_text("class Root {}")
    nested = project / "src" / "nested"
    nested.mkdir(parents=True)
    fixture = Path(__file__).parent.parent / "benchmarks/cases/java/ssl-vulnerable.java"
    (nested / "Main.java").write_bytes(fixture.read_bytes())
    return project


@pytest.mark.parametrize("entry", ["src", "src/nested", "src/nested/Main.java"])
def test_source_unreadable_entries_are_incomplete(permission_guard, permission_project, entry):
    denied = permission_project / entry
    readable, _ = inputs.inspect_target(permission_project)
    assert readable["files_scanned"] == 3
    assert not readable["partial"] and readable["fingerprint_complete"]
    mode = stat.S_IMODE(denied.stat().st_mode)
    try:
        denied.chmod(0)
        with pytest.raises(PermissionError):
            list(denied.iterdir()) if denied.is_dir() else denied.read_bytes()
        incomplete, _ = inputs.inspect_target(permission_project)
        assert incomplete["partial"] and not incomplete["fingerprint_complete"]
        assert incomplete["files_scanned"] == 2
        assert incomplete["warnings"]
        assert str(permission_project) not in " ".join(incomplete["warnings"])
    finally:
        denied.chmod(mode)


def test_source_unreadable_root_is_an_explicit_error(permission_guard, permission_project):
    try:
        permission_project.chmod(0)
        with pytest.raises(ValueError, match="inspection incomplete"):
            inputs.inspect_target(permission_project)
    finally:
        permission_project.chmod(0o700)


def test_source_scan_unreadable_directory_cannot_pass_ci(
    permission_guard, permission_project, tmp_path, capsys
):
    from mobile_audit.cli import main

    arguments = [
        "scan",
        str(permission_project),
        "--home",
        str(tmp_path / "owned-home"),
        "--fail-on",
        "high",
        "--include-candidates",
        "--json",
    ]
    assert main(arguments) == 4
    readable = json.loads(capsys.readouterr().out)["data"]
    assert any(item["rule_id"] == "AST-WEBVIEW-SSL-BYPASS" for item in readable["findings"])
    denied = permission_project / "src"
    try:
        denied.chmod(0)
        assert main(arguments) == 3
        value = json.loads(capsys.readouterr().out)
        assert value["exit_code"] == 3 and value["ok"] is False
        report = value["data"]
        assert report["summary"]["incomplete"]
        assert report["inventory"]["partial"]
        assert not report["inventory"]["fingerprint_complete"]
        assert not any(item["state"] == "checked" for item in report["coverage"])
        assert evaluate(report, {"schema_version": 1})["exit_code"] == 3
    finally:
        denied.chmod(0o700)


@pytest.mark.parametrize("failure", [PermissionError, FileNotFoundError])
def test_source_stat_failure_after_enumeration_is_incomplete(permission_project, monkeypatch, failure):
    lost = permission_project / "src/nested/Main.java"
    original = Path.lstat

    def unreadable(path, *args, **kwargs):
        if path == lost:
            raise failure(
                errno.EACCES if failure is PermissionError else errno.ENOENT, "unavailable", str(path)
            )
        return original(path, *args, **kwargs)

    monkeypatch.setattr(Path, "lstat", unreadable)
    inventory, _ = inputs.inspect_target(permission_project)
    assert inventory["partial"] and not inventory["fingerprint_complete"]
    assert inventory["files_scanned"] == 2
    assert any("src/nested/Main.java" in warning for warning in inventory["warnings"])


@pytest.mark.parametrize("entry", ["node_modules", "linked-directory"])
def test_source_intentional_exclusions_remain_complete(permission_guard, permission_project, tmp_path, entry):
    excluded = tmp_path / "excluded"
    excluded.mkdir()
    (excluded / "Hidden.java").write_text("class Hidden {}")
    if entry == "node_modules":
        excluded.rename(permission_project / entry)
        excluded = permission_project / entry
    else:
        (permission_project / entry).symlink_to(excluded, target_is_directory=True)
    try:
        excluded.chmod(0)
        inventory, _ = inputs.inspect_target(permission_project)
        assert inventory["files_scanned"] == 3
        assert not inventory["partial"] and inventory["fingerprint_complete"]
        assert not inventory["warnings"]
    finally:
        excluded.chmod(0o700)


class LocalStorageAdapter:
    def __init__(self, root):
        self.root = root

    def storage(self):
        return local_storage(self.root)

    def ui(self):
        raise ValueError("This fixture captures storage only")

    def logs(self):
        raise ValueError("This fixture captures storage only")


def storage_assertion():
    return {"assertions": [{"baseline": "before", "snapshot": "after", "marker": "account_a"}]}


@pytest.mark.parametrize("entry", [".", "private", "private/nested", "private/nested/canary.txt"])
def test_storage_unreadable_entries_cannot_pass_deletion(permission_guard, tmp_path, entry):
    root = tmp_path / "owned-storage"
    nested = root / "private/nested"
    nested.mkdir(parents=True)
    canary = nested / "canary.txt"
    canary.write_text("owned-test-canary")
    adapter = LocalStorageAdapter(root)
    markers = {"account_a": "owned-test-canary"}
    before = snapshot(adapter, markers)
    assert before["surfaces"]["storage"]["state"] == "captured"
    unchanged = snapshot(adapter, markers)
    assert (
        evaluate_assertions(storage_assertion(), {"before": before, "after": unchanged})[0]["state"]
        == "failed"
    )
    denied = root / entry
    mode = stat.S_IMODE(denied.stat().st_mode)
    try:
        denied.chmod(0)
        after = snapshot(adapter, markers)
        assert after["surfaces"]["storage"]["state"] == "not-run"
        assert (
            evaluate_assertions(storage_assertion(), {"before": before, "after": after})[0]["state"]
            == "not-run"
        )
        assert "owned-test-canary" not in json.dumps(after)
        assert str(root) not in after["surfaces"]["storage"]["reason"]
    finally:
        denied.chmod(mode)
    assert canary.read_text() == "owned-test-canary"


@pytest.mark.parametrize("failure", [PermissionError, FileNotFoundError])
def test_storage_stat_failure_is_not_a_successful_capture(tmp_path, monkeypatch, failure):
    canary = tmp_path / "canary.txt"
    canary.write_text("owned-test-canary")
    original = Path.lstat

    def unreadable(path, *args, **kwargs):
        if path == canary:
            raise failure(
                errno.EACCES if failure is PermissionError else errno.ENOENT, "unavailable", str(path)
            )
        return original(path, *args, **kwargs)

    monkeypatch.setattr(Path, "lstat", unreadable)
    result = snapshot(LocalStorageAdapter(tmp_path), {"account_a": "owned-test-canary"})
    assert result["surfaces"]["storage"]["state"] == "not-run"
    assert str(tmp_path) not in result["surfaces"]["storage"]["reason"]


def test_storage_observed_deletion_still_passes(tmp_path):
    canary = tmp_path / "canary.txt"
    canary.write_text("owned-test-canary")
    adapter = LocalStorageAdapter(tmp_path)
    markers = {"account_a": "owned-test-canary"}
    before = snapshot(adapter, markers)
    canary.unlink()
    after = snapshot(adapter, markers)
    assert after["surfaces"]["storage"]["state"] == "captured"
    assert (
        evaluate_assertions(storage_assertion(), {"before": before, "after": after})[0]["state"] == "passed"
    )


def test_storage_error_paths_redact_canary_markers(permission_guard, tmp_path):
    nested = tmp_path / "owned-test-canary"
    nested.mkdir()
    try:
        nested.chmod(0)
        result = snapshot(LocalStorageAdapter(tmp_path), {"account_a": "owned-test-canary"})
        assert result["surfaces"]["storage"]["state"] == "not-run"
        assert "[CANARY:account_a]" in result["surfaces"]["storage"]["reason"]
        assert "owned-test-canary" not in json.dumps(result)
    finally:
        nested.chmod(0o700)


def test_storage_partial_capture_keeps_prior_runtime_evidence(permission_guard, store, demo, tmp_path):
    report = scan(store, demo)
    root = tmp_path / "owned-container"
    nested = root / "private"
    nested.mkdir(parents=True)
    (nested / "canary.txt").write_text("owned-test-canary")
    package = next(app["package"] for app in report["inventory"]["apps"] if app["platform"] == "ios")
    scenario = {
        "platform": "ios",
        "package": package,
        "precondition": "Owned local storage adapter with a known canary and logout marker",
        "markers": {"account_a": "owned-test-canary", "logged_out": "owned-logout-marker"},
        "steps": [
            {"action": "snapshot", "label": "before"},
            {"action": "open_url", "url": "owned://logout"},
            {"action": "snapshot", "label": "after"},
        ],
        "assertions": [
            {"baseline": "before", "snapshot": "after", "marker": "account_a"},
            {
                "baseline": "before",
                "snapshot": "after",
                "marker": "logged_out",
                "expect": "present",
                "purpose": "transition",
            },
        ],
    }

    class Container(LocalStorageAdapter):
        def __init__(self, deny):
            super().__init__(root)
            self.deny = deny
            (root / "state.txt").write_text("signed-in")

        def environment(self):
            return {"platform": "ios", "version": "27.0"}

        def open_url(self, url):
            (root / "state.txt").write_text("owned-logout-marker")
            if self.deny:
                nested.chmod(0)

    retained = run(store, tmp_path / "frozen.json", report["id"], adapter=Container(False), scenario=scenario)
    old_ids = {f["id"] for f in retained["findings"] if f["status"] == "runtime-confirmed"}
    assert old_ids
    try:
        incomplete = run(
            store, tmp_path / "frozen.json", retained["id"], adapter=Container(True), scenario=scenario
        )
        assert incomplete["runtime"][-1]["partial"]
        assert all(result["state"] == "not-run" for result in incomplete["runtime"][-1]["assertions"])
        assert old_ids <= {f["id"] for f in incomplete["findings"]}
        assert (
            evaluate(incomplete, {"schema_version": 1, "required_rules": ["RUNTIME-RESIDUAL"]})["exit_code"]
            == 3
        )
    finally:
        nested.chmod(0o700)


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
