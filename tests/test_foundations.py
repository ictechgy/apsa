import copy
import json
import os
import sqlite3
import sys
import time
from pathlib import Path

import pytest

from mobile_audit.audit import compare, scan
from mobile_audit.core import finding, read_under
from mobile_audit.engine import analyze_target, parser_lease
from mobile_audit.inputs import inspect_target
from mobile_audit.processes import command
from mobile_audit.store import Store
from mobile_audit.tools import resolve_tool


@pytest.mark.parametrize("stream", ["stdout", "stderr"])
def test_output_flood_is_stopped_without_returning_sensitive_output(stream):
    started = time.monotonic()
    script = (
        f"import sys; s=sys.{stream}; s.write('PRIVATE' * 200000); s.flush(); import time; time.sleep(20)"
    )
    with pytest.raises(ValueError, match="exceeds size limit") as error:
        command([sys.executable, "-c", script], timeout=3, max_bytes=1024)
    assert "PRIVATE" not in str(error.value)
    assert time.monotonic() - started < 3


def test_command_timeout_includes_children_holding_pipes():
    script = "import subprocess,sys; subprocess.Popen([sys.executable,'-c','import time; time.sleep(20)'])"
    with pytest.raises(ValueError, match="timed out"):
        command([sys.executable, "-c", script], timeout=0.2)


def test_parser_resident_memory_is_bounded():
    script = "import time; data=bytearray(80*1024*1024); time.sleep(20)"
    with pytest.raises(ValueError, match="memory exceeds limit"):
        command([sys.executable, "-c", script], timeout=3, max_rss=30 * 1024 * 1024)


def test_sdk_tools_are_discovered_without_path(monkeypatch, tmp_path):
    sdk = tmp_path / "SDK with spaces"
    adb = sdk / "platform-tools/adb"
    adb.parent.mkdir(parents=True)
    adb.write_text("#!/bin/sh\nexit 0\n")
    adb.chmod(0o700)
    monkeypatch.setenv("ANDROID_SDK_ROOT", str(sdk))
    monkeypatch.setattr("mobile_audit.tools.shutil.which", lambda _: None)
    assert resolve_tool("adb") == str(adb)


def test_reports_are_immutable_and_integrity_checked(store, demo):
    report = scan(store, demo)
    store.save_report(report)
    altered = copy.deepcopy(report)
    altered["warnings"].append("changed")
    with pytest.raises(ValueError, match="immutable"):
        store.save_report(altered)
    assert store.report(report["id"]) == report
    assert store.verify_reports()["state"] == "passed"
    exported = store.home / "reports" / f"{report['id']}.json"
    exported.write_text(json.dumps(altered))
    assert store.verify_reports()["state"] == "failed"
    with store.db:
        store.db.execute("UPDATE reports SET body='{}' WHERE id=?", (report["id"],))
    with pytest.raises(ValueError, match="integrity"):
        store.report(report["id"])


def test_existing_mvp_database_migrates_without_changing_evidence(tmp_path):
    home = tmp_path / "state"
    home.mkdir()
    db = sqlite3.connect(home / "audit.sqlite3")
    db.execute("CREATE TABLE reports(id TEXT PRIMARY KEY,created TEXT,target TEXT,body TEXT)")
    report = {"id": "old", "created": "2026-01-01", "target": "/old", "warnings": []}
    old_body = json.dumps(report)
    db.execute("INSERT INTO reports VALUES(?,?,?,?)", ("old", report["created"], report["target"], old_body))
    db.commit()
    db.close()
    store = Store(home)
    try:
        assert store.report("old") == report
        assert store.db.execute("SELECT body FROM reports").fetchone()[0] == old_body
        assert store.db.execute("PRAGMA user_version").fetchone()[0] == 2
        if os.name == "posix":
            assert (home / "audit.sqlite3").stat().st_mode & 0o777 == 0o600
    finally:
        store.close()


def test_finding_identity_ignores_intel_revision_and_runtime_run_id():
    def item(evidence):
        return finding("CVE-X", "Title", "medium", "candidate", [evidence], "Fix")

    dependency = {"name": "example:lib", "ecosystem": "Maven", "version": "1", "path": "build.gradle"}
    a = item({"dependency": dependency, "intel_snapshot_hash": "old", "advisory_modified": "yesterday"})
    b = item({"dependency": dict(dependency, version="2"), "intel_snapshot_hash": "new"})
    assert a["id"] == b["id"]
    assert item({"path": "App.java", "line": 10})["id"] != item({"path": "App.java", "line": 20})["id"]
    assertion = {"baseline": "before", "snapshot": "after", "marker": "account_a", "surface": "storage"}
    assert (
        item({"runtime_id": "one", "assertion": assertion})["id"]
        == item({"runtime_id": "two", "assertion": assertion})["id"]
    )


def test_compare_preserves_multiple_same_file_locations(store):
    def report(identifier, lines):
        return {
            "id": identifier,
            "created": identifier,
            "target": "/app",
            "coverage": [],
            "findings": [
                finding("RULE", "T", "medium", "candidate", [{"path": "App.java", "line": n}], "Fix")
                for n in lines
            ],
        }

    store.save_report(report("before", [10, 20]))
    store.save_report(report("after", [10]))
    delta = compare(store, "before", "after")
    assert delta["unchanged"] == 1
    assert delta["no_longer_observed"][0]["evidence"][0]["line"] == 20


def test_source_total_byte_budget_marks_incomplete(monkeypatch, tmp_path):
    (tmp_path / "A.java").write_text("class A {}")
    (tmp_path / "B.java").write_text("class B {}")
    monkeypatch.setattr("mobile_audit.inputs.MAX_SOURCE_TOTAL", 15)
    inventory, sources = inspect_target(tmp_path)
    assert len(sources) == 1
    assert inventory["bytes_scanned"] <= 15
    assert not inventory["fingerprint_complete"]
    assert any("total byte limit" in w for w in inventory["warnings"])


def test_secure_traversal_rejects_symlink_ancestors_and_authorized_target_swap(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.java").write_text("private")
    root = tmp_path / "project"
    root.mkdir()
    (root / "src").symlink_to(outside, target_is_directory=True)
    with pytest.raises(OSError):
        read_under(root, Path("src/secret.java"))
    authorized = root.resolve()
    (root / "src").unlink()
    root.rmdir()
    root.symlink_to(outside, target_is_directory=True)
    with pytest.raises(ValueError, match="Authorized input moved"):
        analyze_target(root, expected_target=authorized)


def test_parser_concurrency_budget(tmp_path):
    with parser_lease(tmp_path), parser_lease(tmp_path):
        with pytest.raises(ValueError, match="Two parsers"):
            with parser_lease(tmp_path):
                pass


def test_bounded_file_reads_refuse_replaced_ancestor_symlinks(tmp_path):
    from mobile_audit.core import read_bounded

    original = tmp_path / "original"
    original.mkdir()
    (original / "policy.json").write_text('{"schema_version": 1}')
    link = tmp_path / "swapped"
    link.symlink_to(original, target_is_directory=True)
    with pytest.raises(OSError):
        read_bounded(link / "policy.json")
