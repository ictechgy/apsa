"""Synthetic job-inspection and report-transaction failures retain truthful state."""

from __future__ import annotations

import errno
import json
import os
import socket
import sqlite3
import stat
import subprocess
from pathlib import Path
from unittest.mock import Mock

import psutil
import pytest

from mobile_audit import jobs
from mobile_audit import store as store_module
from mobile_audit.core import now
from mobile_audit.store import Store


@pytest.fixture(autouse=True)
def synthetic_boundaries(monkeypatch, tmp_path):
    original_initialize = Store.__init__

    def initialize_owned_store(self, home=None):
        assert home is not None, "Default report stores are outside this synthetic test"
        assert Path(home).absolute().is_relative_to(tmp_path.absolute())
        original_initialize(self, home)

    def denied(*args, **kwargs):
        raise AssertionError("Process, socket and signal operations must be mocked")

    monkeypatch.setattr(Store, "__init__", initialize_owned_store)
    monkeypatch.setattr(psutil, "Process", denied)
    monkeypatch.setattr(subprocess, "Popen", denied)
    monkeypatch.setattr(socket, "socket", denied)
    monkeypatch.setattr(os, "kill", denied)
    monkeypatch.setattr(os, "killpg", denied)


@pytest.fixture
def fresh_store(tmp_path):
    store = Store(tmp_path / "new-state")
    yield store
    store.close()


def running_job(store, tmp_path, identifier="job-synthetic"):
    jobs.initialize(store)
    payload = {"kind": "scan", "target": str(tmp_path / "new-source.kt")}
    stamp = now()
    with store.db:
        store.db.execute(
            "INSERT INTO jobs VALUES(?,?,?,?,?,?,?,?,?,?,NULL,'')",
            (
                identifier,
                "running",
                stamp,
                stamp,
                payload["target"],
                json.dumps(payload),
                20,
                "scan",
                42,
                1.0,
            ),
        )
    return identifier


def denied_worker(monkeypatch, at):
    process = Mock()
    process.create_time.return_value = 1.0
    process.cmdline.return_value = ["python", "mobile_audit._job_worker", "job-synthetic"]
    if at == "construction":
        monkeypatch.setattr(psutil, "Process", Mock(side_effect=psutil.AccessDenied(42)))
    else:
        getattr(process, at).side_effect = psutil.AccessDenied(42)
        monkeypatch.setattr(psutil, "Process", Mock(return_value=process))
    return process


@pytest.mark.parametrize("at", ["construction", "create_time", "cmdline"])
def test_uninspectable_worker_remains_active_and_can_finish(fresh_store, tmp_path, monkeypatch, at):
    identifier = running_job(fresh_store, tmp_path)
    denied_worker(monkeypatch, at)

    assert jobs.get(fresh_store, identifier)["state"] == "running"
    assert jobs.listing(fresh_store)[0]["state"] == "running"
    assert jobs.update(fresh_store, identifier, progress=60, stage="later-progress")
    assert jobs.finish(fresh_store, identifier, "completed", report_id="new-result")
    result = jobs.get(fresh_store, identifier, private=True)
    assert result["state"] == "completed" and result["progress"] == 100
    assert result["report_id"] == "new-result" and result["error"] == ""


@pytest.mark.parametrize("at", ["construction", "create_time", "cmdline"])
def test_cancel_never_signals_or_completes_an_uninspectable_worker(fresh_store, tmp_path, monkeypatch, at):
    identifier = running_job(fresh_store, tmp_path)
    process = denied_worker(monkeypatch, at)

    result = jobs.cancel(fresh_store, identifier)

    assert result["state"] == "running" and result["stage"] == "cancellation-requested"
    assert result["report_id"] is None and result["error"] == ""
    process.send_signal.assert_not_called()
    assert not jobs.update(fresh_store, identifier, progress=80)
    assert jobs.finish(fresh_store, identifier, "completed", report_id="discarded-result")
    result = jobs.get(fresh_store, identifier, private=True)
    assert result["state"] == result["stage"] == "cancelled"
    assert result["report_id"] is None


@pytest.mark.parametrize("condition", ["missing", "zombie", "reused-pid", "different-command"])
def test_definite_worker_loss_is_still_reaped_without_signalling(
    fresh_store, tmp_path, monkeypatch, condition
):
    identifier = running_job(fresh_store, tmp_path)
    process = Mock()
    process.create_time.return_value = 1.0
    process.cmdline.return_value = ["python", "mobile_audit._job_worker", identifier]
    if condition == "missing":
        process.create_time.side_effect = psutil.NoSuchProcess(42)
    elif condition == "zombie":
        process.cmdline.side_effect = psutil.ZombieProcess(42)
    elif condition == "reused-pid":
        process.create_time.return_value = 2.0
    else:
        process.cmdline.return_value = ["synthetic-unrelated-command"]
    monkeypatch.setattr(psutil, "Process", Mock(return_value=process))

    result = jobs.cancel(fresh_store, identifier)

    assert result["state"] == "interrupted" and result["stage"] == "worker-exited"
    assert "no successful audit result" in result["error"]
    process.send_signal.assert_not_called()


def test_parent_identity_denial_does_not_fail_an_owned_launch(fresh_store, tmp_path, monkeypatch):
    source = tmp_path / "new-source.kt"
    source.write_bytes(b"class New")
    launch = Mock(return_value=Mock(pid=42))
    monkeypatch.setattr(subprocess, "Popen", launch)
    monkeypatch.setattr(psutil, "Process", Mock(side_effect=psutil.AccessDenied(42)))

    result = jobs.start(fresh_store, {"kind": "scan", "target": str(source)})

    assert result["state"] == "queued" and result["stage"] == "queued"
    assert result["error"] == ""
    launch.assert_called_once()
    assert jobs.claim(fresh_store, result["id"], 42, 1.0)
    assert jobs.get(fresh_store, result["id"])["state"] == "running"


def test_unknown_workers_still_count_toward_the_active_cap(fresh_store, tmp_path, monkeypatch):
    running_job(fresh_store, tmp_path)
    running_job(fresh_store, tmp_path, "job-second")
    denied_worker(monkeypatch, "create_time")
    launch = Mock(side_effect=AssertionError("Active cap must prevent launch"))
    monkeypatch.setattr(subprocess, "Popen", launch)

    with pytest.raises(ValueError, match="Two audits are already active"):
        jobs.start(fresh_store, {"kind": "scan", "target": str(tmp_path / "new-third.kt")})

    assert fresh_store.db.execute("SELECT count(*) FROM jobs WHERE state='running'").fetchone()[0] == 2
    launch.assert_not_called()


def test_signal_permission_denial_keeps_cancellation_pending(fresh_store, tmp_path, monkeypatch):
    identifier = running_job(fresh_store, tmp_path)
    process = Mock()
    process.create_time.return_value = 1.0
    process.cmdline.return_value = ["python", "mobile_audit._job_worker", identifier]
    process.send_signal.side_effect = psutil.AccessDenied(42)
    monkeypatch.setattr(psutil, "Process", Mock(return_value=process))

    result = jobs.cancel(fresh_store, identifier)

    assert result["state"] == "running" and result["stage"] == "cancellation-requested"
    process.send_signal.assert_called_once_with(jobs.signal.SIGTERM)


def report(tmp_path):
    return {"id": "report-synthetic", "created": now(), "target": str(tmp_path / "new-source.kt")}


def deferred_failure(store):
    """Use SQLite's actual deferred constraint failure at COMMIT, not a failed write."""
    store.db.execute("PRAGMA foreign_keys=ON")
    store.db.executescript(
        "CREATE TABLE expected_report(id TEXT PRIMARY KEY);"
        "CREATE TABLE report_guard(id TEXT REFERENCES expected_report(id) DEFERRABLE INITIALLY DEFERRED);"
        "CREATE TRIGGER report_commit_failure AFTER INSERT ON reports BEGIN "
        "INSERT INTO report_guard VALUES(NEW.id); END;"
    )


def test_new_export_is_removed_when_the_actual_database_commit_fails(fresh_store, tmp_path):
    value = report(tmp_path)
    deferred_failure(fresh_store)

    with pytest.raises(sqlite3.IntegrityError, match="FOREIGN KEY"):
        fresh_store.save_report(value)

    assert fresh_store.db.execute("SELECT count(*) FROM reports").fetchone()[0] == 0
    assert fresh_store.db.execute("SELECT count(*) FROM report_guard").fetchone()[0] == 0
    assert list((fresh_store.home / "reports").iterdir()) == []
    assert fresh_store.verify_reports() == {"checked": 0, "failures": [], "state": "passed"}


def test_valid_existing_export_is_unchanged_on_idempotent_commit_failure(fresh_store, tmp_path, monkeypatch):
    value = report(tmp_path)
    fresh_store.save_report(value)
    exported = fresh_store.home / "reports" / f"{value['id']}.json"
    # Whitespace belongs to the existing export; canonical equivalence must not replace its inode.
    exported.write_bytes(json.dumps(value, indent=4).encode() + b"\n\n")
    original_bytes = exported.read_bytes()
    original_identity = (exported.stat().st_dev, exported.stat().st_ino)
    deferred_failure(fresh_store)
    original_write = store_module.write_json

    def write_then_defer_failure(path, body):
        original_write(path, body)
        fresh_store.db.execute("INSERT INTO report_guard VALUES('new-missing-reference')")

    monkeypatch.setattr(store_module, "write_json", write_then_defer_failure)
    with pytest.raises(sqlite3.IntegrityError, match="FOREIGN KEY"):
        fresh_store.save_report(value)

    assert fresh_store.report(value["id"]) == value
    assert exported.read_bytes() == original_bytes
    assert (exported.stat().st_dev, exported.stat().st_ino) == original_identity
    assert list(exported.parent.iterdir()) == [exported]
    assert fresh_store.verify_reports()["state"] == "passed"


@pytest.mark.parametrize("boundary", ["write", "link"])
def test_export_failure_rolls_back_database_and_cleans_staging(fresh_store, tmp_path, monkeypatch, boundary):
    def fail(*args, **kwargs):
        raise OSError(errno.ENOSPC, "synthetic export failure")

    monkeypatch.setattr(
        store_module if boundary == "write" else os, "write_json" if boundary == "write" else "link", fail
    )
    with pytest.raises(OSError, match="synthetic export failure"):
        fresh_store.save_report(report(tmp_path))

    assert fresh_store.db.execute("SELECT count(*) FROM reports").fetchone()[0] == 0
    directory = fresh_store.home / "reports"
    assert not directory.exists() or list(directory.iterdir()) == []


def test_commit_failure_does_not_delete_a_replacement_export(fresh_store, tmp_path, monkeypatch):
    value = report(tmp_path)
    exported = fresh_store.home / "reports" / f"{value['id']}.json"
    deferred_failure(fresh_store)
    original_link = os.link

    def replace_after_publish(source, destination, **kwargs):
        original_link(source, destination, **kwargs)
        exported.unlink()
        exported.write_bytes(b"new foreign replacement bytes")

    monkeypatch.setattr(os, "link", replace_after_publish)
    with pytest.raises(sqlite3.IntegrityError, match="FOREIGN KEY"):
        fresh_store.save_report(value)

    assert fresh_store.db.execute("SELECT count(*) FROM reports").fetchone()[0] == 0
    assert exported.read_bytes() == b"new foreign replacement bytes"
    assert list(exported.parent.iterdir()) == [exported]


def test_conflicting_existing_export_is_not_overwritten(fresh_store, tmp_path):
    value = report(tmp_path)
    fresh_store.save_report(value)
    exported = fresh_store.home / "reports" / f"{value['id']}.json"
    corrupted = {**value, "target": str(tmp_path / "different-synthetic-source")}
    exported.write_bytes(json.dumps(corrupted).encode())
    original_bytes = exported.read_bytes()
    original_identity = (exported.stat().st_dev, exported.stat().st_ino)

    with pytest.raises(ValueError, match="Report export conflicts"):
        fresh_store.save_report(value)

    assert fresh_store.report(value["id"]) == value
    assert exported.read_bytes() == original_bytes
    assert (exported.stat().st_dev, exported.stat().st_ino) == original_identity
    assert fresh_store.verify_reports()["state"] == "failed"


def test_successful_idempotent_save_preserves_private_export_bytes_and_inode(fresh_store, tmp_path):
    value = report(tmp_path)
    assert fresh_store.save_report(value) == value
    exported = fresh_store.home / "reports" / f"{value['id']}.json"
    original_bytes = exported.read_bytes()
    original_identity = (exported.stat().st_dev, exported.stat().st_ino)

    assert fresh_store.save_report(value) == value

    assert stat.S_IMODE(exported.stat().st_mode) == 0o600
    assert exported.read_bytes() == original_bytes
    assert (exported.stat().st_dev, exported.stat().st_ino) == original_identity
    assert list(exported.parent.iterdir()) == [exported]
    assert fresh_store.verify_reports()["state"] == "passed"
    with pytest.raises(ValueError, match="immutable"):
        fresh_store.save_report({**value, "target": "new-conflicting-target"})
    assert fresh_store.report(value["id"]) == value
