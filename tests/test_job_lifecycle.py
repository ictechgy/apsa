import json
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from mobile_audit import _job_worker, jobs
from mobile_audit.core import now


def queued(store, tmp_path, *, kind="runtime", created=None):
    jobs.initialize(store)
    payload = {
        "kind": kind,
        "target": str(tmp_path / "synthetic-target"),
        "scenario": str(tmp_path / "synthetic-scenario.json"),
        "scenario_value": {},
        "report_id": "report-original",
    }
    stamp = created or now()
    identifier = "job-synthetic"
    with store.db:
        store.db.execute(
            "INSERT INTO jobs VALUES(?,?,?,?,?,?,?, ?,NULL,NULL,NULL,'')",
            (identifier, "queued", stamp, stamp, payload["target"], json.dumps(payload), 0, "queued"),
        )
    return identifier


def row(store, identifier):
    return dict(store.db.execute("SELECT * FROM jobs WHERE id=?", (identifier,)).fetchone())


def worker_environment(monkeypatch, store, identifier):
    monkeypatch.setattr(_job_worker.sys, "argv", ["synthetic-worker", str(store.home), identifier])
    monkeypatch.setattr(_job_worker.signal, "signal", Mock())
    monkeypatch.setattr(_job_worker.psutil, "Process", lambda *args: SimpleNamespace(create_time=lambda: 1.0))


@pytest.mark.parametrize("kind", ["scan", "runtime"])
@pytest.mark.parametrize("parent_pid_assigned", [False, True])
def test_cancel_committed_after_worker_read_prevents_execution(
    store, tmp_path, monkeypatch, kind, parent_pid_assigned
):
    identifier = queued(store, tmp_path, kind=kind)
    if parent_pid_assigned:
        assert jobs.update(store, identifier, pid=11, process_started=1.0)
    worker_environment(monkeypatch, store, identifier)
    original_get = jobs.get
    first = True

    def cancelled_after_read(active_store, job_id, private=False):
        nonlocal first
        result = original_get(active_store, job_id, private=private)
        if first and private:
            first = False
            assert result["state"] == "queued"
            assert jobs.cancel(active_store, job_id)["state"] == "cancelled"
        return result

    execute = Mock(side_effect=AssertionError("Cancelled work must not execute"))
    process = Mock()
    monkeypatch.setattr(jobs, "get", cancelled_after_read)
    monkeypatch.setattr(jobs, "worker_process", lambda record: process if parent_pid_assigned else None)
    monkeypatch.setattr(_job_worker, "scan", execute)
    monkeypatch.setattr(_job_worker, "run", execute)
    _job_worker.main()
    assert row(store, identifier)["state"] == "cancelled"
    assert row(store, identifier)["report_id"] is None
    execute.assert_not_called()
    assert not jobs.update(store, identifier, pid=22, process_started=2.0)
    if parent_pid_assigned:
        process.send_signal.assert_called_once_with(jobs.signal.SIGTERM)
    else:
        process.send_signal.assert_not_called()


def test_only_one_worker_can_claim_and_terminal_cannot_be_reopened(store, tmp_path):
    identifier = queued(store, tmp_path)
    assert jobs.claim(store, identifier, 11, 1.0)
    assert not jobs.claim(store, identifier, 22, 2.0)
    assert row(store, identifier)["pid"] == 11
    assert jobs.finish(store, identifier, "failed", error="synthetic error")
    assert not jobs.claim(store, identifier, 33, 3.0)
    assert not jobs.update(store, identifier, state="running", stage="input-analysis")
    assert not jobs.finish(store, identifier, "completed", report_id="unexpected")
    assert row(store, identifier)["state"] == "failed"
    assert row(store, identifier)["error"] == "synthetic error"


def test_duplicate_worker_does_not_execute_or_finish_claimed_job(store, tmp_path, monkeypatch):
    identifier = queued(store, tmp_path)
    assert jobs.claim(store, identifier, 11, 1.0)
    worker_environment(monkeypatch, store, identifier)
    monkeypatch.setattr(jobs, "worker_process", lambda record: Mock())
    execute = Mock(side_effect=AssertionError("Duplicate worker must not execute"))
    monkeypatch.setattr(_job_worker, "run", execute)
    _job_worker.main()
    assert row(store, identifier)["state"] == "running"
    assert row(store, identifier)["pid"] == 11
    execute.assert_not_called()


@pytest.mark.parametrize("completion", ["completed", "failed"])
def test_cancellation_survives_progress_and_worker_completion(store, tmp_path, monkeypatch, completion):
    identifier = queued(store, tmp_path)
    assert jobs.claim(store, identifier, 11, 1.0)
    process = Mock()
    monkeypatch.setattr(jobs, "worker_process", lambda record: process)
    cancelled = jobs.cancel(store, identifier)
    assert cancelled["state"] == "running"
    assert cancelled["stage"] == "cancellation-requested"
    process.send_signal.assert_called_once_with(jobs.signal.SIGTERM)
    assert not jobs.update(store, identifier, stage="late-progress", progress=80)
    assert jobs.finish(store, identifier, completion, report_id="discarded", error="discarded")
    result = row(store, identifier)
    assert result["state"] == result["stage"] == "cancelled"
    assert result["report_id"] is None and result["error"] == ""
    assert result["progress"] != 100


def test_completion_committed_before_cancel_remains_completed(store, tmp_path, monkeypatch):
    identifier = queued(store, tmp_path)
    assert jobs.claim(store, identifier, 11, 1.0)
    store.save_report({"id": "report-synthetic", "created": now(), "target": str(tmp_path)})
    assert jobs.finish(store, identifier, "completed", report_id="report-synthetic")
    process = Mock()
    monkeypatch.setattr(jobs, "worker_process", lambda record: process)
    result = jobs.cancel(store, identifier)
    assert result["state"] == "completed" and result["progress"] == 100
    assert result["report_id"] == "report-synthetic"
    process.send_signal.assert_not_called()


def test_cancel_rechecks_completion_under_write_lock(store, tmp_path, monkeypatch):
    identifier = queued(store, tmp_path)
    assert jobs.claim(store, identifier, 11, 1.0)
    store.save_report({"id": "report-synthetic", "created": now(), "target": str(tmp_path)})
    process = Mock()

    def complete_during_initial_read(record):
        assert jobs.finish(store, identifier, "completed", report_id="report-synthetic")
        return process

    monkeypatch.setattr(jobs, "worker_process", complete_during_initial_read)
    result = jobs.cancel(store, identifier)
    assert result["state"] == "completed" and result["report_id"] == "report-synthetic"
    process.send_signal.assert_not_called()


@pytest.mark.parametrize("kind", ["scan", "runtime"])
def test_worker_completion_keeps_saved_report(store, tmp_path, monkeypatch, kind):
    identifier = queued(store, tmp_path, kind=kind)
    worker_environment(monkeypatch, store, identifier)

    def execute(active_store, *args, **kwargs):
        if "progress" in kwargs:
            kwargs["progress"]("synthetic-progress", 50)
        return active_store.save_report({"id": "report-synthetic", "created": now(), "target": str(tmp_path)})

    monkeypatch.setattr(_job_worker, "scan", execute)
    monkeypatch.setattr(_job_worker, "run", execute)
    _job_worker.main()
    result = row(store, identifier)
    assert result["state"] == "completed" and result["progress"] == 100
    assert result["report_id"] == "report-synthetic"


def test_worker_late_result_cannot_overwrite_requested_cancellation(store, tmp_path, monkeypatch):
    identifier = queued(store, tmp_path)
    worker_environment(monkeypatch, store, identifier)
    monkeypatch.setattr(jobs, "worker_process", lambda record: Mock())

    def execute(active_store, *args, **kwargs):
        assert jobs.cancel(active_store, identifier)["stage"] == "cancellation-requested"
        return {"id": "late-report"}

    monkeypatch.setattr(_job_worker, "run", execute)
    _job_worker.main()
    result = row(store, identifier)
    assert result["state"] == result["stage"] == "cancelled"
    assert result["report_id"] is None


def test_stale_launch_timeout_cannot_overwrite_new_worker_claim(store, tmp_path, monkeypatch):
    identifier = queued(
        store, tmp_path, created=(datetime.now(timezone.utc) - timedelta(minutes=5)).isoformat()
    )

    class ClaimDuringClockRead(datetime):
        @classmethod
        def now(cls, tz=None):
            assert jobs.claim(store, identifier, 11, 1.0)
            return datetime.now(tz)

    monkeypatch.setattr(jobs, "datetime", ClaimDuringClockRead)
    monkeypatch.setattr(jobs, "worker_process", lambda record: Mock())
    result = jobs.get(store, identifier)
    assert result["state"] == "running"
    assert result["error"] == ""


def test_worker_exit_uses_latest_cancellation_state(store, tmp_path, monkeypatch):
    identifier = queued(store, tmp_path)
    assert jobs.claim(store, identifier, 11, 1.0)

    def cancel_during_identity_check(record):
        with store.db:
            store.db.execute("UPDATE jobs SET stage='cancellation-requested' WHERE id=?", (identifier,))
        return None

    monkeypatch.setattr(jobs, "worker_process", cancel_during_identity_check)
    result = jobs.get(store, identifier)
    assert result["state"] == result["stage"] == "cancelled"
    assert result["error"] == ""
