import time

import psutil

from mobile_audit import jobs


def terminal(store, identifier):
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        result = jobs.get(store, identifier)
        if result["state"] in jobs.TERMINAL:
            return result
        time.sleep(0.05)
    raise AssertionError("Job did not terminate")


def test_background_scan_persists_progress_and_report(store, demo):
    queued = jobs.start(store, {"kind": "scan", "target": str(demo)})
    result = terminal(store, queued["id"])
    assert result["state"] == "completed"
    assert result["progress"] == 100
    assert store.report(result["report_id"])["inventory"]["fingerprint"]
    assert "payload" not in result and "pid" not in result
    assert jobs.cancel(store, queued["id"])["state"] == "completed"


def test_queued_scan_refuses_replaced_canonical_target_and_keeps_request_provenance(
    store, demo, tmp_path, monkeypatch
):
    requested = tmp_path / "requested-alias"
    requested.symlink_to(demo, target_is_directory=True)
    intended = str(demo.resolve())
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "Other.java").write_text("class Other {}")
    original = jobs.subprocess.Popen

    def replaced(*args, **options):
        demo.rename(tmp_path / "intended-source")
        demo.symlink_to(outside, target_is_directory=True)
        return original(*args, **options)

    monkeypatch.setattr(jobs.subprocess, "Popen", replaced)
    queued = jobs.start(store, {"kind": "scan", "target": str(requested)})
    result = terminal(store, queued["id"])
    assert result["state"] == "failed" and not result["report_id"]
    assert "Authorized input moved" in result["error"]
    assert result["target"] == intended and result["requested_target"] == str(requested)
    assert store.reports() == []


def test_failed_background_scan_is_never_a_pass(store, tmp_path):
    queued = jobs.start(store, {"kind": "scan", "target": str(tmp_path / "missing")})
    result = terminal(store, queued["id"])
    assert result["state"] == "failed"
    assert result["report_id"] is None
    assert "Input not found" in result["error"]


def test_queued_job_cancellation_reaches_terminal_state(store, demo):
    queued = jobs.start(store, {"kind": "scan", "target": str(demo)})
    jobs.cancel(store, queued["id"])
    result = terminal(store, queued["id"])
    assert result["state"] == "cancelled"
    assert not result["report_id"]


def test_pid_reuse_cannot_cancel_an_unrelated_process_and_roots_filter(store, demo, tmp_path):
    queued = jobs.start(store, {"kind": "scan", "target": str(demo)})
    terminal(store, queued["id"])
    own = psutil.Process()
    jobs.update(
        store, queued["id"], state="running", pid=own.pid, process_started=own.create_time(), report_id=None
    )
    result = jobs.cancel(store, queued["id"])
    assert result["state"] == "interrupted"
    assert own.is_running()
    assert jobs.listing(store, roots=[demo])[0]["id"] == queued["id"]
    assert jobs.listing(store, roots=[tmp_path / "other"]) == []
