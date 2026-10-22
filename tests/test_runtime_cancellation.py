"""Real worker/runtime/job transitions using only newly created synthetic data."""

import json
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from mobile_audit import _job_worker, jobs, runtime
from mobile_audit.core import now


class SyntheticDevice:
    device = "new-synthetic-cancellation-device"

    def __init__(self):
        self.calls = []
        self.on_call = lambda action: None

    def record(self, action):
        self.calls.append(action)
        self.on_call(action)

    def environment(self):
        self.record("environment")
        return {
            "platform": "android",
            "app": {"package": "com.synthetic.cancel", "apk_sha256": "1" * 64},
        }

    def launch(self):
        self.record("launch")

    def open_url(self, url):
        self.record("open_url")

    def tap(self, x, y):
        self.record("tap")

    def input_text(self, text):
        self.record("input_text")

    def storage(self):
        self.record("storage")
        return [("fresh-synthetic.txt", b"synthetic empty storage")]

    def ui(self):
        self.record("ui")
        return b"synthetic empty UI"

    def logs(self):
        self.record("logs")
        return b"synthetic empty logs"

    def screenshot(self, path):
        self.record("screenshot")
        path.write_bytes(b"\x89PNG synthetic image")


@pytest.fixture
def execution(store, tmp_path, monkeypatch):
    original = store.save_report(
        {
            "id": "report-before-runtime",
            "created": now(),
            "target": str(tmp_path / "new-synthetic-source"),
            "inventory": {
                "platforms": ["android"],
                "package": "com.synthetic.cancel",
                "apps": [{"platform": "android", "package": "com.synthetic.cancel"}],
                "input_kind": "source",
                "fingerprint": "fresh-synthetic-source",
                "dependencies": [],
            },
            "findings": [],
            "coverage": [],
            "runtime": [],
        }
    )
    value = {
        "platform": "android",
        "package": "com.synthetic.cancel",
        "precondition": "Fresh synthetic adapter; no live device is used",
        "markers": {"account": "new-synthetic-account-canary"},
        "steps": [{"action": "launch"}, {"action": "snapshot", "label": "after"}],
        "assertions": [],
    }
    identifier = "job-new-synthetic-runtime"
    device = SyntheticDevice()
    monkeypatch.setenv("APSA_DEVICE_LOCK_DIR", str(tmp_path / "new-locks"))
    monkeypatch.setattr(runtime, "Android", lambda package, serial: device)
    monkeypatch.setattr(_job_worker.sys, "argv", ["synthetic-worker", str(store.home), identifier])
    monkeypatch.setattr(_job_worker.signal, "signal", Mock())
    monkeypatch.setattr(_job_worker.psutil, "Process", lambda: SimpleNamespace(create_time=lambda: 1.0))
    # This is the production fallback when process inspection is denied: no
    # physical signal can be sent, so the worker must observe the database CAS.
    monkeypatch.setattr(jobs, "worker_process", lambda row: jobs.WorkerInspection.UNINSPECTABLE)

    def cancel():
        result = jobs.cancel(store, identifier)
        assert result["state"] == "running"
        assert result["stage"] == "cancellation-requested"

    def run_worker(*, screenshots=False):
        jobs.initialize(store)
        payload = {
            "kind": "runtime",
            "target": original["target"],
            "scenario": str(tmp_path / "unused-synthetic-scenario.json"),
            "scenario_value": value,
            "report_id": original["id"],
            "screenshots": screenshots,
        }
        stamp = now()
        with store.db:
            store.db.execute(
                "INSERT INTO jobs VALUES(?,?,?,?,?,?,?, ?,NULL,NULL,NULL,'')",
                (identifier, "queued", stamp, stamp, payload["target"], json.dumps(payload), 0, "queued"),
            )
        _job_worker.main()
        return jobs.get(store, identifier)

    def assert_cancelled(result):
        assert result["state"] == result["stage"] == "cancelled"
        assert result["report_id"] is None
        assert result["error"] == ""
        assert result["progress"] < 100
        assert [report["id"] for report in store.reports()] == [original["id"]]
        assert store.report("latest") == original
        # Cooperative and signal cancellation both release the device lease.
        with runtime.device_lease("android", device.device):
            pass

    return SimpleNamespace(
        store=store,
        original=original,
        scenario=value,
        device=device,
        cancel=cancel,
        run_worker=run_worker,
        assert_cancelled=assert_cancelled,
    )


def test_cancel_during_environment_prevents_first_action(execution):
    execution.device.on_call = lambda action: execution.cancel()
    execution.assert_cancelled(execution.run_worker())
    assert execution.device.calls == ["environment"]


@pytest.mark.parametrize(
    "step",
    [
        {"action": "launch"},
        {"action": "open_url", "url": "synthetic://cancel"},
        {"action": "tap", "x": 1, "y": 2},
        {"action": "input_text", "text": "synthetic test input"},
    ],
)
def test_cancel_during_device_action_prevents_later_actions_and_capture(execution, step):
    execution.scenario["steps"] = [step, {"action": "snapshot", "label": "after"}, {"action": "launch"}]
    execution.device.on_call = lambda action: execution.cancel() if action == step["action"] else None
    execution.assert_cancelled(execution.run_worker(screenshots=True))
    assert execution.device.calls == ["environment", step["action"]]


def test_cancel_during_wait_is_polled_without_waiting_for_full_step(execution, monkeypatch):
    execution.scenario["steps"] = [{"action": "wait", "seconds": 10}, {"action": "launch"}]
    clock = [0.0]
    sleeps = []

    def sleep(seconds):
        sleeps.append(seconds)
        clock[0] += seconds
        execution.cancel()

    monkeypatch.setattr(runtime.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(runtime.time, "sleep", sleep)
    execution.assert_cancelled(execution.run_worker())
    assert sleeps == [0.1]
    assert execution.device.calls == ["environment"]


@pytest.mark.parametrize("surface", ["storage", "ui", "logs"])
def test_cancel_during_capture_prevents_other_surfaces_and_screenshot(execution, surface):
    execution.scenario["steps"] = [{"action": "snapshot", "label": "after"}, {"action": "launch"}]
    execution.device.on_call = lambda action: execution.cancel() if action == surface else None
    execution.assert_cancelled(execution.run_worker(screenshots=True))
    expected = ["environment", "storage", "ui", "logs"]
    assert execution.device.calls == expected[: expected.index(surface) + 1]


def test_cancel_during_screenshot_prevents_later_action_and_report(execution):
    execution.scenario["steps"] = [{"action": "snapshot", "label": "after"}, {"action": "launch"}]
    execution.device.on_call = lambda action: execution.cancel() if action == "screenshot" else None
    execution.assert_cancelled(execution.run_worker(screenshots=True))
    assert execution.device.calls == ["environment", "storage", "ui", "logs", "screenshot"]


def test_cancel_after_analysis_prevents_report_persistence(execution, monkeypatch):
    summarize = runtime.summarize

    def cancel_after_summary(report):
        result = summarize(report)
        execution.cancel()
        return result

    monkeypatch.setattr(runtime, "summarize", cancel_after_summary)
    execution.assert_cancelled(execution.run_worker())
    assert execution.device.calls == ["environment", "launch", "storage", "ui", "logs"]


def test_signal_interruption_still_cancels_and_releases_device(execution):
    execution.device.on_call = lambda action: (
        _job_worker.interrupted(None, None) if action == "launch" else None
    )
    execution.assert_cancelled(execution.run_worker())
    assert execution.device.calls == ["environment", "launch"]


def test_uncancelled_worker_finishes_and_persists_runtime_report(execution):
    result = execution.run_worker(screenshots=True)
    assert result["state"] == "completed" and result["progress"] == 100
    saved = execution.store.report(result["report_id"])
    assert saved["parent_report"] == execution.original["id"]
    assert len(saved["runtime"]) == 1
    assert all(step["state"] == "completed" for step in saved["runtime"][0]["steps"])
    assert execution.device.calls == ["environment", "launch", "storage", "ui", "logs", "screenshot"]
    assert len(execution.store.reports()) == 2


def test_direct_run_without_progress_callback_remains_compatible(execution, tmp_path):
    result = runtime.run(
        execution.store,
        tmp_path / "unused-synthetic-scenario.json",
        execution.original["id"],
        adapter=execution.device,
        scenario=execution.scenario,
    )
    assert execution.store.report(result["id"]) == result
    assert execution.device.calls == ["environment", "launch", "storage", "ui", "logs"]
