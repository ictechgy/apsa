"""External-review runtime controls; fresh synthetic stores and adapters only."""

from __future__ import annotations

import json
from types import SimpleNamespace
from typing import cast
from unittest.mock import Mock

import pytest

from mobile_audit import _job_worker, jobs, runtime
from mobile_audit.core import now
from mobile_audit.store import Store
from tests.test_runtime_cancellation import execution as execution
from tests.test_runtime_evidence import SyntheticAdapter, SyntheticStore, scenario


def _android(monkeypatch, *, pid="123", logs=b"empty logs"):
    device = runtime.Android.__new__(runtime.Android)
    device.package = "com.synthetic.app"
    device.prefix = ["synthetic-adb", "-s", "fresh-synthetic-device"]
    commands = []

    def shell(args, **kwargs):
        commands.append((args, kwargs))
        if args[0] == "pidof":
            return pid.encode()
        if args[0] == "logcat":
            return logs
        raise AssertionError(args)

    monkeypatch.setattr(device, "shell", shell)
    monkeypatch.setattr(device, "storage", lambda: [])
    monkeypatch.setattr(device, "ui", lambda: b"empty UI")
    return device, commands


@pytest.mark.parametrize("lines", [1, 2999, 3000])
def test_android_single_pid_tail_cannot_prove_log_absence(monkeypatch, lines):
    device, commands = _android(monkeypatch, logs=b"line\n" * lines)
    after = runtime.snapshot(device, {"account": "fresh-synthetic-canary"})
    before = {
        "surfaces": {"logs": {"state": "captured"}},
        "matches": [{"surface": "logs", "marker_label": "account"}],
    }
    value = {
        "assertions": [{"baseline": "before", "snapshot": "after", "marker": "account", "surface": "logs"}]
    }
    result = runtime.evaluate_assertions(value, {"before": before, "after": after})
    assert after["surfaces"]["logs"]["state"] == "inconclusive"
    assert result[0]["state"] == "inconclusive"
    assert commands[-1][0] == ["logcat", "-d", "--pid", "123", "-t", "3000"]


def test_android_restarted_pid_does_not_clear_log_residual(monkeypatch):
    device, _ = _android(monkeypatch, pid="123", logs=b"fresh-synthetic-canary")
    before = runtime.snapshot(device, {"account": "fresh-synthetic-canary"})
    device2, _ = _android(monkeypatch, pid="456", logs=b"empty logs")
    after = runtime.snapshot(device2, {"account": "fresh-synthetic-canary"})
    value = {
        "assertions": [{"baseline": "before", "snapshot": "after", "marker": "account", "surface": "logs"}]
    }
    assert (
        runtime.evaluate_assertions(value, {"before": before, "after": after})[0]["state"] == "inconclusive"
    )
    assert before["surfaces"]["logs"]["pid"] != after["surfaces"]["logs"]["pid"]


def test_partial_logs_retain_observed_positive_residual(monkeypatch):
    device, _ = _android(monkeypatch, logs=b"fresh-synthetic-canary")
    before = runtime.snapshot(device, {"account": "fresh-synthetic-canary"})
    after = runtime.snapshot(device, {"account": "fresh-synthetic-canary"})
    value = {
        "assertions": [{"baseline": "before", "snapshot": "after", "marker": "account", "surface": "logs"}]
    }
    assert runtime.evaluate_assertions(value, {"before": before, "after": after})[0]["state"] == "failed"


@pytest.mark.parametrize(
    "actions,expected",
    [
        (["open_url"], True),
        (["open_url", "tap"], False),
        (["tap", "open_url"], False),
        (["open_url", "open_url"], False),
        (["tap"], False),
        ([], False),
    ],
)
def test_delivery_marker_bound_to_only_intervening_dispatch(actions, expected):
    steps = [{"action": "snapshot", "label": "before"}]
    steps += [{"action": action} for action in actions]
    steps += [{"action": "snapshot", "label": "after"}]
    transcript = [{"step": i, "action": step["action"], "state": "completed"} for i, step in enumerate(steps)]
    assertions = [
        {"state": "passed", "assertion": {"baseline": "before", "snapshot": "after", "purpose": "delivery"}}
    ]
    evidence = runtime.deeplink_delivery_evidence({"steps": steps}, {}, [], assertions, transcript)
    assert bool(evidence) is expected


def test_acquired_delivery_requires_target_observed():
    steps = [
        {"action": "snapshot", "label": "before"},
        {"action": "open_url"},
        {"action": "snapshot", "label": "after"},
    ]
    transcript = [{"step": 1, "action": "open_url", "state": "completed"}]
    assertions = [
        {"state": "passed", "assertion": {"baseline": "before", "snapshot": "after", "purpose": "delivery"}}
    ]
    assert (
        runtime.deeplink_delivery_evidence(
            {"steps": steps},
            {"after": {"acquisition": {"delivery": "unconfirmed"}}},
            [],
            assertions,
            transcript,
            acquired=True,
        )
        == []
    )
    assert runtime.deeplink_delivery_evidence(
        {"steps": steps},
        {"after": {"acquisition": {"delivery": "target-observed"}}},
        [],
        assertions,
        transcript,
        acquired=True,
    )


@pytest.mark.parametrize("platform", ["android", "ios"])
def test_passing_workflow_with_unrelated_earlier_url_cannot_check_deeplink(tmp_path, monkeypatch, platform):
    value = scenario(platform)
    value["steps"] = [
        {"action": "open_url", "url": "synthetic://unrelated"},
        {"action": "snapshot", "label": "before"},
        {"action": "wait", "seconds": 0},
        {"action": "snapshot", "label": "after"},
    ]

    class Target(SyntheticAdapter):
        def open_url(self, url):
            assert url == "synthetic://unrelated"
            return {"delivery": "requested-not-confirmed"}

        def storage(self):
            self.after = self.storage_calls > 0
            return super().storage()

    home = SyntheticStore(tmp_path / "new-runtime-home")
    home.previous["coverage"].append({"rule_id": "RUNTIME-DEEPLINK", "state": "not-run"})
    monkeypatch.setenv("APSA_DEVICE_LOCK_DIR", str(tmp_path / "new-locks"))
    monkeypatch.setattr(runtime, "correlate", lambda *args: ([], []))
    monkeypatch.setattr(runtime, "source_health", lambda *args: {})
    monkeypatch.setattr(runtime, "summarize", lambda *args: {})
    # SyntheticStore implements the Store report/home/save ports consumed here;
    # intelligence access is explicitly replaced above, with no real DB opened.
    result = runtime.run(cast(Store, home), tmp_path / "unused.json", scenario=value, adapter=Target(value))
    assert result["runtime"][-1]["workflow"][0]["state"] == "passed"
    assert result["runtime"][-1]["delivery_verification"] == "requested-not-confirmed"
    assert next(c for c in result["coverage"] if c["rule_id"] == "RUNTIME-DEEPLINK")["state"] == "observed"


def test_android_storage_explicit_command_budget(monkeypatch):
    device, _ = _android(monkeypatch)
    seen = []

    def command(args, **kwargs):
        seen.append(kwargs)
        raise ValueError("Command output exceeds size limit; capture incomplete")

    monkeypatch.setattr(runtime, "command", command)
    captured = runtime.snapshot(device, {"account": "fresh-synthetic-canary"})
    assert captured["surfaces"]["storage"]["state"] == "captured"  # Synthetic storage remains isolated.
    with pytest.raises(ValueError, match="size limit"):
        runtime.Android.storage(device)
    assert seen == [{"max_bytes": runtime.MAX_CAPTURE}]


@pytest.mark.parametrize("device", [1, True, [], {}, "", "bad\nserial", "x" * 201, "-option"])
def test_device_selector_rejected_before_discovery(device):
    value = scenario()
    value["device"] = device
    with pytest.raises(ValueError, match="device"):
        runtime.validate_scenario(value)


@pytest.mark.parametrize(
    "device", [None, "emulator-5554", "127.0.0.1:5555", "01234567-ABCD-ABCD-ABCD-0123456789AB"]
)
def test_device_selector_existing_valid_forms_preserved(device):
    value = scenario()
    value["device"] = device
    assert runtime.validate_scenario(value)["device"] == device


def test_android_screenshot_refuses_foreign_foreground(tmp_path, monkeypatch):
    device, _ = _android(monkeypatch)
    monkeypatch.setattr(
        device, "require_foreground", lambda: (_ for _ in ()).throw(ValueError("foreign foreground"))
    )
    capture = Mock(side_effect=AssertionError("Must not capture another app"))
    monkeypatch.setattr(runtime, "command", capture)
    with pytest.raises(ValueError, match="foreign foreground"):
        device.screenshot(tmp_path / "never-created.png")
    capture.assert_not_called()


def test_split_apks_cannot_establish_complete_build_binding(monkeypatch):
    device, _ = _android(monkeypatch)

    def shell(args, **kwargs):
        if args[0] == "dumpsys":
            return b"Package [com.synthetic.app] versionCode=1 versionName=1"
        if args[:2] == ["pm", "path"]:
            return b"package:/data/app/fresh/base.apk\npackage:/data/app/fresh/split_feature.apk\n"
        if args[0] == "sha256sum":
            return ("1" * 64 + " base.apk").encode()
        return b""

    monkeypatch.setattr(device, "shell", shell)
    environment = device.environment()
    assert environment["app"]["installed_split_count"] == 1
    assert environment["app"]["base_apk_sha256"] == "1" * 64
    assert "apk_sha256" not in environment["app"]
    assert runtime.build_binding("android", device.package, environment["app"])["state"] == "unavailable"


def test_cancel_during_committed_save_keeps_actual_report_and_completion(store, tmp_path, monkeypatch):
    jobs.initialize(store)
    identifier = "job-fresh-save-race"
    payload = {
        "kind": "runtime",
        "target": str(tmp_path / "owned-source"),
        "scenario": str(tmp_path / "unused.json"),
        "scenario_value": {},
        "report_id": "original",
    }
    stamp = now()
    with store.db:
        store.db.execute(
            "INSERT INTO jobs VALUES(?,?,?,?,?,?,?, ?,NULL,NULL,NULL,'')",
            (identifier, "queued", stamp, stamp, payload["target"], json.dumps(payload), 0, "queued"),
        )
    monkeypatch.setattr(_job_worker.sys, "argv", ["synthetic-worker", str(store.home), identifier])
    monkeypatch.setattr(_job_worker.signal, "signal", Mock())
    monkeypatch.setattr(_job_worker.psutil, "Process", lambda *args: SimpleNamespace(create_time=lambda: 1.0))
    monkeypatch.setattr(jobs, "worker_process", lambda row: jobs.WorkerInspection.UNINSPECTABLE)
    original = _job_worker.Store

    def worker_store(path):
        opened = original(path)
        save = opened.save_report

        def cancellation_after_commit(report):
            result = save(report)
            assert jobs.cancel(opened, identifier)["stage"] == "cancellation-requested"
            return result

        opened.save_report = cancellation_after_commit
        return opened

    monkeypatch.setattr(_job_worker, "Store", worker_store)

    def execute(active_store, *args, **kwargs):
        return active_store.save_report(
            {"id": "fresh-committed-runtime", "created": now(), "target": payload["target"]}
        )

    monkeypatch.setattr(_job_worker, "run", execute)
    _job_worker.main()
    result = dict(store.db.execute("SELECT * FROM jobs WHERE id=?", (identifier,)).fetchone())
    assert result["state"] == result["stage"] == "completed"
    assert result["report_id"] == "fresh-committed-runtime"
    assert store.report("latest")["id"] == result["report_id"]


def test_cancelled_runtime_removes_only_its_fresh_artifacts(execution):
    execution.scenario["steps"] = [{"action": "snapshot", "label": "after"}, {"action": "launch"}]
    execution.device.on_call = lambda action: execution.cancel() if action == "screenshot" else None
    execution.assert_cancelled(execution.run_worker(screenshots=True))
    root = execution.store.home / "artifacts"
    assert root.is_dir()
    assert list(root.iterdir()) == []


def test_executed_inconclusive_residual_is_partial(tmp_path, monkeypatch):
    value = scenario()
    home = SyntheticStore(tmp_path / "new-runtime-home")
    monkeypatch.setenv("APSA_DEVICE_LOCK_DIR", str(tmp_path / "new-locks"))
    monkeypatch.setattr(runtime, "correlate", lambda *args: ([], []))
    monkeypatch.setattr(runtime, "source_health", lambda *args: {})
    monkeypatch.setattr(runtime, "summarize", lambda *args: {})
    result = runtime.run(
        cast(Store, home),
        tmp_path / "unused.json",
        scenario=value,
        adapter=SyntheticAdapter(value, missing="state"),
    )
    assert result["runtime"][-1]["assertions"]
    assert result["runtime"][-1]["partial"] is True
    assert next(c for c in result["coverage"] if c["rule_id"] == "RUNTIME-RESIDUAL")["state"] == "partial"
