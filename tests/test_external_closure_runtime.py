"""R5 closure controls using only fresh response files and synthetic runtime ports."""

from __future__ import annotations

import json
from typing import NoReturn, cast
from unittest.mock import Mock

import pytest

from mobile_audit import runtime
from mobile_audit.store import Store
from scripts import validate_runtime_transport as transport
from tests.test_runtime_evidence import SyntheticAdapter, SyntheticStore, scenario


def _ios_reply_target(tmp_path, monkeypatch, raw):
    target = transport.IosTarget.__new__(transport.IosTarget)
    target.device = "11111111-2222-4333-8444-555555555555"
    target.response = tmp_path / "fresh-response.json"
    target.response.write_bytes(raw)
    dispatch = Mock()
    monkeypatch.setattr(target, "dispatch", dispatch)
    monkeypatch.setattr(target, "lifecycle_observation", lambda: {"state": "synthetic-only"})
    clock = [0.0]
    sleeps = []

    def sleep(seconds):
        sleeps.append(seconds)
        clock[0] += 100

    monkeypatch.setattr(transport.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(transport.time, "sleep", sleep)
    expected = {"action": "capture", "session": "fresh-synthetic-session", "nonce": "fresh-nonce"}
    return target, expected, dispatch, sleeps


def test_ios_binding_value_error_is_not_retried_or_reclassified(tmp_path, monkeypatch):
    raw = b'{"action":"capture","session":"fresh-synthetic-session","nonce":"fresh-nonce"}'
    target, expected, dispatch, sleeps = _ios_reply_target(tmp_path, monkeypatch, raw)
    record = Mock(side_effect=ValueError("fresh binding contract mismatch"))
    monkeypatch.setattr(target, "record_delivery", record)
    with pytest.raises(ValueError, match="fresh binding contract mismatch"):
        target.deliver("synthetic://capture", expected)
    dispatch.assert_called_once_with("synthetic://capture")
    record.assert_called_once_with(expected, expected, raw=raw)
    assert sleeps == []


@pytest.mark.parametrize("malformed", [b"[", b"[]", b'{"action":"capture","action":"capture"}'])
def test_ios_malformed_reply_can_be_replaced_by_one_valid_reply(tmp_path, monkeypatch, malformed):
    target, expected, dispatch, sleeps = _ios_reply_target(tmp_path, monkeypatch, malformed)
    raw = json.dumps(expected).encode()
    record = Mock()
    monkeypatch.setattr(target, "record_delivery", record)

    def replace_reply(seconds):
        sleeps.append(seconds)
        target.response.write_bytes(raw)

    monkeypatch.setattr(transport.time, "sleep", replace_reply)
    assert target.deliver("synthetic://capture", expected) == expected
    record.assert_called_once_with(expected, expected, raw=raw)
    dispatch.assert_called_once()
    assert sleeps == [0.1]


def test_ios_fixture_binding_failure_still_propagates_without_retry(tmp_path, monkeypatch):
    target, expected, _, sleeps = _ios_reply_target(tmp_path, monkeypatch, b'{"action":"fixture-error"}')
    record = Mock()
    monkeypatch.setattr(target, "record_delivery", record)
    with pytest.raises(transport.FixtureFailure, match="fixture rejected binding"):
        target.deliver("synthetic://capture", expected)
    record.assert_not_called()
    assert sleeps == []


def _runtime_store(tmp_path, monkeypatch):
    home = SyntheticStore(tmp_path / "new-runtime-home")
    home.previous["coverage"].append({"rule_id": "RUNTIME-DEEPLINK", "state": "not-run"})
    monkeypatch.setenv("APSA_DEVICE_LOCK_DIR", str(tmp_path / "new-locks"))
    monkeypatch.setattr(runtime, "correlate", lambda *args: ([], []))
    monkeypatch.setattr(runtime, "source_health", lambda *args: {})
    monkeypatch.setattr(runtime, "summarize", lambda *args: {})
    return home


def _run(home, tmp_path, value, adapter):
    # The double provides only the report/home/save ports consumed here, and
    # correlation is replaced above; no persistent database or device is opened.
    return runtime.run(cast(Store, home), tmp_path / "unused.json", scenario=value, adapter=adapter)


@pytest.mark.parametrize("platform", ["android", "ios"])
def test_non_url_transition_does_not_claim_a_url_request(tmp_path, monkeypatch, platform):
    value = scenario(platform)
    value["steps"][1] = {"action": "tap", "x": 1, "y": 2} if platform == "android" else {"action": "launch"}

    class Target(SyntheticAdapter):
        def tap(self, x, y):
            assert (x, y) == (1, 2)
            self.after = True

        def launch(self):
            self.after = True

    home = _runtime_store(tmp_path, monkeypatch)
    result = _run(home, tmp_path, value, Target(value))
    record = result["runtime"][-1]
    assert record["workflow"][0]["state"] == "passed"
    assert record["transition_verification"] == "marker-observed"
    assert record["delivery_verification"] == "not-requested"
    assert record["delivery_evidence"] == []
    assert next(c for c in result["coverage"] if c["rule_id"] == "RUNTIME-DEEPLINK")["state"] == "not-run"
    assert json.loads(json.dumps(result))["runtime"][-1]["delivery_verification"] == "not-requested"


@pytest.mark.parametrize("failure", ["open_url", "before-open-url"])
def test_uncompleted_url_request_retains_the_step_error_without_claiming_delivery(
    tmp_path, monkeypatch, failure
):
    value = scenario()
    if failure == "before-open-url":
        value["steps"].insert(1, {"action": "tap", "x": 1, "y": 2})
    calls = []

    class Target(SyntheticAdapter):
        def tap(self, x, y):
            calls.append("tap")
            raise ValueError("fresh failure before dispatch")

        def open_url(self, url):
            calls.append("open_url")
            raise ValueError("fresh dispatch failure")

    result = _run(_runtime_store(tmp_path, monkeypatch), tmp_path, value, Target(value))
    record = result["runtime"][-1]
    assert calls == (["tap"] if failure == "before-open-url" else ["open_url"])
    assert record["steps"][-1]["state"] == "error"
    assert record["partial"] is True
    assert record["delivery_verification"] == "not-requested"
    assert record["delivery_evidence"] == []
    assert next(c for c in result["coverage"] if c["rule_id"] == "RUNTIME-DEEPLINK")["state"] == "not-run"


@pytest.mark.parametrize(
    "missing,expected", [(None, "marker-observed"), ("delivery", "requested-not-confirmed")]
)
def test_completed_url_dispatch_retains_observed_or_unconfirmed_state(
    tmp_path, monkeypatch, missing, expected
):
    value = scenario()
    result = _run(
        _runtime_store(tmp_path, monkeypatch), tmp_path, value, SyntheticAdapter(value, missing=missing)
    )
    record = result["runtime"][-1]
    assert record["steps"][1]["action"] == "open_url"
    assert record["steps"][1]["state"] == "completed"
    assert record["steps"][1]["delivery"] == "requested-not-confirmed"
    assert record["delivery_verification"] == expected
    assert bool(record["delivery_evidence"]) is (missing is None)
    assert next(c for c in result["coverage"] if c["rule_id"] == "RUNTIME-DEEPLINK")["state"] == (
        "checked" if missing is None else "observed"
    )


@pytest.mark.parametrize("action", ["tap", "open_url"])
def test_cancelled_action_cannot_commit_a_delivery_observation(tmp_path, monkeypatch, action):
    value = scenario()
    if action == "tap":
        value["steps"].insert(1, {"action": "tap", "x": 1, "y": 2})
    home = _runtime_store(tmp_path, monkeypatch)
    created = []
    saved = []
    original_save = home.save_report

    def save_report(report):
        saved.append(report["id"])
        return original_save(report)

    monkeypatch.setattr(home, "save_report", save_report)

    def cancel() -> NoReturn:
        directories = list((home.home / "artifacts").iterdir())
        assert len(directories) == 1 and directories[0].is_dir()
        created.extend(directories)
        raise KeyboardInterrupt("fresh synthetic cancellation")

    class Target(SyntheticAdapter):
        def tap(self, x, y) -> NoReturn:
            cancel()

        def open_url(self, url) -> NoReturn:
            cancel()

    with pytest.raises(KeyboardInterrupt, match="fresh synthetic cancellation"):
        _run(home, tmp_path, value, Target(value))
    assert saved == []
    assert home.previous["id"] == "before"
    assert home.previous["runtime"] == []
    assert len(created) == 1 and not created[0].exists()
    assert not list((home.home / "artifacts").iterdir())
