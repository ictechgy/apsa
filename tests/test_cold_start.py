"""Cold resolver failure evidence, fresh caches and bounded retries; all mocked."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from scripts import verify_cold_start as cold


def runner(monkeypatch, outputs):
    calls, sleeps = [], []

    def run(argv, *, env, **kwargs):
        cache = Path(env["UV_CACHE_DIR"])
        assert not cache.exists()
        cache.mkdir()
        calls.append({"argv": argv, "cache": cache, "home": env["APSA_HOME"]})
        item = outputs[min(len(calls) - 1, len(outputs) - 1)]
        if isinstance(item, BaseException):
            raise item
        return subprocess.CompletedProcess(argv, item[0], item[1], item[2])

    monkeypatch.setattr(cold.subprocess, "run", run)
    monkeypatch.setattr(cold.time, "sleep", sleeps.append)
    return calls, sleeps


def test_index_lag_then_success_retains_each_failure_and_uses_new_cache(monkeypatch, tmp_path):
    calls, sleeps = runner(monkeypatch, [(1, b"", b"synthetic index not ready"), (0, b"1.6.0\n", b"")])
    output = tmp_path / "new-evidence"
    report = cold.verify("1.6.0", output)
    assert report["passed"] and len(calls) == 2 and calls[0]["cache"] != calls[1]["cache"]
    assert len({row["home"] for row in calls}) == 2 and sleeps == [30]
    assert (output / "attempt-01/stderr").read_bytes() == b"synthetic index not ready"
    assert json.loads((output / "result.json").read_text()) == report


def test_successful_exit_with_wrong_version_fails_without_retry(monkeypatch, tmp_path):
    calls, sleeps = runner(monkeypatch, [(0, b"1.5.1\n", b"")])
    report = cold.verify("1.6.0", tmp_path / "new-evidence")
    assert not report["passed"] and len(calls) == 1 and not sleeps
    assert report["attempts"][0]["outcome"] == "version-mismatch"


def test_timeout_and_exhaustion_remain_failed_with_bounded_attempts(monkeypatch, tmp_path):
    timeout = subprocess.TimeoutExpired(
        ["uvx"], 90, output=b"partial synthetic output", stderr=b"synthetic timeout"
    )
    calls, sleeps = runner(monkeypatch, [timeout, (1, b"", b"still unavailable")])
    report = cold.verify("1.6.0", tmp_path / "new-evidence", attempts=3)
    assert not report["passed"] and len(calls) == 3 and sleeps == [30, 30]
    assert report["attempts"][0]["timed_out"] is True


def test_existing_evidence_and_invalid_identity_never_start_resolver(monkeypatch, tmp_path):
    calls, _ = runner(monkeypatch, [(0, b"1.6.0", b"")])
    with pytest.raises(ValueError):
        cold.verify("1.6.0; invalid", tmp_path / "new")
    with pytest.raises(FileExistsError):
        cold.verify("1.6.0", tmp_path)
    assert not calls
