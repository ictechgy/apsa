"""Parent parser boundary rejects malformed output without running a worker."""

import copy
import json
import subprocess
from contextlib import nullcontext

import pytest

from mobile_audit import engine, parser_sandbox
from mobile_audit.store import Store


@pytest.fixture(autouse=True)
def no_external_execution(monkeypatch):
    def refused(*args, **kwargs):
        raise AssertionError("This boundary test must not execute processes or open a report store")

    for name in ("run", "Popen", "call", "check_call", "check_output"):
        monkeypatch.setattr(subprocess, name, refused)
    monkeypatch.setattr(Store, "__init__", refused)
    monkeypatch.setattr(engine, "command", refused)
    monkeypatch.setattr(parser_sandbox, "sandbox_command", refused)
    monkeypatch.setattr(parser_sandbox, "activate", refused)


@pytest.fixture
def worker_boundary(tmp_path, monkeypatch):
    source = tmp_path / "new-source"
    source.mkdir()
    (source / "New.java").write_text("class New {}")
    isolation = {"state": "unit-boundary-only"}
    response = {
        "inventory": {"warnings": []},
        "findings": [],
        "coverage": [{"state": "checked"}],
    }
    monkeypatch.setattr(engine, "parser_lease", lambda: nullcontext())
    monkeypatch.setattr(engine, "command", lambda *args, **kwargs: json.dumps(response))
    monkeypatch.setattr(parser_sandbox, "sandbox_command", lambda args, *a, **k: (args, isolation))
    monkeypatch.setattr(parser_sandbox, "activate", lambda wrapped, args, state, scratch: (wrapped, state))
    return source, response, isolation


@pytest.mark.parametrize("response", [None, [], "malformed"])
def test_non_object_worker_output_is_a_controlled_failure(worker_boundary, monkeypatch, response):
    source, _, _ = worker_boundary
    monkeypatch.setattr(engine, "command", lambda *a, **k: json.dumps(response))
    with pytest.raises(ValueError, match="invalid schema; audit incomplete"):
        engine.analyze_target(source)


@pytest.mark.parametrize("warnings", [None, "malformed", {}, ["valid", {}]])
def test_malformed_worker_warnings_are_a_controlled_failure(worker_boundary, warnings):
    source, response, isolation = worker_boundary
    response["inventory"]["warnings"] = warnings
    isolation.update(activation_probe="failed", unavailable_reason="synthetic failure")
    with pytest.raises(ValueError, match="invalid schema; audit incomplete"):
        engine.analyze_target(source)


def test_missing_worker_warnings_are_a_controlled_failure(worker_boundary):
    source, response, isolation = worker_boundary
    del response["inventory"]["warnings"]
    isolation.update(activation_probe="failed", unavailable_reason="synthetic failure")
    with pytest.raises(ValueError, match="invalid schema; audit incomplete"):
        engine.analyze_target(source)


@pytest.mark.parametrize("coverage", [None, "malformed", {}, [None], [{}], [{"state": []}]])
def test_malformed_worker_coverage_is_a_controlled_failure(worker_boundary, coverage):
    source, response, _ = worker_boundary
    response["coverage"] = coverage
    with pytest.raises(ValueError, match="invalid schema; audit incomplete"):
        engine.analyze_target(source)


def test_missing_worker_coverage_is_a_controlled_failure(worker_boundary):
    source, response, _ = worker_boundary
    del response["coverage"]
    with pytest.raises(ValueError, match="invalid schema; audit incomplete"):
        engine.analyze_target(source)


def test_valid_worker_output_preserves_checks_and_adds_isolation_warning(worker_boundary):
    source, response, isolation = worker_boundary
    original = copy.deepcopy(response)
    isolation.update(activation_probe="failed", unavailable_reason="synthetic failure")
    result = engine.analyze_target(source)
    assert result["coverage"] == original["coverage"]
    assert result["inventory"]["warnings"] == [
        "Parser OS isolation unavailable; parsed with resource limits only: synthetic failure"
    ]
    assert result["inventory"]["input_snapshot"]["partial"] is False


def test_staging_warning_downgrades_valid_worker_coverage(worker_boundary, monkeypatch):
    source, _, _ = worker_boundary
    stage_input = engine.stage_input

    def partial_snapshot(*args, **kwargs):
        snapshot = stage_input(*args, **kwargs)
        snapshot["warnings"] = ["Synthetic staging omission"]
        return snapshot

    monkeypatch.setattr(engine, "stage_input", partial_snapshot)
    result = engine.analyze_target(source)
    assert result["inventory"]["warnings"] == ["Synthetic staging omission"]
    assert result["inventory"]["partial"] is True
    assert result["inventory"]["fingerprint_complete"] is False
    assert result["coverage"] == [{"state": "partial"}]


@pytest.mark.parametrize("error", [PermissionError("synthetic denial"), OSError("synthetic failure")])
def test_parser_lease_closes_candidate_when_flock_fails(tmp_path, monkeypatch, error):
    import fcntl

    closed = []
    monkeypatch.setattr(engine.os, "open", lambda *a, **k: 101)
    monkeypatch.setattr(engine.os, "close", closed.append)

    def fail(*args):
        raise error

    monkeypatch.setattr(fcntl, "flock", fail)
    with pytest.raises(type(error), match="synthetic"):
        with engine.parser_lease(tmp_path / "new-locks"):
            pytest.fail("A failed flock must not acquire a lease")
    assert closed == [101]


def test_parser_lease_closes_busy_candidate_and_acquired_descriptor(tmp_path, monkeypatch):
    import fcntl

    candidates = iter((101, 102))
    closed = []
    monkeypatch.setattr(engine.os, "open", lambda *a, **k: next(candidates))
    monkeypatch.setattr(engine.os, "close", closed.append)

    def lock(descriptor, flags):
        if descriptor == 101:
            raise BlockingIOError("synthetic busy slot")

    monkeypatch.setattr(fcntl, "flock", lock)
    with engine.parser_lease(tmp_path / "new-locks"):
        assert closed == [101]
    assert closed == [101, 102]
