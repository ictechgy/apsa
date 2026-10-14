"""Parent parser boundary rejects malformed output without running a worker."""

import copy
import json
import socket
import subprocess
from contextlib import nullcontext

import pytest

from mobile_audit import audit, engine, output, parser_sandbox, sbom
from mobile_audit.core import finding
from mobile_audit.store import Store


@pytest.fixture(autouse=True)
def no_external_execution(monkeypatch):
    def refused(*args, **kwargs):
        raise AssertionError("This boundary test must not execute processes or open a report store")

    for name in ("run", "Popen", "call", "check_call", "check_output"):
        monkeypatch.setattr(subprocess, name, refused)
    monkeypatch.setattr(Store, "__init__", refused)
    monkeypatch.setattr(socket, "socket", refused)
    monkeypatch.setattr(socket, "create_connection", refused)
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
        "inventory": {
            "dependencies": [],
            "warnings": [],
            "platforms": [],
            "fingerprint": "0" * 64,
            "partial": False,
            "fingerprint_complete": True,
        },
        "findings": [],
        "coverage": [{"rule_id": "SYNTHETIC", "state": "checked"}],
    }
    monkeypatch.setattr(engine, "parser_lease", lambda: nullcontext())
    monkeypatch.setattr(engine, "command", lambda *args, **kwargs: json.dumps(response))
    monkeypatch.setattr(parser_sandbox, "sandbox_command", lambda args, *a, **k: (args, isolation))
    monkeypatch.setattr(parser_sandbox, "activate", lambda wrapped, args, state, scratch: (wrapped, state))
    return source, response, isolation


class SyntheticReportStore:
    def __init__(self, home):
        self.home = home
        self.saved = None

    def intelligence(self, *, limit):
        return []

    def save_report(self, report):
        self.saved = copy.deepcopy(report)
        return report

    def report(self, report_id):
        return self.saved


@pytest.fixture
def scan_boundary(tmp_path, monkeypatch, worker_boundary):
    store = SyntheticReportStore(tmp_path / "new-report-store")
    monkeypatch.setattr(audit, "source_health", lambda store: [])
    queries = []

    def synthetic_query(store, dependencies, **kwargs):
        queries.append(copy.deepcopy(dependencies))
        return [], []

    monkeypatch.setattr(audit, "query_dependencies", synthetic_query)
    return store, queries


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


@pytest.mark.parametrize("online", [False, True])
@pytest.mark.parametrize("dependencies", [None, {}, "malformed", [None], [{}], [{"ecosystem": []}]])
def test_malformed_dependencies_fail_at_parser_boundary_before_scan(
    worker_boundary, scan_boundary, dependencies, online
):
    source, response, _ = worker_boundary
    store, queries = scan_boundary
    response["inventory"]["dependencies"] = dependencies
    with pytest.raises(ValueError, match="invalid schema; audit incomplete"):
        audit.scan(store, source, online=online)
    assert store.saved is None and queries == []


@pytest.mark.parametrize("online", [False, True])
def test_missing_dependencies_fail_at_parser_boundary_before_scan(worker_boundary, scan_boundary, online):
    source, response, _ = worker_boundary
    store, queries = scan_boundary
    del response["inventory"]["dependencies"]
    with pytest.raises(ValueError, match="invalid schema; audit incomplete"):
        audit.scan(store, source, online=online)
    assert store.saved is None and queries == []


@pytest.mark.parametrize("field", ["partial", "fingerprint_complete", "platforms", "fingerprint"])
def test_missing_inventory_report_fields_are_controlled_failures(worker_boundary, field):
    source, response, _ = worker_boundary
    del response["inventory"][field]
    with pytest.raises(ValueError, match="invalid schema; audit incomplete"):
        engine.analyze_target(source)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("partial", 0),
        ("partial", "false"),
        ("fingerprint_complete", 1),
        ("fingerprint_complete", None),
        ("platforms", "android"),
        ("platforms", [{}]),
        ("fingerprint", {}),
    ],
)
def test_malformed_inventory_report_fields_are_controlled_failures(worker_boundary, field, value):
    source, response, _ = worker_boundary
    response["inventory"][field] = value
    with pytest.raises(ValueError, match="invalid schema; audit incomplete"):
        engine.analyze_target(source)


@pytest.mark.parametrize("error", [None, False, 0, {}, [], ""])
def test_malformed_error_envelope_is_rejected_even_with_success_fields(worker_boundary, error):
    source, response, _ = worker_boundary
    response["error"] = error
    with pytest.raises(ValueError, match="invalid schema; audit incomplete"):
        engine.analyze_target(source)


def test_valid_error_envelope_preserves_actionable_worker_error(worker_boundary):
    source, response, _ = worker_boundary
    response.clear()
    response["error"] = "Input analysis failed (ValueError): synthetic invalid archive"
    with pytest.raises(
        ValueError, match=r"^Input analysis failed \(ValueError\): synthetic invalid archive$"
    ):
        engine.analyze_target(source)


@pytest.mark.parametrize(
    "field",
    ["id", "rule_id", "title", "severity", "status", "masvs", "remediation", "references", "evidence"],
)
def test_missing_finding_report_fields_are_controlled_failures(worker_boundary, field):
    source, response, _ = worker_boundary
    item = finding("SYNTHETIC", "Synthetic candidate", "low", "candidate", [], "Review synthetic code")
    del item[field]
    response["findings"] = [item]
    with pytest.raises(ValueError, match="invalid schema; audit incomplete"):
        engine.analyze_target(source)


@pytest.mark.parametrize("findings", [None, {}, [None], [{}]])
def test_malformed_finding_objects_are_controlled_failures(worker_boundary, findings):
    source, response, _ = worker_boundary
    response["findings"] = findings
    with pytest.raises(ValueError, match="invalid schema; audit incomplete"):
        engine.analyze_target(source)


@pytest.mark.parametrize(
    ("field", "value"),
    [("severity", {}), ("status", []), ("references", [{}]), ("evidence", [None]), ("maswe", {})],
)
def test_malformed_finding_report_values_are_controlled_failures(worker_boundary, field, value):
    source, response, _ = worker_boundary
    item = finding("SYNTHETIC", "Synthetic candidate", "low", "candidate", [], "Review synthetic code")
    item[field] = value
    response["findings"] = [item]
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


@pytest.mark.parametrize("check", [{"state": "checked"}, {"rule_id": [], "state": "checked"}])
def test_coverage_without_string_rule_id_is_rejected_before_report_save(
    worker_boundary, scan_boundary, check
):
    source, response, _ = worker_boundary
    store, queries = scan_boundary
    response["coverage"] = [check]
    with pytest.raises(ValueError, match="invalid schema; audit incomplete"):
        audit.scan(store, source)
    assert store.saved is None and queries == []


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("name", []),
        ("version", 1),
        ("confidence", []),
        ("resolution", "malformed"),
        ("osv_query", "bad"),
        ("osv_query", {"state": []}),
        ("osv_query", {"checked": "false"}),
    ],
)
def test_malformed_dependency_coordinates_and_query_metadata_are_controlled_failures(
    worker_boundary, field, value
):
    source, response, _ = worker_boundary
    dep = {"ecosystem": "npm", "name": "synthetic-package", "version": "1.0.0"}
    dep[field] = value
    response["inventory"]["dependencies"] = [dep]
    with pytest.raises(ValueError, match="invalid schema; audit incomplete"):
        engine.analyze_target(source)


def test_real_worker_success_dto_crosses_boundary_without_external_execution(
    worker_boundary, scan_boundary, monkeypatch
):
    from pathlib import Path

    from mobile_audit._parser_worker import analyze

    source, _, _ = worker_boundary
    store, _ = scan_boundary

    def in_process_worker(args, **kwargs):
        return json.dumps(analyze(Path(args[5]), None))

    monkeypatch.setattr(engine, "command", in_process_worker)
    report = audit.scan(store, source)
    assert report["inventory"]["dependencies"] == []
    assert isinstance(report["inventory"]["fingerprint_complete"], bool)
    assert report["inventory"]["files_scanned"] == 1
    assert all(check["rule_id"] and isinstance(check["state"], str) for check in report["coverage"])
    assert output.sarif(report)["version"] == "2.1.0"
    assert output.assistant_context(report)["report_id"] == report["id"]


@pytest.mark.parametrize("state", ["future-state", "", "checked-ish"])
@pytest.mark.parametrize("online", [False, True])
def test_unknown_coverage_state_is_rejected_before_scan_can_claim_complete(
    worker_boundary, scan_boundary, state, online
):
    source, response, _ = worker_boundary
    store, queries = scan_boundary
    response["coverage"] = [{"rule_id": "SYNTHETIC", "state": state}]
    with pytest.raises(ValueError, match="invalid schema; audit incomplete"):
        audit.scan(store, source, online=online)
    assert store.saved is None and queries == []


def test_extra_coverage_metadata_is_preserved_with_supported_state(worker_boundary):
    source, response, _ = worker_boundary
    response["coverage"] = [{"rule_id": "SYNTHETIC", "state": "checked", "extension": {"new": True}}]
    result = engine.analyze_target(source)
    assert result["coverage"] == response["coverage"]


@pytest.mark.parametrize("online", [False, True])
def test_valid_worker_dto_supports_scan_refresh_and_report_exports(worker_boundary, scan_boundary, online):
    source, response, _ = worker_boundary
    store, queries = scan_boundary
    dep = {"ecosystem": "npm", "name": "synthetic-package", "version": "1.0.0"}
    response["inventory"]["dependencies"] = [dep]
    response["findings"] = [
        finding(
            "SYNTHETIC",
            "Synthetic candidate",
            "low",
            "candidate",
            [{"path": "New.java", "line": 1}],
            "Review synthetic code",
        )
    ]
    response["coverage"] = [
        {"rule_id": f"SYNTHETIC-{state}", "state": state}
        for state in ("checked", "partial", "not-run", "not-applicable")
    ]
    report = audit.scan(store, source, online=online)
    assert queries == ([response["inventory"]["dependencies"]] if online else [])
    assert report["summary"]["findings"] == 1 and report["summary"]["incomplete"] is True
    refreshed = audit.refresh_report(store, report["id"])
    assert refreshed["inventory"]["dependencies"] == [dep]
    assert "Synthetic candidate" in output.markdown(refreshed)
    assert output.sarif(refreshed)["runs"][0]["results"][0]["ruleId"] == "SYNTHETIC"
    assert output.assistant_context(refreshed)["findings"][0]["status"] == "candidate"
    assert sbom.cyclonedx(refreshed)["components"][0]["name"] == "synthetic-package"


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
    assert result["coverage"] == [{"rule_id": "SYNTHETIC", "state": "partial"}]


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
