"""The contract benchmark must reject false claims and missing evaluations."""

import json
import sys

import pytest

from benchmarks import followup


def test_fresh_report_pairs_are_deterministic_and_all_assessed():
    first = followup.run()
    assert first == followup.run()
    assert first["passed"] is True, first["disagreements"]
    assert first["metrics"]["declared"] == first["metrics"]["assessed"] == 14
    assert first["metrics"]["false_proof_claims"] == 0
    assert first["fixture_kind"] == "fresh-synthetic-report-pairs"
    assert "not detection accuracy" in " ".join(first["limitations"])


def test_benchmark_fails_when_evaluator_claims_remediation():
    from mobile_audit.followup import assess_finding_followup

    def claims_fix(*args):
        result = assess_finding_followup(*args)
        result["remediation_proven"] = True
        result["artifact_sha256"] = followup._sha(
            {key: value for key, value in result.items() if key != "artifact_sha256"}
        )
        return result

    result = followup.run(claims_fix)
    assert result["passed"] is False
    assert result["metrics"]["false_proof_claims"] == 14
    assert len(result["disagreements"]) == 14


def test_benchmark_retains_unassessed_cases_in_denominator():
    def fails(*args):
        raise ValueError("synthetic evaluator failure")

    result = followup.run(fails)
    assert result["passed"] is False
    assert result["metrics"]["assessed"] == 0
    assert result["metrics"]["declared"] == len(result["disagreements"]) == 14
    assert all(row["error"]["type"] == "ValueError" for row in result["cases"])


def test_benchmark_rejects_missing_observation_instead_of_counting_absence():
    result = followup.run(lambda *args: {"remediation_proven": False})
    assert result["passed"] is False
    assert result["metrics"]["assessed"] == 0
    assert result["metrics"]["observation_match"] == 0


def test_cli_exits_nonzero_and_preserves_failed_result(tmp_path, monkeypatch):
    failed = followup.run(lambda *args: {})
    output = tmp_path / "new.json"
    monkeypatch.setattr(followup, "run", lambda: failed)
    monkeypatch.setattr(sys, "argv", ["followup", "--out", str(output)])
    with pytest.raises(SystemExit) as stopped:
        followup.main()
    assert stopped.value.code == 1
    assert json.loads(output.read_text()) == failed
    with pytest.raises(FileExistsError):
        followup.main()
