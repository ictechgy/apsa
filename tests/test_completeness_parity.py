"""Explicit partial analysis survives stale aggregate coverage and report refresh."""

import copy
import json
import subprocess
import sys
from pathlib import Path

import pytest

from mobile_audit.completeness import report_incomplete
from mobile_audit.policy import evaluate
from mobile_audit.verify import _portable_source_pairing


@pytest.mark.parametrize("key", ["source_analysis", "hybrid_analysis"])
@pytest.mark.parametrize(
    "analysis",
    [
        {"state": "partial"},
        {"partial": True},
        {"files": [{"state": "checked"}, {"state": "partial"}]},
        {"files": [{"partial": True}]},
        {"input_observations_truncated": True},
        {"files": "malformed"},
        {"files": ["malformed"]},
        "malformed",
    ],
)
def test_explicit_partial_analysis_cannot_be_hidden_by_stale_coverage(key, analysis):
    report = {
        "partial": False,
        "inventory": {"partial": False, "fingerprint_complete": True, key: analysis},
        "coverage": [{"state": "checked"}],
        "summary": {"incomplete": False},
    }
    original = copy.deepcopy(report)
    assert report_incomplete(report)
    assert report == original
    before = copy.deepcopy(report)
    before["target"] = "/synthetic/source-before"
    before["inventory"].update(input_kind="source", fingerprint="a" * 64)
    after = copy.deepcopy(before)
    after["target"] = "/synthetic/source-after"
    assert _portable_source_pairing(before, after) == "partial source analysis cannot be normalized"


@pytest.mark.parametrize(
    "inventory",
    [{"hybrid_inputs_truncated": True}, {"hybrid_input_inventory_complete": False}],
)
def test_truncated_hybrid_inventory_is_partial_without_coverage_rows(inventory):
    assert report_incomplete({"inventory": inventory, "coverage": []})


def test_optional_absent_or_complete_analysis_keeps_complete_report():
    for inventory in (
        {},
        {"source_analysis": None},
        {"hybrid_inputs_truncated": False, "hybrid_input_inventory_complete": True},
        {
            "source_analysis": {"state": "checked", "partial": False, "files": []},
            "hybrid_analysis": {"files": [{"state": "not-applicable"}]},
        },
    ):
        assert not report_incomplete({"inventory": inventory, "coverage": []})


@pytest.mark.parametrize("key", ["source_analysis", "hybrid_analysis"])
def test_policy_and_standalone_action_preserve_partial_analysis(tmp_path, key):
    report = {
        "id": "synthetic-partial-analysis",
        "inventory": {key: {"files": [{"state": "partial"}]}},
        "findings": [],
        "coverage": [],
        "summary": {"incomplete": False},
    }
    assert evaluate(report, {"schema_version": 1})["state"] == "incomplete"
    fixture = tmp_path / "new-synthetic-report.json"
    fixture.write_text(json.dumps(report))
    script = Path(__file__).resolve().parents[1] / "scripts/action_summary.py"
    result = subprocess.run(
        [sys.executable, "-I", str(script), "--summary", str(fixture), "0"],
        capture_output=True,
        text=True,
        check=True,
    )
    assert "Audit execution: **incomplete**" in result.stdout
    assert "complete for the stated scope" not in result.stdout
