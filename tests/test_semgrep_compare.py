"""Fresh-source measurement failures must never become clean competitor scores."""

from __future__ import annotations

import json
import sys

import pytest

from benchmarks.competitive_cases import generate
from benchmarks.semgrep_compare import capture, observation, run, summarize


def test_missing_competitor_is_unmeasured_with_no_accuracy_or_rss_claim(tmp_path):
    fixtures = tmp_path / "new-cases"
    generate(fixtures)
    result = run(fixtures, tmp_path / "measurement", None, None)
    assert result["summary"]["semgrep"] == {
        "tp": 0,
        "fp": 0,
        "fn": 0,
        "tn": 0,
        "partial": 0,
        "failed": 0,
        "unmeasured": 4,
        "unsupported": 36,
        "scored_cases": 0,
        "precision": None,
        "recall": None,
    }
    assert result["summary"]["apsa"]["partial"] == 4
    assert result["summary"]["apsa"]["scored_cases"] == 0
    assert sum(row["tools"]["apsa"].get("matched", False) for row in result["cases"]) == 2
    assert all(row["tools"]["semgrep"].get("rss_bytes") is None for row in result["cases"])


@pytest.mark.parametrize("problem", ["error", "omitted", "skipped"])
def test_semgrep_no_alert_requires_complete_actual_target_scan(tmp_path, problem):
    target = tmp_path / "Fresh.java"
    report = {"results": [], "errors": [], "paths": {"scanned": [str(target)]}}
    if problem == "error":
        report["errors"] = [{"type": "ParseError"}]
    elif problem == "omitted":
        report["paths"]["scanned"] = []
    else:
        report["paths"]["skipped"] = [{"path": str(target)}]
    observed = observation(report, "use-of-md5", target)
    assert observed["state"] == "partial"
    counts = summarize([{"risky": True, "tools": {"semgrep": observed}}], "semgrep")
    assert counts["partial"] == 1 and counts["fn"] == counts["tn"] == 0


def test_rule_mapping_is_exact_and_malformed_json_is_not_a_clean_scan(tmp_path):
    target = tmp_path / "New.java"
    report = {
        "results": [{"check_id": "unrelated.use-of-md5"}],
        "errors": [],
        "paths": {"scanned": [str(target)]},
    }
    assert not observation(report, "use-of-md5", target)["matched"]
    with pytest.raises(ValueError, match="results/errors"):
        observation({}, "use-of-md5", target)


def test_actual_capture_preserves_failure_and_bounds_output(tmp_path):
    failed = capture(
        [sys.executable, "-c", "import sys; print('fresh error',file=sys.stderr);sys.exit(7)"], tmp_path, {}
    )
    assert failed["status"] == 7 and failed["stderr"] == "fresh error\n"
    oversized = capture([sys.executable, "-c", "print('x'*2000000)"], tmp_path, {})
    assert oversized["incomplete"] and len(oversized["stdout"]) <= 1024 * 1024


def test_changed_source_truth_is_rejected_before_tool_execution(tmp_path):
    fixtures = tmp_path / "new-cases"
    manifest = generate(fixtures)
    manifest["cases"][0]["risky"] = not manifest["cases"][0]["risky"]
    (fixtures / "manifest.json").write_text(json.dumps(manifest))
    with pytest.raises(ValueError, match="ground truth"):
        run(fixtures, tmp_path / "measurement", None, "/missing/executable")
