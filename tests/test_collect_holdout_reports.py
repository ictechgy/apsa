"""Synthetic CI artifact tests; no network, scanners, or retained run data."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

SCRIPT = Path(__file__).parents[1] / "scripts" / "collect_holdout_reports.py"
SPEC = importlib.util.spec_from_file_location("collect_holdout_reports", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
collector = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(collector)


@pytest.fixture
def run(tmp_path):
    root = tmp_path.resolve()
    truth = {
        "schema": "apsa-fpfn-pairs-v2",
        "pairs": [
            {
                "id": "synthetic-pair",
                "repository": "example/synthetic",
                "vulnerable_commit": "a" * 40,
                "fixed_commit": "b" * 40,
                "weaknesses": ["MASWE-0050"],
            }
        ],
    }
    truth_path = root / "truth.json"
    truth_path.write_text(json.dumps(truth))
    pair = {
        "id": "synthetic-pair",
        "repository": "example/synthetic",
        "expected_rules": [],
        "weaknesses": ["MASWE-0050"],
        "in_scope": True,
        "outcome": {
            "vulnerable": "tp",
            "fixed": "tn",
            "vulnerable_line_level": True,
            "discriminating_tp": True,
        },
    }
    for side, commit in (("vulnerable", "a" * 40), ("fixed", "b" * 40)):
        pair[side] = {
            "commit": commit,
            "archive": {
                "url": f"https://codeload.github.com/example/synthetic/zip/{commit}",
                "sha256": "c" * 64,
                "bytes": 123,
            },
            "scan_root": "app",
            "audit_incomplete": False,
            "rule_version": "synthetic-v1",
            "missing_labeled_paths": [],
            "labeled_file_states": {},
            "hits": [],
            "hit_rules": [],
            "hits_in_labeled_lines": [],
            "in_range_rules": [],
            "any_rule_findings_in_labeled_files": [],
        }
        report_path = root / "work" / "synthetic-pair" / side / "scan" / "report.json"
        report_path.parent.mkdir(parents=True)
        report_path.write_text(json.dumps({"report": {"findings": [], "inventory": {}}}))
    counts = {
        "tp": 1,
        "fn": 0,
        "fp": 0,
        "tn": 1,
        "line_level_tp": 1,
        "discriminating_tp": 1,
        "errors": 0,
        "unscored_sides": 0,
        "scored_pairs": 1,
    }
    summary = {
        "schema": "apsa-fpfn-results-v3",
        "truth": "truth.json",
        "truth_sha256": hashlib.sha256(truth_path.read_bytes()).hexdigest(),
        "amendments_sha256": None,
        "apsa_commit": "d" * 40,
        "worktree_dirty": False,
        "evaluator_sha256": "e" * 64,
        "source_catalog_sha256": "f" * 64,
        "source_weaknesses": ["MASWE-0050"],
        "pairs": [pair],
        "totals": counts,
        "in_scope_totals": dict(counts),
    }
    results_path = root / "artifact" / "results.json"
    results_path.parent.mkdir()
    results_path.write_text(json.dumps(summary))
    return {
        "root": root,
        "truth": truth,
        "summary": summary,
        "truth_path": truth_path,
        "results": results_path,
        "work": root / "work",
        "out": root / "artifact" / "reports",
    }


def save_results(run):
    run["results"].write_text(json.dumps(run["summary"]))


def collect(run, **kwargs):
    return collector.collect(run["truth_path"], run["results"], run["work"], run["out"], **kwargs)


def report(run, side="fixed"):
    return run["work"] / "synthetic-pair" / side / "scan" / "report.json"


def test_complete_collection_copies_exact_report_paths_and_hashes(run):
    # An unrelated report is never searched for or copied.
    extra = run["work"] / "unrelated" / "report.json"
    extra.parent.mkdir()
    extra.write_text("synthetic unrelated evidence")
    manifest = collect(run)
    assert manifest["status"] == "complete" and manifest["errors"] == []
    assert [entry["path"] for entry in manifest["reports"]] == [
        "synthetic-pair/vulnerable/scan/report.json",
        "synthetic-pair/fixed/scan/report.json",
    ]
    for entry in manifest["reports"]:
        original = (run["work"] / entry["path"]).read_bytes()
        assert (run["out"] / entry["path"]).read_bytes() == original
        assert entry["sha256"] == hashlib.sha256(original).hexdigest()
        assert entry["bytes"] == len(original)
    assert json.loads((run["out"] / "collection.json").read_text()) == manifest
    assert sorted(path.relative_to(run["out"]).as_posix() for path in run["out"].rglob("*.json")) == [
        "collection.json",
        "synthetic-pair/fixed/scan/report.json",
        "synthetic-pair/vulnerable/scan/report.json",
    ]


def test_missing_success_report_fails_despite_present_results(run):
    report(run).unlink()
    manifest = collect(run)
    assert manifest["status"] == "incomplete"
    assert manifest["errors"] == ["Missing required report: synthetic-pair/fixed/scan/report.json"]
    assert len(manifest["reports"]) == 1
    assert run["results"].is_file()


def test_caught_evaluator_error_retains_first_side_and_fails(run):
    report(run).unlink()
    run["summary"]["pairs"] = [{"id": "synthetic-pair", "error": "synthetic scan failure"}]
    run["summary"]["totals"] = {
        "tp": 0,
        "fn": 0,
        "fp": 0,
        "tn": 0,
        "line_level_tp": 0,
        "discriminating_tp": 0,
        "errors": 1,
        "unscored_sides": 0,
        "scored_pairs": 0,
    }
    run["summary"]["in_scope_totals"] = {**run["summary"]["totals"], "errors": 0}
    save_results(run)
    manifest = collect(run)
    assert manifest["status"] == "incomplete"
    assert manifest["errors"] == ["Evaluation failed for 1 pair(s)"]
    assert [entry["path"] for entry in manifest["reports"]] == ["synthetic-pair/vulnerable/scan/report.json"]


@pytest.mark.parametrize(
    "state",
    [
        "missing",
        "invalid-json",
        "wrong-hash",
        "wrong-schema",
        "missing-pair",
        "duplicate-pair",
        "unknown-pair",
        "missing-side",
        "wrong-commit",
        "missing-archive-hash",
        "wrong-archive-url",
        "wrong-totals",
        "wrong-labels",
        "missing-provenance",
        "missing-side-metadata",
        "boolean-totals",
        "deep-json",
    ],
)
def test_invalid_results_fail_and_preserve_available_reports(run, state):
    pair = run["summary"]["pairs"][0]
    if state == "missing":
        run["results"].unlink()
    elif state == "invalid-json":
        run["results"].write_text("{")
    elif state == "deep-json":
        run["results"].write_text("{" + '"nested":' + "[" * 1500 + "0" + "]" * 1500 + "}")
    else:
        if state == "wrong-hash":
            run["summary"]["truth_sha256"] = "d" * 64
        elif state == "wrong-schema":
            run["summary"]["schema"] = "apsa-fpfn-results-v0"
        elif state == "missing-pair":
            run["summary"]["pairs"] = []
        elif state == "duplicate-pair":
            run["summary"]["pairs"].append(dict(pair))
        elif state == "unknown-pair":
            pair["id"] = "another-pair"
        elif state == "missing-side":
            del pair["fixed"]
        elif state == "wrong-commit":
            pair["fixed"]["commit"] = "d" * 40
        elif state == "missing-archive-hash":
            del pair["fixed"]["archive"]["sha256"]
        elif state == "wrong-archive-url":
            pair["fixed"]["archive"]["url"] = "https://example.invalid/other"
        elif state == "wrong-totals":
            run["summary"]["totals"]["errors"] = 1
        elif state == "wrong-labels":
            pair["weaknesses"] = []
        elif state == "missing-provenance":
            del run["summary"]["evaluator_sha256"]
        elif state == "missing-side-metadata":
            del pair["fixed"]["audit_incomplete"]
        elif state == "boolean-totals":
            run["summary"]["totals"]["tp"] = True
        save_results(run)
    manifest = collect(run)
    assert manifest["status"] == "incomplete"
    assert any("Results unavailable or invalid" in error for error in manifest["errors"])
    assert len(manifest["reports"]) == 2


@pytest.mark.parametrize("pair_id", ["../outside", "/outside", "pair/child", "..", ".", ""])
def test_truth_path_traversal_never_inspects_work(run, pair_id, monkeypatch):
    run["truth"]["pairs"][0]["id"] = pair_id
    run["truth_path"].write_text(json.dumps(run["truth"]))
    original_directory = collector.directory

    def no_work_read(path, **kwargs):
        assert path != run["work"]
        return original_directory(path, **kwargs)

    monkeypatch.setattr(collector, "directory", no_work_read)
    manifest = collect(run)
    assert manifest["status"] == "incomplete" and manifest["reports"] == []


@pytest.mark.parametrize("component", ["work", "pair", "side", "scan", "file"])
def test_symlinks_are_refused_without_reading_their_targets(run, component):
    external = run["root"] / "fresh-external"
    external.mkdir()
    if component == "work":
        path = run["work"]
    elif component == "pair":
        path = run["work"] / "synthetic-pair"
    elif component == "side":
        path = report(run).parents[1]
    elif component == "scan":
        path = report(run).parent
    else:
        path = report(run)
    moved = external / "synthetic-target"
    path.rename(moved)
    path.symlink_to(moved, target_is_directory=component != "file")
    manifest = collect(run)
    assert manifest["status"] == "incomplete"
    assert not any(entry["path"].startswith("synthetic-pair/fixed/") for entry in manifest["reports"])
    assert any("unsafe" in error or "Cannot retain valid report" in error for error in manifest["errors"])


def test_hardlinks_are_refused(run):
    external = run["root"] / "fresh-external.json"
    external.write_text("synthetic fixture only")
    report(run).unlink()
    os.link(external, report(run))
    manifest = collect(run)
    assert manifest["status"] == "incomplete"
    assert len(manifest["reports"]) == 1


@pytest.mark.parametrize("budget", ["MAX_REPORT_BYTES", "MAX_TOTAL_REPORT_BYTES"])
def test_report_byte_budgets_fail_explicitly(run, budget, monkeypatch):
    monkeypatch.setattr(collector, budget, 1)
    manifest = collect(run)
    assert manifest["status"] == "incomplete" and manifest["reports"] == []
    assert len(manifest["errors"]) == 2


def test_malformed_successful_report_is_retained_but_fails(run):
    report(run).write_text("{")
    manifest = collect(run)
    assert manifest["status"] == "incomplete" and len(manifest["reports"]) == 2
    assert (run["out"] / "synthetic-pair/fixed/scan/report.json").read_text() == "{"


def test_failed_evaluation_step_fails_even_with_complete_results(run):
    manifest = collect(run, evaluation_outcome="failure")
    assert manifest["status"] == "incomplete" and len(manifest["reports"]) == 2
    assert manifest["errors"] == ["Evaluation step outcome: failure"]


def test_stale_destination_cannot_hide_missing_evidence(run):
    run["out"].mkdir()
    with pytest.raises(FileExistsError):
        collect(run)


@pytest.mark.parametrize("missing", [False, True])
def test_cli_exit_status_exposes_collection_failure(run, missing):
    if missing:
        report(run).unlink()
    process = subprocess.run(
        [
            sys.executable,
            "-B",
            str(SCRIPT),
            "--truth",
            str(run["truth_path"]),
            "--results",
            str(run["results"]),
            "--work",
            str(run["work"]),
            "--out",
            str(run["out"]),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert process.returncode == (1 if missing else 0)
    assert (run["out"] / "collection.json").is_file()
