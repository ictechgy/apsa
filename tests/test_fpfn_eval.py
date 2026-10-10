"""The vulnerable/fixed pair harness scores MASWE-labeled (v2) truth without network or scanning."""

from __future__ import annotations

import json
import sys
from pathlib import Path

from benchmarks import fpfn_eval


def finding(rule: str, path: str, line: int) -> dict:
    return {"rule_id": rule, "status": "candidate", "evidence": [{"path": path, "line": line}]}


TRUTH = {
    "schema": "apsa-fpfn-pairs-v2",
    "pairs": [
        {
            "id": "fixed-quiet",
            "repository": "example/app",
            "platform": "android",
            "vulnerable_commit": "a" * 40,
            "fixed_commit": "b" * 40,
            "weaknesses": ["MASWE-0050"],
            "vulnerable_locations": [{"path": "app/Files.kt", "start_line": 10, "end_line": 12}],
            "fixed_locations": [{"path": "app/Files.kt"}],
        },
        {
            "id": "fixed-still-fires",
            "repository": "example/app",
            "platform": "android",
            "vulnerable_commit": "c" * 40,
            "fixed_commit": "d" * 40,
            "weaknesses": ["MASWE-0050"],
            "vulnerable_locations": [{"path": "app/Db.kt", "start_line": 5, "end_line": 5}],
            "fixed_locations": [{"path": "app/Db.kt"}],
        },
        {
            "id": "wrong-lines",
            "repository": "example/app",
            "platform": "ios",
            "vulnerable_commit": "e" * 40,
            "fixed_commit": "f" * 40,
            "weaknesses": ["MASWE-0026"],
            "vulnerable_locations": [{"path": "app/Net.swift", "start_line": 40, "end_line": 41}],
            "fixed_locations": [{"path": "app/Net.swift"}],
        },
        {
            "id": "unmapped",
            "repository": "example/app",
            "platform": "android",
            "vulnerable_commit": "1" * 40,
            "fixed_commit": "2" * 40,
            "weaknesses": ["MASWE-0059"],
            "vulnerable_locations": [{"path": "app/Root.kt", "start_line": 1, "end_line": 3}],
            "fixed_locations": [{"path": "app/Root.kt"}],
        },
    ],
}

REPORTS = {
    "a" * 40: [finding("AST-PATH-TRAVERSAL", "Files.kt", 11)],
    "b" * 40: [finding("STORAGE-SENSITIVE-LOG", "Files.kt", 3)],
    "c" * 40: [finding("AST-SQL-CONCAT", "Db.kt", 5)],
    "d" * 40: [finding("AST-SQL-CONCAT", "Db.kt", 9)],
    "e" * 40: [finding("IOS-ATS-BYPASS-API", "Net.swift", 3)],
    "f" * 40: [],
    "1" * 40: [],
    "2" * 40: [],
}
FILES = {"Files.kt", "Db.kt", "Net.swift", "Root.kt"}


def test_v2_truth_scores_by_weakness_line_and_discrimination(tmp_path, monkeypatch):
    def fake_fetch(repository, commit, out):
        out.write_bytes(commit.encode())
        return {"url": "synthetic", "sha256": commit, "bytes": len(commit)}

    def fake_extract(archive, destination):
        root = destination / "app-src"
        (root / "app").mkdir(parents=True)
        for name in FILES:
            (root / "app" / name).write_text("// synthetic\n")
        return root

    current: list[str] = []

    def fake_scan(target, output):
        # Each side is fetched, extracted and scanned in turn; the last fetched commit is being scanned.
        return {
            "findings": REPORTS[current[0]],
            "inventory": {"source_analysis": {"files": []}},
            "coverage": [],
        }

    def tracking_fetch(repository, commit, out):
        current[:] = [commit]
        return fake_fetch(repository, commit, out)

    monkeypatch.setattr(fpfn_eval, "fetch", tracking_fetch)
    monkeypatch.setattr(fpfn_eval, "extract", fake_extract)
    monkeypatch.setattr(fpfn_eval, "scan", fake_scan)
    truth = tmp_path / "truth.json"
    truth.write_text(json.dumps(TRUTH))
    out = tmp_path / "results.json"
    monkeypatch.setattr(
        sys, "argv", ["fpfn_eval", "--work", str(tmp_path / "work"), "--out", str(out), "--truth", str(truth)]
    )
    fpfn_eval.main()
    summary = json.loads(out.read_text())
    outcomes = {pair["id"]: pair["outcome"] for pair in summary["pairs"]}
    assert outcomes["fixed-quiet"] == {
        "vulnerable": "tp",
        "fixed": "tn",
        "vulnerable_line_level": True,
        "discriminating_tp": True,
    }
    # The fixed side still has the same rule in the file: an upper-bound FP, not a discriminating TP.
    assert outcomes["fixed-still-fires"]["fixed"] == "fp"
    assert outcomes["fixed-still-fires"]["discriminating_tp"] is False
    # A weakness hit outside the labeled lines is a file-level TP only.
    assert outcomes["wrong-lines"]["vulnerable"] == "tp"
    assert outcomes["wrong-lines"]["vulnerable_line_level"] is False
    assert {pair["id"]: pair["in_scope"] for pair in summary["pairs"]}["unmapped"] is False
    assert summary["totals"] == {
        "tp": 3,
        "fn": 1,
        "fp": 1,
        "tn": 3,
        "line_level_tp": 2,
        "discriminating_tp": 1,
        "errors": 0,
        "unscored_sides": 0,
        "scored_pairs": 4,
    }
    assert summary["in_scope_totals"]["scored_pairs"] == 3 and summary["in_scope_totals"]["fn"] == 0
    assert summary["schema"] == "apsa-fpfn-results-v3"
    assert summary["truth_sha256"] == fpfn_eval.sha(truth.read_bytes())
    assert summary["evaluator_sha256"] == fpfn_eval.sha(Path(fpfn_eval.__file__).read_bytes())
    assert "MASWE-0050" in summary["source_weaknesses"] and "MASWE-0059" not in summary["source_weaknesses"]
