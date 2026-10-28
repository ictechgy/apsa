"""The vulnerable/fixed pair harness scores MASWE-labeled (v2) truth without network or scanning."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

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
            "inventory": {
                "source_analysis": {"files": [{"path": name, "state": "checked"} for name in FILES]}
            },
            "coverage": [
                {"rule_id": rule, "state": "checked"}
                for rule in sorted(fpfn_eval.relevant_rule_ids({"weaknesses": ["MASWE-0050", "MASWE-0026"]}))
            ],
        }, {}

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
    assert summary["schema"] == "apsa-fpfn-results-v4"
    assert summary["truth_sha256"] == fpfn_eval.sha(truth.read_bytes())
    assert summary["evaluator_sha256"] == fpfn_eval.sha(Path(fpfn_eval.__file__).read_bytes())
    assert "MASWE-0050" in summary["source_weaknesses"] and "MASWE-0059" not in summary["source_weaknesses"]
    # Discriminating TP needs the fixed side's labeled file: a deleted file proves nothing.
    moved = {**TRUTH["pairs"][0], "id": "moved", "fixed_locations": [{"path": "app/Gone.kt"}]}
    truth.write_text(json.dumps({**TRUTH, "pairs": [moved]}))
    fpfn_eval.main()
    assert json.loads(out.read_text())["pairs"][0]["outcome"]["discriminating_tp"] is False


def test_scan_retains_json_stdout_failure_and_exact_invocation(tmp_path, monkeypatch):
    payload = b'{"ok":false,"error":{"message":"CPU budget exceeded"}}\n'

    def fail(argv, *, stdout, stderr, timeout, env):
        stdout.write(payload)
        stderr.write(b"diagnostic\n")
        return subprocess.CompletedProcess(argv, 1)

    monkeypatch.setattr(fpfn_eval.subprocess, "run", fail)
    output = tmp_path / "scan"
    with pytest.raises(fpfn_eval.ScanError, match="code 1") as caught:
        fpfn_eval.scan(tmp_path / "source", output)
    execution = json.loads((output / "execution.json").read_text())
    assert execution == caught.value.execution
    assert execution["argv"][:4] == [sys.executable, "-I", "-m", "apsa"]
    assert execution["exit_code"] == 1 and not execution["timed_out"]
    assert execution["elapsed_seconds"] >= 0
    assert (output / "stdout.txt").read_bytes() == payload
    assert (output / "stderr.txt").read_bytes() == b"diagnostic\n"
    assert execution["stdout"]["sha256"] == fpfn_eval.sha(payload)


def test_scan_timeout_retains_available_output_with_explicit_truncation(tmp_path, monkeypatch):
    def timeout(argv, **kwargs):
        kwargs["stdout"].write(b"a" * 50)
        raise subprocess.TimeoutExpired(argv, 900, output=b"duplicate", stderr=b"timeout detail")

    monkeypatch.setattr(fpfn_eval.subprocess, "run", timeout)
    monkeypatch.setattr(fpfn_eval, "MAX_STREAM_BYTES", 16)
    output = tmp_path / "scan"
    with pytest.raises(fpfn_eval.ScanError, match="timed out") as caught:
        fpfn_eval.scan(tmp_path / "source", output)
    execution = caught.value.execution
    assert execution["exit_code"] is None and execution["timed_out"] is True
    assert execution["stdout"] == {
        "path": "stdout.txt",
        "bytes": 50,
        "retained_bytes": 16,
        "truncated": True,
        "sha256": fpfn_eval.sha(b"a" * 50),
    }
    assert (output / "stdout.txt").read_bytes() == b"a" * 16
    assert (output / "stderr.txt").read_bytes() == b"timeout detail"


def install_side_fixture(monkeypatch, failing: set[str], calls: list[str]):
    def fetch(repository, commit, out):
        out.write_bytes(commit.encode())
        return {"url": "synthetic", "sha256": fpfn_eval.sha(commit.encode()), "bytes": len(commit)}

    def extract(archive, destination):
        (destination / "app").mkdir(parents=True)
        (destination / "app" / "Files.kt").write_text("// synthetic\n")
        return destination

    def scan(target, output):
        side = output.parent.name
        calls.append(side)
        if side in failing:
            raise fpfn_eval.ScanError("stdout contains parser failure", {"exit_code": 1})
        return {"findings": [], "inventory": {"partial": True}, "coverage": []}, {"exit_code": 4}

    monkeypatch.setattr(fpfn_eval, "fetch", fetch)
    monkeypatch.setattr(fpfn_eval, "extract", extract)
    monkeypatch.setattr(fpfn_eval, "scan", scan)


@pytest.mark.parametrize("failing", [{"vulnerable"}, {"fixed"}, {"vulnerable", "fixed"}])
def test_failed_sides_are_unscored_and_other_side_is_still_attempted(tmp_path, monkeypatch, failing):
    calls = []
    install_side_fixture(monkeypatch, failing, calls)
    pair = fpfn_eval.evaluate(TRUTH["pairs"][0], tmp_path)
    assert calls == ["vulnerable", "fixed"]
    assert pair["in_scope"] is True and pair["repository"] == "example/app"
    assert pair["weaknesses"] == ["MASWE-0050"]
    for side in ("vulnerable", "fixed"):
        if side in failing:
            assert pair[side]["report_returned"] is False
            assert pair[side]["audit_incomplete"] is None
            assert pair["outcome"][side] == "unscored"
            assert pair[side]["execution"] == {"exit_code": 1}
        else:
            assert pair[side]["report_returned"] is True
            assert pair[side]["audit_incomplete"] is True
            assert pair["outcome"][side] == "unscored"
    counts = fpfn_eval.totals_for([pair])
    assert counts["errors"] == 1 and counts["unscored_sides"] == 2
    assert counts["scored_pairs"] == 0
    assert counts["discriminating_tp"] == 0
    assert fpfn_eval.totals_for([p for p in [pair] if p["in_scope"]])["errors"] == 1


def test_main_writes_partial_results_then_exits_nonzero(tmp_path, monkeypatch):
    calls = []
    install_side_fixture(monkeypatch, {"vulnerable"}, calls)
    truth = tmp_path / "truth.json"
    truth.write_text(json.dumps({**TRUTH, "pairs": TRUTH["pairs"][:1]}))
    out = tmp_path / "results.json"
    monkeypatch.setattr(
        sys, "argv", ["fpfn_eval", "--truth", str(truth), "--work", str(tmp_path / "work"), "--out", str(out)]
    )
    with pytest.raises(SystemExit) as caught:
        fpfn_eval.main()
    assert caught.value.code == 1
    result = json.loads(out.read_text())
    assert result["schema"] == "apsa-fpfn-results-v4"
    assert result["totals"]["errors"] == result["in_scope_totals"]["errors"] == 1
    assert result["totals"]["fn"] == result["totals"]["tn"] == 0
    assert result["totals"]["unscored_sides"] == 2


def test_scan_success_returns_partial_report_and_execution(tmp_path, monkeypatch):
    report = {"findings": [], "inventory": {"partial": True}, "coverage": []}

    def successful(argv, **kwargs):
        Path(argv[argv.index("--out") + 1]).write_text(json.dumps(report))
        kwargs["stdout"].write(b"report returned\n")
        return subprocess.CompletedProcess(argv, 4)

    monkeypatch.setattr(fpfn_eval.subprocess, "run", successful)
    observed, execution = fpfn_eval.scan(tmp_path / "source", tmp_path / "scan")
    assert observed == report and execution["exit_code"] == 4
    assert fpfn_eval.report_incomplete(observed) is True
