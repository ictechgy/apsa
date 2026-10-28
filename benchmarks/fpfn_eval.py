"""Score source findings on independently labeled vulnerable/fixed public commits.

Truth schema v1 names the expected rule IDs; v2 names MASWE weaknesses, so a side is flagged by any
finding mapped to one of them and the truth does not depend on APSA's rule names.

Because a weakness such as MASWE-0050 is broad, a v2 file-level hit can come from unrelated code in the
labeled file. For v2 truth the primary recall measure is therefore ``line_level_tp`` (a hit within the
labeled lines, with a small tolerance); file-level TP and FP are reported alongside. Fixed sides have no
line ranges, so their FP stays file-level and is an upper bound: any finding of a labeled weakness in a
fixed file counts.

Declared before the first blind v2 run, as the secondary measure: ``discriminating_tp`` counts vulnerable
sides with an in-range hit from a rule that has no hit in the fixed side's labeled files, so the fix made
that rule go quiet; a fixed side whose labeled files are missing cannot show that and does not count. ``totals`` covers all pairs, where pairs outside APSA's source checks count as FN;
``in_scope_totals`` covers pairs with a weakness some source check relates to.

These are observed findings, including partial reports, not proof of complete coverage or repair.
Execution errors are unscored; each side is attempted independently, with bounded subprocess streams
and execution metadata retained. A run with any failed pair writes its results and returns nonzero.
"""

from __future__ import annotations

import argparse
import hashlib
import http.client
import json
import os
import subprocess
import sys
import tempfile
import time
import urllib.request
import zipfile
from pathlib import Path, PurePosixPath

from benchmarks.dependency_oracle import extract
from mobile_audit.core import report_incomplete
from mobile_audit.maswe import finding_weaknesses, rule_state
from mobile_audit.rules import rules as rule_catalog
from mobile_audit.verify import COVERAGE_ALIASES

# Weaknesses a source tree can be checked for; runtime, binary and package-lint rules do not run on source.
SOURCE_MODES = {"source", "ast", "source-pattern", "configuration"}

HERE = Path(__file__).resolve().parent
TRUTH = HERE / "fpfn_truth.json"
AMENDMENTS = HERE / "fpfn_truth_amendments.json"
MAX_ARCHIVE = 768 * 1024 * 1024
LINE_TOLERANCE = 3
MAX_STREAM_BYTES = 1024 * 1024


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def fetch(repository: str, commit: str, out: Path) -> dict:
    url = f"https://codeload.github.com/{repository}/zip/{commit}"
    with urllib.request.urlopen(url, timeout=300) as response:
        raw = response.read(MAX_ARCHIVE + 1)
    if len(raw) > MAX_ARCHIVE:
        raise ValueError("Source archive exceeds the evaluation budget")
    out.write_bytes(raw)
    return {"url": url, "sha256": sha(raw), "bytes": len(raw)}


class ScanError(ValueError):
    """A failed CLI invocation with replayable execution evidence."""

    def __init__(self, message: str, execution: dict):
        super().__init__(message)
        self.execution = execution


def retain_stream(stream, path: Path) -> dict:
    """Retain a bounded prefix and hash the full stream, explicitly recording truncation."""
    stream.seek(0)
    digest = hashlib.sha256()
    total = retained = 0
    with path.open("xb") as output:
        while chunk := stream.read(64 * 1024):
            digest.update(chunk)
            total += len(chunk)
            prefix = chunk[: max(0, MAX_STREAM_BYTES - retained)]
            output.write(prefix)
            retained += len(prefix)
    return {
        "path": path.name,
        "bytes": total,
        "retained_bytes": retained,
        "truncated": retained < total,
        "sha256": digest.hexdigest(),
    }


def scan(target: Path, output: Path) -> tuple[dict, dict]:
    output.mkdir(parents=True)
    env = os.environ.copy()
    env["APSA_PARSER_LOCK_DIR"] = str(output / "parser-locks")
    argv = [sys.executable, "-I", "-m", "apsa", "--home", str(output / "home"), "scan", str(target)]
    argv += ["--out", str(output / "report.json"), "--json"]
    execution = {
        "schema": "apsa-benchmark-scan-execution-v1",
        "argv": argv,
        "cwd": str(Path.cwd()),
        "exit_code": None,
        "timed_out": False,
    }
    started = time.monotonic()
    failure = None
    with tempfile.TemporaryFile(dir=output) as stdout, tempfile.TemporaryFile(dir=output) as stderr:
        try:
            process = subprocess.run(argv, stdout=stdout, stderr=stderr, timeout=900, env=env)
            execution["exit_code"] = process.returncode
        except subprocess.TimeoutExpired as error:
            execution["timed_out"] = True
            failure = "APSA execution timed out after 900 seconds"
            # Real file-backed subprocesses leave output in these streams. Also preserve available
            # TimeoutExpired output from alternate runners, without duplicating already-written bytes.
            for stream, available in ((stdout, error.output), (stderr, error.stderr)):
                if stream.tell() == 0 and available:
                    stream.write(available.encode() if isinstance(available, str) else available)
        except OSError as error:
            failure = f"APSA execution could not start: {error}"
        execution["elapsed_seconds"] = time.monotonic() - started
        execution["stdout"] = retain_stream(stdout, output / "stdout.txt")
        execution["stderr"] = retain_stream(stderr, output / "stderr.txt")
    (output / "execution.json").write_text(json.dumps(execution, indent=2, sort_keys=True) + "\n")
    if failure is None and execution["exit_code"] not in {0, 3, 4}:
        failure = f"APSA execution failed with code {execution['exit_code']}; see stdout.txt and stderr.txt"
    if failure is not None:
        raise ScanError(failure, execution)
    try:
        report = json.loads((output / "report.json").read_text())
        if not isinstance(report, dict):
            raise ValueError("Report is not an object")
        report = report.get("report", report)
        if not isinstance(report, dict):
            raise ValueError("Report payload is not an object")
    except (OSError, ValueError, RecursionError) as error:
        raise ScanError(f"APSA did not return a readable report: {error}", execution) from error
    return report, execution


def located(report: dict, rules: set[str], path: str, weaknesses: frozenset[str] = frozenset()) -> list[dict]:
    hits = []
    for finding in report["findings"]:
        if rules and finding["rule_id"] not in rules:
            continue
        if weaknesses and not weaknesses & set(finding_weaknesses(finding)):
            continue
        for evidence in finding.get("evidence", []):
            observed = str(evidence.get("path") or "")
            if observed and PurePosixPath(observed) == PurePosixPath(path):
                hits.append(
                    {"rule_id": finding["rule_id"], "status": finding["status"], "line": evidence.get("line")}
                )
    return hits


def source_rules() -> list[dict]:
    return [
        rule
        for rule in rule_catalog()
        if rule.get("mode") in SOURCE_MODES and not rule["id"].startswith("QG-")
    ]


def source_weaknesses() -> set[str]:
    """MASWE weaknesses that at least one source-tree check relates to."""
    return {weakness for rule in source_rules() for weakness in rule.get("maswe", [])}


def provenance() -> dict:
    """Evaluator, catalog and checkout identity, so a result can be tied to what produced it."""
    catalog = sorted(
        (rule["id"], rule.get("mode", ""), tuple(rule.get("maswe", []))) for rule in source_rules()
    )
    commit, dirty = os.environ.get("GITHUB_SHA", ""), None
    try:
        if not commit:
            commit = subprocess.run(
                ["git", "rev-parse", "HEAD"], cwd=HERE, capture_output=True, text=True, check=True
            ).stdout.strip()
        status = subprocess.run(
            ["git", "status", "--porcelain", "--untracked-files=no"],
            cwd=HERE,
            capture_output=True,
            text=True,
            check=True,
        )
        dirty = bool(status.stdout.strip())
    except (OSError, subprocess.CalledProcessError):
        pass
    return {
        "apsa_commit": commit,
        "worktree_dirty": dirty,
        "evaluator_sha256": sha(Path(__file__).read_bytes()),
        "source_catalog_sha256": sha(json.dumps(catalog).encode()),
        "source_weaknesses": sorted(source_weaknesses()),
    }


def pair_identity(pair: dict) -> dict:
    rules = sorted(set(pair.get("expected_rules", [])))
    weaknesses = sorted(set(pair.get("weaknesses", [])))
    return {
        "id": pair["id"],
        "repository": pair["repository"],
        "expected_rules": rules,
        "weaknesses": weaknesses,
        "in_scope": bool(rules) or bool(set(weaknesses) & source_weaknesses()),
    }


def relevant_rule_ids(pair: dict) -> set[str]:
    """Execution checks required before silence on these labels can be scored."""
    rules = set(pair.get("expected_rules", []))
    if not rules:
        weaknesses = set(pair.get("weaknesses", []))
        rules = {rule["id"] for rule in source_rules() if weaknesses & set(rule.get("maswe", []))}
    return {COVERAGE_ALIASES.get(rule) or rule for rule in rules}


def labeled_rule_states(report: dict, pair: dict) -> dict[str, str]:
    return {
        rule: rule_state({row["state"] for row in report.get("coverage", []) if row.get("rule_id") == rule})
        for rule in sorted(relevant_rule_ids(pair))
    }


def labeled_scope_checked(side: dict) -> bool:
    states = side.get("labeled_file_states", {})
    checks = side.get("labeled_rule_states")
    return (
        bool(states)
        and not side.get("missing_labeled_paths")
        and all(state == "checked" for state in states.values())
        and isinstance(checks, dict)
        and all(state == "checked" for state in checks.values())
    )


def evaluate(pair: dict, work: Path) -> dict:
    locations = pair["vulnerable_locations"]
    root_name = PurePosixPath(locations[0]["path"]).parts[0]
    rules = set(pair.get("expected_rules", []))
    weaknesses = frozenset(pair.get("weaknesses", []))
    result = pair_identity(pair)
    for side, commit, places in (
        ("vulnerable", pair["vulnerable_commit"], locations),
        ("fixed", pair["fixed_commit"], pair["fixed_locations"]),
    ):
        side_result = result[side] = {"commit": commit, "report_returned": False, "audit_incomplete": None}
        phase = "prepare"
        try:
            folder = work / pair["id"] / side
            folder.mkdir(parents=True)
            phase = "fetch"
            archive = fetch(pair["repository"], commit, folder / "source.zip")
            side_result["archive"] = archive
            phase = "extract"
            source = extract(folder / "source.zip", folder / "src")
            target = source / root_name
            phase = "scan"
            report, execution = scan(target if target.is_dir() else source, folder / "scan")
            side_result.update(report_returned=True, execution=execution)
            phase = "score"
            relative = [
                str(PurePosixPath(place["path"]).relative_to(root_name)) if target.is_dir() else place["path"]
                for place in places
            ]
            missing = [
                path for path in relative if not ((target if target.is_dir() else source) / path).is_file()
            ]
            hits = []
            in_range = []
            for path, place in zip(relative, places, strict=True):
                for hit in located(report, rules, path, weaknesses):
                    hits.append(hit)
                    start, end = place.get("start_line"), place.get("end_line")
                    line = hit["line"]
                    if (
                        start
                        and end
                        and isinstance(line, int)
                        and start - LINE_TOLERANCE <= line <= end + LINE_TOLERANCE
                    ):
                        in_range.append(hit)
            files = {
                f["path"]: f.get("state")
                for f in report["inventory"].get("source_analysis", {}).get("files", [])
            }
            side_result.update(
                {
                    "commit": commit,
                    "archive": archive,
                    "scan_root": root_name if target.is_dir() else ".",
                    "audit_incomplete": report_incomplete(report),
                    "rule_version": report.get("rule_version"),
                    "missing_labeled_paths": missing,
                    "labeled_file_states": {
                        path: files.get(path, "not-analyzed-as-source") for path in relative
                    },
                    "labeled_rule_states": labeled_rule_states(report, pair),
                    "hits": hits[:20],
                    "hit_rules": sorted({hit["rule_id"] for hit in hits}),
                    "hits_in_labeled_lines": in_range[:20],
                    "in_range_rules": sorted({hit["rule_id"] for hit in in_range}),
                    "any_rule_findings_in_labeled_files": [
                        hit for path in relative for hit in located(report, set(), path)
                    ][:20],
                }
            )
        except (
            ValueError,
            OSError,
            KeyError,
            TypeError,
            subprocess.TimeoutExpired,
            zipfile.BadZipFile,
            http.client.HTTPException,
            RecursionError,
        ) as error:
            side_result.update(error=f"{type(error).__name__}: {error}"[:1000], error_phase=phase)
            if isinstance(error, ScanError):
                side_result["execution"] = error.execution
    failed = [side for side in ("vulnerable", "fixed") if "error" in result[side]]
    if failed:
        result["error"] = "Failed sides: " + ", ".join(failed)
    outcome = {}
    for side, positive, negative in (("vulnerable", "tp", "fn"), ("fixed", "fp", "tn")):
        observed = result[side]
        outcome[side] = (
            "unscored"
            if "error" in observed
            else "out-of-scope"
            if not (rules or weaknesses)
            else "unscored"
            if observed["missing_labeled_paths"] and (side == "vulnerable" or not observed["hits"])
            else positive
            if observed["hits"]
            else "unscored"
            if not labeled_scope_checked(observed)
            else negative
        )
        if outcome[side] == "unscored" and "error" not in observed:
            observed["scoring_abstention"] = (
                "Labeled source files or relevant rules were absent, incomplete or unmeasured"
            )
    if rules or weaknesses:
        vulnerable, fixed = result["vulnerable"], result["fixed"]
        outcome["vulnerable_line_level"] = "error" not in vulnerable and bool(
            vulnerable["hits_in_labeled_lines"]
        )
        outcome["discriminating_tp"] = (
            not failed
            and not vulnerable["missing_labeled_paths"]
            and not fixed["missing_labeled_paths"]
            and labeled_scope_checked(fixed)
            and bool(set(vulnerable["in_range_rules"]) - set(fixed["hit_rules"]))
        )
    result["outcome"] = outcome
    return result


def totals_for(results: list[dict]) -> dict:
    scored = [r for r in results if (r.get("expected_rules") or r.get("weaknesses")) and "outcome" in r]
    return {
        "tp": sum(r["outcome"]["vulnerable"] == "tp" for r in scored),
        "fn": sum(r["outcome"]["vulnerable"] == "fn" for r in scored),
        "fp": sum(r["outcome"]["fixed"] == "fp" for r in scored),
        "tn": sum(r["outcome"]["fixed"] == "tn" for r in scored),
        "line_level_tp": sum(r["outcome"].get("vulnerable_line_level", False) for r in scored),
        "discriminating_tp": sum(r["outcome"].get("discriminating_tp", False) for r in scored),
        "errors": sum("error" in r for r in results),
        "unscored_sides": sum(
            side == "unscored" for r in scored for side in (r["outcome"]["vulnerable"], r["outcome"]["fixed"])
        ),
        "scored_pairs": sum(
            any(r["outcome"][side] in {"tp", "fn", "fp", "tn"} for side in ("vulnerable", "fixed"))
            for r in scored
        ),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--work", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--truth", type=Path, default=TRUTH)
    parser.add_argument(
        "--amendments", type=Path, help="Amendments for this truth; the default truth uses its own file"
    )
    args = parser.parse_args()
    truth_raw = args.truth.read_bytes()
    truth = json.loads(truth_raw)
    amendments_path = args.amendments or (AMENDMENTS if args.truth.resolve() == TRUTH else None)
    amendments = (
        json.loads(amendments_path.read_text())
        if amendments_path and amendments_path.is_file()
        else {"pairs": {}}
    )
    if amendments_path and amendments_path.is_file() and amendments.get("truth_sha256") != sha(truth_raw):
        raise ValueError("Amendments do not apply to this frozen truth")
    for pair in truth["pairs"]:
        pair.update(amendments["pairs"].get(pair["id"], {}))
    results = []
    for pair in truth["pairs"]:
        results.append(evaluate(pair, args.work))
    totals = totals_for(results)
    summary = {
        "schema": "apsa-fpfn-results-v4",
        "truth": str(args.truth.resolve().relative_to(HERE.parent))
        if args.truth.resolve().is_relative_to(HERE.parent)
        else args.truth.name,
        "truth_sha256": sha(truth_raw),
        "amendments_sha256": sha(amendments_path.read_bytes())
        if amendments_path and amendments_path.is_file()
        else None,
        "in_scope_totals": totals_for([r for r in results if r.get("in_scope")]),
        **provenance(),
        "totals": totals,
        "pairs": results,
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    print(json.dumps(totals, indent=2))
    if totals["errors"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
