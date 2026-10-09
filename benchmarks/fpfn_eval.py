"""Score source findings on independently labeled vulnerable/fixed public commits."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import urllib.request
from pathlib import Path, PurePosixPath

from benchmarks.dependency_oracle import extract
from mobile_audit.core import report_incomplete

HERE = Path(__file__).resolve().parent
TRUTH = HERE / "fpfn_truth.json"
AMENDMENTS = HERE / "fpfn_truth_amendments.json"
MAX_ARCHIVE = 768 * 1024 * 1024
LINE_TOLERANCE = 3


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


def scan(target: Path, output: Path) -> dict:
    output.mkdir(parents=True)
    env = os.environ.copy()
    env["APSA_PARSER_LOCK_DIR"] = str(output / "parser-locks")
    process = subprocess.run(
        [sys.executable, "-I", "-m", "apsa", "--home", str(output / "home"), "scan", str(target)]
        + ["--out", str(output / "report.json"), "--json"],
        capture_output=True,
        text=True,
        timeout=900,
        env=env,
    )
    if process.returncode not in {0, 3, 4} or not (output / "report.json").is_file():
        raise ValueError(f"APSA execution failed with code {process.returncode}: {process.stderr[-500:]}")
    report = json.loads((output / "report.json").read_text())
    return report.get("report", report)


def located(report: dict, rules: set[str], path: str) -> list[dict]:
    hits = []
    for finding in report["findings"]:
        if rules and finding["rule_id"] not in rules:
            continue
        for evidence in finding.get("evidence", []):
            observed = str(evidence.get("path") or "")
            if observed and PurePosixPath(observed) == PurePosixPath(path):
                hits.append(
                    {"rule_id": finding["rule_id"], "status": finding["status"], "line": evidence.get("line")}
                )
    return hits


def evaluate(pair: dict, work: Path) -> dict:
    locations = pair["vulnerable_locations"]
    root_name = PurePosixPath(locations[0]["path"]).parts[0]
    result = {"id": pair["id"], "repository": pair["repository"], "expected_rules": pair["expected_rules"]}
    rules = set(pair["expected_rules"])
    for side, commit, places in (
        ("vulnerable", pair["vulnerable_commit"], locations),
        ("fixed", pair["fixed_commit"], pair["fixed_locations"]),
    ):
        folder = work / pair["id"] / side
        folder.mkdir(parents=True)
        archive = fetch(pair["repository"], commit, folder / "source.zip")
        source = extract(folder / "source.zip", folder / "src")
        target = source / root_name
        report = scan(target if target.is_dir() else source, folder / "scan")
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
            for hit in located(report, rules, path):
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
            f["path"]: f.get("state") for f in report["inventory"].get("source_analysis", {}).get("files", [])
        }
        result[side] = {
            "commit": commit,
            "archive": archive,
            "scan_root": root_name if target.is_dir() else ".",
            "audit_incomplete": report_incomplete(report),
            "missing_labeled_paths": missing,
            "labeled_file_states": {path: files.get(path, "not-analyzed-as-source") for path in relative},
            "hits": hits[:20],
            "hits_in_labeled_lines": in_range[:20],
            "any_rule_findings_in_labeled_files": [
                hit for path in relative for hit in located(report, set(), path)
            ][:20],
        }
    if rules:
        vulnerable_hit = bool(result["vulnerable"]["hits"])
        fixed_hit = bool(result["fixed"]["hits"])
        # A labeled path absent from the source cannot be measured.
        result["outcome"] = {
            "vulnerable": "unscored"
            if result["vulnerable"]["missing_labeled_paths"]
            else "tp"
            if vulnerable_hit
            else "fn",
            "fixed": "unscored"
            if result["fixed"]["missing_labeled_paths"] and not fixed_hit
            else "fp"
            if fixed_hit
            else "tn",
            "vulnerable_line_level": bool(result["vulnerable"]["hits_in_labeled_lines"]),
        }
    else:
        result["outcome"] = {"vulnerable": "out-of-scope", "fixed": "out-of-scope"}
    return result


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--work", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    truth_raw = TRUTH.read_bytes()
    truth = json.loads(truth_raw)
    amendments = json.loads(AMENDMENTS.read_text()) if AMENDMENTS.is_file() else {"pairs": {}}
    if AMENDMENTS.is_file() and amendments.get("truth_sha256") != sha(truth_raw):
        raise ValueError("Amendments do not apply to this frozen truth")
    for pair in truth["pairs"]:
        pair.update(amendments["pairs"].get(pair["id"], {}))
    results = []
    for pair in truth["pairs"]:
        try:
            results.append(evaluate(pair, args.work))
        except (ValueError, OSError, subprocess.TimeoutExpired) as error:
            results.append({"id": pair["id"], "error": f"{type(error).__name__}: {error}"[:500]})
    scored = [r for r in results if r.get("expected_rules") and "outcome" in r]
    totals = {
        "tp": sum(r["outcome"]["vulnerable"] == "tp" for r in scored),
        "fn": sum(r["outcome"]["vulnerable"] == "fn" for r in scored),
        "fp": sum(r["outcome"]["fixed"] == "fp" for r in scored),
        "tn": sum(r["outcome"]["fixed"] == "tn" for r in scored),
        "line_level_tp": sum(r["outcome"].get("vulnerable_line_level", False) for r in scored),
        "errors": sum("error" in r for r in results),
        "unscored_sides": sum(
            side == "unscored" for r in scored for side in (r["outcome"]["vulnerable"], r["outcome"]["fixed"])
        ),
        "scored_pairs": len(scored),
    }
    summary = {
        "schema": "apsa-fpfn-results-v2",
        "truth_sha256": sha(truth_raw),
        "amendments_sha256": sha(AMENDMENTS.read_bytes()) if AMENDMENTS.is_file() else None,
        "apsa_commit": os.environ.get("GITHUB_SHA", ""),
        "totals": totals,
        "pairs": results,
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    print(json.dumps(totals, indent=2))


if __name__ == "__main__":
    main()
