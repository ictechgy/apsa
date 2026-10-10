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
"""

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
from mobile_audit.maswe import finding_weaknesses
from mobile_audit.rules import rules as rule_catalog

# Weaknesses a source tree can be checked for; runtime, binary and package-lint rules do not run on source.
SOURCE_MODES = {"source", "ast", "source-pattern", "configuration"}

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


def evaluate(pair: dict, work: Path) -> dict:
    locations = pair["vulnerable_locations"]
    root_name = PurePosixPath(locations[0]["path"]).parts[0]
    rules = set(pair.get("expected_rules", []))
    weaknesses = frozenset(pair.get("weaknesses", []))
    covered = source_weaknesses()
    result = {
        "id": pair["id"],
        "repository": pair["repository"],
        "expected_rules": sorted(rules),
        "weaknesses": sorted(weaknesses),
        # A weakness pair is in scope when some APSA check relates to one of its weaknesses.
        "in_scope": bool(rules) or bool(weaknesses & covered),
    }
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
            "hit_rules": sorted({hit["rule_id"] for hit in hits}),
            "hits_in_labeled_lines": in_range[:20],
            "in_range_rules": sorted({hit["rule_id"] for hit in in_range}),
            "any_rule_findings_in_labeled_files": [
                hit for path in relative for hit in located(report, set(), path)
            ][:20],
        }
    if rules or weaknesses:
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
            # An in-range rule that no longer fires anywhere in the fixed labeled files.
            "discriminating_tp": not result["vulnerable"]["missing_labeled_paths"]
            and not result["fixed"]["missing_labeled_paths"]
            and bool(set(result["vulnerable"]["in_range_rules"]) - set(result["fixed"]["hit_rules"])),
        }
    else:
        result["outcome"] = {"vulnerable": "out-of-scope", "fixed": "out-of-scope"}
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
        "scored_pairs": len(scored),
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
        try:
            results.append(evaluate(pair, args.work))
        except (ValueError, OSError, subprocess.TimeoutExpired) as error:
            results.append({"id": pair["id"], "error": f"{type(error).__name__}: {error}"[:500]})
    totals = totals_for(results)
    summary = {
        "schema": "apsa-fpfn-results-v3",
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


if __name__ == "__main__":
    main()
