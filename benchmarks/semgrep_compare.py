"""Compare two frozen Java crypto rules on newly generated source controls.

Semgrep CE runs only with two byte-pinned upstream local rules. Other categories
are unsupported, not false negatives. This component slice is not a product,
speed, whole-app, or Semgrep Pro ranking. Never point it at retained app inputs.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from benchmarks.competitive import read_manifest
from benchmarks.competitive_cases import MAPPING, cases, project_files
from benchmarks.process_measure import capture
from mobile_audit.source_analysis import analyze_sources

VERSION = "1.179.0"
RULES = {
    "ecb": {"id": "use-of-aes-ecb", "blob": "2315e864a09297798df07409356c455203a2a719"},
    "md5": {"id": "use-of-md5", "blob": "15d8f45591363532c307c8e87d4b9b14f8129e58"},
}


def blob_hash(raw: bytes) -> str:
    return hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()


def prepare_rules(blobs: Path, output: Path) -> dict:
    """Decode explicit upstream Git blob API responses downloaded by CI setup."""
    output.mkdir(parents=True, exist_ok=False)
    evidence = {}
    for spec in RULES.values():
        payload = json.loads((blobs / (spec["blob"] + ".json")).read_text())
        raw = base64.b64decode(payload["content"], validate=False)
        if payload.get("encoding") != "base64" or blob_hash(raw) != spec["blob"]:
            raise ValueError("Upstream rule bytes do not match the frozen Git blob")
        path = output / (spec["id"] + ".yaml")
        path.write_bytes(raw)
        evidence[spec["id"]] = {"git_blob": spec["blob"], "sha256": hashlib.sha256(raw).hexdigest()}
    (output / "provenance.json").write_text(json.dumps(evidence, indent=2) + "\n")
    return evidence


def observation(report: dict, rule: str, target: Path) -> dict:
    if not isinstance(report.get("results"), list) or not isinstance(report.get("errors"), list):
        raise ValueError("Semgrep report lacks results/errors")
    paths = report.get("paths")
    if not isinstance(paths, dict) or not isinstance(paths.get("scanned"), list):
        raise ValueError("Semgrep report lacks scanned-target evidence")
    scanned = any(Path(name).resolve() == target.resolve() for name in paths["scanned"])
    # No finding cannot imply TN when parsing, rule loading, or target selection failed.
    state = "partial" if report["errors"] or not scanned or paths.get("skipped") else "completed"
    return {
        "state": state,
        "matched": any(row.get("check_id") == rule for row in report["results"]),
        "scanned_target": scanned,
        "error_count": len(report["errors"]),
        "rss_bytes": None,
        "rss_state": "unmeasured; no process-tree RSS claim",
    }


def summarize(records: list[dict], tool: str) -> dict:
    counts = dict(tp=0, fp=0, fn=0, tn=0, partial=0, failed=0, unmeasured=0, unsupported=0)
    for record in records:
        result = record["tools"][tool]
        if result["state"] != "completed":
            counts[result["state"]] += 1
            continue
        detected, risky = result["matched"], record["risky"]
        counts["tp" if detected and risky else "fp" if detected else "fn" if risky else "tn"] += 1
    measured = sum(counts[key] for key in ("tp", "fp", "fn", "tn"))
    return counts | {
        "scored_cases": measured,
        "precision": counts["tp"] / (counts["tp"] + counts["fp"]) if counts["tp"] + counts["fp"] else None,
        "recall": counts["tp"] / (counts["tp"] + counts["fn"]) if counts["tp"] + counts["fn"] else None,
    }


def run(fixtures: Path, output: Path, rules: Path | None, executable: str | None) -> dict:
    manifest = read_manifest(fixtures)
    output.mkdir(parents=True, exist_ok=False)
    version = None
    environment = dict(os.environ)
    environment.update(
        SEMGREP_SEND_METRICS="off",
        SEMGREP_ENABLE_VERSION_CHECK="0",
        SEMGREP_SETTINGS_FILE=str(output / "synthetic-settings.yml"),
    )
    environment.pop("SEMGREP_APP_TOKEN", None)
    if executable is not None:
        version_call = capture([executable, "--version"], output, environment, timeout=30)
        (output / "semgrep-version.json").write_text(json.dumps(version_call, indent=2) + "\n")
        version = version_call["stdout"].strip()
        if version_call["status"] or version_call["incomplete"] or version != VERSION:
            raise ValueError("Semgrep executable must report the pinned version " + VERSION)
        if rules is None:
            raise ValueError("Pinned local rules are required for an actual Semgrep run")
    rule_evidence = {}
    if rules is not None:
        for spec in RULES.values():
            raw = (rules / (spec["id"] + ".yaml")).read_bytes()
            if blob_hash(raw) != spec["blob"]:
                raise ValueError("Rule bytes changed before measurement")
            rule_evidence[spec["id"]] = {"git_blob": spec["blob"], "sha256": hashlib.sha256(raw).hexdigest()}
    records = []
    for case in manifest["cases"]:
        record = {key: case[key] for key in ("id", "category", "risky", "sha256", "input_kind")}
        record["tools"] = {}
        if case["language"] != "java" or case["category"] not in RULES or case["input_kind"] != "source-zip":
            record["tools"] = {
                tool: {"state": "unsupported", "matched": False} for tool in ("apsa", "semgrep")
            }
            records.append(record)
            continue
        # read_manifest verified ZIP source bytes against these exact generated bytes.
        base = next(row for row in cases() if row["id"] == case["id"])
        sources = [
            (name, raw.decode()) for name, raw in project_files(base).items() if name.endswith(".java")
        ]
        started = time.perf_counter()
        analyzed = analyze_sources(sources)
        record["tools"]["apsa"] = {
            "state": "partial"
            if analyzed["warnings"] or any(row["state"] == "partial" for row in analyzed["coverage"])
            else "completed",
            "matched": bool(
                {row["rule_id"] for row in analyzed["findings"]} & set(MAPPING[case["category"]]["apsa"])
            ),
            "seconds": time.perf_counter() - started,
            "rss_bytes": None,
        }
        if executable is None:
            record["tools"]["semgrep"] = {
                "state": "unmeasured",
                "matched": False,
                "seconds": None,
                "rss_bytes": None,
            }
        else:
            assert rules is not None
            location = output / case["id"]
            location.mkdir()
            target = location / "ProbeActivity.java"
            target.write_text(sources[0][1])
            spec = RULES[case["category"]]
            argv = [
                executable,
                "scan",
                "--config",
                str((rules / (spec["id"] + ".yaml")).resolve()),
                "--json",
                "--metrics=off",
                "--disable-version-check",
                "--no-rewrite-rule-ids",
                "--no-git-ignore",
                "--strict",
                str(target.resolve()),
            ]
            started = time.perf_counter()
            try:
                process = capture(argv, location, environment)
                elapsed = process["seconds"]
                (location / "invocation.json").write_text(json.dumps(process, indent=2) + "\n")
                if process["status"] != 0 or process["incomplete"]:
                    result = {"state": "failed", "matched": False}
                else:
                    result = observation(json.loads(process["stdout"]), spec["id"], target)
                result["seconds"] = elapsed
                result["rss"] = process["rss"]
                result["rss_bytes"] = process["rss"]["sampled_max_rss_bytes"]
                result["rss_state"] = process["rss"]["state"]
            except (OSError, subprocess.TimeoutExpired, ValueError) as error:
                result = {"state": "failed", "matched": False, "error_type": type(error).__name__}
            record["tools"]["semgrep"] = result
        records.append(record)
    result = {
        "schema": "apsa-semgrep-component-v1",
        "semgrep_version": version,
        "manifest_sha256": hashlib.sha256((fixtures / "manifest.json").read_bytes()).hexdigest(),
        "rules": rule_evidence,
        "cases": records,
        "summary": {tool: summarize(records, tool) for tool in ("apsa", "semgrep")},
        "scope": "Two upstream Semgrep CE Java crypto rules; unsupported categories abstain. APSA source component versus Semgrep CLI. Semgrep CLI process-tree RSS sampled separately; APSA in-process component RSS unmeasured. No speed/RSS or whole-product ranking.",
    }
    (output / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("prepare-rules", "run"))
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--fixtures", type=Path)
    parser.add_argument("--blobs", type=Path)
    parser.add_argument("--rules", type=Path)
    parser.add_argument("--semgrep", default=shutil.which("semgrep"))
    args = parser.parse_args()
    if args.action == "prepare-rules":
        if args.blobs is None:
            parser.error("--blobs is required")
        result = prepare_rules(args.blobs, args.out)
    else:
        if args.fixtures is None:
            parser.error("--fixtures is required")
        result = run(args.fixtures, args.out, args.rules, args.semgrep)
    print(json.dumps(result.get("summary", result), indent=2))


if __name__ == "__main__":
    main()
