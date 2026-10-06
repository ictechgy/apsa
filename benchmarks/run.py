"""Execute the independently labeled, trusted static regression corpus."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from typing import Any

from mobile_audit import binary_analysis, source_analysis
from mobile_audit.core import RULE_VERSION, write_json

DEFAULT_MANIFEST = Path(__file__).with_name("corpus.json")


def _hash(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _labels(entries: Any, label: str) -> set[tuple[str, str]]:
    if not isinstance(entries, list):
        raise ValueError(f"{label} must be a list of rule_id/status records")
    result = set()
    for entry in entries:
        if (
            not isinstance(entry, dict)
            or not isinstance(entry.get("rule_id"), str)
            or not entry["rule_id"]
            or not isinstance(entry.get("status"), str)
            or not entry["status"]
        ):
            raise ValueError(f"{label} contains an invalid rule_id/status record")
        result.add((entry["rule_id"], entry["status"]))
    return result


def _records(labels: set[tuple[str, str]]) -> list[dict]:
    return [{"rule_id": rule, "status": status} for rule, status in sorted(labels)]


def _ratio(numerator: int, denominator: int, undefined: str) -> dict:
    return {
        "value": numerator / denominator if denominator else None,
        "state": "defined" if denominator else undefined,
    }


def _load(path: Path) -> tuple[dict, bytes]:
    with path.open("rb") as stream:
        raw = stream.read(1024 * 1024 + 1)
    if len(raw) > 1024 * 1024:
        raise ValueError("Benchmark manifest exceeds one MiB")
    manifest = json.loads(raw)
    if (
        not isinstance(manifest, dict)
        or manifest.get("schema_version") != 1
        or not isinstance(manifest.get("cases"), list)
        or not manifest["cases"]
    ):
        raise ValueError("Benchmark manifest requires schema_version=1 and nonempty cases")
    if not isinstance(manifest.get("rules"), list) or any(
        not isinstance(rule, str) or not rule for rule in manifest["rules"]
    ):
        raise ValueError("Benchmark manifest requires explicit rule identifiers")
    known = set()
    for case in manifest["cases"]:
        if not isinstance(case, dict) or any(
            not isinstance(case.get(field), str) or not case[field]
            for field in ("id", "path", "variant", "pair", "rationale")
        ):
            raise ValueError("Each benchmark case requires id/path/variant/pair/rationale")
        if case["id"] in known or case.get("kind") not in {"source", "binary"}:
            raise ValueError("Benchmark case IDs must be unique and kind must be source or binary")
        expected = _labels(case.get("expected"), f"Case {case['id']} expected labels")
        if case["variant"] not in {"vulnerable", "fixed", "irrelevant"}:
            raise ValueError("Benchmark variant must be vulnerable, fixed, or irrelevant")
        if bool(expected) != (case["variant"] == "vulnerable"):
            raise ValueError("Vulnerable cases require expected labels; fixed/irrelevant cases require none")
        if any(status != "candidate" for _, status in expected):
            raise ValueError("This static corpus labels only candidate evidence")
        if any(rule not in manifest["rules"] for rule, _ in expected):
            raise ValueError("Expected case rules must be declared in the corpus rule list")
        if case["kind"] == "binary" and (
            not isinstance(case.get("sha256"), str) or not re.fullmatch(r"[0-9a-f]{64}", case["sha256"])
        ):
            raise ValueError("Compiled binary cases require an explicit SHA-256 fixture lock")
        known.add(case["id"])
    return manifest, raw


def run(manifest_path: Path = DEFAULT_MANIFEST, case_ids: list[str] | None = None) -> dict:
    """Count unique case/rule/status labels; repeated findings are not independent samples."""
    manifest, raw = _load(manifest_path)
    selected = set(case_ids or [])
    available = {case["id"] for case in manifest["cases"]}
    if selected - available:
        raise ValueError(f"Unknown benchmark case IDs: {', '.join(sorted(selected - available))}")
    cases = [case for case in manifest["cases"] if not selected or case["id"] in selected]
    counts = {rule: {"tp": 0, "fp": 0, "fn": 0} for rule in manifest["rules"]}
    outcomes = []
    disagreements = []
    for case in cases:
        expected = _labels(case["expected"], case["id"])
        observed: set[tuple[str, str]] = set()
        warnings = []
        partial = []
        error = None
        input_hash = None
        try:
            input_path = (manifest_path.parent / case["path"]).resolve()
            input_raw = input_path.read_bytes()
            input_hash = _hash(input_raw)
            if case.get("sha256") and case["sha256"] != input_hash:
                raise ValueError(
                    "Fixture SHA-256 differs from independently labeled bytes; review and relabel before running"
                )
            if case["kind"] == "source":
                analysis = source_analysis.analyze_sources([(case["path"], input_raw.decode("utf-8"))])
            else:
                analysis = binary_analysis.analyze_binary(input_path, {})
            observed = _labels(analysis["findings"], f"Case {case['id']} observations")
            warnings = analysis.get("warnings", [])
            partial = sorted(
                {
                    row["rule_id"]
                    for row in analysis.get("coverage", [])
                    if row["state"] in {"partial", "not-run"}
                }
            )
        except (OSError, ValueError, KeyError, UnicodeError) as exception:
            error = f"{type(exception).__name__}: {exception}"
        matched = expected & observed
        missing = expected - observed
        unexpected = observed - expected
        for label_set, kind in ((matched, "tp"), (missing, "fn"), (unexpected, "fp")):
            for rule, _status in label_set:
                counts.setdefault(rule, {"tp": 0, "fp": 0, "fn": 0})[kind] += 1
        outcome = {
            "id": case["id"],
            "kind": case["kind"],
            "variant": case["variant"],
            "pair": case["pair"],
            "path": case["path"],
            "input_sha256": input_hash,
            "expected": _records(expected),
            "observed": _records(observed),
            "matched": not missing and not unexpected and not error and not warnings and not partial,
            "warnings": warnings,
            "incomplete_rules": partial,
            "error": error,
        }
        outcomes.append(outcome)
        if not outcome["matched"]:
            disagreements.append(
                {
                    "case_id": case["id"],
                    "false_negatives": _records(missing),
                    "false_positives": _records(unexpected),
                    "warnings": warnings,
                    "incomplete_rules": partial,
                    "error": error,
                }
            )
    metrics = {}
    for rule, count in sorted(counts.items()):
        metrics[rule] = {
            **count,
            "precision": _ratio(
                count["tp"], count["tp"] + count["fp"], "undefined-no-predicted-positive-labels"
            ),
            "recall": _ratio(
                count["tp"], count["tp"] + count["fn"], "undefined-no-ground-truth-positive-labels"
            ),
        }
    totals = {kind: sum(count[kind] for count in counts.values()) for kind in ("tp", "fp", "fn")}
    dependencies = {}
    for package in (
        "tree-sitter",
        "tree-sitter-java",
        "tree-sitter-kotlin",
        "tree-sitter-swift",
        "androguard",
    ):
        try:
            dependencies[package] = version(package)
        except PackageNotFoundError:
            dependencies[package] = None
    engine_hashes = {}
    for module in (source_analysis, binary_analysis):
        path = module.__file__
        engine_hashes[module.__name__.rsplit(".", 1)[-1]] = _hash(Path(path).read_bytes()) if path else None
    return {
        "schema_version": 1,
        "corpus": manifest.get("name"),
        "corpus_sha256": _hash(raw),
        "metric_unit": "unique case-rule-status labels; no instance-level or production accuracy estimate",
        "rule_version": RULE_VERSION,
        "parser_versions": dependencies,
        "engine_sha256": engine_hashes,
        "passed": not disagreements,
        "exit_code": 0 if not disagreements else 1,
        "summary": {
            "cases": len(cases),
            "matched_cases": len(cases) - len(disagreements),
            "disagreements": len(disagreements),
            **totals,
        },
        "metrics": metrics,
        "cases": outcomes,
        "disagreements": disagreements,
        "limitations": "Small handcrafted regression corpus aligned to selected local static evidence patterns. "
        "Labels are not exploitability proof, MASVS certification, or a representative mobile-app sample.",
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--case", action="append", dest="case_ids", help="Select a case ID (repeatable)")
    parser.add_argument("--out", type=Path, help="Save the same JSON result to a release evidence artifact")
    args = parser.parse_args(argv)
    try:
        result = run(args.manifest, args.case_ids)
        if args.out:
            write_json(args.out, result)
        print(json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2))
        return result["exit_code"]
    except (OSError, ValueError, KeyError) as error:
        print(json.dumps({"passed": False, "error": f"{type(error).__name__}: {error}"}), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
