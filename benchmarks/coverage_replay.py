"""Extend the frozen development replay with source metrics and labeled iOS branches."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from benchmarks.hardening_replay import replay
from benchmarks.real_world import PRIMARY, sha, write_json
from mobile_audit.audit import correlate
from mobile_audit.intel import normalize_cve

CASES = Path(__file__).with_name("ios_branch_cases.json")
PREVIOUS = Path(__file__).parent / "results/2026-10-09-public-real-world-hardened.json"
PREVIOUS_SHA = "a52623cff0fefab268c56e2263beebab88ac92a90f04018373200874acc74eee"


def evaluate_branches() -> dict:
    spec = json.loads(CASES.read_text())
    primary = json.loads(PRIMARY.read_text())
    cve = normalize_cve(primary["cna"][spec["cve"]])
    output = []
    for case in spec["cases"]:
        document = spec["documents"][case["document"]]
        vendor = {
            "id": spec["cve"],
            "title": "WebKit: " + document["label"],
            "source": "apple",
            "platform": "ios",
            "component": "WebKit",
            "fixed_release": document["label"],
            "references": [document["url"]],
        }
        environment = {
            "platform": "ios",
            **{k: case[k] for k in ("version", "os_product", "simulator") if k in case},
        }
        findings, advisories = correlate(
            {"dependencies": [], "platforms": ["ios"]}, [cve, vendor], environment
        )
        observed = sorted({a["state"] for a in advisories})
        output.append(
            {
                **case,
                "observed_states": observed,
                "correct": observed == [case["expected"]],
                "finding_statuses": sorted({f["status"] for f in findings}),
                "reachability": sorted({f.get("reachability", "unknown") for f in findings}),
            }
        )
    return {
        "cases": output,
        "correct": sum(c["correct"] for c in output),
        "total": len(output),
        "spec_sha256": sha(CASES.read_bytes()),
        "primary_sha256": sha(PRIMARY.read_bytes()),
        "fixture_kind": spec["fixture_kind"],
        "documents": spec["documents"],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifact", type=Path, required=True)
    parser.add_argument("--supplement-artifact", type=Path, required=True)
    parser.add_argument("--work", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    if sha(PREVIOUS.read_bytes()) != PREVIOUS_SHA:
        raise ValueError("Previous hardening summary changed")
    result = replay(args.artifact, args.supplement_artifact, args.work, args.out, sys.executable)
    result["ios_branch_extension"] = evaluate_branches()
    result["coverage_extension_provenance"] = {
        "previous_summary_sha256": PREVIOUS_SHA,
        "kind": "development-rerun-after-labels-seen",
        "legacy_os_expected_states": "Frozen unchanged; two formerly unknown iOS cases now intentionally produce supported branch decisions. Inspect legacy correctness separately from the new branch fixtures.",
        "source_function_counts": "Recognized function nodes only, with raw grammar counts and adapted analysis counts; not a complete callable inventory. Adapted files remain partial.",
    }
    write_json(args.out / "summary.json", result)
    print("APSA_COVERAGE_RESULT_BEGIN", flush=True)
    print(json.dumps(result), flush=True)
    print("APSA_COVERAGE_RESULT_END", flush=True)


if __name__ == "__main__":
    main()
