"""Synthetic report-pair contract checks; not scanner accuracy or competitor results."""

from __future__ import annotations

import argparse
import hashlib
import json
from copy import deepcopy
from pathlib import Path

from mobile_audit import __version__
from mobile_audit.core import RULE_VERSION, canonical_json, finding

RULE = "AST-PATH-TRAVERSAL"
SOURCE = "app/Test.kt"
# Expectations are declared before evaluation; no observed outputs become labels.
EXPECTED = (
    ("exact-persists", "exact-id-observed", "comparable", 1),
    ("line-moves", "possible-continuation", "comparable", 1),
    ("absent-complete", "no-compatible-observation", "comparable", 0),
    ("partial-after", "no-compatible-observation", "limited", 0),
    ("omitted-file", "no-compatible-observation", "limited", 0),
    ("module-changes", "no-compatible-observation", "limited", 0),
    ("tool-version-drift", "no-compatible-observation", "limited", 0),
    ("rule-version-drift", "no-compatible-observation", "limited", 0),
    ("multiple-candidates", "possible-continuation", "limited", 2),
    ("other-file", "same-rule-elsewhere", "limited", 1),
    ("imported-claim", "no-compatible-observation", "unsupported", 0),
    ("runtime-to-source", "no-compatible-observation", "unsupported", 0),
    ("platform-changes", "no-compatible-observation", "limited", 0),
    ("persisting-partial", "exact-id-observed", "limited", 1),
)


def _sha(value: dict) -> str:
    return hashlib.sha256(canonical_json(value).encode()).hexdigest()


def _finding(line=3, path=SOURCE) -> dict:
    return finding(
        RULE,
        "Synthetic path flow",
        "high",
        "candidate",
        [{"path": path, "line": line, "function": "load", "sink": "File"}],
        "Validate the destination path.",
    )


def _pair(name: str) -> tuple[dict, dict, str]:
    before = {
        "schema_version": 2,
        "id": "synthetic-before",
        "target": "/synthetic/app",
        "tool_version": __version__,
        "rule_version": RULE_VERSION,
        "inventory": {
            "input_kind": "source",
            "platforms": ["android"],
            "package": "synthetic.app",
            "apps": [{"platform": "android", "package": "synthetic.app"}],
            "fingerprint": "a" * 64,
            "fingerprint_complete": True,
            "source_selection": {"module": "app"},
            "input_snapshot": {"partial": False, "app_scope_complete": True},
            "source_analysis": {"files": [{"path": SOURCE, "state": "checked"}]},
        },
        "coverage": [{"rule_id": RULE, "state": "checked", "method": "source-ast-local-flow"}],
        "findings": [_finding()],
        "warnings": [],
        "runtime": [],
    }
    after = deepcopy(before)
    after.update(id="synthetic-after", findings=[])
    after["inventory"]["fingerprint"] = "b" * 64
    if name in {"exact-persists", "persisting-partial"}:
        after["findings"] = [_finding()]
    elif name == "line-moves":
        after["findings"] = [_finding(17)]
    elif name == "multiple-candidates":
        after["findings"] = [_finding(17), _finding(29)]
    elif name == "other-file":
        after["findings"] = [_finding(path="app/Other.kt")]
        after["inventory"]["source_analysis"]["files"].append({"path": "app/Other.kt", "state": "checked"})
    elif name == "omitted-file":
        after["inventory"]["source_analysis"]["files"] = []
    elif name == "module-changes":
        after["inventory"]["source_selection"]["module"] = "other"
    elif name == "tool-version-drift":
        after["tool_version"] = "different-synthetic-tool"
    elif name == "rule-version-drift":
        after["rule_version"] = "different-synthetic-rules"
    elif name == "imported-claim":
        before["findings"][0]["origin"] = "external"
    elif name == "runtime-to-source":
        before["findings"][0]["status"] = "runtime-confirmed"
    elif name == "platform-changes":
        after["inventory"]["platforms"] = ["ios"]
        after["inventory"]["apps"][0]["platform"] = "ios"
    if name in {"partial-after", "persisting-partial"}:
        after["coverage"][0]["state"] = "partial"
    return before, after, before["findings"][0]["id"]


def run(evaluator=None) -> dict:
    """Evaluate every declared pair twice, retaining errors and disagreements."""
    if evaluator is None:
        from mobile_audit.followup import assess_finding_followup

        evaluator = assess_finding_followup
    outcomes = []
    for name, observation, comparability, count in EXPECTED:
        before, after, finding_id = _pair(name)
        expected = {"observation": observation, "comparability": comparability, "candidate_count": count}
        row = {
            "id": name,
            "expected": expected,
            "passed": False,
            "assessed": False,
            "input_pair_sha256": _sha({"before": before, "after": after, "finding_id": finding_id}),
        }
        try:
            first = evaluator(deepcopy(before), deepcopy(after), finding_id)
            second = evaluator(deepcopy(before), deepcopy(after), finding_id)
            observed = {
                "observation": first["observation"]["state"],
                "comparability": first["comparability"]["state"],
                "candidate_count": first["observation"]["candidate_count"],
            }
            hash_valid = first["artifact_sha256"] == _sha(
                {key: value for key, value in first.items() if key != "artifact_sha256"}
            )
            checks = {
                "observation_match": observed["observation"] == observation,
                "comparability_match": observed["comparability"] == comparability,
                "candidate_count_match": observed["candidate_count"] == count,
                "no_remediation_claim": first["remediation_proven"] is False,
                "deterministic": first == second,
                "artifact_hash_valid": hash_valid,
            }
            row.update(
                assessed=True,
                observed=observed,
                checks=checks,
                passed=all(checks.values()),
                artifact_sha256=first["artifact_sha256"],
            )
        except Exception as error:
            row["error"] = {"type": type(error).__name__, "message": str(error)}
        outcomes.append(row)
    metrics = {
        key: sum(row.get("checks", {}).get(key, False) for row in outcomes)
        for key in (
            "observation_match",
            "comparability_match",
            "candidate_count_match",
            "deterministic",
            "artifact_hash_valid",
        )
    }
    metrics.update(
        declared=len(EXPECTED),
        assessed=sum(row["assessed"] for row in outcomes),
        false_proof_claims=sum(
            row.get("checks", {}).get("no_remediation_claim") is False for row in outcomes
        ),
        passed=sum(row["passed"] for row in outcomes),
    )
    return {
        "schema_version": 1,
        "kind": "apsa-followup-contract-benchmark",
        "fixture_kind": "fresh-synthetic-report-pairs",
        "tool_version": __version__,
        "expected_sha256": _sha({"cases": EXPECTED}),
        "limitations": [
            "No scanner, app, device, or competing product is executed.",
            "Checked coverage is hypothetical report metadata, not a claim of complete AST analysis.",
            "Matches measure this declared contract only, not detection accuracy or remediation efficacy.",
            "Zero false-proof claims tests a false-only guard, not proof that fixes work.",
        ],
        "metrics": metrics,
        "cases": outcomes,
        "disagreements": [row["id"] for row in outcomes if not row["passed"]],
        "passed": bool(outcomes) and all(row["passed"] for row in outcomes),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    result = run()
    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("x", encoding="utf-8") as output:
        json.dump(result, output, ensure_ascii=False, indent=2)
        output.write("\n")
    print(json.dumps({"passed": result["passed"], "metrics": result["metrics"]}))
    raise SystemExit(0 if result["passed"] else 1)


if __name__ == "__main__":
    main()
