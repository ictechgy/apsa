"""Freeze public labels against NEW compiled inputs, preserving partial results."""

from __future__ import annotations

import argparse
import copy
import hashlib
import importlib.util
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EXPECTED_PARTIAL_CASES = {
    "java-cross-function-irrelevant",
    "swift-url-vulnerable",
    "swift-url-fixed",
    "swift-documentation-irrelevant",
    "swift-navigation-vulnerable",
    "swift-navigation-fixed",
    "swift-query-javascript-vulnerable",
    "swift-query-javascript-fixed",
    "swift-unrelated-shadow",
}
BINARY_CONTROLS = {"dex-unsafe": "unsafe", "dex-safe": "safe"}
SWIFT_INCOMPLETE_RULES = ["AST-CRYPTO-ECB", "AST-CRYPTO-WEAK-CIPHER", "AST-SQL-CONCAT"]
JAVA_INCOMPLETE_RULES = [
    "AST-CRYPTO-ECB",
    "AST-CRYPTO-HARDCODED-KEY",
    "AST-CRYPTO-STATIC-IV",
    "AST-CRYPTO-WEAK-CIPHER",
    "AST-CRYPTO-WEAK-HASH",
    "AST-IMPLICIT-INTENT",
    "AST-INTENT-REDIRECTION",
    "AST-PATH-TRAVERSAL",
    "AST-PENDINGINTENT-MUTABLE",
    "AST-SQL-CONCAT",
    "AST-WEBVIEW-HOST-ALLOWLIST",
    "AST-WEBVIEW-JS-BRIDGE",
    "AST-WEBVIEW-SSL-BYPASS",
    "AST-WEBVIEW-UNTRUSTED-URL",
]
# This semantic diagnostic contains no machine path or temporary identifier.
JAVA_PARTIAL_WARNING = "Native flow remains partial: object alias identity unavailable; unresolved callable identity or argument signature."


def load_module(name: str, path: Path):
    specification = importlib.util.spec_from_file_location(name, path)
    if specification is None or specification.loader is None:
        raise ValueError(f"Public fixture module unavailable: {path.name}")
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


def freeze_corpus(output: Path, compiled: Path, labels: Path = ROOT / "benchmarks/corpus.json") -> Path:
    """Never open binary paths from old labels; only newly designated controls."""
    if output.resolve().is_relative_to(ROOT):
        raise ValueError("Fresh corpus output must be outside the checkout")
    output.mkdir(parents=True, exist_ok=False)
    manifest = copy.deepcopy(json.loads(labels.read_text()))
    selected = []
    omitted = []
    for case in manifest["cases"]:
        if case["kind"] == "source":
            relative = Path(case["path"])
            if relative.is_absolute() or ".." in relative.parts or relative.parts[0] != "cases":
                raise ValueError("Public source labels must name a relative cases source")
            if relative.suffix not in {".java", ".kt", ".swift"}:
                raise ValueError("Public source labels require a declared source format")
            source = labels.parent / relative
            if source.is_symlink() or any(parent.is_symlink() for parent in source.parents):
                raise ValueError("Public source control symlinks are unsupported")
            target = output / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(source.read_bytes())
        elif case["id"] in BINARY_CONTROLS:
            target = output / "compiled" / (BINARY_CONTROLS[case["id"]] + ".apk")
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes((compiled / target.name).read_bytes())
            case["path"] = target.relative_to(output).as_posix()
        else:
            omitted.append(
                {
                    "id": case["id"],
                    "reason": "Retained upstream binary excluded; no fresh equivalent or independent sample claimed",
                }
            )
            continue
        case["sha256"] = hashlib.sha256(target.read_bytes()).hexdigest()
        selected.append(case)
    manifest["name"] = "apsa-fresh-public-static-controls-v1"
    manifest["cases"] = selected
    manifest["omitted_cases"] = omitted
    manifest["generation_scope"] = (
        "Public source labels frozen before measurement against NEW javac/D8/AAPT2 APKs"
    )
    manifest["published_baseline_approved"] = False
    frozen = output / "fresh-corpus.json"
    frozen.write_text(json.dumps(manifest, indent=2) + "\n")
    return frozen


def _observations(value: object) -> set[tuple[str, str]] | None:
    """Preserve rule/status identity and reject malformed or duplicate labels."""
    if not isinstance(value, list):
        return None
    labels = set()
    for entry in value:
        if (
            not isinstance(entry, dict)
            or set(entry) != {"rule_id", "status"}
            or not isinstance(entry["rule_id"], str)
            or not entry["rule_id"]
            or not isinstance(entry["status"], str)
            or not entry["status"]
        ):
            return None
        label = (entry["rule_id"], entry["status"])
        if label in labels:
            return None
        labels.add(label)
    return labels


def regression_contract(result: dict, labels: Path = ROOT / "benchmarks/corpus.json") -> bool:
    """Check frozen observations separately from deliberately unscored partials."""
    summary, cases, disagreements = result.get("summary"), result.get("cases"), result.get("disagreements")
    if (
        not isinstance(summary, dict)
        or any(type(summary.get(key)) is not int or summary[key] != 0 for key in ("fp", "fn"))
        or not isinstance(cases, list)
        or not isinstance(disagreements, list)
        or result.get("passed") is not False
        or ("published_baseline_approved" in result and result["published_baseline_approved"] is not False)
    ):
        return False
    try:
        truth = json.loads(labels.read_text())["cases"]
        selected = [case for case in truth if case["kind"] == "source" or case["id"] in BINARY_CONTROLS]
        expected = {case["id"]: _observations(case["expected"]) for case in selected}
    except (OSError, ValueError, KeyError, TypeError):
        return False
    if len(expected) != len(selected) or any(value is None for value in expected.values()):
        return False
    seen = set()
    for case in cases:
        if not isinstance(case, dict):
            return False
        identifier = case.get("id")
        if not isinstance(identifier, str) or identifier not in expected or identifier in seen:
            return False
        seen.add(identifier)
        if (
            "error" not in case
            or case["error"] is not None
            or _observations(case.get("expected")) != expected[identifier]
            or _observations(case.get("observed")) != expected[identifier]
        ):
            return False
        if identifier == "java-cross-function-irrelevant":
            rules, warnings = JAVA_INCOMPLETE_RULES, [JAVA_PARTIAL_WARNING]
        elif identifier in EXPECTED_PARTIAL_CASES:
            rules, warnings = SWIFT_INCOMPLETE_RULES, []
        else:
            rules, warnings = [], []
        if (
            case.get("incomplete_rules") != rules
            or case.get("warnings") != warnings
            or case.get("scored") is not (identifier not in EXPECTED_PARTIAL_CASES)
        ):
            return False
    if seen != set(expected) or summary.get("cases") != len(cases):
        return False
    disagreement_ids = []
    for row in disagreements:
        if not isinstance(row, dict) or not isinstance(row.get("case_id"), str):
            return False
        disagreement_ids.append(row["case_id"])
    return (
        len(disagreement_ids) == len(EXPECTED_PARTIAL_CASES)
        and set(disagreement_ids) == EXPECTED_PARTIAL_CASES
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--out", type=Path, required=True, help="New synthetic evidence directory outside checkout"
    )
    parser.add_argument("--sdk", type=Path)
    parser.add_argument(
        "--check-regression-contract",
        action="store_true",
        help="Check label agreement and the explicit known partial case; does not approve accuracy",
    )
    args = parser.parse_args()
    if args.out.resolve().is_relative_to(ROOT):
        raise ValueError("Fresh benchmark evidence must be outside the checkout")
    args.out.mkdir(parents=True, exist_ok=False)
    sdk = args.sdk or os.environ.get("APSA_TEST_ANDROID_SDK") or os.environ.get("ANDROID_HOME")
    if not sdk:
        raise ValueError("Fresh benchmark requires an installed Android SDK")
    builder = load_module("fresh_benchmark_builder", ROOT / "tests/fixtures/binary_analysis/build.py")
    builder.build_fixtures(
        sdk=Path(sdk),
        output_dir=args.out / "new-apks",
        compile_manifest=True,
        javac=os.environ.get("APSA_TEST_JAVAC"),
        environment=dict(os.environ),
        platform=os.environ.get("APSA_TEST_ANDROID_PLATFORM", "android-36"),
        build_tools=os.environ.get("APSA_TEST_ANDROID_BUILD_TOOLS", "36.0.0"),
    )
    frozen = freeze_corpus(args.out / "corpus", args.out / "new-apks")
    benchmark = load_module("fresh_benchmark_engine", ROOT / "benchmarks/run.py")
    result = benchmark.run(frozen)
    result["fresh_fixture_provenance"] = json.loads(
        (args.out / "new-apks/fixture-provenance.json").read_text()
    )
    result["omitted_cases"] = json.loads(frozen.read_text())["omitted_cases"]
    result["regression_contract_passed"] = regression_contract(result)
    result["expected_partial_cases"] = sorted(EXPECTED_PARTIAL_CASES)
    result["observed_partial_cases"] = sorted(
        case["id"] for case in result["cases"] if case["warnings"] or case["incomplete_rules"]
    )
    result["disagreement_case_ids"] = sorted({row["case_id"] for row in result["disagreements"]})
    result["published_baseline_approved"] = False
    (args.out / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    print(
        json.dumps(
            {
                key: result[key]
                for key in (
                    "input_revision",
                    "input_revision_scope",
                    "passed",
                    "regression_contract_passed",
                    "summary",
                    "omitted_cases",
                    "expected_partial_cases",
                    "observed_partial_cases",
                    "disagreement_case_ids",
                    "published_baseline_approved",
                )
            },
            indent=2,
        )
    )
    if args.check_regression_contract:
        return 0 if result["regression_contract_passed"] else 1
    return result["exit_code"]


if __name__ == "__main__":
    sys.exit(main())
