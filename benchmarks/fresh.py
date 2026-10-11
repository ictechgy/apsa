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
EXPECTED_PARTIAL_CASES = {"java-cross-function-irrelevant"}
BINARY_CONTROLS = {"dex-unsafe": "unsafe", "dex-safe": "safe"}


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


def regression_contract(result: dict) -> bool:
    """Known incomplete analysis remains partial; any new disagreement fails."""
    partial = {case["id"] for case in result["cases"] if case["warnings"] or case["incomplete_rules"]}
    return (
        result["summary"]["fp"] == result["summary"]["fn"] == 0
        and all(case["error"] is None for case in result["cases"])
        and partial == EXPECTED_PARTIAL_CASES
        and {row["case_id"] for row in result["disagreements"]} == EXPECTED_PARTIAL_CASES
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
    result["published_baseline_approved"] = False
    (args.out / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    print(
        json.dumps(
            {
                key: result[key]
                for key in (
                    "passed",
                    "regression_contract_passed",
                    "summary",
                    "omitted_cases",
                    "expected_partial_cases",
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
