"""Actual pinned Gitleaks / OSV Scanner component comparison on fresh inputs.

This is a component benchmark, not a full mobile-scanner ranking. Public OSV
requests require --online. Raw subprocess streams are retained separately;
the summary never includes credential candidate text.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from benchmarks.component_cases import generate
from benchmarks.process_measure import capture
from mobile_audit.inputs import parse_dependencies
from mobile_audit.intel import query_dependencies
from mobile_audit.platform_checks import _secrets
from mobile_audit.store import Store

VERSIONS = {"gitleaks": "8.30.1", "osv-scanner": "2.7.0"}
MAX_REPORT = 1024 * 1024
ACQUISITION_SOURCES = {"scripts/acquire_component_tools.py", "scripts/verify_dependency.py"}


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _write(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def _failed(reason: str, state: str = "failed") -> dict:
    return {"state": state, "detected": None, "reason": reason, "other_findings": []}


def _errors(stderr: str) -> bool:
    clean = re.sub(r"\x1b\[[0-9;]*m", "", stderr)
    return bool(re.search(r"\b(?:ERROR|ERR|FATAL)\b", clean, re.IGNORECASE))


def _path_matches(value: object, expected: Path) -> bool:
    if not isinstance(value, str) or not value:
        return False
    path = Path(value)
    # No filesystem read/resolve: reports may spell the explicit input as either
    # an absolute path or a name relative to the supplied fresh working dir.
    return value == expected.name or (path.is_absolute() and path == expected)


def score(expected: bool, observation: dict) -> str | None:
    if observation.get("state") != "completed" or type(observation.get("detected")) is not bool:
        return None
    return ("TP" if expected else "FP") if observation["detected"] else ("FN" if expected else "TN")


def parse_gitleaks(run: dict, raw: str | None, case: dict, path: Path) -> dict:
    if run.get("incomplete") or run.get("status") not in (0, 10) or _errors(run.get("stderr", "")):
        return _failed("process failed, emitted error diagnostics, or capture incomplete")
    try:
        findings = json.loads(raw) if raw is not None else None
    except (ValueError, RecursionError):
        return _failed("malformed JSON report")
    if not isinstance(findings, list) or len(findings) > 1000:
        return _failed("missing or invalid findings list")
    if (run["status"] == 10) != bool(findings):
        return _failed("exit status disagrees with findings presence")
    observed = []
    for item in findings:
        if not isinstance(item, dict) or not isinstance(item.get("RuleID"), str) or not item["RuleID"]:
            return _failed("invalid finding rule")
        if (
            not _path_matches(item.get("File"), path)
            or type(item.get("StartLine")) is not int
            or item["StartLine"] < 1
        ):
            return _failed("finding path or line does not identify this input")
        observed.append({"rule": item["RuleID"], "path": path.name, "line": item["StartLine"]})
    selected = [
        item for item in observed if item["rule"] == case["gitleaks_rule"] and item["line"] == case["line"]
    ]
    return {
        "state": "completed",
        "detected": bool(selected),
        "matched": selected,
        "other_findings": [item for item in observed if item not in selected],
    }


def parse_osv(run: dict, case: dict, path: Path) -> dict:
    if run.get("incomplete") or run.get("status") not in (0, 1) or _errors(run.get("stderr", "")):
        return _failed("process failed, emitted error diagnostics, or capture incomplete")
    try:
        body = json.loads(run.get("stdout", ""))
    except (ValueError, RecursionError):
        return _failed("malformed JSON report")
    if not isinstance(body, dict) or not isinstance(body.get("results"), list) or len(body["results"]) != 1:
        return _failed("all-packages output must contain exactly the supplied package source")
    source = body["results"][0]
    if (
        not isinstance(source, dict)
        or not isinstance(source.get("source"), dict)
        or not _path_matches(source["source"].get("path"), path)
    ):
        return _failed("package source does not identify this input")
    packages = source.get("packages")
    if not isinstance(packages, list) or len(packages) != 1 or not isinstance(packages[0], dict):
        return _failed("all-packages output omitted or duplicated the supplied package")
    package = packages[0].get("package")
    if (
        not isinstance(package, dict)
        or {key: package.get(key) for key in ("ecosystem", "name", "version")} != case["coordinate"]
    ):
        return _failed("extracted coordinate differs from the frozen input")
    vulns = packages[0].get("vulnerabilities", [])
    if not isinstance(vulns, list):
        return _failed("invalid vulnerability list")
    identifiers = set()
    for vuln in vulns:
        if not isinstance(vuln, dict) or not isinstance(vuln.get("id"), str) or not vuln["id"]:
            return _failed("invalid vulnerability identifier")
        aliases = vuln.get("aliases", [])
        if not isinstance(aliases, list) or any(not isinstance(alias, str) or not alias for alias in aliases):
            return _failed("invalid vulnerability aliases")
        identifiers.update([vuln["id"], *aliases])
    if (run["status"] == 1) != bool(vulns):
        return _failed("exit status disagrees with vulnerability presence")
    target = set(case["target_advisories"])
    return {
        "state": "completed",
        "detected": bool(target & identifiers),
        "coordinate": case["coordinate"],
        "matched": sorted(target & identifiers),
        "other_findings": sorted(identifiers - target),
    }


def apsa_secrets(case: dict, path: Path) -> dict:
    started = time.monotonic()
    findings, coverage = _secrets([(path.name, path.read_text())])
    checked = len(coverage) == 1 and coverage[0].get("state") == "checked"
    selected = []
    other = []
    for finding in findings:
        for evidence in finding.get("evidence", []):
            item = {
                "rule": finding.get("rule_id"),
                "credential_type": evidence.get("credential_type"),
                "path": evidence.get("path"),
                "line": evidence.get("line"),
            }
            if item == {
                "rule": case["apsa_rule"],
                "credential_type": case["credential_type"],
                "path": path.name,
                "line": case["line"],
            }:
                selected.append(item)
            else:
                other.append(item)
    return {
        "state": "completed" if checked else "partial",
        "detected": bool(selected) if checked else None,
        "matched": selected,
        "other_findings": other,
        "coverage": coverage,
        "seconds": time.monotonic() - started,
        "timing_scope": "in-process format check plus explicit input read",
        "rss": {"state": "unmeasured", "sampled_max_rss_bytes": None},
    }


def parse_apsa_osv(case: dict, findings: list, errors: list, states: list) -> dict:
    complete = (
        not errors
        and len(states) == 1
        and isinstance(states[0], dict)
        and {key: states[0].get(key) for key in ("ecosystem", "name", "version")} == case["coordinate"]
        and states[0].get("state") == "complete"
        and states[0].get("checked") is True
        and states[0].get("transmitted") is True
    )
    if any(
        not isinstance(item, dict)
        or item.get("query_match") != case["coordinate"]
        or any(not isinstance(item.get(field), str) or not item[field] for field in ("id", "osv_id"))
        for item in findings
    ):
        return _failed("APSA finding does not bind an advisory to the supplied coordinate")
    identifiers = {
        item[field] for item in findings for field in ("id", "osv_id") if isinstance(item.get(field), str)
    }
    target = set(case["target_advisories"])
    return {
        "state": "completed" if complete else "partial",
        "detected": bool(target & identifiers) if complete else None,
        "coordinate": case["coordinate"],
        "matched": sorted(target & identifiers),
        "other_findings": sorted(identifiers - target),
        "package_states": states,
        "errors": errors,
    }


def apsa_osv(case: dict, path: Path, directory: Path) -> dict:
    started = time.monotonic()
    dependencies = parse_dependencies("sbom.json", path.read_bytes())
    coordinates = [{key: dep.get(key) for key in ("ecosystem", "name", "version")} for dep in dependencies]
    if coordinates != [case["coordinate"]]:
        return _failed("APSA extracted coordinate differs from the frozen input")
    store = Store(directory / "fresh-store")
    states: list[dict] = []
    try:
        findings, errors = query_dependencies(store, dependencies, query_mode="legacy", package_states=states)
        _write(
            directory / "apsa-osv-response.json",
            {"findings": findings, "errors": errors, "package_states": states, "feeds": store.feeds()},
        )
    finally:
        store.db.close()
    return parse_apsa_osv(case, findings, errors, states) | {
        "seconds": time.monotonic() - started,
        "timing_scope": "in-process input extraction, fresh SQLite, and live public OSV query",
        "rss": {"state": "unmeasured", "sampled_max_rss_bytes": None},
    }


def _capture(
    argv: list[str], directory: Path, environment: dict[str, str], name: str, timeout: int = 120
) -> dict:
    result = capture(argv, directory, environment, timeout)
    for stream in ("stdout", "stderr"):
        (directory / f"{name}.{stream}.txt").write_text(result[stream])
    _write(
        directory / f"{name}.execution.json",
        {key: value for key, value in result.items() if key not in ("stdout", "stderr")},
    )
    return result


def _version_matches(tool: str, output: str) -> bool:
    if tool == "gitleaks":
        return output.strip() in {VERSIONS[tool], "v" + VERSIONS[tool]}
    return bool(
        re.search(r"(?im)^\s*(?:osv-scanner\s+)?version:\s*v?" + re.escape(VERSIONS[tool]) + r"\s*$", output)
    )


def verify_source_manifest(manifest: dict, source_root: Path) -> None:
    commit = manifest.get("source_commit")
    if not isinstance(commit, str) or not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise ValueError("Acquisition source commit is missing or malformed")
    if os.environ.get("GITHUB_SHA", commit) != commit:
        raise ValueError("Acquisition source commit differs from the running CI commit")
    hashes = manifest.get("source_sha256")
    if not isinstance(hashes, dict) or set(hashes) != ACQUISITION_SOURCES:
        raise ValueError("Acquisition source bindings are missing or unexpected")
    if any(sha256(source_root / name) != digest for name, digest in hashes.items()):
        raise ValueError("Acquisition source differs from its recorded digest")
    for function, name in (
        (_secrets, "platform_checks.py"),
        (parse_dependencies, "inputs.py"),
        (query_dependencies, "intel.py"),
        (Store.__init__, "store.py"),
    ):
        if (
            Path(function.__code__.co_filename).resolve()
            != (source_root / "src/mobile_audit" / name).resolve()
        ):
            raise ValueError("Imported APSA implementation is outside the bound source tree")


def verify_tools(manifest: dict, directory: Path, environment: dict[str, str]) -> dict:
    if manifest.get("schema_version") != 1 or not isinstance(manifest.get("tools"), dict):
        raise ValueError("Invalid acquisition manifest")
    verified = {}
    for name, version in VERSIONS.items():
        entry = manifest["tools"].get(name)
        if not isinstance(entry, dict) or entry.get("version") != version:
            raise ValueError(f"Unexpected {name} manifest version")
        path = Path(entry.get("path", ""))
        if (
            not path.is_absolute()
            or path.is_symlink()
            or not path.is_file()
            or sha256(path) != entry.get("sha256")
        ):
            raise ValueError(f"{name} executable does not match acquisition digest")
        invocation = [str(path), "version" if name == "gitleaks" else "--version"]
        version_run = _capture(invocation, directory, environment, name + "-version", 30)
        if (
            version_run["status"] != 0
            or version_run["incomplete"]
            or not _version_matches(name, version_run["stdout"] + version_run["stderr"])
        ):
            raise ValueError(f"{name} executable version verification failed")
        verified[name] = {
            **entry,
            "version_verified": True,
            "version_output": (version_run["stdout"] + version_run["stderr"]).strip(),
        }
    return verified


def summarize(trials: list[dict], repetitions: int) -> dict:
    grouped: dict[str, list[dict]] = {}
    for trial in trials:
        grouped.setdefault(trial["tool"], []).append(trial)
    output = {}
    for tool, values in grouped.items():
        cases = {}
        for trial in values:
            cases.setdefault(trial["case"], []).append(trial)
        counts = {key: 0 for key in ("TP", "TN", "FP", "FN")}
        excluded = 0
        stability = {}
        for case, repeated in cases.items():
            signatures = {
                (
                    item["observation"]["state"],
                    item["observation"].get("detected"),
                    tuple(sorted(str(value) for value in item["observation"].get("matched", []))),
                    tuple(sorted(str(value) for value in item["observation"].get("other_findings", []))),
                )
                for item in repeated
            }
            stable = len(repeated) == repetitions and len(signatures) == 1
            stability[case] = stable
            classification = repeated[0]["classification"] if stable else None
            if classification is None:
                excluded += 1
            else:
                counts[classification] += 1
        output[tool] = {
            "case_counts": counts,
            "excluded_cases": excluded,
            "repetitions": repetitions,
            "stable": all(stability.values()),
            "case_stability": stability,
            "trial_count": len(values),
        }
    return output


def run(manifest_path: Path, output: Path, repetitions: int, online: bool) -> dict:
    if not online:
        raise ValueError("--online is required for live public OSV queries")
    if not output.is_absolute() or output.exists() or not 1 <= repetitions <= 10:
        raise ValueError("Use a new absolute output directory and 1..10 repetitions")
    output.mkdir(parents=True, exist_ok=False)
    environment = {
        key: value
        for key, value in os.environ.items()
        if key in {"PATH", "SYSTEMROOT", "SSL_CERT_FILE", "SSL_CERT_DIR"}
    }
    for key in ("HOME", "XDG_CONFIG_HOME", "XDG_CACHE_HOME", "TMPDIR"):
        directory = output / ("env-" + key.lower())
        directory.mkdir()
        environment[key] = str(directory)
    environment["NO_COLOR"] = "1"
    manifest = json.loads(manifest_path.read_text())
    source_root = Path(__file__).absolute().parent.parent
    verify_source_manifest(manifest, source_root)
    tools = verify_tools(manifest, output, environment)
    source_paths = [
        source_root / "benchmarks" / name
        for name in ("component_cases.py", "component_compare.py", "process_measure.py")
    ]
    source_paths += sorted((source_root / "src" / "mobile_audit").glob("*.py"))
    source_paths += [source_root / name for name in sorted(ACQUISITION_SOURCES)]
    source_hashes = {str(path.relative_to(source_root)): sha256(path) for path in source_paths}
    cases = generate(output / "inputs")
    labels_hash = sha256(output / "inputs" / "labels.json")
    _write(
        output / "preflight.json",
        {
            "source_commit": manifest.get("source_commit"),
            "source_sha256": source_hashes,
            "labels_sha256": labels_hash,
            "tools": tools,
            "manifest_sha256": sha256(manifest_path),
            "started": datetime.now(timezone.utc).isoformat(),
        },
    )
    trials = []
    for case in cases:
        path = output / "inputs" / case["id"] / case["path"]
        for repetition in range(repetitions):
            for tool in case["supported"]:
                directory = output / "trials" / case["id"] / str(repetition) / tool
                directory.mkdir(parents=True)
                if sha256(path) != case["sha256"]:
                    raise ValueError("Frozen benchmark input changed")
                try:
                    if tool == "apsa-secrets":
                        observation = apsa_secrets(case, path)
                    elif tool == "apsa-osv":
                        observation = apsa_osv(case, path, directory)
                    else:
                        if sha256(Path(tools[tool]["path"])) != tools[tool]["sha256"]:
                            raise ValueError("Executable changed after preflight")
                        if tool == "gitleaks":
                            report = directory / "findings.json"
                            argv = [
                                tools[tool]["path"],
                                "dir",
                                str(path.parent),
                                "--no-banner",
                                "--redact=100",
                                "--exit-code=10",
                                "--report-format=json",
                                "--report-path=" + str(report),
                            ]
                            execution = _capture(argv, directory, environment, tool)
                            raw = (
                                report.read_text()
                                if report.is_file() and report.stat().st_size <= MAX_REPORT
                                else None
                            )
                            observation = parse_gitleaks(execution, raw, case, path)
                        else:
                            argv = [
                                tools[tool]["path"],
                                "scan",
                                "source",
                                "--format=json",
                                "--all-packages",
                                "--no-resolve",
                                "--no-call-analysis=go",
                                "--lockfile=" + str(path),
                            ]
                            execution = _capture(argv, directory, environment, tool)
                            observation = parse_osv(execution, case, path)
                        observation.update(
                            seconds=execution["seconds"],
                            rss=execution["rss"],
                            timing_scope="subprocess lifetime including CLI startup and live queries where applicable",
                            exit_status=execution["status"],
                            incomplete=execution["incomplete"],
                        )
                except Exception as error:
                    # Avoid exposing tool stdout or candidate text in exceptions.
                    observation = _failed("execution raised " + type(error).__name__)
                    (directory / "exception.txt").write_text(type(error).__name__ + "\n")
                trial = {
                    "case": case["id"],
                    "tool": tool,
                    "repetition": repetition,
                    "expected": case["expected"],
                    "input_sha256": case["sha256"],
                    "observation": observation,
                    "classification": score(case["expected"], observation),
                }
                _write(directory / "observation.json", trial)
                trials.append(trial)
    if labels_hash != sha256(output / "inputs" / "labels.json") or any(
        sha256(output / "inputs" / case["id"] / case["path"]) != case["sha256"] for case in cases
    ):
        raise ValueError("Frozen inputs or labels changed during execution")
    if any(sha256(source_root / name) != digest for name, digest in source_hashes.items()):
        raise ValueError("Benchmark source changed during execution")
    summary = {
        "schema_version": 1,
        "source_commit": manifest.get("source_commit"),
        "source_sha256": source_hashes,
        "tools": tools,
        "labels_sha256": labels_hash,
        "cases": cases,
        "trials": trials,
        "scores": summarize(trials, repetitions),
        "completed": datetime.now(timezone.utc).isoformat(),
        "limitations": [
            "12 predeclared synthetic component cases, not a full mobile-scanner ranking or independent holdout",
            "Secret candidates are generated format strings; no credential validity checked or claimed",
            "Dependency negatives concern one target advisory only, not all CVEs",
            "OSV results reflect the live public feed at execution time",
            "APSA in-process and tool CLI timing scopes differ; no efficiency ranking",
            "Unmeasured, partial, failed and unstable cases excluded from scoring",
        ],
    }
    _write(output / "summary.json", summary)
    _write(
        output / "checksums.json",
        {
            str(path.relative_to(output)): sha256(path)
            for path in sorted(output.rglob("*"))
            if path.is_file()
            and "fresh-store" not in path.parts
            and not any(part.startswith("env-") for part in path.parts)
        },
    )
    return summary


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tools", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--repetitions", type=int, default=3)
    parser.add_argument("--online", action="store_true")
    args = parser.parse_args()
    summary = run(args.tools, args.out, args.repetitions, args.online)
    print("APSA_COMPONENT_BENCHMARK=" + json.dumps(summary, sort_keys=True, separators=(",", ":")))
    if any(item["excluded_cases"] or not item["stable"] for item in summary["scores"].values()):
        sys.exit(1)


if __name__ == "__main__":
    main()
