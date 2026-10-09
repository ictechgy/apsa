"""Replay the first independent public captures; no app build or execution."""

from __future__ import annotations

import argparse
import json
import shutil
import statistics
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

from benchmarks.competitive import apsa_observation, apsa_report, engine_metadata
from benchmarks.real_world import (
    MAX_DOCUMENT,
    MAX_DOWNLOAD,
    app_signature,
    compact_apsa,
    dependency_inventory_score,
    sha,
    write_json,
)
from mobile_audit.audit import correlate
from mobile_audit.intel import normalize_cve, parse_apple

HERE = Path(__file__).resolve().parent
TRUTH = HERE / "next_truth.json"
TRUTH_SHA = "b7d297d09997343049de79b79219c86d5c366c5673b2efc90d23ab9e25896bc7"


def evaluate_cves(spec: dict, root: Path) -> list[dict]:
    documents = {d["id"]: d for d in spec["documents"]}
    result = []
    for cve in spec["cves"]:
        raw = (HERE / "primary" / (cve["cve"] + ".json")).read_bytes()
        normalized = normalize_cve(json.loads(raw))
        for case in cve["cases"]:
            doc = documents[case["document"]]
            bulletin = parse_apple((root / (doc["id"] + ".html")).read_bytes(), doc["url"], doc["label"])
            for product in ("ios", "ipados"):
                findings, advisories = correlate(
                    {"dependencies": [], "platforms": ["ios"]},
                    [normalized, *bulletin],
                    {"platform": "ios", "version": case["version"], "os_product": product},
                )
                states = sorted({a["state"] for a in advisories if a["id"] == cve["cve"]})
                expected = "version-affected" if case["expected"] == "affected" else case["expected"]
                result.append(
                    {
                        "id": cve["cve"] + "-" + product + "-" + case["version"],
                        **case,
                        "product": product,
                        "expected_scanner_state": expected,
                        "observed_states": states,
                        "correct": states == [expected],
                        "parsed_bulletin_contains_cve": any(a["id"] == cve["cve"] for a in bulletin),
                        "cna_sha256": sha(raw),
                        "bulletin_sha256": sha((root / (doc["id"] + ".html")).read_bytes()),
                        "finding_statuses": sorted(
                            {f["status"] for f in findings if f.get("cve") == cve["cve"]}
                        ),
                        "reachability": "unknown",
                        "installed_patch_verified": False,
                    }
                )
    return result


FIRST_SHA = "516ce3955c5d5702c3619c0a0f2e657041eeee13f256eba9858f7c6888616b03"


def frozen_copy(path: Path, destination: Path, expected: str, limit: int):
    if path.is_symlink() or not path.is_file() or path.stat().st_size > limit:
        raise ValueError("Frozen holdout input outside bounds")
    if sha(path.read_bytes()) != expected:
        raise ValueError("Frozen holdout input bytes changed")
    shutil.copyfile(path, destination)


def run(root: Path, captured: Path) -> dict:
    if sha(TRUTH.read_bytes()) != TRUTH_SHA:
        raise ValueError("Independent pre-scan truth bytes changed")
    spec = json.loads(TRUTH.read_text())
    original = captured / "summary.json"
    if (
        original.is_symlink()
        or original.stat().st_size > MAX_DOCUMENT
        or sha(original.read_bytes()) != FIRST_SHA
    ):
        raise ValueError("First blind holdout summary changed")
    first = json.loads(original.read_text())
    root.mkdir(exist_ok=False, parents=True)
    captures = []
    apps = []
    for doc in spec["documents"]:
        prior = next(d for d in first["vendor_captures"] if d["id"] == doc["id"])
        frozen_copy(
            captured / (doc["id"] + ".html"), root / (doc["id"] + ".html"), prior["sha256"], MAX_DOCUMENT
        )
        captures.append(prior)
    for app in spec["apps"]:
        prior = next(a for a in first["apps"] if a["id"] == app["id"])
        target = root / (app["id"] + ".zip")
        frozen_copy(captured / target.name, target, prior["input"]["sha256"], MAX_DOWNLOAD)
        provenance = prior["upstream"]
        plists = prior["config"].get("checked_in_info_plists", [])
        prepared = prior["input"]
        signatures = []
        reports = []
        durations = []
        for repeat in range(3):
            report, duration = apsa_report(sys.executable, target, root / f"{app['id']}-{repeat}")
            reports.append(report)
            durations.append(duration)
            signatures.append(sha(app_signature(apsa_observation(report), report).encode()))
        report = reports[0]
        dependencies = dependency_inventory_score(report, app["dependencies"])
        label = app["config_label"]
        if app["id"] == "tusky":
            observed = [
                c.get("cleartext")
                for c in report["inventory"]["android_config"]
                if c["path"].endswith(label["path"])
            ]
            config = {"expected": False, "observed": observed, "correct": observed == ["false"]}
        else:
            config = {
                "expected": "absence-or-unknown",
                "checked_in_info_plists": plists,
                "absence_label_verified": not plists,
                "observed_configurations": report["inventory"].get("ios_config", []),
                "scored": False,
                "reason": "Prepass repository-search absence is provisional, not authoritative negative security truth.",
            }
        apps.append(
            {
                **app,
                "input": prepared,
                "upstream": provenance,
                "config": config,
                "dependencies_scored": dependencies,
                "stable": len(set(signatures)) == 1,
                "repeat_signatures": signatures,
                "seconds": {"runs": durations, "median": statistics.median(durations)},
                "analysis": compact_apsa(report),
                "parser_isolation": report["inventory"].get("parser_isolation"),
            }
        )
    result = {
        "schema": "apsa-next-holdout-result-v1",
        "kind": "development-rerun-after-labels-seen",
        "first_blind_summary_sha256": FIRST_SHA,
        "first_blind_run": 37896002099,
        "truth_sha256": TRUTH_SHA,
        "captured_at": datetime.now(timezone.utc).isoformat(),
        "source_revision": subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip(),
        "engine": engine_metadata(sys.executable),
        "apps": apps,
        "vendor_captures": captures,
        "cve_cases": evaluate_cves(spec, root),
        "scope": "Two selected public-source apps, four dependency versions, one declared cleartext setting and sixteen mobile version/product checks across three CVEs. No exploit reproduction, app execution, comprehensive accuracy or installed-patch assurance.",
    }
    write_json(root / "summary.json", result)
    print("APSA_NEXT_HOLDOUT_BEGIN", flush=True)
    print(json.dumps(result), flush=True)
    print("APSA_NEXT_HOLDOUT_END", flush=True)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--work", type=Path, required=True)
    parser.add_argument("--captured", type=Path, required=True)
    args = parser.parse_args()
    run(args.work, args.captured)


if __name__ == "__main__":
    main()
