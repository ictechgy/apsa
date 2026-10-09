"""First scan of independently labeled public snapshots; no app build or execution."""

from __future__ import annotations

import argparse
import json
import statistics
import subprocess
import sys
import zipfile
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath

import httpx

from benchmarks.competitive import apsa_observation, apsa_report, engine_metadata
from benchmarks.real_world import (
    MAX_DOCUMENT,
    MAX_DOWNLOAD,
    app_signature,
    compact_apsa,
    dependency_inventory_score,
    download,
    sha,
    source_archive,
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


def run(root: Path) -> dict:
    if sha(TRUTH.read_bytes()) != TRUTH_SHA:
        raise ValueError("Independent pre-scan truth bytes changed")
    spec = json.loads(TRUTH.read_text())
    root.mkdir(exist_ok=False, parents=True)
    captures = []
    apps = []
    with httpx.Client(timeout=90, headers={"User-Agent": "APSA-public-holdout"}) as client:
        for doc in spec["documents"]:
            captures.append(
                {"id": doc["id"], **download(client, doc["url"], root / (doc["id"] + ".html"), MAX_DOCUMENT)}
            )
        for app in spec["apps"]:
            upstream = root / (app["id"] + "-upstream.zip")
            provenance = download(
                client,
                f"https://codeload.github.com/{app['repository']}/zip/{app['commit']}",
                upstream,
                MAX_DOWNLOAD,
            )
            # Source-only names independently check the reviewer's provisional absence label.
            with zipfile.ZipFile(upstream) as archive:
                plists = sorted(
                    str(PurePosixPath(*PurePosixPath(i.filename).parts[1:]))
                    for i in archive.infolist()
                    if i.filename.endswith("/Info.plist")
                )
            target = root / (app["id"] + ".zip")
            prepared = source_archive(upstream, target, app)
            upstream.unlink()
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
        "kind": "first-scan-with-independent-pre-scan-labels",
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
    run(parser.parse_args().work)


if __name__ == "__main__":
    main()
