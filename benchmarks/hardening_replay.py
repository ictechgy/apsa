"""Development replay of the original public corpus; never recapture its inputs."""

from __future__ import annotations

import argparse
import json
import shutil
import sys
from pathlib import Path

import httpx

from benchmarks.real_world import OSVTransport, read_prepared, run, sha, write_json

INITIAL_SHA = "a08769d89866515d3af1e772260cb944b970746f2599e77415a39c77747b2d32"
INPUT_SHA = "190a6798ad094e3f2ff65c57e9d4cfa253db0cce28ab4d2e308d5cfb6d213e1e"
OSV_SHA = "6e6fbb050eddfdf5c30b6a424e6d325946235ff18565695d3503e81f96c5fb10"
SUPPLEMENT = {"package": {"name": "org.jsoup:jsoup", "ecosystem": "Maven"}, "version": "1.15.1"}


def replay(artifact: Path, work: Path, output: Path, python: str) -> dict:
    initial_path = artifact / "public-real-world-results/summary.json"
    if sha(initial_path.read_bytes()) != INITIAL_SHA:
        raise ValueError("Original result bytes changed")
    original = json.loads(initial_path.read_text())
    fixtures = artifact / "public-real-world"
    read_prepared(fixtures)
    if sha((fixtures / "manifest.json").read_bytes()) != INPUT_SHA:
        raise ValueError("Original input manifest changed")
    base_path = fixtures / "osv/manifest.json"
    if sha(base_path.read_bytes()) != OSV_SHA:
        raise ValueError("Original OSV manifest changed")
    base = json.loads(base_path.read_text())
    for entry in base["responses"]:
        raw = (fixtures / "osv" / (entry["key"] + ".json")).read_bytes()
        if sha(raw) != entry["sha256"] or len(raw) != entry["bytes"]:
            raise ValueError("Original OSV response changed")
    shutil.copytree(fixtures, work)
    shutil.copyfile(initial_path, work / "original-summary.json")
    shutil.copyfile(base_path, work / "original-osv-manifest.json")
    # One new version becomes queryable after extraction repair. Capture only it
    # in a separate namespace; every original response remains byte-for-byte.
    supplement_root = work / "supplemental-osv"
    transport = OSVTransport(supplement_root, capture=True)
    try:
        request = httpx.Request("POST", "https://api.osv.dev/v1/query", json=SUPPLEMENT)
        response = transport.handle(request)
        response.raise_for_status()
    finally:
        transport.close()
    supplement = json.loads((supplement_root / "manifest.json").read_text())
    entries = supplement["responses"]
    if len(entries) != 1 or entries[0]["payload"] != SUPPLEMENT:
        raise ValueError("Supplement exceeded its fixed public query scope")
    if entries[0]["key"] in {entry["key"] for entry in base["responses"]}:
        raise ValueError("Supplement must not replace an original capture")
    shutil.copyfile(
        supplement_root / (entries[0]["key"] + ".json"), work / "osv" / (entries[0]["key"] + ".json")
    )
    write_json(work / "osv/manifest.json", {**base, "responses": [*base["responses"], *entries]})
    result = run(work, output, python, repeats=3, mobsf=None, capture_osv=False)
    result["replay_provenance"] = {
        "kind": "development-rerun-after-labels-seen",
        "original_run_id": 37879443007,
        "original_source_revision": original["source_revision"],
        "original_summary_sha256": INITIAL_SHA,
        "original_input_manifest_sha256": INPUT_SHA,
        "original_osv_manifest_sha256": OSV_SHA,
        "supplemental_osv_manifest_sha256": sha((supplement_root / "manifest.json").read_bytes()),
        "supplemental_osv": supplement,
        "comparator": "APSA only; original MobSF observations were not rerun",
    }
    write_json(output / "summary.json", result)
    if sha(initial_path.read_bytes()) != INITIAL_SHA or sha(base_path.read_bytes()) != OSV_SHA:
        raise ValueError("Replay mutated original evidence")
    print("APSA_HARDENING_RESULT_BEGIN", flush=True)
    print(json.dumps(result), flush=True)
    print("APSA_HARDENING_RESULT_END", flush=True)
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifact", type=Path, required=True)
    parser.add_argument("--work", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    replay(args.artifact, args.work, args.out, sys.executable)


if __name__ == "__main__":
    main()
