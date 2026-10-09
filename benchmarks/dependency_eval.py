"""Score catalog usage and lockfile evidence against the frozen Gradle oracle."""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
from pathlib import Path

from benchmarks.dependency_oracle import extract
from mobile_audit.inputs import inspect_target

HERE = Path(__file__).resolve().parent
TRUTH = HERE / "dependency_truth.json"
LOCKS = HERE / "dependency_locks"


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def catalog_score(truth: dict, dependencies: list[dict]) -> dict:
    found = {
        d["catalog_alias"]: d
        for d in dependencies
        if d.get("catalog_alias") and d["path"] == "gradle/libs.versions.toml"
    }
    counts = dict(tp=0, fp=0, abstained_shipped=0, abstained_not_shipped=0, missing_entry=0)
    versions = dict(agree=0, differ=0)
    rows = []
    for entry in truth["catalog_libraries"]:
        if not isinstance(entry["catalog_version"], str):
            continue
        dep = found.get(entry["alias"])
        if dep is None:
            counts["missing_entry"] += 1
            rows.append({**entry, "observed": None})
            continue
        declared = dep.get("version_source") == "catalog-alias-declared" and dep["confidence"] == "declared"
        key = (
            ("tp" if entry["shipped"] else "fp")
            if declared
            else ("abstained_shipped" if entry["shipped"] else "abstained_not_shipped")
        )
        counts[key] += 1
        if key == "tp":
            versions["agree" if dep["version"] in entry["shipped_versions"] else "differ"] += 1
        rows.append(
            {
                "alias": entry["alias"],
                "module": entry["module"],
                "shipped": entry["shipped"],
                "shipped_versions": entry["shipped_versions"],
                "catalog_version": entry["catalog_version"],
                "outcome": key,
                "usage_state": (dep.get("catalog_usage") or {}).get("state"),
                "references": (dep.get("catalog_usage") or {}).get("references", [])[:3],
            }
        )
    shipped = counts["tp"] + counts["abstained_shipped"]
    return {
        **counts,
        "declared_precision": counts["tp"] / (counts["tp"] + counts["fp"])
        if counts["tp"] + counts["fp"]
        else None,
        "shipped_catalog_coverage": counts["tp"] / shipped if shipped else None,
        "declared_version_matches_resolved": versions,
        "rows": rows,
    }


def lockfile_score(truth: dict, dependencies: list[dict]) -> dict:
    expected = {(c["module"], v) for c in truth["shipped_coordinates"] for v in c["versions"]}
    observed = {
        (d["name"], d["version"])
        for d in dependencies
        if d.get("version_source") == "gradle-lockfile-resolved" and d["confidence"] == "exact"
    }
    superseded = sum(
        1
        for d in dependencies
        if d.get("catalog_alias")
        and (d.get("resolution") or {}).get("state") == "superseded-by-resolved-build"
    )
    return {
        "expected": len(expected),
        "observed": len(observed),
        "missing": sorted(map(list, expected - observed))[:50],
        "unexpected": sorted(map(list, observed - expected))[:50],
        "superseded_catalog_entries": superseded,
    }


def evaluate(truth: dict, archive: Path, work: Path) -> dict:
    if sha(archive.read_bytes()) != truth["archive"]["sha256"]:
        raise ValueError(f"{truth['id']}: source archive does not match the frozen oracle")
    lock = LOCKS / f"{truth['id']}.lockfile"
    if sha(lock.read_bytes()) != truth["lockfile_sha256"]:
        raise ValueError(f"{truth['id']}: committed lockfile does not match the frozen oracle")
    destination = work / truth["id"]
    if destination.exists():
        shutil.rmtree(destination)
    destination.mkdir(parents=True)
    source = extract(archive, destination)
    upstream_locks = sorted(str(p.relative_to(source)) for p in source.rglob("*.lockfile"))
    inventory, _ = inspect_target(source)
    catalog = catalog_score(truth, inventory["dependencies"])
    module_dir = source / truth["module"].strip(":").replace(":", "/")
    shutil.copyfile(lock, module_dir / "gradle.lockfile")
    locked, _ = inspect_target(source)
    return {
        "id": truth["id"],
        "repository": truth["repository"],
        "commit": truth["commit"],
        "upstream_lockfiles": upstream_locks,
        "inventory_partial": inventory["partial"],
        "warnings": inventory["warnings"][:20],
        "catalog_without_lockfile": catalog,
        "baseline_1_2_0_declared": 0,
        "with_oracle_lockfile": lockfile_score(truth, locked["dependencies"]),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--archives", type=Path, required=True)
    parser.add_argument("--work", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    truth = json.loads(TRUTH.read_text())
    results = []
    for case in truth["cases"]:
        archive = next(args.archives.rglob(f"{case['id']}.zip"))
        results.append(evaluate(case, archive, args.work))
    totals = {
        key: sum(r["catalog_without_lockfile"][key] for r in results)
        for key in ("tp", "fp", "abstained_shipped", "abstained_not_shipped", "missing_entry")
    }
    summary = {
        "schema": "apsa-dependency-evidence-results-v1",
        "truth_sha256": sha(TRUTH.read_bytes()),
        "totals": totals,
        "cases": results,
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"totals": totals, "lockfile": [r["with_oracle_lockfile"] for r in results]}, indent=2))


if __name__ == "__main__":
    main()
