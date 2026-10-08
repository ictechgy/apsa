from __future__ import annotations

import copy
import re
from collections.abc import Callable
from pathlib import Path

from packaging.version import InvalidVersion, Version

from . import __version__
from .core import (
    RULE_VERSION,
    canonical_json,
    finding,
    finding_identity,
    now,
    report_incomplete,
    severity_rank,
    uid,
)
from .engine import analyze_target
from .intel import query_dependencies, source_health
from .store import Store


def in_cve_range(version: str, affected: dict) -> bool | None:
    """Only interpret explicit ranges we can compare. An unknown range stays unknown."""
    try:
        current = Version(version)
    except InvalidVersion:
        return None
    decisions = []
    for entry in affected.get("versions", []):
        status = entry.get("status", "unknown")
        if status not in {"affected", "unaffected"}:
            continue
        lower = entry.get("version", "")
        upper = entry.get("lessThan") or entry.get("lessThanOrEqual")
        if lower in {"unspecified", "n/a", "*"} or upper == "*" or entry.get("changes"):
            continue
        # Vendor-defined custom orderings and version branches cannot be guessed.
        if entry.get("versionType", "semver") not in {"semver", "python", "version"} and upper:
            continue
        try:
            start = Version(lower)
            if upper:
                end = Version(upper)
                matches = current >= start and (
                    current <= end if "lessThanOrEqual" in entry else current < end
                )
            else:
                matches = current == start
        except InvalidVersion:
            continue
        if matches:
            decisions.append(status == "affected")
    if decisions:
        return decisions[0] if all(d == decisions[0] for d in decisions) else None
    # Don't infer unaffected from an incomplete list or an unparseable range.
    return None


def os_cve_coverage(environment: dict | None, advisories: list[dict], feeds: list[dict]) -> dict:
    """Correlation can run against a bounded cache without claiming catalog completeness."""
    platform = (environment or {}).get("platform")
    source = {"android": "android", "ios": "apple"}.get(platform or "")
    feed = next((f for f in feeds if f["source"] == source), None)
    observed = bool(environment) and any(a["platform"] == platform for a in advisories)
    available = bool(feed and feed["status"] == "ok" and not feed["stale"])
    return {
        "rule_id": "OS-CVE",
        "state": "partial" if environment and (observed or available) else "not-run",
        "method": "vendor advisory/environment correlation",
        "collection_scope": "bounded-recent-window",
        "historical_backfill_complete": False,
        "feed_status": feed["status"] if feed else "unavailable",
        "note": "Correlation uses a bounded recent advisory cache, not a complete historical catalog. Feed freshness does not prove historical completeness. Not a platform exploit test; component/backport applicability may remain unknown.",
    }


def correlate(
    inventory: dict, records: list[dict], environment: dict | None = None
) -> tuple[list[dict], list[dict]]:
    findings = []
    advisories = []
    known = {r["id"] for r in records if r.get("known_exploited")}
    rejected = {r["id"] for r in records if r.get("state") == "REJECTED"}
    for record in records:
        if record["id"] in rejected or record.get("withdrawn"):
            continue
        dep = record.get("query_match")
        if dep:
            for current in inventory["dependencies"]:
                if (dep["name"], dep["ecosystem"], dep["version"]) != (
                    current["name"],
                    current["ecosystem"],
                    current["version"],
                ):
                    continue
                findings.append(
                    finding(
                        record["id"],
                        record["title"],
                        max(
                            (record.get("severity") or "medium", "high" if record["id"] in known else "info"),
                            key=severity_rank,
                        ),
                        "version-affected" if current.get("confidence") == "exact" else "candidate",
                        [
                            {
                                "dependency": current,
                                "basis": "OSV package/version query",
                                "advisory_id": record.get("osv_id"),
                                "intel_snapshot_hash": record.get("snapshot_hash"),
                                "advisory_modified": record.get("modified"),
                            }
                        ],
                        "Upgrade to a vendor-fixed dependency release, then rescan the actual build and test the affected feature.",
                        "MASVS-CODE",
                        record.get("references", []),
                        known_exploited=record["id"] in known,
                        reachability="unknown",
                        reproduced=False,
                        origin="intelligence",
                        severity_basis=record.get("severity_basis", "unknown"),
                    )
                )
        platform = record.get("platform")
        if platform not in inventory["platforms"]:
            continue
        state = "device-info-required"
        basis = "OS advisory; application files cannot establish installed platform patch state."
        if environment and environment.get("platform") == platform:
            if environment.get("simulator"):
                state = "simulator-only"
                basis = "Simulator observations cannot establish the security patch state of physical iOS devices."
            elif platform == "android" and record.get("fixed_patch_level"):
                actual = environment.get("security_patch", "")
                versions = record.get("updated_aosp_versions", "")
                release = environment.get("version", "").split(".")[0]
                if re.fullmatch(r"20\d\d-\d\d-\d\d", actual):
                    if actual >= record["fixed_patch_level"]:
                        state = "vendor-patch-level-satisfied"
                    elif release and release in re.findall(r"\b\d+\b", versions):
                        state = "potentially-affected"
                    else:
                        state = "applicability-unknown"
                    basis = "Observed Android security patch level; old patch level alone does not prove this component is vulnerable."
            elif platform == "ios":
                cve = next((r for r in records if r["id"] == record["id"] and r["source"] == "cve"), None)
                decisions = []
                for product in (cve or {}).get("affected", []):
                    if product.get("product", "").lower() in {"ios", "ipados", "iphone os"}:
                        decisions.append(in_cve_range(environment.get("version", ""), product))
                if True in decisions:
                    state = "version-affected"
                elif decisions and all(d is False for d in decisions):
                    state = "outside-published-affected-range"
                else:
                    state = "applicability-unknown"
                basis = "Observed iOS version compared with explicit CNA ranges where supported; fixed-release labels are not used as universal lower bounds."
        entry = {
            "id": record["id"],
            "title": record["title"],
            "component": record.get("component", ""),
            "platform": platform,
            "fixed_release": record.get("fixed_release", ""),
            "fixed_patch_level": record.get("fixed_patch_level", ""),
            "updated_aosp_versions": record.get("updated_aosp_versions", ""),
            "state": state,
            "known_exploited": record["id"] in known,
            "exploitation_reported": record.get("exploitation_reported", False),
            "references": record.get("references", []),
            "basis": basis,
            "intel_snapshot_hash": record.get("snapshot_hash"),
            "environment": environment if environment and environment.get("platform") == platform else None,
        }
        advisories.append(entry)
        if state == "version-affected":
            findings.append(
                finding(
                    "OS-" + record["id"],
                    "Observed OS version is in a published affected range: " + record["id"],
                    "high",
                    "version-affected",
                    [
                        {
                            "id": entry["id"],
                            "platform": platform,
                            "component": entry["component"],
                            "state": state,
                            "basis": basis,
                            "environment": entry["environment"],
                            "advisory_branches": [entry],
                        }
                    ],
                    "Apply the vendor's fixed OS release. Review component applicability; this is version correlation, not exploit reproduction.",
                    "MASVS-CODE",
                    record.get("references", []),
                    origin="intelligence",
                    scope="environment",
                    reachability="unknown",
                    reproduced=False,
                )
            )
    # Deduplicate only identical branch evidence; each snapshot owns its references.
    unique = {}
    for entry in advisories:
        key = (
            entry["id"],
            entry["state"],
            entry["platform"],
            entry["component"],
            entry["fixed_release"],
            entry["fixed_patch_level"],
            entry["updated_aosp_versions"],
            entry["intel_snapshot_hash"],
        )
        if key in unique:
            unique[key]["references"] = sorted(set(unique[key]["references"] + entry["references"]))
        else:
            unique[key] = entry
    unique_findings = {}
    for item in findings:
        previous = unique_findings.get(item["id"])
        if previous and item.get("scope") == "environment":
            # Keep one location per platform/component for stable finding IDs
            # and baselines, with every branch snapshot nested in its evidence.
            branches = {
                canonical_json(branch): branch
                for branch in (
                    previous["evidence"][0]["advisory_branches"] + item["evidence"][0]["advisory_branches"]
                )
            }
            previous["evidence"][0]["advisory_branches"] = [branches[key] for key in sorted(branches)]
            previous["references"] = sorted(set(previous["references"] + item["references"]))
        else:
            unique_findings[item["id"]] = item
    return list(unique_findings.values()), list(unique.values())


def summarize(report: dict) -> dict:
    return {
        "findings": len(report["findings"]),
        "confirmed": sum(
            f["status"] in {"runtime-confirmed", "configuration-confirmed"} for f in report["findings"]
        ),
        "candidates": sum(f["status"] == "candidate" for f in report["findings"]),
        "version_affected": sum(f["status"] == "version-affected" for f in report["findings"]),
        "not_run": sum(c["state"] == "not-run" for c in report["coverage"]),
        "environment_advisories": len(report.get("environment_advisories", [])),
        "warnings": len(report.get("warnings", [])),
        "partial": sum(c["state"] == "partial" for c in report["coverage"]),
        "incomplete": report_incomplete(report),
    }


def scan(
    store: Store,
    target: Path,
    online=False,
    sbom: Path | None = None,
    environment: dict | None = None,
    progress: Callable[[str, int], None] | None = None,
    expected_target: Path | None = None,
) -> dict:
    if progress:
        progress("input-analysis", 5)
    if environment:
        if environment.get("platform") not in {"android", "ios"}:
            raise ValueError("Device info requires platform: android or ios")
        environment = {
            k: v
            for k, v in environment.items()
            if k
            in {
                "platform",
                "version",
                "security_patch",
                "webview_version",
                "model",
                "simulator",
                "observed_at",
            }
        }
    analyzed = analyze_target(target, sbom, expected_target)
    inventory, findings, coverage = analyzed["inventory"], analyzed["findings"], analyzed["coverage"]
    if progress:
        progress("dependency-intelligence" if online else "cached-intelligence", 50)
    warnings = inventory["warnings"].copy()
    failures = []
    if online:
        _, failures = query_dependencies(store, inventory["dependencies"])
        warnings.extend(failures)
    records = store.intelligence(limit=100000)
    feeds = source_health(store)
    feed_map = {f["source"]: f for f in feeds}
    for dep in inventory["dependencies"]:
        key = f"osv:{dep['ecosystem']}:{dep['name']}:{dep['version']}"
        health = feed_map.get(key)
        coverage.append(
            {
                "rule_id": "DEPENDENCY-CVE",
                "dependency": dep,
                "state": "checked"
                if health and health["status"] == "ok" and not health["stale"]
                else "not-run",
                "method": "OSV exact package/version query",
                "note": "Declared source versions may differ from the built artifact. Reachability is not inferred from version matching.",
            }
        )
    if not inventory["dependencies"]:
        coverage.append(
            {
                "rule_id": "DEPENDENCY-CVE",
                "state": "not-run",
                "method": "dependency inventory",
                "note": "No exact dependencies identified. Supply a CycloneDX SBOM or dependency lock files.",
            }
        )
    intel_findings, advisories = correlate(inventory, records, environment)
    if progress:
        progress("evidence-report", 85)
    findings.extend(intel_findings)
    coverage.append(os_cve_coverage(environment, advisories, feeds))
    if not records:
        warnings.append("No cached intelligence. Run intel sync; offline scan did not check current CVEs.")
    if any(f["stale"] or f["status"] != "ok" for f in feeds):
        warnings.append("Some intelligence sources are stale or failed. Inspect intel status for coverage.")
    report = {
        "schema_version": 2,
        "tool_version": __version__,
        "id": uid("audit"),
        "created": now(),
        "target": inventory["target"],
        "requested_target": str(target.expanduser().absolute()),
        "rule_version": RULE_VERSION,
        "inventory": inventory,
        "findings": sorted(findings, key=lambda f: -severity_rank(f["severity"])),
        "coverage": coverage,
        "environment_advisories": advisories,
        "intel_snapshot": feeds,
        "environment": environment,
        "warnings": warnings,
        "runtime": [],
        "online_query": {"requested": bool(online), "errors": failures},
        "scope": "Targeted OWASP-aligned checks; not exhaustive MASVS certification or undisclosed-zero-day detection.",
    }
    report["summary"] = summarize(report)
    return store.save_report(report)


def refresh_report(store: Store, report_id: str, *, save=True) -> dict:
    previous = store.report(report_id)
    report = copy.deepcopy(previous)
    report["id"] = uid("audit")
    report["created"] = now()
    report["parent_report"] = previous["id"]
    report["findings"] = [
        f
        for f in report["findings"]
        if f.get("origin") != "intelligence"
        and not f["rule_id"].startswith(("CVE-", "GHSA-", "OSV-", "OS-CVE-"))
    ]
    records = store.intelligence(limit=100000)
    current, advisories = correlate(report["inventory"], records, report.get("environment"))
    report["findings"].extend(current)
    report["findings"].sort(key=lambda f: -severity_rank(f["severity"]))
    report["environment_advisories"] = advisories
    report["intel_snapshot"] = source_health(store)
    health = {f["source"]: f for f in report["intel_snapshot"]}
    for check in report["coverage"]:
        if check["rule_id"] == "DEPENDENCY-CVE" and check.get("dependency"):
            dep = check["dependency"]
            feed = health.get(f"osv:{dep['ecosystem']}:{dep['name']}:{dep['version']}")
            check["state"] = "checked" if feed and feed["status"] == "ok" and not feed["stale"] else "not-run"
        elif check["rule_id"] == "OS-CVE":
            check.update(os_cve_coverage(report.get("environment"), advisories, report["intel_snapshot"]))
    report["warnings"] = [
        w
        for w in report["warnings"]
        if not w.startswith(("No cached intelligence.", "Some intelligence sources"))
    ]
    if not records:
        report["warnings"].append(
            "No cached intelligence. Run intel sync; offline scan did not check current CVEs."
        )
    if any(f["stale"] or f["status"] != "ok" for f in report["intel_snapshot"]):
        report["warnings"].append(
            "Some intelligence sources are stale or failed. Inspect intel status for coverage."
        )
    report["summary"] = summarize(report)
    return store.save_report(report) if save else report


def compare(store: Store, before: str, after: str) -> dict:
    a, b = store.report(before), store.report(after)

    def key(f):
        return finding_identity(f["rule_id"], f["evidence"], f.get("scope", "app"))

    left, right = {key(f): f for f in a["findings"]}, {key(f): f for f in b["findings"]}
    return {
        "before": a["id"],
        "after": b["id"],
        "added": [right[k] for k in right.keys() - left.keys()],
        "no_longer_observed": [left[k] for k in left.keys() - right.keys()],
        "unchanged": sum(
            (left[k]["status"], left[k]["severity"]) == (right[k]["status"], right[k]["severity"])
            for k in left.keys() & right.keys()
        ),
        "changed": [
            {"before": left[k], "after": right[k]}
            for k in sorted(left.keys() & right.keys())
            if (left[k]["status"], left[k]["severity"]) != (right[k]["status"], right[k]["severity"])
        ],
        "coverage_before": a["coverage"],
        "coverage_after": b["coverage"],
        "note": "No longer observed means absent from this scan, not proof of remediation. Compare input and coverage before closing a finding.",
    }
