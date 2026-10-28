"""Deterministic, read-only finding continuity between supplied report snapshots.

Hashes identify supplied documents, not authentic or fresh scan executions. Even
comparable absence is an observation, never proof that remediation succeeded.
"""

from __future__ import annotations

import json
import re

from .completeness import report_incomplete
from .core import canonical_json, digest
from .maswe import RULE_WEAKNESSES, UNMAPPED
from .verify import COVERAGE_ALIASES, SOURCE_SUFFIXES, compare_reports

MAX_OUTPUT_BYTES = 65536
ANCHORS = ("function", "class", "method", "sink", "sink_api")
CONFIG_RULES = {
    "ANDROID-DEBUG",
    "ANDROID-CLEARTEXT",
    "ANDROID-EXPORTED-COMPONENT",
    "ANDROID-ALLOW-BACKUP",
    "ANDROID-TARGET-SDK",
    "ANDROID-DEEPLINK-AUTOVERIFY",
    "IOS-ATS",
    "IOS-ATS-EXCEPTION",
}
UNSUPPORTED_EVIDENCE_LOCI = {
    "IOS-PRIVACY-MANIFEST": {
        "analysis": "privacy-manifest-and-source",
        "next_step": "validate-privacy-manifest-declarations-and-api-use",
    },
    "ANDROID-NSC-USER-CA": {
        "analysis": "resolved-network-security-resource",
        "next_step": "validate-resolved-network-security-resources",
    },
}
BUILTIN_ORIGINS = {"builtin", "source", "source-analysis", "quaygate-lint"}
NOTE = (
    "These are supplied report snapshots, not proof of fresh scan execution. SHA256 values identify "
    "document contents, not signatures or authenticity. Observed continuity and comparable absence "
    "do not prove remediation, exploitability, or safety. Runtime, binary, intelligence and external "
    "finding absence are unsupported in this schema."
)


def _encoded(value: object) -> bytes:
    try:
        return json.dumps(
            value, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False
        ).encode("utf-8")
    except (TypeError, ValueError, RecursionError, UnicodeError):
        raise ValueError("Follow-up inputs must be finite JSON report objects") from None


def _validate(report: dict) -> bytes:
    if not isinstance(report, dict):
        raise ValueError("before and after must be report objects")
    raw = _encoded(report)
    if not isinstance(report.get("inventory", {}), dict):
        raise ValueError("Report inventory must be an object")
    for key in ("findings", "coverage"):
        rows = report.get(key, [])
        if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
            raise ValueError(f"Report {key} must be a list of objects")
    ids = []
    for item in report.get("findings", []):
        if any(not isinstance(item.get(key), str) or not item[key] for key in ("id", "rule_id")):
            raise ValueError("Findings require nonempty string id and rule_id")
        evidence = item.get("evidence", [])
        if not isinstance(evidence, list) or any(not isinstance(row, dict) for row in evidence):
            raise ValueError("Finding evidence must be a list of objects")
        if any(
            key in item and (not isinstance(item[key], str) or not item[key])
            for key in ("origin", "scope", "status", "severity")
        ):
            raise ValueError(
                "Finding origin, scope, status and severity must be nonempty strings when present"
            )
        ids.append(item["id"])
    if len(set(ids)) != len(ids):
        raise ValueError("Duplicate finding IDs cannot be followed up unambiguously")
    return raw


def _identity(item: dict) -> tuple:
    return item["rule_id"], item.get("origin", "builtin"), item.get("scope", "app")


def _anchors(item: dict) -> set[str]:
    return {
        canonical_json({"path": row["path"], **{key: row[key] for key in ANCHORS if row.get(key)}})
        for row in item.get("evidence", [])
        if isinstance(row.get("path"), str)
        and row["path"]
        and any(isinstance(row.get(key), str) and row[key] for key in ANCHORS)
    }


def _path_only(item: dict) -> set[str]:
    rows = item.get("evidence", [])
    paths = {row["path"] for row in rows if isinstance(row.get("path"), str) and row["path"]}
    return paths - {
        row["path"]
        for row in rows
        if isinstance(row.get("path"), str) and any(row.get(key) for key in ANCHORS)
    }


def _specifications(report: dict) -> dict:
    inventory = report.get("inventory", {})
    return {
        "report": {key: report[key] for key in ("spec_hash", "specs", "analysis_specs") if key in report},
        "inventory": {
            key: inventory[key]
            for key in ("project_specification", "analysis_specs", "apps")
            if key in inventory
        },
    }


def _incomplete_flags(holder: dict, *, positive: tuple = (), negative: tuple = ()) -> bool:
    """Optional legacy fields may be absent; declared completeness must be a strict boolean."""
    return any(key in holder and holder[key] is not True for key in positive) or any(
        key in holder and holder[key] is not False for key in negative
    )


def _omissions_incomplete(value: object, *, nested: bool = False) -> bool:
    if not isinstance(value, dict):
        return True
    if nested:
        return any(_omissions_incomplete(row) for row in value.values())
    return any(
        not isinstance(row, dict)
        or any(type(row.get(key)) is not int or row[key] != 0 for key in ("files", "bytes"))
        for row in value.values()
    )


def _analysis_completeness_incomplete(inventory: dict) -> bool:
    if _incomplete_flags(
        inventory, positive=("hybrid_input_inventory_complete",), negative=("hybrid_inputs_truncated",)
    ):
        return True
    for key in ("source_analysis", "hybrid_analysis"):
        if key not in inventory:
            continue
        analysis = inventory[key]
        if not isinstance(analysis, dict) or _incomplete_flags(
            analysis,
            positive=("complete", "function_inventory_complete"),
            negative=("partial", "input_observations_truncated"),
        ):
            return True
        files = analysis.get("files", [])
        if not isinstance(files, list) or any(
            not isinstance(row, dict) or _incomplete_flags(row, negative=("partial",)) for row in files
        ):
            return True
    return False


def assess_finding_followup(
    before: dict,
    after: dict,
    finding_id: str,
    *,
    portable_inputs: bool = False,
) -> dict:
    """Follow one before-finding without reading files, changing IDs, or executing a scan."""
    if not isinstance(finding_id, str) or not finding_id:
        raise ValueError("finding_id must be a nonempty string")
    if type(portable_inputs) is not bool:
        raise ValueError("portable_inputs must be a boolean")
    raw = {"before": _validate(before), "after": _validate(after)}
    selected = next((item for item in before.get("findings", []) if item["id"] == finding_id), None)
    if selected is None:
        raise ValueError("finding_id does not exist in the before report")
    blockers: list[dict] = []
    omissions = {
        "metadata_fields": 0,
        "evidence_rows": 0,
        "coverage_rows": 0,
        "candidates": 0,
        "location_rows": 0,
    }

    def block(code: str, side: str = "pair") -> None:
        entry = {"code": code, "side": side}
        if entry not in blockers:
            blockers.append(entry)

    def small(value):
        # Omit, never rewrite, oversized IDs or paths. Snapshot hashes still bind their full values.
        if (value is None or isinstance(value, (bool, int, float, str))) and len(_encoded(value)) <= 512:
            return value
        omissions["metadata_fields"] += 1
        return None

    def metadata(item: dict) -> dict:
        rows = item.get("evidence", [])
        omissions["evidence_rows"] += max(0, len(rows) - 4)
        return {
            **{key: small(item.get(key)) for key in ("id", "rule_id", "status", "severity")},
            "origin": small(item.get("origin", "builtin")),
            "scope": small(item.get("scope", "app")),
            "evidence": [
                {key: small(row[key]) for key in ("path", "line", *ANCHORS) if key in row} for row in rows[:4]
            ],
        }

    # Evaluate every candidate before bounding presentation; no omitted candidate becomes absence.
    compatible = [item for item in after.get("findings", []) if _identity(item) == _identity(selected)]
    exact = [item for item in compatible if item["id"] == finding_id]
    anchors = _anchors(selected)
    unanchored = _path_only(selected)
    bases = {
        item["id"]: "semantic-path-and-anchors"
        if anchors & _anchors(item)
        else "path-only-unconfirmed"
        if unanchored & _path_only(item)
        else "same-rule-other-location-or-anchor"
        for item in compatible
    }
    continuations = [item for item in compatible if bases[item["id"]] != "same-rule-other-location-or-anchor"]
    candidates = exact or continuations or compatible
    observation = (
        "exact-id-observed"
        if exact
        else "possible-continuation"
        if continuations
        else "same-rule-elsewhere"
        if compatible
        else "no-compatible-observation"
    )
    if not exact and len(continuations) > 1:
        block("ambiguous-continuation", "after")
    if observation == "same-rule-elsewhere":
        block("same-rule-elsewhere", "after")
    if any(
        item["id"] == finding_id and _identity(item) != _identity(selected)
        for item in after.get("findings", [])
    ):
        block("finding-identity-conflict", "after")

    # Retain existing path/build pairing semantics without processing unrelated runtime records.
    try:
        paired = compare_reports(
            {**before, "findings": [], "runtime": []},
            {**after, "findings": [], "runtime": []},
            portable_inputs=portable_inputs,
        )
    except (TypeError, ValueError, KeyError, AttributeError):
        paired = {
            "scope_pairing": {"state": "unavailable"},
            "path_pairing": {"state": "unavailable"},
            "build_pairing": {"state": "unavailable"},
            "normalization_basis": "none",
        }
        block("malformed-scope")
    if paired["scope_pairing"]["state"] != "unchanged":
        block("scope-not-identical")
    specs = {side: _specifications(report) for side, report in (("before", before), ("after", after))}
    if specs["before"] != specs["after"]:
        block("declared-specification-or-app-scope-differs")
    rule = selected["rule_id"]
    unsupported_locus = UNSUPPORTED_EVIDENCE_LOCI.get(rule)
    unknown = rule not in RULE_WEAKNESSES and rule not in UNMAPPED
    if unknown:
        block("unknown-rule", "before")
    unsupported = unknown or selected.get("origin", "builtin") not in BUILTIN_ORIGINS
    if unsupported_locus:
        unsupported = True
        block("unsupported-evidence-locus", "before")
    unsupported |= rule.startswith(
        (
            "RUNTIME-",
            "BINARY-",
            "DEPENDENCY-",
            "OS-",
            "CVE-",
            "GHSA-",
            "OSV-",
            "QG-DEX-",
            "QG-BIN-",
            "QG-NATIVE-",
            "QG-IPA-",
        )
    )
    unsupported |= selected.get("status") == "runtime-confirmed" or any(
        "runtime_id" in row or "dependency" in row or "scenario_identity" in row
        for row in selected.get("evidence", [])
    )
    paths = {
        row["path"]
        for row in selected.get("evidence", [])
        if isinstance(row.get("path"), str) and row["path"]
    }
    if not paths or any(
        not isinstance(row.get("path"), str) or not row["path"] for row in selected.get("evidence", [])
    ):
        block("evidence-path-unavailable", "before")
    coverage, locations, methods = {}, {}, {}
    for side, report in (("before", before), ("after", after)):
        inventory = report.get("inventory", {})
        if not isinstance(report.get("id"), str) or not report["id"]:
            block("missing-report-id", side)
        relevant = [selected] if side == "before" else candidates
        if any(
            item.get("status")
            not in ("candidate", "version-affected", "configuration-confirmed", "runtime-confirmed")
            for item in relevant
        ):
            block("finding-status-unavailable", side)
        if any(item.get("status") == "runtime-confirmed" for item in relevant):
            unsupported = True
        if inventory.get("input_kind") != "source" or inventory.get("binary"):
            unsupported = True
            block("unsupported-input-kind", side)
        fingerprint = inventory.get("fingerprint")
        if (
            not isinstance(fingerprint, str)
            or re.fullmatch(r"[0-9a-f]{64}", fingerprint) is None
            or inventory.get("fingerprint_complete") is not True
        ):
            block("complete-canonical-fingerprint-required", side)
        platforms, apps = inventory.get("platforms"), inventory.get("apps", [])
        if (
            not isinstance(report.get("target"), str)
            or not report["target"]
            or not isinstance(platforms, list)
            or not platforms
            or any(platform not in ("android", "ios") for platform in platforms)
            or not isinstance(apps, list)
            or any(
                not isinstance(app, dict)
                or any(not isinstance(app.get(key), str) or not app[key] for key in ("platform", "package"))
                for app in apps
            )
            or not isinstance(inventory.get("source_selection", {}), dict)
        ):
            block("scope-evidence-incomplete", side)
        snapshot = inventory.get("input_snapshot", {})
        if (
            not isinstance(snapshot, dict)
            or _incomplete_flags(
                snapshot,
                positive=("app_scope_complete", "hybrid_input_inventory_complete"),
                negative=("partial", "hybrid_inputs_truncated", "omitted_by_module_truncated"),
            )
            or any(
                key in snapshot and _omissions_incomplete(snapshot[key], nested=key == "omitted_by_module")
                for key in ("omitted", "omitted_by_module", "omitted_other_modules")
            )
            or (
                "omitted_module_groups" in snapshot
                and (
                    type(snapshot["omitted_module_groups"]) is not int
                    or snapshot["omitted_module_groups"] != 0
                )
            )
        ):
            block("input-scope-incomplete", side)
        if (
            report_incomplete(report)
            or _incomplete_flags(report, negative=("partial",))
            or _incomplete_flags(inventory, negative=("partial",))
            or _analysis_completeness_incomplete(inventory)
        ):
            block("partial-report", side)
        runtime, online = report.get("runtime", []), report.get("online_query", {})
        if (
            not isinstance(runtime, list)
            or (
                runtime
                and (
                    not isinstance(runtime[-1], dict) or _incomplete_flags(runtime[-1], negative=("partial",))
                )
            )
            or not isinstance(online, dict)
            or type(online.get("requested", False)) is not bool
            or (online.get("requested") is True and not isinstance(online.get("errors", []), list))
        ):
            block("partial-report", side)
        for holder, keys in (
            (report, ("spec_hash", "specs", "analysis_specs")),
            (inventory, ("project_specification", "analysis_specs")),
        ):
            if any(
                key in holder and not isinstance(holder[key], str if key == "spec_hash" else dict)
                for key in keys
            ):
                block("malformed-analysis-specification", side)
        for key in ("tool_version", "rule_version"):
            if not isinstance(report.get(key), str) or not report[key]:
                block(f"missing-{key.replace('_', '-')}", side)
            elif before.get(key) != after.get(key):
                block(f"{key.replace('_', '-')}-differs")
        checks = [
            row
            for row in report.get("coverage", [])
            if row.get("rule_id") in (rule, COVERAGE_ALIASES.get(rule, rule))
        ]
        if not checks or any(row.get("state") not in ("checked", "observed") for row in checks):
            block("rule-coverage-incomplete", side)
        if not checks or any(not isinstance(row.get("method"), str) or not row["method"] for row in checks):
            block("rule-method-unavailable", side)
        methods[side] = {row["method"] for row in checks if isinstance(row.get("method"), str)}
        if any(
            _incomplete_flags(row, positive=("function_inventory_complete",), negative=("partial",))
            for row in checks
        ):
            block("rule-coverage-incomplete", side)
        omissions["coverage_rows"] += max(0, len(checks) - 16)
        coverage[side] = [
            {key: small(row.get(key)) for key in ("rule_id", "state", "method")} for row in checks[:16]
        ]
        assessed_locations = []
        if unsupported_locus:
            assessed_locations = [
                {"path": path, "state": "unsupported", "analysis": unsupported_locus["analysis"]}
                for path in sorted(paths)
            ]
        elif rule in CONFIG_RULES:
            config_paths = set()
            for key in ("android_config", "ios_config"):
                entries = inventory.get(key, [])
                if not isinstance(entries, list) or any(not isinstance(row, dict) for row in entries):
                    block("configuration-location-not-covered", side)
                else:
                    config_paths.update(row["path"] for row in entries if isinstance(row.get("path"), str))
            if (
                not paths <= config_paths
                or not checks
                or any(row.get("method") != "configuration" for row in checks)
            ):
                block("configuration-location-not-covered", side)
            assessed_locations = [
                {
                    "path": path,
                    "state": "checked" if path in config_paths else "not-covered",
                    "analysis": "configuration-inventory",
                }
                for path in sorted(paths)
            ]
        else:
            source = inventory.get("source_analysis", {})
            source_complete = isinstance(source, dict) and (
                "state" not in source or source["state"] == "checked"
            )
            if not source_complete:
                block("source-analysis-not-complete", side)
            files = source.get("files", []) if isinstance(source, dict) else []
            files = files if isinstance(files, list) else []
            for path in sorted(paths):
                rows = [row for row in files if isinstance(row, dict) and row.get("path") == path]
                if (
                    not source_complete
                    or not path.lower().endswith(SOURCE_SUFFIXES)
                    or not rows
                    or any(row.get("state") != "checked" for row in rows)
                ):
                    block("source-location-not-covered", side)
                assessed_locations.append(
                    {
                        "path": path,
                        "state": "checked"
                        if source_complete and rows and all(row.get("state") == "checked" for row in rows)
                        else "not-covered",
                        "analysis": "source_analysis",
                    }
                )
        locations[side] = [
            {key: small(value) for key, value in row.items()} for row in assessed_locations[:16]
        ]
        omissions["location_rows"] += max(0, len(assessed_locations) - 16)
    if methods["before"] != methods["after"]:
        block("rule-method-differs")
    if unsupported:
        block("unsupported-evidence-class", "before")
    scope_pairing = {
        key: small(value)
        for key, value in paired["scope_pairing"].items()
        if key not in ("before", "after", "normalized_fields")
    }
    result = {
        "schema_version": 1,
        "kind": "apsa-finding-followup",
        "selected_finding": metadata(selected),
        "observation": {
            "state": observation,
            "candidate_count": len(candidates),
            "candidates": [
                {**metadata(item), "match_basis": "exact-id" if exact else bases[item["id"]]}
                for item in sorted(candidates, key=lambda item: item["id"])[:8]
            ],
            "ambiguous": not bool(exact) and len(continuations) > 1,
            "same_rule_count": len(compatible),
            "truncated": len(candidates) > 8,
        },
        "comparability": {
            "state": "unsupported" if unsupported else "limited" if blockers else "comparable",
            "blockers": sorted(blockers, key=lambda item: (item["side"], item["code"])),
            "execution_provenance": "not-established",
        },
        "scope_pairing": scope_pairing,
        "path_pairing": {key: small(value) for key, value in paired["path_pairing"].items()},
        "build_pairing": {key: small(value) for key, value in paired["build_pairing"].items()},
        "specification_pairing": {
            "state": "unchanged" if specs["before"] == specs["after"] else "changed",
            **{side + "_sha256": digest(_encoded(value)) for side, value in specs.items()},
        },
        "remediation_proven": False,
        "coverage": coverage,
        "location_coverage": locations,
        "omissions": omissions,
        "next_steps": _next_steps(blockers, bool(candidates), unsupported_locus),
        "note": NOTE,
    }
    for side, report in (("before", before), ("after", after)):
        result[side] = {
            "report_id": small(report.get("id")),
            "report_sha256": digest(raw[side]),
            "input_fingerprint": small(report.get("inventory", {}).get("fingerprint")),
            "fingerprint_complete": report.get("inventory", {}).get("fingerprint_complete") is True,
            "tool_version": small(report.get("tool_version")),
            "rule_version": small(report.get("rule_version")),
        }
    omissions["candidates"] = max(0, len(candidates) - len(result["observation"]["candidates"]))
    # Reserve the digest field's serialized bytes; retain all decision inputs in snapshot hashes.
    while len(_encoded(result)) > MAX_OUTPUT_BYTES - 100:
        if result["observation"]["candidates"]:
            result["observation"]["candidates"].pop()
            omissions["candidates"] += 1
            result["observation"]["truncated"] = True
        elif result["selected_finding"]["evidence"]:
            result["selected_finding"]["evidence"].pop()
            omissions["evidence_rows"] += 1
        else:
            for group, count in ((locations, "location_rows"), (coverage, "coverage_rows")):
                side = next((side for side in ("after", "before") if group[side]), None)
                if side:
                    group[side].pop()
                    omissions[count] += 1
                    break
            else:
                raise ValueError("Follow-up metadata cannot fit within the output byte limit")
    result["artifact_sha256"] = digest(_encoded(result))
    return result


def _next_steps(
    blockers: list[dict], has_candidates: bool, unsupported_locus: dict | None = None
) -> list[str]:
    steps = {"independently-validate-remediation"}
    if unsupported_locus:
        steps.add(unsupported_locus["next_step"])
    if not blockers:
        steps.add("inspect-continuation-candidates" if has_candidates else "review-prior-evidence-location")
    for entry in blockers:
        code = entry["code"]
        if code.startswith("unsupported-") or code == "unknown-rule":
            steps.add("use-evidence-class-specific-validation")
        elif "version" in code:
            steps.add("align-tool-and-rule-versions")
        elif code.startswith("rule-method"):
            steps.add("align-and-document-rule-analysis-methods")
        elif code == "source-analysis-not-complete":
            steps.add("complete-source-analysis")
        elif "fingerprint" in code:
            steps.add("capture-complete-canonical-fingerprints")
        elif code in ("same-rule-elsewhere", "ambiguous-continuation", "finding-identity-conflict"):
            steps.add("inspect-and-disambiguate-observations")
        elif "location" in code or "coverage" in code:
            steps.add("restore-prior-location-and-rule-coverage")
        elif "partial" in code:
            steps.add("complete-partial-analysis")
        else:
            steps.add("align-and-complete-report-scope")
    return sorted(steps)
