"""Cross-check a finding claimed elsewhere (for example by an AI reviewer) against APSA evidence.

The result is deterministic and never refutes a claim: APSA can corroborate it
with its own finding, or report that its related checks did, partially did, or
did not run there. Absence of an APSA finding is not evidence of absence.
"""

from __future__ import annotations

import re
from pathlib import PurePosixPath, PureWindowsPath

from .completeness import analysis_incomplete, report_incomplete
from .core import canonical_json, digest
from .maswe import (
    RULE_WEAKNESSES,
    UNMAPPED,
    aggregate_states,
    finding_weaknesses,
    rule_state,
    weakness_index,
    weaknesses_for,
)
from .rules import rules

STATUS_STRENGTH = ("candidate", "version-affected", "configuration-confirmed", "runtime-confirmed")
NOTE = (
    "APSA evidence can corroborate a claim; it cannot refute one. not-observed means the related "
    "checks ran without an APSA finding at that location, which is not proof that the weakness is absent. "
    "file-not-analyzed means APSA's source analysis did not cover the claimed file; path-unmatched means "
    "the claimed path matches no analyzed file exactly, and candidate_paths lists analyzed files it may name."
)
AST_SUFFIXES = (".java", ".kt", ".kts", ".swift", ".m")
SOURCE_SUFFIXES = AST_SUFFIXES + (".js", ".jsx", ".jsbundle", ".ts", ".tsx", ".dart")

# Narrow claim correspondence, not the broader MASWE traceability relation.
# CWE-22, CWE-89 and CWE-502 describe distinct path, SQL and deserialization
# behaviors even though MASWE-0050 relates to all three. Certificate bypasses
# map to CWE-295; trusting user-installed CAs alone is not a bypass. Other CWE
# claims remain unassessed until a specific check correspondence is established.
CWE_CHECKS = {
    "CWE-22": {"AST-PATH-TRAVERSAL"},
    "CWE-89": {"AST-SQL-CONCAT", "HYBRID-SQL-INPUT"},
    "CWE-295": {
        "WEBVIEW-SSL-BYPASS",
        "AST-WEBVIEW-SSL-BYPASS",
        "BINARY-WEBVIEW-SSL-BYPASS",
        "SOURCE-TRUST-ALL-CERTS",
        "SWIFT-SERVER-TRUST-ACCEPTED",
    },
    "CWE-502": {"SOURCE-JAVA-DESERIALIZATION", "IOS-INSECURE-UNARCHIVE"},
}

# Configuration findings have precise IDs but share a production coverage entry.
# These aliases affect execution states only, never finding correspondence.
COVERAGE_ALIASES = {
    "ANDROID-DEBUG": "ANDROID-CONFIG",
    "ANDROID-CLEARTEXT": "ANDROID-CONFIG",
    "IOS-ATS": "IOS-CONFIG",
}


def _claim_checks(weakness: str | None, rule: str | None) -> set[str]:
    value = weakness.strip().upper() if weakness else ""
    if value.startswith("CWE-"):
        checks = CWE_CHECKS.get(f"CWE-{int(value[4:])}", set()).copy()
    elif weakness:
        # Use only the caller's explicit MASWE, not categories inferred from rule.
        checks = {check for check, mapped in RULE_WEAKNESSES.items() if value in mapped}
    else:
        checks = set()
    if rule:
        return checks & {rule} if weakness else {rule}
    return checks


def _portable_source_pairing(before: dict, after: dict) -> str:
    """Authorize target-only normalization from report evidence; never touch input paths."""
    for report in (before, after):
        inventory = report.get("inventory", {})
        if inventory.get("input_kind") != "source" or inventory.get("binary"):
            return "complete source inputs required; binary pairing remains strict"
        target = report.get("target")
        if (
            not isinstance(target, str)
            or not (PurePosixPath(target).is_absolute() or PureWindowsPath(target).is_absolute())
            or PurePosixPath(target.replace("\\", "/").rstrip("/")).suffix.lower() == ".app"
        ):
            return "absolute source targets required"
        fingerprint = inventory.get("fingerprint")
        if not isinstance(fingerprint, str) or re.fullmatch(r"[0-9a-f]{64}", fingerprint) is None:
            return "canonical SHA256 source fingerprints required"
        if inventory.get("fingerprint_complete") is not True:
            return "explicitly complete source fingerprints required"
        snapshot = inventory.get("input_snapshot") or {}
        if (
            not isinstance(snapshot, dict)
            or report.get("partial")
            or inventory.get("partial")
            or snapshot.get("partial")
            or ("app_scope_complete" in snapshot and snapshot["app_scope_complete"] is not True)
        ):
            return "partial source or input scope cannot be normalized"
        omitted = snapshot.get("omitted", {})
        if omitted and (
            not isinstance(omitted, dict)
            or any(
                not isinstance(counts, dict) or counts.get("files") or counts.get("bytes")
                for counts in omitted.values()
            )
        ):
            return "omitted source input cannot be normalized"
        if any(check.get("state") == "partial" for check in report.get("coverage", [])):
            return "partial analysis coverage cannot be normalized"
        if analysis_incomplete(inventory):
            return "partial source analysis cannot be normalized"
    if before["inventory"]["fingerprint"] != after["inventory"]["fingerprint"]:
        return "source fingerprints differ; relocation pairing requires identical input"
    # Preserve every declared spec representation, not only scope()'s effective
    # fallback. No additional analysis field is normalized away with the path.
    for key in ("spec_hash", "specs", "analysis_specs"):
        if (key in before) != (key in after) or before.get(key) != after.get(key):
            return "analysis specification differs"
    for key in ("project_specification", "analysis_specs"):
        left, right = before["inventory"], after["inventory"]
        if (key in left) != (key in right) or left.get(key) != right.get(key):
            return "analysis specification differs"
    if sorted(canonical_json(app) for app in before["inventory"].get("apps", [])) != sorted(
        canonical_json(app) for app in after["inventory"].get("apps", [])
    ):
        return "app scope differs"
    return "eligible"


def compare_reports(before: dict, after: dict, *, portable_inputs: bool = False) -> dict:
    """Compare evidence snapshots without converting disappearance into remediation.

    Audit fingerprints are retained as an explicit before/after build pair.
    Runtime comparisons require the identical executable scenario scope and
    observed installed build. Legacy records without those bindings are unknown.
    portable_inputs only pairs relocated complete source snapshots with identical
    canonical SHA256 fingerprints; original paths and scope hashes remain visible.
    """
    if type(portable_inputs) is not bool:
        raise ValueError("portable_inputs must be a boolean")

    def scope(report):
        inventory = report.get("inventory", {})
        return {
            "target": report.get("target"),
            "input_kind": inventory.get("input_kind"),
            "platforms": sorted(inventory.get("platforms", [])),
            "apps": sorted((a.get("platform", ""), a.get("package", "")) for a in inventory.get("apps", [])),
            "package": inventory.get("package"),
            "analysis_spec": inventory.get(
                "project_specification", report.get("spec_hash", report.get("specs", {}))
            ),
            "source_selection": inventory.get("source_selection", {}),
            "tool_version": report.get("tool_version"),
            "rule_version": report.get("rule_version"),
            "rules": sorted(c.get("rule_id", "") for c in report.get("coverage", [])),
        }

    before_scope, after_scope = scope(before), scope(after)
    complete_scope = bool(before_scope["target"] and before_scope["input_kind"] and before_scope["platforms"])
    original_scope_state = (
        "unchanged"
        if complete_scope and before_scope == after_scope
        else ("changed" if complete_scope else "unavailable")
    )
    normalized_before, normalized_after = dict(before_scope), dict(after_scope)
    path_normalized = False
    normalization_reason = "portable pairing not requested"
    if portable_inputs and before_scope["target"] != after_scope["target"]:
        normalization_reason = _portable_source_pairing(before, after)
        if normalization_reason == "eligible" and complete_scope:
            normalized_before["target"] = normalized_after["target"] = "<portable-source-input>"
            if normalized_before == normalized_after:
                path_normalized = True
                normalization_reason = (
                    "identical complete canonical source input and unchanged analysis scope"
                )
            else:
                normalization_reason = "analysis scope differs beyond target"
        elif normalization_reason == "eligible":
            normalization_reason = "analysis scope unavailable"
    elif portable_inputs:
        normalization_reason = "target unchanged; normalization unnecessary"
    # Failed eligibility never normalizes any field, including hash evidence.
    if not path_normalized:
        normalized_before, normalized_after = before_scope, after_scope
    scope_state = "unchanged" if path_normalized else original_scope_state
    normalization_basis = "identical-complete-canonical-source-sha256" if path_normalized else "none"
    fingerprints = {
        "before": before.get("inventory", {}).get("fingerprint"),
        "after": after.get("inventory", {}).get("fingerprint"),
    }
    build_state = (
        "unavailable"
        if not all(fingerprints.values())
        or any(r.get("inventory", {}).get("fingerprint_complete") is False for r in (before, after))
        else ("same-build" if fingerprints["before"] == fingerprints["after"] else "different-builds")
    )
    old = {f["id"]: f for f in before.get("findings", [])}
    new = {f["id"]: f for f in after.get("findings", [])}
    changes = []
    for identifier in sorted(old.keys() | new.keys()):
        initial, final = old.get(identifier), new.get(identifier)
        observation = (
            "still-observed" if initial and final else ("newly-observed" if final else "no-longer-observed")
        )
        item = final if final is not None else old[identifier]
        changes.append(
            {
                "finding_id": identifier,
                "rule_id": item["rule_id"],
                "observation": observation,
                "before_status": initial.get("status") if initial else None,
                "after_status": final.get("status") if final else None,
                "verification": "comparable-observation" if scope_state == "unchanged" else "inconclusive",
                "source_traces": [
                    {
                        k: e[k]
                        for k in ("path", "line", "source", "sink", "sink_api", "trace", "source_trace")
                        if k in e
                    }
                    for e in item.get("evidence", [])
                ],
            }
        )
    runtime_pairs = []
    for current in after.get("runtime", []):
        # Child reports retain history. Compare only observations newly added after the baseline.
        if current.get("id") in {r.get("id") for r in before.get("runtime", [])}:
            continue
        candidates = [
            r
            for r in before.get("runtime", [])
            if current.get("scenario_scope") and r.get("scenario_scope") == current["scenario_scope"]
        ]
        prior = candidates[-1] if candidates else None
        binding = current.get("app_binding", {})
        exact_build = (
            prior is not None
            and binding.get("state") == "bound"
            and prior.get("app_binding", {}).get("state") == "bound"
            and bool(binding.get("identity"))
            and binding["identity"] == prior.get("app_binding", {}).get("identity")
        )
        runtime_pairs.append(
            {
                "before_runtime_id": prior.get("id") if prior else None,
                "after_runtime_id": current.get("id"),
                "scenario_scope": current.get("scenario_scope"),
                "scenario_identity": current.get("scenario_identity"),
                "before_build": prior.get("app_binding") if prior else None,
                "after_build": binding,
                "scope_pairing": "unchanged" if prior else "unavailable",
                "build_pairing": "same-build" if exact_build else "unavailable-or-different",
                "assertion_pairing": "unchanged"
                if prior
                and current.get("scenario_identity")
                and current["scenario_identity"] == prior.get("scenario_identity")
                else "unavailable-or-changed",
                "verification": "comparable-observation"
                if original_scope_state == "unchanged"
                and prior is not None
                and exact_build
                and current.get("scenario_identity")
                and current["scenario_identity"] == prior.get("scenario_identity")
                and not prior.get("partial", True)
                and not current.get("partial", True)
                else "inconclusive",
                "before_assertions": prior.get("assertions", []) if prior else [],
                "after_assertions": current.get("assertions", []),
            }
        )
    for change in changes:
        item = new.get(change["finding_id"]) or old[change["finding_id"]]
        if item.get("status") == "runtime-confirmed":
            evidence_runs = {e.get("runtime_id") for e in item.get("evidence", [])}
            paired = [
                p
                for p in runtime_pairs
                if p["before_runtime_id"] in evidence_runs or p["after_runtime_id"] in evidence_runs
            ]
            change["verification"] = (
                "comparable-observation"
                if paired and all(p["verification"] == "comparable-observation" for p in paired)
                else "inconclusive"
            )
        else:
            states = [
                c.get("state")
                for r in (before, after)
                for c in r.get("coverage", [])
                if c.get("rule_id") == change["rule_id"]
            ]
            if (
                not states
                or any(state not in {"checked", "observed"} for state in states)
                or any(r.get("partial") or report_incomplete(r) for r in (before, after))
            ):
                change["verification"] = "inconclusive"
    return {
        "schema_version": 1,
        "before_report_id": before.get("id"),
        "after_report_id": after.get("id"),
        "scope_pairing": {
            "state": scope_state,
            "original_state": original_scope_state,
            "normalization_basis": normalization_basis,
            "normalized_fields": ["target"] if path_normalized else [],
            "before": before_scope,
            "after": after_scope,
            "before_sha256": digest(canonical_json(before_scope).encode()),
            "after_sha256": digest(canonical_json(after_scope).encode()),
            "comparison_before_sha256": digest(canonical_json(normalized_before).encode()),
            "comparison_after_sha256": digest(canonical_json(normalized_after).encode()),
        },
        "path_pairing": {
            "state": "portable-source-target"
            if path_normalized
            else "exact-target"
            if before_scope["target"] and before_scope["target"] == after_scope["target"]
            else "changed-target"
            if before_scope["target"] and after_scope["target"]
            else "unavailable",
            "portable_inputs_requested": portable_inputs,
            "normalized": path_normalized,
            "before_target": before_scope["target"],
            "after_target": after_scope["target"],
            "reason": normalization_reason,
        },
        "normalization_basis": normalization_basis,
        "build_pairing": {"state": build_state, **fingerprints},
        "finding_transitions": changes,
        "runtime_pairs": runtime_pairs,
        "note": "No-longer-observed describes these snapshots only; it is not proof of remediation, complete deletion, or backend session invalidation. Changed scope or unbound runtime builds remain inconclusive.",
    }


def _weaknesses(weakness: str | None, rule: str | None) -> list[str]:
    known = {w["id"]: w for w in weakness_index()["weaknesses"]}
    found: list[str] = []
    if weakness:
        value = weakness.strip().upper()
        if re.fullmatch(r"MASWE-\d{4}", value):
            if value not in known:
                raise ValueError(f"Unknown MASWE identifier {value}")
            found.append(value)
        elif re.fullmatch(r"CWE-\d{1,5}", value):
            value = f"CWE-{int(value[4:])}"  # CWE-089 is CWE-89
            found += [w["id"] for w in known.values() if value in w["cwe"]]
        else:
            raise ValueError("weakness must be a MASWE-NNNN or CWE-N identifier")
    if rule:
        if rule not in RULE_WEAKNESSES and rule not in UNMAPPED and rule not in {r["id"] for r in rules()}:
            raise ValueError(f"Unknown APSA rule {rule}")
        found += [w for w in weaknesses_for(rule) if w not in found]
    return found


def _relative(path: str, targets: list[str]) -> str | None:
    """The claimed path relative to the audited target; absolute paths must lie inside it.

    ``targets`` holds the target's spellings (resolved and as requested), so a
    claim through the symlink used for the scan still matches. None means the
    claim names the audited file itself.
    """
    value = path.replace("\\", "/")
    if value.startswith("/") or re.match(r"[A-Za-z]:/", value):
        # Compared as spelled: resolving a client-supplied path would touch the filesystem
        # outside the audited roots. The target's resolved and requested spellings both count.
        for target in targets:
            base = target.replace("\\", "/").rstrip("/")
            if value == base:
                return None
            if value.startswith(base + "/"):
                value = value[len(base) + 1 :]
                break
        else:
            raise ValueError("path is outside the audited target")
    parts = [part for part in value.split("/") if part not in {"", "."}]
    if not parts or ".." in parts:
        raise ValueError("path must name a file inside the audited target")
    return "/".join(parts)


def _same_file(evidence_path: str, claimed: str, target: str) -> bool:
    """Exact match, or a claim with a repository prefix that ends at the audited target.

    A bare file name never matches a deeper evidence path: ``Foo.kt`` is not
    ``app/src/Foo.kt``.
    """
    evidence = str(PurePosixPath(evidence_path.replace("\\", "/").lstrip("/")))
    if evidence == claimed:
        return True
    if not claimed.endswith("/" + evidence):
        return False
    prefix = claimed[: -len(evidence) - 1].split("/")
    tail = [part for part in target.replace("\\", "/").split("/") if part]
    return len(prefix) <= len(tail) and tail[-len(prefix) :] == prefix


def verify_claim(
    report: dict,
    *,
    path: str | None = None,
    line: int | None = None,
    weakness: str | None = None,
    rule: str | None = None,
    window: int = 3,
) -> dict:
    if not (weakness or rule):
        raise ValueError("Provide a weakness (MASWE or CWE identifier) or an APSA rule ID")
    if line is not None and (line < 1 or path is None):
        raise ValueError("line must be positive and needs a path")
    if not 0 <= window <= 50:
        raise ValueError("window must be 0-50 lines")
    weaknesses = _weaknesses(weakness, rule)
    checks = sorted(_claim_checks(weakness, rule))
    narrow_claim = bool(rule or (weakness and weakness.strip().upper().startswith("CWE-")))
    target = str(report.get("target", ""))
    requested = report.get("requested_target")
    spellings = [target] + ([str(requested)] if requested else [])
    claimed = _relative(path, spellings) if path else None
    states: dict[str, set[str]] = {}
    for item in report.get("coverage", []):
        if isinstance(item.get("state"), str):
            for check in checks:
                if item.get("rule_id") in {check, COVERAGE_ALIASES.get(check, check)}:
                    states.setdefault(check, set()).add(item["state"])
    matches, elsewhere = [], []
    for item in report.get("findings", []):
        if item.get("origin") == "external":
            # An imported claim is not independent APSA evidence for itself.
            continue
        mapped = finding_weaknesses(item)
        # Dependency findings carry upstream advisory IDs rather than the coverage
        # group's rule ID. Environment advisories cannot corroborate an app claim.
        dependency_match = (
            "DEPENDENCY-CVE" in checks
            and item.get("origin") == "intelligence"
            and item.get("scope", "app") != "environment"
        )
        if (
            item.get("rule_id") not in checks
            and not dependency_match
            and (narrow_claim or not set(weaknesses) & set(mapped))
        ):
            continue
        located = [e for e in item.get("evidence", []) if isinstance(e, dict)]
        summary = {
            "finding_id": item["id"],
            "rule_id": item["rule_id"],
            "status": item["status"],
            "severity": item["severity"],
            "locations": [{k: e[k] for k in ("path", "line") if k in e} for e in located if e.get("path")],
        }
        if claimed is None:
            matches.append(summary)
            continue
        in_file = [e for e in located if e.get("path") and _same_file(e["path"], claimed, target)]
        if not in_file:
            continue
        if line is None or any(
            isinstance(e.get("line"), int) and abs(e["line"] - line) <= window for e in in_file
        ):
            matches.append(summary)
        else:
            elsewhere.append(summary)
    file_state = None
    candidates: list[str] = []
    if claimed is not None:
        records = [
            r
            for key in ("source_analysis", "hybrid_analysis")
            for r in (report.get("inventory", {}).get(key) or {}).get("files", [])
            if isinstance(r, dict) and isinstance(r.get("path"), str)
        ]
        for record in records:
            if _same_file(record["path"], claimed, target):
                file_state = record.get("state")
        if file_state is None and claimed.endswith(SOURCE_SUFFIXES):
            # A claim relative to another root (a module, a bare file name) may name an analyzed
            # file APSA cannot pick out; list the analyzed files it could mean.
            # A bare file name may mean any analyzed file of that name; a longer claim only
            # files that end with the whole claimed path.
            bare = "/" not in claimed
            candidates = sorted(
                {
                    r["path"]
                    for r in records
                    if r["path"].endswith("/" + claimed) or (bare and r["path"] == claimed)
                }
            )
            file_state = "path-unmatched" if candidates else "not-analyzed"
    observed = aggregate_states([rule_state(values) for values in states.values()])
    if matches:
        verdict = "corroborated"
    elif not checks:
        verdict = "not-assessed"
    elif elsewhere:
        verdict = "same-file-other-location"
    elif file_state == "path-unmatched":
        verdict = "path-unmatched"
    elif file_state in {"skipped", "not-analyzed"}:
        verdict = "file-not-analyzed"
    elif observed == "partial" or file_state == "partial":
        verdict = "partial"
    elif observed == "checked":
        verdict = "partial" if report_incomplete(report) else "not-observed"
    else:
        verdict = "not-run"
    strongest = max(
        (m["status"] for m in matches),
        key=lambda status: STATUS_STRENGTH.index(status) if status in STATUS_STRENGTH else -1,
        default=None,
    )
    titles = {w["id"]: w["title"] for w in weakness_index()["weaknesses"]}
    return {
        "report_id": report.get("id"),
        "claim": {"path": claimed, "line": line, "weakness": weakness, "rule": rule, "window": window},
        "verdict": verdict,
        "report_incomplete": report_incomplete(report),
        "strongest_status": strongest,
        "weaknesses": [{"id": w, "title": titles[w]} for w in weaknesses],
        "related_checks": [{"rule_id": c, "states": sorted(states.get(c, set()))} for c in checks],
        "source_file_state": file_state,
        "candidate_paths": candidates[:20],
        "matching_findings": matches[:50],
        "other_findings_in_file": elsewhere[:50],
        "note": NOTE
        + (
            " CWE corroboration requires an explicit rule mapping; currently CWE-22, CWE-89, CWE-295 and CWE-502 "
            "are supported. Broader MASWE overlap cannot corroborate an unsupported CWE claim."
            if weakness and weakness.strip().upper().startswith("CWE-")
            else ""
        ),
    }
