"""Validated project policy and evidence-aware CI gates without changing reports."""

from __future__ import annotations

import copy
import json
import re
import tomllib
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from .core import (
    finding_identities,
    match_identities,
    own_identities,
    read_bounded,
    report_incomplete,
    severity_rank,
)

SEVERITIES = ("critical", "high", "medium", "low", "info")
STATUSES = ("candidate", "version-affected", "configuration-confirmed", "runtime-confirmed")
STATUS_RANK = {status: rank for rank, status in enumerate(STATUSES)}
WAIVER_FIELDS = {"finding_id", "reason", "expires", "severity", "known_exploited"}
DEFAULTS = {
    "schema_version": 1,
    "thresholds": {"critical": 0, "high": 0, "medium": -1, "low": -1, "info": -1},
    "allowed_statuses": list(STATUSES[1:]),
    "only_new": False,
    "fail_on_partial": True,
    "strict_coverage": False,
    "required_rules": [],
    "require_fresh_intel": False,
    "required_feeds": [],
    "intel_max_age_hours": 24,
    "intel_max_pending": 0,
    "waivers": [],
}


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _strings(value: Any, name: str) -> list[str]:
    if (
        not isinstance(value, list)
        or len(value) > 1000
        or any(not isinstance(item, str) or not item.strip() or len(item) > 240 for item in value)
    ):
        raise ValueError(f"Policy {name} must be a list of nonempty strings (at most 1000).")
    if len(set(value)) != len(value):
        raise ValueError(f"Policy {name} contains duplicate entries.")
    return value.copy()


def _validate(policy: Any) -> dict:
    if not isinstance(policy, dict):
        raise ValueError("Policy must be an object.")
    unknown = set(policy) - set(DEFAULTS)
    if unknown:
        raise ValueError(f"Unknown policy fields: {', '.join(sorted(map(str, unknown)))}.")
    if type(policy.get("schema_version")) is not int or policy["schema_version"] != 1:
        raise ValueError("Policy schema_version must be 1.")
    result = copy.deepcopy(DEFAULTS)
    result.update(copy.deepcopy(policy))
    for name in ("only_new", "fail_on_partial", "strict_coverage", "require_fresh_intel"):
        if type(result[name]) is not bool:
            raise ValueError(f"Policy {name} must be a boolean.")
    thresholds = result["thresholds"]
    if not isinstance(thresholds, dict) or set(thresholds) - set(SEVERITIES):
        raise ValueError("Policy thresholds must contain only critical/high/medium/low/info.")
    for severity, threshold in thresholds.items():
        if type(threshold) is not int or not -1 <= threshold <= 1_000_000:
            raise ValueError(f"Policy thresholds.{severity} must be -1 or a nonnegative integer.")
    result["thresholds"] = {**DEFAULTS["thresholds"], **thresholds}
    for name in ("allowed_statuses", "required_rules", "required_feeds"):
        result[name] = _strings(result[name], name)
    if not result["allowed_statuses"] or set(result["allowed_statuses"]) - set(STATUSES):
        raise ValueError(f"Policy allowed_statuses must explicitly select from {', '.join(STATUSES)}.")
    age = result["intel_max_age_hours"]
    if type(age) is not int or not 1 <= age <= 8760:
        raise ValueError("Policy intel_max_age_hours must be an integer between 1 and 8760.")
    if type(result["intel_max_pending"]) is not int or not 0 <= result["intel_max_pending"] <= 1_000_000:
        raise ValueError("Policy intel_max_pending must be a nonnegative integer up to 1000000.")
    if result["require_fresh_intel"] and not result["required_feeds"]:
        raise ValueError("Policy require_fresh_intel requires an explicit required_feeds list.")
    waivers = result["waivers"]
    if not isinstance(waivers, list) or len(waivers) > 1000:
        raise ValueError("Policy waivers must be a list of at most 1000 entries.")
    ids = set()
    normalized = []
    for waiver in waivers:
        if (
            not isinstance(waiver, dict)
            or not {"finding_id", "reason", "expires"} <= set(waiver) <= WAIVER_FIELDS
        ):
            raise ValueError(
                "Each waiver must contain finding_id, reason, and expires, "
                "and optionally severity and known_exploited."
            )
        finding_id, reason, expiry = waiver["finding_id"], waiver["reason"], waiver["expires"]
        if not isinstance(finding_id, str) or not re.fullmatch(
            r"F-[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", finding_id
        ):
            raise ValueError("Waiver finding_id must be a complete F- finding identifier.")
        if finding_id in ids:
            raise ValueError(f"Duplicate waiver finding_id: {finding_id}.")
        if not isinstance(reason, str) or not reason.strip() or len(reason) > 2000:
            raise ValueError(f"Waiver {finding_id} requires a nonempty reason (at most 2000 characters).")
        if type(expiry) is date:
            expiry = expiry.isoformat()
        if not isinstance(expiry, str) or not re.fullmatch(r"\d{4}-\d{2}-\d{2}", expiry):
            raise ValueError(f"Waiver {finding_id} expires must be YYYY-MM-DD.")
        try:
            date.fromisoformat(expiry)
        except ValueError as error:
            raise ValueError(f"Waiver {finding_id} has an invalid expiry date.") from error
        approved = {}
        if "severity" in waiver:
            if waiver["severity"] not in SEVERITIES:
                raise ValueError(f"Waiver {finding_id} severity must be one of {', '.join(SEVERITIES)}.")
            approved["severity"] = waiver["severity"]
        if "known_exploited" in waiver:
            if type(waiver["known_exploited"]) is not bool:
                raise ValueError(f"Waiver {finding_id} known_exploited must be a boolean.")
            if "severity" not in waiver:
                raise ValueError(f"Waiver {finding_id} known_exploited requires the approved severity.")
            approved["known_exploited"] = waiver["known_exploited"]
        ids.add(finding_id)
        normalized.append({"finding_id": finding_id, "reason": reason.strip(), "expires": expiry, **approved})
    result["waivers"] = normalized
    return result


def load_policy(path: Path, *, authorized: bool = False) -> dict:
    """Load TOML or JSON and reject unknown fields and malformed waiver records.

    Expiry is checked on every evaluation, including a policy loaded before its
    expiry date. Expired waivers make the gate incomplete and never suppress a
    finding. Dates are inclusive through the specified UTC calendar day.
    """
    if path.suffix.lower() not in {".toml", ".json"}:
        raise ValueError("Policy must be a .toml or .json file.")
    raw = read_bounded(path if authorized else path.expanduser().parent.resolve() / path.name)
    try:
        policy = (
            tomllib.loads(raw.decode("utf-8"))
            if path.suffix.lower() == ".toml"
            else json.loads(raw, object_pairs_hook=_unique_object)
        )
    except (UnicodeError, ValueError, RecursionError) as error:
        raise ValueError(f"Could not parse policy {path.name}: {error}.") from error
    return _validate(policy)


def _unique_object(pairs: list[tuple[str, Any]]) -> dict:
    output = {}
    for key, value in pairs:
        if key in output:
            raise ValueError(f"Duplicate JSON policy field: {key}")
        output[key] = value
    return output


def template() -> str:
    return """# APSA project policy. Finding waivers expire at the end of the UTC date.
schema_version = 1
allowed_statuses = ["configuration-confirmed", "runtime-confirmed", "version-affected"]
# Add "candidate" explicitly if source/binary candidates should block CI.
only_new = false
fail_on_partial = true
# strict_coverage = true also treats limited (precision-limited, fully examined) coverage as incomplete.
strict_coverage = false
required_rules = []
# Require specific checks for this app, e.g. ["AST-WEBVIEW-UNTRUSTED-URL"].
require_fresh_intel = false
required_feeds = []
# Example: ["kev", "apple", "android", "cve", "owasp"] with require_fresh_intel = true.
intel_max_age_hours = 24
intel_max_pending = 0
# CVE processing backlog is separate from fetch freshness; raise only by team decision.

[thresholds]
# Maximum allowed findings at each exact severity; -1 disables that severity gate.
critical = 0
high = 0
medium = -1
low = -1
info = -1

# [[waivers]]
# finding_id = "F-<identifier copied from the report>"
# reason = "Document the reviewed scope and reason for this temporary exception."
# expires = "YYYY-MM-DD"
# Record the approved state: a higher severity, or a finding that becomes known
# exploited, then reopens the finding instead of staying waived.
# severity = "medium"
# known_exploited = false
"""


def _findings(report: Any, label: str) -> tuple[list[dict], list[dict]]:
    errors = []
    if not isinstance(report, dict) or not isinstance(report.get("findings"), list):
        return [], [{"code": "invalid-report", "message": f"{label} must contain a findings list."}]
    output = []
    ids = set()
    for index, item in enumerate(report["findings"]):
        valid = isinstance(item, dict) and all(
            isinstance(item.get(field), str) and item[field]
            for field in ("id", "rule_id", "severity", "status")
        )
        valid = (
            valid
            and item["severity"] in SEVERITIES
            and item["status"] in STATUSES
            and isinstance(item.get("evidence"), list)
            and all(isinstance(entry, dict) for entry in item["evidence"])
        )
        if not valid:
            errors.append(
                {
                    "code": "invalid-finding",
                    "message": f"{label} finding {index} has invalid identity, evidence, severity, or status.",
                }
            )
        elif item["id"] in ids:
            errors.append(
                {"code": "duplicate-finding-id", "message": f"{label} has duplicate finding ID {item['id']}."}
            )
        else:
            ids.add(item["id"])
            output.append(item)
    return output, errors


def _identities(items: list[dict]) -> list[tuple[set[str], set[str]]]:
    return [(own_identities(item), finding_identities(item)) for item in items]


def _waiver_escalation(waiver: dict, item: dict) -> bool:
    """Whether a finding now exceeds the severity or known-exploited state its waiver approved.

    Legacy waivers record no severity and keep suppressing as before.
    """
    if "severity" not in waiver:
        return False
    return severity_rank(item["severity"]) > severity_rank(waiver["severity"]) or (
        item.get("known_exploited") is True and waiver.get("known_exploited") is not True
    )


def _created(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo is not None else None


def _baseline_order_problem(report: dict, baseline: Any) -> dict | None:
    """Reject baselines that cannot predate the evaluated report.

    A report compared with itself, or with a later snapshot, would mark every
    current finding as already known and silently pass an only_new gate.
    """
    if not isinstance(baseline, dict):
        return None
    report_id, baseline_id = report.get("id"), baseline.get("id")
    if isinstance(report_id, str) and report_id and report_id == baseline_id:
        return {
            "code": "baseline-is-report",
            "message": "Baseline must be an earlier report, not the evaluated report itself.",
        }
    before, after = _created(baseline.get("created")), _created(report.get("created"))
    if before is not None and after is not None and before > after:
        return {
            "code": "baseline-not-earlier",
            "message": "Baseline was created after the evaluated report; choose an earlier report.",
        }
    return None


def _subject(report: dict) -> tuple:
    inventory = report.get("inventory", {})
    scope = ()
    if isinstance(inventory, dict):
        selection = inventory.get("source_selection", {})
        if not isinstance(selection, dict):
            raise ValueError("Source selection must be an object")
        for key in ("module", "configuration", "configuration_semantics"):
            if selection.get(key) is not None and not isinstance(selection[key], str):
                raise ValueError("Source selection fields must be strings")
        if "dependency_build" in selection:
            build = selection["dependency_build"]
            if (
                not isinstance(build, dict)
                or any(
                    not isinstance(build.get(key), str) or not build[key].strip()
                    for key in ("application_module", "runtime_configuration")
                )
                or not isinstance(build.get("evidence_paths"), list)
                or any(not isinstance(path, str) or not path for path in build["evidence_paths"])
                or ("freshness" in build and not isinstance(build["freshness"], str))
                or (
                    "installed_build_verified" in build
                    and type(build["installed_build_verified"]) is not bool
                )
            ):
                raise ValueError("Dependency build selection is malformed")
        # Preserve the entire declared scope, including future selection fields.
        # JSON key order is irrelevant; dropping a variant or lockfile scope is not.
        scope = (
            (
                "source_selection",
                json.dumps(selection, sort_keys=True, allow_nan=False, separators=(",", ":")),
            ),
        )
        apps = inventory.get("apps", [])
        if not isinstance(apps, list):
            apps = []
        known = sorted(
            {
                (app["platform"], app["package"])
                for app in apps
                if isinstance(app, dict)
                and isinstance(app.get("platform"), str)
                and isinstance(app.get("package"), str)
                and app["package"]
            }
        )
        if known:
            return ("apps", *known, *scope)
        if inventory.get("package") and isinstance(inventory.get("platforms"), list):
            return ("apps", *((p, inventory["package"]) for p in sorted(inventory["platforms"])), *scope)
    return ("target", report["target"], *scope) if report.get("target") else scope


def evaluate(report: dict, policy: dict, baseline: dict | None = None) -> dict:
    """Evaluate evidence, severity budgets, coverage, freshness, and temporary waivers.

    Baselines use stable finding locations, rather than report IDs or volatile
    intelligence/runtime metadata. A higher severity or stronger evidence status
    reopens a baseline finding. Input reports and policy objects remain unchanged.
    """
    policy = _validate(policy)
    current, incomplete = _findings(report, "Report")
    report = report if isinstance(report, dict) else {}
    failures = []
    eligible = [item for item in current if item["status"] in policy["allowed_statuses"]]
    now = _now()
    today = now.date()
    active, expired, notices = [], [], []
    identities = _identities(current)
    # Each waiver ID matches a finding's own identities or, for a dependency
    # advisory whose display ID changed, one equivalent advisory identity.
    waiver_matches = match_identities(
        identities, [({w["finding_id"]}, {w["finding_id"]}) for w in policy["waivers"]]
    )
    matched_by: dict[int, list[dict]] = {}
    for position, found in enumerate(waiver_matches):
        for index in found:
            matched_by.setdefault(index, []).append(current[position])
    suppressed: set[str] = set()
    for index, waiver in enumerate(policy["waivers"]):
        matched = matched_by.get(index, [])
        record = {**waiver, "matched": bool(matched)}
        if date.fromisoformat(waiver["expires"]) < today:
            expired.append(record)
            incomplete.append(
                {
                    "code": "expired-waiver",
                    "message": f"Waiver {waiver['finding_id']} expired on {waiver['expires']}.",
                }
            )
        else:
            reopened = [item for item in matched if _waiver_escalation(waiver, item)]
            suppressed.update(item["id"] for item in matched if not _waiver_escalation(waiver, item))
            if "severity" not in waiver:
                notices.append(
                    {
                        "code": "waiver-severity-unrecorded",
                        "finding_id": waiver["finding_id"],
                        "message": f"Waiver {waiver['finding_id']} does not record the approved severity, "
                        "so a severity or known-exploited escalation cannot reopen its finding.",
                    }
                )
            if reopened:
                escalation = {
                    "waived_severity": waiver["severity"],
                    "waived_known_exploited": waiver.get("known_exploited", False),
                    "current_severity": max((item["severity"] for item in reopened), key=severity_rank),
                    "known_exploited": any(item.get("known_exploited") is True for item in reopened),
                    "findings": sorted(item["id"] for item in reopened),
                }
                record["escalated"] = escalation
                notices.append(
                    {
                        "code": "waiver-severity-escalated",
                        "finding_id": waiver["finding_id"],
                        **escalation,
                        "message": f"Waiver {waiver['finding_id']} approved severity {waiver['severity']}"
                        + (" with known exploitation" if escalation["waived_known_exploited"] else "")
                        + f"; the finding is now {escalation['current_severity']}"
                        + (" and known exploited" if escalation["known_exploited"] else "")
                        + ", so the waiver no longer suppresses it.",
                    }
                )
            active.append(record)
    baseline_existing = escalated = 0
    if policy["only_new"]:
        if baseline is None:
            incomplete.append(
                {"code": "baseline-required", "message": "only_new requires an explicit baseline report."}
            )
        else:
            previous, errors = _findings(baseline, "Baseline")
            incomplete.extend(errors)
            ordering = _baseline_order_problem(report, baseline)
            if ordering is not None:
                incomplete.append(ordering)
                previous = []
            if isinstance(baseline, dict):
                try:
                    subject_matches = _subject(report) == _subject(baseline)
                except (TypeError, ValueError, RecursionError):
                    incomplete.append(
                        {
                            "code": "invalid-baseline-scope",
                            "message": "Report and baseline require valid app and source selection scope.",
                        }
                    )
                    previous = []
                else:
                    if not subject_matches:
                        incomplete.append(
                            {
                                "code": "baseline-target-mismatch",
                                "message": "Baseline belongs to a different app, source target, or selection.",
                            }
                        )
                        previous = []
            # Every identity of every baseline item counts, including equivalent
            # advisory IDs, but an alias never lets one baseline item cover two findings.
            # Ambiguity is judged against every current finding, not only gated ones.
            known = dict(
                zip(
                    (item["id"] for item in current),
                    match_identities(identities, _identities(previous)),
                    strict=True,
                )
            )
            newly_observed = []
            for item in eligible:
                prior = [previous[index] for index in known[item["id"]]]
                covered = any(
                    severity_rank(old["severity"]) >= severity_rank(item["severity"])
                    and STATUS_RANK[old["status"]] >= STATUS_RANK[item["status"]]
                    for old in prior
                )
                if covered:
                    baseline_existing += 1
                else:
                    newly_observed.append(item)
                    escalated += bool(prior)
            eligible = newly_observed
    waived = [item for item in eligible if item["id"] in suppressed]
    gated = [item for item in eligible if item["id"] not in suppressed]
    by_severity = {severity: sum(item["severity"] == severity for item in gated) for severity in SEVERITIES}
    blocking = []
    for severity, count in by_severity.items():
        budget = policy["thresholds"][severity]
        if budget >= 0 and count > budget:
            failures.append(
                {
                    "code": "severity-threshold",
                    "severity": severity,
                    "count": count,
                    "allowed": budget,
                    "message": f"{count} {severity} findings exceed the allowed count {budget}.",
                }
            )
            blocking.extend(item["id"] for item in gated if item["severity"] == severity)
    coverage = report.get("coverage", []) if isinstance(report, dict) else []
    if not isinstance(coverage, list) or any(
        not isinstance(item, dict)
        or not isinstance(item.get("rule_id"), str)
        or not isinstance(item.get("state"), str)
        for item in coverage
    ):
        incomplete.append(
            {"code": "invalid-coverage", "message": "Report coverage must contain rule_id/state records."}
        )
        coverage = []
    strict = policy["strict_coverage"]
    if policy["fail_on_partial"]:
        # Limited coverage examined the whole scope; strict coverage also counts it.
        counted = {"partial", "limited"} if strict else {"partial"}
        partial_rules = sorted({item["rule_id"] for item in coverage if item["state"] in counted})
        if report_incomplete({**report, "coverage": coverage}, strict=strict):
            incomplete.append(
                {
                    "code": "partial-audit",
                    "rules": partial_rules,
                    "message": "Audit explicitly reports partial execution or coverage"
                    + (", or limited coverage under strict_coverage." if strict else "."),
                }
            )
    satisfied = {"checked", "not-applicable"} | (set() if strict else {"limited"})
    for rule in policy["required_rules"]:
        checks = [item for item in coverage if item["rule_id"] == rule]
        if not checks or any(item["state"] not in satisfied for item in checks):
            incomplete.append(
                {
                    "code": "required-rule-incomplete",
                    "rule_id": rule,
                    "states": [item["state"] for item in checks],
                    "message": f"Required rule {rule} was not fully checked.",
                }
            )
    if policy["require_fresh_intel"]:
        feeds = report.get("intel_snapshot", [])
        if not isinstance(feeds, list) or any(not isinstance(feed, dict) for feed in feeds):
            incomplete.append(
                {
                    "code": "invalid-intelligence",
                    "message": "Report intel_snapshot must be a list of feed records.",
                }
            )
            feeds = []
        for source in policy["required_feeds"]:
            matching = [feed for feed in feeds if feed.get("source") == source]
            fresh = False
            if len(matching) == 1:
                feed = matching[0]
                try:
                    succeeded = datetime.fromisoformat(
                        feed.get("fetched_ok", feed.get("succeeded", ""))
                        if source == "cve"
                        else feed.get("succeeded", "")
                    )
                    age = now - succeeded
                    fresh = succeeded.tzinfo is not None and -timedelta(minutes=5) <= age <= timedelta(
                        hours=policy["intel_max_age_hours"]
                    )
                except (ValueError, TypeError):
                    pass
                backlog_allowed = (
                    source == "cve"
                    and feed.get("status") == "partial"
                    and type(feed.get("pending")) is int
                    and 0 < feed["pending"] <= policy["intel_max_pending"]
                    and feed.get("retrying") == 0
                )
                fresh = (
                    fresh
                    and (feed.get("status") == "ok" or backlog_allowed)
                    and type(feed.get("stale", False)) is bool
                )
            if not fresh:
                incomplete.append(
                    {
                        "code": "required-intelligence-unavailable",
                        "source": source,
                        "message": f"Required intelligence feed {source} is missing, failed, stale, or has invalid freshness evidence.",
                    }
                )
    # A threshold failure is never masked by incompleteness; both remain in reasons.
    state = "failed" if failures else "incomplete" if incomplete else "passed"
    return {
        "schema_version": 1,
        "state": state,
        "exit_code": {"passed": 0, "failed": 4, "incomplete": 3}[state],
        "report_id": report.get("id") if isinstance(report, dict) else None,
        "baseline_report_id": baseline.get("id") if isinstance(baseline, dict) else None,
        "evaluated_at": now.isoformat(timespec="seconds"),
        "counts": {
            "total": len(current),
            "status_excluded": len(current)
            - sum(item["status"] in policy["allowed_statuses"] for item in current),
            "baseline_existing": baseline_existing,
            "escalated": escalated,
            "waived": len(waived),
            "considered": len(gated),
            "by_severity": by_severity,
        },
        "reasons": [*incomplete, *failures],
        # Notices never change the gate state or exit code; reasons do.
        "notices": notices,
        "active_waivers": active,
        "expired_waivers": expired,
        "waived_findings": [item["id"] for item in waived],
        "gate_findings": blocking,
        "policy": {
            "schema_version": 1,
            "allowed_statuses": policy["allowed_statuses"],
            "thresholds": policy["thresholds"],
            "only_new": policy["only_new"],
            "fail_on_partial": policy["fail_on_partial"],
            "strict_coverage": policy["strict_coverage"],
        },
    }
