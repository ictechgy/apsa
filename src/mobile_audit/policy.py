"""Validated project policy and evidence-aware CI gates without changing reports."""

from __future__ import annotations

import copy
import json
import re
import tomllib
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from .core import finding_identity, read_bounded, report_incomplete, severity_rank

SEVERITIES = ("critical", "high", "medium", "low", "info")
STATUSES = ("candidate", "version-affected", "configuration-confirmed", "runtime-confirmed")
STATUS_RANK = {status: rank for rank, status in enumerate(STATUSES)}
DEFAULTS = {
    "schema_version": 1,
    "thresholds": {"critical": 0, "high": 0, "medium": -1, "low": -1, "info": -1},
    "allowed_statuses": list(STATUSES[1:]),
    "only_new": False,
    "fail_on_partial": True,
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
    for name in ("only_new", "fail_on_partial", "require_fresh_intel"):
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
        if not isinstance(waiver, dict) or set(waiver) != {"finding_id", "reason", "expires"}:
            raise ValueError("Each waiver must contain exactly finding_id, reason, and expires.")
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
        ids.add(finding_id)
        normalized.append({"finding_id": finding_id, "reason": reason.strip(), "expires": expiry})
    result["waivers"] = normalized
    return result


def load_policy(path: Path) -> dict:
    """Load TOML or JSON and reject unknown fields and malformed waiver records.

    Expiry is checked on every evaluation, including a policy loaded before its
    expiry date. Expired waivers make the gate incomplete and never suppress a
    finding. Dates are inclusive through the specified UTC calendar day.
    """
    if path.suffix.lower() not in {".toml", ".json"}:
        raise ValueError("Policy must be a .toml or .json file.")
    raw = read_bounded(path.expanduser().parent.resolve() / path.name)
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


def _identity(item: dict) -> str:
    return finding_identity(item["rule_id"], item["evidence"], item.get("scope", "app"))


def _subject(report: dict) -> tuple:
    inventory = report.get("inventory", {})
    if isinstance(inventory, dict):
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
            return ("apps", *known)
        if inventory.get("package") and isinstance(inventory.get("platforms"), list):
            return ("apps", *((p, inventory["package"]) for p in sorted(inventory["platforms"])))
    return ("target", report["target"]) if report.get("target") else ()


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
    active, expired = [], []
    waived_ids = set()
    current_ids = {item["id"] for item in current} | {_identity(item) for item in current}
    for waiver in policy["waivers"]:
        record = {**waiver, "matched": waiver["finding_id"] in current_ids}
        if date.fromisoformat(waiver["expires"]) < today:
            expired.append(record)
            incomplete.append(
                {
                    "code": "expired-waiver",
                    "message": f"Waiver {waiver['finding_id']} expired on {waiver['expires']}.",
                }
            )
        else:
            active.append(record)
            waived_ids.add(waiver["finding_id"])
    baseline_existing = escalated = 0
    if policy["only_new"]:
        if baseline is None:
            incomplete.append(
                {"code": "baseline-required", "message": "only_new requires an explicit baseline report."}
            )
        else:
            previous, errors = _findings(baseline, "Baseline")
            incomplete.extend(errors)
            if isinstance(baseline, dict) and _subject(report) != _subject(baseline):
                incomplete.append(
                    {
                        "code": "baseline-target-mismatch",
                        "message": "Baseline belongs to a different app or source target.",
                    }
                )
                previous = []
            known: dict[str, list[dict]] = {}
            for item in previous:
                known.setdefault(_identity(item), []).append(item)
            newly_observed = []
            for item in eligible:
                prior = known.get(_identity(item), [])
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
    waived = [item for item in eligible if item["id"] in waived_ids or _identity(item) in waived_ids]
    gated = [item for item in eligible if item["id"] not in waived_ids and _identity(item) not in waived_ids]
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
    if policy["fail_on_partial"]:
        partial_rules = sorted({item["rule_id"] for item in coverage if item["state"] == "partial"})
        if report_incomplete({**report, "coverage": coverage}):
            incomplete.append(
                {
                    "code": "partial-audit",
                    "rules": partial_rules,
                    "message": "Audit explicitly reports partial execution or coverage.",
                }
            )
    for rule in policy["required_rules"]:
        checks = [item for item in coverage if item["rule_id"] == rule]
        if not checks or any(item["state"] not in {"checked", "not-applicable"} for item in checks):
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
                    and feed.get("stale", False) is False
                )
            if not fresh:
                incomplete.append(
                    {
                        "code": "required-intelligence-unavailable",
                        "source": source,
                        "message": f"Required intelligence feed {source} is missing, failed, stale, or has invalid freshness evidence.",
                    }
                )
    state = "incomplete" if incomplete else "failed" if failures else "passed"
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
        },
    }
