"""Bounded model responses; response pagination never changes audit completeness."""

from __future__ import annotations

import json

from .core import report_incomplete, report_limited
from .output import MODEL_CONTEXT_INSTRUCTIONS, assistant_context, assistant_finding

SECTIONS = (
    "findings",
    "coverage",
    "environment_advisories",
    "intel_snapshot",
    "runtime",
    "maswe",
    "warnings",
)
DEFAULT_BYTES = 65536


def _size(value: dict) -> int:
    return len(json.dumps(value, ensure_ascii=False).encode("utf-8"))


def page(base: dict, section: str, values: list, cursor=0, limit=20, max_bytes=DEFAULT_BYTES) -> dict:
    if type(cursor) is not int or cursor < 0 or cursor > len(values):
        raise ValueError("cursor must be an index within the selected immutable report section")
    if type(limit) is not int or not 1 <= limit <= 100:
        raise ValueError("limit must be 1–100")
    if type(max_bytes) is not int or not 4096 <= max_bytes <= 262144:
        raise ValueError("max_bytes must be 4096–262144")
    result = {
        **base,
        # This boundary is fixed guidance, never report- or app-controlled metadata.
        "instructions": MODEL_CONTEXT_INSTRUCTIONS,
        section: [],
        "page": {
            "section": section,
            "cursor": cursor,
            "total": len(values),
            "next_cursor": None,
            "oversized_indices": [],
        },
        "partial_response": True,
    }
    if _size(result) > max_bytes - 512:
        # Preserve stable identity even when app-controlled metadata is excessive.
        result = {
            k: v
            for k, v in result.items()
            if k
            in {
                "report_id",
                "id",
                "rule_id",
                "severity",
                "status",
                "instructions",
                "audit_incomplete",
                section,
                "page",
                "partial_response",
            }
        }
        result["metadata_truncated"] = True
    end = cursor
    for index in range(cursor, min(len(values), cursor + limit)):
        result[section].append(values[index])
        if _size(result) > max_bytes - 512:
            result[section].pop()
            if result[section]:
                break
            result["page"]["oversized_indices"].append(index)
        end = index + 1
    result["page"]["next_cursor"] = end if end < len(values) else None
    result["partial_response"] = (
        end < len(values)
        or bool(result["page"]["oversized_indices"])
        or result.get("metadata_truncated", False)
    )
    result["response_bytes"] = 0
    for _ in range(4):
        result["response_bytes"] = _size(result)
    if _size(result) > max_bytes:
        raise ValueError("Response metadata exceeds the byte budget")
    return result


def report_context(
    report: dict,
    *,
    section="findings",
    cursor=0,
    limit=20,
    max_bytes=DEFAULT_BYTES,
    severity: str | None = None,
    status: str | None = None,
) -> dict:
    if section not in SECTIONS:
        raise ValueError("Unknown report section")
    if severity is not None and severity not in {"critical", "high", "medium", "low", "info"}:
        raise ValueError("Unknown severity")
    if status is not None and status not in {
        "candidate",
        "version-affected",
        "configuration-confirmed",
        "runtime-confirmed",
    }:
        raise ValueError("Unknown finding status")
    if section != "findings" and (severity or status):
        raise ValueError("Finding filters require the findings section")
    context = assistant_context(report)
    values = context[section]
    if section == "findings":
        values = [
            f
            for f in values
            if (not severity or f["severity"] == severity) and (not status or f["status"] == status)
        ]
    base = {
        k: context[k]
        for k in ("report_id", "created", "summary", "input", "engines", "maswe_source", "instructions")
    }
    base["section_counts"] = {name: len(context[name]) for name in SECTIONS}
    base["coverage_summary"] = {
        state: sum(c["state"] == state for c in report["coverage"])
        for state in {c["state"] for c in report["coverage"]}
    }
    base["audit_incomplete"] = report_incomplete(report)
    base["audit_limited"] = report_limited(report)
    base["filters"] = {"severity": severity, "status": status}
    return page(base, section, values, cursor, limit, max_bytes)


def finding_context(
    item: dict, *, report_id: str | None = None, cursor=0, limit=20, max_bytes=DEFAULT_BYTES
) -> dict:
    result = assistant_finding(item)
    if report_id is not None:
        result["report_id"] = report_id
    evidence = result.pop("evidence")
    return page(result, "evidence", evidence, cursor, limit, max_bytes)


def untrusted_context(value: dict) -> dict:
    """A report-derived model response: no source excerpts, plus the fixed evidence boundary."""
    result = assistant_finding(value)
    result["instructions"] = MODEL_CONTEXT_INSTRUCTIONS
    return result


COMPARE_FINDING_LISTS = ("added", "changed", "no_longer_observed")


def compare_context(result: dict, *, max_bytes: int = DEFAULT_BYTES) -> dict:
    """Model-facing report comparison: no source excerpts, fixed guidance, bounded size.

    Finding lists keep their order; entries that do not fit are counted in
    ``omitted`` and can be inspected with reports_get or reports_followup.
    """
    if type(max_bytes) is not int or not 4096 <= max_bytes <= 262144:
        raise ValueError("max_bytes must be 4096–262144")
    # assistant_finding removes every nested `excerpt`, including verification traces.
    context = assistant_finding(result)
    context["instructions"] = MODEL_CONTEXT_INSTRUCTIONS
    lists = {key: context.get(key) or [] for key in COMPARE_FINDING_LISTS}
    counts = {key: len(values) for key, values in lists.items()}
    context.update({key: [] for key in COMPARE_FINDING_LISTS})
    context["finding_counts"] = counts
    context["omitted"] = dict.fromkeys(COMPARE_FINDING_LISTS, 0)
    context["partial_response"] = False
    budget = max_bytes - 512
    if _size(context) > budget:
        # Coverage of unchanged checks is the least informative part of a diff.
        for side, other in (("coverage_before", "coverage_after"), ("coverage_after", "coverage_before")):
            peers = {
                (entry.get("rule_id"), entry.get("state"))
                for entry in result.get(other) or []
                if isinstance(entry, dict)
            }
            context[side] = [
                entry
                for entry in context.get(side) or []
                if not isinstance(entry, dict) or (entry.get("rule_id"), entry.get("state")) not in peers
            ]
        context["coverage_unchanged_omitted"] = True
        context["partial_response"] = True
    used = _size(context)
    for key in COMPARE_FINDING_LISTS:
        for entry in lists[key]:
            cost = _size({"entry": entry})
            if used + cost > budget:
                context["omitted"][key] += 1
                continue
            context[key].append(entry)
            used += cost
    if any(context["omitted"].values()):
        context["partial_response"] = True
    if _size(context) > max_bytes:
        raise ValueError("Comparison metadata exceeds the byte budget")
    return context
