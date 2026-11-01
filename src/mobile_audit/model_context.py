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
# verification=true lists grow with the diff; they are bounded like finding lists.
VERIFICATION_LISTS = ("finding_transitions", "runtime_pairs")
COVERAGE_LISTS = ("coverage_before", "coverage_after")
# Identity, counts, pairing states and fixed notes kept when other metadata cannot fit.
COMPARE_IDENTITY = {
    "before",
    "after",
    "note",
    "unchanged",
    "audit_incomplete_before",
    "audit_incomplete_after",
    "audit_limited_before",
    "audit_limited_after",
    "instructions",
    "finding_counts",
    "verification_counts",
    "coverage_counts",
    "coverage_unchanged_omitted",
    "omitted",
    "partial_response",
    "verification",
    *COMPARE_FINDING_LISTS,
    *COVERAGE_LISTS,
}
VERIFICATION_IDENTITY = {
    "schema_version",
    "before_report_id",
    "after_report_id",
    "normalization_basis",
    "build_pairing",
    "note",
    *VERIFICATION_LISTS,
}
PAIRING_IDENTITY = {
    "scope_pairing": (
        "state",
        "original_state",
        "normalization_basis",
        "normalized_fields",
        "before_sha256",
        "after_sha256",
        "comparison_before_sha256",
        "comparison_after_sha256",
    ),
    "path_pairing": ("state", "portable_inputs_requested", "normalized", "reason"),
}


def _identity_only(context: dict) -> dict:
    """Drop app-controlled bulk (scope inventories, input snapshots, other metadata)."""
    reduced = {key: value for key, value in context.items() if key in COMPARE_IDENTITY}
    verification = context.get("verification")
    if isinstance(verification, dict):
        kept = {key: value for key, value in verification.items() if key in VERIFICATION_IDENTITY}
        for name, fields in PAIRING_IDENTITY.items():
            pairing = verification.get(name)
            if isinstance(pairing, dict):
                kept[name] = {key: pairing[key] for key in fields if key in pairing}
        reduced["verification"] = kept
    reduced["metadata_truncated"] = True
    reduced["partial_response"] = True
    return reduced


def _take(context: dict, container: dict, keys: tuple[str, ...], prefix: str = "") -> list[tuple]:
    """Empty each list-valued key for bounded refilling; return (container, key, entries, label)."""
    taken = []
    for key in keys:
        values = container.get(key)
        if isinstance(values, list):
            container[key] = []
            taken.append((container, key, values, prefix + key))
            context["omitted"][prefix + key] = 0
    return taken


def compare_context(result: dict, *, max_bytes: int = DEFAULT_BYTES) -> dict:
    """Model-facing report comparison: no source excerpts, fixed guidance, bounded size.

    Finding lists, verification transitions and runtime pairs, and coverage
    entries share the budget in turn and keep their order. Entries that do not
    fit are counted in ``omitted`` (verification lists as ``verification.<name>``)
    and can be inspected with reports_get or reports_followup; coverage entries
    unchanged between the reports are dropped first. A large diff never raises:
    excess entries are omitted and oversized metadata is reduced to identity and
    pairing state.
    """
    if type(max_bytes) is not int or not 4096 <= max_bytes <= 262144:
        raise ValueError("max_bytes must be 4096–262144")
    # assistant_finding removes every nested `excerpt`, including verification traces.
    context = assistant_finding(result)
    context["instructions"] = MODEL_CONTEXT_INSTRUCTIONS
    context["omitted"] = {}
    for key in COMPARE_FINDING_LISTS:
        context[key] = context.get(key) or []
    pending = _take(context, context, COMPARE_FINDING_LISTS)
    context["finding_counts"] = {key: len(values) for _, key, values, _ in pending}
    verification = context.get("verification")
    if isinstance(verification, dict):
        taken = _take(context, verification, VERIFICATION_LISTS, "verification.")
        context["verification_counts"] = {key: len(values) for _, key, values, _ in taken}
        pending += taken
    coverage = _take(context, context, COVERAGE_LISTS)
    context["coverage_counts"] = {key: len(values) for _, key, values, _ in coverage}
    context["partial_response"] = False
    budget = max_bytes - 512
    costs = [[_size({"entry": entry}) for entry in values] for _, _, values, _ in pending + coverage]
    if _size(context) + sum(map(sum, costs)) > budget:
        # Coverage of unchanged checks is the least informative part of a diff.
        for index, (_, side, values, _) in enumerate(coverage, len(pending)):
            other = "coverage_after" if side == "coverage_before" else "coverage_before"
            peers = {
                (entry.get("rule_id"), entry.get("state"))
                for entry in result.get(other) or []
                if isinstance(entry, dict)
            }
            changed = [
                not isinstance(entry, dict) or (entry.get("rule_id"), entry.get("state")) not in peers
                for entry in values
            ]
            context["omitted"][side] += changed.count(False)
            values[:] = [entry for entry, keep in zip(values, changed, strict=True) if keep]
            costs[index] = [cost for cost, keep in zip(costs[index], changed, strict=True) if keep]
        context["coverage_unchanged_omitted"] = True
        context["partial_response"] = True
    pending += coverage
    if _size(context) > budget:
        context = _identity_only(context)
        # Containers of the top-level lists are now the reduced context.
        pending = [
            (context if container is not verification else context["verification"], key, values, label)
            for container, key, values, label in pending
        ]
    used = _size(context)
    # One entry from each list in turn: every list keeps a share of the budget.
    for position in range(max((len(values) for _, _, values, _ in pending), default=0)):
        for (container, key, values, label), list_costs in zip(pending, costs, strict=True):
            if position >= len(values):
                continue
            if used + list_costs[position] > budget:
                context["omitted"][label] += 1
                continue
            container[key].append(values[position])
            used += list_costs[position]
    if any(context["omitted"].values()):
        context["partial_response"] = True
    if _size(context) > max_bytes:
        # Identity metadata is bounded by report IDs and fixed text; unreachable in practice.
        raise ValueError("Comparison metadata exceeds the byte budget")
    return context
