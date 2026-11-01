"""Helpers for the composite GitHub Action; standard library only."""

from __future__ import annotations

import json
import os
import runpy
import sys
from collections import Counter
from pathlib import Path

# Load only the stdlib helper, avoiding package/dependency imports under python -I.
# The Action owns this source alongside its script, even before APSA is installed.
_completeness = runpy.run_path(str(Path(__file__).resolve().parents[1] / "src/mobile_audit/completeness.py"))
report_incomplete = _completeness["report_incomplete"]
report_limited = _completeness["report_limited"]


def sarif_root(target: str, workspace: str) -> str:
    """Repository-relative path of the target, or an error outside the workspace."""
    path = os.path.realpath(target)
    base = os.path.realpath(workspace)
    if path == base:
        return ""
    if os.path.commonpath([path, base]) != base:
        raise SystemExit("::error::path must be inside the workspace")
    return os.path.relpath(path, base).replace(os.sep, "/")


def envelope(path: str) -> dict:
    try:
        with open(path, encoding="utf-8") as handle:
            value = json.load(handle)
    except (OSError, ValueError):
        return {}
    return value if isinstance(value, dict) else {}


def report_of(result: dict) -> dict:
    data = result.get("data")
    if isinstance(data, dict) and isinstance(data.get("report"), dict):
        return data["report"]
    # Direct CLI payloads and exported full reports share these report fields.
    fields = ("findings", "coverage", "inventory", "id", "summary", "runtime", "online_query")
    if isinstance(data, dict):
        return data if any(key in data for key in fields) else {}
    return result if any(key in result for key in fields) else {}


def gate_of(result: dict) -> dict:
    """The policy gate of a ``scan --policy`` envelope, or an empty dict."""
    data = result.get("data")
    gate = data.get("gate") if isinstance(data, dict) else None
    return gate if isinstance(gate, dict) else {}


def effective_strict(result: dict, strict: bool) -> bool:
    """The Action input or the evaluated policy's strict_coverage: either counts limited coverage."""
    policy = gate_of(result).get("policy")
    return strict or (isinstance(policy, dict) and policy.get("strict_coverage") is True)


def partial_audit_reason(result: dict) -> bool:
    """Whether the policy gate recorded a partial-audit reason (it may share exit 4 with a failure)."""
    return any(
        isinstance(reason, dict) and reason.get("code") == "partial-audit"
        for reason in gate_of(result).get("reasons") or []
    )


RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def threshold_exceeded(path: str, fail_on: str) -> bool:
    """Whether a policy or severity threshold failed, independent of audit completeness.

    With a policy, every gate reason counts except partial-audit, which the
    policy's own setting and fail-on-incomplete govern: tolerating partial
    parsing must not switch off required rules, waivers or baseline checks.
    """
    if fail_on not in {*RANK, ""}:
        raise SystemExit("::error::unsupported fail-on value")
    result = envelope(path)
    data = result.get("data") if isinstance(result.get("data"), dict) else {}
    gate = data.get("gate") if isinstance(data, dict) else None
    if isinstance(gate, dict):
        return any(
            isinstance(reason, dict) and reason.get("code") != "partial-audit"
            for reason in gate.get("reasons") or []
        )
    if fail_on not in RANK:
        return False
    return any(
        isinstance(item, dict)
        and item.get("status") != "candidate"
        and RANK.get(item.get("severity", ""), -1) >= RANK[fail_on]
        for item in report_of(result).get("findings", [])
    )


def strict_flag(value: str) -> bool:
    """The Action's strict-coverage input: exactly "true" or "false"."""
    if value not in {"true", "false"}:
        raise SystemExit("::error::strict-coverage must be true or false")
    return value == "true"


def audit_incomplete(path: str, strict: bool = False) -> bool:
    """Whether the report itself is partial, whatever exit code a lenient policy produced.

    With ``strict`` or a policy with ``strict_coverage = true``, limited coverage
    (a precision limit) also counts as incomplete, as does a partial-audit gate reason.
    """
    result = envelope(path)
    report = report_of(result)
    return bool(report) and (
        report_incomplete(report, strict=effective_strict(result, strict))
        or (report.get("summary") or {}).get("incomplete") is True
        or partial_audit_reason(result)
    )


def gate_reasons(path: str) -> list[str]:
    """Policy gate reason codes that fail the job (every code except partial-audit)."""
    result = envelope(path)
    data = result.get("data") if isinstance(result.get("data"), dict) else {}
    gate = data.get("gate") if isinstance(data, dict) else None
    if not isinstance(gate, dict):
        return []
    codes = [
        str(reason.get("code"))
        for reason in gate.get("reasons") or []
        if isinstance(reason, dict) and reason.get("code") != "partial-audit"
    ]
    return sorted(set(codes))


def summary(path: str, code: str, strict: bool = False) -> str:
    result = envelope(path)
    report = report_of(result)
    lines = ["## APSA mobile security audit", ""]
    if not report:
        error = (result.get("error") or {}).get("message", "no report was produced")
        return "\n".join(lines + [f"APSA did not complete: {error} (exit code {code})."]) + "\n"
    inventory = report.get("inventory") or {}
    snapshot = inventory.get("input_snapshot") or {}
    strict = effective_strict(result, strict)
    incomplete = (
        report_incomplete(report, strict=strict)
        or code == "3"
        or (report.get("summary") or {}).get("incomplete") is True
        or partial_audit_reason(result)
    )
    limited = report_limited(report)
    # Exit 3 returns the report in an ok: false envelope: an incomplete audit, not an execution error.
    failed = code not in {"0", "3", "4"} or (result.get("ok") is False and code != "3")
    execution = "failed" if failed else "incomplete" if incomplete else "complete for the stated scope"
    lines += [
        f"- Report: `{report.get('id')}` · APSA {report.get('tool_version')} · rules `{report.get('rule_version')}`",
        f"- Audit execution: **{execution}** (exit code {code})",
    ]
    if limited:
        lines.append(
            "- Limited coverage: every input was examined, but the bounded static model abstained on some "
            "paths; "
            + (
                "strict coverage counts this as incomplete."
                if strict
                else "this does not make the audit incomplete unless strict-coverage is set."
            )
        )
    if failed:
        error = (result.get("error") or {}).get("message", "audit execution failed")
        lines.append(f"- Execution error: {error}.")
    if snapshot:
        lines.append(
            f"- Input staging: **{'partial' if snapshot.get('partial') else 'complete'}**; "
            f"{snapshot.get('files', '?')} files, {snapshot.get('bytes', '?')} bytes staged; "
            f"app scope {'unknown' if snapshot.get('app_scope_complete') is False else 'retained'}."
        )
        for kind, count in sorted((snapshot.get("omitted") or {}).items()):
            lines.append(f"- Omitted {kind}: {count['files']} files, {count['bytes']} bytes.")
        modules = snapshot.get("omitted_by_module") or {}
        if modules:
            lines.append(
                f"- Input omissions affect {snapshot.get('omitted_module_groups', len(modules))} "
                "inferred module group(s); "
                "see the report's input_snapshot.omitted_by_module for file and byte counts."
            )
        if snapshot.get("omitted_by_module_truncated"):
            lines.append("- Additional module counts are combined in input_snapshot.omitted_other_modules.")
    findings = report.get("findings", [])
    severities = Counter(item.get("severity", "unknown") for item in findings)
    statuses = Counter(item.get("status", "unknown") for item in findings)
    lines.append(
        f"- Findings: {len(findings)} ("
        + ", ".join(f"{key} {value}" for key, value in sorted(severities.items()))
        + ")"
        if findings
        else "- Findings: none observed by the executed checks; review coverage before treating this as safe."
    )
    if statuses:
        lines.append("- Evidence: " + ", ".join(f"{key} {value}" for key, value in sorted(statuses.items())))
    coverage = Counter(item.get("state", "unknown") for item in report.get("coverage", []))
    lines.append("- Coverage: " + ", ".join(f"{key} {value}" for key, value in sorted(coverage.items())))
    gate = (result.get("data") or {}).get("gate") if isinstance(result.get("data"), dict) else None
    if isinstance(gate, dict):
        lines.append(f"- Policy: **{gate.get('state', 'unknown')}**")
        # Notices (for example waiver severity escalations) never fail the job; reasons do.
        notices = Counter(
            str(notice.get("code"))
            for notice in gate.get("notices") or []
            if isinstance(notice, dict) and str(notice.get("code")).replace("-", "").isalnum()
        )
        if notices:
            lines.append(
                "- Policy notices (non-blocking): "
                + ", ".join(f"{code} {count}" for code, count in sorted(notices.items()))
            )
    lines += [
        "",
        "Candidate findings are heuristics; not-run, partial and limited coverage never mean safe.",
    ]
    return "\n".join(lines) + "\n"


def main(argv: list[str]) -> int:
    if argv[:1] == ["--sarif-root"] and len(argv) == 3:
        print(sarif_root(argv[1], argv[2]))
        return 0
    if argv[:1] == ["--report-id"] and len(argv) == 2:
        report_id = report_of(envelope(argv[1])).get("id")
        if isinstance(report_id, str):
            print(f"report-id={report_id}")
        return 0
    if argv[:1] == ["--threshold"] and len(argv) == 3:
        print(f"threshold-exceeded={'true' if threshold_exceeded(argv[1], argv[2]) else 'false'}")
        # Reason codes are fixed identifiers; keep only safe characters for the output file.
        codes = [c for c in gate_reasons(argv[1]) if c.replace("-", "").isalnum()]
        print(f"gate-reasons={','.join(codes)}")
        return 0
    if argv[:1] == ["--incomplete"] and len(argv) in {2, 3}:
        strict = strict_flag(argv[2]) if len(argv) == 3 else False
        print(f"incomplete={'true' if audit_incomplete(argv[1], strict) else 'false'}")
        return 0
    if argv[:1] == ["--summary"] and len(argv) in {3, 4}:
        strict = strict_flag(argv[3]) if len(argv) == 4 else False
        sys.stdout.write(summary(argv[1], argv[2], strict))
        return 0
    raise SystemExit(
        "usage: action_summary.py --sarif-root TARGET WORKSPACE | --report-id RESULT"
        " | --threshold RESULT FAIL_ON | --incomplete RESULT [STRICT] | --summary RESULT CODE [STRICT]"
        " (STRICT is true or false)"
    )


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
