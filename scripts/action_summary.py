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
report_incomplete = runpy.run_path(
    str(Path(__file__).resolve().parents[1] / "src/mobile_audit/completeness.py")
)["report_incomplete"]


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


RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def threshold_exceeded(path: str, fail_on: str) -> bool:
    """Whether a policy or severity threshold failed, independent of audit completeness.

    With a policy, every gate reason counts except partial-audit, which the
    policy's own setting and fail-on-incomplete govern: tolerating partial
    parsing must not switch off required rules, waivers or baseline checks.
    """
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


def summary(path: str, code: str) -> str:
    result = envelope(path)
    report = report_of(result)
    lines = ["## APSA mobile security audit", ""]
    if not report:
        error = (result.get("error") or {}).get("message", "no report was produced")
        return "\n".join(lines + [f"APSA did not complete: {error} (exit code {code})."]) + "\n"
    inventory = report.get("inventory") or {}
    snapshot = inventory.get("input_snapshot") or {}
    incomplete = (
        report_incomplete(report) or code == "3" or (report.get("summary") or {}).get("incomplete") is True
    )
    failed = result.get("ok") is False or code not in {"0", "3", "4"}
    execution = "failed" if failed else "incomplete" if incomplete else "complete for the stated scope"
    lines += [
        f"- Report: `{report.get('id')}` · APSA {report.get('tool_version')} · rules `{report.get('rule_version')}`",
        f"- Audit execution: **{execution}** (exit code {code})",
    ]
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
    lines += [
        "",
        "Candidate findings are heuristics; not-run and partial coverage never mean safe.",
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
    if argv[:1] == ["--summary"] and len(argv) == 3:
        sys.stdout.write(summary(argv[1], argv[2]))
        return 0
    raise SystemExit(
        "usage: action_summary.py --sarif-root TARGET WORKSPACE | --report-id RESULT"
        " | --threshold RESULT FAIL_ON | --summary RESULT CODE"
    )


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
