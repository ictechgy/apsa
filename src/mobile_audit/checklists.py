"""Checklist views of a report and a finding timeline across reports.

A checklist maps external items (MASVS controls, or an organization's own
inspection items) to MASWE weaknesses and APSA rules. APSA reports the related
checks' states and findings per item; it never declares an item passed, because
a related check covers only part of a weakness.
"""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

from .core import digest, read_bounded
from .maswe import RULE_WEAKNESSES, aggregate_states, coverage_matrix, rule_state, weakness_index

MAX_CHECKLIST_BYTES = 256 * 1024
MAX_ITEMS = 500
ITEM_ID = re.compile(r"[\w.-]{1,40}")


def builtin_masvs() -> dict:
    controls: dict[str, list[str]] = {}
    for weakness in weakness_index()["weaknesses"]:
        for control in weakness["masvs"]:
            controls.setdefault(control, []).append(weakness["id"])
    return {
        "name": "OWASP MASVS v2.1 controls (through MASWE v1.0)",
        "source": "builtin:masvs-v2",
        "items": [
            {"id": control, "title": control, "maswe": sorted(ids), "rules": []}
            for control, ids in sorted(controls.items())
        ],
    }


def load_checklist(value: str) -> dict:
    """``masvs-v2`` or a TOML file with ``version = 1``, ``name`` and ``[[item]]`` entries."""
    if value == "masvs-v2":
        return builtin_masvs()
    path = Path(value)
    raw = read_bounded(path, MAX_CHECKLIST_BYTES)
    try:
        document = tomllib.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeError) as error:
        raise ValueError(f"Checklist is not valid TOML: {error}") from None
    if document.get("version") != 1 or not isinstance(document.get("name"), str):
        raise ValueError("Checklist needs version = 1 and a name")
    items = document.get("item")
    if not isinstance(items, list) or not 0 < len(items) <= MAX_ITEMS:
        raise ValueError(f"Checklist needs 1-{MAX_ITEMS} [[item]] entries")
    known_weaknesses = {w["id"] for w in weakness_index()["weaknesses"]}
    from .rules import rules

    known_rules = {r["id"] for r in rules()} | set(RULE_WEAKNESSES)
    seen, normalized = set(), []
    for item in items:
        if not isinstance(item, dict) or set(item) - {"id", "title", "maswe", "rules", "note"}:
            raise ValueError("Checklist items accept id, title, maswe, rules and note")
        identifier, title = item.get("id"), item.get("title", "")
        if not isinstance(identifier, str) or not ITEM_ID.fullmatch(identifier) or identifier in seen:
            raise ValueError(f"Invalid or duplicate checklist item id {identifier!r}")
        seen.add(identifier)
        maswe, rule_ids = item.get("maswe", []), item.get("rules", [])
        if not isinstance(title, str) or len(title) > 200:
            raise ValueError("Checklist item titles are text of at most 200 characters")
        if not isinstance(maswe, list) or not set(maswe) <= known_weaknesses:
            raise ValueError(f"Item {identifier}: unknown MASWE identifiers")
        if not isinstance(rule_ids, list) or not set(rule_ids) <= known_rules:
            raise ValueError(f"Item {identifier}: unknown APSA rules")
        normalized.append(
            {
                "id": identifier,
                "title": title,
                "maswe": sorted(maswe),
                "rules": sorted(rule_ids),
                "note": str(item.get("note", ""))[:300],
            }
        )
    return {
        "name": document["name"][:200],
        "source": f"file:{path.name}",
        "sha256": digest(raw),
        "items": normalized,
    }


def checklist_view(report: dict, checklist: dict) -> dict:
    matrix = {row["id"]: row for row in coverage_matrix(report)["weaknesses"]}
    states: dict[str, set[str]] = {}
    for item in report.get("coverage", []):
        if (
            isinstance(item, dict)
            and isinstance(item.get("rule_id"), str)
            and isinstance(item.get("state"), str)
        ):
            states.setdefault(item["rule_id"], set()).add(item["state"])
    rows = []
    for item in checklist["items"]:
        weakness_rows = [matrix[w] for w in item["maswe"] if w in matrix]
        checks = sorted({c for row in weakness_rows for c in row["checks"]} | set(item["rules"]))
        findings = sorted(
            {f for row in weakness_rows for f in row["findings"]}
            | {f["id"] for f in report.get("findings", []) if f["rule_id"] in item["rules"]}
        )
        state = aggregate_states([rule_state(states[c]) for c in checks if c in states] or ["not-run"])
        if findings:
            status = "findings"
        elif not checks:
            status = "not-assessed"
        elif (
            weakness_rows and not item["rules"] and all(r["state"] == "not-applicable" for r in weakness_rows)
        ):
            status = "not-applicable"
        else:
            status = {"checked": "no-findings-in-checked-scope", "partial": "partial"}.get(state, "not-run")
        rows.append(
            {
                **item,
                "checks": checks,
                "status": status,
                "findings": findings[:50],
                "finding_count": len(findings),
            }
        )
    summary: dict[str, int] = {}
    for row in rows:
        summary[row["status"]] = summary.get(row["status"], 0) + 1
    return {
        "report_id": report["id"],
        "checklist": {k: checklist[k] for k in ("name", "source") if k in checklist}
        | ({"sha256": checklist["sha256"]} if "sha256" in checklist else {}),
        "note": "Status reflects APSA's related checks only. no-findings-in-checked-scope means every related "
        "check that applied ran fully without findings; it is not a pass. A mix of run and not-run checks is "
        "partial; items outside APSA's checks need other evidence.",
        "summary": summary,
        "items": rows,
    }


def checklist_markdown(view: dict) -> str:
    lines = [
        f"# {view['checklist']['name']}",
        f"\nReport: `{view['report_id']}`",
        f"\n{view['note']}",
        "\nSummary: " + ", ".join(f"{k} {v}" for k, v in sorted(view["summary"].items())),
        "\n| Item | Status | Related checks | Findings |",
        "| --- | --- | --- | --- |",
    ]
    for row in view["items"]:
        title = f"{row['id']} {row['title']}".strip().replace("|", "\\|")
        checks = ", ".join(f"`{c}`" for c in row["checks"]) or "none"
        lines.append(f"| {title} | {row['status']} | {checks} | {row['finding_count']} |")
    return "\n".join(lines) + "\n"


def timeline(store, target: str, limit: int = 200) -> dict:
    """First and last observation of each finding across saved reports of one target."""
    history = list(reversed(store.target_reports(target, limit=limit)))
    entries: dict[str, dict] = {}
    report_ids = []
    for item in history:
        report = store.report(item["id"])
        report_ids.append(item["id"])
        present = set()
        for finding in report.get("findings", []):
            present.add(finding["id"])
            entry = entries.setdefault(
                finding["id"],
                {
                    "finding_id": finding["id"],
                    "rule_id": finding["rule_id"],
                    "title": finding["title"],
                    "first_seen": report["created"],
                    "first_report": report["id"],
                },
            )
            entry.update(
                last_seen=report["created"],
                last_report=report["id"],
                severity=finding["severity"],
                status=finding["status"],
            )
            entry.pop("resolved_in", None)
            entry.pop("resolved_at", None)
        for finding_id, entry in entries.items():
            if (
                finding_id not in present
                and "resolved_in" not in entry
                and entry["last_report"] != report["id"]
            ):
                entry.update(resolved_in=report["id"], resolved_at=report["created"])
    open_items = [e for e in entries.values() if "resolved_in" not in e]
    return {
        "target": target,
        "reports": report_ids,
        "note": "resolved means a later report of the same target no longer observed the finding; it is not proof "
        "of remediation unless the same checks completed. Compare coverage before closing an item.",
        "open": len(open_items),
        "resolved": len(entries) - len(open_items),
        "findings": sorted(entries.values(), key=lambda e: (e["first_seen"], e["finding_id"])),
    }
