"""Cross-check a finding claimed elsewhere (for example by an AI reviewer) against APSA evidence.

The result is deterministic and never refutes a claim: APSA can corroborate it
with its own finding, or report that its related checks did, partially did, or
did not run there. Absence of an APSA finding is not evidence of absence.
"""

from __future__ import annotations

import re
from pathlib import PurePosixPath

from .maswe import RULE_WEAKNESSES, UNMAPPED, weakness_index, weaknesses_for
from .rules import rules

STATUS_STRENGTH = ("candidate", "version-affected", "configuration-confirmed", "runtime-confirmed")
NOTE = (
    "APSA evidence can corroborate a claim; it cannot refute one. not-observed means the related "
    "checks ran without an APSA finding at that location, which is not proof that the weakness is absent."
)


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
            found += [w["id"] for w in known.values() if value in w["cwe"]]
        else:
            raise ValueError("weakness must be a MASWE-NNNN or CWE-N identifier")
    if rule:
        if rule not in RULE_WEAKNESSES and rule not in UNMAPPED and rule not in {r["id"] for r in rules()}:
            raise ValueError(f"Unknown APSA rule {rule}")
        found += [w for w in weaknesses_for(rule) if w not in found]
    return found


def _relative(path: str, target: str) -> str:
    value = path.replace("\\", "/")
    root = target.replace("\\", "/").rstrip("/") + "/"
    if value.startswith(root):
        value = value[len(root) :]
    return str(PurePosixPath(value.lstrip("/")))


def _same_file(evidence_path: str, claimed: str) -> bool:
    evidence = str(PurePosixPath(evidence_path.replace("\\", "/").lstrip("/")))
    return evidence == claimed or evidence.endswith("/" + claimed) or claimed.endswith("/" + evidence)


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
    checks = sorted(
        {rule_id for rule_id, mapped in RULE_WEAKNESSES.items() if set(mapped) & set(weaknesses)}
        | ({rule} if rule else set())
    )
    claimed = _relative(path, report.get("target", "")) if path else None
    states: dict[str, set[str]] = {}
    for item in report.get("coverage", []):
        if item.get("rule_id") in checks and isinstance(item.get("state"), str):
            states.setdefault(item["rule_id"], set()).add(item["state"])
    matches, elsewhere = [], []
    for item in report.get("findings", []):
        mapped = item.get("maswe") or weaknesses_for(item.get("rule_id", ""))
        if item.get("rule_id") not in checks and not set(weaknesses) & set(mapped):
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
        in_file = [e for e in located if e.get("path") and _same_file(e["path"], claimed)]
        if not in_file:
            continue
        if line is None or any(
            isinstance(e.get("line"), int) and abs(e["line"] - line) <= window for e in in_file
        ):
            matches.append(summary)
        else:
            elsewhere.append(summary)
    file_state = None
    if claimed is not None:
        for record in (report.get("inventory", {}).get("source_analysis") or {}).get("files", []):
            if isinstance(record, dict) and _same_file(str(record.get("path", "")), claimed):
                file_state = record.get("state")
    observed = set().union(*states.values()) if states else set()
    if matches:
        verdict = "corroborated"
    elif not checks:
        verdict = "not-assessed"
    elif elsewhere:
        verdict = "same-file-other-location"
    elif "partial" in observed or file_state == "partial":
        verdict = "partial"
    elif "checked" in observed:
        verdict = "not-observed"
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
        "strongest_status": strongest,
        "weaknesses": [{"id": w, "title": titles[w]} for w in weaknesses],
        "related_checks": [{"rule_id": c, "states": sorted(states.get(c, set()))} for c in checks],
        "source_file_state": file_state,
        "matching_findings": matches[:50],
        "other_findings_in_file": elsewhere[:50],
        "note": NOTE,
    }
