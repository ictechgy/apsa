"""Import another tool's SARIF results into an APSA report as corroborating evidence.

Imported results are untrusted data: they are bounded, sanitized and kept as
candidates with ``origin: external``. APSA did not execute those checks, so
they never add APSA coverage. Where an imported result and an APSA finding for
a related weakness sit at the same location, each records the other.
"""

from __future__ import annotations

import copy
import json
import re
from pathlib import Path, PurePosixPath

from .core import digest, finding, now, read_bounded, redact, severity_rank, uid
from .maswe import finding_weaknesses, weakness_index

MAX_SARIF_BYTES = 16 * 1024 * 1024
MAX_RESULTS = 5000
LINE_WINDOW = 3


def _slug(value: str, limit: int = 60) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "-", value).strip("-")[:limit] or "unknown"


CREDENTIAL = re.compile(
    r"(?i)\b([\w.-]*(?:token|secret|password|passwd|pwd|api[_-]?key|auth)[\w.-]*\s*[=:]\s*)[^\s,;]+"
)


def _object(value: object, label: str) -> dict:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ValueError(f"Invalid SARIF {label}: expected an object")
    return value


def _array(value: object, label: str) -> list:
    if value is None:
        return []
    if not isinstance(value, list):
        raise ValueError(f"Invalid SARIF {label}: expected an array")
    return value


def _string(value: object, label: str) -> str:
    if value is None:
        return ""
    if not isinstance(value, str):
        raise ValueError(f"Invalid SARIF {label}: expected a string")
    return value


def _text(value: object, limit: int = 300) -> str:
    """Untrusted tool text: no literal contents or credential-like assignments."""
    text = re.sub(r"""(["'`])(?:\\.|(?!\1).)*?\1""", '"…"', _string(value, "text")[: limit * 8])
    return redact(CREDENTIAL.sub(r"\1[REDACTED]", text)).replace("\n", " ")[:limit]


def _severity(rule: dict, result: dict) -> str:
    level = _string(result.get("level"), "result level")
    score = _object(rule.get("properties"), "rule properties").get("security-severity")
    try:
        value = float(score) if isinstance(score, (str, int, float)) else None
    except (ValueError, OverflowError):
        value = None
    if value is not None:
        return "critical" if value >= 9 else "high" if value >= 7 else "medium" if value >= 4 else "low"
    level = (
        level
        or _string(
            _object(rule.get("defaultConfiguration"), "rule default configuration").get("level"), "rule level"
        )
        or "warning"
    )
    return {"error": "medium", "warning": "low"}.get(level, "info")


def _cwes(rule: dict) -> list[str]:
    tags = _object(rule.get("properties"), "rule properties").get("tags") or []
    found = []
    for tag in tags if isinstance(tags, list) else []:
        if not isinstance(tag, str):
            continue
        match = re.search(r"cwe[-/]?(\d{1,5})", tag, re.I)
        if match and f"CWE-{int(match[1])}" not in found:
            found.append(f"CWE-{int(match[1])}")
    return found


def _location(result: dict, root: str) -> tuple[str | None, int | None]:
    for location in _array(result.get("locations"), "result locations"):
        physical = _object(_object(location, "location").get("physicalLocation"), "physical location")
        uri = _string(_object(physical.get("artifactLocation"), "artifact location").get("uri"), "URI")
        if not uri or "://" in uri or uri.startswith("/") or ".." in PurePosixPath(uri).parts:
            continue
        if root and uri.startswith(root + "/"):
            uri = uri[len(root) + 1 :]
        line = _object(physical.get("region"), "region").get("startLine")
        return uri, line if type(line) is int and line > 0 else None
    return None, None


def external_findings(raw: bytes, tool: str, root: str = "") -> tuple[list[dict], dict]:
    if len(raw) > MAX_SARIF_BYTES:
        raise ValueError("SARIF file exceeds 16 MiB")
    try:
        document = json.loads(raw)
    except (ValueError, UnicodeError, RecursionError) as error:
        raise ValueError(f"SARIF is not valid JSON: {error}") from None
    if not isinstance(document, dict) or document.get("version") != "2.1.0":
        raise ValueError("Only SARIF 2.1.0 is supported")
    cwe_to_maswe: dict[str, list[str]] = {}
    for weakness in weakness_index()["weaknesses"]:
        for cwe in weakness["cwe"]:
            cwe_to_maswe.setdefault(cwe, []).append(weakness["id"])
    from .output import sarif_root

    root = sarif_root(root) or ""
    label = _slug(tool, 40)
    findings, drivers, skipped, total = [], [], 0, 0
    for run_value in _array(document.get("runs"), "runs"):
        run = _object(run_value, "run")
        driver = _object(_object(run.get("tool"), "tool").get("driver"), "driver")
        drivers.append({"name": _text(driver.get("name"), 80), "version": _text(driver.get("version"), 40)})
        # Keep positional slots: dropping malformed entries changes the meaning of ruleIndex.
        rules = _array(driver.get("rules"), "rules")
        by_id = {r["id"]: r for r in rules if isinstance(r, dict) and isinstance(r.get("id"), str)}
        for result in _array(run.get("results"), "results"):
            total += 1
            if total > MAX_RESULTS:
                skipped += 1
                continue
            if not isinstance(result, dict):
                skipped += 1
                continue
            index = result.get("ruleIndex")
            indexed_rule = rules[index] if type(index) is int and 0 <= index < len(rules) else {}
            indexed_rule = indexed_rule if isinstance(indexed_rule, dict) else {}
            rule_id = _string(result.get("ruleId"), "result rule ID")
            if rule_id and indexed_rule and indexed_rule.get("id") != rule_id:
                raise ValueError("Invalid SARIF result: rule ID and index disagree")
            rule = by_id.get(rule_id, {}) if rule_id else indexed_rule
            rule_name = rule_id or _string(rule.get("id"), "rule ID") or "unknown"
            path, line = _location(result, root)
            if path is None:
                skipped += 1
                continue
            cwes = _cwes(rule)
            maswe = sorted({w for cwe in cwes for w in cwe_to_maswe.get(cwe, [])})
            evidence: dict[str, object] = {
                "path": path,
                "external_tool": label,
                "external_rule": _text(rule_name, 120),
                "external_message": _text(_object(result.get("message"), "result message").get("text")),
                "basis": "imported SARIF result; APSA did not execute this check",
            }
            if line:
                evidence["line"] = line
            title = _object(rule.get("shortDescription"), "rule short description").get("text") or rule_name
            help_uri = _string(rule.get("helpUri"), "rule help URI")
            findings.append(
                finding(
                    f"EXT-{label}-{_slug(rule_name)}",
                    _text(title, 160),
                    _severity(rule, result),
                    "candidate",
                    [evidence],
                    "Review the imported result in its tool; APSA did not verify it.",
                    "",
                    [help_uri] if help_uri.startswith("https://") else [],
                    origin="external",
                    maswe=maswe,
                    cwe=cwes,
                )
            )
    return findings, {
        "tool": label,
        "drivers": drivers[:10],
        "sha256": digest(raw),
        "results": total,
        "imported": len(findings),
        "skipped": skipped,
    }


def _near(a: dict, b: dict) -> bool:
    left = (a.get("evidence") or [{}])[0]
    for right in b.get("evidence") or []:
        if not isinstance(right, dict) or not right.get("path") or not left.get("path"):
            continue
        same = (
            right["path"] == left["path"]
            or right["path"].endswith("/" + left["path"])
            or left["path"].endswith("/" + right["path"])
        )
        first, second = left.get("line"), right.get("line")
        if same and (
            not isinstance(first, int) or not isinstance(second, int) or abs(first - second) <= LINE_WINDOW
        ):
            return True
    return False


def ingest(store, report_id: str, sarif_path: Path, tool: str, root: str = "") -> dict:
    from .audit import summarize

    previous = store.report(report_id)
    imported, record = external_findings(read_bounded(sarif_path, MAX_SARIF_BYTES), tool, root)
    report = copy.deepcopy(previous)
    report["id"] = uid("audit")
    report["created"] = now()
    report["parent_report"] = previous["id"]
    # Re-importing a tool replaces its earlier results.
    report["findings"] = [
        f
        for f in report["findings"]
        if not (f.get("origin") == "external" and f["evidence"][0].get("external_tool") == record["tool"])
    ]
    for item in report["findings"]:
        if item.get("external_corroboration"):
            item["external_corroboration"] = [
                c for c in item["external_corroboration"] if c.get("tool") != record["tool"]
            ]
    native = [f for f in report["findings"] if f.get("origin") != "external"]
    for external in imported:
        matches = [
            f
            for f in native
            if set(external.get("maswe") or []) & set(finding_weaknesses(f)) and _near(external, f)
        ]
        external["evidence"][0]["corroborated_by"] = [f["id"] for f in matches][:20]
        for match in matches:
            match.setdefault("external_corroboration", []).append(
                {
                    "tool": record["tool"],
                    "rule": external["evidence"][0]["external_rule"],
                    "finding_id": external["id"],
                }
            )
    report["findings"] = sorted(report["findings"] + imported, key=lambda f: -severity_rank(f["severity"]))
    report["coverage"] = [c for c in report["coverage"] if c.get("rule_id") != f"EXTERNAL-{record['tool']}"]
    report["coverage"].append(
        {
            "rule_id": f"EXTERNAL-{record['tool']}",
            "state": "not-applicable",
            "method": "external-sarif",
            "note": f"{record['imported']} results imported from {record['tool']}; APSA did not execute these checks, so they add no APSA coverage.",
        }
    )
    report["external_inputs"] = [
        item for item in report.get("external_inputs", []) if item.get("tool") != record["tool"]
    ] + [record]
    report["summary"] = summarize(report)
    return store.save_report(report)
