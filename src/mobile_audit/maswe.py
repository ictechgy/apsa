"""OWASP MASWE v1.0 traceability: which APSA checks relate to each weakness.

A mapping means an APSA check looks at part of the weakness, never that it
implements every MASTG test for it. Weaknesses without a related check are
reported as not assessed rather than dropped.
"""

from __future__ import annotations

import json
from functools import cache
from importlib.resources import files

RULE_WEAKNESSES: dict[str, tuple[str, ...]] = {
    # Source patterns, AST and Objective-C candidates.
    "WEBVIEW-SSL-BYPASS": ("MASWE-0027",),
    "AST-WEBVIEW-SSL-BYPASS": ("MASWE-0027",),
    "WEBVIEW-HOST-MATCH": ("MASWE-0029", "MASWE-0035"),
    "AST-WEBVIEW-HOST-ALLOWLIST": ("MASWE-0035",),
    "AST-WEBVIEW-UNTRUSTED-URL": ("MASWE-0035", "MASWE-0029"),
    "OBJC-WEBVIEW-UNTRUSTED-REQUEST": ("MASWE-0035",),
    "WEBVIEW-JS-BRIDGE": ("MASWE-0033",),
    "AST-WEBVIEW-JS-BRIDGE": ("MASWE-0033",),
    "WEBVIEW-FILE-ACCESS": ("MASWE-0034",),
    "STORAGE-SENSITIVE-LOG": ("MASWE-0005",),
    "STORAGE-TOKEN-PREFS": ("MASWE-0001",),
    "IOS-KEYCHAIN-ACCESS": ("MASWE-0001",),
    "AST-CRYPTO-ECB": ("MASWE-0007",),
    "AST-CRYPTO-WEAK-HASH": ("MASWE-0008",),
    "OBJC-CRYPTO-WEAK-HASH": ("MASWE-0008",),
    "AST-SQL-CONCAT": ("MASWE-0050",),
    "AST-PENDINGINTENT-MUTABLE": ("MASWE-0032",),
    "SOURCE-INSECURE-RANDOM": ("MASWE-0012",),
    "SOURCE-HARDCODED-SECRET": ("MASWE-0004",),
    "IOS-PRIVACY-MANIFEST": ("MASWE-0073",),
    "ANDROID-EXPORTED-COMPONENT": ("MASWE-0018",),
    "ANDROID-ALLOW-BACKUP": ("MASWE-0006",),
    "ANDROID-TARGET-SDK": ("MASWE-0042",),
    # Compiled code and binary metadata.
    "BINARY-WEBVIEW-SSL-BYPASS": ("MASWE-0027",),
    "BINARY-WEBVIEW-JS-BRIDGE": ("MASWE-0033",),
    "BINARY-WEBVIEW-FILE-ACCESS": ("MASWE-0034",),
    "BINARY-WEBVIEW-DEBUGGING": ("MASWE-0063",),
    "BINARY-STORAGE-SENSITIVE-LOG": ("MASWE-0005",),
    "BINARY-STORAGE-TOKEN-PREFS": ("MASWE-0001",),
    "BINARY-IOS-PIE": ("MASWE-0045",),
    "BINARY-IOS-DEBUG-ENTITLEMENT": ("MASWE-0063",),
    # Declared configuration; *-CONFIG are the coverage entries for these findings.
    "ANDROID-DEBUG": ("MASWE-0063",),
    "ANDROID-CLEARTEXT": ("MASWE-0026",),
    "ANDROID-CONFIG": ("MASWE-0026", "MASWE-0063"),
    "IOS-ATS": ("MASWE-0026",),
    "IOS-CONFIG": ("MASWE-0026",),
    # Runtime scenarios on prepared test apps.
    "RUNTIME-RESIDUAL": ("MASWE-0024",),
    "RUNTIME-AUTH-EXPOSURE": ("MASWE-0024",),
    "RUNTIME-UI-EXPOSURE": ("MASWE-0024", "MASWE-0036"),
    "RUNTIME-DEEPLINK": ("MASWE-0029",),
    # Dependency intelligence.
    "DEPENDENCY-CVE": ("MASWE-0044",),
    # Bundled lint engine indicators.
    "QG-APP-DEBUGGABLE": ("MASWE-0063",),
    "QG-APP-ALLOWBACKUP": ("MASWE-0006",),
    "QG-APP-CLEARTEXT": ("MASWE-0026",),
    "QG-APP-NSC-USER-TRUST": ("MASWE-0027",),
    "QG-APP-NSC-DEBUG-OVERRIDES": ("MASWE-0027",),
    "QG-APP-EXPORTED": ("MASWE-0018",),
    "QG-APP-DEEPLINK": ("MASWE-0029",),
    "QG-APP-PROVIDER-GRANT": ("MASWE-0018",),
    "QG-APP-PROVIDER-PATHS": ("MASWE-0018",),
    "QG-APP-PERMISSIONS-DANGEROUS": ("MASWE-0066",),
    "QG-APP-CUSTOM-PERMISSIONS": ("MASWE-0018",),
    "QG-APP-TARGET-SDK": ("MASWE-0042",),
    "QG-DEX-WEAK-CRYPTO": ("MASWE-0007", "MASWE-0008"),
    "QG-DEX-WEBVIEW": ("MASWE-0033", "MASWE-0034"),
    "QG-DEX-DYNAMIC-CODE": ("MASWE-0049",),
    "QG-DEX-SECRETS": ("MASWE-0004",),
    "QG-DEX-EMBEDDED-KEYS": ("MASWE-0004",),
    "QG-DEX-CLEARTEXT-URLS": ("MASWE-0026",),
    "QG-NATIVE-HARDENING": ("MASWE-0045",),
    "QG-IPA-ATS": ("MASWE-0026",),
    "QG-IPA-ATS-DOMAINS": ("MASWE-0026",),
    "QG-IPA-FILE-SHARING": ("MASWE-0002",),
    "QG-IPA-URL-SCHEMES": ("MASWE-0029",),
    "QG-IPA-MIN-OS": ("MASWE-0041",),
    "QG-IPA-GET-TASK-ALLOW": ("MASWE-0063",),
    "QG-IPA-BINARY-HARDENING": ("MASWE-0045",),
    "QG-BIN-SECRETS": ("MASWE-0004",),
    "QG-BIN-EMBEDDED-KEYS": ("MASWE-0004",),
    "QG-BIN-WEAK-CRYPTO": ("MASWE-0007", "MASWE-0008"),
    "QG-BIN-CLEARTEXT-URLS": ("MASWE-0026",),
    "QG-BIN-WEBVIEW": ("MASWE-0033", "MASWE-0034"),
}

# Checks deliberately left without a weakness, with the reason.
UNMAPPED: dict[str, str] = {
    "QG-APP-MANIFEST-ANOMALY": "Manifest parsing anomaly indicator, not a MASWE weakness",
    "QG-APP-SIGNATURE": "Package signing scheme is distribution integrity, not a MASWE weakness",
    "QG-APP-CERT": "Signing certificate properties are distribution integrity, not a MASWE weakness",
    "QG-DEX-SCAN": "Scan scope record",
    "QG-BIN-SCAN": "Scan scope record",
    "QG-NATIVE-SCAN-SCOPE": "Scan scope record",
    "QG-DEX-TRACKERS": "Tracker SDK presence alone does not establish a privacy weakness",
    "QG-BIN-TRACKERS": "Tracker SDK presence alone does not establish a privacy weakness",
    "OS-CVE": "Device platform patch state, not a weakness of the app",
}

# Correlated intelligence findings use advisory identifiers as rule IDs.
ADVISORY_PREFIXES = ("CVE-", "GHSA-", "OSV-")
STATE_ORDER = ("partial", "checked", "not-run", "not-applicable")


@cache
def weakness_index() -> dict:
    return json.loads(files("mobile_audit").joinpath("data", "maswe.json").read_text())


def from_beta(identifier: str) -> tuple[str, ...]:
    """MASWE v1 identifiers that absorbed a beta identifier (MASTG v2.0 tests use beta IDs)."""
    return tuple(w["id"] for w in weakness_index()["weaknesses"] if identifier in w.get("beta", []))


def weaknesses_for(rule_id: str) -> tuple[str, ...]:
    if rule_id.startswith(ADVISORY_PREFIXES):
        return RULE_WEAKNESSES["DEPENDENCY-CVE"]
    return RULE_WEAKNESSES.get(rule_id, ())


def _state(states: set[str]) -> str:
    if "partial" in states:
        return "partial"
    if "checked" in states:
        return "checked"
    if states and states <= {"not-applicable"}:
        return "not-applicable"
    return "not-run"


def coverage_matrix(report: dict) -> dict:
    """Per weakness: related checks, their aggregate execution state and findings."""
    index = weakness_index()
    platforms = set(report.get("inventory", {}).get("platforms") or [])
    states: dict[str, set[str]] = {}
    for item in report.get("coverage", []):
        rule = item.get("rule_id")
        if isinstance(rule, str) and isinstance(item.get("state"), str):
            states.setdefault(rule, set()).add(item["state"])
    findings: dict[str, list[str]] = {}
    for item in report.get("findings", []):
        for weakness in weaknesses_for(item.get("rule_id", "")):
            findings.setdefault(weakness, []).append(item["id"])
    rows = []
    for weakness in index["weaknesses"]:
        checks = sorted(rule for rule, mapped in RULE_WEAKNESSES.items() if weakness["id"] in mapped)
        if platforms and not platforms & set(weakness["platform"]):
            state = "not-applicable"
        elif not checks:
            state = "not-assessed"
        else:
            observed = set().union(*(states.get(rule, set()) for rule in checks))
            state = _state(observed)
            if findings.get(weakness["id"]) and state in {"not-run", "not-applicable"}:
                # A finding is evidence that some related check executed.
                state = "checked"
        rows.append(
            {
                "id": weakness["id"],
                "title": weakness["title"],
                "masvs": weakness["masvs"],
                "platform": weakness["platform"],
                "checks": checks,
                "state": state,
                "scope": "partial" if checks else "none",
                "findings": sorted(set(findings.get(weakness["id"], []))),
            }
        )
    summary: dict[str, int] = {}
    for row in rows:
        summary[row["state"]] = summary.get(row["state"], 0) + 1
    return {
        "source": index["source"],
        "url": index["url"],
        "license": index["license"],
        "note": "A related check covers part of a weakness, not every MASTG test for it. not-assessed means APSA has no related check; not-run and partial never mean safe.",
        "summary": summary,
        "weaknesses": rows,
    }
