from __future__ import annotations

import json
import re
from importlib.resources import files
from itertools import islice

from .core import code_excerpt, finding
from .maswe import weaknesses_for


def rules() -> list[dict]:
    from .quaygate_analysis import catalog

    data = files("mobile_audit").joinpath("data")
    loaded = (
        json.loads(data.joinpath("rules.json").read_text())
        + json.loads(data.joinpath("structural-rules.json").read_text())
        + catalog()
    )
    # One MASWE v1.0 mapping for the catalog, findings, SARIF and coverage matrix.
    return [{**rule, "maswe": list(weaknesses_for(rule["id"]))} for rule in loaded]


def strip_comments(text: str) -> str:
    # Preserve offsets/line numbers; don't remove URL slashes inside string literals.
    pattern = r""""(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|//[^\n]*|/\*[\s\S]*?\*/"""
    return re.sub(
        pattern, lambda m: re.sub(r"[^\n]", " ", m[0]) if m[0].startswith(("//", "/*")) else m[0], text
    )


def static_checks(
    inventory: dict, sources: list[tuple[str, str]], pattern_exclusions: dict | None = None
) -> tuple[list[dict], list[dict]]:
    findings = []
    coverage = []
    for rule in rules():
        if rule["mode"] != "source":
            continue
        applicable = not rule.get("platform") or rule["platform"] in inventory["platforms"]
        # Compiled packages carry binary XML; a text pattern cannot run on it.
        source_files = [
            (path, text)
            for path, text in sources
            if PathSuffix(path) in rule.get("suffixes", [])
            and (PathSuffix(path) != ".xml" or text.lstrip("\ufeff \t\r\n").startswith("<"))
        ]
        truncated = False
        if not applicable:
            state = "not-applicable"
        elif not source_files:
            state = "not-run"
        else:
            state = "checked"
            for path, text in source_files:
                cleaned = strip_comments(text)
                if rule.get("requires") and not re.search(rule["requires"], cleaned):
                    continue
                # Some APIs are a property of the file (for example a deprecated class); report its first use.
                matches = islice(
                    re.finditer(rule["pattern"], cleaned, 0 if rule.get("case_sensitive") else re.I),
                    1 if rule.get("once_per_file") else 31,
                )
                for index, match in enumerate(matches):
                    if index == 30:
                        state = "partial"
                        truncated = True
                        break
                    excluded = (pattern_exclusions or {}).get(path, {}).get(rule["id"], [])
                    start = len(text[: match.start()].encode("utf-8"))
                    end = len(text[: match.end()].encode("utf-8"))
                    if any(item["start"] == start and end <= item["end"] for item in excluded):
                        continue
                    if len(findings) >= 2000:
                        state = "partial"
                        break
                    line_number = cleaned.count("\n", 0, match.start()) + 1
                    evidence = [
                        {
                            "path": path,
                            "line": line_number,
                            "excerpt": code_excerpt(text.splitlines()[line_number - 1]),
                            "basis": "source-pattern",
                        }
                    ]
                    findings.append(
                        finding(
                            rule["id"],
                            rule["title"],
                            rule["severity"],
                            "candidate",
                            evidence,
                            rule["remediation"],
                            rule["masvs"],
                            rule["references"],
                            confidence="heuristic",
                            mastg_tests=rule.get("mastg_tests", []),
                            maswe=rule.get("maswe", []),
                        )
                    )
        coverage.append(
            {
                "rule_id": rule["id"],
                "state": state,
                "method": "source-pattern",
                "mastg_tests": rule.get("mastg_tests", []),
                "mapping_scope": rule.get("mapping_scope", "partial"),
                "truncated": truncated,
                "note": "Pattern check is not proof of exploitability or complete absence of defects."
                + (
                    " Per-file finding limit reached; additional matching evidence was omitted."
                    if truncated
                    else ""
                ),
            }
        )
    for config in inventory["android_config"]:
        for flag, rule_id, title, remediation in [
            (
                config["debuggable"] == "true",
                "ANDROID-DEBUG",
                "Debuggable app build",
                "Ensure the release variant has android:debuggable=false.",
            ),
            (
                config["cleartext"] == "true",
                "ANDROID-CLEARTEXT",
                "Cleartext traffic explicitly allowed",
                "Restrict cleartext traffic and review network security configuration.",
            ),
        ]:
            if flag:
                findings.append(
                    finding(
                        rule_id,
                        title,
                        "medium",
                        "configuration-confirmed"
                        if rule_id == "ANDROID-DEBUG" or not config["network_security_config"]
                        else "candidate",
                        [{"path": config["path"], "configuration": config}],
                        remediation,
                        "MASVS-NETWORK" if "CLEAR" in rule_id else "MASVS-RESILIENCE",
                        ["https://developer.android.com/privacy-and-security/security-config"],
                    )
                )
    for config in inventory["ios_config"]:
        ats = config["ats"]
        if ats.get("NSAllowsArbitraryLoads") or ats.get("NSAllowsArbitraryLoadsInWebContent"):
            findings.append(
                finding(
                    "IOS-ATS",
                    "App Transport Security exception",
                    "medium",
                    "configuration-confirmed",
                    [{"path": config["path"], "ats": ats}],
                    "Remove broad ATS exceptions or document and restrict the domains that need them.",
                    "MASVS-NETWORK",
                    [
                        "https://developer.apple.com/documentation/bundleresources/information-property-list/nsapptransportsecurity"
                    ],
                )
            )
    for platform in inventory["platforms"]:
        coverage.append(
            {
                "rule_id": f"{platform.upper()}-CONFIG",
                "state": "checked"
                if any(c.get("bundle_role") != "embedded" for c in inventory[f"{platform}_config"])
                else "not-run",
                "method": "configuration",
            }
        )
    for rule, group, note in [
        (
            "RUNTIME-DEEPLINK",
            "MASVS-PLATFORM",
            "Run a scenario on a prepared device to verify link behavior and authentication.",
        ),
        (
            "RUNTIME-RESIDUAL",
            "MASVS-STORAGE",
            "Capture known test canaries before/after logout and across accounts; storage presence alone does not prove cross-account exposure.",
        ),
    ]:
        coverage.append(
            {"rule_id": rule, "masvs": group, "state": "not-run", "method": "runtime", "note": note}
        )
    unique = {f["id"]: f for f in findings}
    return list(unique.values()), coverage


def PathSuffix(path: str) -> str:
    return "." + path.rsplit(".", 1)[-1] if "." in path else ""
