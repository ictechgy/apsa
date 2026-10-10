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


# Every token ends at its terminator or at the end of the line (character literals) or
# file, so a start without a terminator is consumed once instead of rescanned from each
# later quote (Android \' prose). Triple-quoted strings (Kotlin, Swift, Dart, Groovy) may
# span lines and hold quotes; a Kotlin raw string may end in extra quotes ("""say "hi"""").
# The named groups record whether a terminator was found.
TRIPLE = r"'''[\s\S]*?(?:'''|\Z)|" + '"""' + r'[\s\S]*?(?:"{3,}|\Z)'
DOUBLE = r'"(?:\\[\s\S]|[^"\\])*(?:(?P<quote>")|\\?\Z)'
SINGLE_AND_LINE = r"'(?:\\.|[^'\\\n])*(?:'|\\?$)|//[^\n]*"
BLOCK = r"/\*[\s\S]*?(?:(?P<close>\*/)|\Z)"
CLEANERS = {
    (double, block): re.compile(
        "|".join([TRIPLE, *[DOUBLE] * double, SINGLE_AND_LINE, *[BLOCK] * block]), re.MULTILINE
    )
    for double in (True, False)
    for block in (True, False)
}


def strip_comments(text: str) -> str:
    # Preserve offsets/line numbers; don't remove URL slashes inside string literals.
    parts, position, double, block = [], 0, True, True
    while match := CLEANERS[double, block].search(text, position):
        value, groups = match[0], match.groupdict()
        unterminated_block = value.startswith("/*") and not groups.get("close")
        unterminated_double = value[0] == '"' and not value.startswith('"""') and not groups.get("quote")
        if unterminated_block or unterminated_double:
            # No terminator follows (a stray /* or " such as in a JS regex literal): keep it as
            # text, as 1.5.0 did, and stop matching that token, since every later one is
            # unterminated too.
            width = 2 if unterminated_block else 1
            parts.append(text[position : match.start() + width])
            position = match.start() + width
            double, block = double and not unterminated_double, block and not unterminated_block
            continue
        parts.append(text[position : match.start()])
        parts.append(re.sub(r"[^\n]", " ", value) if value.startswith(("//", "/*")) else value)
        position = match.end()
    parts.append(text[position:])
    return "".join(parts)


def strip_xml_comments(text: str) -> str:
    """Blank <!-- --> comments, keeping offsets; XML text has no // or /* */ comments."""
    return re.sub(r"<!--[\s\S]*?(?:-->|\Z)", lambda m: re.sub(r"[^\n]", " ", m[0]), text)


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
                # A required token absent from the raw text is absent after cleaning too.
                if rule.get("requires") and not re.search(rule["requires"], text):
                    continue
                cleaned = strip_xml_comments(text) if PathSuffix(path) == ".xml" else strip_comments(text)
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
