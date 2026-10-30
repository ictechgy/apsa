from __future__ import annotations

import json
import re
from importlib.resources import files
from itertools import islice

from .core import code_excerpt, finding
from .maswe import weaknesses_for
from .sensitive_logging import JS_LINE_END, JS_SUFFIXES, sensitive_log_matches
from .sensitive_logging import MATCHER as SENSITIVE_LOG_MATCHER


def rules() -> list[dict]:
    from .quaygate_analysis import catalog

    data = files("mobile_audit").joinpath("data")
    loaded = (
        json.loads(data.joinpath("rules.json").read_text())
        + json.loads(data.joinpath("structural-rules.json").read_text())
        + catalog()
    )
    # Import lazily: the hybrid interpreter uses this module's comment cleaner.
    from .hybrid_analysis import RULES as hybrid_rules

    loaded.extend(
        {
            "id": rule,
            "title": title,
            "severity": "medium" if rule == "HYBRID-NATIVE-BRIDGE" else "high",
            "mode": "structural",
            "method": "hybrid-structural-flow",
            "masvs": masvs,
            "scope": "Bounded JS/TS/Dart token/block argument-return flow; always partial; unknown native dispatch and sanitizers require review.",
            "references": ["https://mas.owasp.org/MASTG/"],
        }
        for rule, (title, masvs) in hybrid_rules.items()
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


def _strip_template_comments(text: str) -> str:
    """Blank JS comments while preserving nested template literals and offsets."""
    cleaned = list(text)
    # Zero denotes template text; positive depths denote ${...} expressions.
    stack: list[int] = []
    position, block, expression, regex = 0, True, True, True
    while position < len(text):
        token = text[position]
        if stack and stack[-1] == 0:
            if token == "\\":
                position += 2
            elif token == "`":
                stack.pop()
                position += 1
                expression = False
            elif text.startswith("${", position):
                stack.append(1)
                position += 2
                expression = True
            else:
                position += 1
            continue
        if token == "`":
            stack.append(0)
        elif token in {"'", '"'}:
            quote = token
            position += 1
            while position < len(text) and text[position] not in {quote, "\n"}:
                position += 2 if text[position] == "\\" else 1
            if position < len(text) and text[position] == quote:
                position += 1
            expression = False
            continue
        elif text.startswith("//", position) or (block and text.startswith("/*", position)):
            line = text[position + 1] == "/"
            end = text.find("\n" if line else "*/", position + 2)
            if end < 0 and not line:
                # As in the generic cleaner, a stray regex-like /* stays text;
                # avoid searching the rest of the file again for every later /*.
                block = False
            else:
                end = len(text) if end < 0 else end if line else end + 2
                for index in range(position, end):
                    if text[index] != "\n":
                        cleaned[index] = " "
                position = end
                continue
        elif token == "/" and expression and regex:
            end, character_class = position + 1, False
            while end < len(text) and text[end] != "\n":
                if text[end] == "\\":
                    end += 2
                    continue
                if text[end] == "[":
                    character_class = True
                elif text[end] == "]":
                    character_class = False
                elif text[end] == "/" and not character_class:
                    break
                end += 1
            if end < len(text) and text[end] == "/":
                position = end + 1
                expression = False
                continue
            # At most one failed regex scan per line, keeping malformed input linear.
            regex = False
        elif token.isalnum() or token in {"_", "$"}:
            end = position + 1
            while end < len(text) and (text[end].isalnum() or text[end] in {"_", "$"}):
                end += 1
            expression = text[position:end] in {
                "return",
                "throw",
                "case",
                "yield",
                "await",
                "typeof",
                "void",
                "delete",
                "in",
                "of",
            }
            position = end
            continue
        elif stack:
            if token == "{":
                stack[-1] += 1
            elif token == "}":
                stack[-1] -= 1
                if stack[-1] == 0:
                    stack.pop()
        if token == "\n":
            regex = True
        if not token.isspace():
            expression = token in "=([{,:;!?&|+-*%^~<>/"
        position += 1
    return "".join(cleaned)


def strip_comments(text: str, *, templates: bool = False) -> str:
    # Preserve offsets/line numbers; don't remove URL slashes inside string literals.
    if templates and "`" in text:
        return _strip_template_comments(text)
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
    compiled_package = inventory.get("input_kind") in {"apk", "ipa"}
    # Screen Apple API symbols without asserting an iOS application identity.
    # UIWebView remains an iOS API mention; the other APIs also exist on macOS.
    apple_symbol_rules = {
        "IOS-KEYCHAIN-ACCESS",
        "IOS-CRYPTO-WEAK-CIPHER",
        "IOS-ATS-BYPASS-API",
        "IOS-INSECURE-UNARCHIVE",
        "IOS-UIWEBVIEW",
    }
    apple_source = not compiled_package and any(
        PathSuffix(path) in {".swift", ".m", ".mm"} for path, _ in sources
    )
    packaged_source_suffixes = {".js", ".jsx", ".jsbundle", ".bundle", ".ts", ".tsx", ".dart"}
    admitted_bundles = set()
    for path, text in sources:
        if PathSuffix(path) == ".bundle":
            from .hybrid_analysis import hybrid_source_input

            if hybrid_source_input(path, text.encode("utf-8"))[1] is not None:
                admitted_bundles.add(path)
    for rule in rules():
        if rule["mode"] != "source":
            continue
        applicable = (
            not rule.get("platform")
            or rule["platform"] in inventory["platforms"]
            or (apple_source and rule["id"] in apple_symbol_rules)
        )
        # Native code and manifests in compiled packages are not source input,
        # even if a member happens to contain plaintext. Bundled hybrid sources
        # remain inspectable by the source rules that support their language.
        source_files = [
            (path, text)
            for path, text in sources
            if PathSuffix(path) in rule.get("suffixes", [])
            and (PathSuffix(path) != ".bundle" or path in admitted_bundles)
            and (not compiled_package or PathSuffix(path) in packaged_source_suffixes)
            and (PathSuffix(path) != ".xml" or text.lstrip("\ufeff \t\r\n").startswith("<"))
        ]
        truncated = False
        uncertain_log_boundaries = False
        uncertain_log_reasons: set[str] = set()
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
                if PathSuffix(path) == ".xml":
                    cleaned = strip_xml_comments(text)
                elif rule.get("matcher") == SENSITIVE_LOG_MATCHER:
                    # The call matcher resolves comments and slash literals together.
                    cleaned = text
                else:
                    cleaned = strip_comments(
                        text, templates=PathSuffix(path) in {".js", ".jsx", ".ts", ".tsx"}
                    )
                if rule.get("requires") and not re.search(rule["requires"], cleaned):
                    continue
                excluded = (pattern_exclusions or {}).get(path, {}).get(rule["id"], [])
                byte_offsets: dict[int, int] = {}
                # Some APIs are a property of the file (for example a deprecated class); report its first use.
                if rule["id"] == "STORAGE-SENSITIVE-LOG":
                    log_matches = sensitive_log_matches(
                        cleaned,
                        PathSuffix(path),
                        call_pattern=rule["pattern"],
                        argument_pattern=rule["argument_pattern"],
                    )
                    spans = iter(log_matches.spans)
                    if excluded:
                        # Convert the needed boundaries in one ordered pass, rather
                        # than repeatedly encoding long prefixes for many redacted calls.
                        previous, encoded = 0, 0
                        for position in sorted({p for span in log_matches.spans for p in span}):
                            encoded += len(text[previous:position].encode("utf-8"))
                            byte_offsets[position] = encoded
                            previous = position
                        excluded_ends: dict[int, int] = {}
                        for item in excluded:
                            excluded_ends[item["start"]] = max(
                                excluded_ends.get(item["start"], -1), item["end"]
                            )
                        spans = (
                            (start, end)
                            for start, end in log_matches.spans
                            if byte_offsets[end] > excluded_ends.get(byte_offsets[start], -1)
                        )
                    if log_matches.uncertain:
                        state = "partial"
                        uncertain_log_boundaries = True
                        if log_matches.reason:
                            uncertain_log_reasons.add(log_matches.reason)
                else:
                    spans = (
                        (match.start(), match.end())
                        for match in re.finditer(
                            rule["pattern"], cleaned, 0 if rule.get("case_sensitive") else re.I
                        )
                    )
                matches = islice(spans, 1 if rule.get("once_per_file") else 31)
                for index, (match_start, match_end) in enumerate(matches):
                    if index == 30:
                        state = "partial"
                        truncated = True
                        break
                    start = (
                        byte_offsets[match_start] if byte_offsets else len(text[:match_start].encode("utf-8"))
                    )
                    end = byte_offsets[match_end] if byte_offsets else len(text[:match_end].encode("utf-8"))
                    if any(item["start"] == start and end <= item["end"] for item in excluded):
                        continue
                    if len(findings) >= 2000:
                        state = "partial"
                        break
                    line_number = (
                        sum(1 for _ in JS_LINE_END.finditer(cleaned, 0, match_start)) + 1
                        if rule.get("matcher") == SENSITIVE_LOG_MATCHER and PathSuffix(path) in JS_SUFFIXES
                        else cleaned.count("\n", 0, match_start) + 1
                    )
                    evidence = [
                        {
                            "path": path,
                            "line": line_number,
                            "excerpt": code_excerpt(
                                (
                                    JS_LINE_END.split(text)
                                    if rule.get("matcher") == SENSITIVE_LOG_MATCHER
                                    and PathSuffix(path) in JS_SUFFIXES
                                    else text.split("\n")
                                )[line_number - 1]
                            ),
                            "basis": "source-pattern",
                        }
                    ]
                    if rule["id"] == "STORAGE-SENSITIVE-LOG":
                        # Separate call sites on a minified line need distinct
                        # identities; offset is an existing finding-location field.
                        evidence[0]["offset"] = start
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
                    " Native source and manifest members of compiled packages are not inspected by source patterns."
                    if compiled_package
                    else ""
                )
                + (
                    " Per-file finding limit reached; additional matching evidence was omitted."
                    if truncated
                    else ""
                )
                + (
                    " Some sensitive-log argument boundaries were malformed or unresolved; candidates were retained conservatively."
                    if uncertain_log_boundaries
                    else ""
                )
                + (" " + "; ".join(sorted(uncertain_log_reasons)) + "." if uncertain_log_reasons else ""),
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
        if platform not in {"android", "ios"}:
            continue
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
