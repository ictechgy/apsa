"""Source-tree platform checks: component exposure, backup, target SDK, privacy manifests, secrets.

APK and IPA inputs keep the bundled lint engine's equivalents; these checks run
for source trees and AAB manifests, where that engine does not.
"""

from __future__ import annotations

import plistlib
import re
from xml.parsers.expat import ExpatError

from .core import finding
from .rules import strip_comments

# Google Play: new apps and updates must target API 36 from 2026-08-31.
PLAY_TARGET_SDK = 36
PLAY_TARGET_REFERENCE = "https://developer.android.com/google/play/requirements/target-sdk"
EXPORTED_REFERENCE = "https://developer.android.com/privacy-and-security/risks/android-exported"
BACKUP_REFERENCE = "https://developer.android.com/identity/data/autobackup"
PRIVACY_REFERENCE = (
    "https://developer.apple.com/documentation/bundleresources/describing-use-of-required-reason-api"
)
SECRET_REFERENCE = "https://mas.owasp.org/MASWE/MASVS-STORAGE/MASWE-0004/"

# Apple required-reason API categories and the symbols that indicate their use.
REQUIRED_REASON = {
    "NSPrivacyAccessedAPICategoryFileTimestamp": r"\b(?:creationDate|modificationDate|fileModificationDate|contentModificationDateKey|creationDateKey|getattrlist(?:bulk|at)?|fgetattrlist)\b|\b(?:f|l)?stat(?:at)?\s*\(",
    "NSPrivacyAccessedAPICategorySystemBootTime": r"\b(?:systemUptime|mach_absolute_time)\b",
    "NSPrivacyAccessedAPICategoryDiskSpace": r"\b(?:volumeAvailableCapacity(?:ForImportantUsage|ForOpportunisticUsage)?Key|volumeTotalCapacityKey|systemFreeSize|systemSize)\b|\bf?statv?fs\s*\(",
    "NSPrivacyAccessedAPICategoryActiveKeyboards": r"\bactiveInputModes\b",
    "NSPrivacyAccessedAPICategoryUserDefaults": r"\b(?:NS)?UserDefaults\b",
}
APPLE_SOURCES = (".swift", ".m", ".mm")

# High-confidence credential formats; generic entropy is out of scope.
SECRETS = [
    ("private-key", "high", r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----"),
    ("aws-access-key-id", "high", r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    ("github-token", "high", r"\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{60,255})\b"),
    ("slack-token", "high", r"\bxox[baprs]-[A-Za-z0-9-]{10,72}\b"),
    ("stripe-live-key", "high", r"\b[rs]k_live_[0-9A-Za-z]{24,99}\b"),
    (
        "openai-api-key",
        "high",
        r"\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{20,200}T3BlbkFJ[A-Za-z0-9_-]{20,200}\b",
    ),
    ("anthropic-api-key", "high", r"\bsk-ant-(?:api|admin)\d{2}-[A-Za-z0-9_-]{80,200}\b"),
    ("google-api-key", "low", r"\bAIza[0-9A-Za-z_-]{35}\b"),
]
SECRET_SUFFIXES = (
    ".java",
    ".kt",
    ".kts",
    ".swift",
    ".m",
    ".mm",
    ".xml",
    ".plist",
    ".json",
    ".properties",
    ".gradle",
    ".strings",
)
MAX_SECRET_FINDINGS = 50
RANDOM_REFERENCE = "https://developer.android.com/privacy-and-security/risks/weak-prng"
# Identifier words that name security values; matched as whole camelCase/snake_case words.
SECURITY_WORDS = {"token", "nonce", "salt", "otp", "secret", "password", "passcode", "iv"}
ASSIGNMENT = re.compile(r"(?<![\w.])([A-Za-z_]\w{0,63})\s*(?::\s*[\w<>?.]{1,60}\s*)?=(?!=)")
WEAK_RANDOM = re.compile(
    r"(?<!\w)Random\s*\(|\bMath\.random\s*\(|(?<!\w)Random\.(?:Default|next[A-Z]\w{0,20})\b"
    r"|\bThreadLocalRandom\.current\s*\("
)
MAX_RANDOM_FINDINGS = 50


def _line(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def _masked(value: str) -> str:
    return f"{value[:4]}…({len(value)} characters)"


def _exposed(component: dict, target_level: int | None) -> bool:
    exported = component.get("exported")
    implicit = (
        exported == "unspecified"
        and component.get("intent_filters")
        and (target_level is None or target_level < 31)
    )
    # A provider with only one of read/write permission stays open for the other direction.
    protected = bool(component.get("permission")) or bool(
        component.get("read_permission") and component.get("write_permission")
    )
    return bool((exported == "true" or implicit) and not protected)


def exposed_providers(inventory: dict) -> set[str]:
    """Simple class names of declared providers that other apps can reach."""
    target = str((inventory.get("android_sdk") or {}).get("target") or "")
    level = int(target) if target.isdigit() else None
    return {
        str(c.get("name", "")).rsplit(".", 1)[-1]
        for c in inventory.get("components", [])
        if c.get("type") == "provider" and c.get("name") and _exposed(c, level)
    }


def _blocks(text: str, name: str):
    """Yield (start, end) of each ``name { ... }`` block, matching braces."""
    for match in re.finditer(rf"\b{name}\s*\{{", text):
        depth, index = 1, match.end()
        while index < len(text) and depth:
            depth += {"{": 1, "}": -1}.get(text[index], 0)
            index += 1
        yield match.end(), index


def _gradle_targets(path: str, text: str) -> list[tuple[str, int | None, int]]:
    """Literal targetSdk in defaultConfig and productFlavors of application modules."""
    cleaned = strip_comments(text)
    # Library targetSdk does not set the app's target; root scripts only define variables.
    if re.search(r"""com\.android\.library|\bandroid[.-]library\b|androidLibrary\b""", cleaned):
        return []
    found = []
    for block in ("defaultConfig", "productFlavors"):
        for start, end in _blocks(cleaned, block):
            for match in re.finditer(
                r"\btargetSdk(?:Version)?\s*(?:=\s*|\(\s*|\s+)(\d{2})\b", cleaned[start:end]
            ):
                found.append((path, _line(cleaned, start + match.start()), int(match[1])))
    return list(dict.fromkeys(found))


def _android(inventory: dict, sources: list[tuple[str, str]]) -> tuple[list[dict], list[dict]]:
    findings: list[dict] = []
    coverage: list[dict] = []
    if "android" not in inventory.get("platforms", []):
        return findings, [
            {"rule_id": rule, "state": "not-applicable", "method": "configuration"}
            for rule in ("ANDROID-EXPORTED-COMPONENT", "ANDROID-ALLOW-BACKUP", "ANDROID-TARGET-SDK")
        ]
    declared = inventory.get("android_sdk") or {}
    target = str(declared.get("target") or "")
    target_level = int(target) if target.isdigit() else None
    # Manifest uses-sdk first, then literal targetSdk in Gradle build files.
    targets: list[tuple[str, int | None, int]] = (
        [(declared.get("path") or "AndroidManifest.xml", None, target_level)]
        if target_level is not None
        else []
    )
    for path, text in sources:
        if path.endswith((".gradle", ".gradle.kts")):
            targets += _gradle_targets(path, text)
    if target_level is None and targets:
        target_level = min(level for _, _, level in targets)
    for component in inventory.get("components", []):
        if component.get("type") not in {"activity", "activity-alias", "service", "receiver", "provider"}:
            continue
        exported = component.get("exported")
        implicit = exported == "unspecified" and bool(component.get("intent_filters"))
        if _exposed(component, target_level) and not component.get("launcher"):
            severity = "low" if component["type"] in {"activity", "activity-alias"} else "medium"
            findings.append(
                finding(
                    "ANDROID-EXPORTED-COMPONENT",
                    f"Exported {component['type']} without a permission",
                    severity,
                    "candidate",
                    [
                        {
                            "path": component.get("path", ""),
                            "component": component.get("name", ""),
                            "component_type": component["type"],
                            "exported": exported,
                            "implicit_export": bool(implicit),
                            "basis": "declared manifest attributes; reachable behavior is not analyzed",
                        }
                    ],
                    'Set android:exported="false" unless other apps must reach the component; otherwise '
                    "require a signature-level permission and validate every incoming Intent.",
                    "MASVS-PLATFORM",
                    [EXPORTED_REFERENCE],
                )
            )
    coverage.append(
        {
            "rule_id": "ANDROID-EXPORTED-COMPONENT",
            "state": "checked" if inventory.get("android_config") else "not-run",
            "method": "configuration",
            "note": "Launcher activities and permission-protected components are excluded; merged-manifest and flavor differences are not resolved.",
        }
    )
    for config in inventory.get("android_config", []):
        if config.get("allow_backup") == "true":
            findings.append(
                finding(
                    "ANDROID-ALLOW-BACKUP",
                    "Application backup explicitly allowed",
                    "low",
                    "configuration-confirmed",
                    [{"path": config["path"], "allow_backup": "true"}],
                    "Exclude sensitive files with dataExtractionRules/fullBackupContent, or set "
                    'android:allowBackup="false".',
                    "MASVS-STORAGE",
                    [BACKUP_REFERENCE],
                )
            )
    coverage.append(
        {
            "rule_id": "ANDROID-ALLOW-BACKUP",
            "state": "checked" if inventory.get("android_config") else "not-run",
            "method": "configuration",
            "note": "Only an explicit allowBackup=true is reported; backup rule files are not evaluated.",
        }
    )
    for path, line, level in targets:
        if level >= PLAY_TARGET_SDK:
            continue
        severity = "high" if level < 23 else "medium" if level < 29 else "low"
        evidence = {"path": path, "target_sdk": level, "required": PLAY_TARGET_SDK}
        if line:
            evidence["line"] = line
        findings.append(
            finding(
                "ANDROID-TARGET-SDK",
                f"targetSdk {level} is below the current Google Play requirement ({PLAY_TARGET_SDK})",
                severity,
                "configuration-confirmed",
                [evidence],
                "Raise targetSdk and test the platform behavior changes it enables.",
                "MASVS-CODE",
                [PLAY_TARGET_REFERENCE],
            )
        )
    coverage.append(
        {
            "rule_id": "ANDROID-TARGET-SDK",
            "state": "checked" if targets else "not-run",
            "method": "configuration",
            "note": f"Compared with the Google Play requirement of API {PLAY_TARGET_SDK} for new apps and updates from 2026-08-31.",
        }
    )
    return findings, coverage


def _privacy_manifest(inventory: dict, sources: list[tuple[str, str]]) -> tuple[list[dict], list[dict]]:
    if "ios" not in inventory.get("platforms", []):
        return [], [
            {"rule_id": "IOS-PRIVACY-MANIFEST", "state": "not-applicable", "method": "source-pattern"}
        ]
    declared: set[str] = set()
    manifests, unreadable = [], []
    for path, text in sources:
        if not path.endswith(".xcprivacy"):
            continue
        manifests.append(path)
        try:
            document = plistlib.loads(text.encode("utf-8"))
        except (
            plistlib.InvalidFileException,
            ExpatError,
            ValueError,
            TypeError,
            OverflowError,
            UnicodeError,
        ):
            unreadable.append(path)
            continue
        types = document.get("NSPrivacyAccessedAPITypes", []) if isinstance(document, dict) else None
        if not isinstance(types, list):
            unreadable.append(path)
            continue
        for item in types:
            if isinstance(item, dict) and isinstance(item.get("NSPrivacyAccessedAPIType"), str):
                declared.add(item["NSPrivacyAccessedAPIType"])
    first_use: dict[str, tuple[str, int, int]] = {}
    scanned = 0
    for path, text in sources:
        if not path.endswith(APPLE_SOURCES):
            continue
        scanned += 1
        cleaned = re.sub(r"//[^\n]*|/\*[\s\S]*?\*/", lambda m: re.sub(r"[^\n]", " ", m[0]), text)
        for category, pattern in REQUIRED_REASON.items():
            if category in first_use or category in declared:
                continue
            match = re.search(pattern, cleaned)
            if match:
                first_use[category] = (path, _line(cleaned, match.start()), match.start())
    findings = [
        finding(
            "IOS-PRIVACY-MANIFEST",
            "Required-reason API used without a privacy manifest declaration",
            "medium",
            "candidate",
            [
                {
                    "path": path,
                    "line": line,
                    "offset": offset,
                    "category": category,
                    "manifests": manifests[:20],
                    "basis": "symbol name in app source; SDK manifests in the tree count as declarations",
                }
            ],
            "Declare the category with an approved reason in PrivacyInfo.xcprivacy, or remove the API use. "
            "App Store Connect rejects uploads that use required-reason APIs without a declaration.",
            "MASVS-PRIVACY",
            [PRIVACY_REFERENCE],
        )
        for category, (path, line, offset) in sorted(first_use.items())
    ]
    note = "Symbol-name evidence only; compiled SDKs and dynamic use are not inspected."
    if unreadable:
        note += (
            f" {len(unreadable)} privacy manifest(s) could not be read, so their declarations are unknown."
        )
    return findings, [
        {
            "rule_id": "IOS-PRIVACY-MANIFEST",
            "state": ("partial" if unreadable else "checked") if scanned else "not-run",
            "method": "source-pattern",
            "note": note,
        }
    ]


ATS_REFERENCE = "https://developer.apple.com/documentation/bundleresources/information-property-list/nsapptransportsecurity/nsexceptiondomains"
TRUST_REFERENCE = "https://developer.apple.com/documentation/security/sectrustevaluatewitherror(_:_:)"


def _ats_exceptions(inventory: dict) -> tuple[list[dict], list[dict]]:
    if "ios" not in inventory.get("platforms", []):
        return [], [{"rule_id": "IOS-ATS-EXCEPTION", "state": "not-applicable", "method": "configuration"}]
    findings = []
    for config in inventory.get("ios_config", []):
        ats = config.get("ats") or {}
        reasons_by_domain: dict[str, list[str]] = {}
        if ats.get("NSAllowsArbitraryLoadsForMedia") is True:
            reasons_by_domain["(media)"] = ["NSAllowsArbitraryLoadsForMedia allows unencrypted media loads"]
        declared = ats.get("NSExceptionDomains")
        domains: dict = declared if isinstance(declared, dict) else {}
        for domain, settings in domains.items():
            if not isinstance(settings, dict):
                continue
            reasons = []
            for prefix in ("NSException", "NSThirdPartyException"):
                if settings.get(f"{prefix}AllowsInsecureHTTPLoads") is True:
                    reasons.append(f"{prefix}AllowsInsecureHTTPLoads permits HTTP")
                if settings.get(f"{prefix}MinimumTLSVersion") in {"TLSv1.0", "TLSv1.1"}:
                    reasons.append(f"{prefix}MinimumTLSVersion {settings[f'{prefix}MinimumTLSVersion']}")
                if settings.get(f"{prefix}RequiresForwardSecrecy") is False:
                    reasons.append(f"{prefix}RequiresForwardSecrecy disabled")
            if reasons:
                reasons_by_domain[str(domain)[:200]] = reasons
        for domain, reasons in sorted(reasons_by_domain.items()):
            findings.append(
                finding(
                    "IOS-ATS-EXCEPTION",
                    "ATS exception weakens transport security",
                    "medium",
                    "configuration-confirmed",
                    [{"path": config.get("path", ""), "domain": domain, "reasons": reasons}],
                    "Remove the exception or limit it to the specific host and setting that needs it; keep TLS 1.2+ with forward secrecy.",
                    "MASVS-NETWORK",
                    [ATS_REFERENCE],
                )
            )
    return findings, [
        {
            "rule_id": "IOS-ATS-EXCEPTION",
            "state": "checked" if inventory.get("ios_config") else "not-run",
            "method": "configuration",
            "note": "Declared ATS exceptions only; the hosts the app actually contacts are not observed.",
        }
    ]


def _swift_functions(text: str):
    """Yield (offset, body) for Swift functions, skipping comments and strings for brace matching."""
    masked = re.sub(
        r'//[^\n]*|/\*[\s\S]*?\*/|"(?:\\.|[^"\\\n])*"',
        lambda m: re.sub(r"[^\n]", " ", m[0]),
        text,
    )
    for match in re.finditer(r"\bfunc\b[^{;]*\{", masked):
        depth, index = 1, match.end()
        while index < len(masked) and depth:
            depth += {"{": 1, "}": -1}.get(masked[index], 0)
            index += 1
        yield match.start(), masked[match.start() : index]


def _server_trust(sources: list[tuple[str, str]]) -> tuple[list[dict], list[dict]]:
    findings, scanned = [], 0
    for path, text in sources:
        if not path.endswith(".swift") or "URLCredential" not in text:
            continue
        scanned += 1
        for offset, body in _swift_functions(text):
            use = re.search(r"\.useCredential\s*,\s*URLCredential\s*\(\s*trust\s*:", body)
            if use and not re.search(r"\bSecTrustEvaluate(?:WithError|AsyncWithError)?\s*\(", body):
                findings.append(
                    finding(
                        "SWIFT-SERVER-TRUST-ACCEPTED",
                        "Server trust accepted without evaluation",
                        "high",
                        "candidate",
                        [
                            {
                                "path": path,
                                "line": _line(text, offset + use.start()),
                                "basis": "function completes the challenge with the presented trust and never evaluates it",
                            }
                        ],
                        "Evaluate the trust with SecTrustEvaluateWithError (and pin if required) before using it; "
                        "otherwise call completionHandler(.performDefaultHandling, nil).",
                        "MASVS-NETWORK",
                        [TRUST_REFERENCE],
                    )
                )
    return findings, [
        {
            "rule_id": "SWIFT-SERVER-TRUST-ACCEPTED",
            "state": "checked" if any(p.endswith(".swift") for p, _ in sources) else "not-run",
            "method": "source-pattern",
            "note": "Function-local text check; evaluation in a helper function is not followed.",
        }
    ]


def _secrets(sources: list[tuple[str, str]]) -> tuple[list[dict], list[dict]]:
    findings: list[dict] = []
    truncated = False
    scanned = 0
    for path, text in sources:
        if not path.endswith(SECRET_SUFFIXES):
            continue
        scanned += 1
        for kind, severity, pattern in SECRETS:
            for match in re.finditer(pattern, text):
                if len(findings) >= MAX_SECRET_FINDINGS:
                    truncated = True
                    break
                findings.append(
                    finding(
                        "SOURCE-HARDCODED-SECRET",
                        f"Hard-coded credential ({kind})",
                        severity,
                        "candidate",
                        [
                            {
                                "path": path,
                                "line": _line(text, match.start()),
                                "offset": match.start(),
                                "credential_type": kind,
                                "masked_value": _masked(match[0]),
                                "basis": "credential format match; validity and scope are not checked",
                            }
                        ],
                        "Remove the credential from the app, rotate it, and fetch scoped short-lived tokens "
                        "from your backend. Google API keys meant for apps must carry API and app restrictions.",
                        "MASVS-STORAGE",
                        [SECRET_REFERENCE],
                    )
                )
    return findings, [
        {
            "rule_id": "SOURCE-HARDCODED-SECRET",
            "state": "partial" if truncated else "checked" if scanned else "not-run",
            "method": "source-pattern",
            "note": "Known credential formats only; generic secrets and encoded values are not detected.",
        }
    ]


def _words(identifier: str) -> list[str]:
    """camelCase, PascalCase and snake_case words, lowercased."""
    return [w.lower() for w in re.findall(r"[A-Z]+(?![a-z])|[A-Z]?[a-z]+|\d+", identifier)]


def _insecure_random(inventory: dict, sources: list[tuple[str, str]]) -> tuple[list[dict], list[dict]]:
    if "android" not in inventory.get("platforms", []):
        return [], [
            {"rule_id": "SOURCE-INSECURE-RANDOM", "state": "not-applicable", "method": "source-pattern"}
        ]
    findings: list[dict] = []
    scanned, truncated = 0, False
    for path, text in sources:
        if not path.endswith((".kt", ".java")):
            continue
        scanned += 1
        if "andom" not in text:
            continue
        cleaned = strip_comments(text)
        for match in ASSIGNMENT.finditer(cleaned):
            words = _words(match[1])
            if not (
                SECURITY_WORDS & set(words)
                or any(a == "session" and b == "id" for a, b in zip(words, words[1:], strict=False))
            ):
                continue
            end = cleaned.find("\n", match.end())
            statement = cleaned[match.end() : match.end() + 160 if end < 0 else min(end, match.end() + 160)]
            generator = WEAK_RANDOM.search(statement.split(";", 1)[0])
            if not generator:
                continue
            if len(findings) >= MAX_RANDOM_FINDINGS:
                truncated = True
                break
            findings.append(
                finding(
                    "SOURCE-INSECURE-RANDOM",
                    "Non-cryptographic random value assigned to a security-named variable",
                    "medium",
                    "candidate",
                    [
                        {
                            "path": path,
                            "line": _line(cleaned, match.start()),
                            "offset": match.start(),
                            "variable": match[1],
                            "generator": generator[0].rstrip("( "),
                            "basis": "assignment of java.util/kotlin Random or Math.random to a security-named variable",
                        }
                    ],
                    "Use java.security.SecureRandom (or a platform key generator) for tokens, nonces, salts and passwords.",
                    "MASVS-CRYPTO",
                    [RANDOM_REFERENCE],
                )
            )
    return findings, [
        {
            "rule_id": "SOURCE-INSECURE-RANDOM",
            "state": "partial" if truncated else "checked" if scanned else "not-run",
            "method": "source-pattern",
            "note": "Single-statement assignments only; values passed through helpers or fields are not followed.",
        }
    ]


def platform_checks(inventory: dict, sources: list[tuple[str, str]]) -> tuple[list[dict], list[dict]]:
    findings: list[dict] = []
    coverage: list[dict] = []
    if inventory.get("input_kind") in {"apk", "ipa"}:
        # The bundled lint engine reports these for compiled packages.
        return findings, coverage
    for part in (
        _android(inventory, sources),
        _privacy_manifest(inventory, sources),
        _ats_exceptions(inventory),
        _server_trust(sources),
        _secrets(sources),
        _insecure_random(inventory, sources),
    ):
        findings += part[0]
        coverage += part[1]
    # The same identity can arise twice, for example one manifest reached through two source roots.
    seen: set[str] = set()
    unique = [item for item in findings if not (item["id"] in seen or seen.add(item["id"]))]
    return unique, coverage
