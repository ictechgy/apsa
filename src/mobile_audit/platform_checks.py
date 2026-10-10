"""Source-tree platform checks: component exposure, backup, target SDK, privacy manifests, secrets.

APK and IPA inputs keep the bundled lint engine's equivalents; these checks run
for source trees and AAB manifests, where that engine does not.
"""

from __future__ import annotations

import re
from itertools import islice
from xml.sax.handler import ContentHandler

from defusedxml import sax as defused_sax

from .core import finding, load_plist
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
SECURITY_WORDS = {"token", "nonce", "salt", "otp", "secret", "password", "passcode", "pin", "iv"}
# Names ending in these words hold a size or setting, not the secret value itself.
QUANTITY_WORDS = {
    "length",
    "len",
    "size",
    "count",
    "index",
    "idx",
    "max",
    "min",
    "attempts",
    "retries",
    "timeout",
}
ASSIGNMENT = re.compile(r"(?<!\w)([A-Za-z_]\w{0,63})\s*(?::\s*[\w<>?.]{1,60}\s*)?=(?!=)")
WEAK_RANDOM = re.compile(
    r"(?<!\w)Random\s*\(|\bMath\.random\s*\(|(?<!\w)Random\.(?:Default|next[A-Z]\w{0,20})\b"
    r"|\bThreadLocalRandom\.current\s*\("
)
# C library generators and GameplayKit sources; arc4random and Swift's default generator are secure.
WEAK_RANDOM_APPLE = re.compile(
    r"(?<![\w.])(?:rand|random|drand48|lrand48|mrand48)\s*\(\s*\)"
    r"|\bGK(?:MersenneTwister|LinearCongruential|ARC4)RandomSource\b|\bGKRandomSource\b"
)
MAX_RANDOM_FINDINGS = 50
MAX_PATTERN_FINDINGS = 50

ANDROID_AUTH_REFERENCE = "https://developer.android.com/identity/sign-in/biometric-auth"
APPLE_AUTH_REFERENCE = "https://developer.apple.com/documentation/localauthentication/accessing-keychain-items-with-face-id-or-touch-id"
WEBVIEW_FILE_REFERENCE = "https://mas.owasp.org/MASWE/MASVS-PLATFORM/MASWE-0034/"
NSC_REFERENCE = "https://developer.android.com/privacy-and-security/security-config"
APP_LINKS_REFERENCE = "https://developer.android.com/training/app-links/verify-android-applinks"
LOOPBACK = {"localhost", "127.0.0.1", "::1", "[::1]", "ip6-localhost"}
# A key or keychain item bound to the authentication; an evaluatePolicy result alone is a boolean.
APPLE_AUTH_BINDING = re.compile(
    r"\bkSecAttrAccessControl\b|\bSecAccessControlCreateWithFlags\b|\bkSecUseAuthenticationContext\b"
    r"|\bevaluateAccessControl\b"
)
APPLE_FALLBACK_POLICY = re.compile(
    r"\bevaluatePolicy\s*\(\s*(?:LAPolicy)?\.deviceOwnerAuthentication\b"
    r"|\bevaluatePolicy\s*:\s*LAPolicyDeviceOwnerAuthentication\b"
)
# Access-control flags; only read in files that create a SecAccessControl.
APPLE_FALLBACK_FLAGS = re.compile(
    r"(?<!\w)\.(?:userPresence|devicePasscode)\b|\bkSecAccessControl(?:UserPresence|DevicePasscode)\b"
)
APPLE_ENROLLMENT = re.compile(
    r"(?<!\w)\.(?:biometryAny|touchIDAny)\b|\bkSecAccessControl(?:BiometryAny|TouchIDAny)\b"
)
ANDROID_FALLBACK = re.compile(r"\bsetDeviceCredentialAllowed\s*\(\s*true\b")
# A Keystore key that requires authentication within a positive time window (time-bound).
ANDROID_AUTH_REQUIRED = re.compile(r"\bsetUserAuthenticationRequired\s*\(\s*true\b")
ANDROID_AUTH_WINDOW = re.compile(
    r"\bsetUserAuthenticationParameters\s*\(\s*[1-9]|\bsetUserAuthenticationValidityDurationSeconds\s*\(\s*[1-9]"
)
# Debug and test source sets (debug, androidTest, test, testFixtures, sharedTest, ...) never ship in release.
NON_RELEASE_SOURCE_SET = re.compile(
    r"(?:^|/)src/(?:[^/]*[Dd]ebug[^/]*|test(?:[A-Z0-9]\w*)?|androidTest\w*|[a-z]\w*Test(?:[A-Z]\w*)?)/"
)
ANDROID_FALLBACK_ARGUMENTS = {
    "setAllowedAuthenticators": "DEVICE_CREDENTIAL",
    "setUserAuthenticationParameters": "AUTH_DEVICE_CREDENTIAL",
}
ANDROID_ENROLLMENT = re.compile(r"\bsetInvalidatedByBiometricEnrollment\s*\(\s*false\b")
FILE_ACCESS_KEY = re.compile(
    r"\bsetValue\s*(?:\(\s*true\s*,\s*forKey\s*:\s*|:\s*@\(?\s*(?:YES|true|1)\s*\)?\s+forKey\s*:\s*@)"
    r'"(allowFileAccessFromFileURLs|allowUniversalAccessFromFileURLs)"'
)
READ_ACCESS = re.compile(r"\ballowingReadAccessTo(?:URL)?\s*:\s*")
BROAD_DIRECTORY = re.compile(
    r"\b(?:documentDirectory|libraryDirectory|applicationSupportDirectory|cachesDirectory|NSDocumentDirectory"
    r"|NSLibraryDirectory|NSApplicationSupportDirectory|NSCachesDirectory|NSHomeDirectory"
    r"|homeDirectoryForCurrentUser|NSTemporaryDirectory|temporaryDirectory)\b"
    r'|\bfileURLWithPath\s*:\s*@?"/"'
)


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


def android_levels(inventory: dict) -> dict:
    """Manifest-declared minSdk and targetSdk as integers, None when absent or not literal."""
    declared = inventory.get("android_sdk") or {}
    levels: dict[str, int | None] = {}
    for key in ("min", "target"):
        value = str(declared.get(key) or "")
        levels[key] = int(value) if value.isdigit() else None
    return levels


def exposed_providers(inventory: dict) -> set[str]:
    """Simple class names of declared providers that other apps can reach."""
    target = str((inventory.get("android_sdk") or {}).get("target") or "")
    level = int(target) if target.isdigit() else None
    return {
        # A nested class is declared as Outer$Inner; its source declaration is named Inner.
        str(c.get("name", "")).rsplit(".", 1)[-1].rsplit("$", 1)[-1]
        for c in inventory.get("components", [])
        if c.get("type") == "provider" and c.get("name") and _exposed(c, level)
    }


LIBRARY_PLUGIN = re.compile(
    r"""\bid\s*\(?\s*["']com\.android\.library["']"""
    r"""|\bapply\s+plugin\s*:\s*["']com\.android\.library["']"""
    r"""|\balias\s*\(\s*libs\.plugins\.[\w.]*?\blibrary\b[\w.]*\s*\)"""
    r"""|\bandroidLibrary\b"""
)
STRING_LITERAL = re.compile(r""""(?:\\.|[^"\\\n])*"|'(?:\\.|[^'\\\n])*'""")


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
    without_comments = strip_comments(text)
    # A library module's targetSdk does not set the app's target. Only its plugin declaration
    # counts, not dependency coordinates that happen to mention "android-library".
    if LIBRARY_PLUGIN.search(without_comments):
        return []
    # String contents are blanked (offsets kept) so braces inside strings do not nest blocks.
    cleaned = STRING_LITERAL.sub(lambda m: m[0][0] + " " * (len(m[0]) - 2) + m[0][-1], without_comments)
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
            document = load_plist(text.encode("utf-8"))
        except ValueError:
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
    platforms = inventory.get("platforms", [])
    suffixes = (".kt", ".java") * ("android" in platforms) + APPLE_SOURCES * ("ios" in platforms)
    if not suffixes:
        return [], [
            {"rule_id": "SOURCE-INSECURE-RANDOM", "state": "not-applicable", "method": "source-pattern"}
        ]
    findings: list[dict] = []
    scanned, truncated = 0, False
    for path, text in sources:
        if not path.endswith(suffixes):
            continue
        scanned += 1
        apple = path.endswith(APPLE_SOURCES)
        weak_random = WEAK_RANDOM_APPLE if apple else WEAK_RANDOM
        if not re.search(r"rand|Random", text):
            continue
        cleaned = strip_comments(text)
        for match in ASSIGNMENT.finditer(cleaned):
            words = _words(match[1])
            if words and words[-1] in QUANTITY_WORDS:
                continue
            if not (
                SECURITY_WORDS & set(words)
                or any(a == "session" and b == "id" for a, b in zip(words, words[1:], strict=False))
            ):
                continue
            end = cleaned.find("\n", match.end())
            statement = cleaned[match.end() : match.end() + 160 if end < 0 else min(end, match.end() + 160)]
            generator = weak_random.search(statement.split(";", 1)[0])
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
                            "generator": generator[0].rstrip("() "),
                            "basis": "assignment of a C library or GameplayKit generator to a security-named variable"
                            if apple
                            else "assignment of java.util/kotlin Random or Math.random to a security-named variable",
                        }
                    ],
                    "Use SecRandomCopyBytes or CryptoKit on Apple platforms, and java.security.SecureRandom (or a "
                    "platform key generator) on Android, for tokens, nonces, salts and passwords.",
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


def _capped(matches) -> tuple[list, bool]:
    """At most MAX_PATTERN_FINDINGS matches, and whether more were left unread."""
    taken = list(islice(matches, MAX_PATTERN_FINDINGS + 1))
    return taken[:MAX_PATTERN_FINDINGS], len(taken) > MAX_PATTERN_FINDINGS


TRUNCATED = {"truncated": True}


def _masked_code(text: str) -> str:
    """Blank comments and string contents (quotes kept) so brackets inside them do not nest."""
    return re.sub(
        r'//[^\n]*|/\*[\s\S]*?\*/|"(?:\\.|[^"\\\n])*"',
        lambda m: re.sub(r"[^\n]", " ", m[0]) if m[0].startswith("/") else '"' + " " * (len(m[0]) - 2) + '"',
        text,
    )


def _arguments(masked: str, start: int, limit: int = 4000) -> list[tuple[int, int]] | None:
    """Top-level argument spans of the call whose ``(`` is at ``start``; None when unbalanced."""
    depth, begin, spans = 0, start + 1, []
    for index in range(start, min(len(masked), start + limit)):
        char = masked[index]
        if char in "([{":
            depth += 1
        elif char in ")]}":
            depth -= 1
            if depth == 0:
                if masked[begin:index].strip():
                    spans.append((begin, index))
                return spans
        elif char == "," and depth == 1:
            spans.append((begin, index))
            begin = index + 1
    return None


def _declared_as(masked: str, name: str, type_pattern: str) -> bool:
    """Whether ``name`` is declared or assigned with a type or constructor matching ``type_pattern``."""
    name = re.escape(name)
    return bool(
        re.search(
            rf"\b{name}\s*(?::\s*(?:[\w.]*\.)?(?:{type_pattern})\b|=\s*(?:[\w.]*\.)?(?:{type_pattern})\s*[.(])"
            rf"|\b(?:{type_pattern})\s+{name}\b",
            masked,
        )
    )


def _auth_finding(rule: str, path: str, text: str, offset: int, api: str, basis: str) -> dict:
    titles = {
        "SOURCE-BIOMETRIC-EVENT-BOUND": (
            "Biometric result is not bound to a key or keychain item",
            "medium",
            "Unlock a Keystore key (BiometricPrompt.CryptoObject) or a Keychain item with an access control "
            "instead of trusting a success callback, so the result cannot be bypassed by hooking it.",
        ),
        "SOURCE-BIOMETRIC-FALLBACK": (
            "Biometric authentication falls back to the device credential",
            "low",
            "For sensitive operations, require biometrics only (BIOMETRIC_STRONG, .biometryCurrentSet, "
            ".deviceOwnerAuthenticationWithBiometrics) or document why a PIN or passcode is acceptable.",
        ),
        "SOURCE-BIOMETRIC-ENROLLMENT": (
            "Biometric-protected key survives new biometric enrollment",
            "low",
            "Invalidate keys on new enrollment (setInvalidatedByBiometricEnrollment(true), .biometryCurrentSet) "
            "so a newly added fingerprint or face cannot unlock existing secrets.",
        ),
    }
    title, severity, remediation = titles[rule]
    apple = path.endswith(APPLE_SOURCES)
    return finding(
        rule,
        title,
        severity,
        "candidate",
        [{"path": path, "line": _line(text, offset), "offset": offset, "api": api, "basis": basis}],
        remediation,
        "MASVS-AUTH",
        [APPLE_AUTH_REFERENCE if apple else ANDROID_AUTH_REFERENCE],
    )


def _android_auth(path: str, text: str) -> list[dict]:
    masked = _masked_code(text)
    findings = []
    # A key that requires recent authentication (time-bound) binds the result to the Keystore.
    bound = bool(ANDROID_AUTH_REQUIRED.search(masked) and ANDROID_AUTH_WINDOW.search(masked))
    for count, match in enumerate(re.finditer(r"\.\s*authenticate\s*\(", masked)):
        if bound:
            break
        if count >= MAX_PATTERN_FINDINGS:
            findings.append(TRUNCATED)
            break
        head = re.search(r"(\w{1,200}|\))\s*\??\s*$", masked[max(0, match.start() - 220) : match.start()])
        args = _arguments(masked, match.end() - 1)
        if args is None or head is None:
            continue
        receiver = head[1]
        receiver_start = match.start() - (
            len(masked[max(0, match.start() - 220) : match.start()]) - head.start(1)
        )
        if receiver == ")":
            # A call chain such as BiometricPrompt.Builder(...).build().authenticate(...).
            window = masked[max(0, match.start() - 600) : match.start()]
            prompt = re.search(r"\bBiometricPrompt\s*(?:\.\s*Builder\s*)?\(", window) is not None
            fingerprint = re.search(r"\bFingerprintManager(?:Compat)?\b", window) is not None
        else:
            prompt = _declared_as(masked, receiver, "BiometricPrompt")
            fingerprint = _declared_as(masked, receiver, r"FingerprintManager(?:Compat)?")
        first = text[args[0][0] : args[0][1]].strip() if args else ""
        # androidx: authenticate(info) or (info, crypto); framework: (cancel, executor, callback) or (crypto, ...).
        if (prompt and len(args) in {1, 3}) or (fingerprint and first == "null"):
            findings.append(
                _auth_finding(
                    "SOURCE-BIOMETRIC-EVENT-BOUND",
                    path,
                    text,
                    receiver_start,
                    "FingerprintManager.authenticate" if fingerprint else "BiometricPrompt.authenticate",
                    "authenticate call without a CryptoObject argument",
                )
            )
    matches, cut = _capped(ANDROID_FALLBACK.finditer(masked))
    findings += [TRUNCATED] * cut
    for match in matches:
        findings.append(
            _auth_finding(
                "SOURCE-BIOMETRIC-FALLBACK",
                path,
                text,
                match.start(),
                "setDeviceCredentialAllowed",
                "device credential allowed as an alternative",
            )
        )
    for method, token in ANDROID_FALLBACK_ARGUMENTS.items():
        matches, cut = _capped(re.finditer(rf"\b{method}\s*\(", masked))
        findings += [TRUNCATED] * cut
        for match in matches:
            args = _arguments(masked, match.end() - 1)
            if args and any(re.search(rf"\b{token}\b", masked[a:b]) for a, b in args):
                findings.append(
                    _auth_finding(
                        "SOURCE-BIOMETRIC-FALLBACK",
                        path,
                        text,
                        match.start(),
                        method,
                        f"{token} among the allowed authenticators",
                    )
                )
    matches, cut = _capped(ANDROID_ENROLLMENT.finditer(masked))
    findings += [TRUNCATED] * cut
    for match in matches:
        findings.append(
            _auth_finding(
                "SOURCE-BIOMETRIC-ENROLLMENT",
                path,
                text,
                match.start(),
                "KeyGenParameterSpec.Builder.setInvalidatedByBiometricEnrollment",
                "key explicitly kept valid after new biometric enrollment",
            )
        )
    return findings


def _apple_auth(path: str, text: str) -> list[dict]:
    masked = _masked_code(text)
    findings = []
    if not APPLE_AUTH_BINDING.search(masked):
        # Calls only: a protocol requirement, a mock or an Objective-C method definition is not use.
        policies, cut = _capped(re.finditer(r"\bevaluatePolicy\s*[(:]", masked))
        findings += [TRUNCATED] * cut
        for match in policies:
            line_start = masked.rfind("\n", 0, match.start()) + 1
            # A declaration starts its line within a short prefix; longer prefixes are calls.
            prefix = masked[max(line_start, match.start() - 200) : match.start()]
            if match.start() - line_start <= 200 and re.search(
                r"\bfunc\s+$|^\s*[-+]\s*\([^)]*\)\s*$", prefix
            ):
                continue
            findings.append(
                _auth_finding(
                    "SOURCE-BIOMETRIC-EVENT-BOUND",
                    path,
                    text,
                    match.start(),
                    "LAContext.evaluatePolicy",
                    "evaluatePolicy reply used in a file without a Keychain access control",
                )
            )
    fallback = [APPLE_FALLBACK_POLICY] + [APPLE_FALLBACK_FLAGS] * ("SecAccessControl" in masked)
    for pattern in fallback:
        matches, cut = _capped(pattern.finditer(masked))
        findings += [TRUNCATED] * cut
        for match in matches:
            findings.append(
                _auth_finding(
                    "SOURCE-BIOMETRIC-FALLBACK",
                    path,
                    text,
                    match.start(),
                    match[0].strip(" (:"),
                    "policy or access control that accepts the device passcode",
                )
            )
    if "SecAccessControl" in masked:
        matches, cut = _capped(APPLE_ENROLLMENT.finditer(masked))
        findings += [TRUNCATED] * cut
        for match in matches:
            findings.append(
                _auth_finding(
                    "SOURCE-BIOMETRIC-ENROLLMENT",
                    path,
                    text,
                    match.start(),
                    match[0],
                    "access control that stays valid after new biometric enrollment",
                )
            )
    return findings


def _local_auth(sources: list[tuple[str, str]]) -> tuple[list[dict], list[dict]]:
    findings: list[dict] = []
    scanned = truncated = False
    for path, text in sources:
        if path.endswith((".kt", ".java")):
            scanned = True
            if re.search(r"BiometricPrompt|FingerprintManager|setInvalidatedByBiometricEnrollment", text):
                found = _android_auth(path, text)
                truncated = truncated or any(item.get("truncated") for item in found)
                findings += [item for item in found if not item.get("truncated")]
        elif path.endswith(APPLE_SOURCES):
            scanned = True
            if re.search(r"evaluatePolicy|SecAccessControl", text):
                found = _apple_auth(path, text)
                truncated = truncated or any(item.get("truncated") for item in found)
                findings += [item for item in found if not item.get("truncated")]
    if len(findings) > MAX_PATTERN_FINDINGS:
        findings, truncated = findings[:MAX_PATTERN_FINDINGS], True
    notes = {
        "SOURCE-BIOMETRIC-EVENT-BOUND": "BiometricPrompt and FingerprintManager authenticate calls by argument "
        "count; LAContext.evaluatePolicy in files without a Keychain access control. Bindings in other files "
        "are not followed.",
        "SOURCE-BIOMETRIC-FALLBACK": "Literal authenticator, policy and access-control arguments; values held "
        "in variables are not resolved.",
        "SOURCE-BIOMETRIC-ENROLLMENT": "Explicit setInvalidatedByBiometricEnrollment(false) and biometryAny or "
        "touchIDAny access-control flags.",
    }
    return findings, [
        {
            "rule_id": rule,
            "state": "partial" if truncated else "checked" if scanned else "not-run",
            "method": "source-pattern",
            "note": note,
        }
        for rule, note in notes.items()
    ]


def _assigned_values(text: str, name: str) -> list[str]:
    name = re.escape(name)
    return [
        m[1]
        for m in re.finditer(
            rf"(?:\b(?:let|var)\s+{name}\b\s*(?::[^=\n]+)?|(?<![\w.]){name}\s*)=(?!=)\s*([^\n;]+)", text
        )
    ]


def _ios_webview_file_access(
    inventory: dict, sources: list[tuple[str, str]]
) -> tuple[list[dict], list[dict]]:
    if "ios" not in inventory.get("platforms", []):
        return [], [
            {"rule_id": "IOS-WEBVIEW-FILE-ACCESS", "state": "not-applicable", "method": "source-pattern"}
        ]
    findings, scanned, truncated = [], 0, False
    for path, text in sources:
        if not path.endswith(APPLE_SOURCES):
            continue
        scanned += 1
        if "allow" not in text:
            continue
        cleaned = strip_comments(text)
        keys, cut = _capped(FILE_ACCESS_KEY.finditer(cleaned))
        truncated = truncated or cut
        for match in keys:
            findings.append(
                finding(
                    "IOS-WEBVIEW-FILE-ACCESS",
                    "WKWebView file URLs may read other local files",
                    "high",
                    "candidate",
                    [
                        {
                            "path": path,
                            "line": _line(cleaned, match.start()),
                            "offset": match.start(),
                            "setting": match[1],
                            "basis": "private WebKit preference enabled through key-value coding",
                        }
                    ],
                    "Do not enable allowFileAccessFromFileURLs or allowUniversalAccessFromFileURLs. Serve local "
                    "content through a WKURLSchemeHandler or a narrowly scoped loadFileURL read-access directory.",
                    "MASVS-PLATFORM",
                    [WEBVIEW_FILE_REFERENCE],
                )
            )
        masked = _masked_code(cleaned)
        assigned: dict[str, list[str]] = {}
        accesses, cut = _capped(READ_ACCESS.finditer(cleaned))
        truncated = truncated or cut
        for match in accesses:
            end = match.end()
            depth = 0
            while end < len(masked) and end - match.end() < 300:
                char = masked[end]
                if char in "([{":
                    depth += 1
                elif char in ")]}":
                    if depth == 0:
                        break
                    depth -= 1
                elif char in ",\n" and depth == 0:
                    break
                end += 1
            argument = cleaned[match.end() : end].strip()
            identifier = re.fullmatch(r"(?:(?:self|Self|\w+)\.)?(\w+)!?", argument)
            if identifier and identifier[1] not in assigned:
                assigned[identifier[1]] = _assigned_values(cleaned, identifier[1])
            resolved = [argument] + (assigned[identifier[1]] if identifier else [])
            broad = next(filter(None, (BROAD_DIRECTORY.search(value) for value in resolved)), None)
            # A file or subdirectory appended to the directory narrows the access.
            appended = broad.string[broad.end() :] if broad else ""
            standard = re.search(
                r'(?:appendingPathComponent|appending\s*\(\s*(?:path|component)\s*:)\s*\(?\s*@?"(?:Documents|Library'
                r'|tmp|Library/Caches|Library/Application Support)/?"',
                appended,
            )
            home = broad is not None and broad[0] in {"NSHomeDirectory", "homeDirectoryForCurrentUser"}
            if (
                broad
                and re.search(
                    r"\bappendingPathComponent\b|\bappending\s*\(|\bURLByAppendingPathComponent\b", appended
                )
                and not (home and standard)
            ):
                broad = None
            if broad:
                findings.append(
                    finding(
                        "IOS-WEBVIEW-FILE-ACCESS",
                        "WKWebView granted read access to a whole app directory",
                        "medium",
                        "candidate",
                        [
                            {
                                "path": path,
                                "line": _line(cleaned, match.start()),
                                "offset": match.start(),
                                "read_access": argument[:120],
                                "directory": broad[0],
                                "basis": "loadFileURL read-access argument"
                                + (
                                    " resolved through a local assignment" if argument != broad.string else ""
                                ),
                            }
                        ],
                        "Grant read access only to the directory that holds the bundled web content, never "
                        "Documents, Library or the home directory, and do not load untrusted HTML from file URLs.",
                        "MASVS-PLATFORM",
                        [WEBVIEW_FILE_REFERENCE],
                    )
                )
    return findings[:MAX_PATTERN_FINDINGS], [
        {
            "rule_id": "IOS-WEBVIEW-FILE-ACCESS",
            "state": ("partial" if truncated or len(findings) > MAX_PATTERN_FINDINGS else "checked")
            if scanned
            else "not-run",
            "method": "source-pattern",
            "note": "Key-value-coded WebKit file preferences and loadFileURL read-access directories resolved "
            "within one file.",
        }
    ]


class _NetworkConfig(ContentHandler):
    """Collect user trust anchors and cleartext permissions outside <debug-overrides>, with lines."""

    def __init__(self) -> None:
        super().__init__()
        self.locator = None
        self.stack: list[str] = []
        self.configs: list[dict] = []
        self.user: list[tuple[int, str]] = []
        self.cleartext: list[dict] = []
        self.domain: list[str] | None = None

    def setDocumentLocator(self, locator) -> None:  # noqa: N802 - SAX API
        self.locator = locator

    def startElement(self, name, attrs) -> None:  # noqa: N802 - SAX API
        line = (self.locator.getLineNumber() or 0) if self.locator else 0
        debug = "debug-overrides" in self.stack
        if not debug and name in {"base-config", "domain-config"}:
            self.configs.append(
                {
                    "tag": name,
                    "line": line,
                    "cleartext": attrs.get("cleartextTrafficPermitted") == "true",
                    "domains": [],
                }
            )
        elif not debug and name == "domain" and self.configs:
            self.domain = []
        elif (
            not debug
            and name == "certificates"
            and attrs.get("src") == "user"
            and self.configs
            and "trust-anchors" in self.stack
        ):
            self.user.append((line, self.configs[-1]["tag"]))
        self.stack.append(name)

    def characters(self, content) -> None:
        if self.domain is not None:
            self.domain.append(content)

    def endElement(self, name) -> None:  # noqa: N802 - SAX API
        if self.stack:
            self.stack.pop()
        if name == "domain" and self.domain is not None and self.configs:
            self.configs[-1]["domains"].append("".join(self.domain).strip()[:200])
            self.domain = None
        elif (
            name in {"base-config", "domain-config"} and self.configs and "debug-overrides" not in self.stack
        ):
            config = self.configs.pop()
            if config["cleartext"]:
                self.cleartext.append(config)


def _module_root(manifest: str) -> str:
    """The module directory a manifest belongs to: the part before src/, or its own directory."""
    if "/src/" in "/" + manifest:
        return ("/" + manifest).split("/src/", 1)[0].lstrip("/") + (
            "/" if not manifest.startswith("src/") else ""
        )
    return manifest.rsplit("/", 1)[0] + "/" if "/" in manifest else ""


def _network_security_config(
    inventory: dict, sources: list[tuple[str, str]]
) -> tuple[list[dict], list[dict]]:
    if "android" not in inventory.get("platforms", []):
        return [], [
            {"rule_id": rule, "state": "not-applicable", "method": "configuration"}
            for rule in ("ANDROID-NSC-USER-CA", "ANDROID-NSC-CONFIG")
        ]
    # Each selected manifest's reference resolves in its own module's res/xml, never another module's.
    referenced: dict[tuple[str, str], list[str]] = {}
    for config in inventory.get("android_config", []):
        if config.get("network_security_config") and config.get("bundle_role") != "embedded":
            manifest = str(config.get("path") or "")
            name = str(config["network_security_config"]).rsplit("/", 1)[-1]
            referenced.setdefault((_module_root(manifest), name), []).append(manifest)
    findings: list[dict] = []
    read, unreadable, compiled = 0, [], []
    parsed_for: set[str] = set()
    matched: list[tuple[str, str, list[tuple[str, str]]]] = []
    for path, text in sources:
        # Debug and test source sets do not ship in the release build.
        if not path.endswith(".xml") or "/res/xml/" not in "/" + path or NON_RELEASE_SOURCE_SET.search(path):
            continue
        stem = path.rsplit("/", 1)[-1].removesuffix(".xml")
        keys = [(module, name) for module, name in referenced if stem == name and path.startswith(module)]
        if keys:
            matched.append((path, text, keys))
    # A flat layout (manifest and configuration side by side, no res/xml) is read only when
    # the module has no res/xml match for that reference.
    found = {key for _, _, keys in matched for key in keys}
    for (module, name), manifests in referenced.items():
        if (module, name) in found:
            continue
        beside = {manifest.rsplit("/", 1)[0] + "/" if "/" in manifest else "" for manifest in manifests}
        for path, text in sources:
            if path.endswith(f"{name}.xml") and any(path == f"{folder}{name}.xml" for folder in beside):
                matched.append((path, text, [(module, name)]))
    per_reference: dict[tuple[str, str], int] = {}
    for _, _, keys in matched:
        for key in keys:
            per_reference[key] = per_reference.get(key, 0) + 1
    for path, text, keys in matched:
        owners = [manifest for key in keys for manifest in referenced[key]]
        # Several source sets (flavors) define the reference; which one ships is not resolved.
        variants = max(per_reference[key] for key in keys)
        status = "configuration-confirmed" if variants == 1 else "candidate"
        if not text.lstrip("\ufeff \t\r\n").startswith("<"):
            compiled.append(path)  # AAB resources are compiled protobuf, not XML text
            continue
        handler = _NetworkConfig()
        try:
            defused_sax.parseString(text.encode("utf-8"), handler)
        except Exception:  # noqa: BLE001 - any parse failure leaves this file unverified
            unreadable.append(path)
            continue
        read += 1
        parsed_for.update(owners)
        for line, scope in handler.user:
            findings.append(
                finding(
                    "ANDROID-NSC-USER-CA",
                    "Network security configuration trusts user-installed CAs",
                    "medium",
                    status,
                    [
                        {
                            "path": path,
                            "line": line,
                            "scope": scope,
                            **({"source_set_variants": variants} if variants > 1 else {}),
                        }
                    ],
                    'Remove <certificates src="user"/> from release configurations; keep it only under '
                    "<debug-overrides>, and pin certificates for sensitive hosts.",
                    "MASVS-NETWORK",
                    [NSC_REFERENCE],
                )
            )
        for config in handler.cleartext:
            domains = config["domains"][:20]
            # Loopback traffic does not leave the device (for example a local media server).
            if config["tag"] == "domain-config" and domains and all(d.lower() in LOOPBACK for d in domains):
                continue
            findings.append(
                finding(
                    "ANDROID-CLEARTEXT",
                    "Network security configuration permits cleartext traffic",
                    "medium" if config["tag"] == "base-config" else "low",
                    status,
                    [
                        {
                            "path": path,
                            "line": config["line"],
                            "scope": config["tag"],
                            **({"domains": domains} if domains else {}),
                        }
                    ],
                    "Remove cleartextTrafficPermitted or limit it to hosts that cannot use TLS.",
                    "MASVS-NETWORK",
                    [NSC_REFERENCE],
                )
            )
    # Read by the worker: a parsed configuration overrides the manifest's usesCleartextTraffic on API 24+.
    inventory["network_security_parsed"] = sorted(parsed_for)
    if not referenced:
        state, note = "checked", "No networkSecurityConfig is referenced; platform defaults apply."
    elif unreadable:
        state = "partial"
        note = f"{len(unreadable)} referenced network security configuration(s) could not be parsed."
    elif compiled and not read:
        state = "not-run"
        note = "The referenced configuration is compiled (AAB protobuf resources) and is not decoded."
    elif not read:
        state = "partial"
        note = "The referenced network security configuration is not among the scanned sources."
    else:
        state, note = "checked", "Referenced network security configuration; <debug-overrides> is excluded."
    state = state if inventory.get("android_config") else "not-run"
    return findings, [
        {"rule_id": "ANDROID-NSC-USER-CA", "state": state, "method": "configuration", "note": note},
        # The same read decides whether cleartext permissions in the configuration were checked (MASWE-0026).
        {"rule_id": "ANDROID-NSC-CONFIG", "state": state, "method": "configuration", "note": note},
    ]


def _app_links(inventory: dict) -> tuple[list[dict], list[dict]]:
    if "android" not in inventory.get("platforms", []):
        return [], [
            {"rule_id": "ANDROID-DEEPLINK-AUTOVERIFY", "state": "not-applicable", "method": "configuration"}
        ]
    hosts: dict[tuple[str, str], set[str]] = {}
    for link in inventory.get("deep_links", []):
        if (
            link.get("platform") == "android"
            and link.get("scheme") in {"http", "https"}
            and link.get("host")
            and link.get("browsable")
            and link.get("auto_verify") != "true"
        ):
            hosts.setdefault((link.get("origin", ""), link.get("component", "")), set()).add(link["host"])
    findings = [
        finding(
            "ANDROID-DEEPLINK-AUTOVERIFY",
            "Web link intent filter is not verified as an App Link",
            "low",
            "candidate",
            [
                {
                    "path": origin,
                    "component": component,
                    "hosts": sorted(names)[:20],
                    "basis": 'VIEW and BROWSABLE http(s) filter without android:autoVerify="true"',
                }
            ],
            'For hosts the app owns, add android:autoVerify="true" and publish assetlinks.json so other apps '
            "cannot claim the links. Links to hosts it does not own can be claimed by other apps, so treat "
            "every parameter they carry as untrusted.",
            "MASVS-PLATFORM",
            [APP_LINKS_REFERENCE],
        )
        for (origin, component), names in sorted(hosts.items())
    ]
    return findings, [
        {
            "rule_id": "ANDROID-DEEPLINK-AUTOVERIFY",
            "state": (
                "partial"
                if any("Deep-link combinations limited" in str(w) for w in inventory.get("warnings", []))
                else "checked"
            )
            if inventory.get("android_config")
            else "not-run",
            "method": "configuration",
            "note": "Declared intent filters; assetlinks.json and the verification result are not checked.",
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
        _local_auth(sources),
        _ios_webview_file_access(inventory, sources),
        _network_security_config(inventory, sources),
        _app_links(inventory),
    ):
        findings += part[0]
        coverage += part[1]
    # The same identity can arise twice, for example one manifest reached through two source roots.
    seen: set[str] = set()
    unique = [item for item in findings if not (item["id"] in seen or seen.add(item["id"]))]
    return unique, coverage
