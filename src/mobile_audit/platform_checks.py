"""Source-tree platform checks: component exposure, backup, target SDK, privacy manifests, secrets.

APK and IPA inputs keep the bundled lint engine's equivalents; these checks run
for source trees and AAB manifests, where that engine does not.
"""

from __future__ import annotations

import plistlib
import re

from .core import finding

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
    ("openai-api-key", "high", r"\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{20,}T3BlbkFJ[A-Za-z0-9_-]{20,}\b"),
    ("anthropic-api-key", "high", r"\bsk-ant-(?:api|admin)\d{2}-[A-Za-z0-9_-]{80,}\b"),
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


def _line(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def _masked(value: str) -> str:
    return f"{value[:4]}…({len(value)} characters)"


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
            for match in re.finditer(r"\btargetSdk(?:Version)?\s*(?:=\s*|\(\s*|\s+)(\d{2})\b", text):
                targets.append((path, _line(text, match.start()), int(match[1])))
    if target_level is None and targets:
        target_level = min(level for _, _, level in targets)
    for component in inventory.get("components", []):
        if component.get("type") not in {"activity", "activity-alias", "service", "receiver", "provider"}:
            continue
        exported = component.get("exported")
        implicit = (
            exported == "unspecified"
            and component.get("intent_filters")
            and (target_level is None or target_level < 31)
        )
        protected = any(component.get(key) for key in ("permission", "read_permission", "write_permission"))
        if (exported == "true" or implicit) and not protected and not component.get("launcher"):
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
    manifests = []
    for path, text in sources:
        if not path.endswith(".xcprivacy"):
            continue
        manifests.append(path)
        try:
            document = plistlib.loads(text.encode("utf-8"))
        except (plistlib.InvalidFileException, ValueError, UnicodeError):
            continue
        for item in document.get("NSPrivacyAccessedAPITypes", []) if isinstance(document, dict) else []:
            if isinstance(item, dict) and isinstance(item.get("NSPrivacyAccessedAPIType"), str):
                declared.add(item["NSPrivacyAccessedAPIType"])
    first_use: dict[str, tuple[str, int]] = {}
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
                first_use[category] = (path, _line(cleaned, match.start()))
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
        for category, (path, line) in sorted(first_use.items())
    ]
    return findings, [
        {
            "rule_id": "IOS-PRIVACY-MANIFEST",
            "state": "checked" if scanned else "not-run",
            "method": "source-pattern",
            "note": "Symbol-name evidence only; compiled SDKs and dynamic use are not inspected.",
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


def platform_checks(inventory: dict, sources: list[tuple[str, str]]) -> tuple[list[dict], list[dict]]:
    findings: list[dict] = []
    coverage: list[dict] = []
    if inventory.get("input_kind") in {"apk", "ipa"}:
        # The bundled lint engine reports these for compiled packages.
        return findings, coverage
    for part in (_android(inventory, sources), _privacy_manifest(inventory, sources), _secrets(sources)):
        findings += part[0]
        coverage += part[1]
    return findings, coverage
