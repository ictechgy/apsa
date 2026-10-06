"""Adapt Quaygate's lint evidence inside the existing bounded parser process.

Both binary engines inspect the same private, immutable input copy. No archive
members are extracted, and Quaygate never opens the report store or a network.
"""

from __future__ import annotations

import re
from collections import defaultdict
from pathlib import Path

from quaygate import __version__ as lint_version

from .core import code_excerpt, file_digest, finding, severity_rank

ANDROID_CHECKS = (
    "app-manifest-anomaly",
    "app-debuggable",
    "app-allowbackup",
    "app-cleartext",
    "app-nsc-user-trust",
    "app-nsc-debug-overrides",
    "app-exported",
    "app-deeplink",
    "app-provider-grant",
    "app-provider-paths",
    "app-permissions-dangerous",
    "app-custom-permissions",
    "app-target-sdk",
    "app-signature",
    "app-cert",
    "dex-scan",
    "dex-weak-crypto",
    "dex-webview",
    "dex-dynamic-code",
    "dex-secrets",
    "dex-embedded-keys",
    "dex-cleartext-urls",
    "dex-trackers",
    "native-hardening",
    "native-scan-scope",
)
IOS_CHECKS = (
    "ipa-ats",
    "ipa-ats-domains",
    "ipa-file-sharing",
    "ipa-url-schemes",
    "ipa-min-os",
    "ipa-get-task-allow",
    "ipa-binary-hardening",
    "bin-scan",
    "bin-secrets",
    "bin-embedded-keys",
    "bin-weak-crypto",
    "bin-cleartext-urls",
    "bin-webview",
    "bin-trackers",
)
# These facts have the same meaning as the original configuration findings.
# Other lint indicators keep distinct IDs; similar API names do not prove the
# same source-to-sink path or the same affected component.
OVERLAP = {"app-debuggable": "ANDROID-DEBUG"}
CONFIGURATION = {"app-debuggable", "app-allowbackup", "ipa-file-sharing"}


def rule_id(check: str) -> str:
    return "QG-" + check.upper()


def group(check: str) -> str:
    if "crypto" in check:
        return "MASVS-CRYPTO"
    if any(word in check for word in ("cleartext", "ats", "nsc")):
        return "MASVS-NETWORK"
    if any(word in check for word in ("backup", "sharing", "secrets", "keys")):
        return "MASVS-STORAGE"
    if any(word in check for word in ("hardening", "debug", "signature", "cert", "task-allow")):
        return "MASVS-RESILIENCE"
    return "MASVS-PLATFORM"


def catalog() -> list[dict]:
    return [
        {
            "id": rule_id(check),
            "title": check,
            "platform": platform,
            "mode": "quaygate-binary",
            "masvs": group(check),
            "mapping_scope": "partial",
            "engine": "quaygate-lint",
        }
        for platform, checks in (("android", ANDROID_CHECKS), ("ios", IOS_CHECKS))
        for check in checks
    ]


def _audit(target: Path):
    if target.suffix.lower() == ".apk":
        from quaygate.apk import Apk
        from quaygate.appchecks import audit_apk

        with Apk(str(target)) as archive:
            meta, results = audit_apk(archive)
            meta["dex_entries"] = sum(
                bool(re.fullmatch(r"classes\d*\.dex", name)) for name in archive.entry_names()
            )
            return meta, results
    from quaygate.ipa import Ipa, audit_ipa

    with Ipa(str(target)) as archive:
        return audit_ipa(archive)


def analyze(target: Path) -> dict:
    output = {
        "findings": [],
        "coverage": [],
        "warnings": [],
        "metadata": {
            "engine": "quaygate-lint",
            "version": lint_version,
            "complete": True,
        },
    }
    checks = ANDROID_CHECKS if target.suffix.lower() == ".apk" else IOS_CHECKS
    try:
        meta, results = _audit(target)
    except Exception as error:
        output["metadata"]["complete"] = False
        output["warnings"].append(f"Quaygate lint incomplete: {type(error).__name__}")
        output["coverage"] = [
            {"rule_id": rule_id(check), "state": "partial", "method": "quaygate-lint"} for check in checks
        ]
        return output
    output["metadata"]["input_sha256"] = file_digest(target)
    grouped = defaultdict(list)
    for result in results:
        grouped[result.check_id].append(result)
    for check in sorted(set(checks) | set(grouped)):
        records = grouped[check]
        states = {r.status for r in records}
        state = "partial" if "error" in states else "not-run" if not states or "na" in states else "checked"
        # The legacy engine treats an absent/unparseable profile as a pass.
        # Absence cannot establish the actual signing entitlements.
        if check == "ipa-get-task-allow" and states == {"pass"}:
            state = "not-run"
        if check.startswith("dex-") and not meta.get("dex_entries"):
            state = "not-run"
        if check.startswith("bin-") and any(r.check_id == "bin-scan" and r.status == "na" for r in results):
            state = "not-run"
        if check in {"dex-scan", "native-scan-scope", "app-manifest-anomaly"} and not records:
            state = "not-applicable"
        if check == "app-manifest-anomaly" and records:
            state = "partial"
        if check in {"dex-scan", "native-scan-scope"} and "info" in states:
            state = "partial"
        output["coverage"].append(
            {
                "rule_id": rule_id(check),
                "state": state,
                "method": "quaygate-lint",
                "engine": "quaygate-lint",
                "masvs": group(check),
                "mapping_scope": "partial",
                "note": "Scoped static screening only. Signature block presence is not cryptographic signature verification; symbol/string indicators are heuristic. Missing checks never establish safety.",
            }
        )
        if state == "partial":
            output["metadata"]["complete"] = False
            output["warnings"].append(f"Quaygate check incomplete: {rule_id(check)}")
        issues = [r for r in records if r.status in {"fail", "warn", "info"}]
        if not issues:
            continue
        primary = max(issues, key=lambda r: severity_rank((r.severity or "INFO").lower()))
        path = (
            "AndroidManifest.xml"
            if check.startswith("app-")
            else "Payload/Info.plist"
            if check.startswith("ipa-")
            else "binary"
        )
        confirmed = check in CONFIGURATION and states <= {"fail", "warn", "info", "pass"}
        output["findings"].append(
            finding(
                rule_id(check),
                code_excerpt(primary.title),
                (primary.severity or "INFO").lower(),
                "configuration-confirmed" if confirmed else "candidate",
                [
                    {
                        "path": path,
                        "component": check,
                        "basis": "quaygate-lint",
                        "details": [code_excerpt(r.detail) for r in issues[:20]],
                    }
                ],
                code_excerpt(primary.recommendation),
                group(check),
                origin="quaygate-lint",
                confidence="configuration-observation" if confirmed else "static-indicator",
                reachability="unknown",
                reproduced=False,
            )
        )
    return output


def merge(findings: list[dict], additional: list[dict]) -> list[dict]:
    """Coalesce only an exactly equivalent fact; retain stable original IDs."""
    for item in additional:
        check = item["rule_id"][3:].lower()
        existing = [
            f
            for f in findings
            if f["rule_id"] == OVERLAP.get(check)
            and any(e.get("path") == "AndroidManifest.xml" for e in f["evidence"])
        ]
        if len(existing) == 1:
            match = existing[0]
            match["engines"] = sorted(set(match.get("engines", ["mobile-audit"]) + ["quaygate-lint"]))
            match["supporting_checks"] = sorted(set(match.get("supporting_checks", []) + [item["rule_id"]]))
            if severity_rank(item["severity"]) > severity_rank(match["severity"]):
                match["severity"] = item["severity"]
        else:
            findings.append(item)
    return findings
