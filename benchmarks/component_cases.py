"""Fresh, predeclared component fixtures; no credential validity is claimed."""

from __future__ import annotations

import hashlib
import json
import random
import string
from pathlib import Path

GITLEAKS_RULES = "https://github.com/gitleaks/gitleaks/blob/v8.30.1/config/gitleaks.toml"


def _token(label: str, length: int, alphabet: str = string.ascii_letters + string.digits) -> str:
    randomizer = random.Random(f"apsa-component-public-synthetic-v1:{label}")
    return "".join(randomizer.choice(alphabet) for _ in range(length))


def secret_cases() -> list[dict]:
    """Pairs exercise the intersection of pinned upstream and APSA formats."""
    definitions = [
        (
            "aws",
            "aws-access-key-id",
            "aws-access-token",
            "AKIA" + _token("aws", 16, string.ascii_uppercase + "234567"),
        ),
        ("github", "github-token", "github-pat", "ghp_" + _token("github", 36)),
        (
            "slack",
            "slack-token",
            "slack-bot-token",
            "xoxb-"
            + _token("slack-a", 12, string.digits)
            + "-"
            + _token("slack-b", 12, string.digits)
            + "-"
            + _token("slack-c", 24),
        ),
        ("stripe", "stripe-live-key", "stripe-access-token", "sk_live_" + _token("stripe", 28)),
    ]
    result = []
    for provider, credential_type, rule, token in definitions:
        for present in (True, False):
            # A changed prefix preserves file, line, length and entropy while
            # deliberately removing the provider-specific format being scored.
            value = token if present else "synthetic_" + token.split("_", 1)[-1][5:]
            result.append(
                {
                    "id": f"secret-{provider}-{'present' if present else 'absent'}",
                    "kind": "secret",
                    "expected": present,
                    "scope": "provider credential-format candidate; no validity or live account claim",
                    "supported": {"apsa-secrets": True, "gitleaks": True},
                    "path": "Probe.kt",
                    "line": 2,
                    "apsa_rule": "SOURCE-HARDCODED-SECRET",
                    "credential_type": credential_type,
                    "gitleaks_rule": rule,
                    "mapping_source": GITLEAKS_RULES,
                    "content": '// Newly generated public synthetic fixture.\nval candidate = "'
                    + value
                    + '"\n',
                }
            )
    return result


def dependency_cases() -> list[dict]:
    result = []
    for ecosystem, name, purl, versions, identifiers in [
        (
            "Maven",
            "org.apache.logging.log4j:log4j-core",
            "pkg:maven/org.apache.logging.log4j/log4j-core",
            ("2.14.1", "2.17.1"),
            ["GHSA-jfh8-c2jp-5v3q", "CVE-2021-44228"],
        ),
        (
            "npm",
            "lodash",
            "pkg:npm/lodash",
            ("4.17.20", "4.17.21"),
            ["GHSA-35jh-r3h4-6jhm", "CVE-2021-23337"],
        ),
    ]:
        for expected, version in zip((True, False), versions, strict=True):
            component = {
                "type": "library",
                "name": name.split(":")[-1],
                "version": version,
                "purl": f"{purl}@{version}",
            }
            if ecosystem == "Maven":
                component["group"] = name.split(":")[0]
            result.append(
                {
                    "id": f"dependency-{'log4j' if ecosystem == 'Maven' else 'lodash'}-{version}",
                    "kind": "dependency",
                    "expected": expected,
                    "scope": "named target advisory only; absent target does not imply absence of all vulnerabilities",
                    "supported": {"apsa-osv": True, "osv-scanner": True},
                    "coordinate": {"ecosystem": ecosystem, "name": name, "version": version},
                    "target_advisories": identifiers,
                    "mapping_source": "https://osv.dev/vulnerability/" + identifiers[0],
                    "path": "bom.json",
                    "content": json.dumps(
                        {
                            "bomFormat": "CycloneDX",
                            "specVersion": "1.5",
                            "version": 1,
                            "components": [component],
                        },
                        sort_keys=True,
                    )
                    + "\n",
                }
            )
    return result


def generate(root: Path) -> list[dict]:
    """Create once and freeze input hashes and labels before any execution."""
    root.mkdir(parents=True, exist_ok=False)
    cases = []
    for original in secret_cases() + dependency_cases():
        case = dict(original)
        raw = case.pop("content").encode()
        directory = root / case["id"]
        directory.mkdir()
        (directory / case["path"]).write_bytes(raw)
        case["sha256"] = hashlib.sha256(raw).hexdigest()
        case["bytes"] = len(raw)
        cases.append(case)
    (root / "labels.json").write_text(json.dumps(cases, indent=2, sort_keys=True) + "\n")
    return cases
