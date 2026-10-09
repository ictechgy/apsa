"""CycloneDX 1.6 SBOM with embedded VEX from an APSA report.

Components are the dependencies APSA discovered, with the evidence behind each
version. Vulnerabilities are APSA's dependency matches. Every analysis state is
``in_triage``: APSA does not decide exploitability, so it never emits
``not_affected``; a person must record that decision with a justification.
"""

from __future__ import annotations

import uuid
from pathlib import Path
from urllib.parse import quote

from . import __version__
from .core import report_incomplete
from .maswe import ADVISORY_PREFIXES
from .source_context import superseded

NAMESPACE = uuid.UUID("6f1d6c5e-4b8e-5f0a-9a0e-61707361626f")
PURL_TYPES = {
    "Maven": "maven",
    "npm": "npm",
    "PyPI": "pypi",
    "Go": "golang",
    "Pub": "pub",
    "CocoaPods": "cocoapods",
}


def purl(dep: dict) -> str | None:
    ecosystem, name, version = dep.get("ecosystem"), dep.get("name", ""), dep.get("version", "")
    if not version:
        return None
    suffix = f"@{quote(version, safe='')}"
    if ecosystem == "Maven" and ":" in name:
        group, artifact = name.split(":", 1)
        return f"pkg:maven/{quote(group, safe='.')}/{quote(artifact, safe='.')}{suffix}"
    if ecosystem == "npm" and name.startswith("@") and "/" in name:
        scope, package = name.split("/", 1)
        return f"pkg:npm/{quote(scope, safe='')}/{quote(package, safe='.')}{suffix}"
    if ecosystem == "SwiftURL":
        location = name.removeprefix("https://").removeprefix("http://").removesuffix(".git").strip("/")
        if location.count("/") < 2:
            return None
        namespace, package = location.rsplit("/", 1)
        return f"pkg:swift/{quote(namespace, safe='./')}/{quote(package, safe='.')}{suffix}"
    if ecosystem == "Go" and "/" in name:
        # Go module paths keep their segments: pkg:golang/github.com/org/module@v1.
        segments = [quote(part, safe=".") for part in name.split("/") if part]
        return f"pkg:golang/{'/'.join(segments)}{suffix}"
    if ecosystem == "CocoaPods" and "/" in name:
        # A subspec is a subpath of its pod: pkg:cocoapods/Pod@1.0#Subspec.
        pod, subspec = name.split("/", 1)
        subpath = "/".join(quote(part, safe=".") for part in subspec.split("/") if part)
        return f"pkg:cocoapods/{quote(pod, safe='.')}{suffix}" + (f"#{subpath}" if subpath else "")
    if ecosystem in PURL_TYPES:
        return f"pkg:{PURL_TYPES[ecosystem]}/{quote(name, safe='.')}{suffix}"
    return None


def _property(name: str, value: object) -> dict:
    return {"name": f"apsa:{name}", "value": str(value).lower() if isinstance(value, bool) else str(value)}


def cyclonedx(report: dict, first_observed: dict[str, str] | None = None) -> dict:
    """``first_observed`` maps finding IDs to the earliest report time that showed them."""
    inventory = report["inventory"]
    application = {
        "type": "application",
        "bom-ref": "app",
        "name": inventory.get("package") or Path(report["target"]).name,
    }
    if inventory.get("fingerprint"):
        application["hashes"] = [{"alg": "SHA-256", "content": inventory["fingerprint"]}]
    components, refs = [], {}
    for index, dep in enumerate(inventory.get("dependencies", [])):
        key = (dep.get("ecosystem"), dep.get("name"), dep.get("version"))
        if key in refs:
            continue
        identifier = purl(dep)
        ref = f"dep-{index}" if identifier is None or identifier in refs.values() else identifier
        refs[key] = ref
        properties = [
            _property("ecosystem", dep.get("ecosystem", "")),
            _property("confidence", dep.get("confidence", "unknown")),
            _property("evidence-path", dep.get("path", "")),
        ]
        if dep.get("version_source"):
            properties.append(_property("version-source", dep["version_source"]))
        if superseded(dep):
            properties.append(_property("superseded-by-resolved-build", True))
        component = {
            "type": "library",
            "bom-ref": ref,
            "name": dep.get("name", ""),
            "version": dep.get("version", ""),
            "properties": properties,
        }
        if identifier:
            component["purl"] = identifier
        components.append(component)
    vulnerabilities: dict[str, dict] = {}
    for item in report.get("findings", []):
        if item.get("origin") != "intelligence" or not item["rule_id"].startswith(ADVISORY_PREFIXES):
            continue
        dep = (item.get("evidence") or [{}])[0].get("dependency") or {}
        ref = refs.get((dep.get("ecosystem"), dep.get("name"), dep.get("version")))
        entry = vulnerabilities.setdefault(
            item["rule_id"],
            {
                "bom-ref": f"vuln-{item['rule_id']}",
                "id": item["rule_id"],
                "source": {"name": "OSV", "url": "https://osv.dev"},
                "ratings": [{"severity": item["severity"] if item["severity"] != "info" else "info"}],
                "affects": [],
                "analysis": {
                    "state": "in_triage",
                    "detail": "Version match only; reachability and exploitability were not analyzed by APSA.",
                },
                "properties": [_property("known-exploited", bool(item.get("known_exploited")))],
            },
        )
        if ref and {"ref": ref} not in entry["affects"]:
            entry["affects"].append({"ref": ref})
        entry["properties"] += [
            _property("finding-id", item["id"]),
            _property("evidence-status", item["status"]),
        ]
        if first_observed and item["id"] in first_observed:
            entry["properties"].append(_property("first-observed", first_observed[item["id"]]))
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{uuid.uuid5(NAMESPACE, report['id'])}",
        "version": 1,
        "metadata": {
            "timestamp": report["created"],
            "tools": {
                "components": [
                    {
                        "type": "application",
                        "name": "apsa",
                        "version": report.get("tool_version", __version__),
                    }
                ]
            },
            "component": application,
            "properties": [
                _property("report-id", report["id"]),
                _property("audit-incomplete", report_incomplete(report)),
                _property(
                    "scope",
                    "Dependencies APSA discovered from source declarations, lockfiles, SBOM input and binaries; "
                    "not a complete build inventory.",
                ),
            ],
        },
        "components": components,
        "dependencies": [{"ref": "app", "dependsOn": [c["bom-ref"] for c in components]}],
        "vulnerabilities": list(vulnerabilities.values()),
    }
