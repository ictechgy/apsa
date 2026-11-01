"""Synthetic regressions for dependency intelligence correlation and its exports.

KEV catalog scope, OSV malicious-package severity, CycloneDX VEX selection,
Markdown escaping and multi-version dependency findings. Every advisory, path
and catalog entry here is synthetic; HTTP uses MockTransport only.
"""

from __future__ import annotations

import copy
import re

import httpx
import pytest

from mobile_audit.audit import correlate
from mobile_audit.core import finding, finding_identity
from mobile_audit.intel import _normalize_osv, normalize_kev, sync
from mobile_audit.maswe import coverage_matrix
from mobile_audit.osv_records import aggregate_osv_query
from mobile_audit.output import assistant_context, markdown, sarif
from mobile_audit.policy import evaluate
from mobile_audit.sbom import cyclonedx

MODIFIED = "2026-01-01T00:00:00Z"


def kev(identifier: str, vendor: str, product: str) -> dict:
    return {
        "cveID": identifier,
        "vulnerabilityName": f"{vendor} {product} synthetic issue",
        "vendorProject": vendor,
        "product": product,
        "shortDescription": "Synthetic catalog entry",
        "dateAdded": "2026-01-01",
        "requiredAction": "Apply updates.",
    }


CATALOG = {
    "vulnerabilities": [
        kev("CVE-2021-44228", "Apache", "Log4j2"),
        kev("CVE-2023-4211", "Arm", "Mali GPU Kernel Driver"),
        kev("CVE-2023-21492", "Samsung", "Mobile Devices"),
        kev("CVE-2023-4863", "Google", "Chromium WebP"),
        kev("CVE-2023-41993", "Apple", "Multiple Products"),
    ]
}


def dep(ecosystem: str, name: str, version: str, path: str = "app/gradle.lockfile", **extra) -> dict:
    return {
        "ecosystem": ecosystem,
        "name": name,
        "version": version,
        "confidence": "exact",
        "path": path,
        **extra,
    }


def osv(identifier: str, aliases: tuple[str, ...] = (), severity: str | None = None, **extra) -> dict:
    value = {
        "id": identifier,
        "aliases": list(aliases),
        "summary": f"Synthetic {identifier}",
        "modified": MODIFIED,
        "references": [{"url": f"https://example.invalid/{identifier}"}],
        **extra,
    }
    if severity:
        value["database_specific"] = {"severity": severity}
    return value


def inventory(*dependencies: dict, platforms: tuple[str, ...] = ()) -> dict:
    return {"dependencies": list(dependencies), "platforms": list(platforms)}


def report(dependencies: list[dict], findings: list[dict], **extra) -> dict:
    return {
        "id": "audit_synthetic",
        "created": "2026-11-01T00:00:00+00:00",
        "target": "/synthetic/app",
        "rule_version": "synthetic",
        "inventory": {
            "dependencies": dependencies,
            "platforms": [],
            "fingerprint": "0" * 64,
            "input_kind": "source",
        },
        "summary": {},
        "scope": "Synthetic scope.",
        "findings": findings,
        "coverage": [],
        "intel_snapshot": [],
        "warnings": [],
        **extra,
    }


def client(handler) -> httpx.Client:
    return httpx.Client(transport=httpx.MockTransport(handler), trust_env=False)


def vex_property(bom: dict, identifier: str, name: str) -> list[str]:
    vulnerability = next(v for v in bom["vulnerabilities"] if v["id"] == identifier)
    return [p["value"] for p in vulnerability["properties"] if p["name"] == f"apsa:{name}"]


# KEV catalog scope


def test_kev_catalog_keeps_library_and_mobile_chipset_vendors():
    assert [record["id"] for record in normalize_kev(CATALOG)] == [
        "CVE-2021-44228",
        "CVE-2023-4211",
        "CVE-2023-21492",
        "CVE-2023-4863",
        "CVE-2023-41993",
    ]


def test_library_kev_entry_marks_synced_dependency_finding_exploited(store):
    with client(lambda request: httpx.Response(200, json=CATALOG)) as http:
        assert not sync(store, ["kev"], client=http)["partial"]
    log4j = dep("Maven", "org.apache.logging.log4j:log4j-core", "2.14.1")
    store.upsert_intel([_normalize_osv(osv("GHSA-jfh8-c2jp-5v3q", ("CVE-2021-44228",), "MODERATE"), log4j)])
    findings, advisories = correlate(inventory(log4j), store.correlation_intelligence([log4j]))
    assert [(f["rule_id"], f["severity"], f["known_exploited"]) for f in findings] == [
        ("CVE-2021-44228", "high", True)
    ]
    assert advisories == []  # A catalog entry alone is never an OS advisory.
    assert vex_property(cyclonedx(report([log4j], findings)), "CVE-2021-44228", "known-exploited") == ["true"]


def test_unlisted_dependency_and_mobile_os_advisory_keep_their_exploitation_state():
    records = normalize_kev(CATALOG)
    library = dep("Maven", "synthetic:library", "1.0.0")
    records.append(_normalize_osv(osv("GHSA-aaaa-bbbb-cccc", ("CVE-2099-1111",), "MODERATE"), library))
    records.append(
        {
            "id": "CVE-2023-41993",
            "source": "apple",
            "title": "WebKit",
            "platform": "ios",
            "component": "WebKit",
            "fixed_release": "iOS 17.0.1",
            "references": [],
        }
    )
    findings, advisories = correlate(inventory(library, platforms=("ios",)), records)
    assert [(f["rule_id"], f["severity"], f["known_exploited"]) for f in findings] == [
        ("CVE-2099-1111", "medium", False)
    ]
    assert [(a["id"], a["known_exploited"]) for a in advisories] == [("CVE-2023-41993", True)]


def test_cve_enrichment_still_queues_only_mobile_kev_entries(store):
    with client(lambda request: httpx.Response(200, json=CATALOG)) as http:
        sync(store, ["kev"], client=http)
    requested = []

    def handler(request):
        if request.url.path.endswith("deltaLog.json"):
            return httpx.Response(200, json=[])
        requested.append(request.url.path.rsplit("/", 1)[-1].removesuffix(".json"))
        return httpx.Response(404)

    with client(handler) as http:
        sync(store, ["cve"], limit=10, client=http)
    queued = {row[0] for row in store.db.execute("SELECT id FROM cve_queue")}
    assert queued == set(requested) == {"CVE-2023-4863", "CVE-2023-41993"}


# OSV malicious-package severity


@pytest.mark.parametrize(
    ("identifier", "aliases"),
    [("MAL-2026-0001", ()), ("GHSA-mal0-0000-0001", ("MAL-2026-0001",))],
)
def test_malicious_package_advisory_is_critical_and_gates_by_default(identifier, aliases):
    package = dep("npm", "synthetic-malicious", "1.0.0", "package-lock.json")
    findings, _ = correlate(inventory(package), [_normalize_osv(osv(identifier, aliases), package)])
    assert [(f["rule_id"], f["severity"], f["severity_basis"]) for f in findings] == [
        (identifier, "critical", "malicious-package")
    ]
    assert (
        evaluate({"id": "r", "findings": findings, "coverage": []}, {"schema_version": 1})["state"]
        == "failed"
    )
    run = sarif(report([package], findings))["runs"][0]
    assert run["results"][0]["level"] == "error"
    assert run["tool"]["driver"]["rules"][0]["properties"]["security-severity"] == "9.5"


@pytest.mark.parametrize("withdrawn", [False, True])
def test_malicious_member_of_aggregated_advisory_unless_withdrawn(withdrawn):
    package = dep("npm", "synthetic-shared", "1.0.0", "package-lock.json")
    rated = osv("GHSA-rate-0000-0001", ("CVE-2099-0001",), "HIGH")
    malicious = osv("MAL-2099-0001", ("CVE-2099-0001",), **({"withdrawn": MODIFIED} if withdrawn else {}))
    records = aggregate_osv_query(
        [_normalize_osv(rated, package), _normalize_osv(malicious, package)],
        source="osv:npm:synthetic-shared:1.0.0",
    )
    # The rated advisory represents the group; the malicious member is only nested.
    assert [(r["id"], r["osv_id"], r["osv_ids"]) for r in records] == [
        ("CVE-2099-0001", "GHSA-rate-0000-0001", ["GHSA-rate-0000-0001", "MAL-2099-0001"])
    ]
    findings, _ = correlate(inventory(package), records)
    expected = ("high", "database_specific.severity") if withdrawn else ("critical", "malicious-package")
    assert [(f["severity"], f["severity_basis"]) for f in findings] == [expected]


def test_unrated_and_rated_advisories_keep_their_severity_basis():
    package = dep("PyPI", "synthetic-py", "1.0", "requirements.txt")
    scored = osv("GHSA-cvss-0000-0001", ("CVE-2099-0002",))
    scored["severity"] = [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]
    records = [
        _normalize_osv(osv("GHSA-unra-0000-0001"), package),
        _normalize_osv(scored, package),
        _normalize_osv(osv("PYSEC-2099-MAL1", (), "MODERATE"), package),
    ]
    legacy = {key: value for key, value in records[0].items() if key not in {"severity", "severity_basis"}}
    legacy["id"] = legacy["osv_id"] = "GHSA-lega-0000-0001"
    findings, _ = correlate(inventory(package), [*records, legacy])
    assert sorted((f["rule_id"], f["severity"], f["severity_basis"]) for f in findings) == [
        ("CVE-2099-0002", "critical", "CVSS_V3"),
        ("GHSA-lega-0000-0001", "medium", "unknown"),
        ("GHSA-unra-0000-0001", "medium", "unknown"),
        ("PYSEC-2099-MAL1", "medium", "database_specific.severity"),
    ]


# CycloneDX VEX selection


def test_cyclonedx_vex_lists_every_osv_dependency_namespace():
    go = dep("Go", "golang.org/x/net", "v0.1.0", "go.sum")
    npm = dep("npm", "synthetic-malicious", "1.0.0", "package-lock.json")
    pypi = dep("PyPI", "synthetic-py", "1.0", "requirements.txt")
    records = [
        _normalize_osv(osv("GO-2024-2687", ("GHSA-4v7x-pqxf-cx7m",), "HIGH"), go),
        _normalize_osv(osv("MAL-2026-0001"), npm),
        _normalize_osv(osv("PYSEC-2026-1", (), "LOW"), pypi),
    ]
    findings, _ = correlate(inventory(go, npm, pypi), records)
    bom = cyclonedx(report([go, npm, pypi], findings))
    assert {v["id"]: (v["affects"], v["ratings"]) for v in bom["vulnerabilities"]} == {
        "GO-2024-2687": ([{"ref": "pkg:golang/golang.org/x/net@v0.1.0"}], [{"severity": "high"}]),
        "MAL-2026-0001": ([{"ref": "pkg:npm/synthetic-malicious@1.0.0"}], [{"severity": "critical"}]),
        "PYSEC-2026-1": ([{"ref": "pkg:pypi/synthetic-py@1.0"}], [{"severity": "low"}]),
    }
    weakness = next(
        row for row in coverage_matrix(report([], findings))["weaknesses"] if row["id"] == "MASWE-0044"
    )
    assert set(weakness["findings"]) == {item["id"] for item in findings}


def test_cyclonedx_vex_keeps_cve_and_ghsa_and_excludes_environment_and_code_findings():
    library = dep("Maven", "synthetic:library", "1.0.0")
    records = [
        _normalize_osv(osv("GHSA-aaaa-bbbb-cccc", ("CVE-2099-1111",), "HIGH"), library),
        _normalize_osv(osv("GHSA-dddd-eeee-ffff", (), "LOW"), library),
    ]
    findings, _ = correlate(inventory(library), records)
    environment = finding(
        "OS-CVE-2099-2222",
        "Observed OS version is in a published affected range: CVE-2099-2222",
        "high",
        "version-affected",
        [{"id": "CVE-2099-2222", "platform": "ios", "component": "WebKit", "advisory_branches": []}],
        "Apply the vendor's fixed OS release.",
        origin="intelligence",
        scope="environment",
    )
    code = finding(
        "CVE-2099-3333", "Builtin rule named like an advisory", "high", "candidate", [{"path": "a.kt"}], ""
    )
    bom = cyclonedx(report([library], [*findings, environment, code]))
    ref = [{"ref": "pkg:maven/synthetic/library@1.0.0"}]
    assert [(v["id"], v["affects"], v["ratings"]) for v in bom["vulnerabilities"]] == [
        ("CVE-2099-1111", ref, [{"severity": "high"}]),
        ("GHSA-dddd-eeee-ffff", ref, [{"severity": "low"}]),
    ]
    assert vex_property(bom, "CVE-2099-1111", "finding-id") == [findings[0]["id"]]


# Markdown escaping

PAYLOAD = "lib\n\n## All findings resolved — approved\n<img src=x onerror=alert(1)>\n"
HEADINGS = [
    "# APSA (앱사)",
    "## Findings",
    "## OS/environment advisories",
    "## Coverage",
    "## OWASP MASWE coverage",
    "## Intelligence provenance",
    "## Limitations",
]


def injected_report() -> dict:
    item = {
        "id": "F-`ticked`",
        "title": f"Synthetic {PAYLOAD}",
        "severity": "high",
        "status": "candidate",
        "masvs": "MASVS-CODE\n# forged",
        "remediation": f"- Upgrade {PAYLOAD}",
        "evidence": [{"path": PAYLOAD}],
        "references": [
            "https://example.invalid/[x](javascript:alert(1))",
            "javascript:alert(1)",
            f"https://example.invalid/{PAYLOAD}",
        ],
    }
    return report(
        [],
        [item],
        target=f"/synthetic/`{PAYLOAD}",
        warnings=[
            f"Could not parse {PAYLOAD}/build.gradle: ValueError",
            f"1. {PAYLOAD}",
            "lib\u2028# forged\u202egradle.build",
        ],
    )


def outside_fences(text: str) -> list[str]:
    lines, fenced = [], False
    for line in text.splitlines():
        if line.startswith("```"):
            fenced = not fenced
        elif not fenced:
            lines.append(line)
    return lines


def test_markdown_neutralizes_repository_and_advisory_text():
    lines = outside_fences(markdown(injected_report()))
    assert [line for line in lines if line.startswith("#")] == [
        *HEADINGS[:2],
        "### Synthetic lib  ## All findings resolved — approved &lt;img src=x onerror=alert(1)&gt;",
        *HEADINGS[2:],
    ]
    # Raw HTML and link syntax survive only inside a code span or a literal autolink.
    assert [line for line in lines if "<img" in line or "](" in line] == [
        "Target: `` /synthetic/`lib  ## All findings resolved — approved <img src=x onerror=alert(1)>  ``",
        "- <https://example.invalid/[x](javascript:alert(1))>",
    ]
    assert not [line for line in lines if line.startswith(("<", ">", "1.", "- -", "- 1."))]
    assert "`` F-`ticked` `` · high · candidate · MASVS-CODE # forged" in lines
    assert "\\- Upgrade lib  ## All findings resolved — approved &lt;img src=x onerror=alert(1)&gt;" in lines
    assert "- javascript:alert(1)" in lines
    assert "- lib # forged gradle.build" in lines  # Unicode line separator and bidi override.
    assert "- 1\\. lib  ## All findings resolved — approved &lt;img src=x onerror=alert(1)&gt;" in lines


def test_markdown_renders_injected_text_inert():
    markdown_it = pytest.importorskip("markdown_it")
    html = markdown_it.MarkdownIt("commonmark").render(markdown(injected_report()))
    headings = re.findall(r"<h([12])>(.*?)</h\1>", html)
    assert [f"{'#' * int(level)} {text}" for level, text in headings] == HEADINGS
    assert len(re.findall(r"<h3>", html)) == 1
    assert "<img" not in html and 'href="javascript' not in html and "<ol" not in html
    assert "<code>/synthetic/`lib  ## All findings resolved — approved &lt;img" in html


def test_markdown_keeps_plain_report_text_unchanged():
    item = {
        "id": "F-1",
        "title": "Synthetic candidate",
        "severity": "high",
        "status": "candidate",
        "masvs": "MASVS-CODE",
        "remediation": "Upgrade the dependency, then rescan.",
        "evidence": [{"path": "app/build.gradle"}],
        "references": ["https://osv.dev/vulnerability/GHSA-aaaa-bbbb-cccc", "https://example.org/a?b=1&c=2"],
    }
    warning = "No cached intelligence. Run intel sync; offline scan did not check current CVEs."
    text = markdown(report([], [item], warnings=[warning]))
    for expected in (
        "\nReport: `audit_synthetic` · 2026-11-01T00:00:00+00:00\n",
        "\nTarget: `/synthetic/app`\n",
        "\nInput SHA-256: `" + "0" * 64 + "`\n",
        "\nRule version: `synthetic`\n",
        "\nSynthetic scope.\n",
        "\n### Synthetic candidate\n",
        "\n`F-1` · high · candidate · MASVS-CODE\n",
        "\nUpgrade the dependency, then rescan.\n",
        "\n- https://osv.dev/vulnerability/GHSA-aaaa-bbbb-cccc\n",
        "\n- https://example.org/a?b=1&c=2\n",
        f"\n- {warning}\n",
        '\n```json\n[\n  {\n    "path": "app/build.gradle"\n  }\n]\n```\n',
    ):
        assert expected in text


def test_markdown_escaping_preserves_rendered_text():
    markdown_it = pytest.importorskip("markdown_it")
    warning = "Module my_lib (a*b) uses `x` & <T> [1] ~1.0 #2 \\ path"
    html = markdown_it.MarkdownIt("commonmark").render(markdown(report([], [], warnings=[warning])))
    assert "<li>Module my_lib (a*b) uses `x` &amp; &lt;T&gt; [1] ~1.0 #2 \\ path</li>" in html


# Multiple versions of one dependency location


OKHTTP = dep("Maven", "com.squareup.okhttp3:okhttp", "3.12.0", "sbom.json")
OKHTTP_4 = {**OKHTTP, "version": "4.9.0"}
ADVISORY = osv("GHSA-xxxx-yyyy-zzzz", ("CVE-2099-0001",), "HIGH")


def test_two_versions_at_one_location_keep_both_in_evidence_and_vex():
    records = [_normalize_osv(ADVISORY, OKHTTP), _normalize_osv(ADVISORY, OKHTTP_4)]
    findings, _ = correlate(inventory(OKHTTP, OKHTTP_4), records)
    assert len(findings) == 1
    item = findings[0]
    # The ID and the identity recomputed from evidence (baselines, compare) are unchanged.
    assert item["id"] == finding_identity("CVE-2099-0001", [{"dependency": OKHTTP}])
    assert finding_identity(item["rule_id"], item["evidence"]) == item["id"]
    assert len(item["evidence"]) == 1 and item["evidence"][0]["dependency"] == OKHTTP
    assert [row["dependency"]["version"] for row in item["evidence"][0]["dependency_matches"]] == [
        "3.12.0",
        "4.9.0",
    ]
    assert cyclonedx(report([OKHTTP, OKHTTP_4], findings))["vulnerabilities"][0]["affects"] == [
        {"ref": "pkg:maven/com.squareup.okhttp3/okhttp@3.12.0"},
        {"ref": "pkg:maven/com.squareup.okhttp3/okhttp@4.9.0"},
    ]
    assert correlate(inventory(OKHTTP, OKHTTP_4), list(reversed(records)))[0] == findings
    (location,) = assistant_context(report([OKHTTP, OKHTTP_4], findings))["findings"][0]["locations"]
    assert [row["dependency"]["version"] for row in location["dependency_matches"]] == ["3.12.0", "4.9.0"]


def test_merged_versions_keep_strongest_severity_and_evidence_status():
    candidate = {**OKHTTP_4, "confidence": "declared"}
    older = osv("GHSA-xxxx-yyyy-zzzz", ("CVE-2099-0001",), "LOW", modified="2025-01-01T00:00:00Z")
    records = [_normalize_osv(older, OKHTTP), _normalize_osv(ADVISORY, candidate)]
    findings, _ = correlate(inventory(OKHTTP, candidate), records)
    assert [(f["severity"], f["status"], f["severity_basis"]) for f in findings] == [
        ("high", "version-affected", "database_specific.severity")
    ]
    assert {row["dependency"]["version"] for row in findings[0]["evidence"][0]["dependency_matches"]} == {
        "3.12.0",
        "4.9.0",
    }


def test_single_version_and_separate_locations_are_unchanged():
    record = _normalize_osv(ADVISORY, OKHTTP)
    findings, _ = correlate(inventory(OKHTTP), [record])
    assert [item["evidence"] for item in findings] == [
        [
            {
                "dependency": OKHTTP,
                "basis": "OSV package/version query",
                "advisory_id": "GHSA-xxxx-yyyy-zzzz",
                "intel_snapshot_hash": None,
                "advisory_modified": MODIFIED,
            }
        ]
    ]
    # An identical duplicate inventory row adds nothing.
    assert correlate(inventory(OKHTTP, copy.deepcopy(OKHTTP)), [record])[0] == findings
    elsewhere = {**OKHTTP, "path": "other/sbom.json"}
    separate, _ = correlate(inventory(OKHTTP, elsewhere), [record])
    assert len(separate) == 2
    assert all(
        len(item["evidence"]) == 1 and "dependency_matches" not in item["evidence"][0] for item in separate
    )
