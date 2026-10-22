"""Claims require their own check evidence, and incomplete checks stay incomplete."""

import pytest

from mobile_audit.core import finding
from mobile_audit.rules import static_checks
from mobile_audit.source_analysis import analyze_sources
from mobile_audit.verify import verify_claim
from tests.test_agent_verification import PROVIDER

TRAVERSAL = """import java.io.File
import java.util.zip.ZipInputStream
class Example {
    fun unzip(stream: ZipInputStream, dir: File) {
        val entry = stream.nextEntry ?: return
        val out = File(dir, entry.name)
    }
}
"""


def source_report(name, text, exported_providers=None):
    analyzed = analyze_sources([(name, text)], None, exported_providers)
    return {
        "id": "synthetic-claim-report",
        "target": "/synthetic/project",
        "findings": analyzed["findings"],
        "coverage": analyzed["coverage"],
        "inventory": {"platforms": ["android"], "source_analysis": analyzed["metadata"]},
    }


@pytest.mark.parametrize(
    "claim", [{"rule": "AST-SQL-CONCAT"}, {"weakness": "CWE-89"}, {"weakness": "CWE-502"}]
)
def test_path_finding_cannot_corroborate_sql_or_deserialization_claim(claim):
    report = source_report("Example.kt", TRAVERSAL)
    assert [item["rule_id"] for item in report["findings"]] == ["AST-PATH-TRAVERSAL"]
    result = verify_claim(report, path="Example.kt", line=6, **claim)
    assert result["verdict"] != "corroborated"
    assert not result["matching_findings"] and not result["other_findings_in_file"]
    assert all(check["rule_id"] != "AST-PATH-TRAVERSAL" for check in result["related_checks"])


@pytest.mark.parametrize(
    "claim", [{"rule": "AST-PATH-TRAVERSAL"}, {"weakness": "CWE-22"}, {"weakness": "MASWE-0050"}]
)
def test_matching_rule_cwe_and_broad_maswe_remain_corroborated(claim):
    report = source_report("Example.kt", TRAVERSAL)
    assert verify_claim(report, path="Example.kt", line=6, **claim)["verdict"] == "corroborated"


@pytest.mark.parametrize("weakness", ["CWE-89", "cwe-089", "MASWE-0050"])
def test_real_sql_finding_satisfies_exact_and_compatible_weakness_claims(weakness):
    report = source_report("FilesProvider.java", PROVIDER, {"FilesProvider"})
    result = verify_claim(report, path="FilesProvider.java", rule="AST-SQL-CONCAT", weakness=weakness)
    assert result["verdict"] == "corroborated"
    assert {item["rule_id"] for item in result["matching_findings"]} == {"AST-SQL-CONCAT"}


@pytest.mark.parametrize("weakness", ["CWE-89", "MASWE-0008"])
def test_rule_and_weakness_are_both_constraints(weakness):
    report = source_report("Example.kt", TRAVERSAL)
    result = verify_claim(report, rule="AST-PATH-TRAVERSAL", weakness=weakness)
    assert result["verdict"] == "not-assessed"
    assert not result["matching_findings"]


def test_unmapped_precise_cwe_never_borrows_a_related_maswe_result():
    report = source_report("Example.kt", TRAVERSAL)
    # CWE-20 is also related to MASWE-0050, but has no precise supported check mapping.
    result = verify_claim(report, weakness="CWE-20")
    assert result["verdict"] == "not-assessed"
    assert not result["matching_findings"] and "explicit rule mapping" in result["note"]


@pytest.mark.parametrize(
    "rule,expected",
    [
        ("WEBVIEW-SSL-BYPASS", "corroborated"),
        ("AST-WEBVIEW-SSL-BYPASS", "corroborated"),
        ("BINARY-WEBVIEW-SSL-BYPASS", "corroborated"),
        ("SOURCE-TRUST-ALL-CERTS", "corroborated"),
        ("SWIFT-SERVER-TRUST-ACCEPTED", "corroborated"),
        ("ANDROID-NSC-USER-CA", "not-run"),
    ],
)
def test_certificate_claim_requires_bypass_evidence_not_shared_maswe(rule, expected):
    report = {
        "findings": [finding(rule, "Synthetic evidence", "medium", "candidate", [], "Review")],
        "coverage": [],
        "inventory": {},
    }
    assert verify_claim(report, weakness="CWE-295")["verdict"] == expected


@pytest.mark.parametrize(
    "rule,group,sibling",
    [
        ("ANDROID-DEBUG", "ANDROID-CONFIG", "ANDROID-CLEARTEXT"),
        ("ANDROID-CLEARTEXT", "ANDROID-CONFIG", "ANDROID-DEBUG"),
        ("IOS-ATS", "IOS-CONFIG", "IOS-ATS-EXCEPTION"),
    ],
)
@pytest.mark.parametrize(
    "state,expected", [("checked", "not-observed"), ("partial", "partial"), ("not-run", "not-run")]
)
def test_config_coverage_alias_never_broadens_finding_or_weakness_scope(
    rule, group, sibling, state, expected
):
    report = {
        "findings": [finding(sibling, "Different claim", "medium", "candidate", [], "Review")],
        "coverage": [{"rule_id": group, "state": state}],
        "inventory": {},
    }
    result = verify_claim(report, rule=rule)
    assert result["verdict"] == expected and not result["matching_findings"]
    assert result["related_checks"] == [{"rule_id": rule, "states": [state]}]
    incompatible = verify_claim(report, rule=rule, weakness="CWE-89")
    assert incompatible["verdict"] == "not-assessed" and not incompatible["related_checks"]


def test_real_safe_config_checks_support_exact_claims():
    inventory = {
        "platforms": ["android", "ios"],
        "android_config": [
            {
                "path": "AndroidManifest.xml",
                "debuggable": "false",
                "cleartext": "false",
                "network_security_config": None,
            }
        ],
        "ios_config": [{"path": "Info.plist", "ats": {}}],
    }
    findings, coverage = static_checks(inventory, [])
    report = {"findings": findings, "coverage": coverage, "inventory": inventory}
    for rule in ("ANDROID-DEBUG", "ANDROID-CLEARTEXT", "IOS-ATS"):
        assert verify_claim(report, rule=rule)["verdict"] == "not-observed"


@pytest.mark.parametrize(
    "states,expected",
    [
        (["checked", "not-run"], "partial"),
        (["checked", "partial"], "partial"),
        (["checked", "not-applicable"], "not-observed"),
        (["checked"], "not-observed"),
        (["not-run"], "not-run"),
        (["not-applicable"], "not-run"),
        ([], "not-run"),
    ],
)
def test_dependency_verification_aggregates_all_present_coverage(states, expected):
    report = {
        "findings": [],
        "coverage": [{"rule_id": "DEPENDENCY-CVE", "state": state} for state in states],
        "inventory": {},
    }
    assert verify_claim(report, rule="DEPENDENCY-CVE")["verdict"] == expected


def test_partial_coverage_across_broad_related_rules_and_exact_rule_scope():
    report = {
        "findings": [],
        "coverage": [
            {"rule_id": "AST-SQL-CONCAT", "state": "checked"},
            {"rule_id": "AST-PATH-TRAVERSAL", "state": "not-run"},
        ],
        "inventory": {},
    }
    assert verify_claim(report, weakness="MASWE-0050")["verdict"] == "partial"
    assert verify_claim(report, rule="AST-SQL-CONCAT")["verdict"] == "not-observed"


@pytest.mark.parametrize(
    "origin,scope,expected",
    [
        ("intelligence", "app", "corroborated"),
        ("intelligence", "environment", "not-run"),
        ("external", "app", "not-run"),
    ],
)
def test_dependency_group_retains_advisory_ids_without_borrowing_environment_or_external(
    origin, scope, expected
):
    report = {
        "findings": [
            finding(
                "GHSA-synthetic",
                "Synthetic dependency",
                "high",
                "version-affected",
                [],
                "Upgrade",
                origin=origin,
                scope=scope,
            )
        ],
        "coverage": [],
        "inventory": {},
    }
    assert verify_claim(report, rule="DEPENDENCY-CVE")["verdict"] == expected
