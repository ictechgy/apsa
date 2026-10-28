"""R1 review closure: preserve NSC positives and machine-readable unknown scope."""

from pathlib import Path

import pytest

from mobile_audit import quaygate_analysis
from quaygate.apk import Apk
from quaygate.appchecks import audit_apk
from tests.helpers import build_code_dex, temp_apk

UNKNOWN_BOOL = "@2131034113"


def nsc(base, *domains):
    return [
        (
            "network-security-config",
            {},
            [
                ("base-config", {"cleartextTrafficPermitted": base}, []),
                *[
                    (
                        "domain-config",
                        {"cleartextTrafficPermitted": value},
                        [
                            ("domain", {}, ["synthetic-" + str(index) + ".example"]),
                        ],
                    )
                    for index, value in enumerate(domains)
                ],
            ],
        )
    ]


def actual_apk(tree):
    dex = build_code_dex(
        [("Lcom/synthetic/A;", "run", "Ljavax/crypto/Cipher;", "getInstance", "AES/GCM/NoPadding")]
    )
    # Valid analyzable DEX isolates the NSC coverage state; no certificate tools run.
    return temp_apk(
        app_over={"networkSecurityConfig": "@xml/network_security_config"},
        nsc=tree,
        v1=False,
        files={"classes.dex": dex},
    )


@pytest.mark.parametrize(
    "base,domains",
    [
        ("true", [UNKNOWN_BOOL]),
        (UNKNOWN_BOOL, ["true"]),
        ("false", ["true", UNKNOWN_BOOL]),
        (UNKNOWN_BOOL, [UNKNOWN_BOOL, "true"]),
    ],
)
def test_known_cleartext_and_unknown_scope_have_separate_legacy_records(base, domains):
    with actual_apk(nsc(base, *domains)) as path:
        with Apk(path) as archive:
            _, findings = audit_apk(archive)
    rows = [row for row in findings if row.check_id == "app-cleartext"]
    assert {row.status for row in rows} == {"warn", "na"}
    assert len(rows) == 2
    assert next(row for row in rows if row.status == "warn").severity in {"LOW", "MEDIUM"}
    assert "cleartextTrafficPermitted" in next(row for row in rows if row.status == "na").detail


@pytest.mark.parametrize(
    "base,domains",
    [
        ("true", [UNKNOWN_BOOL]),
        (UNKNOWN_BOOL, ["true"]),
        ("false", ["true", UNKNOWN_BOOL]),
        (UNKNOWN_BOOL, [UNKNOWN_BOOL, "true"]),
    ],
)
def test_real_wrapper_report_retains_finding_and_partial_nsc_coverage(base, domains):
    with actual_apk(nsc(base, *domains)) as path:
        result = quaygate_analysis.analyze(Path(path).resolve())
    finding = next(row for row in result["findings"] if row["rule_id"] == "QG-APP-CLEARTEXT")
    assert finding["severity"] in {"low", "medium"}
    assert finding["evidence"][0]["component"] == "app-cleartext"
    coverage = next(row for row in result["coverage"] if row["rule_id"] == "QG-APP-CLEARTEXT")
    assert coverage["state"] == "partial"
    assert result["metadata"]["complete"] is False
    assert "Quaygate check incomplete: QG-APP-CLEARTEXT" in result["warnings"]


@pytest.mark.parametrize("base,domains", [("true", ["false"]), ("false", ["true"])])
def test_fully_read_known_cleartext_still_has_checked_coverage(base, domains):
    with actual_apk(nsc(base, *domains)) as path:
        result = quaygate_analysis.analyze(Path(path).resolve())
    assert (
        next(row for row in result["coverage"] if row["rule_id"] == "QG-APP-CLEARTEXT")["state"] == "checked"
    )
    assert (
        next(row for row in result["findings"] if row["rule_id"] == "QG-APP-CLEARTEXT")["status"]
        == "candidate"
    )
    assert "Quaygate check incomplete: QG-APP-CLEARTEXT" not in result["warnings"]


def test_unknown_without_observed_cleartext_never_creates_positive():
    with actual_apk(nsc("false", UNKNOWN_BOOL)) as path:
        with Apk(path) as archive:
            _, findings = audit_apk(archive)
        result = quaygate_analysis.analyze(Path(path).resolve())
    assert [row.status for row in findings if row.check_id == "app-cleartext"] == ["na"]
    assert not any(row["rule_id"] == "QG-APP-CLEARTEXT" for row in result["findings"])
    assert (
        next(row for row in result["coverage"] if row["rule_id"] == "QG-APP-CLEARTEXT")["state"] != "checked"
    )
