from __future__ import annotations

from mobile_audit.audit import correlate
from mobile_audit.intel import _normalize_osv, normalize_kev

DEP = {
    "ecosystem": "npm",
    "name": "webview-lib",
    "version": "1.0.0",
    "confidence": "exact",
    "path": "package-lock.json",
}
INVENTORY = {"dependencies": [DEP], "platforms": []}


def advisory(osv_id="GHSA-aaaa-bbbb-cccc", aliases=("CVE-2023-1111", "CVE-2023-9999"), **extra):
    value = {
        "id": osv_id,
        "aliases": list(aliases),
        "summary": "WebView library bug",
        "modified": "2024-01-01T00:00:00Z",
        "database_specific": {"severity": "MODERATE"},
        **extra,
    }
    return _normalize_osv(value, DEP)


def rejected(identifier):
    return {
        "id": identifier,
        "source": "cve",
        "state": "REJECTED",
        "title": "REJECTED",
        "affected": [],
        "references": [],
    }


def test_rejected_display_alias_does_not_hide_a_live_osv_advisory():
    record = advisory()
    assert record["id"] == "CVE-2023-1111"
    findings, _ = correlate(INVENTORY, [rejected("CVE-2023-1111"), record])
    assert [(item["rule_id"], item["status"]) for item in findings] == [("CVE-2023-9999", "version-affected")]
    assert findings[0]["evidence"][0]["advisory_id"] == "GHSA-aaaa-bbbb-cccc"


def test_advisory_keeps_its_osv_identity_when_every_cve_alias_is_rejected():
    findings, _ = correlate(INVENTORY, [rejected("CVE-2023-1111"), rejected("CVE-2023-9999"), advisory()])
    assert [item["rule_id"] for item in findings] == ["GHSA-aaaa-bbbb-cccc"]


def test_rejected_or_withdrawn_upstream_identity_is_still_suppressed():
    own_cve = advisory(osv_id="CVE-2023-5555", aliases=())
    assert correlate(INVENTORY, [rejected("CVE-2023-5555"), own_cve])[0] == []
    withdrawn = advisory(withdrawn="2024-02-01T00:00:00Z")
    assert correlate(INVENTORY, [withdrawn])[0] == []
    plain_cve = {"id": "CVE-2023-7777", "source": "cve", "state": "REJECTED", "title": "x"}
    assert correlate({"dependencies": [], "platforms": []}, [plain_cve]) == ([], [])


def test_known_exploited_flag_matches_any_advisory_alias():
    kev = normalize_kev(
        {
            "vulnerabilities": [
                {
                    "cveID": "CVE-2023-9999",
                    "vulnerabilityName": "WebKit UAF",
                    "vendorProject": "Apple",
                    "product": "WebKit",
                    "shortDescription": "x",
                    "dateAdded": "2024-01-01",
                    "requiredAction": "patch",
                }
            ]
        }
    )
    findings, _ = correlate(INVENTORY, [*kev, advisory()])
    assert [(item["rule_id"], item["severity"], item["known_exploited"]) for item in findings] == [
        ("CVE-2023-1111", "high", True)
    ]
