"""Generate new protocol controls; these are not published advisory or app evidence."""

from mobile_audit.ios_ranges import APPLE_ORG


def apple_cna_document() -> dict:
    """A fresh CNA-shaped input for branch-binding and malformed-input tests."""
    return {
        "cveMetadata": {"cveId": "CVE-2099-900001", "assignerOrgId": APPLE_ORG},
        "containers": {
            "cna": {
                "providerMetadata": {"orgId": APPLE_ORG},
                "title": "Synthetic WebKit branch control",
                "descriptions": [{"lang": "en", "value": "New synthetic protocol control only"}],
                "references": [
                    {"url": "https://support.apple.com/en-us/" + identifier}
                    for identifier in ("122281", "122346", "122345", "122372")
                ],
                "affected": [
                    {
                        "vendor": "Apple",
                        "product": product,
                        "versions": [
                            {
                                "version": "0",
                                "lessThan": fixed,
                                "versionType": "custom",
                                "status": "affected",
                            }
                            for fixed in boundaries
                        ],
                    }
                    for product, boundaries in (
                        ("iOS and iPadOS", ("15.8.4", "16.7.11", "18.3.2")),
                        ("iPadOS", ("17.7.6",)),
                    )
                ],
            }
        },
    }


def evaluation_spec() -> dict:
    """New labels exercising the frozen-spec parser, never a real app corpus."""
    states = ["affected"] * 8 + ["unaffected"] * 19 + ["unknown"] * 5
    return {
        "schema": "apsa-real-world-spec-v1",
        "fixture_origin": "new-synthetic-controls-only",
        "apps": [{"id": f"synthetic-app-{index}"} for index in range(6)],
        "dependency_cases": [
            {"id": f"synthetic-dependency-{index}", "expected": state} for index, state in enumerate(states)
        ],
        "os_cases": [{"id": f"synthetic-os-{index}"} for index in range(11)],
        "limits": {},
    }
