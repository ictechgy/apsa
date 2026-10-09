"""Explicit Android bulletin backfill and chipset applicability on synthetic inputs."""

from __future__ import annotations

import json

import httpx
import pytest

from mobile_audit.audit import correlate
from mobile_audit.intel import backfill, parse_android, vendor_scope

BULLETIN = (
    b"<h2>2024-01-01 security patch level</h2><h3>System</h3><table><tr><th>CVE</th><th>Severity</th>"
    b"<th>Updated AOSP versions</th></tr><tr><td>CVE-2024-00001</td><td>High</td><td>14</td></tr></table>"
    b"<h2>2024-01-05 security patch level</h2><h3>Qualcomm components</h3><table><tr><th>CVE</th>"
    b"<th>Severity</th><th>Updated AOSP versions</th></tr><tr><td>CVE-2024-00002</td><td>High</td><td>14</td>"
    b"</tr></table>"
)


@pytest.mark.parametrize(
    "heading,scope",
    [
        ("Qualcomm closed-source components", "qualcomm"),
        ("MediaTek components", "mediatek"),
        ("Arm components", "arm"),
        ("Kernel components", "kernel"),
        ("Framework", "platform"),
        ("Alarm manager", "platform"),
    ],
)
def test_bulletin_sections_keep_chipset_vendor_scope(heading, scope):
    assert vendor_scope(heading) == scope


def test_backfill_replaces_each_month_and_reports_gaps(store):
    seen = []

    def handler(request):
        seen.append(str(request.url))
        if request.url.path.endswith("2024-01-01"):
            return httpx.Response(200, content=BULLETIN)
        if request.url.path.endswith("2024-02-01"):
            return httpx.Response(404)
        return httpx.Response(503)

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        result = backfill(store, "android", "2024-01", "2024-03", client=client)
    assert seen == [f"https://source.android.com/docs/security/bulletin/2024-0{m}-01" for m in (1, 2, 3)]
    assert result["fetched"] == ["2024-01"] and result["missing"] == ["2024-02"]
    assert [f["month"] for f in result["failed"]] == ["2024-03"] and result["partial"]
    assert result["historical_backfill_complete"] is False
    assert {r["id"] for r in store.intelligence("CVE-2024-0000", 10)} == {"CVE-2024-00001", "CVE-2024-00002"}
    qualcomm = store.intel_by_id("CVE-2024-00002")[0]
    assert qualcomm["vendor_scope"] == "qualcomm"
    assert json.loads(store.cursor("android-backfill"))["months"] == ["2024-01"]


@pytest.mark.parametrize(
    "since,until", [("2015-07", "2016-01"), ("2024-05", "2024-01"), ("2024-13", "2025-01"), ("2014", "2015")]
)
def test_backfill_rejects_invalid_or_unbounded_ranges(store, since, until):
    with pytest.raises(ValueError):
        backfill(store, "android", since, until)
    with pytest.raises(ValueError):
        backfill(store, "apple", "2024-01", "2024-02")


def records():
    return parse_android(BULLETIN, "https://source.android.com/docs/security/bulletin/2024-01-01")


def states(environment):
    _, advisories = correlate({"platforms": ["android"], "dependencies": []}, records(), environment)
    return {a["id"]: a["state"] for a in advisories}


def test_chipset_components_use_vendor_patch_level_and_flag_vendor_mismatch():
    base = {"platform": "android", "version": "14", "security_patch": "2024-02-01"}
    assert states(base) == {
        "CVE-2024-00001": "vendor-patch-level-satisfied",
        "CVE-2024-00002": "vendor-patch-level-satisfied",
    }
    behind = {**base, "soc_manufacturer": "Qualcomm", "vendor_security_patch": "2023-12-05"}
    assert states(behind)["CVE-2024-00002"] == "potentially-affected"
    assert states(behind)["CVE-2024-00001"] == "vendor-patch-level-satisfied"
    other = {**behind, "soc_manufacturer": "MediaTek"}
    assert states(other)["CVE-2024-00002"] == "chipset-vendor-mismatch"
    unknown = {**behind, "soc_manufacturer": ""}
    assert states(unknown)["CVE-2024-00002"] == "potentially-affected"
