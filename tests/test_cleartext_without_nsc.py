"""Fresh synthetic APK coverage for manifest cleartext policy without an NSC."""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from mobile_audit import quaygate_analysis
from quaygate.apk import Apk
from quaygate.appchecks import audit_apk
from quaygate.checks import MEDIUM
from tests.helpers import temp_apk

CASES = [
    ("min21-false", "21", "34", "false", [("warn", MEDIUM)], "checked"),
    ("min22-false", "22", "34", "false", [("warn", MEDIUM)], "checked"),
    ("absent-min-false", None, "34", "false", [("warn", MEDIUM)], "checked"),
    ("min21-absent", "21", "34", None, [("warn", MEDIUM)], "checked"),
    ("min23-absent", "23", "34", None, [("warn", MEDIUM)], "checked"),
    ("min23-false", "23", "34", "false", [("pass", None)], "checked"),
    ("min24-absent", "24", "34", None, [("pass", None)], "checked"),
    ("min24-false", "24", "34", "false", [("pass", None)], "checked"),
    ("min21-true", "21", "34", "true", [("warn", MEDIUM)], "checked"),
    ("min23-true", "23", "34", "true", [("warn", MEDIUM)], "checked"),
    ("min24-true", "24", "34", "true", [("warn", MEDIUM)], "checked"),
    ("min21-resource", "21", "34", "@2130837504", [("warn", MEDIUM), ("na", None)], "partial"),
    ("min23-resource", "23", "34", "@2130837504", [("na", None)], "not-run"),
    ("min24-resource", "24", "34", "@2130837504", [("na", None)], "not-run"),
    ("preview-min-false", "S", "34", "false", [("pass", None)], "checked"),
    ("unknown-target-min24", "24", "S", None, [("na", None)], "not-run"),
    ("old-target-min23", "23", "22", None, [("warn", MEDIUM)], "checked"),
]


@pytest.mark.parametrize(
    ("case", "min_sdk", "target_sdk", "cleartext", "expected", "coverage_state"),
    CASES,
    ids=[case[0] for case in CASES],
)
def test_no_nsc_cleartext_respects_supported_device_apis(
    case, min_sdk, target_sdk, cleartext, expected, coverage_state
):
    # None removes the helpers' defaults, so absent declarations are truly absent.
    with temp_apk(
        app_over={"usesCleartextTraffic": cleartext, "networkSecurityConfig": None},
        sdk_over={"minSdkVersion": min_sdk, "targetSdkVersion": target_sdk},
        nsc=None,
    ) as name:
        path = Path(name).resolve()
        with Apk(str(path)) as apk:
            _, findings = audit_apk(apk)
        raw = [item for item in findings if item.check_id == "app-cleartext"]
        report = quaygate_analysis.analyze(path)
        actual_sha256 = hashlib.sha256(path.read_bytes()).hexdigest()

    assert [(item.status, item.severity) for item in raw] == expected
    [coverage] = [item for item in report["coverage"] if item["rule_id"] == "QG-APP-CLEARTEXT"]
    assert coverage["state"] == coverage_state
    assert coverage["engine"] == "quaygate-lint"
    assert report["metadata"]["input_sha256"] == actual_sha256
    assert report["metadata"]["engine"] == "quaygate-lint"
    issues = [item for item in report["findings"] if item["rule_id"] == "QG-APP-CLEARTEXT"]
    if any(status == "warn" for status, _ in expected):
        [issue] = issues
        assert issue["severity"] == "medium"
        assert issue["origin"] == "quaygate-lint"
        assert issue["confidence"] == "static-indicator"
        assert issue["reproduced"] is False
        assert issue["evidence"][0]["path"] == "AndroidManifest.xml"
        assert issue["evidence"][0]["basis"] == "quaygate-lint"
    else:
        assert issues == []
    if min_sdk in ("21", "22", None):
        assert "API 22 이하" in raw[0].detail
        if cleartext == "false":
            assert "선언값(false)" in raw[0].detail
            assert "minSdk를 23 이상" in raw[0].recommendation
    if case == "min23-absent":
        assert "API 23" in raw[0].detail and "targetSdk 34" in raw[0].detail
    if case == "min21-resource":
        assert "참조값" in raw[1].detail
        assert report["metadata"]["complete"] is False
        assert "Quaygate check incomplete: QG-APP-CLEARTEXT" in report["warnings"]
