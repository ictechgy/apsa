"""A root desktop hint cannot discard a possible mobile privacy declaration."""

import plistlib

import pytest

from mobile_audit.inputs import inspect_target
from mobile_audit.platform_checks import platform_checks

PRIVACY = plistlib.dumps(
    {"NSPrivacyAccessedAPITypes": [{"NSPrivacyAccessedAPIType": "NSPrivacyAccessedAPICategoryUserDefaults"}]}
)


@pytest.mark.parametrize(
    ("source_path", "manifest_path"),
    [
        ("M/Main.swift", "M/PrivacyInfo.xcprivacy"),
        ("App/Sources/Main.swift", "App/Resources/PrivacyInfo.xcprivacy"),
    ],
)
def test_root_desktop_module_does_not_drop_mobile_privacy_declaration(tmp_path, source_path, manifest_path):
    target = tmp_path / "source"
    files = {
        "Main.swift": b"import AppKit",
        source_path: b'import UIKit\nUserDefaults.standard.set(true, forKey: "seen")',
        manifest_path: PRIVACY,
    }
    for name, content in files.items():
        path = target / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
    inventory, sources = inspect_target(target)
    findings, coverage = platform_checks(inventory, sources)
    assert "ios" in inventory["platforms"]
    assert any(row["root"] == "." for row in inventory["apple_source_scope"]["modules"])
    assert not any(row["rule_id"] == "IOS-PRIVACY-MANIFEST" for row in findings)
    privacy = next(row for row in coverage if row["rule_id"] == "IOS-PRIVACY-MANIFEST")
    assert privacy["state"] == "partial"
