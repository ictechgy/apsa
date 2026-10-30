"""Platform identity must not suppress common Apple security checks."""

import plistlib

import pytest

from mobile_audit.inputs import inspect_target
from mobile_audit.platform_checks import platform_checks
from mobile_audit.rules import static_checks


def inspect_source(tmp_path, files):
    target = tmp_path / "source"
    target.mkdir()
    for name, content in files.items():
        path = target / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content.encode() if isinstance(content, str) else content)
    inventory, sources = inspect_target(target)
    findings, coverage = platform_checks(inventory, sources)
    patterns, _ = static_checks(inventory, sources)
    return inventory, findings + patterns, coverage


@pytest.mark.parametrize("framework", ["AppKit", "Foundation"])
def test_common_apple_checks_survive_without_ios_identity(tmp_path, framework):
    inventory, findings, coverage = inspect_source(
        tmp_path,
        {
            "Main.swift": f"""import {framework}
let sessionToken = rand()
view.setValue(true, forKey: "allowFileAccessFromFileURLs")
let access = kSecAttrAccessibleAlways
let cipher = kCCAlgorithmDES
let settings = NWParameters(tls: nil)
let value = NSKeyedUnarchiver.unarchiveObject(with: data)
UserDefaults.standard.set(true, forKey: "seen")
"""
        },
    )
    assert "ios" not in inventory["platforms"] and inventory["apps"] == []
    assert {
        "SOURCE-INSECURE-RANDOM",
        "IOS-WEBVIEW-FILE-ACCESS",
        "IOS-KEYCHAIN-ACCESS",
        "IOS-CRYPTO-WEAK-CIPHER",
        "IOS-ATS-BYPASS-API",
        "IOS-INSECURE-UNARCHIVE",
    } <= {row["rule_id"] for row in findings}
    assert not any(row["rule_id"] == "IOS-PRIVACY-MANIFEST" for row in findings)
    privacy = next(row for row in coverage if row["rule_id"] == "IOS-PRIVACY-MANIFEST")
    assert privacy["state"] == ("partial" if framework == "Foundation" else "not-applicable")


def test_mixed_tree_privacy_observation_comes_from_mobile_source(tmp_path):
    _, findings, coverage = inspect_source(
        tmp_path,
        {
            "Desktop/Main.swift": "import AppKit\nlet boot = ProcessInfo.processInfo.systemUptime",
            "Mobile/Main.swift": 'import UIKit\nUserDefaults.standard.set(true, forKey: "seen")',
        },
    )
    privacy = [row for row in findings if row["rule_id"] == "IOS-PRIVACY-MANIFEST"]
    assert len(privacy) == 1 and privacy[0]["evidence"][0]["path"] == "Mobile/Main.swift"
    assert next(row for row in coverage if row["rule_id"] == "IOS-PRIVACY-MANIFEST")["state"] == "partial"


PRIVACY = plistlib.dumps(
    {"NSPrivacyAccessedAPITypes": [{"NSPrivacyAccessedAPIType": "NSPrivacyAccessedAPICategoryUserDefaults"}]}
)


def test_desktop_declaration_does_not_mask_mobile_required_reason(tmp_path):
    _, findings, _ = inspect_source(
        tmp_path,
        {
            "Desktop/Main.swift": "import AppKit",
            "Desktop/PrivacyInfo.xcprivacy": PRIVACY,
            "Mobile/Main.swift": 'import UIKit\nUserDefaults.standard.set(true, forKey: "seen")',
        },
    )
    assert any(row["rule_id"] == "IOS-PRIVACY-MANIFEST" for row in findings)


def test_nearest_mobile_module_manifest_survives_desktop_parent(tmp_path):
    _, findings, _ = inspect_source(
        tmp_path,
        {
            "Main.swift": "import AppKit",
            "Mobile/Main.swift": 'import UIKit\nUserDefaults.standard.set(true, forKey: "seen")',
            "Mobile/PrivacyInfo.xcprivacy": PRIVACY,
        },
    )
    assert not any(row["rule_id"] == "IOS-PRIVACY-MANIFEST" for row in findings)


def test_explicit_mobile_app_configuration_keeps_foundation_privacy_screening(tmp_path):
    inventory, findings, _ = inspect_source(
        tmp_path,
        {
            "Info.plist": plistlib.dumps(
                {"CFBundleIdentifier": "org.synthetic.mobile", "MinimumOSVersion": "16.0"}
            ),
            "Main.swift": 'import Foundation\nUserDefaults.standard.set(true, forKey: "seen")',
        },
    )
    assert inventory["apps"][0]["platform"] == "ios"
    assert inventory["apple_source_scope"]["partial"] is False
    assert inventory["apple_source_scope"]["files"][0]["platforms"] == ["ios"]
    assert any(row["rule_id"] == "IOS-PRIVACY-MANIFEST" for row in findings)


@pytest.mark.parametrize("sibling", [False, True])
@pytest.mark.parametrize("guard", ["os(macOS)", "canImport(AppKit)"])
def test_conditional_desktop_hint_cannot_suppress_shared_ios_privacy(tmp_path, sibling, guard):
    hint = f"#if {guard}\nimport AppKit\n#endif\n"
    shared = 'import Foundation\nUserDefaults.standard.set(true, forKey: "seen")'
    files = {
        "Info.plist": plistlib.dumps({"CFBundleIdentifier": "org.synthetic.shared"}),
        "Shared.swift": shared if sibling else hint + shared,
    }
    if sibling:
        files["Platform.swift"] = hint
    inventory, findings, coverage = inspect_source(tmp_path, files)
    scope = next(row for row in inventory["apple_source_scope"]["files"] if row["path"] == "Shared.swift")
    assert scope["state"] == "conditional" and "ios" in scope["platforms"]
    assert any(row["rule_id"] == "IOS-PRIVACY-MANIFEST" for row in findings)
    assert next(row for row in coverage if row["rule_id"] == "IOS-PRIVACY-MANIFEST")["state"] == "partial"


@pytest.mark.parametrize("hint", ["import AppKit", "swiftpm-macos-minimum"])
def test_module_hint_is_not_exclusive_shared_file_membership(tmp_path, hint):
    files = {
        "Info.plist": plistlib.dumps({"CFBundleIdentifier": "org.synthetic.shared"}),
        "Shared.swift": 'import Foundation\nUserDefaults.standard.set(true, forKey: "seen")',
    }
    if hint == "swiftpm-macos-minimum":
        files["Package.swift"] = (
            'import PackageDescription\nlet package = Package(name: "Shared", platforms: [.macOS(.v14)])'
        )
    else:
        files["Desktop.swift"] = hint
    inventory, findings, _ = inspect_source(tmp_path, files)
    scope = next(row for row in inventory["apple_source_scope"]["files"] if row["path"] == "Shared.swift")
    assert scope["state"] == "inferred" and set(scope["platforms"]) == {"ios", "macos"}
    assert any(row["rule_id"] == "IOS-PRIVACY-MANIFEST" for row in findings)


@pytest.mark.parametrize("hint", ["import AppKit", "#if os(macOS)\nimport AppKit\n#endif"])
def test_configured_ios_module_privacy_declaration_is_not_excluded(tmp_path, hint):
    _, findings, _ = inspect_source(
        tmp_path,
        {
            "Info.plist": plistlib.dumps({"CFBundleIdentifier": "org.synthetic.shared"}),
            "Platform.swift": hint,
            "Shared.swift": 'import Foundation\nUserDefaults.standard.set(true, forKey: "seen")',
            "PrivacyInfo.xcprivacy": PRIVACY,
        },
    )
    assert not any(row["rule_id"] == "IOS-PRIVACY-MANIFEST" for row in findings)


def test_unresolved_shared_module_retains_its_privacy_declaration(tmp_path):
    inventory, findings, _ = inspect_source(
        tmp_path,
        {
            "Desktop/Platform.swift": "import AppKit",
            "Desktop/Shared.swift": 'import Foundation\nUserDefaults.standard.set(true, forKey: "seen")',
            "Desktop/PrivacyInfo.xcprivacy": PRIVACY,
            "Mobile/Main.swift": "import UIKit",
        },
    )
    assert inventory["apple_source_scope"]["partial"] is True
    assert not any(row["rule_id"] == "IOS-PRIVACY-MANIFEST" for row in findings)
