"""A desktop ancestor hint cannot discard a possible mobile privacy declaration."""

import plistlib
import zipfile

import pytest

from mobile_audit.inputs import inspect_target
from mobile_audit.platform_checks import platform_checks

PRIVACY = plistlib.dumps(
    {"NSPrivacyAccessedAPITypes": [{"NSPrivacyAccessedAPIType": "NSPrivacyAccessedAPICategoryUserDefaults"}]}
)


def source_target(tmp_path, files, archive):
    if archive:
        target = tmp_path / "source.zip"
        with zipfile.ZipFile(target, "w") as output:
            for name, content in files.items():
                output.writestr(name, content)
    else:
        target = tmp_path / "source"
        for name, content in files.items():
            path = target / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content)
    return target


@pytest.mark.parametrize("archive", [False, True])
@pytest.mark.parametrize(
    ("desktop_path", "source_path", "manifest_path"),
    [
        ("Main.swift", "M/Main.swift", "M/PrivacyInfo.xcprivacy"),
        ("Main.swift", "App/Sources/Main.swift", "App/Resources/PrivacyInfo.xcprivacy"),
        ("App/MacSupport.swift", "App/Sources/Main.swift", "App/PrivacyInfo.xcprivacy"),
        ("App/MacSupport.swift", "App/Sources/Main.swift", "App/Resources/PrivacyInfo.xcprivacy"),
        ("M/MacSupport.swift", "M/Sources/Main.swift", "M/Resources/PrivacyInfo.xcprivacy"),
        (
            "Workspace/App/MacSupport.swift",
            "Workspace/App/iOS/Sources/Main.swift",
            "Workspace/App/Resources/PrivacyInfo.xcprivacy",
        ),
    ],
)
def test_desktop_ancestor_module_does_not_drop_mobile_privacy_declaration(
    tmp_path, archive, desktop_path, source_path, manifest_path
):
    files = {
        desktop_path: b"import AppKit",
        source_path: b'import UIKit\nUserDefaults.standard.set(true, forKey: "seen")',
        manifest_path: PRIVACY,
    }
    inventory, sources = inspect_target(source_target(tmp_path, files, archive))
    findings, coverage = platform_checks(inventory, sources)
    assert "ios" in inventory["platforms"]
    desktop_root = desktop_path.rsplit("/", 1)[0] if "/" in desktop_path else "."
    assert any(row["root"] == desktop_root for row in inventory["apple_source_scope"]["modules"])
    assert not any(row["rule_id"] == "IOS-PRIVACY-MANIFEST" for row in findings)
    privacy = next(row for row in coverage if row["rule_id"] == "IOS-PRIVACY-MANIFEST")
    assert privacy["state"] == "partial"


@pytest.mark.parametrize("archive", [False, True])
@pytest.mark.parametrize(("desktop_root", "mobile_root"), [("Desktop", "Mobile"), ("App", "Application")])
def test_separate_desktop_manifest_does_not_mask_mobile_declaration_gap(
    tmp_path, archive, desktop_root, mobile_root
):
    files = {
        desktop_root + "/Main.swift": b"import AppKit",
        desktop_root + "/PrivacyInfo.xcprivacy": PRIVACY,
        mobile_root + "/Main.swift": b'import UIKit\nUserDefaults.standard.set(true, forKey: "seen")',
    }
    inventory, sources = inspect_target(source_target(tmp_path, files, archive))
    findings, _ = platform_checks(inventory, sources)
    privacy = [row for row in findings if row["rule_id"] == "IOS-PRIVACY-MANIFEST"]
    assert len(privacy) == 1
    assert privacy[0]["evidence"][0]["path"] == mobile_root + "/Main.swift"


@pytest.mark.parametrize("archive", [False, True])
@pytest.mark.parametrize("suffix", ["m", "mm"])
@pytest.mark.parametrize("nested", [False, True])
@pytest.mark.parametrize("desktop_root", [".", "Desktop", "Workspace/Desktop"])
def test_unclassified_objc_source_keeps_its_possible_privacy_declaration(
    tmp_path, archive, suffix, nested, desktop_root
):
    prefix = "" if desktop_root == "." else desktop_root + "/"
    objc_path = prefix + ("Deep/" if nested else "") + "Use." + suffix
    files = {
        prefix + "Main.swift": b"import AppKit",
        prefix + "PrivacyInfo.xcprivacy": PRIVACY,
        objc_path: b'[NSUserDefaults.standardUserDefaults boolForKey:@"seen"];',
        "Mobile/Main.swift": b"import UIKit",
    }
    inventory, sources = inspect_target(source_target(tmp_path, files, archive))
    assert objc_path not in {row["path"] for row in inventory["apple_source_scope"]["files"]}
    findings, coverage = platform_checks(inventory, sources)
    assert not any(row["rule_id"] == "IOS-PRIVACY-MANIFEST" for row in findings)
    privacy = next(row for row in coverage if row["rule_id"] == "IOS-PRIVACY-MANIFEST")
    assert privacy["state"] == "partial"


@pytest.mark.parametrize("archive", [False, True])
@pytest.mark.parametrize("suffix", ["m", "mm"])
def test_objc_path_prefix_sibling_does_not_reclassify_desktop_manifest(tmp_path, archive, suffix):
    files = {
        "Desktop/Main.swift": b"import AppKit",
        "Desktop/PrivacyInfo.xcprivacy": PRIVACY,
        "DesktopExtra/Use." + suffix: b"@interface Thing : NSObject\n@end",
        "Mobile/Main.swift": b'import UIKit\nUserDefaults.standard.set(true, forKey: "seen")',
    }
    inventory, sources = inspect_target(source_target(tmp_path, files, archive))
    findings, _ = platform_checks(inventory, sources)
    privacy = [row for row in findings if row["rule_id"] == "IOS-PRIVACY-MANIFEST"]
    assert len(privacy) == 1
    assert privacy[0]["evidence"][0]["path"] == "Mobile/Main.swift"
