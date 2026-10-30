"""Source macOS plist hints cannot complete an iOS app audit."""

import plistlib
import zipfile

import pytest

from mobile_audit.inputs import inspect_target
from mobile_audit.platform_checks import platform_checks

SWIFT = b'import SwiftUI\nUserDefaults.standard.set(true, forKey: "seen")'


def source_target(tmp_path, files, archive=False):
    if archive:
        target = tmp_path / "source.zip"
        with zipfile.ZipFile(target, "w") as output:
            for path, content in files.items():
                output.writestr(path, content)
    else:
        target = tmp_path / "source"
        for name, content in files.items():
            path = target / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content)
    return target


def privacy_coverage(inventory, sources):
    _, coverage = platform_checks(inventory, sources)
    return next(row for row in coverage if row["rule_id"] == "IOS-PRIVACY-MANIFEST")


@pytest.mark.parametrize("archive", [False, True])
@pytest.mark.parametrize(
    "hints", [{"LSMinimumSystemVersion": "13.0"}, {"CFBundleSupportedPlatforms": ["MacOSX"]}]
)
def test_explicit_macos_source_plist_does_not_establish_ios_identity(tmp_path, archive, hints):
    target = source_target(
        tmp_path,
        {
            "Desktop/Info.plist": plistlib.dumps({"CFBundleIdentifier": "org.synthetic.desktop", **hints}),
            "Desktop/App.swift": SWIFT,
        },
        archive,
    )
    inventory, sources = inspect_target(target)
    assert inventory["platforms"] == ["macos"]
    assert inventory["apps"] == inventory["ios_config"] == []
    assert inventory["package"] == ""
    assert inventory["apple_source_plists"][0]["package"] == "org.synthetic.desktop"
    scope = inventory["apple_source_scope"]
    assert not scope["app_identity_established"]
    assert scope["files"][0]["platforms"] == ["macos"]
    assert scope["files"][0]["state"] == "inferred"
    assert scope["partial"] and inventory["partial"]
    assert privacy_coverage(inventory, sources)["state"] == "partial"


@pytest.mark.parametrize("archive", [False, True])
@pytest.mark.parametrize(
    "ios_hint",
    [
        {"MinimumOSVersion": "16.0"},
        {"UIDeviceFamily": [1, 2]},
        {"LSRequiresIPhoneOS": True},
        {"CFBundleSupportedPlatforms": ["MacOSX", "iPhoneOS"]},
    ],
)
def test_dual_plist_hints_retain_ios_observations_with_partial_scope(tmp_path, archive, ios_hint):
    target = source_target(
        tmp_path,
        {
            "Shared/Info.plist": plistlib.dumps(
                {"CFBundleIdentifier": "org.synthetic.shared", "LSMinimumSystemVersion": "13.0", **ios_hint}
            ),
            "Shared/App.swift": SWIFT,
        },
        archive,
    )
    inventory, sources = inspect_target(target)
    assert inventory["platforms"] == ["ios", "macos"]
    assert inventory["apps"][0]["platform"] == "ios"
    assert inventory["apps"][0]["package"] == "org.synthetic.shared"
    assert inventory["ios_config"][0]["path"] == "Shared/Info.plist"
    assert inventory["apple_source_plists"][0]["platforms"] == ["ios", "macos"]
    scope = inventory["apple_source_scope"]
    assert scope["files"][0]["platforms"] == ["ios", "macos"]
    assert scope["files"][0]["state"] == "inferred"
    assert scope["partial"] and inventory["partial"]
    assert privacy_coverage(inventory, sources)["state"] == "partial"


@pytest.mark.parametrize("archive", [False, True])
def test_bundle_identifier_only_source_plist_keeps_existing_behavior(tmp_path, archive):
    target = source_target(
        tmp_path,
        {
            "Mobile/Info.plist": plistlib.dumps({"CFBundleIdentifier": "org.synthetic.legacy"}),
            "Mobile/App.swift": SWIFT,
        },
        archive,
    )
    inventory, sources = inspect_target(target)
    assert inventory["platforms"] == ["ios"]
    assert inventory["apps"][0]["package"] == "org.synthetic.legacy"
    assert inventory["apple_source_scope"]["partial"] is False
    assert privacy_coverage(inventory, sources)["state"] == "checked"


@pytest.mark.parametrize("archive", [False, True])
def test_macos_plist_does_not_remove_direct_uikit_evidence(tmp_path, archive):
    target = source_target(
        tmp_path,
        {
            "Shared/Info.plist": plistlib.dumps(
                {"CFBundleIdentifier": "org.synthetic.shared", "LSMinimumSystemVersion": "13.0"}
            ),
            "Shared/App.swift": b"import UIKit",
        },
        archive,
    )
    inventory, _ = inspect_target(target)
    assert inventory["platforms"] == ["ios", "macos"]
    assert inventory["apps"] == inventory["ios_config"] == []
    assert inventory["apple_source_scope"]["files"][0]["platforms"] == ["ios"]
    assert inventory["partial"]


@pytest.mark.parametrize(("archive", "referenced"), [(False, False), (False, True), (True, True)])
def test_named_or_selected_macos_source_plist_remains_available_without_ios_config(
    tmp_path, archive, referenced
):
    files = {
        "Desktop/Named.plist": plistlib.dumps(
            {"CFBundleIdentifier": "org.synthetic.desktop", "LSMinimumSystemVersion": "13.0"}
        ),
        "Desktop/App.swift": SWIFT,
    }
    if referenced:
        files["App.xcodeproj/project.pbxproj"] = b'INFOPLIST_FILE = "Desktop/Named.plist";'
    target = source_target(tmp_path, files, archive)
    inventory, _ = inspect_target(target, configuration=None if referenced else "Desktop/Named.plist")
    assert inventory["platforms"] == ["macos"]
    assert inventory["apps"] == inventory["ios_config"] == []
    assert inventory["apple_source_plists"][0]["path"] == "Desktop/Named.plist"
    assert inventory["partial"]
    if referenced:
        assert inventory["configuration_references"][0]["state"] == "observed"


@pytest.mark.parametrize("package_type", ["app-folder", "app-zip", "ipa"])
@pytest.mark.parametrize("identified", [False, True])
def test_source_plist_guard_preserves_packaged_main_identity_contract(tmp_path, package_type, identified):
    document = {"LSMinimumSystemVersion": "13.0"}
    if identified:
        document["CFBundleIdentifier"] = "org.synthetic.mobile"
    raw = plistlib.dumps(document)
    if package_type == "app-folder":
        target = tmp_path / "Mobile.app"
        target.mkdir()
        (target / "Info.plist").write_bytes(raw)
    else:
        target = tmp_path / ("mobile.ipa" if package_type == "ipa" else "mobile.zip")
        with zipfile.ZipFile(target, "w") as output:
            output.writestr("Payload/Mobile.app/Info.plist", raw)
    if not identified:
        with pytest.raises(ValueError, match="main Info.plist with an app identifier"):
            inspect_target(target)
        return
    inventory, _ = inspect_target(target)
    assert inventory["platforms"] == ["ios"]
    assert inventory["apps"][0]["package"] == "org.synthetic.mobile"
    assert inventory["ios_config"][0]["minimum_os"] == ""
    assert "apple_source_plists" not in inventory
    assert "apple_source_scope" not in inventory


@pytest.mark.parametrize("archive", [False, True])
@pytest.mark.parametrize(
    "hints",
    [
        {"LSMinimumSystemVersion": 13},
        {"LSMinimumSystemVersion": 13.5},
        {"LSMinimumSystemVersion": {"version": "13.0"}},
        {"LSMinimumSystemVersion": []},
        {"LSMinimumSystemVersion": True},
        {"LSMinimumSystemVersion": b"13.0"},
        {"CFBundleSupportedPlatforms": "MacOSX"},
        {"CFBundleSupportedPlatforms": 13},
        {"CFBundleSupportedPlatforms": {}},
        {"CFBundleSupportedPlatforms": [1]},
        {"CFBundleSupportedPlatforms": ["MacOSX", 1]},
    ],
)
def test_malformed_source_platform_hints_cannot_complete_ios_identity(tmp_path, archive, hints):
    target = source_target(
        tmp_path,
        {
            "Desktop/Info.plist": plistlib.dumps({"CFBundleIdentifier": "org.synthetic.desktop", **hints}),
            "Desktop/App.swift": SWIFT,
        },
        archive,
    )
    inventory, sources = inspect_target(target)
    assert inventory["apps"] == inventory["ios_config"] == []
    assert inventory["platforms"] == []
    assert inventory["partial"] and inventory["apple_source_scope"]["partial"]
    assert not inventory["apple_source_scope"]["app_identity_established"]
    assert privacy_coverage(inventory, sources)["state"] == "partial"
    assert any("Desktop/Info.plist" in warning for warning in inventory["warnings"])


@pytest.mark.parametrize("archive", [False, True])
@pytest.mark.parametrize("hints", [{"LSMinimumSystemVersion": ""}, {"CFBundleSupportedPlatforms": []}])
def test_empty_typed_source_hints_preserve_bundle_identifier_only_behavior(tmp_path, archive, hints):
    target = source_target(
        tmp_path,
        {
            "Mobile/Info.plist": plistlib.dumps({"CFBundleIdentifier": "org.synthetic.legacy", **hints}),
            "Mobile/App.swift": SWIFT,
        },
        archive,
    )
    inventory, sources = inspect_target(target)
    assert inventory["platforms"] == ["ios"]
    assert inventory["apps"][0]["package"] == "org.synthetic.legacy"
    assert inventory["apple_source_scope"]["partial"] is False
    assert privacy_coverage(inventory, sources)["state"] == "checked"


@pytest.mark.parametrize("archive", [False, True])
def test_null_source_platform_hint_is_an_invalid_plist_not_ios_evidence(tmp_path, archive):
    raw = (
        b'<?xml version="1.0"?><plist version="1.0"><dict>'
        b"<key>CFBundleIdentifier</key><string>org.synthetic.desktop</string>"
        b"<key>LSMinimumSystemVersion</key><null/></dict></plist>"
    )
    target = source_target(tmp_path, {"Desktop/Info.plist": raw, "Desktop/App.swift": SWIFT}, archive)
    inventory, _ = inspect_target(target)
    assert inventory["apps"] == inventory["ios_config"] == []
    assert inventory["partial"]


@pytest.mark.parametrize(
    "hints", [{"LSMinimumSystemVersion": 13}, {"CFBundleSupportedPlatforms": "iPhoneOS"}]
)
def test_source_only_hint_validation_preserves_packaged_ipa_behavior(tmp_path, hints):
    target = tmp_path / "mobile.ipa"
    with zipfile.ZipFile(target, "w") as output:
        output.writestr(
            "Payload/Mobile.app/Info.plist",
            plistlib.dumps({"CFBundleIdentifier": "org.synthetic.mobile", **hints}),
        )
    inventory, _ = inspect_target(target)
    assert inventory["platforms"] == ["ios"]
    assert inventory["apps"][0]["package"] == "org.synthetic.mobile"
