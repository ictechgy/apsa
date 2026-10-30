"""Fresh synthetic source-platform evidence; no app builds or live app data."""

from __future__ import annotations

import plistlib
import zipfile
from pathlib import Path

import pytest

from mobile_audit.inputs import inspect_target
from mobile_audit.source_analysis import analyze_sources


def source_target(tmp_path: Path, files: dict[str, str | bytes], *, archive: bool = False) -> Path:
    if archive:
        target = tmp_path / "sources.zip"
        with zipfile.ZipFile(target, "w") as output:
            for name, content in files.items():
                output.writestr(name, content)
        return target
    target = tmp_path / "sources"
    target.mkdir()
    for name, content in files.items():
        member = target / name
        member.parent.mkdir(parents=True, exist_ok=True)
        member.write_bytes(content.encode() if isinstance(content, str) else content)
    return target


def file_scope(inventory: dict) -> dict[str, dict]:
    return {item["path"]: item for item in inventory["apple_source_scope"]["files"]}


@pytest.mark.parametrize("archive", [False, True], ids=["folder", "source-zip"])
def test_macos_swiftpm_scope_covers_foundation_without_inventing_ios_app(tmp_path, archive):
    target = source_target(
        tmp_path,
        {
            "Desktop/Package.swift": 'import PackageDescription\nlet package = Package(name: "Desktop", platforms: [.macOS(.v14)])',
            "Desktop/Sources/Main.swift": 'import AppKit\nUserDefaults.standard.set(true, forKey: "seen")',
            "Desktop/Sources/Shared.swift": "import Foundation\nlet uptime = ProcessInfo.processInfo.systemUptime",
        },
        archive=archive,
    )
    inventory, sources = inspect_target(target)
    assert inventory["platforms"] == ["macos"]
    assert inventory["apps"] == [] and inventory["ios_config"] == []
    assert inventory["partial"] is True
    assert inventory["apple_source_scope"]["app_identity_established"] is False
    assert file_scope(inventory)["Desktop/Sources/Shared.swift"]["platforms"] == ["macos"]
    assert len(sources) == 3


@pytest.mark.parametrize("framework", ["AppKit", "Cocoa", "Carbon"])
def test_macos_import_hints_do_not_apply_ios_privacy_by_swift_extension(tmp_path, framework):
    inventory, _ = inspect_target(
        source_target(tmp_path, {"Main.swift": f"import {framework}\nimport Foundation"})
    )
    assert inventory["platforms"] == ["macos"]
    assert inventory["apps"] == []


@pytest.mark.parametrize("framework", ["Foundation", "SwiftUI", "Darwin"])
@pytest.mark.parametrize("archive", [False, True], ids=["folder", "source-zip"])
def test_ambiguous_swift_is_partial_without_ios_app_identity(tmp_path, framework, archive):
    inventory, sources = inspect_target(
        source_target(tmp_path, {"Shared.swift": f"import {framework}\nlet value = 1"}, archive=archive)
    )
    assert inventory["platforms"] == [] and inventory["apps"] == []
    assert inventory["partial"] is True
    assert file_scope(inventory)["Shared.swift"]["state"] == "unknown"
    assert inventory["apple_source_scope"]["unresolved_files"] == 1
    assert sources[0][0] == "Shared.swift"


def test_uikit_is_positive_mobile_source_evidence_without_app_identity(tmp_path):
    inventory, _ = inspect_target(
        source_target(tmp_path, {"Main.swift": "@preconcurrency import UIKit\nlet view = UIView()"})
    )
    assert inventory["platforms"] == ["ios"] and inventory["apps"] == []
    assert inventory["apple_source_scope"]["app_identity_established"] is False
    assert file_scope(inventory)["Main.swift"]["platforms"] == ["ios"]


def test_package_manifest_alone_does_not_establish_mobile_platform_or_complete_scope(tmp_path):
    inventory, _ = inspect_target(
        source_target(
            tmp_path, {"Package.swift": 'import PackageDescription\nlet package = Package(name: "Shared")'}
        )
    )
    assert inventory["platforms"] == [] and inventory["apps"] == []
    assert inventory["partial"] is True
    assert inventory["apple_source_scope"]["partial"] is True


def test_explicit_ios_configuration_survives_desktop_source_evidence(tmp_path):
    inventory, _ = inspect_target(
        source_target(
            tmp_path,
            {
                "Mobile/Info.plist": plistlib.dumps(
                    {"CFBundleIdentifier": "example.mobile", "MinimumOSVersion": "16.0"}
                ),
                "Desktop/Main.swift": "import AppKit",
            },
        )
    )
    assert inventory["platforms"] == ["ios", "macos"]
    assert inventory["apps"][0]["package"] == "example.mobile"
    assert inventory["apple_source_scope"]["app_identity_established"] is True
    assert inventory["ios_config"][0]["path"] == "Mobile/Info.plist"


def test_appkit_module_never_suppresses_independent_mobile_or_ambiguous_modules(tmp_path):
    inventory, _ = inspect_target(
        source_target(
            tmp_path,
            {
                "Desktop/Main.swift": "import AppKit",
                "Mobile/Main.swift": "import UIKit",
                "Shared/Model.swift": "import Foundation",
            },
        )
    )
    paths = file_scope(inventory)
    assert inventory["platforms"] == ["ios", "macos"]
    assert paths["Desktop/Main.swift"]["platforms"] == ["macos"]
    assert paths["Mobile/Main.swift"]["platforms"] == ["ios"]
    assert paths["Shared/Model.swift"]["platforms"] == []


def test_conditional_imports_retain_possible_platforms_and_partial_scope(tmp_path):
    inventory, _ = inspect_target(
        source_target(
            tmp_path,
            {"Shared.swift": "#if canImport(UIKit)\nimport UIKit\n#else\nimport AppKit\n#endif"},
        )
    )
    assert inventory["platforms"] == ["ios", "macos"]
    assert inventory["apple_source_scope"]["conditional_files"] == 1
    assert file_scope(inventory)["Shared.swift"]["state"] == "conditional"
    assert inventory["partial"] is True and inventory["apps"] == []


def test_same_line_imports_keep_both_platform_hints(tmp_path):
    inventory, _ = inspect_target(source_target(tmp_path, {"Shared.swift": "import AppKit; import UIKit"}))
    assert inventory["platforms"] == ["ios", "macos"]


def test_nested_swiftpm_package_has_independent_platform_scope(tmp_path):
    inventory, _ = inspect_target(
        source_target(
            tmp_path,
            {
                "Package.swift": 'import PackageDescription\nlet package = Package(name: "Desktop", platforms: [.macOS(.v14)])',
                "Sources/Desktop.swift": "import Foundation",
                "Mobile/Package.swift": 'import PackageDescription\nlet package = Package(name: "Mobile", platforms: [.iOS(.v16)])',
                "Mobile/Sources/Main.swift": "import Foundation",
            },
        )
    )
    paths = file_scope(inventory)
    assert paths["Sources/Desktop.swift"]["platforms"] == ["macos"]
    assert paths["Mobile/Sources/Main.swift"]["platforms"] == ["ios"]
    assert inventory["platforms"] == ["ios", "macos"]


@pytest.mark.parametrize(
    "source",
    [
        "// import AppKit\nimport Foundation",
        'let message = "import AppKit"\nimport Foundation',
        'let message = """\nimport AppKit\n"""\nimport Foundation',
        'let message = ##"\nimport AppKit\n"##\nimport Foundation',
        'let message = #"""\nimport AppKit\n"""#\nimport Foundation',
        "/* outer /* nested */\nimport AppKit\n*/\nimport Foundation",
        "let expression = #/\nimport AppKit\n/#\nimport Foundation",
        "/* unterminated\nimport AppKit",
        'let message = "unterminated\nimport AppKit',
    ],
)
def test_literals_comments_and_unterminated_regions_are_not_platform_evidence(tmp_path, source):
    inventory, _ = inspect_target(source_target(tmp_path, {"Shared.swift": source}))
    assert inventory["platforms"] == []
    assert inventory["apple_source_scope"]["unresolved_files"] == 1


@pytest.mark.parametrize(
    "declaration",
    [
        'let text = "platforms: [.macOS(.v14)]"\nlet package = Package(name: "Shared")',
        'let package = Package(name: "Shared", /* platforms: [.macOS(.v14)] */ targets: [])',
        'let package = Package(name: "Shared", platforms: supportedPlatforms)',
        'let package = Package(name: "Shared", unrelated_platforms: [.macOS(.v14)])',
        '#if os(macOS)\nlet package = Package(name: "Shared", platforms: [.macOS(.v14)])\n#endif',
    ],
)
def test_swiftpm_requires_a_literal_unconditional_platforms_argument(tmp_path, declaration):
    inventory, _ = inspect_target(
        source_target(tmp_path, {"Package.swift": declaration, "Sources/Shared.swift": "import Foundation"})
    )
    assert inventory["platforms"] == []


@pytest.mark.parametrize("extension", ["apk", "ipa"])
def test_source_zip_exception_never_admits_manifestless_mobile_packages(tmp_path, extension):
    target = tmp_path / f"unidentified.{extension}"
    with zipfile.ZipFile(target, "w") as output:
        output.writestr("Main.swift", "import UIKit")
    with pytest.raises(ValueError, match="no (?:readable Android manifest or )?main iOS Info.plist"):
        inspect_target(target)


def test_app_bundle_zip_still_requires_main_plist(tmp_path):
    target = source_target(tmp_path, {"Desktop.app/Main.swift": "import AppKit"}, archive=True)
    with pytest.raises(ValueError, match="no readable Android manifest or main iOS Info.plist"):
        inspect_target(target)


@pytest.mark.parametrize("extension", ["apk", "ipa"])
def test_packaged_mobile_platforms_are_unchanged_by_embedded_swift_text(tmp_path, extension):
    target = tmp_path / f"app.{extension}"
    with zipfile.ZipFile(target, "w") as output:
        if extension == "apk":
            output.writestr(
                "AndroidManifest.xml", '<manifest package="example.android"><application/></manifest>'
            )
            output.writestr("Main.swift", "import AppKit")
        else:
            output.writestr(
                "Payload/Mobile.app/Info.plist", plistlib.dumps({"CFBundleIdentifier": "example.ios"})
            )
            output.writestr("Payload/Mobile.app/Main.swift", "import AppKit")
    inventory, _ = inspect_target(target)
    assert inventory["platforms"] == ["android" if extension == "apk" else "ios"]
    assert "apple_source_scope" not in inventory


def test_platform_scope_does_not_remove_swift_from_ast_security_analysis(tmp_path):
    source = """import AppKit
import CryptoKit
func digest(_ runtime: Data) {
    let digest = Insecure.MD5.hash(data: runtime)
}
"""
    inventory, sources = inspect_target(source_target(tmp_path, {"Desktop.swift": source}))
    analyzed = analyze_sources(sources)
    assert inventory["platforms"] == ["macos"]
    assert any(item["rule_id"] == "AST-CRYPTO-WEAK-HASH" for item in analyzed["findings"])
