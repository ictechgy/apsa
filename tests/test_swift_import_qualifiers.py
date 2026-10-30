"""Qualified Swift imports provide lexical hints, without inventing app identity."""

import plistlib
import zipfile

import pytest

from mobile_audit import platform_checks
from mobile_audit.inputs import _swift_platform_code, inspect_target


@pytest.mark.parametrize(
    "declaration,platform",
    [
        ("public import UIKit", "ios"),
        ("package import UIKit", "ios"),
        ("internal import UIKit", "ios"),
        ("fileprivate import UIKit", "ios"),
        ("private import UIKit", "ios"),
        ("@_exported import UIKit", "ios"),
        ("@_spi(Testing) import UIKit", "ios"),
        ("@_spi(Testing) public import UIKit", "ios"),
        ("@preconcurrency @_spi(Testing) public import class UIKit.UIView", "ios"),
        ("@_exported import AppKit", "macos"),
        ("internal import struct AppKit.NSRect", "macos"),
    ],
)
def test_qualified_framework_import_is_observed_without_app_identity(tmp_path, declaration, platform):
    (tmp_path / "Main.swift").write_text(declaration)
    inventory, _ = inspect_target(tmp_path)
    assert inventory["platforms"] == [platform]
    assert inventory["apps"] == []
    entry = inventory["apple_source_scope"]["files"][0]
    assert entry["state"] == "observed"
    assert entry["platform_basis"] == "direct-framework-import"


@pytest.mark.parametrize(
    "source",
    [
        "// public import UIKit\nimport Foundation",
        'let text = "@_exported import UIKit"\nimport Foundation',
        "@_spi(UIKit) import Foundation",
        "arbitrary public import UIKit",
    ],
)
def test_import_like_text_and_attribute_arguments_do_not_establish_platform(tmp_path, source):
    (tmp_path / "Main.swift").write_text(source)
    inventory, _ = inspect_target(tmp_path)
    assert inventory["platforms"] == []
    assert inventory["apple_source_scope"]["files"][0]["state"] == "unknown"
    assert inventory["partial"] is True


def test_qualified_imports_keep_conditional_uncertainty(tmp_path):
    (tmp_path / "Main.swift").write_text(
        "#if os(iOS)\npublic import UIKit\n#else\n@_spi(Testing) internal import AppKit\n#endif"
    )
    inventory, _ = inspect_target(tmp_path)
    assert inventory["platforms"] == ["ios", "macos"]
    assert inventory["apple_source_scope"]["files"][0]["state"] == "conditional"
    assert inventory["partial"] is True


@pytest.mark.parametrize(
    "expression",
    [
        r"let regex = /foo; import AppKit/",
        r"let regex = /foo\/; import AppKit/",
        r"let regex = /[a/; import AppKit]+/",
        r'let regex = /"; import AppKit"/',
        r"let regex = /((foo); import AppKit)/",
        r"return /foo; import AppKit/",
        r"consume(/foo; import AppKit/)",
    ],
)
def test_bare_regex_contents_are_masked_before_import_hints(tmp_path, expression):
    code = expression + "; import UIKit\n"
    masked = _swift_platform_code(code)
    assert masked is not None and "import AppKit" not in masked
    assert masked.count("\n") == code.count("\n")
    (tmp_path / "Main.swift").write_text(code)
    inventory, _ = inspect_target(tmp_path)
    assert inventory["platforms"] == ["ios"]
    assert inventory["apple_source_scope"]["files"][0]["platform_basis"] == "direct-framework-import"


def test_real_import_on_next_line_survives_regex_masking(tmp_path):
    (tmp_path / "Main.swift").write_text("let regex = /foo; import UIKit/\nimport AppKit\n")
    inventory, _ = inspect_target(tmp_path)
    assert inventory["platforms"] == ["macos"]
    assert inventory["apple_source_scope"]["files"][0]["state"] == "observed"


@pytest.mark.parametrize(
    "expression",
    [
        "let ratio = total / count",
        "let ratio = total/count",
        "let ratio = 1 / 2 / 3",
        "let ratio = (total)/count",
        "var count = 10\ncount /= 2",
        "var count = 10\ncount/=2",
    ],
)
def test_clear_division_and_assignment_operators_preserve_actual_imports(tmp_path, expression):
    code = expression + "\nimport UIKit\n"
    assert _swift_platform_code(code) == code
    (tmp_path / "Main.swift").write_text(code)
    inventory, _ = inspect_target(tmp_path)
    assert inventory["platforms"] == ["ios"]
    assert inventory["apple_source_scope"]["files"][0]["state"] == "observed"


@pytest.mark.parametrize(
    "expression",
    [
        "let regex = /foo\nimport AppKit/",
        "let regex = /foo; import AppKit",
        "let regex = /foo; import AppKit /",
        r"let regex = /\Qfoo/; import AppKit\E/",
        r"let regex = /(?x)foo; import AppKit/",
        r"let regex = /[]/; import AppKit]/",
        "let ratio = value /foo; import AppKit/",
        "consume(^/foo; import AppKit/)",
    ],
)
def test_unresolved_slash_syntax_is_opaque_and_partial(tmp_path, expression):
    assert _swift_platform_code(expression) is None
    (tmp_path / "Main.swift").write_text(expression)
    inventory, _ = inspect_target(tmp_path)
    assert inventory["platforms"] == []
    scope = inventory["apple_source_scope"]
    assert scope["files"][0]["state"] == "conditional"
    assert scope["files"][0]["platforms"] == []
    assert scope["partial"] is True


@pytest.mark.parametrize("archive", [False, True], ids=["folder", "source-zip"])
@pytest.mark.parametrize("ambiguous", [False, True], ids=["bare-regex", "opaque-regex"])
def test_regex_import_text_cannot_hide_ios_privacy_candidates(tmp_path, archive, ambiguous):
    regex = "/foo\nimport AppKit/" if ambiguous else "/foo; import AppKit/"
    contents = {
        "Info.plist": plistlib.dumps({"CFBundleIdentifier": "org.synthetic.mobile"}),
        "Main.swift": (
            "import Foundation\nlet regex = " + regex + '\nUserDefaults.standard.set(true, forKey: "seen")\n'
        ).encode(),
    }
    if archive:
        target = tmp_path / "source.zip"
        with zipfile.ZipFile(target, "x") as output:
            for name, raw in contents.items():
                output.writestr(name, raw)
    else:
        target = tmp_path / "source"
        target.mkdir()
        for name, raw in contents.items():
            (target / name).write_bytes(raw)
    inventory, sources = inspect_target(target)
    findings, coverage = platform_checks.platform_checks(inventory, sources)
    assert inventory["platforms"] == ["ios"]
    assert len([row for row in findings if row["rule_id"] == "IOS-PRIVACY-MANIFEST"]) == 1
    state = next(row["state"] for row in coverage if row["rule_id"] == "IOS-PRIVACY-MANIFEST")
    assert state == ("partial" if ambiguous else "checked")
