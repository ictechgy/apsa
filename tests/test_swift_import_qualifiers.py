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


@pytest.mark.parametrize("hashes", ["", "#", "##", "###"])
@pytest.mark.parametrize("multiline", [False, True])
def test_active_string_interpolation_is_opaque_before_any_inner_quote(hashes, multiline):
    quote = '"""' if multiline else '"'
    newline = "\n" if multiline else ""
    text = "let text = " + hashes + quote + newline
    text += "prefix \\" + hashes + '(String("; import AppKit"))'
    text += newline + quote + hashes + "; import UIKit"
    assert _swift_platform_code(text) is None


@pytest.mark.parametrize(
    "text",
    [
        r'let text = "prefix \\(literal)"; import UIKit',
        r'let text = #"prefix \##(literal)"#; import UIKit',
        r'let text = ##"prefix \#(literal)"##; import UIKit',
        r'let text = ###"prefix \##(literal)"###; import UIKit',
    ],
)
def test_escaped_or_mismatched_interpolation_markers_still_mask_literal_text(text):
    code = _swift_platform_code(text)
    assert code is not None and "import UIKit" in code
    assert "literal" not in code


@pytest.mark.parametrize(
    "prefix",
    [
        "try",
        "try?",
        "try!",
        "await",
        "if",
        "while",
        "switch",
        "guard",
        "in",
        "where",
        "copy",
        "consume",
        "borrow",
        "borrowing",
        "consuming",
        "yield",
        "return",
        "throw",
        "case",
        "for",
        "catch",
        "repeat",
        "as",
        "is",
        "some",
        "any",
        "each",
        "isolated",
        "sending",
        "async",
        "do",
        "else",
        "defer",
        "_futureContext",
        "futureContext",
    ],
)
@pytest.mark.parametrize("spacing", ["", " ", "\t"])
@pytest.mark.parametrize("trailing", [";", ")", "]", "}", "\n"])
def test_keyword_and_unresolved_contexts_never_expose_regex_imports(prefix, spacing, trailing):
    text = "let regex = " + prefix + spacing + "/foo; import AppKit/" + trailing
    code = _swift_platform_code(text)
    assert code is None or "import AppKit" not in code


@pytest.mark.parametrize(
    "text",
    [
        r'let text = "prefix \\\(String("; import AppKit"))"',
        "let regex = futureContext/[a/; import AppKit]+/;",
        "let regex = try" + " " * 257 + "/foo; import AppKit/;",
        "let regex = futureContext/" + "a" * 600 + "; import AppKit/;",
    ],
)
def test_nested_or_bounded_unknown_contexts_remain_opaque(text):
    assert _swift_platform_code(text) is None


@pytest.mark.parametrize(
    "code",
    [
        "let ratio = total/count; import UIKit",
        "let ratio = total / count\nimport UIKit",
        "var count = 10; count/=2; import UIKit",
    ],
)
def test_clear_division_controls_preserve_real_imports_after_keyword_guard(code):
    assert _swift_platform_code(code) == code


@pytest.mark.parametrize("archive", [False, True], ids=["folder", "source-zip"])
@pytest.mark.parametrize(
    "snippet",
    [
        r'let text = "a \(String("; import AppKit"))"',
        "let regex = try/foo; import AppKit/;",
        "let regex = await/foo; import AppKit/;",
    ],
)
def test_nested_interpolation_and_keyword_regex_keep_ios_privacy_candidates(tmp_path, archive, snippet):
    contents = {
        "Info.plist": plistlib.dumps({"CFBundleIdentifier": "org.synthetic.mobile"}),
        "Main.swift": (
            "import Foundation\n" + snippet + '\nUserDefaults.standard.set(true, forKey: "seen")\n'
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
    assert inventory["apple_source_scope"]["partial"] is True
    assert len([row for row in findings if row["rule_id"] == "IOS-PRIVACY-MANIFEST"]) == 1
    assert next(row["state"] for row in coverage if row["rule_id"] == "IOS-PRIVACY-MANIFEST") == "partial"
