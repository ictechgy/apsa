"""Qualified Swift imports provide lexical hints, without inventing app identity."""

import pytest

from mobile_audit.inputs import inspect_target


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
