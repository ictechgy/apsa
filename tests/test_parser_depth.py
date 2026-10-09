"""Byte-preserving grammar adaptations on newly written synthetic sources."""

from __future__ import annotations

import pytest

from mobile_audit.source_analysis import analyze_sources
from tests.test_next_hardening import OBJC

SWIFT = """import WebKit
@_documentation(visibility: private)
public struct Generated {}
class LinkHandler {
 let browser = WKWebView()
 let done = { () }
 func application(_ app: UIApplication, open incoming: URL, options: [String: Any]) {
  #warning("synthetic reminder")
  complete(.success(()))
  browser.load(URLRequest(url: incoming))
 }
 func complete(_ result: Result<Void, Error>) {}
}"""


def adaptations(report):
    return {a["kind"] for a in report["metadata"]["files"][0]["adaptations"]}


def test_swift_attributes_directives_and_empty_tuples_parse_with_original_offsets():
    report = analyze_sources([("App.swift", SWIFT)])
    metadata = report["metadata"]["files"][0]
    assert metadata["native_parse_errors"] and not metadata["parse_errors"]
    assert {
        "swift-documentation-attribute",
        "swift-diagnostic-directive",
        "swift-empty-tuple-argument",
    } <= adaptations(report)
    assert metadata["state"] == "partial"
    finding = next(f for f in report["findings"] if f["rule_id"] == "AST-WEBVIEW-UNTRUSTED-URL")
    assert finding["evidence"][0]["line"] == 10
    assert finding["evidence"][0]["offset"] == SWIFT.encode().index(b"browser.load")


@pytest.mark.parametrize(
    "text",
    [
        'let note = "@_documentation(visibility: private) ()"',
        '// #warning("comment") complete(.success(()))',
    ],
)
def test_swift_adaptations_ignore_strings_and_comments(text):
    report = analyze_sources([("App.swift", SWIFT.replace("let done = { () }", text))])
    assert report["metadata"]["files"][0]["native_parse_errors"]
    assert "AST-WEBVIEW-UNTRUSTED-URL" in {f["rule_id"] for f in report["findings"]}


OBJC_PARTS = OBJC.replace(
    "@implementation",
    "typedef NS_ENUM(NSInteger, SyntheticStyle) {\n  SyntheticStylePlain,\n};\n\n@implementation",
    1,
)


def test_objc_enum_macro_and_split_conditional_parse_without_new_identity():
    text = OBJC_PARTS.replace(
        "[webView loadRequest:request];",
        'NSString *title = NSLocalizedString(@"TITLE", comment: @"");\n'
        "    [webView loadRequest:request];\n"
        "#if TARGET_OS_IOS\n    if (title) {\n#else\n    if (!title) {\n#endif\n"
        "        title = nil;\n    }",
    )
    report = analyze_sources([("Handler.m", text)])
    metadata = report["metadata"]["files"][0]
    assert metadata["native_parse_errors"] and not metadata["parse_errors"]
    assert {
        "objc-enum-macro",
        "objc-localized-comment-label",
        "objc-preprocessor-first-branch",
    } <= adaptations(report)
    assert metadata["state"] == "partial"
    assert "OBJC-WEBVIEW-UNTRUSTED-REQUEST" in {f["rule_id"] for f in report["findings"]}


def test_objc_adapted_conditional_imports_never_establish_platform_identity():
    text = OBJC_PARTS.replace(
        "#import <WebKit/WebKit.h>", "#if TARGET_OS_IOS\n#import <WebKit/WebKit.h>\n#endif"
    )
    text = text.replace(
        "[webView loadRequest:request];",
        "#if 1\n    if (request) {\n#endif\n    [webView loadRequest:request];\n    }",
    )
    report = analyze_sources([("Handler.m", text)])
    assert report["metadata"]["files"][0]["native_parse_errors"]
    assert "OBJC-WEBVIEW-UNTRUSTED-REQUEST" not in {f["rule_id"] for f in report["findings"]}


def test_objc_dead_branch_is_not_the_kept_branch():
    text = OBJC_PARTS.replace(
        "[webView loadRequest:request];",
        "#if 0\n    if (request) {\n#else\n    if (!request) {\n#endif\n    [webView loadRequest:request];\n    }",
    )
    report = analyze_sources([("Handler.m", text)])
    assert not report["metadata"]["files"][0]["parse_errors"]
