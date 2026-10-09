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


def test_aab_feature_manifest_components_keep_module_and_delivery(tmp_path):
    import zipfile

    from mobile_audit.inputs import inspect_target
    from tests.test_next_hardening import attribute, bundle, field, xmlnode

    android = "http://schemas.android.com/apk/res/android"
    dist = "http://schemas.android.com/apk/distribution"
    true = field(7, field(8, 1))

    def element(name, *, namespace="", attrs=b"", children=()):
        body = (field(2, namespace) if namespace else b"") + field(3, name) + attrs
        return field(1, body + b"".join(field(5, child) for child in children))

    module = element(
        "module",
        namespace=dist,
        attrs=attribute("title", "@string/feature_title", namespace=dist),
        children=(element("delivery", namespace=dist, children=(element("on-demand", namespace=dist),)),),
    )
    view = xmlnode("action", attribute("name", "android.intent.action.VIEW", namespace=android))
    data = xmlnode(
        "data",
        attribute("scheme", "https", namespace=android)
        + attribute("host", "feature.example", namespace=android),
    )
    activity = xmlnode(
        "activity",
        attribute("name", "audit.synthetic.feature.Entry", namespace=android)
        + attribute("exported", namespace=android, compiled=true),
        children=(xmlnode("intent-filter", children=(view, data)),),
    )
    feature = xmlnode(
        "manifest",
        attribute("package", "audit.synthetic") + attribute("split", "feature"),
        children=(module, xmlnode("application", children=(activity,))),
    )
    path = bundle(tmp_path)
    with zipfile.ZipFile(path, "a") as archive:
        archive.writestr("checkout/manifest/AndroidManifest.xml", feature)
        archive.writestr("checkout/dex/classes.dex", b"")
    inventory, _ = inspect_target(path)
    assert inventory["package"] == "audit.synthetic"
    assert len(inventory["android_config"]) == 1
    entry = next(m for m in inventory["aab_feature_manifests"] if m["module"] == "checkout")
    assert entry["split"] == "feature" and entry["installation_state"] == "unknown"
    assert entry["delivery"] == "on-demand" and entry["title_resource"] == "@string/feature_title"
    assert entry["components"] == 1 and entry["deep_links"] == 1
    component = next(c for c in inventory["components"] if c.get("module") == "checkout")
    assert component["name"] == "audit.synthetic.feature.Entry" and component["exported"] == "true"
    assert component["module_delivery"] == "on-demand"
    link = next(d for d in inventory["deep_links"] if d.get("module") == "checkout")
    assert link["host"] == "feature.example"
    assert inventory["partial"]
