"""Swift extension member-type uncertainty; new synthetic source, no SDK/process/network.

Direct Handler.URL and Handler typealias URL must retain taint/partial coverage.
Foundation.URL qualification, a different extended owner and deeper unrelated
member scopes remain positive SDK controls. No extension SDK-member-shadowing
claim is made.
"""

import pytest

from mobile_audit.source_analysis import analyze_sources

APP = """import WebKit
class Handler {
 let web = WKWebView()
 func application(_ app: UIApplication, open incoming: Foundation.URL, options: [String: Any]) -> Bool {
  let parsed = {constructor}(string: incoming.absoluteString)!
  guard parsed.scheme == "https", parsed.host == "guide.example.test" else { return false }
  web.load(URLRequest(url: incoming))
  return true
 }
}
"""
FAKE = """struct {name} {
 let scheme: String? = "https"
 let host: String? = "guide.example.test"
 init?(string: String) {}
}
"""


def source(kind, layout, qualified=False, unrelated=False, deep=False):
    app = APP.replace("{constructor}", "Foundation.URL" if qualified else "URL")
    owner = "Other" if unrelated else "Handler"
    declaration = FAKE.replace("{name}", "URL") if kind == "nominal" else "typealias URL = FakeURL\n"
    if deep:
        declaration = "struct Inner {\n" + declaration + "}\n"
    extra = ("class Other {}\n" if unrelated else "") + (
        FAKE.replace("{name}", "FakeURL") if kind == "alias" else ""
    )
    extension = extra + "extension " + owner + " {\n" + declaration + "}\n"
    if layout == "same-before":
        return [("App.swift", extension + app)]
    if layout == "same-after":
        return [("App.swift", app + extension)]
    if layout == "split-before":
        return [("ZCaller.swift", app), ("AMembers.swift", "import WebKit\n" + extension)]
    return [("ACaller.swift", app), ("ZMembers.swift", "import WebKit\n" + extension)]


LAYOUTS = [
    ("same-before", False),
    ("same-after", False),
    ("split-before", False),
    ("split-before", True),
    ("split-after", False),
    ("split-after", True),
]
RULE = "AST-WEBVIEW-UNTRUSTED-URL"


@pytest.mark.parametrize("kind", ["nominal", "alias"])
@pytest.mark.parametrize("layout,reverse", LAYOUTS)
@pytest.mark.parametrize(
    "control", ["attack", "qualified-sdk", "unrelated-extension", "deep-unrelated-member"]
)
def test_extension_member_type_cannot_supply_sdk_url_safety(kind, layout, reverse, control):
    sources = source(
        kind,
        layout,
        qualified=control == "qualified-sdk",
        unrelated=control == "unrelated-extension",
        deep=control == "deep-unrelated-member",
    )
    if reverse:
        sources.reverse()
    report = analyze_sources(sources)
    assert report["metadata"]["function_inventory_complete"] is True
    assert all(
        item["parse_errors"] is False and item["native_parse_errors"] is False
        for item in report["metadata"]["files"]
    )
    matches = [item for item in report["findings"] if item["rule_id"] == RULE]
    states = [item["state"] for item in report["coverage"] if item["rule_id"] == RULE]
    assert states
    if control == "attack":
        assert matches, report
        assert all(item["status"] == "candidate" for item in matches)
        assert report["metadata"]["native_flow"]["state"] == "partial", report
        assert set(states) == {"partial"}, report
    else:
        assert not matches, report
        assert report["metadata"]["native_flow"]["state"] == "checked", report
        assert set(states) == {"checked"}, report


@pytest.mark.parametrize("extension", [False, True])
@pytest.mark.parametrize("qualified", [False, True])
def test_unguarded_source_still_reaches_the_same_webview_sink(extension, qualified):
    sources = (
        source("nominal", "same-after", qualified=qualified)
        if extension
        else [("App.swift", APP.replace("{constructor}", "Foundation.URL" if qualified else "URL"))]
    )
    sources = [
        (
            path,
            text.replace(
                '  guard parsed.scheme == "https", parsed.host == "guide.example.test" else { return false }\n',
                "",
            ),
        )
        for path, text in sources
    ]
    report = analyze_sources(sources)
    matches = [item for item in report["findings"] if item["rule_id"] == RULE]
    assert matches and all(item["status"] == "candidate" for item in matches), report


@pytest.mark.parametrize("kind", ["nominal", "alias"])
@pytest.mark.parametrize("target", ["module-alias", "qualified-member-alias"])
@pytest.mark.parametrize("layout", ["same-before", "split-after"])
def test_extension_target_alias_cannot_hide_member_type_uncertainty(kind, target, layout):
    sources = source(kind, layout)
    prefix, replacement = (
        ("typealias H = Handler\n", "extension H")
        if target == "module-alias"
        else ("class Holder { typealias H = Handler }\n", "extension Holder.H")
    )
    sources = [
        (
            path,
            prefix + text.replace("extension Handler", replacement) if "extension Handler" in text else text,
        )
        for path, text in sources
    ]
    report = analyze_sources(sources)
    assert all(
        item["parse_errors"] is False and item["native_parse_errors"] is False
        for item in report["metadata"]["files"]
    )
    matches = [item for item in report["findings"] if item["rule_id"] == RULE]
    assert matches and all(item["status"] == "candidate" for item in matches), report
    assert report["metadata"]["native_flow"]["state"] == "partial", report
    assert {item["state"] for item in report["coverage"] if item["rule_id"] == RULE} == {"partial"}, report


@pytest.mark.parametrize("kind", ["nominal", "alias"])
@pytest.mark.parametrize("limit", [0, 1])
def test_extension_type_inventory_exhaustion_cannot_report_checked(monkeypatch, kind, limit):
    from mobile_audit import native_flow

    monkeypatch.setattr(native_flow, "MAX_EXTENSION_TYPES", limit, raising=False)
    members = (
        "struct First {}\nstruct Second {}"
        if kind == "nominal"
        else "typealias First = String\ntypealias Second = String"
    )
    extra = "class Other {}\nextension Other {\n" + members + "\n}\n"
    sources = [("App.swift", APP.replace("{constructor}", "URL")), ("Members.swift", extra)]
    report = analyze_sources(sources)
    assert all(
        item["parse_errors"] is False and item["native_parse_errors"] is False
        for item in report["metadata"]["files"]
    )
    assert report["metadata"]["native_flow"]["state"] == "partial", report
    assert {item["state"] for item in report["coverage"] if item["rule_id"] == RULE} == {"partial"}, report
