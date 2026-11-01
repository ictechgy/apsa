"""Property accessor bodies are analysis units; reading such a property stays unmodelled."""

from __future__ import annotations

import pytest

from mobile_audit.source_analysis import analyze_sources

URL_RULE = "AST-WEBVIEW-UNTRUSTED-URL"


def scan(*files: tuple[str, str]) -> dict:
    return analyze_sources(list(files))


def located(report: dict, rule: str = URL_RULE) -> set[tuple[int, str]]:
    return {
        (item["evidence"][0]["line"], item["evidence"][0]["function"])
        for item in report["findings"]
        if item["rule_id"] == rule
    }


ROUTER = """import UIKit
import WebKit
final class Router {
    let webView = WKWebView()
    var pending: URL?
    func application(_ app: UIApplication, open url: URL, options: [UIApplication.OpenURLOptionsKey: Any]) -> Bool {
        pending = url
        return true
    }
    PROPERTY
}
"""


@pytest.mark.parametrize(
    ("prop", "expected"),
    [
        (
            "var loadPending: Bool {\n        guard let target = pending else { return false }\n"
            "        webView.load(URLRequest(url: target))\n        return true\n    }",
            {(12, "loadPending")},
        ),
        (
            "var loadPending: Bool {\n        get {\n            guard let target = pending else { return false }\n"
            "            webView.load(URLRequest(url: target))\n            return true\n        }\n    }",
            {(13, "loadPending")},
        ),
        (
            "var shown = false {\n        willSet { print(newValue) }\n"
            "        didSet { if let target = pending { webView.load(URLRequest(url: target)) } }\n    }",
            {(12, "shown")},
        ),
        (
            'var loadHome: Bool {\n        webView.load(URLRequest(url: URL(string: "https://example.com")!))\n'
            "        return true\n    }",
            set(),
        ),
    ],
)
def test_swift_computed_and_observer_bodies_check_external_url_loads(prop, expected):
    report = scan(("App/Router.swift", ROUTER.replace("PROPERTY", prop)))
    assert located(report) == expected, report
    assert report["metadata"]["native_flow"]["state"] == "checked", report


def test_swift_setter_new_value_holds_what_the_property_was_assigned():
    source = """import UIKit
import WebKit
final class Router {
    let webView = WKWebView()
    var link: URL {
        get { URL(string: "https://example.com")! }
        set { webView.load(URLRequest(url: newValue)) }
    }
    func application(_ app: UIApplication, open url: URL, options: [UIApplication.OpenURLOptionsKey: Any]) -> Bool {
        link = url
        return true
    }
}
"""
    assert located(scan(("App/Router.swift", source))) == {(7, "link")}


SWIFT_BODY = """import SwiftUI
import WebKit
struct ContentView: View {
    let webView = WKWebView()
    var body: some View {
        get { Text("x").onOpenURL { url in webView.load(URLRequest(url: url)) } }
    }
}
"""


def test_swiftui_explicit_get_body_is_checked():
    assert located(scan(("App/ContentView.swift", SWIFT_BODY))) == {(6, "body")}


KOTLIN = """package app

import android.app.Activity
import android.webkit.WebView

class Screen : Activity() {
    lateinit var web: WebView
    var value: String = ""
    MEMBERS
    fun go() {
        ASSIGN
    }
}
"""


@pytest.mark.parametrize(
    ("members", "assign", "expected"),
    [
        (
            'val loaded: Boolean\n        get() { web.loadUrl(intent.getStringExtra("u")!!); return true }',
            "",
            {(10, "loaded")},
        ),
        (
            'var target: String = ""\n        set(value) {\n            field = value\n'
            "            web.loadUrl(value)\n        }",
            'target = intent.getStringExtra("u")!!',
            {(12, "target")},
        ),
        # The setter parameter shadows the tainted class field with the same name.
        (
            'var target: String = ""\n        set(value) { web.loadUrl(value) }',
            'value = intent.getStringExtra("u")!!',
            set(),
        ),
        ("val loaded: Boolean\n        get() = web.url != null", "", set()),
    ],
)
def test_kotlin_custom_accessor_bodies_check_sinks(members, assign, expected):
    report = scan(("app/Screen.kt", KOTLIN.replace("MEMBERS", members).replace("ASSIGN", assign)))
    assert located(report) == expected, report
    # A backing `field` and setter parameter are accessor locals, not unknown receiver fields.
    assert report["metadata"]["native_flow"]["state"] == "checked", report


COUNTS = {
    "App/Counts.swift": (
        """protocol P { var z: Int { get } }
final class C {
    var storage = [1]
    func a() {}
    var body: Int { 1 }
    var x: Int {
        get { return 1 }
        set(v) { print(v) }
    }
    var y: Int = 0 {
        willSet { print(newValue) }
        didSet { print(oldValue) }
    }
    var empty: Int = 0 { didSet {} }
    subscript(i: Int) -> Int { get { storage[i] } set { storage[i] = newValue } }
    static var shared: Int { 2 }
}
""",
        # a, body, x get/set, y willSet/didSet, shared. Requirements, empty observers and
        # subscripts (whose parameters are not modelled) are not analysis units.
        7,
    ),
    "app/Counts.kt": (
        """package app
class K {
    fun a() {}
    val x: Int get() = 1
    var y: Int = 0
        get() { return field }
        set(value) { field = value }
    var w: Int = 0
        private set
}
""",
        # a, x get, y get/set; a body-less `private set` is not a unit.
        4,
    ),
}


@pytest.mark.parametrize("path", COUNTS)
def test_accessor_units_are_counted_with_functions(path):
    text, expected = COUNTS[path]
    report = scan((path, text))
    assert report["metadata"]["functions"] == {
        "observed": expected,
        "analyzed": expected,
        "skipped": 0,
        "without_body": 0,
    }
    (metric,) = report["metadata"]["files"]
    assert metric["functions"]["observed"] == metric["native_functions"]["observed"] == expected
    assert (
        next(row for row in report["coverage"] if row["rule_id"] == URL_RULE)["functions_analyzed"]
        == expected
    )
    assert report["metadata"]["native_flow"]["state"] == "checked", report


def test_reading_a_computed_property_elsewhere_stays_abstained():
    source = """import UIKit
import WebKit
final class Router {
    let webView = WKWebView()
    var stored: URL?
    var current: URL { stored ?? URL(string: "https://example.com")! }
    func application(_ app: UIApplication, open url: URL, options: [UIApplication.OpenURLOptionsKey: Any]) -> Bool {
        stored = url
        webView.load(URLRequest(url: current))
        return true
    }
}
"""
    report = scan(("App/Router.swift", source))
    # No return summary is built for `current`: the read is an unavailable field.
    assert located(report) == {(9, "application")}, report
    assert "receiver field inventory unavailable" in report["metadata"]["native_flow"]["reasons"]


SWIFTUI_APP = {
    "App/ContentView.swift": """import SwiftUI
import WebKit

struct ContentView: View {
    @State private var name = ""
    @State private var showing = false
    let items: [String] = ["a", "b"]
    var body: some View {
        NavigationStack {
            VStack(alignment: .leading, spacing: 8) {
                Text("Hello, \\(name)")
                    .font(.title)
                    .padding()
                TextField("Name", text: $name)
                Button("Show") { showing.toggle() }
                ForEach(items, id: \\.self) { item in
                    Text(item)
                }
                if showing {
                    DetailView(title: name)
                }
            }
            .navigationTitle("Home")
            .onAppear { name = "x" }
            .sheet(isPresented: $showing) { DetailView(title: "Sheet") }
        }
    }
}
""",
    "App/DetailView.swift": """import SwiftUI

struct DetailView: View {
    let title: String
    @Environment(\\.dismiss) private var dismiss
    var greeting: String { "Hi " + title }
    var body: some View {
        VStack {
            Text(greeting)
            Image(systemName: "star")
                .resizable()
                .frame(width: 20, height: 20)
            Button(action: { dismiss() }) { Label("Close", systemImage: "xmark") }
        }
    }
}
""",
    "App/SettingsView.swift": """import SwiftUI

struct SettingsView: View {
    @AppStorage("flag") private var flag = false
    private var footer: some View {
        Text("Footer").foregroundStyle(.secondary)
    }
    var body: some View {
        Form {
            Section(header: Text("General"), footer: footer) {
                Toggle("Flag", isOn: $flag)
                    .onChange(of: flag) { _, newValue in print(newValue) }
            }
        }
    }
}
""",
    "App/MyApp.swift": """import SwiftUI

@main
struct MyApp: App {
    var body: some Scene {
        WindowGroup { ContentView() }
    }
}
""",
}


CONSTRUCTOR_REASON = "constructor field mapping unavailable"
SOURCE_VIEWS = {"ContentView", "DetailView"}


def framework_constructions(report):
    """Constructions recorded as unmodeled that are not the app's own views (SwiftUI credit)."""
    return {
        detail["call"]
        for detail in report["metadata"]["native_flow"]["partial_details"]
        if detail["reason"] == CONSTRUCTOR_REASON and detail["call"] not in SOURCE_VIEWS
    }


def test_ordinary_swiftui_views_credit_framework_views_and_keep_source_view_limits():
    # View-builder closures are followed (1.7.1). SwiftUI's own views are credited;
    # the app's memberwise view initializers, the dismiss environment action, a
    # computed property read and a @State write in a closure remain precision limits.
    report = scan(*SWIFTUI_APP.items())
    assert report["metadata"]["functions"]["analyzed"] == 6, report
    assert not report["findings"], report
    assert report["metadata"]["native_flow"]["budget_reasons"] == [], report
    assert report["metadata"]["native_flow"]["reasons"] == [
        "callable value binding unresolved",
        CONSTRUCTOR_REASON,
        "object storage alias unavailable",
        "receiver field inventory unavailable",
    ], report
    assert not framework_constructions(report), report


@pytest.mark.parametrize(
    "imports",
    [
        # A third-party or attributed import may supply View or a view type name.
        "import SwiftUI\nimport WebKit\nimport Kingfisher",
        "import SwiftUI\n@testable import WebKit",
        # RealityKit re-exports RealityFoundation.Scene.
        "import SwiftUI\nimport WebKit\nimport RealityKit",
    ],
)
def test_swiftui_credit_needs_an_apple_only_import_set(imports):
    files = {**SWIFTUI_APP}
    files["App/ContentView.swift"] = files["App/ContentView.swift"].replace(
        "import SwiftUI\nimport WebKit", imports
    )
    report = scan(*files.items())
    assert "VStack" in framework_constructions(report), report


@pytest.mark.parametrize(
    "shadow",
    [
        "typealias View = Int",
        "protocol Scene {}",
        "enum Wrapper {\n    typealias App = Int\n}",
        "extension View {\n    struct Text {}\n}",
        "extension View {\n    typealias Text = Int\n}",
        "extension SwiftUI.Scene {\n    typealias Group = Int\n}",
    ],
)
def test_source_swiftui_names_or_member_adding_extensions_withdraw_the_credit(shadow):
    report = scan(*SWIFTUI_APP.items(), ("App/Shadow.swift", "import SwiftUI\n" + shadow + "\n"))
    assert framework_constructions(report), report


def test_extension_adding_only_members_keeps_the_credit():
    extension = "import SwiftUI\nextension View {\n    var framed: some View { border(Color.gray) }\n}\n"
    report = scan(*SWIFTUI_APP.items(), ("App/Style.swift", extension))
    assert not framework_constructions(report), report
    assert report["metadata"]["native_flow"]["budget_reasons"] == [], report


def test_swift_shadows_leave_android_framework_credit_unchanged():
    android = """package app

import android.app.Activity
import android.content.Intent
import android.net.Uri
import android.webkit.WebView

class Screen : Activity() {
    fun open(webView: WebView, launch: Intent) {
        val uri = Uri.parse(launch.getStringExtra("url"))
        if (uri.scheme == "https" && uri.host == "example.com") webView.loadUrl(uri.toString())
    }
}
"""
    shadow = ("App/Shadow.swift", "import SwiftUI\nimport Kingfisher\ntypealias View = Int\n")
    for files in ([("app/Screen.kt", android)], [("app/Screen.kt", android), shadow]):
        report = scan(*files)
        assert not located(report), report
        assert "app/Screen.kt" not in {
            detail["path"] for detail in report["metadata"]["native_flow"]["partial_details"]
        }, report


@pytest.mark.parametrize(
    ("imports", "conformance", "extra"),
    [
        ("import SwiftUI", "View", None),
        ("import SwiftUI\nimport Foundation\nimport WebKit", "View", None),
        ("import SwiftUI", "SwiftUI.View", None),
        ("import protocol SwiftUI.View\nimport SwiftUI", "View", None),
        # Another module may supply View/VStack; an unlisted protocol may supply member types.
        ("import SwiftUI\nimport ComposableArchitecture", "View", "partial"),
        ("import SwiftUI\nimport RealityKit", "View", "partial"),
        ("import SwiftUI", "View, Identifiable", "partial"),
        ("import Foundation", "View", "partial"),
        # A source declaration of View in the module outranks SwiftUI's.
        ("import SwiftUI", "View", ("App/Shadow.swift", "protocol View {}\n")),
    ],
)
def test_swiftui_protocol_conformance_must_resolve_to_swiftui(imports, conformance, extra):
    view = f"""{imports}
struct ContentView: {conformance} {{
    var body: some View {{
        VStack {{ Text("x") }}
    }}
}}
"""
    files = [("App/ContentView.swift", view)]
    if isinstance(extra, tuple):
        files.append(extra)
    report = scan(*files)
    assert report["metadata"]["native_flow"]["state"] == ("checked" if extra is None else "partial"), report
