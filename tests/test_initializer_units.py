"""Kotlin init blocks and secondary constructors and Swift init/deinit bodies are analysis units.

They are observed, analyzed and counted like methods, see the parameters they are
called with, and credit guards inside them. An initializer of a local or anonymous
class stays part of its enclosing function, whose locals it captures.
"""

from __future__ import annotations

import pytest

from mobile_audit.source_analysis import analyze_sources

UNTRUSTED = {"AST-WEBVIEW-UNTRUSTED-URL"}
KOTLIN = """package a
import android.content.Intent
import android.webkit.WebView
class Loader(intent: Intent, private val webView: WebView) {
    MEMBER
}
"""
KOTLIN_BODY = "val u = intent.data!!\n        GUARDwebView.loadUrl(u.toString())"
KOTLIN_GUARD = 'if (u.scheme == "https" && u.host == "example.com") { } else { return }\n        '
SECONDARY = KOTLIN.replace("class Loader(intent: Intent, private val webView: WebView)", "class Loader")
SWIFT = """import class UIKit.UIOpenURLContext
import class WebKit.WKWebView
import class WebKit.WKNavigationAction
import struct Foundation.URLRequest
class Links {
    let webView: WKWebView
    MEMBER
}
"""
SWIFT_BODY = "self.webView = webView\n        let url = action.request.url!\n        GUARDwebView.load(URLRequest(url: url))"
SWIFT_GUARD = 'guard url.scheme == "https", url.host == "example.com" else { return }\n        '


def analyze(path: str, source: str) -> tuple[set[str], str, dict]:
    report = analyze_sources([(path, source)])
    rules = {item["rule_id"] for item in report["findings"]}
    return rules, report["metadata"]["native_flow"]["state"], report["metadata"]["functions"]


def unit(member: str, body: str, guard: str) -> str:
    return member + " {\n        " + body.replace("GUARD", guard) + "\n    }"


CASES = [
    ("kotlin-init", "app/Loader.kt", KOTLIN, "init", KOTLIN_BODY, KOTLIN_GUARD),
    (
        "kotlin-secondary-constructor",
        "app/Loader.kt",
        SECONDARY,
        "constructor(intent: Intent, webView: WebView)",
        KOTLIN_BODY,
        KOTLIN_GUARD,
    ),
    (
        "swift-init",
        "App/Links.swift",
        SWIFT,
        "init(action: WKNavigationAction, webView: WKWebView)",
        SWIFT_BODY,
        SWIFT_GUARD,
    ),
]


@pytest.mark.parametrize(
    ("path", "template", "member", "body", "guard"),
    [case[1:] for case in CASES],
    ids=[case[0] for case in CASES],
)
@pytest.mark.parametrize("guarded", [False, True], ids=["unguarded", "guarded"])
def test_initializer_body_is_an_analysis_unit(path, template, member, body, guard, guarded):
    source = template.replace("MEMBER", unit(member, body, guard if guarded else ""))
    rules, state, functions = analyze(path, source)
    assert rules == (set() if guarded else UNTRUSTED)
    assert state == "checked"
    assert functions == {"observed": 1, "analyzed": 1, "skipped": 0, "without_body": 0}


ACTIVITY_INIT = """package com.example.app
import android.app.Activity
import android.webkit.WebView
class MainActivity(webView: WebView) : Activity() {
    init {
        webView.loadUrl(intent.data.toString())
    }
}
"""
SCENE_INIT = """import WebKit
class C {
    init(contexts URLContexts: Set<UIOpenURLContext>) {
        let wv = WKWebView()
        wv.load(URLRequest(url: URLContexts.first!.url))
    }
}
"""


@pytest.mark.parametrize(
    ("path", "source"),
    [("app/src/main/java/A.kt", ACTIVITY_INIT), ("App/C.swift", SCENE_INIT)],
    ids=["kotlin-activity-init", "swift-url-context-init"],
)
def test_untrusted_load_in_initializer_is_reported(path, source):
    report = analyze_sources([(path, source)])
    assert UNTRUSTED <= {item["rule_id"] for item in report["findings"]}
    assert report["metadata"]["functions"]["analyzed"] == 1
    assert report["metadata"]["function_inventory_complete"] is True


def test_swift_deinit_and_bodiless_secondary_constructor_are_counted():
    deinit = SWIFT.replace("MEMBER", "init(webView: WKWebView) { self.webView = webView }\n    deinit { }")
    assert analyze("App/Links.swift", deinit)[2] == {
        "observed": 2,
        "analyzed": 2,
        "skipped": 0,
        "without_body": 0,
    }
    delegating = KOTLIN.replace("MEMBER", "constructor(webView: WebView) : this(Intent(), webView)")
    counts = analyze("app/Loader.kt", delegating)[2]
    assert counts["observed"] == 1 and counts["analyzed"] == 0


NESTED = [
    (
        "kotlin-anonymous-object-init",
        "app/Host.kt",
        """package a
import android.content.Intent
import android.webkit.WebView
class Host {
    fun go(intent: Intent, web: WebView) {
        val u = intent.data
        val r = object : Runnable {
            init { web.loadUrl(u.toString()) }
            override fun run() { }
        }
        r.run()
    }
}
""",
        2,
    ),
]


@pytest.mark.parametrize(
    ("path", "source", "observed"), [case[1:] for case in NESTED], ids=[case[0] for case in NESTED]
)
def test_nested_initializer_stays_part_of_its_function(path, source, observed):
    rules, _, functions = analyze(path, source)
    assert rules == UNTRUSTED
    assert functions["observed"] == observed
