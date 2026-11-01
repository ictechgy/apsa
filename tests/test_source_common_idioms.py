"""Ordinary Kotlin/Java/Swift idioms that must behave like their explicit forms."""

from __future__ import annotations

import pytest

from mobile_audit.source_analysis import analyze_sources

KOTLIN_ACTIVITY = """package a
import android.app.Activity
import android.webkit.WebView
import android.database.sqlite.SQLiteDatabase
import java.io.File
import javax.crypto.spec.SecretKeySpec
class A : Activity() {
    fun go(webView: WebView, db: SQLiteDatabase, runtimeSecret: String) {
        val q = intent.getStringExtra("q")
        STATEMENT
    }
}
"""


def rules(path: str, text: str, ignore: frozenset[str] = frozenset()) -> set[str]:
    return {item["rule_id"] for item in analyze_sources([(path, text)])["findings"]} - ignore


@pytest.mark.parametrize(
    ("statement", "expected"),
    [
        ('webView.loadUrl("https://example.com/s?q=$q")', {"AST-WEBVIEW-UNTRUSTED-URL"}),
        ('webView.loadUrl("https://example.com/s?q=${q}")', {"AST-WEBVIEW-UNTRUSTED-URL"}),
        ('db.execSQL("DELETE FROM t WHERE id=$q")', {"AST-SQL-CONCAT"}),
        ('File(filesDir, "uploads/$q").writeText("x")', {"AST-PATH-TRAVERSAL"}),
        ('webView.loadUrl("https://example.com/s?q=1")', set()),
        ('webView.loadUrl("https://example.com/s?q=\\$q")', set()),
        ('db.execSQL("DELETE FROM t WHERE id=1")', set()),
        ('SecretKeySpec("$runtimeSecret".toByteArray(), "AES")', set()),
        ('SecretKeySpec("0123456789abcdef".toByteArray(), "AES")', {"AST-CRYPTO-HARDCODED-KEY"}),
    ],
)
def test_kotlin_simple_string_templates_carry_values(statement, expected):
    assert rules("a/A.kt", KOTLIN_ACTIVITY.replace("STATEMENT", statement)) == expected


JAVA_CONSTANTS = """package a;
import javax.crypto.Cipher;
import java.security.MessageDigest;
class C {
    private static final String TRANSFORMATION = "AES/ECB/PKCS5Padding";
    private static final String CIPHER = "DES";
    private static final String DIGEST = "MD5";
    private static final String SAFE = "AES/GCM/NoPadding";
    private String mutable = "AES/ECB/PKCS5Padding";
    void f() throws Exception { CALL }
}
"""
KOTLIN_CONSTANTS = """package a
import javax.crypto.Cipher
import java.security.MessageDigest
class K {
    private val transformation = "AES/ECB/PKCS5Padding"
    private val digest = "MD5"
    fun f(parameter: String) { CALL }
}
"""
KEY = frozenset({"AST-CRYPTO-HARDCODED-KEY"})


@pytest.mark.parametrize(
    ("path", "source", "call", "expected"),
    [
        ("a/C.java", JAVA_CONSTANTS, "Cipher.getInstance(TRANSFORMATION);", {"AST-CRYPTO-ECB"}),
        ("a/C.java", JAVA_CONSTANTS, "Cipher.getInstance(CIPHER);", {"AST-CRYPTO-WEAK-CIPHER"}),
        ("a/C.java", JAVA_CONSTANTS, "MessageDigest.getInstance(DIGEST);", {"AST-CRYPTO-WEAK-HASH"}),
        ("a/C.java", JAVA_CONSTANTS, "Cipher.getInstance(SAFE);", set()),
        (
            "a/C.java",
            JAVA_CONSTANTS,
            "String TRANSFORMATION = load(); Cipher.getInstance(TRANSFORMATION);",
            set(),
        ),
        ("a/C.java", JAVA_CONSTANTS, "mutable = load(); Cipher.getInstance(mutable);", set()),
        ("a/K.kt", KOTLIN_CONSTANTS, "Cipher.getInstance(transformation)", {"AST-CRYPTO-ECB"}),
        ("a/K.kt", KOTLIN_CONSTANTS, "MessageDigest.getInstance(digest)", {"AST-CRYPTO-WEAK-HASH"}),
        ("a/K.kt", KOTLIN_CONSTANTS, "val digest = parameter; MessageDigest.getInstance(digest)", set()),
    ],
)
def test_same_class_algorithm_constants_are_resolved(path, source, call, expected):
    assert rules(path, source.replace("CALL", call), KEY) == expected


SWIFT_SCENE = """import UIKit
import WebKit
class Scene: UIResponder, UIWindowSceneDelegate {
    let webView = WKWebView()
    func scene(_ scene: UIScene, openURLContexts URLContexts: Set<UIOpenURLContext>) {
        BODY
    }
}
"""
SWIFT_ACTIVITY = """import UIKit
import WebKit
class Links: UIResponder, UIApplicationDelegate {
    let webView = WKWebView()
    func application(_ application: UIApplication, continue userActivity: NSUserActivity,
                     restorationHandler: @escaping ([UIUserActivityRestoring]?) -> Void) -> Bool {
        BODY
        return true
    }
}
"""
UNTRUSTED = {"AST-WEBVIEW-UNTRUSTED-URL"}


@pytest.mark.parametrize(
    ("template", "body", "expected"),
    [
        (SWIFT_SCENE, "let url = URLContexts.first!.url\nwebView.load(URLRequest(url: url))", UNTRUSTED),
        (
            SWIFT_SCENE,
            "guard let url = URLContexts.first?.url else { return }\nwebView.load(URLRequest(url: url))",
            UNTRUSTED,
        ),
        (
            SWIFT_SCENE,
            "if let url = URLContexts.first?.url { webView.load(URLRequest(url: url)) }",
            UNTRUSTED,
        ),
        # Sinks inside an optional-binding body or its else arm are analyzed at all.
        (
            SWIFT_SCENE,
            "let raw = URLContexts.first!.url\nif let ok = Optional(true) { webView.load(URLRequest(url: raw)) }",
            UNTRUSTED,
        ),
        (
            SWIFT_SCENE,
            "let raw = URLContexts.first!.url\nif let ok = Optional(1) { print(ok) } else { webView.load(URLRequest(url: raw)) }",
            UNTRUSTED,
        ),
        (
            SWIFT_SCENE,
            'if let url = URL(string: "https://example.com/help") { webView.load(URLRequest(url: url)) }',
            set(),
        ),
        (SWIFT_ACTIVITY, "let url = userActivity.webpageURL!\nwebView.load(URLRequest(url: url))", UNTRUSTED),
        (
            SWIFT_ACTIVITY,
            "guard let url = userActivity.webpageURL else { return false }\nwebView.load(URLRequest(url: url))",
            UNTRUSTED,
        ),
        (SWIFT_ACTIVITY, 'webView.load(URLRequest(url: URL(string: "https://example.com")!))', set()),
    ],
)
def test_swift_optional_bindings_and_link_sources(template, body, expected):
    assert rules("App/Links.swift", template.replace("BODY", body.replace("\n", "\n        "))) == expected


JAVA_TLS = """package a;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.X509ExtendedTrustManager;
import okhttp3.OkHttpClient;
class Net {
    OkHttpClient lambda() {
        return new OkHttpClient.Builder().hostnameVerifier((hostname, session) -> true).build();
    }
    void defaults() {
        HttpsURLConnection.setDefaultHostnameVerifier((h, s) -> { return true; });
    }
    HostnameVerifier field = (h, s) -> true;
    OkHttpClient pinned() {
        return new OkHttpClient.Builder().hostnameVerifier((h, s) -> h.equals("api.example.com")).build();
    }
}
"""
JAVA_EXTENDED_TRUST = """package a;
import java.net.Socket;
import java.security.cert.X509Certificate;
import javax.net.ssl.X509ExtendedTrustManager;
class Trusting extends X509ExtendedTrustManager {
    public void checkServerTrusted(X509Certificate[] chain, String authType) {}
}
"""


def test_java_lambda_hostname_verifiers_and_extended_trust_managers(store, tmp_path, monkeypatch):
    from mobile_audit.audit import scan

    monkeypatch.setenv("APSA_PARSER_SANDBOX", "off")
    root = tmp_path / "tls"
    root.mkdir()
    (root / "Net.java").write_text(JAVA_TLS)
    (root / "Trusting.java").write_text(JAVA_EXTENDED_TRUST)
    report = scan(store, root)
    lines = {
        rule: sorted(
            (item["evidence"][0]["path"], item["evidence"][0].get("line"))
            for item in report["findings"]
            if item["rule_id"] == rule
        )
        for rule in ("SOURCE-HOSTNAME-VERIFIER-ALL", "SOURCE-TRUST-ALL-CERTS")
    }
    assert lines == {
        "SOURCE-HOSTNAME-VERIFIER-ALL": [("Net.java", 8), ("Net.java", 11), ("Net.java", 13)],
        "SOURCE-TRUST-ALL-CERTS": [("Trusting.java", 6)],
    }


KOTLIN_ONE_LINE = """package com.example.ecb

import javax.crypto.Cipher
import java.security.MessageDigest

class Crypto { fun cipher(): Cipher = Cipher.getInstance("AES/ECB/PKCS5Padding") }

class Hash { fun md5(b: ByteArray): ByteArray = MessageDigest.getInstance("MD5").digest(b) }

object Keys { const val LABEL = "brace } stays" }
"""


def test_one_line_kotlin_class_bodies_are_analyzed_at_original_lines():
    from mobile_audit.parser_compat import adapted_source, kotlin_tokens

    result = analyze_sources([("app/Crypto.kt", KOTLIN_ONE_LINE)])
    assert sorted((item["rule_id"], item["evidence"][0]["line"]) for item in result["findings"]) == [
        ("AST-CRYPTO-ECB", 6),
        ("AST-CRYPTO-WEAK-HASH", 8),
    ]
    files = result["metadata"]["files"]
    assert files[0]["state"] == "checked" and files[0]["parse_errors"] is False
    assert files[0]["adaptations"] == [
        {"kind": "kotlin-same-line-closing-brace", "edits": 3, "lossless": True}
    ]
    raw = KOTLIN_ONE_LINE.encode()
    adapted, _ = adapted_source(raw, "kotlin", [])
    assert len(adapted) == len(raw) and b'"brace } stays"' in adapted
    assert [token for token, _, _ in kotlin_tokens(adapted)] == [token for token, _, _ in kotlin_tokens(raw)]


SWIFT_OPEN_URL = """import SwiftUI
import WebKit
struct ContentView: View {
    let webView = WKWebView()
    CONTAINER {
        Text("x").MODIFIER { BODY }
    }
}
"""


# SwiftUI declares views in a computed `var body`; a helper method behaves the same.
@pytest.mark.parametrize("container", ["func content() -> some View", "var body: some View"])
@pytest.mark.parametrize(
    ("modifier", "body", "expected"),
    [
        ("onOpenURL", "url in webView.load(URLRequest(url: url))", UNTRUSTED),
        ("onOpenURL", "webView.load(URLRequest(url: $0))", UNTRUSTED),
        ("onOpenURL", 'url in webView.load(URLRequest(url: URL(string: "https://example.com")!))', set()),
        ("onAppear", 'webView.load(URLRequest(url: URL(string: "https://example.com")!))', set()),
    ],
)
def test_swiftui_open_url_callback_parameter_is_an_external_url(container, modifier, body, expected):
    source = (
        SWIFT_OPEN_URL.replace("CONTAINER", container).replace("MODIFIER", modifier).replace("BODY", body)
    )
    assert rules("App/ContentView.swift", source) == expected


KOTLIN_BASE_ACTIVITY = """package a
import android.webkit.WebView
class DeepK : BaseActivity<String>() {
    fun go(helper: DbHelper, web: WebView) {
        val q = intent.getStringExtra("q")
        STATEMENT
    }
}
"""
JAVA_HELPER = """package a;
class DeepJ extends BaseActivity {
    void go(DbHelper helper) {
        String q = getIntent().getStringExtra("q");
        STATEMENT
    }
}
"""
SQL = {"AST-SQL-CONCAT"}


@pytest.mark.parametrize(
    ("path", "template", "statement", "expected"),
    [
        ("a/D.kt", KOTLIN_BASE_ACTIVITY, "web.loadUrl(q!!)", UNTRUSTED),
        (
            "a/D.kt",
            KOTLIN_BASE_ACTIVITY,
            'val db = helper.writableDatabase\ndb.rawQuery("SELECT * FROM t WHERE q=" + q, null)',
            SQL,
        ),
        (
            "a/D.kt",
            KOTLIN_BASE_ACTIVITY,
            'helper.writableDatabase.execSQL("DELETE FROM t WHERE q=" + q)',
            SQL,
        ),
        (
            "a/D.kt",
            KOTLIN_BASE_ACTIVITY,
            'val db = openOrCreateDatabase("x.db", 0, null)\ndb.execSQL("DELETE FROM t WHERE q=$q")',
            SQL,
        ),
        (
            "a/D.kt",
            KOTLIN_BASE_ACTIVITY,
            'helper.writableDatabase.rawQuery("SELECT 1 WHERE q=?", arrayOf(q))',
            set(),
        ),
        ("a/D.kt", KOTLIN_BASE_ACTIVITY, 'helper.writableDatabase.execSQL("DELETE FROM t")', set()),
        ("a/D.java", JAVA_HELPER, 'helper.getWritableDatabase().execSQL("DELETE FROM t WHERE q=" + q);', SQL),
        (
            "a/D.java",
            JAVA_HELPER,
            'helper.getWritableDatabase().rawQuery("SELECT 1 WHERE q=?", new String[]{q});',
            set(),
        ),
    ],
)
def test_project_activity_bases_and_sqlite_accessors(path, template, statement, expected):
    source = template.replace("STATEMENT", statement.replace("\n", "\n        "))
    assert rules(path, source) == expected


OBJC_HASH = """IMPORT
void hash(NSData *data) {
    unsigned char digest[16];
    CC_MD5(data.bytes, (CC_LONG)data.length, digest);
}
"""
OBJC_NAVIGATION = """IMPORT
@interface Nav : NSObject <WKNavigationDelegate>
@property (nonatomic, strong) WKWebView *webView;
@end
@implementation Nav
- (void)webView:(WKWebView *)webView decidePolicyForNavigationAction:(WKNavigationAction *)navigationAction
    decisionHandler:(void (^)(WKNavigationActionPolicy))decisionHandler {
    WKWebView *other = self.webView;
    [other loadRequest:navigationAction.request];
    decisionHandler(WKNavigationActionPolicyAllow);
}
@end
"""


@pytest.mark.parametrize(
    ("template", "imported", "expected"),
    [
        (OBJC_HASH, "@import CommonCrypto;", {("OBJC-CRYPTO-WEAK-HASH", "MASVS-CRYPTO")}),
        (OBJC_HASH, "@import CommonCrypto.CommonDigest;", {("OBJC-CRYPTO-WEAK-HASH", "MASVS-CRYPTO")}),
        (OBJC_HASH, "@import Foundation;", set()),
        (OBJC_HASH, "#ifdef DEBUG\n@import CommonCrypto;\n#endif", set()),
        (OBJC_NAVIGATION, "@import WebKit;", {("OBJC-WEBVIEW-UNTRUSTED-REQUEST", "MASVS-PLATFORM")}),
        (
            OBJC_NAVIGATION,
            "#import <WebKit/WebKit.h>",
            {("OBJC-WEBVIEW-UNTRUSTED-REQUEST", "MASVS-PLATFORM")},
        ),
    ],
)
def test_objective_c_module_imports_and_webview_mapping(template, imported, expected):
    result = analyze_sources([("App/X.m", template.replace("IMPORT", imported))])
    assert {(item["rule_id"], item["masvs"]) for item in result["findings"]} == expected
