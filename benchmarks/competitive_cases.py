"""Independent, generated risk/fix/control pairs for a limited two-tool comparison.

Labels describe the selected local risk, not exploitability or whole-app safety.
Every input is generated into a new temporary directory. No user apps are used.
"""

from __future__ import annotations

import copy
import hashlib
import json
import plistlib
import zipfile
from pathlib import Path

SCHEMA = "apsa-competitive-v1"
MOBSF_COMMIT = "d3869adc464b89db92a6a8a9e2dc13376f4a4c25"
MOBSF_IMAGE = "opensecurity/mobile-security-framework-mobsf:v4.5.3"
REFERENCES = {
    "url": "https://developer.android.com/privacy-and-security/risks/unsafe-uri-loading",
    "ssl": "https://developer.android.com/reference/android/webkit/WebViewClient#onReceivedSslError(android.webkit.WebView,%20android.webkit.SslErrorHandler,%20android.net.http.SslError)",
    "file": "https://developer.android.com/privacy-and-security/risks/webview-unsafe-file-inclusion",
    "log": "https://developer.android.com/privacy-and-security/risks/log-info-disclosure",
    "crypto": "https://developer.android.com/privacy-and-security/cryptography",
    "sql": "https://developer.android.com/privacy-and-security/risks/sql-injection",
    "debug": "https://developer.android.com/privacy-and-security/risks/android-debuggable",
    "cleartext": "https://developer.android.com/privacy-and-security/security-config",
    "keychain": "https://developer.apple.com/documentation/security/ksecattraccessiblealways",
    "ats": "https://developer.apple.com/documentation/bundleresources/information-property-list/nsapptransportsecurity",
}
# Rule IDs are read from the pinned engines' catalogs, never selected from results.
# Reserved AST crypto/SQL IDs deliberately expose gaps in APSA 1.1.0.
# MobSF has no equivalent local untrusted-URL rule in the pinned catalogs.
MAPPING = {
    "url": {
        "apsa": ["AST-WEBVIEW-UNTRUSTED-URL", "AST-WEBVIEW-HOST-ALLOWLIST", "WEBVIEW-HOST-MATCH"],
        "mobsf": [],
    },
    "ssl": {
        "apsa": ["AST-WEBVIEW-SSL-BYPASS", "WEBVIEW-SSL-BYPASS", "BINARY-WEBVIEW-SSL-BYPASS"],
        "mobsf": ["android_webview_ignore_ssl"],
    },
    "file": {
        "apsa": ["WEBVIEW-FILE-ACCESS", "BINARY-WEBVIEW-FILE-ACCESS"],
        "mobsf": ["android_webview_allow_file_from_url"],
    },
    "log": {
        "apsa": ["STORAGE-SENSITIVE-LOG", "BINARY-STORAGE-SENSITIVE-LOG"],
        "mobsf": ["android_logging", "ios_swift_log"],
    },
    "ecb": {"apsa": ["AST-CRYPTO-ECB"], "mobsf": ["android_aes_ecb", "android_aws_ecb_default"]},
    "md5": {"apsa": ["AST-CRYPTO-WEAK-HASH"], "mobsf": ["android_md5", "ios_swift_md5_collision"]},
    "sql": {"apsa": ["AST-SQL-CONCAT"], "mobsf": ["android_sql_raw_query"]},
    "debug": {"apsa": ["ANDROID-DEBUG"], "mobsf": ["manifest:app_is_debuggable"]},
    "cleartext": {"apsa": ["ANDROID-CLEARTEXT"], "mobsf": ["manifest:clear_text_traffic"]},
    "keychain": {"apsa": ["IOS-KEYCHAIN-ACCESS"], "mobsf": ["ios_keychain_weak_accessibility_value"]},
    "ats": {"apsa": ["IOS-ATS"], "mobsf": ["ats:App Transport Security AllowsArbitraryLoads is allowed"]},
}

JAVA_IMPORTS = """package test.synthetic;
import android.app.Activity;
import android.os.Bundle;
import android.content.Intent;
import android.net.Uri;
import android.net.http.SslError;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import android.webkit.SslErrorHandler;
import android.util.Log;
import android.database.sqlite.SQLiteDatabase;
import javax.crypto.Cipher;
import java.security.MessageDigest;
public class ProbeActivity extends Activity {
  private WebView view;
  public void onCreate(Bundle saved) {
    super.onCreate(saved); view = new WebView(this); setContentView(view);
  }
"""


def ssl_body(action: str) -> str:
    return """public void installClient(WebView browser) {
    browser.setWebViewClient(new WebViewClient() {
      @Override public void onReceivedSslError(WebView browser, SslErrorHandler handler, SslError error) {
        ACTION
      }
    });
  }""".replace("ACTION", action)


def cases() -> list[dict]:
    records = []

    def add(case_id, language, category, variant, source, reason, **flags):
        reference = REFERENCES.get(category, REFERENCES["crypto"])
        records.append(
            {
                "id": case_id,
                "language": language,
                "category": category,
                "variant": variant,
                "risky": variant == "risky",
                "source": source,
                "reason": reason,
                "reference": reference,
                "flags": flags,
            }
        )

    uri = 'String next = intent.getStringExtra("next");'
    callback = "public void onNewIntent(Intent intent) { super.onNewIntent(intent); %s }"
    add(
        "java-url-direct",
        "java",
        "url",
        "risky",
        callback % (uri + " view.loadUrl(next);"),
        "Intent string reaches WebView without a scheme/host guard.",
    )
    guard = 'Uri parsed = Uri.parse(next); if ("https".equals(parsed.getScheme()) && "accounts.example.test".equals(parsed.getHost())) { view.loadUrl(next); }'
    add(
        "java-url-guarded",
        "java",
        "url",
        "fixed",
        callback % (uri + guard),
        "Both parsed scheme and complete hostname are checked.",
    )
    add(
        "java-url-suffix",
        "java",
        "url",
        "risky",
        callback
        % (
            uri
            + 'Uri parsed = Uri.parse(next); if (parsed.getHost().endsWith("example.test")) { view.loadUrl(next); }'
        ),
        "A hostname suffix lacks a leading-dot boundary and scheme validation.",
    )
    add(
        "java-url-constant",
        "java",
        "url",
        "irrelevant",
        callback % 'view.loadUrl("https://accounts.example.test/start");',
        "This selected flow loads a fixed HTTPS URL, not platform input.",
    )
    add(
        "java-ssl-proceed",
        "java",
        "ssl",
        "risky",
        ssl_body("handler.proceed();"),
        "The real certificate-error callback explicitly accepts a rejected certificate.",
        apk=True,
    )
    add(
        "java-ssl-cancel",
        "java",
        "ssl",
        "fixed",
        ssl_body("handler.cancel();"),
        "The certificate error is cancelled.",
        apk=True,
    )
    add(
        "java-ssl-comment",
        "java",
        "ssl",
        "irrelevant",
        ssl_body("// Prior bug: handler.proceed();\n        handler.cancel();"),
        "The unsafe statement is only a comment; the live callback cancels.",
    )
    add(
        "java-ssl-unrelated",
        "java",
        "ssl",
        "irrelevant",
        ssl_body("handler.cancel();")
        + "static class LocalHandler { void proceed() {} } public void diagnostics(LocalHandler handler) { handler.proceed(); }",
        "A different handler type has an unrelated proceed method; the TLS callback cancels.",
    )
    for enabled in (True, False):
        word = str(enabled).lower()
        add(
            "java-file-" + word,
            "java",
            "file",
            "risky" if enabled else "fixed",
            f"public void settings(WebView browser) {{ browser.getSettings().setJavaScriptEnabled(true); browser.getSettings().setAllowUniversalAccessFromFileURLs({word}); }}",
            "Universal file-origin access is " + ("enabled." if enabled else "disabled."),
            apk=True,
        )
    add(
        "java-log-secret",
        "java",
        "log",
        "risky",
        callback
        % 'String sessionToken = intent.getStringExtra("session"); Log.i("probe", "session token=" + sessionToken);',
        "A platform-supplied session credential is written to logs.",
    )
    add(
        "java-log-redacted",
        "java",
        "log",
        "fixed",
        callback
        % 'String sessionToken = intent.getStringExtra("session"); Log.i("probe", "session token=[REDACTED]");',
        "The log contains a redaction marker and never the credential value.",
    )
    add(
        "java-log-comment",
        "java",
        "log",
        "irrelevant",
        callback % '// Log.i("probe", "session token=" + sessionToken);\n int count = 0;',
        "Logging appears only in a source comment.",
    )
    for mode in ("ECB", "GCM"):
        add(
            "java-cipher-" + mode.lower(),
            "java",
            "ecb",
            "risky" if mode == "ECB" else "fixed",
            f'public Cipher cipher() throws Exception {{ return Cipher.getInstance("AES/{mode}/NoPadding"); }}',
            "AES mode selection is " + mode + "; only the ECB-mode risk is labeled.",
        )
    for algorithm in ("MD5", "SHA-256"):
        add(
            "java-digest-" + algorithm.lower(),
            "java",
            "md5",
            "risky" if algorithm == "MD5" else "fixed",
            f'public byte[] verifySignatureMaterial(byte[] material) throws Exception {{ return MessageDigest.getInstance("{algorithm}").digest(material); }}',
            "A collision-sensitive digest uses " + algorithm + "; this is not a checksum-use case.",
        )
    add(
        "java-sql-concat",
        "java",
        "sql",
        "risky",
        callback
        % 'String account = intent.getStringExtra("account"); SQLiteDatabase database = openOrCreateDatabase("accounts", MODE_PRIVATE, null); database.rawQuery("SELECT name FROM accounts WHERE name=\'" + account + "\'", null);',
        "Platform input is concatenated directly into a SQL statement.",
    )
    add(
        "java-sql-bound",
        "java",
        "sql",
        "fixed",
        callback
        % 'String account = intent.getStringExtra("account"); SQLiteDatabase database = openOrCreateDatabase("accounts", MODE_PRIVATE, null); database.rawQuery("SELECT name FROM accounts WHERE name=?", new String[]{account});',
        "The statement is constant and the input is supplied as a bound parameter.",
    )
    for category, attribute in (("debug", "debuggable"), ("cleartext", "usesCleartextTraffic")):
        for enabled in (True, False):
            word = str(enabled).lower()
            add(
                "java-" + category + "-" + word,
                "java",
                category,
                "risky" if enabled else "fixed",
                "public void marker() {}",
                f"The selected manifest flag {attribute} is explicitly {word}.",
                **{attribute: enabled, "apk": category == "debug"},
            )
    for unsafe in (True, False):
        action = "proceed" if unsafe else "cancel"
        add(
            "kotlin-ssl-" + action,
            "kotlin",
            "ssl",
            "risky" if unsafe else "fixed",
            f"fun configure(browser: WebView) {{ browser.webViewClient = object : WebViewClient() {{ override fun onReceivedSslError(browser: WebView, handler: SslErrorHandler, error: SslError) {{ handler.{action}() }} }} }}",
            "The Kotlin callback " + action + "s the certificate error.",
        )
    add(
        "kotlin-url-direct",
        "kotlin",
        "url",
        "risky",
        'override fun onNewIntent(intent: Intent) { super.onNewIntent(intent); val next = intent.getStringExtra("next") ?: return; view.loadUrl(next) }',
        "Intent string reaches WebView without a recognized guard.",
    )
    add(
        "kotlin-url-guarded",
        "kotlin",
        "url",
        "fixed",
        'override fun onNewIntent(intent: Intent) { super.onNewIntent(intent); val next = intent.getStringExtra("next") ?: return; val parsed = Uri.parse(next); if (parsed.scheme == "https" && parsed.host == "accounts.example.test") { view.loadUrl(next) } }',
        "The parsed scheme and exact hostname are both checked.",
    )
    add(
        "kotlin-log-secret",
        "kotlin",
        "log",
        "risky",
        'fun audit(sessionToken: String) { Log.i("probe", "session token=" + sessionToken) }',
        "A credential parameter is included in the log message.",
    )
    add(
        "kotlin-log-redacted",
        "kotlin",
        "log",
        "fixed",
        'fun audit(sessionToken: String) { Log.i("probe", "session token=[REDACTED]") }',
        "The credential parameter is not logged.",
    )
    swift_head = "func application(_ app: UIApplication, open incoming: URL, options: [UIApplication.OpenURLOptionsKey: Any] = [:]) -> Bool {"
    add(
        "swift-url-direct",
        "swift",
        "url",
        "risky",
        swift_head + " let browser = WKWebView(); browser.load(URLRequest(url: incoming)); return true }",
        "An incoming application URL is loaded directly into a WebView.",
    )
    add(
        "swift-url-guarded",
        "swift",
        "url",
        "fixed",
        swift_head
        + ' guard incoming.scheme == "https", incoming.host == "accounts.example.test" else { return false }; let browser = WKWebView(); browser.load(URLRequest(url: incoming)); return true }',
        "The incoming URL requires the HTTPS scheme and exact hostname.",
    )
    add(
        "swift-log-secret",
        "swift",
        "log",
        "risky",
        'func audit(sessionToken: String) { print("session token=" + sessionToken) }',
        "A session credential is logged.",
    )
    add(
        "swift-log-redacted",
        "swift",
        "log",
        "fixed",
        'func audit(sessionToken: String) { print("session token=[REDACTED]") }',
        "The log never contains the credential value.",
    )
    add(
        "swift-log-comment",
        "swift",
        "log",
        "irrelevant",
        'func audit(sessionToken: String) { /* print("session token=" + sessionToken) */ }',
        "The log call is only a comment.",
    )
    for value in ("Always", "WhenUnlockedThisDeviceOnly"):
        add(
            "swift-keychain-" + value.lower(),
            "swift",
            "keychain",
            "risky" if value == "Always" else "fixed",
            f'func storeCredential(_ token: Data) {{ let item: [CFString: Any] = [kSecClass: kSecClassGenericPassword, kSecAttrAccount: "synthetic", kSecValueData: token, kSecAttrAccessible: kSecAttrAccessible{value}]; SecItemAdd(item as CFDictionary, nil) }}',
            "Credential accessibility is explicitly " + value + ".",
        )
    for algorithm in ("MD5", "SHA256"):
        add(
            "swift-digest-" + algorithm.lower(),
            "swift",
            "md5",
            "risky" if algorithm == "MD5" else "fixed",
            f"func verifySignatureMaterial(_ material: Data) {{ material.withUnsafeBytes {{ buffer in var digest = [UInt8](repeating: 0, count: Int(CC_{algorithm}_DIGEST_LENGTH)); CC_{algorithm}(buffer.baseAddress, CC_LONG(material.count), &digest) }} }}",
            "Collision-sensitive signature material uses " + algorithm + ".",
        )
    for enabled in (True, False):
        add(
            "swift-ats-" + str(enabled).lower(),
            "swift",
            "ats",
            "risky" if enabled else "fixed",
            "func marker() {}",
            "The broad ATS exception is explicitly " + str(enabled).lower() + ".",
            ats=enabled,
        )
    return records


def project_files(case: dict) -> dict[str, bytes]:
    if case["language"] == "swift":
        info = {
            "CFBundleIdentifier": "test.synthetic." + case["id"].replace("-", ""),
            "CFBundleName": "SyntheticProbe",
            "CFBundleVersion": "1",
            "CFBundleShortVersionString": "1.0",
            "CFBundleExecutable": "SyntheticProbe",
            "CFBundlePackageType": "APPL",
            "NSAppTransportSecurity": {"NSAllowsArbitraryLoads": case["flags"].get("ats", False)},
        }
        source = (
            "import UIKit\nimport WebKit\nimport Security\nimport CommonCrypto\nclass Probe: UIResponder, UIApplicationDelegate {\n"
            + case["source"]
            + "\n}\n"
        )
        return {
            "SyntheticProbe/Probe.swift": source.encode(),
            "SyntheticProbe/Info.plist": plistlib.dumps(info),
            "SyntheticProbe.xcodeproj/project.pbxproj": b"// Source-analysis fixture; not an Xcode build validation.\n{}\n",
        }
    debug = str(case["flags"].get("debuggable", False)).lower()
    cleartext = str(case["flags"].get("usesCleartextTraffic", False)).lower()
    manifest = f'''<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="test.synthetic" android:versionCode="1" android:versionName="1.0">
<uses-sdk android:minSdkVersion="24" android:targetSdkVersion="35"/>
<uses-permission android:name="android.permission.INTERNET"/>
<application android:label="SyntheticProbe" android:debuggable="{debug}" android:usesCleartextTraffic="{cleartext}" android:allowBackup="false">
<activity android:name=".ProbeActivity" android:exported="true"><intent-filter><action android:name="android.intent.action.MAIN"/><category android:name="android.intent.category.LAUNCHER"/></intent-filter></activity>
</application></manifest>'''
    if case["language"] == "java":
        source = JAVA_IMPORTS + case["source"] + "\n}\n"
        path = "app/src/main/java/test/synthetic/ProbeActivity.java"
    else:
        source = (
            """package test.synthetic
import android.app.Activity
import android.content.Intent
import android.net.Uri
import android.net.http.SslError
import android.webkit.WebView
import android.webkit.WebViewClient
import android.webkit.SslErrorHandler
import android.util.Log
class ProbeActivity : Activity() {
  lateinit var view: WebView
"""
            + case["source"]
            + "\n}\n"
        )
        path = "app/src/main/kotlin/test/synthetic/ProbeActivity.kt"
    return {
        path: source.encode(),
        "app/src/main/AndroidManifest.xml": manifest.encode(),
        "settings.gradle": b"include ':app'\n",
        "app/build.gradle": b"plugins { id 'com.android.application' }\nandroid { namespace 'test.synthetic'; compileSdk 35 }\n",
    }


def generate(root: Path) -> dict:
    """Create a new fixture directory; never reuse or inspect a previous input tree."""
    root.mkdir(parents=True, exist_ok=False)
    records = []
    for case in cases():
        files = project_files(case)
        folder = root / case["id"]
        for name, content in files.items():
            destination = folder / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(content)
        archive = root / (case["id"] + ".zip")
        with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as output:
            for name, content in sorted(files.items()):
                info = zipfile.ZipInfo(name, date_time=(2020, 1, 1, 0, 0, 0))
                info.compress_type = zipfile.ZIP_DEFLATED
                info.external_attr = 0o100644 << 16
                output.writestr(info, content)
        records.append(
            {k: v for k, v in case.items() if k != "source"}
            | {
                "input": archive.name,
                "input_kind": "source-zip",
                "sha256": hashlib.sha256(archive.read_bytes()).hexdigest(),
                "files": {
                    name: hashlib.sha256(content).hexdigest() for name, content in sorted(files.items())
                },
            }
        )
    manifest = {
        "schema": SCHEMA,
        "mobsf_commit": MOBSF_COMMIT,
        "mobsf_image": MOBSF_IMAGE,
        "mapping": copy.deepcopy(MAPPING),
        "cases": records,
        "limits": [
            "Handcrafted local-pattern risk labels, not exploit proofs or production accuracy.",
            "Swift/Kotlin projects are source-analysis fixtures; only the selected Java APKs are compiler-validated.",
            "No dynamic/device tests, IPA binaries, AAB, obfuscation, CVE feed comparison, or cross-function flows.",
            "Generic review alerts may count as alert false positives against these narrower labels.",
        ],
    }
    (root / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    return manifest
