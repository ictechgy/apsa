"""Source-tree platform checks and the added candidate rules (1.5)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from mobile_audit.audit import scan
from mobile_audit.output import sarif

MANIFEST = """<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.example.platform">
  <uses-sdk android:minSdkVersion="24" android:targetSdkVersion="30" />
  <application android:allowBackup="true">
    <activity android:name=".Main" android:exported="true">
      <intent-filter>
        <action android:name="android.intent.action.MAIN" />
        <category android:name="android.intent.category.LAUNCHER" />
      </intent-filter>
    </activity>
    <provider android:name=".Files" android:authorities="com.example.files" android:exported="true" />
    <provider android:name=".Guarded" android:authorities="com.example.guarded" android:exported="true"
        android:readPermission="com.example.READ" />
    <receiver android:name=".Implicit">
      <intent-filter><action android:name="com.example.PING" /></intent-filter>
    </receiver>
    <service android:name=".Private" android:exported="false" />
  </application>
</manifest>
"""

KOTLIN = """package com.example.platform

import android.app.PendingIntent
import android.content.Intent
import java.security.SecureRandom
import java.util.Random

class Tokens {
    fun build(context: android.content.Context) {
        val sessionToken = Random().nextLong()
        val nonce = SecureRandom().nextInt()
        val count = Random().nextInt(10)
        val mutable = PendingIntent.getBroadcast(context, 0, Intent("com.example.PING"), PendingIntent.FLAG_MUTABLE)
        val explicit = PendingIntent.getActivity(context, 0, Intent(context, Tokens::class.java), PendingIntent.FLAG_MUTABLE)
        val immutable = PendingIntent.getService(context, 0, Intent("x"), PendingIntent.FLAG_IMMUTABLE)
        val key = "AKIAIOSFODNN7EXAMPLE"
    }
}
"""

SWIFT = """import Foundation

// UserDefaults in a comment is not use.
final class Settings {
    func boot() -> TimeInterval { ProcessInfo.processInfo.systemUptime }
    func save() { UserDefaults.standard.set(true, forKey: "seen") }
}
"""

PRIVACY = """<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
  <key>NSPrivacyAccessedAPITypes</key>
  <array><dict>
    <key>NSPrivacyAccessedAPIType</key><string>NSPrivacyAccessedAPICategoryUserDefaults</string>
    <key>NSPrivacyAccessedAPITypeReasons</key><array><string>CA92.1</string></array>
  </dict></array>
</dict></plist>
"""


@pytest.fixture
def project(tmp_path, monkeypatch):
    monkeypatch.setenv("APSA_PARSER_SANDBOX", "off")
    root = tmp_path / "app"
    (root / "src").mkdir(parents=True)
    (root / "AndroidManifest.xml").write_text(MANIFEST)
    (root / "src/Tokens.kt").write_text(KOTLIN)
    (root / "Settings.swift").write_text(SWIFT)
    (root / "PrivacyInfo.xcprivacy").write_text(PRIVACY)
    return root


def by_rule(report: dict, rule: str) -> list[dict]:
    return [item for item in report["findings"] if item["rule_id"] == rule]


def test_exported_components_backup_and_target_sdk(store, project):
    report = scan(store, project)
    exported = {
        item["evidence"][0]["component"]: item for item in by_rule(report, "ANDROID-EXPORTED-COMPONENT")
    }
    assert set(exported) == {".Files", ".Implicit"}
    assert exported[".Files"]["severity"] == "medium" and exported[".Files"]["status"] == "candidate"
    assert exported[".Implicit"]["evidence"][0]["implicit_export"] is True
    backup = by_rule(report, "ANDROID-ALLOW-BACKUP")
    assert len(backup) == 1 and backup[0]["status"] == "configuration-confirmed"
    target = by_rule(report, "ANDROID-TARGET-SDK")
    assert [(t["evidence"][0]["path"], t["evidence"][0]["target_sdk"]) for t in target] == [
        ("AndroidManifest.xml", 30)
    ]


def test_gradle_target_sdk_is_located_and_current_levels_pass(store, tmp_path, monkeypatch):
    monkeypatch.setenv("APSA_PARSER_SANDBOX", "off")
    root = tmp_path / "gradle-app"
    (root / "app").mkdir(parents=True)
    (root / "app/AndroidManifest.xml").write_text(
        '<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.example.g">'
        "<application/></manifest>"
    )
    (root / "app/build.gradle.kts").write_text(
        "android {\n    defaultConfig {\n        targetSdk = 34\n    }\n}\n"
    )
    (root / "lib.gradle").write_text("android { defaultConfig { targetSdkVersion 36 } }\n")
    report = scan(store, root)
    target = by_rule(report, "ANDROID-TARGET-SDK")
    assert [(t["evidence"][0]["path"], t["evidence"][0]["line"], t["severity"]) for t in target] == [
        ("app/build.gradle.kts", 3, "low")
    ]
    assert {c["rule_id"]: c["state"] for c in report["coverage"]}["ANDROID-TARGET-SDK"] == "checked"


def test_privacy_manifest_declarations_and_comments(store, project):
    report = scan(store, project)
    missing = by_rule(report, "IOS-PRIVACY-MANIFEST")
    assert [item["evidence"][0]["category"] for item in missing] == [
        "NSPrivacyAccessedAPICategorySystemBootTime"
    ]
    (project / "PrivacyInfo.xcprivacy").unlink()
    categories = {
        item["evidence"][0]["category"] for item in by_rule(scan(store, project), "IOS-PRIVACY-MANIFEST")
    }
    assert categories == {
        "NSPrivacyAccessedAPICategorySystemBootTime",
        "NSPrivacyAccessedAPICategoryUserDefaults",
    }


def test_hardcoded_secrets_are_masked_everywhere(store, project):
    report = scan(store, project)
    secrets = by_rule(report, "SOURCE-HARDCODED-SECRET")
    assert len(secrets) == 1 and secrets[0]["severity"] == "high"
    evidence = secrets[0]["evidence"][0]
    assert evidence["credential_type"] == "aws-access-key-id" and evidence["masked_value"].startswith("AKIA…")
    assert "AKIAIOSFODNN7EXAMPLE" not in json.dumps(report)
    assert "AKIAIOSFODNN7EXAMPLE" not in json.dumps(sarif(report))


def test_insecure_random_and_mutable_pending_intents(store, project):
    report = scan(store, project)
    random = by_rule(report, "SOURCE-INSECURE-RANDOM")
    assert [item["evidence"][0]["line"] for item in random] == [10]
    pending = by_rule(report, "AST-PENDINGINTENT-MUTABLE")
    assert [item["evidence"][0]["line"] for item in pending] == [13]
    assert pending[0]["evidence"][0]["factory"] == "PendingIntent.getBroadcast"


def test_compiled_packages_keep_the_lint_engine_checks(store, monkeypatch):
    monkeypatch.setenv("APSA_PARSER_SANDBOX", "off")
    report = scan(store, Path(__file__).parent / "fixtures/binary_analysis/unsafe.apk")
    rules = {item["rule_id"] for item in report["coverage"]}
    assert "QG-APP-EXPORTED" in rules
    assert not rules & {"ANDROID-EXPORTED-COMPONENT", "ANDROID-ALLOW-BACKUP", "SOURCE-HARDCODED-SECRET"}


NETWORK_KT = """package com.example.net

import java.io.ObjectInputStream
import java.security.cert.X509Certificate
import javax.net.ssl.HostnameVerifier
import javax.net.ssl.X509TrustManager

class Net {
    val trustAll = object : X509TrustManager {
        override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?) {}
        override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?) {}
        override fun getAcceptedIssuers(): Array<X509Certificate> = arrayOf()
    }
    val strict = object : X509TrustManager {
        override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?) {}
        override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?) {
            delegate.checkServerTrusted(chain, authType)
        }
        override fun getAcceptedIssuers(): Array<X509Certificate> = arrayOf()
    }
    fun open(connection: javax.net.ssl.HttpsURLConnection, context: android.content.Context, input: java.io.InputStream) {
        connection.hostnameVerifier = HostnameVerifier { hostname, _ ->
            log(hostname)
            true
        }
        val file = java.io.File(context.getExternalFilesDir(null), "token.txt")
        val value = ObjectInputStream(input).readObject()
    }
}
"""

TRUST_SWIFT = """import Foundation

final class Delegate: NSObject, URLSessionDelegate {
    func urlSession(_ s: URLSession, didReceive challenge: URLAuthenticationChallenge,
                    completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        guard let trust = challenge.protectionSpace.serverTrust else { return }
        completionHandler(.useCredential, URLCredential(trust: trust))
    }
}

final class Checked: NSObject, URLSessionDelegate {
    func urlSession(_ s: URLSession, didReceive challenge: URLAuthenticationChallenge,
                    completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        guard let trust = challenge.protectionSpace.serverTrust else { return }
        var error: CFError?
        if SecTrustEvaluateWithError(trust, &error) {
            completionHandler(.useCredential, URLCredential(trust: trust))
        }
    }
}
"""

ATS_PLIST = """<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
  <key>CFBundleIdentifier</key><string>com.example.ats</string>
  <key>NSAppTransportSecurity</key>
  <dict>
    <key>NSExceptionDomains</key>
    <dict>
      <key>legacy.example.com</key>
      <dict>
        <key>NSExceptionMinimumTLSVersion</key><string>TLSv1.0</string>
        <key>NSExceptionRequiresForwardSecrecy</key><false/>
      </dict>
      <key>modern.example.com</key>
      <dict><key>NSIncludesSubdomains</key><true/></dict>
    </dict>
  </dict>
</dict></plist>
"""


def test_network_storage_and_deserialization_candidates(store, tmp_path, monkeypatch):
    monkeypatch.setenv("APSA_PARSER_SANDBOX", "off")
    root = tmp_path / "net"
    root.mkdir()
    (root / "Net.kt").write_text(NETWORK_KT)
    (root / "Delegate.swift").write_text(TRUST_SWIFT)
    (root / "Info.plist").write_text(ATS_PLIST)
    report = scan(store, root)
    lines = {
        rule: [f["evidence"][0].get("line") for f in by_rule(report, rule)]
        for rule in (
            "SOURCE-TRUST-ALL-CERTS",
            "SOURCE-HOSTNAME-VERIFIER-ALL",
            "SOURCE-EXTERNAL-STORAGE",
            "SOURCE-JAVA-DESERIALIZATION",
            "SWIFT-SERVER-TRUST-ACCEPTED",
        )
    }
    assert lines == {
        "SOURCE-TRUST-ALL-CERTS": [11],
        "SOURCE-HOSTNAME-VERIFIER-ALL": [22],
        "SOURCE-EXTERNAL-STORAGE": [26],
        "SOURCE-JAVA-DESERIALIZATION": [27],
        "SWIFT-SERVER-TRUST-ACCEPTED": [7],
    }
    [ats] = by_rule(report, "IOS-ATS-EXCEPTION")
    assert ats["evidence"][0]["domain"] == "legacy.example.com" and len(ats["evidence"][0]["reasons"]) == 2
