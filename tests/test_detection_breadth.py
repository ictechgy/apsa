"""1.5 detection breadth: crypto, local authentication, transport, intents, WebViews and file paths."""

from __future__ import annotations

from pathlib import Path

import pytest

from mobile_audit.audit import scan
from mobile_audit.maswe import weaknesses_for
from mobile_audit.source_analysis import analyze_sources

ANDROID_MANIFEST = """<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.example.breadth">
  <uses-sdk android:minSdkVersion="26" android:targetSdkVersion="35" />
  <application android:networkSecurityConfig="@xml/network_security_config">
    <activity android:name=".Links" android:exported="true">
      <intent-filter>
        <action android:name="android.intent.action.VIEW" />
        <category android:name="android.intent.category.DEFAULT" />
        <category android:name="android.intent.category.BROWSABLE" />
        <data android:scheme="https" android:host="links.example.com" />
      </intent-filter>
    </activity>
    <activity android:name=".Verified" android:exported="true">
      <intent-filter android:autoVerify="true">
        <action android:name="android.intent.action.VIEW" />
        <category android:name="android.intent.category.DEFAULT" />
        <category android:name="android.intent.category.BROWSABLE" />
        <data android:scheme="https" android:host="verified.example.com" />
      </intent-filter>
    </activity>
    <activity android:name=".Custom" android:exported="true">
      <intent-filter>
        <action android:name="android.intent.action.VIEW" />
        <category android:name="android.intent.category.BROWSABLE" />
        <data android:scheme="breadth" android:host="open" />
      </intent-filter>
    </activity>
  </application>
</manifest>
"""

NETWORK_CONFIG = """<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <!-- <certificates src="user" /> in a comment is not configuration -->
    <base-config cleartextTrafficPermitted="false">
        <trust-anchors>
            <certificates src="system" />
            <certificates src="user" />
        </trust-anchors>
    </base-config>
    <domain-config cleartextTrafficPermitted="true">
        <domain includeSubdomains="true">legacy.example.com</domain>
    </domain-config>
    <domain-config cleartextTrafficPermitted="true">
        <domain includeSubdomains="false">127.0.0.1</domain>
        <domain includeSubdomains="false">localhost</domain>
    </domain-config>
    <debug-overrides>
        <trust-anchors>
            <certificates src="user" />
        </trust-anchors>
    </debug-overrides>
</network-security-config>
"""


def by_rule(report: dict, rule: str) -> list[dict]:
    return [item for item in report["findings"] if item["rule_id"] == rule]


def lines(report: dict, rule: str) -> list[int | None]:
    return sorted(item["evidence"][0].get("line") for item in by_rule(report, rule))


def ast(path: str, text: str) -> dict[str, list[int]]:
    result: dict[str, list[int]] = {}
    for item in analyze_sources([(path, text)])["findings"]:
        result.setdefault(item["rule_id"], []).append(item["evidence"][0]["line"])
    return {rule: sorted(found) for rule, found in result.items()}


@pytest.fixture
def android(tmp_path, monkeypatch):
    monkeypatch.setenv("APSA_PARSER_SANDBOX", "off")
    root = tmp_path / "android"
    (root / "res/xml").mkdir(parents=True)
    (root / "AndroidManifest.xml").write_text(ANDROID_MANIFEST)
    (root / "res/xml/network_security_config.xml").write_text(NETWORK_CONFIG)
    return root


def test_network_security_config_and_app_links(store, android):
    report = scan(store, android)
    user = by_rule(report, "ANDROID-NSC-USER-CA")
    assert [(u["evidence"][0]["line"], u["evidence"][0]["scope"]) for u in user] == [(7, "base-config")]
    assert user[0]["status"] == "configuration-confirmed"
    cleartext = [c for c in by_rule(report, "ANDROID-CLEARTEXT") if c["evidence"][0]["path"].endswith(".xml")]
    assert [(c["evidence"][0]["scope"], c["evidence"][0]["domains"], c["severity"]) for c in cleartext] == [
        ("domain-config", ["legacy.example.com"], "low")
    ]
    links = by_rule(report, "ANDROID-DEEPLINK-AUTOVERIFY")
    # Verified filters and custom schemes are not App Link candidates.
    assert [(item["evidence"][0]["component"], item["evidence"][0]["hosts"]) for item in links] == [
        (".Links", ["links.example.com"])
    ]
    states = {c["rule_id"]: c["state"] for c in report["coverage"]}
    assert states["ANDROID-NSC-USER-CA"] == states["ANDROID-DEEPLINK-AUTOVERIFY"] == "checked"


def test_unreferenced_network_config_is_not_read(store, android):
    manifest = android / "AndroidManifest.xml"
    manifest.write_text(
        manifest.read_text().replace(' android:networkSecurityConfig="@xml/network_security_config"', "")
    )
    report = scan(store, android)
    assert not by_rule(report, "ANDROID-NSC-USER-CA")
    coverage = next(c for c in report["coverage"] if c["rule_id"] == "ANDROID-NSC-USER-CA")
    assert coverage["state"] == "checked" and "No networkSecurityConfig" in coverage["note"]


CRYPTO_KT = """package com.example.breadth

import android.util.Base64
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec
import java.security.SecureRandom

private const val KEY = "0123456789abcdef"
private const val TRANSFORMATION = "DESede/CBC/PKCS5Padding"

class Crypto {
    companion object {
        val IV = byteArrayOf(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16)
    }

    fun weak() {
        val des = Cipher.getInstance("DES")
        val defaultMode = Cipher.getInstance("AES")
        val ecb = Cipher.getInstance("AES/ECB/PKCS5Padding")
        val triple = Cipher.getInstance(TRANSFORMATION)
        val gcm = Cipher.getInstance("AES/GCM/NoPadding")
    }

    fun hardcoded(input: ByteArray): ByteArray {
        val literal = SecretKeySpec("my secret here".toByteArray(), "AES")
        val bytes = byteArrayOf(0x6C, 0x61, 0x6B, 0x64)
        val fromBytes = SecretKeySpec(bytes, "AES")
        val fromConstant = SecretKeySpec(KEY.toByteArray(Charsets.UTF_8), "AES")
        val decoded = SecretKeySpec(Base64.decode("AAECAwQFBgcICQoLDA0ODw==", Base64.DEFAULT), "AES")
        val zeroIv = IvParameterSpec(ByteArray(16))
        val companionIv = IvParameterSpec(Companion.IV)
        val nonce = GCMParameterSpec(128, "fixed-nonce!".toByteArray())
        return input
    }

    fun random(input: ByteArray, key: ByteArray): ByteArray {
        val keyBytes = ByteArray(16)
        SecureRandom().nextBytes(keyBytes)
        val generated = SecretKeySpec(keyBytes, "AES")
        val iv = ByteArray(12)
        SecureRandom().nextBytes(iv)
        val spec = GCMParameterSpec(128, iv)
        val passed = SecretKeySpec(key, "AES")
        val filled = ByteArray(16) { it.toByte() }
        val lambda = IvParameterSpec(filled)
        return input
    }
}
"""


def test_cipher_algorithms_and_constant_key_material():
    found = ast("Crypto.kt", CRYPTO_KT)
    assert found["AST-CRYPTO-WEAK-CIPHER"] == [19, 22]
    assert found["AST-CRYPTO-ECB"] == [20, 21]
    assert found["AST-CRYPTO-HARDCODED-KEY"] == [27, 29, 30, 31]
    assert found["AST-CRYPTO-STATIC-IV"] == [32, 33, 34]
    findings = analyze_sources([("Crypto.kt", CRYPTO_KT)])["findings"]
    modes = {
        f["evidence"][0]["line"]: f["evidence"][0].get("mode")
        for f in findings
        if f["rule_id"] == "AST-CRYPTO-ECB"
    }
    assert modes == {20: "provider default (ECB)", 21: "ECB"}
    materials = {
        f["evidence"][0]["line"]: f["evidence"][0]["material"]
        for f in findings
        if f["rule_id"] == "AST-CRYPTO-STATIC-IV"
    }
    assert materials == {32: "zero-filled array", 33: "literal array", 34: "string literal"}


CRYPTO_JAVA = """package com.example.breadth;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

class Legacy {
    private static final String KEY = "0123456789abcdef";
    private static final byte[] IV = {1, 2, 3, 4};

    void run(byte[] runtimeKey) throws Exception {
        Cipher rc4 = Cipher.getInstance("RC4");
        SecretKeySpec key = new SecretKeySpec(KEY.getBytes(StandardCharsets.UTF_8), "AES");
        IvParameterSpec iv = new IvParameterSpec(IV);
        byte[] zero = new byte[16];
        IvParameterSpec zeroIv = new IvParameterSpec(zero);
        byte[] fresh = new byte[16];
        new SecureRandom().nextBytes(fresh);
        IvParameterSpec freshIv = new IvParameterSpec(fresh);
        byte[] patched = new byte[] {1, 2};
        patched[0] = runtimeKey[0];
        SecretKeySpec mixed = new SecretKeySpec(patched, "AES");
        SecretKeySpec runtime = new SecretKeySpec(runtimeKey, "AES");
    }
}
"""


def test_java_constants_and_runtime_material():
    found = ast("Legacy.java", CRYPTO_JAVA)
    assert found["AST-CRYPTO-WEAK-CIPHER"] == [14]
    assert found["AST-CRYPTO-HARDCODED-KEY"] == [15]
    assert found["AST-CRYPTO-STATIC-IV"] == [16, 18]


CRYPTO_SWIFT = """import CryptoKit
import Foundation
import Security

struct Keys {
    static let raw: [UInt8] = [0x01, 0x02, 0x03]

    func make(runtime: Data) throws {
        let symmetric = SymmetricKey(data: "secret".data(using: .utf8)!)
        let fresh = SymmetricKey(size: .bits256)
        let signing = try P256.Signing.PrivateKey(rawRepresentation: Data(Keys.raw))
        let imported = try P256.Signing.PrivateKey(rawRepresentation: runtime)
        let nonce = try AES.GCM.Nonce(data: Data(base64Encoded: "AAAAAAAAAAAAAAAA")!)
        let digest = Insecure.MD5.hash(data: runtime)
        let sha1 = Insecure.SHA1.hash(data: runtime)
        let sha256 = SHA256.hash(data: runtime)
    }

    func importPublic(bytes: [UInt8]) {
        let pinned: [UInt8] = [0x30, 0x59]
        let key = SecKeyCreateWithData(Data(pinned) as CFData, [kSecAttrKeyClass: kSecAttrKeyClassPublic] as CFDictionary, nil)
    }

    func importPrivate() {
        let material: [UInt8] = [0x30, 0x77]
        let attributes: [String: Any] = [kSecAttrKeyClass as String: kSecAttrKeyClassPrivate]
        let key = SecKeyCreateWithData(Data(material) as CFData, attributes as CFDictionary, nil)
    }
}
"""


def test_swift_key_material_and_cryptokit_digests():
    found = ast("Keys.swift", CRYPTO_SWIFT)
    assert found["AST-CRYPTO-HARDCODED-KEY"] == [9, 11, 27]
    assert found["AST-CRYPTO-STATIC-IV"] == [13]
    assert found["AST-CRYPTO-WEAK-HASH"] == [14, 15]


INTENTS_KT = """package com.example.breadth

import android.app.Activity
import android.content.Intent
import androidx.core.content.IntentCompat
import androidx.localbroadcastmanager.content.LocalBroadcastManager

class Router : Activity() {
    companion object {
        const val ACTION_SYNC = "com.example.breadth.SYNC"
    }

    fun forward() {
        val next = intent.getParcelableExtra<Intent>("next")
        startActivity(next)
        val compat = IntentCompat.getParcelableExtra(intent, "next", Intent::class.java)
        startService(compat)
        val bundled = intent.extras?.getParcelable<Intent>("next")
        val checked = intent.getParcelableExtra<Intent>("checked")
        if (checked?.component?.packageName == packageName) {
            startActivity(checked)
        }
    }

    fun broadcast(token: String) {
        sendBroadcast(Intent("com.example.breadth.TOKEN").putExtra("token", token))
        sendBroadcast(Intent(ACTION_SYNC))
        sendBroadcast(Intent("com.example.breadth.TOKEN"), "com.example.breadth.PERMISSION")
        val internal = Intent().apply {
            action = "com.example.breadth.INTERNAL"
        }
        startActivity(internal)
        val explicit = Intent("com.example.breadth.INTERNAL").setPackage(packageName)
        startActivity(explicit)
        startActivity(Intent(Intent.ACTION_VIEW))
        startActivity(Intent("android.settings.SETTINGS"))
        LocalBroadcastManager.getInstance(this).sendBroadcast(Intent("com.example.breadth.LOCAL"))
    }
}
"""


def test_intent_redirection_and_implicit_internal_intents():
    found = ast("Router.kt", INTENTS_KT)
    assert found["AST-INTENT-REDIRECTION"] == [15, 17]
    assert found["AST-IMPLICIT-INTENT"] == [26, 27, 32]
    findings = analyze_sources([("Router.kt", INTENTS_KT)])["findings"]
    actions = {
        f["evidence"][0]["line"]: f["evidence"][0]["action"]
        for f in findings
        if f["rule_id"] == "AST-IMPLICIT-INTENT"
    }
    assert actions == {
        26: "com.example.breadth.TOKEN",
        27: "com.example.breadth.SYNC",
        32: "com.example.breadth.INTERNAL",
    }


PATHS_KT = """package com.example.breadth

import android.app.Activity
import android.content.Intent
import android.provider.OpenableColumns
import java.io.File
import java.io.FileOutputStream
import java.util.zip.ZipInputStream

class Files : Activity() {
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        val uri = data?.data ?: return
        var name = "default"
        contentResolver.query(uri, null, null, null, null)?.use {
            val index = it.getColumnIndex(OpenableColumns.DISPLAY_NAME)
            if (it.moveToFirst()) {
                name = it.getString(index)
            }
        }
        val target = File(filesDir, name)
        FileOutputStream(target).use { it.write(1) }
        val safe = File(filesDir, File(name).name)
        val extra = File(cacheDir, intent.getStringExtra("file") ?: "x")
    }

    fun unzip(stream: ZipInputStream, dir: File) {
        var entry = stream.nextEntry
        while (entry != null) {
            val out = File(dir, entry.name)
            entry = stream.nextEntry
        }
    }

    fun guarded(stream: ZipInputStream, dir: File) {
        val entry = stream.nextEntry ?: return
        val out = File(dir, entry.name)
        if (!out.canonicalPath.startsWith(dir.canonicalPath + File.separator)) {
            throw SecurityException("zip slip")
        }
    }

    fun local() {
        val file = File(filesDir, "settings.json")
    }
}
"""


def test_path_traversal_sources_sanitizers_and_guards():
    found = ast("Files.kt", PATHS_KT)
    assert found["AST-PATH-TRAVERSAL"] == [20, 23, 29]
    findings = analyze_sources([("Files.kt", PATHS_KT)])["findings"]
    kinds = {
        f["evidence"][0]["line"]: [s["kind"] for s in f["evidence"][0]["sources"]]
        for f in findings
        if f["rule_id"] == "AST-PATH-TRAVERSAL"
    }
    assert kinds[20] == ["Content provider display name"]
    assert kinds[29] == ["Archive entry name"]
    assert all(f["masvs"] == "MASVS-CODE" for f in findings if f["rule_id"] == "AST-PATH-TRAVERSAL")


PROVIDER_KT = """package com.example.breadth

import android.content.ContentProvider
import android.database.Cursor
import android.database.sqlite.SQLiteQueryBuilder
import android.net.Uri

class Outer {
    class Records : ContentProvider() {
        override fun query(uri: Uri, projection: Array<String>?, selection: String?, args: Array<String>?, sortOrder: String?): Cursor? {
            val qb = SQLiteQueryBuilder()
            qb.appendWhere("id=" + uri.pathSegments[1])
            return qb.query(db, projection, selection, args, null, null, sortOrder)
        }
    }
}
"""


def test_nested_exported_provider_and_query_builder_sinks(store, tmp_path, monkeypatch):
    monkeypatch.setenv("APSA_PARSER_SANDBOX", "off")
    root = tmp_path / "provider"
    root.mkdir()
    (root / "AndroidManifest.xml").write_text(
        '<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.example.breadth">'
        '<application><provider android:name="com.example.breadth.Outer$Records" '
        'android:authorities="com.example.records" android:exported="true" /></application></manifest>'
    )
    (root / "Outer.kt").write_text(PROVIDER_KT)
    report = scan(store, root)
    sql = by_rule(report, "AST-SQL-CONCAT")
    assert sorted((s["evidence"][0]["line"], s["evidence"][0]["sink_api"]) for s in sql) == [
        (12, "SQLiteQueryBuilder.appendWhere"),
        (13, "SQLiteQueryBuilder.query"),
    ]
    query = next(s for s in sql if s["evidence"][0]["line"] == 13)
    assert query["evidence"][0]["statement_scope"].startswith("argument 2, 6 is SQL syntax")


AUTH_KT = """package com.example.breadth

import androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_STRONG
import androidx.biometric.BiometricManager.Authenticators.DEVICE_CREDENTIAL
import androidx.biometric.BiometricPrompt
import android.security.keystore.KeyGenParameterSpec

class Login(private val prompt: BiometricPrompt) {
    private lateinit var secured: BiometricPrompt

    fun unlock(info: BiometricPrompt.PromptInfo, crypto: BiometricPrompt.CryptoObject, manager: AuthManager) {
        prompt.authenticate(info)
        secured.authenticate(info, crypto)
        manager.authenticate(info)
        val builder = BiometricPrompt.PromptInfo.Builder()
            .setAllowedAuthenticators(BIOMETRIC_STRONG or DEVICE_CREDENTIAL)
            .setDeviceCredentialAllowed(true)
        val strong = BiometricPrompt.PromptInfo.Builder().setAllowedAuthenticators(BIOMETRIC_STRONG)
        val spec = KeyGenParameterSpec.Builder("k", 3)
            .setInvalidatedByBiometricEnrollment(false)
    }
}
"""

AUTH_SWIFT = """import LocalAuthentication
import Security

final class Gate {
    func unlock() {
        let context = LAContext()
        if context.canEvaluatePolicy(.deviceOwnerAuthentication, error: nil) {
            context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: "Unlock") { success, _ in }
        }
    }
}
"""

KEYCHAIN_SWIFT = """import LocalAuthentication
import Security

final class Vault {
    func store() {
        let any = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleWhenUnlocked, .biometryAny, nil)
        let passcode = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleWhenUnlocked, [.biometryCurrentSet, .or, .devicePasscode], nil)
        let strict = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleWhenUnlocked, .biometryCurrentSet, nil)
        let context = LAContext()
        context.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, localizedReason: "Read") { _, _ in }
        let query: [String: Any] = [kSecAttrAccessControl as String: strict as Any, kSecUseAuthenticationContext as String: context]
    }
}
"""


def test_local_authentication_checks(store, tmp_path, monkeypatch):
    monkeypatch.setenv("APSA_PARSER_SANDBOX", "off")
    root = tmp_path / "auth"
    root.mkdir()
    (root / "AndroidManifest.xml").write_text(
        '<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.example.breadth"><application/></manifest>'
    )
    (root / "Info.plist").write_text(
        '<?xml version="1.0" encoding="UTF-8"?><plist version="1.0"><dict>'
        "<key>CFBundleIdentifier</key><string>com.example.breadth</string></dict></plist>"
    )
    (root / "Login.kt").write_text(AUTH_KT)
    (root / "Gate.swift").write_text(AUTH_SWIFT)
    (root / "Vault.swift").write_text(KEYCHAIN_SWIFT)
    report = scan(store, root)
    found = {
        rule: sorted((f["evidence"][0]["path"], f["evidence"][0]["line"]) for f in by_rule(report, rule))
        for rule in (
            "SOURCE-BIOMETRIC-EVENT-BOUND",
            "SOURCE-BIOMETRIC-FALLBACK",
            "SOURCE-BIOMETRIC-ENROLLMENT",
        )
    }
    # The bound file (Vault) evaluates a policy next to a Keychain access control; canEvaluatePolicy is a check.
    assert found["SOURCE-BIOMETRIC-EVENT-BOUND"] == [("Gate.swift", 8), ("Login.kt", 12)]
    assert found["SOURCE-BIOMETRIC-FALLBACK"] == [
        ("Gate.swift", 8),
        ("Login.kt", 16),
        ("Login.kt", 17),
        ("Vault.swift", 7),
    ]
    assert found["SOURCE-BIOMETRIC-ENROLLMENT"] == [("Login.kt", 20), ("Vault.swift", 6)]
    assert all(f["masvs"] == "MASVS-AUTH" for rule in found for f in by_rule(report, rule))


IOS_SOURCES = {
    "Net.swift": """import Network
import Foundation

final class Net {
    func open(host: NWEndpoint.Host) {
        let plain = NWConnection(host: host, port: 80, using: .tcp)
        let secure = NWConnection(host: host, port: 443, using: .tls)
        let configuration = URLSessionConfiguration.default
        configuration.tlsMinimumSupportedProtocolVersion = .TLSv11
        configuration.tlsMinimumSupportedProtocolVersion = .TLSv12
        let fd = socket(AF_INET, SOCK_STREAM, 0)
    }
}
""",
    "Web.swift": """import UIKit
import WebKit

final class Web {
    private static let docs = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first!

    func show(page: URL) {
        let legacy = UIWebView()
        let other = UIWebView(frame: .zero)
        let view = WKWebView()
        view.configuration.preferences.setValue(true, forKey: "allowFileAccessFromFileURLs")
        view.loadFileURL(page, allowingReadAccessTo: Web.docs)
        view.loadFileURL(page, allowingReadAccessTo: page.deletingLastPathComponent())
    }
}
""",
    "Archive.swift": """import Foundation

final class Archive {
    func read(data: Data) throws {
        let legacy = NSKeyedUnarchiver.unarchiveObject(with: data)
        let unarchiver = try NSKeyedUnarchiver(forReadingFrom: data)
        unarchiver.requiresSecureCoding = false
        let safe = try NSKeyedUnarchiver.unarchivedObject(ofClass: NSString.self, from: data)
    }
}
""",
    "Crypto.m": """#import <CommonCrypto/CommonCrypto.h>

void encrypt(void) {
    CCCrypt(kCCEncrypt, kCCAlgorithmDES, kCCOptionPKCS7Padding, key, 8, NULL, input, 16, output, 32, &moved);
    CCCrypt(kCCEncrypt, kCCAlgorithmAES, kCCOptionECBMode, key, 16, NULL, input, 16, output, 32, &moved);
    CCCrypt(kCCEncrypt, kCCAlgorithmAES, kCCOptionPKCS7Padding, key, 16, iv, input, 16, output, 32, &moved);
    NSDictionary *attributes = @{ (id)kSecAttrKeyType: (id)kSecAttrKeyTypeRSA, (id)kSecAttrKeySizeInBits: @1024 };
}
""",
}


def test_ios_source_patterns(store, tmp_path, monkeypatch):
    monkeypatch.setenv("APSA_PARSER_SANDBOX", "off")
    root = tmp_path / "ios"
    root.mkdir()
    (root / "Info.plist").write_text(
        '<?xml version="1.0" encoding="UTF-8"?><plist version="1.0"><dict>'
        "<key>CFBundleIdentifier</key><string>com.example.breadth</string></dict></plist>"
    )
    for name, text in IOS_SOURCES.items():
        (root / name).write_text(text)
    report = scan(store, root)

    def at(rule: str) -> list[tuple[str, int]]:
        return sorted((f["evidence"][0]["path"], f["evidence"][0]["line"]) for f in by_rule(report, rule))

    assert at("IOS-ATS-BYPASS-API") == [("Net.swift", 6), ("Net.swift", 11)]
    assert at("SOURCE-WEAK-TLS-VERSION") == [("Net.swift", 9)]
    # A deprecated class is reported once per file.
    assert at("IOS-UIWEBVIEW") == [("Web.swift", 8)]
    assert at("IOS-WEBVIEW-FILE-ACCESS") == [("Web.swift", 11), ("Web.swift", 12)]
    assert at("IOS-INSECURE-UNARCHIVE") == [("Archive.swift", 5), ("Archive.swift", 7)]
    assert at("IOS-CRYPTO-WEAK-CIPHER") == [("Crypto.m", 4), ("Crypto.m", 5)]
    assert at("SOURCE-WEAK-KEY-SIZE") == [("Crypto.m", 7)]


ANDROID_SOURCES = {
    "Web.kt": """package com.example.breadth

class Web {
    fun configure(view: android.webkit.WebView) {
        view.settings.safeBrowsingEnabled = false
        view.settings.safeBrowsingEnabled = true
    }
}
""",
    "Tls.java": """package com.example.breadth;

import javax.net.ssl.SSLContext;
import java.security.KeyPairGenerator;

class Tls {
    void open() throws Exception {
        SSLContext legacy = SSLContext.getInstance("TLSv1");
        SSLContext current = SSLContext.getInstance("TLSv1.2");
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(1024);
        generator.initialize(2048);
    }
}
""",
}


def test_android_source_patterns(store, android):
    (android / "AndroidManifest.xml").write_text(
        ANDROID_MANIFEST.replace(
            "</application>",
            '<meta-data android:name="android.webkit.WebView.EnableSafeBrowsing" android:value="false" /></application>',
        )
    )
    for name, text in ANDROID_SOURCES.items():
        (android / name).write_text(text)
    report = scan(store, android)

    def at(rule: str) -> list[tuple[str, int]]:
        return sorted((f["evidence"][0]["path"], f["evidence"][0]["line"]) for f in by_rule(report, rule))

    assert at("WEBVIEW-SAFE-BROWSING-OFF") == [("AndroidManifest.xml", 27), ("Web.kt", 5)]
    assert at("SOURCE-WEAK-TLS-VERSION") == [("Tls.java", 8)]
    assert at("SOURCE-WEAK-KEY-SIZE") == [("Tls.java", 11)]


def test_insecure_random_on_apple_sources(store, tmp_path, monkeypatch):
    monkeypatch.setenv("APSA_PARSER_SANDBOX", "off")
    root = tmp_path / "random"
    root.mkdir()
    (root / "Info.plist").write_text(
        '<?xml version="1.0" encoding="UTF-8"?><plist version="1.0"><dict>'
        "<key>CFBundleIdentifier</key><string>com.example.breadth</string></dict></plist>"
    )
    (root / "Token.swift").write_text(
        "import GameplayKit\n"
        "func make() {\n"
        "    let sessionToken = String(random())\n"
        "    let nonce = GKMersenneTwisterRandomSource().nextInt()\n"
        "    let secure = UInt64.random(in: 0...UInt64.max)\n"
        "    let delay = Double(random()) / 2\n"
        "}\n"
    )
    report = scan(store, root)
    assert lines(report, "SOURCE-INSECURE-RANDOM") == [3, 4]


def test_new_rules_have_catalog_entries_and_maswe_mapping():
    from mobile_audit.rules import rules

    catalog = {rule["id"]: rule for rule in rules()}
    new = [
        "AST-CRYPTO-WEAK-CIPHER",
        "IOS-CRYPTO-WEAK-CIPHER",
        "AST-CRYPTO-STATIC-IV",
        "AST-CRYPTO-HARDCODED-KEY",
        "SOURCE-WEAK-KEY-SIZE",
        "SOURCE-BIOMETRIC-EVENT-BOUND",
        "SOURCE-BIOMETRIC-FALLBACK",
        "SOURCE-BIOMETRIC-ENROLLMENT",
        "SOURCE-WEAK-TLS-VERSION",
        "IOS-ATS-BYPASS-API",
        "ANDROID-NSC-USER-CA",
        "ANDROID-DEEPLINK-AUTOVERIFY",
        "AST-INTENT-REDIRECTION",
        "AST-IMPLICIT-INTENT",
        "IOS-WEBVIEW-FILE-ACCESS",
        "WEBVIEW-SAFE-BROWSING-OFF",
        "IOS-UIWEBVIEW",
        "AST-PATH-TRAVERSAL",
        "IOS-INSECURE-UNARCHIVE",
    ]
    for rule in new:
        assert rule in catalog, rule
        assert weaknesses_for(rule) and catalog[rule]["maswe"] == list(weaknesses_for(rule)), rule
        assert catalog[rule]["references"], rule


def test_swift_only_projects_mark_android_structural_rules_not_applicable(tmp_path: Path):
    result = analyze_sources([("A.swift", "func f() {}\n")])
    states = {c["rule_id"]: c["state"] for c in result["coverage"]}
    for rule in ("AST-CRYPTO-WEAK-CIPHER", "AST-INTENT-REDIRECTION", "AST-IMPLICIT-INTENT"):
        assert states[rule] == "not-applicable"
    for rule in ("AST-CRYPTO-HARDCODED-KEY", "AST-CRYPTO-STATIC-IV", "AST-PATH-TRAVERSAL"):
        assert states[rule] == "checked"


def test_evaluate_policy_declarations_are_not_calls():
    from mobile_audit.platform_checks import _apple_auth

    swift = (
        "protocol LAContextProtocol {\n"
        "    func evaluatePolicy(_ policy: LAPolicy, localizedReason: String, reply: @escaping (Bool, Error?) -> Void)\n"
        "}\n"
        "final class Mock: LAContextProtocol {\n"
        "    func evaluatePolicy(_ policy: LAPolicy, localizedReason: String, reply: @escaping (Bool, Error?) -> Void) {}\n"
        "}\n"
        'func real(context: LAContext) { context.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, localizedReason: "x") { _, _ in } }\n'
    )
    objc = (
        "- (void)evaluatePolicy:(LAPolicy)policy reply:(id)reply {}\n"
        'void f(LAContext *c) { [c evaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometrics localizedReason:@"x" reply:nil]; }\n'
    )
    assert [f["evidence"][0]["line"] for f in _apple_auth("A.swift", swift)] == [7]
    assert [f["evidence"][0]["line"] for f in _apple_auth("A.m", objc)] == [2]
