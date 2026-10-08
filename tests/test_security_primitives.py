"""Risk controls independent of the fixed competitive corpus."""

from __future__ import annotations

import pytest

from mobile_audit.rules import static_checks
from mobile_audit.source_analysis import analyze_sources


def inspect(text: str, suffix: str = "java") -> tuple[dict, set[str]]:
    path = "Independent." + suffix
    report = analyze_sources([(path, text)])
    return report, {item["rule_id"] for item in report["findings"]}


@pytest.mark.parametrize("algorithm,expected", [("AES/ECB/NoPadding", True), ("AES/GCM/NoPadding", False)])
def test_framework_cipher_transformation_is_a_candidate(algorithm, expected):
    report, ids = inspect(
        'import javax.crypto.Cipher; class Probe { void encrypt() throws Exception { Cipher.getInstance("'
        + algorithm
        + '"); } }'
    )
    assert ("AST-CRYPTO-ECB" in ids) is expected
    if expected:
        assert report["findings"][0]["status"] == "candidate"


@pytest.mark.parametrize(
    "shadow",
    [
        "class Cipher { static Object getInstance(String s) { return null; } }",
        'class Probe { Object Cipher; void encrypt() { Cipher.getInstance("AES/ECB/NoPadding"); } }',
        'class Probe { void encrypt(Custom Cipher) { Cipher.getInstance("AES/ECB/NoPadding"); } }',
    ],
)
def test_same_named_local_crypto_receiver_is_not_a_framework_proof(shadow):
    source = "import javax.crypto.Cipher; " + shadow
    if shadow.startswith("class Cipher"):
        source += ' class Probe { void encrypt() { Cipher.getInstance("AES/ECB/NoPadding"); } }'
    assert "AST-CRYPTO-ECB" not in inspect(source)[1]


@pytest.mark.parametrize("algorithm,expected", [("SHA-1", True), ("SHA-256", False)])
def test_qualified_digest_does_not_claim_a_verified_security_purpose(algorithm, expected):
    report, ids = inspect(
        'class DigestProbe { void check() throws Exception { java.security.MessageDigest.getInstance("'
        + algorithm
        + '"); } }'
    )
    assert ("AST-CRYPTO-WEAK-HASH" in ids) is expected
    if expected:
        assert report["findings"][0]["evidence"][0]["security_purpose"] == "unverified"


@pytest.mark.parametrize(
    "body,expected",
    [
        ("values.withUnsafeBytes { buffer in CC_SHA1(buffer.baseAddress, 0, nil) }", True),
        ("CC_SHA256(nil, 0, nil)", False),
    ],
)
def test_swift_digest_inside_a_trailing_closure_is_inspected(body, expected):
    report, ids = inspect("import CommonCrypto\nfunc checksum(_ values: Data) { " + body + " }", "swift")
    assert not report["warnings"]
    assert ("AST-CRYPTO-WEAK-HASH" in ids) is expected


def test_local_swift_digest_function_is_not_attributed_to_commoncrypto():
    source = "import CommonCrypto\nfunc CC_MD5(_ x: Int) {}\nfunc checksum() { CC_MD5(1) }"
    assert "AST-CRYPTO-WEAK-HASH" not in inspect(source, "swift")[1]


@pytest.mark.parametrize(
    "statement,expected",
    [
        ('db.execSQL("DELETE FROM accounts WHERE name=" + alias);', True),
        ('db.execSQL("DELETE FROM accounts WHERE name=?", new Object[]{alias});', False),
    ],
)
def test_only_sql_statement_argument_receives_platform_input(statement, expected):
    source = (
        'import android.database.sqlite.SQLiteDatabase; import android.content.Intent; class Probe { void erase(Intent incoming, SQLiteDatabase db) { String name = incoming.getStringExtra("name"); String alias = name; '
        + statement
        + " } }"
    )
    report, ids = inspect(source)
    assert ("AST-SQL-CONCAT" in ids) is expected
    if expected:
        assert report["findings"][0]["evidence"][0]["sources"]


def test_custom_database_api_is_not_a_platform_sql_sink():
    source = 'class Probe { void erase(Intent incoming, LocalDatabase db) { db.rawQuery(incoming.getStringExtra("name"), null); } }'
    assert "AST-SQL-CONCAT" not in inspect(source)[1]


@pytest.mark.parametrize(
    "call,expected",
    [
        ('Log.i("audit", "password=[REDACTED]")', False),
        ('Log.i("audit", "password=[REDACTED]" + password)', True),
        ('Log.i("audit", "password=[REDACTED]", error)', True),
        ('Log.i("audit", "password=real [REDACTED]")', True),
        ('Log.i("password=[REDACTED]", "email=visible@example.test")', True),
        ('Log.i("password=[REDACTED]", "visible-value")', True),
    ],
)
def test_redaction_marker_cannot_hide_other_sensitive_log_content(call, expected):
    source = "/* 한글 주석 */ class Probe { void audit(String password, Throwable error) { " + call + "; } }"
    report, _ = inspect(source)
    findings, _ = static_checks(
        {"platforms": ["android"], "android_config": [], "ios_config": []},
        [("Independent.java", source)],
        report["pattern_exclusions"],
    )
    assert ("STORAGE-SENSITIVE-LOG" in {f["rule_id"] for f in findings}) is expected


def test_redacted_and_live_log_calls_on_the_same_line_keep_live_evidence():
    source = (
        'class Probe { void audit(String token) { Log.d("tag", "token=[REDACTED]"); Log.d("tag", token); } }'
    )
    report, _ = inspect(source)
    findings, _ = static_checks(
        {"platforms": ["android"], "android_config": [], "ios_config": []},
        [("Independent.java", source)],
        report["pattern_exclusions"],
    )
    assert any(f["rule_id"] == "STORAGE-SENSITIVE-LOG" for f in findings)


def test_pattern_alerts_remain_when_no_ast_proof_is_available():
    source = 'Log.d("tag", "token=[REDACTED]");'
    findings, _ = static_checks(
        {"platforms": ["android"], "android_config": [], "ios_config": []}, [("Independent.java", source)]
    )
    assert any(f["rule_id"] == "STORAGE-SENSITIVE-LOG" for f in findings)


def test_kotlin_explicit_framework_cipher_is_detected():
    source = 'import javax.crypto.Cipher\nfun encrypt() { Cipher.getInstance("AES/ECB/PKCS5Padding") }'
    assert "AST-CRYPTO-ECB" in inspect(source, "kt")[1]


def test_swift_interpolation_keeps_sensitive_log_alert():
    source = r'func audit(token: String) { print("token=[REDACTED] \(token)") }'
    report, _ = inspect(source, "swift")
    findings, _ = static_checks(
        {"platforms": ["ios"], "android_config": [], "ios_config": []},
        [("Independent.swift", source)],
        report["pattern_exclusions"],
    )
    assert any(f["rule_id"] == "STORAGE-SENSITIVE-LOG" for f in findings)


def test_inherited_local_handler_does_not_establish_non_sdk_proceed():
    source = "class LocalHandler extends SslErrorHandler {} class Probe { void next(LocalHandler handler) { handler.proceed(); } }"
    report, _ = inspect(source)
    assert not report["pattern_exclusions"].get("Independent.java", {}).get("WEBVIEW-SSL-BYPASS")


def test_syntax_recovery_cannot_suppress_a_pattern_alert():
    source = 'class Probe { void audit() { Log.d("tag", "token=[REDACTED]"); } } broken $$$'
    report, _ = inspect(source)
    assert report["warnings"]
    assert not report["pattern_exclusions"]
