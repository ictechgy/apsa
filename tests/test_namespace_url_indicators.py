"""Exact metadata identifiers must not erase real or ambiguous HTTP candidates."""

import pytest

from quaygate.apk import Apk
from quaygate.appchecks import audit_apk
from quaygate.indicators import audit_strings, scan_strings
from quaygate.ipa import Ipa, audit_ipa
from tests.helpers import temp_apk, temp_ipa

ANDROID_NS = "http://schemas.android.com/apk/res/android"


@pytest.mark.parametrize(
    "identifier",
    [
        ANDROID_NS,
        "http://schemas.android.com/apk/res-auto",
        "http://ns.adobe.com/xap/1.0/",
        "http://www.w3.org/XML/1998/namespace",
        "http://www.w3.org/2000/svg",
        "http://www.w3.org/ns/ttml#parameter",
        "http://purl.org/dc/elements/1.1/",
        "http://purl.org/rss/1.0/modules/content/",
        "http://podlove.org/simple-chapters",
        "http://xml.org/sax/features/external-general-entities",
        "http://xml.org/sax/properties/lexical-handler",
        "http://apache.org/xml/features/nonvalidating/load-external-dtd",
    ],
)
def test_exact_metadata_identifiers_are_not_endpoint_candidates(identifier: str) -> None:
    assert scan_strings([identifier])["http_hosts"] == []


@pytest.mark.parametrize(
    "candidate",
    [
        "http://schemas.android.com/login",
        "http://schemas.android.com/apk/res/android/credentials",
        "http://schemas.android.com/apk/res/android.evil.example",
        "http://schemas.android.com.evil.example/apk/res/android",
        "http://schemas.android.com@evil.example/apk/res/android",
        "http://user@schemas.android.com/apk/res/android",
        "http://schemas.android.com:80/apk/res/android",
        ANDROID_NS + "?token=secret",
        ANDROID_NS + "#login",
        ANDROID_NS + ")",
        ANDROID_NS + ",http://api.example.test/login",
        ANDROID_NS + "\\@evil.example",
        ANDROID_NS + "\\n",
        ANDROID_NS + "\x00suffix",
        "http://ns.adobe.com/xap/1.0/\ufffd\ufffd",
        "http://xml.org/sax/features/send-credentials",
        "http://apache.org/xml/features/nonvalidating/load-external-dtd?user=secret",
        "http://www.itunes.com/dtds/podcast-1.0.dtd",
    ],
)
def test_uncertain_and_nonmetadata_urls_remain_candidates(candidate: str) -> None:
    assert scan_strings([candidate])["http_hosts"]


def test_namespace_and_real_endpoint_on_same_host_retains_warning() -> None:
    strings = [ANDROID_NS, "http://schemas.android.com/login"]
    assert scan_strings(strings)["http_hosts"] == ["schemas.android.com"]
    finding = audit_strings(strings, "dex", "synthetic", groups={"cleartext-urls"})[0]
    assert finding.status == "warn"
    assert "실제 네트워크 사용은 미확인" in finding.detail


def test_quoted_namespace_and_adjacent_real_url_are_scanned_independently() -> None:
    value = f'<x xmlns="{ANDROID_NS}" href="http://api.example.test/login"/>'
    assert scan_strings([value])["http_hosts"] == ["api.example.test"]


def test_other_indicator_groups_stay_visible() -> None:
    value = ANDROID_NS + " AKIAIOSFODNN7EXAMPLE AES/ECB setAllowFileAccess com.facebook.ads"
    observed = scan_strings([value])
    assert observed["http_hosts"] == []
    assert observed["secrets"]
    assert observed["weak_crypto"] == ["AES/ECB"]
    assert observed["webview"] == ["setAllowFileAccess"]
    assert observed["trackers"] == ["com.facebook."]


def test_apk_dex_namespace_only_and_real_endpoint_controls() -> None:
    with temp_apk(dex=[ANDROID_NS]) as path:
        with Apk(path) as apk:
            findings = audit_apk(apk)[1]
    assert next(f for f in findings if f.check_id == "dex-cleartext-urls").status == "pass"
    with temp_apk(dex=[ANDROID_NS, "http://schemas.android.com/login"]) as path:
        with Apk(path) as apk:
            findings = audit_apk(apk)[1]
    assert next(f for f in findings if f.check_id == "dex-cleartext-urls").status == "warn"


def test_ipa_binary_namespace_only_and_real_endpoint_controls() -> None:
    for suffix, expected in [(b"", "pass"), (b"http://schemas.android.com/login\x00", "warn")]:
        with temp_ipa(binary=b"\x00" + ANDROID_NS.encode() + b"\x00" + suffix) as path:
            with Ipa(path) as ipa:
                findings = audit_ipa(ipa)[1]
        assert next(f for f in findings if f.check_id == "bin-cleartext-urls").status == expected
