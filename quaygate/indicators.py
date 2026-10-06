"""문자열 지표 스캐너 — APK DEX 문자열 / IPA 바이너리 문자열 공용.

문자열 존재만으로 취약 여부를 단언할 수 없다. 모든 결과는 '지표(휴리스틱)'로
표기하며, 심각도는 지표가 실제 문제일 때의 전형적 영향을 따른다.
"""
from __future__ import annotations

import re

from .checks import Finding, HIGH, INFO, LOW, MEDIUM

# 서버 측 비밀 — 하드코드면 즉시 심각
SECRET_PATTERNS = [
    ("AWS 액세스 키 ID", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("Stripe 라이브 시크릿", re.compile(r"\bsk_live_[0-9a-zA-Z]{16,}\b")),
    ("GitHub 토큰", re.compile(r"\bgh[pousr]_[0-9A-Za-z]{20,}\b")),
    ("Slack 토큰", re.compile(r"\bxox[baprs]-[0-9A-Za-z\-]{10,}\b")),
]
# 앱 내장이 전제인 공개 키(Maps/Firebase 등) — 심각 아님, 제한 확인 권고
EMBEDDED_KEY_PATTERNS = [
    ("Google API 키", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
]
WEAK_CRYPTO_TOKENS = ("AES/ECB", "DES/", "DESede", "RC4")
WEAK_HASH_TOKENS = ("MD5", "SHA1", "SHA-1")
WEBVIEW_TOKENS = (
    "setAllowFileAccess",
    "setAllowUniversalAccessFromFileURLs",
    "setSavePassword",
    "addJavascriptInterface",
    "setJavaScriptEnabled",
)
TRACKER_PREFIXES = (
    "com.facebook.", "com.facebook.audience", "com.google.android.gms.ads",
    "com.google.android.gms.measurement", "com.adjust.sdk", "com.appsflyer",
    "com.amplitude.api", "com.mixpanel", "io.branch.referral", "com.segment.analytics",
    "com.kochava", "com.tenjin.android", "com.flurry", "com.umeng", "com.tencent.stat",
    "com.tencent.mta", "com.applovin", "com.mintegral", "com.ironsource",
    "com.unity3d.ads", "com.bytedance.sdk.openadsdk",
)
URL_RE = re.compile(r"https?://[A-Za-z0-9.\-]+(?::\d+)?[^\s\"'<>\\]*")


def _mask(secret: str) -> str:
    return secret[:8] + "…" if len(secret) > 8 else secret


def scan_strings(strings: list) -> dict:
    http_hosts, secrets, embedded, weak, webview, trackers = set(), [], [], set(), set(), set()
    for s in strings:
        if not s:
            continue
        for m in URL_RE.finditer(s):
            url = m.group(0)
            if url.startswith("http://"):
                host = re.sub(r"^http://", "", url).split("/")[0].split(":")[0]
                http_hosts.add(host)
        for label, pattern in SECRET_PATTERNS:
            for m in pattern.finditer(s):
                secrets.append(f"{label}: {_mask(m.group(0))}")
        for label, pattern in EMBEDDED_KEY_PATTERNS:
            for m in pattern.finditer(s):
                embedded.append(f"{label}: {_mask(m.group(0))}")
        for token in WEAK_CRYPTO_TOKENS:
            if token in s:
                weak.add(token)
        for token in WEAK_HASH_TOKENS:
            if token in s:
                weak.add(token)
        for token in WEBVIEW_TOKENS:
            if token in s:
                webview.add(token)
        for prefix in TRACKER_PREFIXES:
            if prefix in s:
                trackers.add(prefix)
    return {
        "http_hosts": sorted(http_hosts),
        "secrets": sorted(set(secrets)),
        "embedded_keys": sorted(set(embedded)),
        "weak_crypto": sorted(weak),
        "webview": sorted(webview),
        "trackers": sorted(trackers),
    }


def audit_strings(strings: list, prefix: str, heuristics_note: str, groups=None) -> list:
    """groups: 포함할 지표 집합(secrets/weak-crypto/cleartext-urls/webview/trackers). None이면 전부."""
    scan = scan_strings(strings)
    findings = []

    def wanted(group):
        return groups is None or group in groups

    if scan["secrets"] and wanted("secrets"):
        findings.append(Finding(
            f"{prefix}-secrets", "하드코드 시크릿 지표", "fail", HIGH,
            f"공개 패턴과 일치: {'; '.join(scan['secrets'][:5])}"
            + (f" 외 {len(scan['secrets']) - 5}건" if len(scan['secrets']) > 5 else "")
            + f" ({heuristics_note})",
            "문자열 패턴 일치이므로 실제 사용 여지를 확인하세요. 시크릿은 빌드 주입으로 옮기고 노출된 키는 폐기·재발급하세요.",
        ))
    elif wanted("secrets"):
        findings.append(Finding(f"{prefix}-secrets", "하드코드 시크릿 지표", "pass", None,
                                f"공개 패턴 일치 없음 ({heuristics_note})."))
    if scan.get("embedded_keys") and wanted("secrets"):
        findings.append(Finding(
            f"{prefix}-embedded-keys", "앱 내장 공개 키", "warn", MEDIUM,
            f"앱 포함이 전제인 키 패턴: {'; '.join(scan['embedded_keys'][:5])} ({heuristics_note})",
            "Maps/Firebase 등 앱 내장 키입니다. API/앱/HTTP 리퍼러 제한과 키 감사를 확인하세요.",
        ))
    if scan["weak_crypto"] and wanted("weak-crypto"):
        findings.append(Finding(
            f"{prefix}-weak-crypto", "약한 암호 알고리즘 지표", "warn", MEDIUM,
            f"문자열 발견: {', '.join(scan['weak_crypto'])} ({heuristics_note})",
            "암호 변환·해시 선택에 실제로 쓰이는지 확인하고, 그렇다면 AES-GCM/SHA-256 이상으로 교체하세요.",
        ))
    elif wanted("weak-crypto"):
        findings.append(Finding(f"{prefix}-weak-crypto", "약한 암호 알고리즘 지표", "pass", None,
                                f"해당 없음 ({heuristics_note})."))
    if scan["http_hosts"] and wanted("cleartext-urls"):
        findings.append(Finding(
            f"{prefix}-cleartext-urls", "평문(http) URL 지표", "warn", LOW,
            f"{len(scan['http_hosts'])}개 호스트: {', '.join(scan['http_hosts'][:5])}"
            + (f" 외" if len(scan['http_hosts']) > 5 else "")
            + f" ({heuristics_note})",
            "평문 엔드포인트가 실제 사용 중인지 확인하고 HTTPS로 전환하세요.",
        ))
    elif wanted("cleartext-urls"):
        findings.append(Finding(f"{prefix}-cleartext-urls", "평문(http) URL 지표", "pass", None,
                                f"해당 없음 ({heuristics_note})."))
    if scan["webview"] and wanted("webview"):
        findings.append(Finding(
            f"{prefix}-webview", "WebView 설정 지표", "info", INFO,
            f"문자열 발견: {', '.join(scan['webview'])} ({heuristics_note})",
            "파일 접근·JS 인터페이스 사용 시 신뢰하는 콘텐츠만 로드하는지 확인하세요.",
        ))
    elif wanted("webview"):
        findings.append(Finding(f"{prefix}-webview", "WebView 설정 지표", "pass", None,
                                f"해당 없음 ({heuristics_note})."))
    if scan["trackers"] and wanted("trackers"):
        findings.append(Finding(
            f"{prefix}-trackers", "임베디드 추적 SDK 지표", "info", INFO,
            f"{len(scan['trackers'])}개: {', '.join(scan['trackers'])} ({heuristics_note})",
            "광고·분석 SDK가 포함되어 있습니다. 개인정보 처리 고지와 최소화를 검토하세요.",
        ))
    elif wanted("trackers"):
        findings.append(Finding(f"{prefix}-trackers", "임베디드 추적 SDK 지표", "pass", None,
                                f"알려진 추적 SDK 패턴 없음 ({heuristics_note})."))
    return findings
