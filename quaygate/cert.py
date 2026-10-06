"""v1(JAR) 서명 인증서 점검 — openssl 선택 연동.

openssl이 없으면 확인불가로 물러난다(의존성 0 원칙 유지). 출력 포맷은
OpenSSL/LibreSSL 세대 차이가 있어 느슨하게 파싱한다.
"""
from __future__ import annotations

import shutil
import subprocess
import re
from datetime import datetime

DEBUG_MARKERS = ("Android Debug", "androiddebugkey")


def _default_runner(args, data=None):
    binary = shutil.which("openssl")
    if binary is None:
        return None
    try:
        proc = subprocess.run([binary, *args], input=data, capture_output=True, timeout=20)
    except (OSError, subprocess.TimeoutExpired):
        return None
    return proc.returncode, proc.stdout.decode("utf-8", "replace"), proc.stderr.decode("utf-8", "replace")


def _parse_not_after(text: str):
    for line in text.splitlines():
        if line.startswith("notAfter="):
            raw = line.split("=", 1)[1].strip()
            match = re.fullmatch(r"([A-Z][a-z]{2})\s+(\d{1,2})\s+\d{2}:\d{2}:\d{2}\s+(\d{4})\s+GMT", raw)
            if match:
                months = "Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec".split()
                try:
                    return datetime(int(match[3]), months.index(match[1]) + 1, int(match[2])).date()
                except ValueError:
                    continue
            for fmt in ("%Y-%m-%d %H:%M:%S",):
                try:
                    return datetime.strptime(raw, fmt).date()
                except ValueError:
                    continue
    return None


def analyze_v1_certificate(cert_der: bytes, runner=None) -> dict:
    """PKCS#7 DER 인증서 분석. 실패 시 {"error": 사유} 반환."""
    runner = runner or _default_runner
    if runner is _default_runner and shutil.which("openssl") is None:
        return {"error": "openssl 미설치"}

    out = runner(["pkcs7", "-inform", "DER", "-print_certs"], cert_der)
    if out is None:
        return {"error": "openssl 실행 불가"}
    rc, stdout, stderr = out
    if rc != 0:
        return {"error": f"pkcs7 파싱 실패: {(stderr or stdout).strip()[:120]}"}

    info = runner(["x509", "-noout", "-subject", "-enddate"], stdout.encode("utf-8", "replace"))
    if info is None:
        return {"error": "openssl x509 실행 불가"}
    rc2, out2, err2 = info
    if rc2 != 0:
        # PEM이 여러 장일 수 있으니 첫 블록만 다시 시도
        first = stdout[stdout.find("-----BEGIN CERTIFICATE-----"):]
        end = first.find("-----END CERTIFICATE-----")
        if end > 0:
            info = runner(["x509", "-noout", "-subject", "-enddate"],
                          first[: end + len("-----END CERTIFICATE-----")].encode())
            if info is None or info[0] != 0:
                return {"error": "x509 파싱 실패"}
            rc2, out2, err2 = info
        else:
            return {"error": f"x509 파싱 실패: {(err2 or out2).strip()[:120]}"}

    subject = ""
    for line in out2.splitlines():
        if line.startswith("subject"):
            subject = line.split("=", 1)[1].strip() if "=" in line else line
            break
    # 마커는 subject/issuer 라인에서만 매칭 — PEM 본문(base64) 전체 스캔은 오탐 표면
    meta_text = "\n".join(
        line for line in (out2 + "\n" + stdout).splitlines()
        if line.lower().startswith(("subject", "issuer")))
    debug = any(marker.lower() in meta_text.lower() for marker in DEBUG_MARKERS)
    not_after = _parse_not_after(out2)
    expired = None if not_after is None else not_after < datetime.now().date()
    result = {"debug": debug, "expired": expired, "subject": subject, "not_after": str(not_after or "")}
    if not_after is None:
        result["error"] = "인증서 만료 날짜 판단 불가"
    return result
