"""기기 단위 보안 점검 규칙.

모든 점검은 읽기 전용 adb 명령만 사용한다(getprop/settings/getenforce/locksettings/appops/bmgr).
설정 변경·잠금 우회·데이터 추출 동작은 하지 않는다 — 본인 기기 자가 점검이 전제다.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import date

from .adb import AdbError

HIGH = "HIGH"
MEDIUM = "MEDIUM"
LOW = "LOW"
INFO = "INFO"

SEVERITY_LABEL = {HIGH: "높음", MEDIUM: "보통", LOW: "낮음", INFO: "정보"}
STATUS_LABEL = {
    "pass": "통과",
    "warn": "경고",
    "fail": "심각",
    "info": "정보",
    "na": "확인불가",
    "error": "오류",
}
SEVERITY_ORDER = {HIGH: 0, MEDIUM: 1, LOW: 2, INFO: 3}

# 참고용 버전 정책(2026-10 기준). 제조사 지원 기간 편차가 커 상수로 분리했다.
VERSION_POLICY = {
    "min_release": 13,        # 이보다 오래된 메이저 버전은 지원 종료 가능성
    "patch_warn_months": 6,   # 보안 패치가 이 개월보다 오래되면 경고
    "patch_fail_months": 12,  # 이 개월보다 오래되면 심각
}


@dataclass
class Finding:
    check_id: str
    title: str
    status: str            # pass | warn | fail | info | na | error
    severity: str | None   # HIGH/MEDIUM/LOW/INFO — pass·na·error면 None
    detail: str = ""
    recommendation: str = ""


def parse_getprop(text: str) -> dict:
    props = {}
    for m in re.finditer(r"^\[([^\]]+)\]:\s*\[(.*)\]$", text, re.MULTILINE):
        props[m.group(1)] = m.group(2)
    return props


def months_between(old: date, new: date) -> int:
    return (new.year - old.year) * 12 + (new.month - old.month)


def _get_setting(runner, namespace: str, key: str) -> str:
    return runner.shell("settings", "get", namespace, key).strip()


def check_patch_level(props: dict, today: date | None = None) -> Finding:
    today = today or date.today()
    title = "보안 패치 수준"
    raw = props.get("ro.build.version.security_patch", "")
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", raw or ""):
        return Finding(
            "patch-level", title, "warn", MEDIUM,
            f"보안 패치 수준을 읽지 못했습니다(읽은 값: {raw or '없음'}).",
            "설정 > 시스템 > 정보에서 보안 패치 수준을 확인하고 최신으로 업데이트하세요.",
        )
    patch = date.fromisoformat(raw)
    months = months_between(patch, today)
    if months < 0:
        return Finding("patch-level", title, "na", None,
                       f"보안 패치 날짜가 미래입니다({raw}) — 기기 시계 또는 빌드 시각 이상.",
                       "기기 시간 설정을 확인하세요.")
    if months > VERSION_POLICY["patch_fail_months"]:
        return Finding(
            "patch-level", title, "fail", HIGH,
            f"보안 패치가 {months}개월째 갱신되지 않았습니다({raw}).",
            "OS 업데이트를 실행해 최신 보안 패치를 적용하세요.",
        )
    if months > VERSION_POLICY["patch_warn_months"]:
        return Finding(
            "patch-level", title, "warn", MEDIUM,
            f"보안 패치가 {months}개월째 갱신되지 않았습니다({raw}).",
            "OS 업데이트를 실행해 최신 보안 패치를 적용하세요.",
        )
    return Finding("patch-level", title, "pass", None, f"최신 편({raw}, {months}개월 전).")


def check_android_version(props: dict) -> Finding:
    title = "Android 버전"
    release = props.get("ro.build.version.release", "")
    m = re.search(r"\d+", release)
    if not m:
        return Finding("android-version", title, "na", None, f"버전 확인 불가(읽은 값: {release or '없음'}).")
    if int(m.group(0)) < VERSION_POLICY["min_release"]:
        return Finding(
            "android-version", title, "warn", MEDIUM,
            f"Android {release} — 메이저 {VERSION_POLICY['min_release']} 미만은 제조사 보안 지원이 종료됐을 가능성이 큽니다.",
            "지원 중인 버전으로 업데이트하거나 기기 교체를 고려하세요.",
        )
    return Finding("android-version", title, "pass", None, f"Android {release}.")


def check_crypto_state(props: dict) -> Finding:
    title = "저장 암호화"
    state = props.get("ro.crypto.state")
    if state == "encrypted":
        return Finding("encryption", title, "pass", None, "기기 저장소 암호화 활성.")
    if state in ("unsupported", "unencrypted"):
        return Finding(
            "encryption", title, "fail", HIGH,
            f"기기 저장소 암호화가 꺼져 있습니다(ro.crypto.state={state}). 분실 시 데이터 복호화가 쉬워집니다.",
            "설정 > 보안에서 기기 암호화를 켜거나 지원 기기로 교체하세요.",
        )
    return Finding("encryption", title, "na", None, f"확인 불가(읽은 값: {state or '없음'}).")


def check_selinux(runner) -> Finding:
    title = "SELinux"
    state = runner.shell("getenforce").strip()
    if state == "Enforcing":
        return Finding("selinux", title, "pass", None, "Enforcing.")
    if state == "Permissive":
        return Finding(
            "selinux", title, "warn", MEDIUM,
            "SELinux가 Permissive입니다. 접근 제어 위반이 차단되지 않고 기록만 됩니다.",
            "루팅·커스텀 ROM 설정을 점검하고 Enforcing으로 되돌리세요.",
        )
    if state == "Disabled":
        return Finding(
            "selinux", title, "fail", HIGH,
            "SELinux가 비활성화되어 있습니다. 시스템 서비스 격리가 무력화된 상태입니다.",
            "커스텀 ROM·커널 설정을 점검하고 Enforcing으로 되돌리세요.",
        )
    return Finding("selinux", title, "na", None, f"확인 불가(출력: {state or '빈 출력'}).")


def check_lock_screen(runner) -> Finding:
    title = "잠금 화면"
    out = runner.shell("locksettings", "get-disabled")
    m = re.search(r"\b(true|false)\b", out.lower())
    if not m:
        return Finding("lock-screen", title, "na", None, f"판정 불가(출력: {out.strip() or '빈 출력'}).")
    if m.group(1) == "true":
        return Finding(
            "lock-screen", title, "fail", HIGH,
            "잠금 화면이 꺼져 있습니다(None/Swipe). 분실 시 데이터가 즉시 노출됩니다.",
            "설정 > 보안 > 화면 잠금에서 PIN/패턴/비밀번호/생체인식을 설정하세요.",
        )
    return Finding("lock-screen", title, "pass", None, "잠금 화면 활성 상태.")


def check_oem_unlock(props: dict) -> Finding:
    title = "OEM 잠금 해제 허용"
    state = props.get("sys.oem_unlock_allowed")
    if state == "0":
        return Finding("oem-unlock", title, "pass", None, "허용 안 함.")
    if state == "1":
        return Finding(
            "oem-unlock", title, "warn", MEDIUM,
            "OEM 잠금 해제가 허용된 상태입니다(개발자 옵션). 부트로더 언락이 가능해 물리적 접근 시 공격 표면이 넓어집니다.",
            "커스텀 ROM 사용 등 특별한 이유가 없다면 설정에서 끄세요.",
        )
    return Finding("oem-unlock", title, "na", None, f"확인 불가(읽은 값: {state or '없음'}).")


def check_flash_locked(props: dict) -> Finding:
    title = "부트로더 잠금"
    state = props.get("ro.boot.flash.locked")
    if state == "1":
        return Finding("bootloader-lock", title, "pass", None, "잠김.")
    if state == "0":
        return Finding(
            "bootloader-lock", title, "fail", HIGH,
            "부트로더가 언락 상태입니다. 물리적 접근 시 시스템 무결성 검증(verified boot)이 우회될 수 있습니다.",
            "일반 사용이라면 OEM 잠금 해제를 끄고 재잠금하세요(데이터 초기화가 필요할 수 있음).",
        )
    return Finding("bootloader-lock", title, "na", None, f"확인 불가(읽은 값: {state or '없음'}).")


def check_dev_options(runner) -> Finding:
    title = "개발자 옵션"
    val = _get_setting(runner, "global", "development_settings_enabled")
    if val == "1":
        return Finding(
            "dev-options", title, "warn", LOW,
            "개발자 옵션이 활성화되어 있습니다. USB 디버깅 등 상위 스위치가 열려 있는 상태입니다.",
            "필요할 때만 켜고 평시에는 꺼 두세요.",
        )
    return Finding("dev-options", title, "pass", None, "꺼짐(또는 기본).")


def check_adb_enabled(runner) -> Finding:
    title = "USB 디버깅"
    val = _get_setting(runner, "global", "adb_enabled")
    if val == "1":
        return Finding(
            "usb-debugging", title, "info", INFO,
            "USB 디버깅이 켜져 있습니다 — 이 도구 사용을 위해 필요합니다. 승인되지 않은 PC 연결로도 ADB 제어가 가능한 상태입니다.",
            "점검 후에는 설정에서 끄는 것을 권장합니다.",
        )
    return Finding("usb-debugging", title, "pass", None, "꺼짐.")


def check_wireless_debug(runner) -> Finding:
    title = "무선 디버깅"
    val = _get_setting(runner, "global", "adb_wifi_enabled")
    if val == "1":
        return Finding(
            "wireless-debugging", title, "warn", LOW,
            "무선 디버깅이 켜져 있습니다. 같은 네트워크의 기기에서 adb 연결 시도가 가능합니다.",
            "사용 후 끄세요(개발자 옵션 > 무선 디버깅).",
        )
    return Finding("wireless-debugging", title, "pass", None, "꺼짐(또는 미지원).")


def check_verifier(runner) -> Finding:
    title = "앱 설치 검증"
    val = _get_setting(runner, "global", "package_verifier_enable")
    if val == "0":
        return Finding(
            "app-verifier", title, "warn", MEDIUM,
            "앱 설치 시 패키지 검증이 꺼져 있습니다.",
            "설정 > 보안에서 앱 설치 검증/Play Protect를 켜세요.",
        )
    if val == "1":
        return Finding("app-verifier", title, "pass", None, "켜짐.")
    return Finding("app-verifier", title, "na", None, f"확인 불가(읽은 값: {val or '없음'}).")


def check_install_unknown(runner) -> Finding:
    title = "알 수 없는 출처 설치 허용 앱"
    out = runner.shell("appops", "query-op", "REQUEST_INSTALL_PACKAGES", "allow")
    pkgs = sorted(set(re.findall(r"\b[a-zA-Z][\w]*(?:\.[\w]+)+\b", out)))
    if pkgs:
        return Finding(
            "install-unknown", title, "info", INFO,
            f"다른 앱 설치(REQUEST_INSTALL_PACKAGES)를 허용한 앱 {len(pkgs)}개: {', '.join(pkgs)}",
            "브라우저·파일 관리자가 기본 포함되는 경우가 많습니다. 예상치 못한 앱이면 설정 > 앱 > 특수 앱 액세스에서 취소하세요.",
        )
    return Finding("install-unknown", title, "pass", None, "허용 앱 없음(또는 미지원).")


def check_backup(runner) -> Finding:
    title = "기기 백업"
    out = runner.shell("bmgr", "enabled")
    if "disabled" in out:
        return Finding("backup", title, "pass", None, "꺼짐.")
    if "enabled" in out:
        return Finding(
            "backup", title, "warn", LOW,
            "기기 백업이 켜져 있습니다. allowBackup 앱의 데이터가 클라우드 계정으로 올라갑니다.",
            "백업 계정의 2단계 인증과 비밀번호 관리를 강화하세요. 민감 앱은 백업 제외 여부를 확인하세요.",
        )
    return Finding("backup", title, "na", None, f"확인 불가(출력: {out.strip() or '빈 출력'}).")


def run_device_checks(runner, props: dict, today: date | None = None) -> list:
    """등록된 기기 점검 전체 실행. 개별 실패는 na/error로 기록하고 계속한다."""
    today = today or date.today()
    checks = [
        ("patch-level", lambda: check_patch_level(props, today)),
        ("android-version", lambda: check_android_version(props)),
        ("encryption", lambda: check_crypto_state(props)),
        ("selinux", lambda: check_selinux(runner)),
        ("lock-screen", lambda: check_lock_screen(runner)),
        ("oem-unlock", lambda: check_oem_unlock(props)),
        ("bootloader-lock", lambda: check_flash_locked(props)),
        ("dev-options", lambda: check_dev_options(runner)),
        ("usb-debugging", lambda: check_adb_enabled(runner)),
        ("wireless-debugging", lambda: check_wireless_debug(runner)),
        ("app-verifier", lambda: check_verifier(runner)),
        ("install-unknown", lambda: check_install_unknown(runner)),
        ("backup", lambda: check_backup(runner)),
    ]
    findings = []
    for check_id, fn in checks:
        try:
            findings.append(fn())
        except AdbError as exc:
            findings.append(Finding(check_id, f"점검 {check_id}", "na", None, f"점검 명령 실패: {exc}"))
        except Exception as exc:  # 기대 밖의 출력/파싱 오류 — 기록하고 계속
            findings.append(Finding(check_id, f"점검 {check_id}", "error", None, f"점검 중 오류: {exc!r}"))
    return findings
