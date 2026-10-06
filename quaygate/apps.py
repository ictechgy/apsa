"""설치 앱 점검(본인 기기의 서드파티 앱 대상, 읽기 전용).

dumpsys package 출력은 Android 버전·제조사별 편차가 있어 파서는 보수적으로
동작한다: 매칭 실패는 '확인 불가'로 흘리고 단언하지 않는다.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from .checks import HIGH, INFO, LOW, MEDIUM, Finding

TARGET_SDK_FAIL_BELOW = 23  # 런타임 권한 도입 전 — 설치 시점에 전체 권한 부여
TARGET_SDK_WARN_BELOW = 29  # 레거시 권한/저장소 동작 허용
TARGET_SDK_LOW_BELOW = 30   # 범위 저장소(scoped storage) 미적용 가능


@dataclass
class AppInfo:
    name: str
    target_sdk: int | None
    debuggable: bool
    installer: str | None
    installer_present: bool = True  # 필드 자체가 있었는지(null과 미매칭 구분)


def list_third_party(runner) -> list:
    out = runner.shell("pm", "list", "packages", "-3")
    names = [ln[len("package:"):] for ln in out.splitlines() if ln.startswith("package:")]
    return sorted(set(names))


def parse_package_dump(name: str, text: str) -> AppInfo:
    m = re.search(r"targetSdk(?:Version)?=(\d+)", text)
    target = int(m.group(1)) if m else None
    flag_blocks = re.findall(r"[Ff]lags=\[[^\]]*\]", text)
    debuggable = any("DEBUGGABLE" in block for block in flag_blocks)
    installer = None
    installer_present = False
    m = re.search(r"installerPackageName=(\S+)", text)
    if m:
        installer_present = True
        if m.group(1) not in ("null", ""):
            installer = m.group(1)
    return AppInfo(name, target, debuggable, installer, installer_present)


def collect_apps(runner, names: list):
    infos, errors = [], []
    for name in names:
        try:
            infos.append(parse_package_dump(name, runner.shell("dumpsys", "package", name)))
        except Exception:
            errors.append(name)
    return infos, errors


def audit_apps(infos: list, errors: list) -> list:
    findings = []

    debuggable = [a.name for a in infos if a.debuggable]
    if debuggable:
        findings.append(Finding(
            "apps-debuggable", "디버그 가능(debuggable) 앱 설치", "fail", HIGH,
            f"run-as 등으로 앱 데이터 추출이 가능한 앱 {len(debuggable)}개: {', '.join(debuggable)}",
            "릴리스 빌드가 아니거나 개발·테스트용 앱입니다. 필요 없으면 삭제하세요.",
        ))
    else:
        findings.append(Finding("apps-debuggable", "디버그 가능 앱 설치", "pass", None, "debuggable 플래그 앱 없음."))

    tiers = {"fail": [], "med": [], "low": []}
    unknown_target = 0
    for app in infos:
        if app.target_sdk is None:
            unknown_target += 1
        elif app.target_sdk < TARGET_SDK_FAIL_BELOW:
            tiers["fail"].append(app)
        elif app.target_sdk < TARGET_SDK_WARN_BELOW:
            tiers["med"].append(app)
        elif app.target_sdk < TARGET_SDK_LOW_BELOW:
            tiers["low"].append(app)
    suffix = f" · targetSdk 확인 불가 {unknown_target}개" if unknown_target else ""
    if tiers["fail"]:
        detail = "구식 권한 모델 앱들(설치 시점 전체 권한 부여): "
        detail += ", ".join(f"{a.name} ({a.target_sdk})" for a in tiers["fail"])
        if tiers["med"] or tiers["low"]:
            detail += f" · 레거시 {len(tiers['med']) + len(tiers['low'])}개"
        findings.append(Finding(
            "apps-target-sdk", "앱 targetSdk 수준", "fail", HIGH,
            detail + suffix,
            "targetSdk<23 앱은 위치·연락처 등 민감 권한을 설치 시 한 번에 가져갑니다. 대체 앱 사용 또는 삭제를 권장합니다.",
        ))
    elif tiers["med"]:
        findings.append(Finding(
            "apps-target-sdk", "앱 targetSdk 수준", "warn", MEDIUM,
            "레거시 동작 허용 앱(targetSdk<29): "
            + ", ".join(f"{a.name} ({a.target_sdk})" for a in tiers["med"]) + suffix,
            "개발자가 targetSdk를 올리기 전까지 레거시 권한/저장소 동작이 허용됩니다. 최신 버전 업데이트 또는 삭제를 고려하세요.",
        ))
    elif tiers["low"]:
        findings.append(Finding(
            "apps-target-sdk", "앱 targetSdk 수준", "warn", LOW,
            "범위 저장소 미적용 가능 앱(targetSdk<30): "
            + ", ".join(f"{a.name} ({a.target_sdk})" for a in tiers["low"]) + suffix,
            "공용 저장소 접근이 허용되는 앱입니다. 사용하지 않으면 삭제를 고려하세요.",
        ))
    else:
        findings.append(Finding("apps-target-sdk", "앱 targetSdk 수준", "pass", None,
                                f"점검한 앱 전체 targetSdk {TARGET_SDK_LOW_BELOW} 이상{suffix or '.'}"))

    # installerPackageName=null(매칭됨)만 sideload — 필드 부재(미매칭)는 단언하지 않음
    sideloaded = [a.name for a in infos if a.installer_present and a.installer is None]
    if sideloaded:
        findings.append(Finding(
            "apps-sideloaded", "스토어 외부 설치 앱", "info", INFO,
            f"설치 출처(installerPackageName)가 없는 앱 {len(sideloaded)}개: {', '.join(sideloaded)}",
            "APK 직접 설치(sideload) 앱입니다. 공식 출처가 아닌 경우 필요 시만 유지하세요.",
        ))
    else:
        unknown_installers = [a.name for a in infos if not a.installer_present]
        if unknown_installers:
            findings.append(Finding(
                "apps-sideloaded", "스토어 외부 설치 앱", "pass", None,
                f"기록된 설치 출처 없음(확인 불가) {len(unknown_installers)}개 — sideload로 단언하지 않음.",
            ))
        else:
            findings.append(Finding("apps-sideloaded", "스토어 외부 설치 앱", "pass", None,
                                    "전부 설치 출처 기록 있음."))

    if errors:
        findings.append(Finding(
            "apps-errors", "앱 점검 오류", "info", INFO,
            f"{len(errors)}개 패키지 덤프 실패: {', '.join(errors)}",
            "재실행하거나 해당 앱을 설정에서 직접 확인하세요.",
        ))
    return findings
