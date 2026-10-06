"""앱 정적 점검 규칙 — APK 매니페스트·서명·DEX 지표 / IPA Info.plist·바이너리 지표."""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, field

from . import cert, dexcode, elf, indicators, network_security
from .apk import Apk, ApkError
from .apps import TARGET_SDK_FAIL_BELOW, TARGET_SDK_LOW_BELOW, TARGET_SDK_WARN_BELOW
from .axml import parse_axml
from .checks import HIGH, INFO, LOW, MEDIUM, Finding

# 프레임워크가 protected-broadcast로 선언한 대표 시스템 브로드캐스트(송신 시스템 전용).
# android.* 액션이라도 이 목록 밖(VIEW/SEND 등)은 임의 앱이 송신할 수 있다.
PROTECTED_BROADCASTS = {
    "android.intent.action.BOOT_COMPLETED", "android.intent.action.LOCKED_BOOT_COMPLETED",
    "android.intent.action.PACKAGE_ADDED", "android.intent.action.PACKAGE_REMOVED",
    "android.intent.action.PACKAGE_REPLACED", "android.intent.action.PACKAGE_CHANGED",
    "android.intent.action.PACKAGE_FULLY_REMOVED", "android.intent.action.PACKAGE_RESTARTED",
    "android.intent.action.PACKAGE_DATA_CLEARED", "android.intent.action.PACKAGE_FIRST_LAUNCH",
    "android.intent.action.TIME_TICK", "android.intent.action.TIME_SET",
    "android.intent.action.TIMEZONE_CHANGED", "android.intent.action.LOCALE_CHANGED",
    "android.intent.action.SCREEN_ON", "android.intent.action.SCREEN_OFF",
    "android.intent.action.BATTERY_CHANGED", "android.intent.action.BATTERY_LOW",
    "android.intent.action.BATTERY_OKAY", "android.intent.action.CONFIGURATION_CHANGED",
    "android.intent.action.UID_REMOVED", "android.intent.action.USER_PRESENT",
    "android.intent.action.INPUT_METHOD_CHANGED",
}

COMPONENT_TAGS = {"activity", "activity-alias", "service", "receiver", "provider"}

DANGEROUS_PERMISSIONS = {
    "android.permission.CAMERA", "android.permission.RECORD_AUDIO",
    "android.permission.ACCESS_FINE_LOCATION", "android.permission.ACCESS_COARSE_LOCATION",
    "android.permission.ACCESS_BACKGROUND_LOCATION", "android.permission.READ_CONTACTS",
    "android.permission.WRITE_CONTACTS", "android.permission.READ_CALENDAR",
    "android.permission.WRITE_CALENDAR", "android.permission.READ_SMS",
    "android.permission.SEND_SMS", "android.permission.RECEIVE_SMS",
    "android.permission.RECEIVE_MMS", "android.permission.RECEIVE_WAP_PUSH",
    "android.permission.READ_PHONE_STATE", "android.permission.READ_PHONE_NUMBERS",
    "android.permission.CALL_PHONE", "android.permission.READ_CALL_LOG",
    "android.permission.WRITE_CALL_LOG", "android.permission.BODY_SENSORS",
    "android.permission.BODY_SENSORS_BACKGROUND", "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.WRITE_EXTERNAL_STORAGE", "android.permission.MANAGE_EXTERNAL_STORAGE",
    "android.permission.SYSTEM_ALERT_WINDOW", "android.permission.QUERY_ALL_PACKAGES",
    "android.permission.REQUEST_INSTALL_PACKAGES", "android.permission.ACCESS_MEDIA_LOCATION",
    "android.permission.ACTIVITY_RECOGNITION", "android.permission.POST_NOTIFICATIONS",
    "android.permission.BLUETOOTH_SCAN", "android.permission.BLUETOOTH_CONNECT",
    "android.permission.BLUETOOTH_ADVERTISE", "android.permission.READ_MEDIA_IMAGES",
    "android.permission.READ_MEDIA_VIDEO", "android.permission.READ_MEDIA_AUDIO",
    "android.permission.GET_ACCOUNTS", "android.permission.USE_BIOMETRIC",
}


@dataclass
class Manifest:
    root: dict = field(default_factory=dict)
    app: dict = field(default_factory=dict)
    sdk: dict = field(default_factory=dict)
    permissions: list = field(default_factory=list)
    declared_permissions: list = field(default_factory=list)
    components: list = field(default_factory=list)
    anomalies: list = field(default_factory=list)  # 중복 요소 등 비정상 구조


def build_manifest(events: list) -> Manifest:
    m = Manifest()
    stack = []
    skip_app_depth = None  # 중복 <application> 내부 — 플랫폼은 첫 선언만 사용
    seen_application = False
    current = None
    current_depth = 0
    collecting_actions = None
    for event, name, attrs in events:
        if event == "start":
            if skip_app_depth is not None:
                stack.append(name)
                continue
            if name == "manifest":
                if m.root:
                    m.anomalies.append("중복 <manifest>")
                m.root = attrs
            elif name == "application":
                if seen_application:
                    m.anomalies.append("중복 <application>")
                    skip_app_depth = len(stack)  # 플랫폼은 첫 선언만 사용 — 이하 무시
                else:
                    m.app = attrs
                    seen_application = True
            elif name == "uses-sdk":
                m.sdk = attrs
            elif name in ("uses-permission", "uses-permission-sdk-23"):
                m.permissions.append(attrs.get("name", ""))
            elif name == "permission":
                m.declared_permissions.append({
                    "name": attrs.get("name", ""),
                    "protectionLevel": attrs.get("protectionLevel", ""),
                })
            elif name in COMPONENT_TAGS and current is None:
                current = {
                    "tag": name,
                    "name": attrs.get("name", ""),
                    "exported": attrs.get("exported"),
                    "permission": attrs.get("permission"),
                    "readPermission": attrs.get("readPermission"),
                    "writePermission": attrs.get("writePermission"),
                    "authorities": attrs.get("authorities"),
                    "grantUriPermissions": attrs.get("grantUriPermissions"),
                    "intent_filters": [],      # {actions, categories, schemes, hosts, autoVerify}
                    "path_permissions": [],    # provider 하위 path-permission
                    "grant_uri_paths": [],     # provider 하위 grant-uri-permissions
                }
                current_depth = len(stack)
            elif name == "intent-filter" and current is not None:
                collecting_actions = {"actions": [], "categories": [], "schemes": [],
                                      "hosts": [], "data_paths": [],
                                      "autoVerify": attrs.get("autoVerify")}
            elif name == "action" and collecting_actions is not None:
                collecting_actions["actions"].append(attrs.get("name", ""))
            elif name == "category" and collecting_actions is not None:
                collecting_actions["categories"].append(attrs.get("name", ""))
            elif name == "data" and collecting_actions is not None:
                if attrs.get("scheme"):
                    collecting_actions["schemes"].append(attrs["scheme"])
                if attrs.get("host"):
                    collecting_actions["hosts"].append(attrs["host"])
                for path_key in ("path", "pathPrefix", "pathPattern"):
                    if attrs.get(path_key):
                        collecting_actions["data_paths"].append(attrs[path_key])
            elif name == "path-permission" and current is not None and current["tag"] == "provider":
                current["path_permissions"].append({
                    "path": attrs.get("path"),
                    "pathPrefix": attrs.get("pathPrefix"),
                    "pathPattern": attrs.get("pathPattern"),
                    "permission": attrs.get("permission"),
                    "readPermission": attrs.get("readPermission"),
                    "writePermission": attrs.get("writePermission"),
                })
            elif name == "grant-uri-permissions" and current is not None and current["tag"] == "provider":
                current["grant_uri_paths"].append(dict(attrs))
            stack.append(name)
        else:
            if stack:
                stack.pop()
            if skip_app_depth is not None and len(stack) <= skip_app_depth:
                skip_app_depth = None  # 중복 application 종료 — 이후 요소 다시 수집
            if name == "intent-filter" and current is not None and collecting_actions is not None:
                current["intent_filters"].append(collecting_actions)
                collecting_actions = None
            if current is not None and len(stack) == current_depth:
                m.components.append(current)
                current = None
    return m


def _int_or_none(value):
    try:
        return int(str(value))
    except (TypeError, ValueError):
        return None


from .network_security import UNKNOWN as _UNKNOWN
from .network_security import resolve_bool_attr as _attr_bool

UNKNOWN = _UNKNOWN


def load_manifest(apk: Apk) -> Manifest:
    if "AndroidManifest.xml" not in apk.entry_names():
        raise ApkError("AndroidManifest.xml 없음 — APK가 아니거나 손상되었습니다")
    events = parse_axml(apk.read("AndroidManifest.xml"))
    return build_manifest(events)


def audit_apk(apk: Apk, cert_runner=None) -> tuple:
    m = load_manifest(apk)
    findings: list = []
    if m.anomalies:
        findings.append(Finding(
            "app-manifest-anomaly", "매니페스트 비정상 구조", "warn", MEDIUM,
            ", ".join(m.anomalies) + " — 첫 선언 기준으로 판정했습니다.",
            "공식 빌드 도구 산출물이 아니거나 조작된 APK일 수 있습니다.",
        ))

    debuggable = _attr_bool(apk, m.app.get("debuggable"))
    if debuggable is True:
        findings.append(Finding(
            "app-debuggable", "디버그 모드(debuggable)", "fail", HIGH,
            "매니페스트가 debuggable=true입니다. run-as 등으로 앱 데이터 추출이 가능합니다.",
            "릴리스 빌드 매니페스트에서 제거하세요(debuggable은 기본 false).",
        ))
    elif debuggable is UNKNOWN:
        findings.append(Finding(
            "app-debuggable", "디버그 모드(debuggable)", "na", None,
            f"debuggable이 참조값({m.app.get('debuggable')})이고 해석하지 못했습니다 — 단언 불가.",
            "리소스 bool 값을 확인하세요.",
        ))
    else:
        findings.append(Finding("app-debuggable", "디버그 모드(debuggable)", "pass", None, "false(또는 선언 없음)."))

    backup = _attr_bool(apk, m.app.get("allowBackup"))
    if backup is False:
        findings.append(Finding("app-allowbackup", "ADB 백업 허용(allowBackup)", "pass", None, "명시적으로 비허용."))
    elif backup is True:
        findings.append(Finding(
            "app-allowbackup", "ADB 백업 허용(allowBackup)", "warn", MEDIUM,
            "명시적 true — adb backup / 클라우드 백업으로 앱 데이터가 추출될 수 있습니다.",
            "민감 데이터를 다루면 android:allowBackup=\"false\"와 dataExtractionRules를 설정하세요.",
        ))
    elif backup is UNKNOWN:
        findings.append(Finding(
            "app-allowbackup", "ADB 백업 허용(allowBackup)", "na", None,
            f"allowBackup이 참조값({m.app.get('allowBackup')})이고 해석하지 못했습니다.",
            "리소스 bool 값을 확인하세요.",
        ))
    else:
        findings.append(Finding(
            "app-allowbackup", "ADB 백업 허용(allowBackup)", "warn", MEDIUM,
            "선언 없음(기본값 true) — adb backup / 클라우드 백업으로 앱 데이터가 추출될 수 있습니다.",
            "민감 데이터를 다루면 android:allowBackup=\"false\"와 dataExtractionRules를 설정하세요.",
        ))

    target = _int_or_none(m.sdk.get("targetSdkVersion"))
    cleartext = _attr_bool(apk, m.app.get("usesCleartextTraffic"))
    nsc_ref = m.app.get("networkSecurityConfig")
    nsc_events, nsc_error = network_security.load(apk, m.app)
    nsc = network_security.analyze(nsc_events, apk=apk) if nsc_events is not None else None
    if nsc_ref and nsc is None:
        # 정책 파일이 존재하나 해석 불가 — API 24+에서 정책이 manifest를 덮어쓰므로 단언 금지
        reason = f"NSC 해석 불가({nsc_error})"
        findings.append(Finding("app-cleartext", "평문 트래픽 허용", "na", None, reason + "."))
        findings.append(Finding("app-nsc-user-trust", "사용자 인증서 신뢰", "na", None, reason + "."))
        findings.append(Finding("app-nsc-debug-overrides", "debug-overrides", "na", None, reason + "."))
    elif nsc is not None and nsc.get("base_unknown"):
        findings.append(Finding(
            "app-cleartext", "평문 트래픽 허용", "na", None,
            "정책의 cleartextTrafficPermitted가 참조값이라 해석하지 못했습니다 — 단언 불가.",
            "리소스 bool 값을 확인하세요.",
        ))
    elif nsc is not None:
        # API 24+에서는 networkSecurityConfig가 manifest 선언을 덮어쓴다 — 정책 파일 기준 판정.
        base = nsc["base_cleartext"]
        base_source = "base-config 선언"
        if base is None:
            # base-config 미선언 — 플랫폼 기본값 상속(targetSdk<28이면 허용)
            if target is None:
                base = None
                base_source = "기본값(targetSdk 불명)"
            else:
                base = target < 28
                base_source = f"targetSdk {target} 기본값"
        domains_note = (f" · 예외 도메인 {len(nsc['cleartext_domains'])}개: "
                        + ", ".join(nsc["cleartext_domains"][:6]) if nsc["cleartext_domains"] else "")
        if base is True:
            findings.append(Finding(
                "app-cleartext", "평문 트래픽 허용", "warn", MEDIUM,
                f"networkSecurityConfig가 평문을 허용합니다({base_source})." + domains_note,
                "cleartextTrafficPermitted=false로 바꾸고 필요 도메인만 domain-config로 예외화하세요.",
            ))
        elif nsc["cleartext_domains"]:
            findings.append(Finding(
                "app-cleartext", "평문 트래픽 허용", "warn", LOW,
                f"기본 차단({base_source}), 예외 {len(nsc['cleartext_domains'])}개 도메인 평문 허용: "
                + ", ".join(nsc["cleartext_domains"][:8]),
                "예외 도메인이 여전히 필요한지 검토하세요.",
            ))
        elif base is False:
            findings.append(Finding("app-cleartext", "평문 트래픽 허용", "pass", None,
                                    f"networkSecurityConfig가 평문 차단({base_source})."))
        else:
            findings.append(Finding("app-cleartext", "평문 트래픽 허용", "na", None,
                                    "targetSdk 불명으로 정책 기본값 판단 불가."))
    else:
        note = ""
        if cleartext is True:
            findings.append(Finding(
                "app-cleartext", "평문 트래픽 허용", "warn", MEDIUM,
                "usesCleartextTraffic=true — 중간자 도청 표면이 열립니다." + note,
                "false로 바꾸고 networkSecurityConfig로 예외 도메인만 허용하세요.",
            ))
        elif cleartext is False:
            findings.append(Finding("app-cleartext", "평문 트래픽 허용", "pass", None, "명시적 false." + note))
        elif cleartext is UNKNOWN:
            findings.append(Finding("app-cleartext", "평문 트래픽 허용", "na", None,
                                   "usesCleartextTraffic이 참조값이라 해석하지 못했습니다." + note))
        elif target is not None and target < 28:
            findings.append(Finding(
                "app-cleartext", "평문 트래픽 허용", "warn", MEDIUM,
                f"선언 없음 + targetSdk {target}(<28) — 기본값이 평문 허용입니다." + note,
                "targetSdk를 올리거나 networkSecurityConfig로 명시하세요.",
            ))
        elif target is not None:
            findings.append(Finding("app-cleartext", "평문 트래픽 허용", "pass", None,
                                    f"기본 차단(targetSdk {target})." + note))
        else:
            findings.append(Finding("app-cleartext", "평문 트래픽 허용", "na", None, "targetSdk 확인 불가."))

    if nsc is not None:
        if nsc["user_trust"]:
            findings.append(Finding(
                "app-nsc-user-trust", "사용자 인증서 신뢰", "warn", MEDIUM,
                "trust-anchors에 사용자 설치 인증서(src=user)가 포함되어 있습니다.",
                "사용자가 설치한 임의 인증서를 신뢰하면 중간자 공격 표면이 열립니다. debug-overrides로 한정하세요.",
            ))
        if nsc["debug_overrides"]:
            if debuggable is True:  # 이미 해석된 값 사용 — 원시 문자열 비교 금지
                findings.append(Finding(
                    "app-nsc-debug-overrides", "debug-overrides 활성", "warn", MEDIUM,
                    "debuggable 빌드에서 networkSecurityConfig debug-overrides가 적용되고 있습니다.",
                    "디버그 전용 신뢰 설정입니다. 릴리스 빌드에 남지 않는지 확인하세요.",
                ))
            elif debuggable is UNKNOWN:
                findings.append(Finding(
                    "app-nsc-debug-overrides", "debug-overrides 판정", "na", None,
                    "debuggable이 참조값이라 해석하지 못해 적용 여부를 단언할 수 없습니다.",
                    "리소스 bool 값을 확인하세요.",
                ))
            else:
                findings.append(Finding(
                    "app-nsc-debug-overrides", "debug-overrides 선언", "info", INFO,
                    "debug-overrides가 정의되어 있으나 debuggable이 아니라 릴리스에서는 무시됩니다.",
                    "공식 권장 패턴입니다(사용자 CA 신뢰를 디버그로 한정). 그대로 두어도 안전합니다.",
                ))

    def _is_normal_pattern(c):
        """정상 공개 패턴 — 런처 진입점, 시스템 보호 브로드캐스트 수신(명시/암시 공통)."""
        if any("android.intent.category.LAUNCHER" in f.get("categories", [])
               for f in c["intent_filters"]):
            return True
        if c["tag"] == "receiver":
            actions = [a for f in c["intent_filters"] for a in f.get("actions", [])]
            # 보호 브로드캐스트만 송신 시스템 전용 — 그 외 android.* 액션은 임의 앱이 도달 가능
            return bool(actions) and all(a in PROTECTED_BROADCASTS for a in actions)
        return False

    def _component_protected(c):
        if c.get("permission"):
            return True
        if c["tag"] == "provider":
            return bool(c.get("readPermission")) and bool(c.get("writePermission"))
        return False

    def _exported_value(c):
        raw = c["exported"]
        if raw is None or raw in ("true", "false"):
            return raw
        resolved = _attr_bool(apk, raw)
        return "true" if resolved is True else "false" if resolved is False else UNKNOWN

    unknown_exported = [c for c in m.components if _exported_value(c) == UNKNOWN]
    exported_explicit = [c for c in m.components if _exported_value(c) == "true"]
    unprotected = [c for c in exported_explicit if not _component_protected(c)]
    normal_public = [c for c in unprotected if _is_normal_pattern(c)]
    truly_unprotected = [c for c in unprotected if not _is_normal_pattern(c)]
    implicit = [c for c in m.components if c["exported"] is None and c["intent_filters"]]
    reachable = [c for c in implicit if not _is_normal_pattern(c)]
    reachable = reachable + unknown_exported  # 참조 해석 실패 — 보수적으로 도달 가능 취급
    normal_implicit = [c for c in implicit if _is_normal_pattern(c)]
    if truly_unprotected:
        extra = f" · intent-filter로 타 앱 도달 가능 {len(reachable)}개" if reachable else ""
        findings.append(Finding(
            "app-exported", "외부 공개 컴포넌트", "warn", MEDIUM,
            "permission 없이 exported=true: "
            + ", ".join(f"{c['tag']} {c['name']}" for c in truly_unprotected[:8]) + extra,
            "외부 공개가 필요한지 검토하고, 필요하면 권한·서명 검증을 붙이세요. 불필요하면 exported=false.",
        ))
    elif reachable:
        findings.append(Finding(
            "app-exported", "외부 공개 컴포넌트", "info", INFO,
            "intent-filter로 암시적 공개·타 앱 도달 가능(커스텀 인텐트/딥링크; targetSdk<31 규칙 — "
            "31+에서는 exported 미선언 시 설치 불가): "
            + ", ".join(f"{c['tag']} {c['name']}" for c in reachable[:8])
            + (f" · 시스템용 정상 exported {len(normal_implicit)}개" if normal_implicit else ""),
            "해당 컴포넌트는 임의 앱의 인텐트로 실행될 수 있습니다. 노출 의도를 확인하고 입력을 검증하세요.",
        ))
    else:
        normal_total = len(normal_public) + len(normal_implicit)
        note = (f" · 정상 공개(런처·시스템 브로드캐스트) {normal_total}개" if normal_total else "")
        findings.append(Finding("app-exported", "외부 공개 컴포넌트", "pass", None,
                                "보호 없는 공개 컴포넌트 없음." + note))

    deeplinks = []
    for c in m.components:
        for f in c["intent_filters"]:
            if "android.intent.category.BROWSABLE" in f.get("categories", []):
                deeplinks.append((c, f))
    if deeplinks:
        def _filter_note(c, f):
            paths = f.get("data_paths") or []
            return f"({','.join(paths[:2])})" if paths else ""

        custom = [(c, f) for c, f in deeplinks
                  if not f.get("schemes")
                  or any(s not in ("http", "https") for s in f["schemes"])]
        unverified = [(c, f) for c, f in deeplinks if f.get("autoVerify") != "true"]
        if custom:
            listing = ", ".join(
                f"{next(iter(f['schemes']), '?')}://{c['name'].rsplit('.', 1)[-1]}"
                f"{_filter_note(c, f)}"
                for c, f in custom[:8])
            findings.append(Finding(
                "app-deeplink", "딥링크 도달 표면", "warn", MEDIUM,
                f"커스텀 스킴 BROWSABLE 딥링크 {len(custom)}개(스킴 가로채기 가능): {listing}",
                "커스텀 스킴은 동일 스킴을 등록한 다른 앱이 가로챌 수 있습니다. App Links(autoVerify) 전환과 딥링크 파라미터 검증을 검토하세요.",
            ))
        elif unverified:
            findings.append(Finding(
                "app-deeplink", "딥링크 도달 표면", "warn", LOW,
                f"autoVerify 없는 http(s) 딥링크 {len(unverified)}개 — 도메인 소유 검증 없이 브라우저에서 도달 가능.",
                "App Links(assetlinks.json)로 autoVerify를 켜 도메인 귀속을 검증하세요.",
            ))
        else:
            findings.append(Finding("app-deeplink", "딥링크 도달 표면", "pass", None,
                                    "검증된 App Links(autoVerify) 딥링크."))
    else:
        findings.append(Finding("app-deeplink", "딥링크 도달 표면", "pass", None,
                                "BROWSABLE 딥링크 없음."))

    exported_providers = [c for c in m.components
                          if c["tag"] == "provider" and _exported_value(c) == "true"]
    grant_providers = [c for c in exported_providers
                       if _attr_bool(apk, c.get("grantUriPermissions")) is True
                       or c.get("grant_uri_paths")]
    if grant_providers:
        findings.append(Finding(
            "app-provider-grant", "exported provider URI 권한 위임", "warn", MEDIUM,
            "exported provider가 URI 권한 위임 허용(속성 또는 grant-uri-permissions): "
            + ", ".join(c["name"] or c.get("authorities") or "?" for c in grant_providers[:6]),
            "권한 없는 앱이 URI 단위 접근 승인을 요청할 수 있습니다. 위임 경로를 최소화하세요.",
        ))
    else:
        findings.append(Finding("app-provider-grant", "exported provider URI 권한 위임", "pass", None,
                                "해당 없음."))

    ineffective = []
    partial_providers = []
    for p in exported_providers:
        perms = p.get("path_permissions", [])
        for e in perms:
            if not (e.get("readPermission") or e.get("writePermission") or e.get("permission")):
                ineffective.append((p, e))
        if not (p.get("permission") or p.get("readPermission") or p.get("writePermission")):
            if any(e.get("readPermission") or e.get("writePermission") or e.get("permission")
                   for e in perms):
                partial_providers.append(p)
    if ineffective:
        listing = ", ".join(
            f"{e.get('path') or e.get('pathPrefix') or e.get('pathPattern') or '?'}"
            for _p, e in ineffective[:8])
        findings.append(Finding(
            "app-provider-paths", "provider 경로 권한", "info", INFO,
            f"읽기·쓰기 권한이 전혀 없는 path-permission({listing}) — 프레임워크가 해당 선언을 무시하고 provider 권한이 그대로 적용됩니다.",
            "path-permission에 permission/readPermission/writePermission 중 하나는 지정하세요.",
        ))
    elif partial_providers:
        findings.append(Finding(
            "app-provider-paths", "provider 경로 권한", "info", INFO,
            "provider 단위 권한 없이 경로 패턴으로만 보호: "
            + ", ".join(p["name"] or p.get("authorities") or "?" for p in partial_providers[:6])
            + " — 패턴에 걸리지 않는 URI는 무보호일 수 있습니다.",
            "provider 단위 permission을 기본 보호로 두고 path-permission은 예외 허용용으로만 쓰세요.",
        ))
    else:
        findings.append(Finding("app-provider-paths", "provider 경로 권한", "pass", None,
                                "해당 없음."))

    dangerous = [p for p in m.permissions if p in DANGEROUS_PERMISSIONS]
    if dangerous:
        findings.append(Finding(
            "app-permissions-dangerous", "민감(dangerous) 권한", "info", INFO,
            f"{len(dangerous)}건: {', '.join(sorted(p.rsplit('.', 1)[-1] for p in dangerous))}",
            "권한 최소화를 검토하세요(필요 시점 요청, 미사용 권한 제거).",
        ))
    else:
        findings.append(Finding("app-permissions-dangerous", "민감(dangerous) 권한", "pass", None, "요청 목록에 민감 권한 없음."))

    def _protection_rank(raw):
        """0=normal 1=dangerous 2=signature 3=signatureOrSystem. 숫자(TYPE_INT_HEX)와 문자열 모두."""
        if raw is None:
            return 0
        text = str(raw).strip()
        if text.isdigit():
            return int(text) & 0xF
        return {"normal": 0, "dangerous": 1, "signature": 2,
                "signatureOrSystem": 3}.get(text, 0)

    loose_custom = [d for d in m.declared_permissions if _protection_rank(d["protectionLevel"]) in (0, 1)]
    if loose_custom:
        findings.append(Finding(
            "app-custom-permissions", "커스텀 권한 보호 수준", "info", INFO,
            "normal/dangerous(또는 미선언) 커스텀 권한: "
            + ", ".join(f"{d['name']}" for d in loose_custom[:8]),
            "다른 앱이 가로채기 쉬운 권한입니다. signature 수준으로 보호하세요.",
        ))
    else:
        findings.append(Finding("app-custom-permissions", "커스텀 권한 보호 수준", "pass", None, "커스텀 권한 없음 또는 signature 보호."))

    if target is None:
        findings.append(Finding("app-target-sdk", "targetSdk 수준", "na", None, "uses-sdk 확인 불가."))
    elif target < TARGET_SDK_FAIL_BELOW:
        findings.append(Finding(
            "app-target-sdk", "targetSdk 수준", "fail", HIGH,
            f"targetSdk={target}(<{TARGET_SDK_FAIL_BELOW}) — 런타임 권한 등 현행 보안 모델 미적용.",
            "targetSdk를 현행 요건으로 올리세요.",
        ))
    elif target < TARGET_SDK_WARN_BELOW:
        findings.append(Finding(
            "app-target-sdk", "targetSdk 수준", "warn", MEDIUM,
            f"targetSdk={target}(<{TARGET_SDK_WARN_BELOW}) — 레거시 동작 허용.",
            "targetSdk 상향을 검토하세요.",
        ))
    elif target < TARGET_SDK_LOW_BELOW:
        findings.append(Finding(
            "app-target-sdk", "targetSdk 수준", "warn", LOW,
            f"targetSdk={target}(<{TARGET_SDK_LOW_BELOW}) — 범위 저장소 미적용 가능.",
            "targetSdk 상향을 검토하세요.",
        ))
    else:
        findings.append(Finding("app-target-sdk", "targetSdk 수준", "pass", None,
                                f"targetSdk={target}(기준 2026-10)."))

    v1 = bool(apk.v1_signature_files())
    v2 = apk.has_v2_plus_signature()
    if not v1 and not v2:
        findings.append(Finding(
            "app-signature", "APK 서명 방식", "fail", HIGH,
            "v1(JAR) 서명과 v2+ 서명 모두 없습니다. 무결성 검증 불가.",
            "APK가 손상되었거나 재압축된 것은 아닌지 확인하세요.",
        ))
    elif not v2:
        findings.append(Finding(
            "app-signature", "APK 서명 방식", "warn", MEDIUM,
            "v1(JAR) 서명만 있습니다. v2+ 미사용 시 설치 검증·무결성 보호가 약합니다.",
            "apksigner로 v2 이상 체계를 함께 적용하세요.",
        ))
    else:
        findings.append(Finding("app-signature", "APK 서명 방식", "pass", None,
                                f"v2+ 서명 블록 감지{' (+v1 병기)' if v1 else ''}."))

    cert_info = None
    if v1:
        try:
            cert_der = apk.read(apk.v1_signature_files()[0])
        except ApkError as exc:
            cert_info = {"error": f"인증서 엔트리 읽기 실패: {exc}"}
        else:
            cert_info = cert.analyze_v1_certificate(cert_der, runner=cert_runner)
        if cert_info is None or (cert_info.get("error") and not cert_info.get("debug")):
            findings.append(Finding(
                "app-cert", "서명 인증서", "na", None,
                f"인증서 분석 불가: {(cert_info or {}).get('error') or '알 수 없음'}",
            ))
        elif cert_info["debug"]:
            findings.append(Finding(
                "app-cert", "서명 인증서", "fail", HIGH,
                f"디버그 키로 서명되었습니다({cert_info['subject']}).",
                "디버그 키스토어는 널리 알려져 위조가 가능합니다. 릴리스 키스토어로 서명하세요.",
            ))
        elif cert_info["expired"]:
            findings.append(Finding(
                "app-cert", "서명 인증서", "warn", LOW,
                f"만료된 인증서입니다({cert_info['subject']}). Android는 유효기간을 강제하지 않습니다.",
                "키 순환이 필요하면 v3 키 회전 또는 Play App Signing을 검토하세요(인증서 교체는 업데이트 서명 불일치로 이어집니다).",
            ))
        else:
            findings.append(Finding("app-cert", "서명 인증서", "pass", None,
                                    f"정상({cert_info['subject'] or '주체 정보 없음'})."))
    elif v2:
        findings.append(Finding(
            "app-cert", "서명 인증서", "na", None,
            "v2/v3 전용 서명 — 현재 버전은 v1(JAR) 인증서만 분석합니다.",
            "v1 병기 빌드로 확인하거나 apksigner로 인증서를 별도 확인하세요.",
        ))

    dex_scan = dexcode.scan_apk(apk)
    dex_entries, dex_errors = apk.dex_scan_stats()
    if dex_entries and dex_errors == dex_entries:
        findings.append(Finding(
            "dex-scan", "DEX 문자열 지표", "na", None,
            f"DEX {dex_entries}개 모두 읽기 실패 — 문자열/바이트코드 지표를 스캔할 수 없습니다.",
            "APK가 손상되지 않았는지 확인하세요.",
        ))
    else:
        findings += indicators.audit_strings(
            apk.dex_strings(), "dex", "DEX 문자열 스캔 휴리스틱",
            groups=None if not dex_scan["available"] else ("secrets", "cleartext-urls", "trackers"))
        if dex_errors:
            findings.append(Finding(
                "dex-scan", "DEX 스캔 범위", "info", INFO,
                f"DEX {dex_errors}/{dex_entries}개 읽기 실패로 건너뛰었습니다 — 지표가 해당 DEX를 포함하지 않습니다.",
                "APK 무결성을 확인하세요.",
            ))
    if dex_scan["available"]:
        if dex_scan["weak_crypto"]:
            findings.append(Finding(
                "dex-weak-crypto", "약한 암호 알고리즘 호출", "warn", MEDIUM,
                f"바이트코드 호출 지점 {dex_scan['scanned']}개 메서드 중 "
                f"{len(dex_scan['weak_crypto'])}곳: "
                + "; ".join(dex_scan["weak_crypto"][:6])
                + (f" 외 {len(dex_scan['weak_crypto']) - 6}곳" if len(dex_scan["weak_crypto"]) > 6 else ""),
                "해당 지점의 알고리즘을 AES-GCM/SHA-256 이상으로 교체하세요.",
            ))
        else:
            findings.append(Finding("dex-weak-crypto", "약한 암호 알고리즘 호출", "pass", None,
                                    f"바이트코드 내 호출 미발견({dex_scan['scanned']}개 메서드 스캔)."))
        if dex_scan["webview"]:
            findings.append(Finding(
                "dex-webview", "WebView 설정 호출", "info", INFO,
                "호출 지점: " + "; ".join(dex_scan["webview"][:6]),
                "파일 접근·JS 인터페이스 사용 시 신뢰하는 콘텐츠만 로드하는지 확인하세요.",
            ))
        else:
            findings.append(Finding("dex-webview", "WebView 설정 호출", "pass", None,
                                    f"바이트코드 내 호출 미발견({dex_scan['scanned']}개 메서드 스캔)."))
        if dex_scan["dynamic"]:
            findings.append(Finding(
                "dex-dynamic-code", "동적 코드·리플렉션 호출", "info", INFO,
                "호출 지점: " + "; ".join(dex_scan["dynamic"][:6])
                + (f" 외 {len(dex_scan['dynamic']) - 6}곳" if len(dex_scan["dynamic"]) > 6 else ""),
                "DexClassLoader/Runtime.exec/System.load는 동적 코드 적재 지점입니다. 입력 출처를 검증하세요.",
            ))
        else:
            findings.append(Finding("dex-dynamic-code", "동적 코드·리플렉션 호출", "pass", None,
                                    "바이트코드 내 호출 미발견."))
    else:
        pass  # 문자열 지표 모드는 위 audit_strings(groups=None)가 weak/webview 포함 전량 생성

    lib_entries = {}
    for n in apk.entry_names():
        lib_match = re.fullmatch(r"lib/([^/]+)/([^/]+\.so)", n)
        if lib_match:
            lib_entries[(lib_match.group(1), lib_match.group(2))] = n
    if lib_entries:
        # (abi, basename) 전체를 검사 — ZIP 기록 순서에 따라 실제 실행 ABI(통상
        # arm64-v8a)의 결과가 바뀌는 일이 없어야 한다.
        rows, exec_stack, missing, unreadable, unknown_stack = [], [], [], [], []
        for (abi, basename), entry in sorted(lib_entries.items()):
            label = f"{basename}[{abi}]"
            try:
                blob = apk.read(entry)[: 16 * 1024 * 1024]
            except ApkError:
                unreadable.append(label)
                continue
            hard = elf.parse(blob)
            if hard is None:
                unreadable.append(label)
                continue
            rows.append(
                f"{label}: PIE {'O' if hard['pie'] else 'X'} · RELRO {hard['relro']} · "
                f"NX {'?' if hard['nx'] is None else 'O' if hard['nx'] else 'X'} · 카나리 {'O' if hard['canary'] else 'X'}")
            if hard["nx"] is None:
                unknown_stack.append(label)
            if hard["nx"] is False:
                exec_stack.append(label)
            elif not hard["pie"] or not hard["canary"] or hard["relro"] == "none":
                missing.append(label)
        if exec_stack:
            findings.append(Finding(
                "native-hardening", "네이티브 라이브러리 하드닝", "warn", MEDIUM,
                f"실행 가능 스택(NX 없음): {', '.join(exec_stack)}",
                "링커 플래그로 실행 스택을 제거하세요(-z noexecstack).",
            ))
        elif missing:
            findings.append(Finding(
                "native-hardening", "네이티브 라이브러리 하드닝", "warn", LOW,
                f"하드닝 미적용 항목 있음({', '.join(missing[:6])}): "
                + " | ".join(rows[:6]),
                "NDK 기본 권장(-fstack-protector-strong, full RELRO, PIE) 적용을 검토하세요.",
            ))
        elif rows and not unknown_stack:
            findings.append(Finding("native-hardening", "네이티브 라이브러리 하드닝", "pass", None,
                                    f"{len(rows)}개 ABI 조합 검사 · " + " · ".join(rows[:4])))
        elif not rows:
            findings.append(Finding(
                "native-hardening", "네이티브 라이브러리 하드닝", "na", None,
                "해석 가능한 .so 없음" + (f"(읽기/파싱 실패: {', '.join(unreadable[:4])})"
                                          if unreadable else ".")))
        if unknown_stack:
            findings.append(Finding(
                "native-hardening", "네이티브 라이브러리 하드닝", "na", None,
                f"GNU_STACK 선언이 없어 NX 판단 불가: {', '.join(unknown_stack)}",
            ))
        if unreadable and rows:
            findings.append(Finding(
                "native-scan-scope", "네이티브 스캔 범위", "info", INFO,
                f"{len(unreadable)}개 .so 읽기/파싱 실패로 건너뛰었습니다: "
                + ", ".join(unreadable[:4]),
                "해당 ABI의 하드닝 상태가 결과에 포함되지 않습니다. APK 무결성을 확인하세요.",
            ))
    else:
        findings.append(Finding("native-hardening", "네이티브 라이브러리 하드닝", "pass", None,
                                "네이티브 라이브러리 없음."))

    meta = {
        "type": "apk",
        "file": os.path.basename(apk.path),
        "package": m.root.get("package"),
        "versionName": m.root.get("versionName"),
        "minSdk": m.sdk.get("minSdkVersion"),
        "targetSdk": m.sdk.get("targetSdkVersion"),
        "components": len(m.components),
    }
    return meta, findings
