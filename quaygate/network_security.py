"""networkSecurityConfig(res/xml AXML) 점검.

매니페스트 참조는 두 형태를 해석한다: "@xml/이름" 문자열과 "@<숫자>" 리소스 ID
(후자는 apk.resource_names()의 resources.arsc 최소 파싱으로 이름을 복원).
API 24+에서는 이 정책 파일이 usesCleartextTraffic을 덮어쓰므로, 해석에 성공하면
정책 파일 기준으로 판정한다.
"""
from __future__ import annotations

import re

from .apk import Apk
from .axml import AxmlError, parse_axml


UNKNOWN = "?"  # 참조형 속성을 해석하지 못함 — 단언 금지


def resolve_bool_attr(apk, value):
    """속성의 불리언 해석 — True/False/None(선언 없음)/UNKNOWN(참조 해석 실패).

    aapt2는 불리언 속성을 typed 값으로 컴파일하고 참조형은 '@<id>'로 디코딩된다.
    arsc의 bool 값을 따라 해석하고, 실패하면 단언하지 않는다.
    (appchecks와 network_security 양쪽에서 쓰는 단일 해석기.)
    """
    if value is None:
        return None
    if value == "true":
        return True
    if value == "false":
        return False
    if value.startswith("@") and value[1:].isdigit():
        resolved = apk.resource_names().get(int(value[1:]))
        if resolved and len(resolved) > 2 and resolved[2] in ("true", "false"):
            return resolved[2] == "true"
        return UNKNOWN
    return None


def _resolve_config_name(value, apk: Apk):
    """(엔트리명, 경로 힌트, 실패 사유) 반환. 사유가 None이면 해석 성공.

    경로 힌트는 리소스 값 문자열(경로 난독화 APK의 실제 res/ 경로)이다.
    """
    if not isinstance(value, str):
        return None, None, "참조 없음"
    m = re.fullmatch(r"@xml/([\w.\-]+)", value)
    if m:
        return m.group(1), None, None
    m = re.fullmatch(r"@(\d+)", value)
    if m:
        resolved = apk.resource_names().get(int(m.group(1)))
        if resolved and resolved[0] == "xml":
            path_hint = resolved[2] if len(resolved) > 2 else None
            return resolved[1], path_hint, None
        if resolved:
            return None, None, f"참조가 xml 타입이 아님({resolved[0]})"
        return None, None, "리소스 ID 해석 실패(arsc 없음 또는 미등록)"
    return None, None, "참조 형식 미인식"


def load(apk: Apk, app_attrs: dict):
    """설정 파일 이벤트 목록 반환. 없으면 (None, 사유)."""
    name, path_hint, reason = _resolve_config_name(app_attrs.get("networkSecurityConfig"), apk)
    if name is None:
        return None, reason
    entries = apk.entry_names()
    match = None
    if path_hint and path_hint in entries and path_hint.endswith(".xml"):
        match = path_hint  # 경로 난독화 APK — 값에 드러난 실제 경로
    if match is None:
        suffix = f"/{name}.xml"
        match = next((n for n in entries
                      if n.startswith("res/xml") and n.endswith(suffix)
                      and n.lower() == n), None) or \
            next((n for n in entries if n.startswith("res/xml") and n.endswith(suffix)), None)
    if match is None:
        return None, f"res/xml/{name}.xml 엔트리 없음"
    try:
        return parse_axml(apk.read(match)), None
    except AxmlError as exc:
        return None, f"파싱 실패: {exc}"
    except Exception as exc:  # 엔트리 읽기 실패 등 — 해석 불가로 전달
        return None, f"읽기 실패: {type(exc).__name__}: {exc}"


def analyze(events: list, apk=None) -> dict:
    """base-cleartext / 평문 허용 도메인 / 사용자 인증서 신뢰 / debug-overrides 추출.

    상속 규칙 전체를 재현하지 않는다 — 명시적 선언만 보고한다(보수적 판정).
    """
    result = {
        "base_cleartext": None,       # True/False/None(선언 없음)
        "base_unknown": False,        # 참조 해석 실패 — 단언 금지(na 유도)
        "cleartext_domains": [],
        "user_trust": False,
        "debug_overrides": False,
    }
    stack = []
    for event, val, attrs in events:
        if event == "text":
            if stack and stack[-1]["tag"] == "domain" and val and val.strip():
                stack[-1]["text"] = val.strip()
            continue
        if event == "start":
            node = {"tag": val, "text": ""}
            if val == "base-config":
                declared = attrs.get("cleartextTrafficPermitted")
                if declared is not None:
                    if apk is not None:
                        resolved = resolve_bool_attr(apk, declared)
                        if resolved == UNKNOWN:
                            result["base_unknown"] = True  # na 유도 — 단언 금지
                        else:
                            result["base_cleartext"] = resolved
                    else:
                        result["base_cleartext"] = declared == "true"
            elif val == "domain-config":
                node["cleartext"] = attrs.get("cleartextTrafficPermitted")
            elif val == "debug-overrides":
                result["debug_overrides"] = True
            elif val == "certificates" and attrs.get("src") == "user":
                in_debug = any(a["tag"] == "debug-overrides" for a in stack)
                if not in_debug:
                    result["user_trust"] = True
            stack.append(node)
        elif event == "end" and stack:
            node = stack.pop()
            if node["tag"] == "domain" and node["text"]:
                for anc in reversed(stack):
                    if anc["tag"] == "domain-config":
                        anc.setdefault("domains", []).append(node["text"])
                        break
            elif node["tag"] == "domain-config":
                node_cleartext = node.get("cleartext")
                if node_cleartext is not None and apk is not None:
                    resolved = resolve_bool_attr(apk, node_cleartext)
                    node_cleartext = "true" if resolved is True else None if resolved == UNKNOWN else node_cleartext if resolved is None else "false"
                if node_cleartext == "true":
                    result["cleartext_domains"].extend(node.get("domains", []))
    return result
