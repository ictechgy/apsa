"""DEX 코드 분석 — 클래스/메서드 정의와 바이트코드를 읽어 민감 API 호출 지점 추출.

디컴파일러가 아니다: invoke 계열 명령의 method_id와 메서드 내 const-string만
추적해 '어떤 메서드가 어떤 API를 어떤 문자열과 호출했는지'를 본다. 문자열 인자
귀속은 메서드 범위 휴리스틱이고(레지스터 데이터플로 미추적), 알 수 없는 명령은
해당 지점만 건너뛴다(보수적 파싱, 부분 결과 허용).
"""
from __future__ import annotations

import struct

from . import dex as dexmod

CRYPTO_GETINSTANCE_CLASSES = ("Ljavax/crypto/Cipher;", "Ljava/security/MessageDigest;")
WEBVIEW_APIS = {
    ("Landroid/webkit/WebSettings;", "setJavaScriptEnabled"),
    ("Landroid/webkit/WebSettings;", "setAllowFileAccess"),
    ("Landroid/webkit/WebSettings;", "setAllowUniversalAccessFromFileURLs"),
    ("Landroid/webkit/WebSettings;", "setSavePassword"),
    ("Landroid/webkit/WebView;", "addJavascriptInterface"),
}
DYNAMIC_APIS = {
    ("Ldalvik/system/DexClassLoader;", "<init>"),
    ("Ldalvik/system/InMemoryDexClassLoader;", "<init>"),
    ("Ljava/lang/Runtime;", "exec"),
    ("Ljava/lang/System;", "load"),
    ("Ljava/lang/System;", "loadLibrary"),
    ("Ljava/lang/reflect/Method;", "invoke"),
}


def _build_sizes():
    sizes = [1] * 256
    for op, size in [
        (0x02, 2), (0x03, 3), (0x05, 2), (0x06, 3), (0x08, 2), (0x09, 3),
        (0x13, 2), (0x14, 3), (0x15, 2), (0x16, 2), (0x17, 3), (0x18, 5), (0x19, 2),
        (0x1A, 2), (0x1B, 3), (0x1C, 2), (0x1F, 2), (0x20, 2), (0x22, 2), (0x23, 2),
        (0x24, 3), (0x25, 3), (0x26, 3), (0x29, 2), (0x2A, 3), (0x2B, 3), (0x2C, 3),
        (0xFA, 4), (0xFB, 4), (0xFC, 3), (0xFD, 3),
    ]:
        sizes[op] = size
    for op in range(0x2D, 0x3E):  # cmp*(23x) 0x2D-0x31 + if*(22t) 0x32-0x3D — 모두 2유닛
        sizes[op] = 2
    for op in range(0x44, 0x6E):
        sizes[op] = 2
    for op in range(0x6E, 0x73):
        sizes[op] = 3
    for op in range(0x74, 0x79):
        sizes[op] = 3
    for op in range(0x90, 0xB0):
        sizes[op] = 2
    for op in range(0xD0, 0xE3):
        sizes[op] = 2
    sizes[0xFE] = 2  # const-method-handle (21c)
    sizes[0xFF] = 2  # const-method-type (21c)
    return sizes


INSTRUCTION_SIZES = _build_sizes()


def _weak_algo(value: str) -> bool:
    text = value.strip()
    if text in ("MD5", "SHA1", "SHA-1", "DES", "DESede", "RC4"):
        return True
    return any(token in text for token in ("DES/", "/DES", "RC4", "ECB", "MD5", "SHA1", "SHA-1"))


def pretty_type(descriptor: str) -> str:
    return descriptor[1:-1].replace("/", ".")


def _short(descriptor: str) -> str:
    return descriptor[1:-1].rsplit("/", 1)[-1]


class DexCode:
    """헤더·문자열·타입·메서드 id·클래스 정의까지 읽은 DEX 뷰."""

    def __init__(self, data: bytes) -> None:
        if len(data) < 0x70 or data[:4] != b"dex\n":
            raise ValueError("DEX가 아님")
        (self.string_count, self.string_off) = struct.unpack_from("<II", data, 0x38)
        (self.type_count, self.type_off) = struct.unpack_from("<II", data, 0x40)
        (self.proto_count, self.proto_off) = struct.unpack_from("<II", data, 0x48)
        (self.method_count, self.method_off) = struct.unpack_from("<II", data, 0x58)
        (self.class_count, self.class_off) = struct.unpack_from("<II", data, 0x60)
        self.data = data
        self.strings = dexmod.dex_strings(data)
        self._scan_cache = {}

    def _u32(self, off):
        return struct.unpack_from("<I", self.data, off)[0]

    def _u16(self, off):
        return struct.unpack_from("<H", self.data, off)[0]

    def type_name(self, idx: int) -> str:
        if not 0 <= idx < self.type_count:
            return "?"
        sidx = self._u32(self.type_off + 4 * idx)
        return self.strings[sidx] if 0 <= sidx < len(self.strings) else "?"

    def method_ref(self, mid: int):
        """method_id → (클래스 타입 디스크립터, 메서드명)."""
        if not 0 <= mid < self.method_count:
            return "?", "?"
        off = self.method_off + 8 * mid
        class_idx, _proto_idx, name_idx = struct.unpack_from("<HHI", self.data, off)
        name = self.strings[name_idx] if 0 <= name_idx < len(self.strings) else "?"
        return self.type_name(class_idx), name

    def iter_methods(self):
        """(선언 클래스 타입, method_id, code_off) 목록."""
        for i in range(self.class_count):
            base = self.class_off + 32 * i
            if base + 32 > len(self.data):
                break
            class_idx = self._u32(base)
            code_data_off = self._u32(base + 24)
            decl = self.type_name(class_idx)
            if not code_data_off or code_data_off >= len(self.data):
                continue
            pos = code_data_off

            def uleb(pos):
                result = 0
                shift = 0
                while pos < len(self.data) and shift <= 28:  # uleb128 최대 5바이트
                    b = self.data[pos]
                    pos += 1
                    result |= (b & 0x7F) << shift
                    if not b & 0x80:
                        return result, pos
                    shift += 7
                return result, pos

            counts = []
            for _ in range(4):
                value, pos = uleb(pos)
                counts.append(value)
            # 비정상적으로 큰 개수 필드 — 남은 바이트로 상한(2바이트/엔트리 최소)
            budget = max(0, (len(self.data) - pos) // 2)
            for _ in range(min(counts[0] + counts[1], budget)):  # 필드 건너뛰기
                _, pos = uleb(pos)
                _, pos = uleb(pos)
            for group in (counts[2], counts[3]):  # direct, virtual 메서드
                group = min(group, budget)
                mid_acc = 0
                for _ in range(group):
                    diff, pos = uleb(pos)
                    _access, pos = uleb(pos)
                    code_off, pos = uleb(pos)
                    mid_acc += diff
                    yield decl, mid_acc, code_off

    def scan_code(self, code_off: int):
        """code_item의 invoke 호출(method_id)과 const-string(문자열) 수집.

        여러 메서드가 같은 code_off를 공유하는 비정상 DEX에서 반복 스캔을 피한다.
        """
        if not code_off or code_off + 16 > len(self.data):
            return [], []
        if code_off in self._scan_cache:
            return self._scan_cache[code_off]
        result = self._scan_code_impl(code_off)
        if len(self._scan_cache) < 65536:
            self._scan_cache[code_off] = result
        return result

    def _scan_code_impl(self, code_off: int):
        insns_size = self._u32(code_off + 12)
        base = code_off + 16
        limit = min(insns_size, (len(self.data) - base) // 2)
        calls, strings = [], []
        pos = 0
        while pos < limit:
            unit = self._u16(base + 2 * pos)
            op = unit & 0xFF
            ident = unit >> 8
            if op == 0x00 and ident in (1, 2, 3):
                # 유사 명령 페이로드 — 전체 크기(코드 유닛)만큼 건너뛴다.
                # packed-switch(1): [식별, N, 키, N×타깃] = 4+2N
                # sparse-switch(2): [식별, N, N×키, N×타깃] = 2+4N
                # fill-array-data(3): [식별, 폭, 개수, 데이터] = 4+ceil(개수×폭/2)
                if pos + 4 <= limit:
                    if ident == 1:
                        size = 4 + 2 * self._u16(base + 2 * (pos + 1))
                    elif ident == 2:
                        size = 2 + 4 * self._u16(base + 2 * (pos + 1))
                    else:
                        width = self._u16(base + 2 * (pos + 1))
                        count = self._u32(base + 2 * (pos + 2))
                        size = 4 + (count * width + 1) // 2
                else:
                    size = 1
            else:
                size = INSTRUCTION_SIZES[op]
            if size <= 0:
                size = 1
            if 0x6E <= op <= 0x78 and op != 0x73 and pos + 1 < limit:
                calls.append(self._u16(base + 2 * (pos + 1)))
            if op == 0x1A and pos + 1 < limit:
                idx = self._u16(base + 2 * (pos + 1))
                if idx < len(self.strings):
                    strings.append(self.strings[idx])
            elif op == 0x1B and pos + 2 < limit:
                idx = self._u32(base + 2 * (pos + 1))
                if idx < len(self.strings):
                    strings.append(self.strings[idx])
            pos += size
        return calls, strings


def analyze_dex(data: bytes):
    """단일 DEX의 민감 API 호출 분석. 파싱 실패 시 None."""
    try:
        dx = DexCode(data)  # __init__에서 문자열 테이블까지 파싱(예외 여기서 발견)
    except (ValueError, struct.error, IndexError):
        return None
    weak, webview, dynamic = [], [], []
    scanned = 0
    try:
        for decl, mid, code_off in dx.iter_methods():
            if not code_off:
                continue
            scanned += 1
            calls, strings = dx.scan_code(code_off)
            if not calls:
                continue
            label = f"{pretty_type(decl)}->{dx.method_ref(mid)[1]}"
            for call_mid in calls:
                cls, name = dx.method_ref(call_mid)
                if cls in CRYPTO_GETINSTANCE_CLASSES and name == "getInstance":
                    for s in strings:
                        if _weak_algo(s):
                            weak.append(f"{label} ▸ {_short(cls)}.getInstance('{s}')")
                if (cls, name) in WEBVIEW_APIS:
                    webview.append(f"{label} ▸ {_short(cls)}.{name}()")
                if (cls, name) in DYNAMIC_APIS:
                    dynamic.append(f"{label} ▸ {pretty_type(cls)}.{name}()")
    except (struct.error, IndexError):
        pass  # 부분 결과라도 반환
    return {
        "scanned": scanned,
        "weak_crypto": sorted(set(weak)),
        "webview": sorted(set(webview)),
        "dynamic": sorted(set(dynamic)),
    }


def scan_apk(apk) -> dict:
    """APK 전체 DEX 분석. 분석 가능한 dex가 하나라도 있으면 available=True."""
    result = {"available": False, "scanned": 0,
              "weak_crypto": [], "webview": [], "dynamic": []}
    import re as _re

    for name in apk.entry_names():
        if _re.fullmatch(r"classes\d*\.dex", name):
            try:
                data = apk.read(name)
            except Exception:
                continue  # 손상 엔트리 — 부분 결과라도 계속
            analysis = analyze_dex(data)
            if analysis is None or analysis["scanned"] == 0:
                continue
            result["available"] = True
            result["scanned"] += analysis["scanned"]
            for key in ("weak_crypto", "webview", "dynamic"):
                result[key] = sorted(set(result[key] + analysis[key]))
    return result
