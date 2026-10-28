"""DEX 코드 분석 — 클래스/메서드 정의와 바이트코드를 읽어 민감 API 호출 지점 추출.

디컴파일러가 아니다: invoke 계열 명령의 method_id와 메서드 내 const-string만
추적해 '어떤 메서드가 어떤 API를 어떤 문자열과 호출했는지'를 본다. 문자열 인자
귀속은 메서드 범위 휴리스틱이다. 단, bare AES는 분기 전 선형 명령의 문자열
레지스터가 실제 Cipher.getInstance 인자인 경우만 수집한다. 일반적인 데이터플로·
taint 분석은 아니며 알 수 없는 명령은 부분 결과를 허용한다.
"""

from __future__ import annotations

import struct

from . import dex as dexmod

MAX_METHODS = 100000
MAX_CLASS_DATA_ENTRIES = 200000
MAX_INSTRUCTIONS = 1000000
MAX_METHOD_INSTRUCTIONS = 65536
MAX_FINDINGS = 10000

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
        (0x02, 2),
        (0x03, 3),
        (0x05, 2),
        (0x06, 3),
        (0x08, 2),
        (0x09, 3),
        (0x13, 2),
        (0x14, 3),
        (0x15, 2),
        (0x16, 2),
        (0x17, 3),
        (0x18, 5),
        (0x19, 2),
        (0x1A, 2),
        (0x1B, 3),
        (0x1C, 2),
        (0x1F, 2),
        (0x20, 2),
        (0x22, 2),
        (0x23, 2),
        (0x24, 3),
        (0x25, 3),
        (0x26, 3),
        (0x29, 2),
        (0x2A, 3),
        (0x2B, 3),
        (0x2C, 3),
        (0xFA, 4),
        (0xFB, 4),
        (0xFC, 3),
        (0xFD, 3),
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
        for count, offset, width in (
            (self.string_count, self.string_off, 4),
            (self.type_count, self.type_off, 4),
            (self.proto_count, self.proto_off, 12),
            (self.method_count, self.method_off, 8),
            (self.class_count, self.class_off, 32),
        ):
            if count > MAX_CLASS_DATA_ENTRIES or offset + count * width > len(data):
                raise ValueError("Invalid/budgeted DEX metadata table")
        self.complete = True
        self.reasons = []
        self._instruction_count = 0
        self.instruction_budget = MAX_INSTRUCTIONS
        self.method_budget = MAX_METHODS
        self.entry_budget = MAX_CLASS_DATA_ENTRIES
        self.metadata_entries = 0
        self.data = data
        self.strings = dexmod.dex_strings(data)
        self._scan_cache = {}
        self._bare_aes_calls = {}

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

    def _incomplete(self, reason):
        self.complete = False
        if not hasattr(self, "reasons"):
            self.reasons = []
        if reason not in self.reasons:
            self.reasons.append(reason)

    def iter_methods(self):
        """Walk each class-data block once, with a global metadata-entry budget."""
        visited, entries, methods = set(), 0, 0
        for i in range(self.class_count):
            base = self.class_off + 32 * i
            if base + 32 > len(self.data):
                self._incomplete("truncated class definitions")
                return
            class_idx = self._u32(base)
            code_data_off = self._u32(base + 24)
            decl = self.type_name(class_idx)
            if not code_data_off:
                continue
            if code_data_off in visited:
                self._incomplete("aliased class-data block")
                continue
            visited.add(code_data_off)
            pos = code_data_off

            def uleb(at):
                result = 0
                for shift in range(0, 35, 7):
                    if at >= len(self.data):
                        raise ValueError("truncated class-data ULEB")
                    byte = self.data[at]
                    at += 1
                    result |= (byte & 0x7F) << shift
                    if not byte & 0x80:
                        return result, at
                raise ValueError("invalid class-data ULEB")

            counts = []
            for _ in range(4):
                value, pos = uleb(pos)
                counts.append(value)
            if entries + sum(counts) > self.entry_budget:
                self._incomplete("class-data entry budget")
                return
            entries += sum(counts)
            self.metadata_entries = entries
            for _ in range(counts[0] + counts[1]):
                _, pos = uleb(pos)
                _, pos = uleb(pos)
            for group in (counts[2], counts[3]):
                mid_acc = 0
                for _ in range(group):
                    if methods >= self.method_budget:
                        self._incomplete("method budget")
                        return
                    methods += 1
                    diff, pos = uleb(pos)
                    _access, pos = uleb(pos)
                    code_off, pos = uleb(pos)
                    mid_acc += diff
                    if mid_acc >= self.method_count:
                        raise ValueError("method index outside table")
                    yield decl, mid_acc, code_off

    def scan_code(self, code_off: int):
        """code_item의 invoke 호출(method_id)과 const-string(문자열) 수집.

        여러 메서드가 같은 code_off를 공유하는 비정상 DEX에서 반복 스캔을 피한다.
        """
        if not code_off or code_off + 16 > len(self.data):
            self._incomplete("truncated code item")
            return [], []
        if code_off in self._scan_cache:
            return self._scan_cache[code_off]
        result = self._scan_code_impl(code_off)
        if len(self._scan_cache) < 65536:
            self._scan_cache[code_off] = result
        return result

    def _scan_code_impl(self, code_off: int):
        insns_size = self._u32(code_off + 12)
        register_count = self._u16(code_off)
        # Only the entry prefix is proven: no exception entries or unmodelled
        # control flow may reach a call while bypassing its const-string.
        linear_prefix = self._u16(code_off + 6) == 0
        aes_registers, bare_aes_calls = set(), set()
        base = code_off + 16
        remaining = max(
            0, getattr(self, "instruction_budget", MAX_INSTRUCTIONS) - getattr(self, "_instruction_count", 0)
        )
        limit = min(insns_size, (len(self.data) - base) // 2, MAX_METHOD_INSTRUCTIONS, remaining)
        if limit < insns_size:
            self._incomplete("truncated/budgeted instructions")
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
            if pos + size > limit:
                self._incomplete("truncated instruction")
                break
            if linear_prefix:
                if op in (0x1A, 0x1B):
                    idx = self._u16(base + 2 * (pos + 1)) if op == 0x1A else self._u32(base + 2 * (pos + 1))
                    aes_registers.discard(ident)
                    if ident < register_count and idx < len(self.strings) and self.strings[idx] == "AES":
                        aes_registers.add(ident)
                elif op in (0x07, 0x08, 0x09):  # move-object[/from16|/16]
                    if op == 0x07:
                        dest, source = ident & 0xF, ident >> 4
                    elif op == 0x08:
                        dest, source = ident, self._u16(base + 2 * (pos + 1))
                    else:
                        dest = self._u16(base + 2 * (pos + 1))
                        source = self._u16(base + 2 * (pos + 2))
                    is_aes = source in aes_registers and source < register_count
                    aes_registers.discard(dest)
                    if is_aes and dest < register_count:
                        aes_registers.add(dest)
                elif op in (0x71, 0x77):  # invoke-static (35c), invoke-static/range (3rc)
                    count = ident >> 4 if op == 0x71 else ident
                    args = self._u16(base + 2 * (pos + 2))
                    first = args & 0xF if op == 0x71 else args
                    if op == 0x71:
                        registers = [*(args >> shift & 0xF for shift in (0, 4, 8, 12)), ident & 0xF]
                        valid = 1 <= count <= 5 and all(r < register_count for r in registers[:count])
                    else:
                        valid = 1 <= count <= register_count - first
                    if valid and first in aes_registers:
                        call_mid = self._u16(base + 2 * (pos + 1))
                        bare_aes_calls.add(call_mid)
                elif op in (0x6E, 0x6F, 0x70, 0x72, 0x74, 0x75, 0x76, 0x78) or unit == 0:
                    pass  # Invokes do not overwrite caller registers; move-result does.
                elif op in (0x0E, 0x0F, 0x10, 0x11, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C) or (
                    0x32 <= op <= 0x3D
                ):
                    linear_prefix = False
                elif (
                    0x01 <= op <= 0x26
                    or 0x2D <= op <= 0x31
                    or 0x44 <= op <= 0x6D
                    or 0x7B <= op <= 0xE2
                    or op in (0xFA, 0xFB, 0xFC, 0xFD, 0xFE, 0xFF)
                ):
                    # Conservatively invalidate all literals for other known
                    # instructions, including wide writes and field/array reads.
                    aes_registers.clear()
                else:
                    # Unknown opcodes/payloads could alter control flow. Keep
                    # already proven prefix calls, but never resume attribution.
                    linear_prefix = False
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
        if not hasattr(self, "_bare_aes_calls"):
            self._bare_aes_calls = {}
        self._bare_aes_calls[code_off] = bare_aes_calls
        self._instruction_count = getattr(self, "_instruction_count", 0) + limit
        return calls, strings


def analyze_dex(data: bytes, *, instruction_budget=None, method_budget=None, entry_budget=None):
    """단일 DEX의 민감 API 호출 분석. 파싱 실패 시 None."""
    try:
        dx = DexCode(data)  # __init__에서 문자열 테이블까지 파싱(예외 여기서 발견)
    except (ValueError, struct.error, IndexError):
        return None
    if instruction_budget is not None:
        dx.instruction_budget = max(0, min(MAX_INSTRUCTIONS, instruction_budget))
    if method_budget is not None:
        dx.method_budget = max(0, min(MAX_METHODS, method_budget))
    if entry_budget is not None:
        dx.entry_budget = max(0, min(MAX_CLASS_DATA_ENTRIES, entry_budget))
    weak, webview, dynamic = [], [], []
    scanned = 0
    try:
        for decl, mid, code_off in dx.iter_methods():
            if not code_off:
                continue
            if dx._instruction_count >= dx.instruction_budget:
                dx._incomplete("global instruction budget")
                break
            scanned += 1
            calls, strings = dx.scan_code(code_off)
            if not calls:
                continue
            label = f"{pretty_type(decl)[:512]}->{dx.method_ref(mid)[1][:512]}"
            weak_strings = sorted({s for s in set(strings) if _weak_algo(s)})
            for call_mid in set(calls):
                if len(weak) + len(webview) + len(dynamic) >= MAX_FINDINGS:
                    dx._incomplete("finding budget")
                    break
                cls, name = dx.method_ref(call_mid)
                if cls in CRYPTO_GETINSTANCE_CLASSES and name == "getInstance":
                    values = weak_strings
                    if cls == "Ljavax/crypto/Cipher;" and call_mid in dx._bare_aes_calls.get(code_off, ()):
                        values = [*values, "AES"]
                    for value in values:
                        if len(weak) + len(webview) + len(dynamic) >= MAX_FINDINGS:
                            dx._incomplete("finding budget")
                            break
                        weak.append(f"{label} ▸ {_short(cls)}.getInstance('{value[:160]}')")
                if (cls, name) in WEBVIEW_APIS:
                    webview.append(f"{label} ▸ {_short(cls)}.{name}()")
                if (cls, name) in DYNAMIC_APIS:
                    dynamic.append(f"{label} ▸ {pretty_type(cls)}.{name}()")
            if not dx.complete and "finding budget" in dx.reasons:
                break
    except (struct.error, IndexError, ValueError):
        dx._incomplete("malformed bytecode metadata")
    return {
        "scanned": scanned,
        "complete": dx.complete,
        "instructions": dx._instruction_count,
        "metadata_entries": dx.metadata_entries,
        "reasons": dx.reasons,
        "weak_crypto": sorted(set(weak)),
        "webview": sorted(set(webview)),
        "dynamic": sorted(set(dynamic)),
    }


def scan_apk(apk) -> dict:
    """Aggregate results without allowing one good DEX to hide incomplete peers."""
    result = {
        "available": False,
        "complete": True,
        "failed": 0,
        "entries": 0,
        "scanned": 0,
        "reasons": [],
        "weak_crypto": [],
        "webview": [],
        "dynamic": [],
    }
    import re as _re

    remaining_instructions, remaining_methods, remaining_entries = (
        MAX_INSTRUCTIONS,
        MAX_METHODS,
        MAX_CLASS_DATA_ENTRIES,
    )
    for name in apk.entry_names():
        if not _re.fullmatch(r"classes\d*\.dex", name):
            continue
        result["entries"] += 1
        try:
            analysis = (
                analyze_dex(
                    apk.read(name),
                    instruction_budget=remaining_instructions,
                    method_budget=remaining_methods,
                    entry_budget=remaining_entries,
                )
                if min(remaining_instructions, remaining_methods, remaining_entries) > 0
                else None
            )
        except Exception:
            analysis = None
        if analysis is None or not analysis["complete"] or analysis["scanned"] == 0:
            result["complete"] = False
            result["failed"] += 1
        if analysis is None:
            continue
        remaining_instructions -= analysis["instructions"]
        remaining_methods -= analysis["scanned"]
        remaining_entries -= analysis["metadata_entries"]
        result["available"] = result["available"] or analysis["scanned"] > 0
        result["scanned"] += analysis["scanned"]
        for key in ("weak_crypto", "webview", "dynamic"):
            merged = sorted(set(result[key]).union(analysis[key]))
            if len(merged) > MAX_FINDINGS:
                result["complete"] = False
                if "aggregate finding budget" not in result["reasons"]:
                    result["reasons"].append("aggregate finding budget")
            result[key] = merged[:MAX_FINDINGS]
    if result["entries"] == 0:
        result["complete"] = False
    return result
