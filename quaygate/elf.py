"""ELF(안드로이드 네이브 라이브러리 .so) 하드닝 점검 — checksec 최소판.

프로그램 헤더에서 PIE/NX/RELRO를, PT_DYNAMIC 태그에서 BIND_NOW(풀 RELRO)를 읽는다.
카나리는 가져오기 심볼 문자열(__stack_chk_fail) 탐지로 판단한다 — 섹션 헤더가
stripped된 파일에서도 동작하는 휴리스틱이다.
"""
from __future__ import annotations

import struct

PT_DYNAMIC = 2
PT_GNU_STACK = 0x6474E551
PT_GNU_RELRO = 0x6474E552
DT_NULL = 0
DT_BINDNOW = 24
DT_FLAGS = 0x1E
DF_BIND_NOW = 0x8
DT_FLAGS_1 = 0x6FFFFFFB
DF_1_NOW = 0x1
CANARY_SYMBOL = b"__stack_chk_fail"


def _binds_now(data: bytes, dynamic, endian: str, is64: bool) -> bool:
    if not dynamic:
        return False
    doff, dsize = dynamic
    pos = doff
    end = min(doff + dsize, len(data))
    entry = struct.Struct(endian + ("QQ" if is64 else "II"))
    while pos + entry.size <= end:
        tag, val = entry.unpack_from(data, pos)
        if tag == DT_NULL:
            return False
        if tag == DT_BINDNOW:
            return True
        if tag == DT_FLAGS and val & DF_BIND_NOW:
            return True
        if tag == DT_FLAGS_1 and val & DF_1_NOW:
            return True
        pos += entry.size
    return False


def parse(data: bytes):
    """{pie, nx, relro, canary} 반환. ELF가 아니거나 해석 불가면 None."""
    if len(data) < 64 or data[:4] != b"\x7fELF":
        return None
    is64 = data[4] == 2
    endian = "<" if data[5] == 1 else ">"
    try:
        (e_type,) = struct.unpack_from(endian + "H", data, 16)
        if is64:
            (phoff,) = struct.unpack_from(endian + "Q", data, 32)
            (_entsize, phnum) = struct.unpack_from(endian + "HH", data, 54)
            phsize = 56
        else:
            (phoff,) = struct.unpack_from(endian + "I", data, 28)
            (_entsize, phnum) = struct.unpack_from(endian + "HH", data, 42)
            phsize = 32
        if phoff >= len(data):
            return None
        pie = e_type == 3
        nx = None  # No GNU_STACK declaration: runtime NX cannot be established here.
        has_relro = False
        dynamic = None
        for i in range(min(phnum, 128)):
            off = phoff + phsize * i
            if off + phsize > len(data):
                break
            (p_type,) = struct.unpack_from(endian + "I", data, off)
            if p_type == PT_GNU_STACK:
                # Elf64_Phdr.p_flags@+4 / Elf32_Phdr.p_flags@+24(표준 레이아웃)
                flags_off = off + 4 if is64 else off + 24
                (flags,) = struct.unpack_from(endian + "I", data, flags_off)
                nx = not (flags & 0x1)  # PF_X
            elif p_type == PT_GNU_RELRO:
                has_relro = True
            elif p_type == PT_DYNAMIC:
                if is64:
                    doff = struct.unpack_from(endian + "Q", data, off + 8)[0]
                    dsize = struct.unpack_from(endian + "Q", data, off + 32)[0]
                else:
                    doff = struct.unpack_from(endian + "I", data, off + 4)[0]
                    dsize = struct.unpack_from(endian + "I", data, off + 16)[0]
                dynamic = (doff, dsize)
    except struct.error:
        return None
    if has_relro and _binds_now(data, dynamic, endian, is64):
        relro = "full"
    elif has_relro:
        relro = "partial"
    else:
        relro = "none"
    return {
        "pie": pie,
        "nx": nx,
        "relro": relro,
        "canary": CANARY_SYMBOL in data,
    }
