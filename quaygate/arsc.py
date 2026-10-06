"""resources.arsc 최소 파싱 — 리소스 ID(int) → (타입명, 엔트리명, 값 문자열) 매핑.

리소스 경로 난독화(res/xY.xml 해시명)를 가진 APK는 파일 경로가 엔트리 값의
문자열에 들어 있으므로, 이름뿐 아니라 STRING 값도 읽는다: 패키지의
typeStrings/keyStrings 풀, 테이블 전역 문자열 풀, RES_TABLE_TYPE 청크의 엔트리.
aapt2의 sparse(FLAG_SPARSE — u16 idx + u16 offset×4)·OFFSET16(u16 offset×4)·
compact(엔트리 하위 0x08 마커 — key=u16@0, type=flags>>8, data=u32@4) 엔트리도
필요한 범위만 처리한다. bool 값(TYPE_INT_BOOLEAN)은 value 문자열 자리에
"true"/"false"로 기록해 @bool 참조 해석에 쓴다.
비정상 청크는 건너뛰고 부분 결과라도 반환한다(보수적 파싱).
"""
from __future__ import annotations

import struct

from .axml import _read_string_pool

RES_TABLE_TYPE = 0x0002
RES_STRING_POOL_TYPE = 0x0001
RES_TABLE_PACKAGE_TYPE = 0x0200
RES_TABLE_TYPE_TYPE = 0x0201
NO_ENTRY = 0xFFFFFFFF
# ResTable_type.flags — 헤더 +9의 u8
FLAG_SPARSE = 0x01
FLAG_OFFSET16 = 0x02
# ResTable_entry.flags
FLAG_COMPLEX = 0x0001  # 맵/스타일 — 값 없음
FLAG_COMPACT = 0x0008  # aapt2 compact — key=u16@0, type=flags>>8, data=u32@4
TYPE_STRING = 0x03     # Res_value 타입(전역 문자열 풀 참조)
TYPE_INT_BOOLEAN = 0x12
PACKAGE_HEADER_MIN = 8 + 4 + 256 + 16  # 청크 헤더 + id + 이름(char16[128]) + 4×u32


def _u32(data, off):
    return struct.unpack_from("<I", data, off)[0]


def _u16(data, off):
    return struct.unpack_from("<H", data, off)[0]


def parse_resource_names(data: bytes) -> dict:
    names = {}
    if len(data) < 12:
        return names
    ftype, _fheader, fsize = struct.unpack_from("<HHI", data, 0)
    if ftype != RES_TABLE_TYPE:
        return names
    limit = min(len(data), fsize)
    global_strings = []
    pos = 12
    while pos + 8 <= limit:
        ctype, _cheader, csize = struct.unpack_from("<HHI", data, pos)
        if csize <= 0 or pos + csize > limit:
            break
        if ctype == RES_STRING_POOL_TYPE:
            try:
                global_strings = _read_string_pool(data, pos)
            except (struct.error, IndexError):
                global_strings = []
        elif ctype == RES_TABLE_PACKAGE_TYPE:
            _parse_package(data, pos, csize, global_strings, names)
        pos += csize
    return names


def _parse_package(data, pos, csize, global_strings, out):
    if csize < PACKAGE_HEADER_MIN:
        return
    pkg_id = _u32(data, pos + 8)
    header_size = _u16(data, pos + 2)
    if header_size < PACKAGE_HEADER_MIN or header_size > csize:
        header_size = PACKAGE_HEADER_MIN
    type_off = _u32(data, pos + 12 + 256)         # typeStrings(헤더8+id4+이름256 뒤)
    key_off = _u32(data, pos + 12 + 256 + 8)      # keyStrings(사이 lastPublicType 건너뜀)
    if not type_off or not key_off or pos + type_off >= pos + csize:
        return
    try:
        type_strings = _read_string_pool(data, pos + type_off)
        key_strings = _read_string_pool(data, pos + key_off)
    except (struct.error, IndexError):
        return
    if not type_strings or not key_strings:
        return
    inner = pos + header_size
    end = pos + csize
    while inner + 8 <= end:
        ctype, _cheader, ccsz = struct.unpack_from("<HHI", data, inner)
        if ccsz <= 0 or inner + ccsz > end:
            break
        if ctype == RES_TABLE_TYPE_TYPE:
            _parse_type_chunk(data, inner, ccsz, pkg_id, type_strings, key_strings,
                              global_strings, out)
        inner += ccsz


def _parse_type_chunk(data, pos, csize, pkg_id, type_strings, key_strings,
                      global_strings, out):
    if csize < 24:
        return
    type_id = data[pos + 8]
    flags = data[pos + 9]  # ResTable_type.flags — +9 u8(+10은 reserved)
    entry_count = _u32(data, pos + 12)
    entries_start = _u32(data, pos + 16)
    config_size = _u32(data, pos + 20)
    if config_size < 8 or config_size > csize:
        config_size = 8
    offsets_pos = pos + 20 + config_size
    entries_base = pos + entries_start
    if not 0 < type_id <= len(type_strings):
        return
    type_name = type_strings[type_id - 1]

    def record(entry_idx, entry_off):
        if entry_off < 0 or entry_off + 4 > len(data):
            return
        entry_flags = _u16(data, entry_off + 2)
        vtype = vdata = None
        value_off = None
        if entry_flags & FLAG_COMPLEX:
            if entry_off + 8 > len(data):
                return
            key = _u32(data, entry_off + 4)
        elif entry_flags & FLAG_COMPACT:
            key = _u16(data, entry_off)
            vtype = entry_flags >> 8
            if entry_off + 8 > len(data):
                return
            vdata = _u32(data, entry_off + 4)
        else:
            if entry_off + 8 > len(data):
                return
            key = _u32(data, entry_off + 4)
            value_off = entry_off + max(_u16(data, entry_off), 8)
        if key >= len(key_strings):
            return
        if value_off is not None and value_off + 8 <= len(data):
            _vsize, _res0, vtype, vdata = struct.unpack_from("<HBBI", data, value_off)
        value_text = None
        if vtype == TYPE_STRING and vdata is not None and vdata < len(global_strings):
            value_text = global_strings[vdata] or None
        elif vtype == TYPE_INT_BOOLEAN and vdata is not None:
            value_text = "true" if vdata else "false"
        out[(pkg_id << 24) | (type_id << 16) | entry_idx] = (type_name, key_strings[key], value_text)

    if flags & FLAG_SPARSE:
        for i in range(entry_count):
            o = offsets_pos + 4 * i
            if o + 4 > len(data):
                break
            idx, off16 = struct.unpack_from("<HH", data, o)
            # complex 엔트리는 offset 상위 비트(0x8000)로 마킹된다(SPARSE_COMPLEX_CODE)
            record(idx, entries_base + (off16 & 0x7FFF) * 4)
    elif flags & FLAG_OFFSET16:
        for i in range(entry_count):
            o = offsets_pos + 2 * i
            if o + 2 > len(data):
                break
            (off16,) = struct.unpack_from("<H", data, o)
            if off16 == 0xFFFF:  # NO_ENTRY16 is a sentinel, not a scaled offset.
                continue
            record(i, entries_base + off16 * 4)
    else:
        for i in range(entry_count):
            o = offsets_pos + 4 * i
            if o + 4 > len(data):
                break
            off = _u32(data, o)
            if off == NO_ENTRY:
                continue
            record(i, entries_base + off)
