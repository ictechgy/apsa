"""DEX(Dalvik Executable) 문자열 테이블 추출.

완전한 DEX 파서가 아니다 — 정적 지표 스캔에 필요한 string_ids만 읽는다.
형식이 달라도 예외 대신 빈 결과를 돌려 점검이 멈추지 않게 한다.
"""
from __future__ import annotations

import struct


def dex_strings(data: bytes) -> list:
    if len(data) < 0x40 or data[:4] != b"dex\n":
        raise ValueError("DEX 파일이 아닙니다")
    count, offset = struct.unpack_from("<II", data, 0x38)
    if count > len(data) or offset + 4 * count > len(data):
        raise ValueError("DEX 헤더 문자열 테이블 범위 비정상")
    out = []
    for i in range(count):
        (str_off,) = struct.unpack_from("<I", data, offset + 4 * i)
        if str_off >= len(data):
            continue
        # string_data_item: uleb128 utf16 크기 + MUTF-8 바이트 + NUL
        result = 0
        shift = 0
        pos = str_off
        while pos < len(data) and shift <= 28:  # uleb128 최대 5바이트
            b = data[pos]
            pos += 1
            result |= (b & 0x7F) << shift
            if not b & 0x80:
                break
            shift += 7
        end = data.find(b"\x00", pos)
        if end < 0:
            end = len(data)
        out.append(data[pos:end].decode("utf-8", "replace"))
    return out
