"""DEX(Dalvik Executable) 문자열 테이블 추출.

완전한 DEX 파서가 아니다 — 정적 지표 스캔에 필요한 string_ids만 읽는다.
형식이 달라도 예외 대신 빈 결과를 돌려 점검이 멈추지 않게 한다.
"""

from __future__ import annotations

import struct

MAX_STRINGS = 200000
MAX_STRING_BYTES = 8 * 1024 * 1024
MAX_SINGLE_STRING_BYTES = 64 * 1024


def dex_strings(data: bytes) -> list:
    if len(data) < 0x40 or data[:4] != b"dex\n":
        raise ValueError("DEX 파일이 아닙니다")
    count, offset = struct.unpack_from("<II", data, 0x38)
    if count > MAX_STRINGS or offset + 4 * count > len(data):
        raise ValueError("DEX 헤더 문자열 테이블 범위/개수 비정상")
    out, decoded, total = [], {}, 0
    for i in range(count):
        (str_off,) = struct.unpack_from("<I", data, offset + 4 * i)
        if str_off in decoded:
            out.append(decoded[str_off])
            continue
        pos, units = str_off, 0
        for shift in range(0, 35, 7):
            if pos >= len(data):
                raise ValueError("Truncated DEX string length")
            byte = data[pos]
            pos += 1
            units |= (byte & 0x7F) << shift
            if not byte & 0x80:
                break
        else:
            raise ValueError("Invalid DEX string length")
        if units > MAX_SINGLE_STRING_BYTES:
            raise ValueError("DEX single-string budget exceeded")
        end = data.find(b"\0", pos, min(len(data), pos + min(3 * units, MAX_SINGLE_STRING_BYTES) + 1))
        if end < 0:
            raise ValueError("Unterminated/oversized DEX string")
        total += end - pos
        if total > MAX_STRING_BYTES:
            raise ValueError("DEX decoded-string budget exceeded")
        value = data[pos:end].decode("utf-8", "replace")
        decoded[str_off] = value
        out.append(value)
    return out
