"""Android 바이너리 XML(AXML) 파서.

AndroidManifest.xml 등 리소스 XML은 텍스트가 아니라 컴파일된 청크 포맷이다.
AOSP ResourceTypes.h 형식을 따르며, 알 수 없는 청크는 건너뛴다(보수적 파싱).
"""
from __future__ import annotations

import struct


def _plain_xml(data: bytes) -> list:
    """Fixture/development XML; reject declarations that can expand entities."""
    import io
    import xml.etree.ElementTree as ET

    if len(data) > 8 * 1024 * 1024 or b"<!DOCTYPE" in data or b"<!ENTITY" in data:
        raise AxmlError("Text XML exceeds limits or contains a DTD/entity declaration")
    events = []
    depth = 0
    try:
        for event, element in ET.iterparse(io.BytesIO(data), events=("start", "end")):
            name = element.tag.rsplit("}", 1)[-1]
            if event == "start":
                depth += 1
                if depth > 128 or len(events) > 12000:
                    raise AxmlError("Text XML exceeds structural limits")
                attrs = {key.rsplit("}", 1)[-1]: value for key, value in element.attrib.items()}
                events.append(("start", name, attrs))
            else:
                if element.text and element.text.strip():
                    events.append(("text", element.text.strip(), None))
                events.append(("end", name, None))
                depth -= 1
                element.clear()
    except ET.ParseError as error:
        raise AxmlError("Invalid text XML") from error
    return events

RES_STRING_POOL_TYPE = 0x0001
RES_XML_START_NAMESPACE_TYPE = 0x0100
RES_XML_END_NAMESPACE_TYPE = 0x0101
RES_XML_START_ELEMENT_TYPE = 0x0102
RES_XML_END_ELEMENT_TYPE = 0x0103
RES_XML_CDATA_TYPE = 0x0104
RES_XML_RESOURCE_MAP_TYPE = 0x0180

TYPE_STRING = 0x03
TYPE_REFERENCE = 0x01
TYPE_INT_BOOLEAN = 0x12

UTF8_FLAG = 0x100
NO_INDEX = 0xFFFFFFFF


class AxmlError(ValueError):
    """AXML 파싱 실패."""


def _read_string(data: bytes, pos: int, is_utf8: bool) -> str:
    if is_utf8:
        n = data[pos]
        pos += 1
        if n & 0x80:
            n = ((n & 0x7F) << 8) | data[pos]
            pos += 1
        n = data[pos]  # 바이트 길이 — 문자 수와 다를 수 있지만 디코딩에는 불필요
        pos += 1
        if n & 0x80:
            pos += 1  # 확장 길이 두 번째 바이트
        end = data.find(b"\x00", pos)
        if end < 0:
            end = len(data)
        return data[pos:end].decode("utf-8", "replace")
    (n,) = struct.unpack_from("<H", data, pos)
    pos += 2
    if n & 0x8000:
        (n2,) = struct.unpack_from("<H", data, pos)
        pos += 2
        n = ((n & 0x7FFF) << 16) | n2
    raw = data[pos:pos + n * 2]
    return raw.decode("utf-16-le", "replace")


def _read_string_pool(data: bytes, start: int) -> list:
    (_, header_size, _size, string_count, _style_count, flags,
     strings_start, _styles_start) = struct.unpack_from("<HHIIIIII", data, start)
    is_utf8 = bool(flags & UTF8_FLAG)
    strings = []
    for i in range(string_count):
        (off,) = struct.unpack_from("<I", data, start + header_size + 4 * i)
        try:
            strings.append(_read_string(data, start + strings_start + off, is_utf8))
        except (struct.error, IndexError):
            strings.append("")
    return strings


def _pool_ref(strings: list, idx: int) -> str:
    if idx == NO_INDEX or idx >= len(strings):
        return ""
    return strings[idx]


def _decode_attr_value(strings: list, raw: int, data_type: int, data: int) -> str:
    if raw != NO_INDEX and raw < len(strings):
        return strings[raw]
    if data_type == TYPE_STRING:
        return _pool_ref(strings, data)
    if data_type == TYPE_INT_BOOLEAN:
        return "true" if data else "false"
    if data_type == TYPE_REFERENCE:
        return f"@{data}"
    return str(data)


def parse_axml(data: bytes) -> list:
    """이벤트 목록 반환: ("start", 태그명, {속성명: 값}) / ("end", 태그명, None) /
    ("text", 텍스트, None) — res/xml 설정 파일의 도메인명 등 텍스트 노드."""
    if data.lstrip().startswith(b"<"):
        return _plain_xml(data)
    if len(data) < 8:
        raise AxmlError("데이터가 너무 짧습니다")
    ftype, fheader, fsize = struct.unpack_from("<HHI", data, 0)
    if ftype != 0x0003:
        raise AxmlError("AXML 파일이 아닙니다(매직 불일치)")
    strings: list = []
    events: list = []
    pos = fheader
    limit = min(len(data), fsize)
    while pos + 8 <= limit:
        try:
            ctype, cheader, csize = struct.unpack_from("<HHI", data, pos)
            if csize < cheader or csize <= 0 or pos + csize > limit:
                break  # 잘렸거나 비정상 청크 — 여기까지의 결과만 반환
            if ctype == RES_STRING_POOL_TYPE:
                strings = _read_string_pool(data, pos)
            elif ctype == RES_XML_START_ELEMENT_TYPE:
                ext = pos + max(cheader, 16)  # 확장부는 노드 headerSize 기반(변형 허용)
                (_ns, name, attr_start, attr_size, attr_count, _id, _cls, _style) = \
                    struct.unpack_from("<IIHHHHHH", data, ext)
                attrs = {}
                for i in range(attr_count):
                    base = ext + attr_start + i * attr_size
                    ans, aname, raw = struct.unpack_from("<III", data, base)
                    _vsize, _res0, vtype, vdata = struct.unpack_from("<HBBI", data, base + 12)
                    attrs[_pool_ref(strings, aname) or "?"] = _decode_attr_value(strings, raw, vtype, vdata)
                events.append(("start", _pool_ref(strings, name) or "?", attrs))
            elif ctype == RES_XML_END_ELEMENT_TYPE:
                (_ns, name) = struct.unpack_from("<II", data, pos + max(cheader, 16))
                events.append(("end", _pool_ref(strings, name) or "?", None))
            elif ctype == RES_XML_CDATA_TYPE:
                (text_idx,) = struct.unpack_from("<I", data, pos + max(cheader, 16))
                events.append(("text", _pool_ref(strings, text_idx), None))
        except struct.error as exc:
            # 손상된 속성 오프셋/개수 등 — 부분 결과 대신 명확한 오류로 종료
            raise AxmlError(f"비정상 청크 구조: {exc}") from exc
        pos += csize
    if not events:
        raise AxmlError("XML 요소를 찾지 못했습니다")
    return events
