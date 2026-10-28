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
                attrs = {}
                for key, value in element.attrib.items():
                    if key.startswith("{") and not key.startswith("{" + ANDROID_NS + "}"):
                        continue
                    name_key = key.rsplit("}", 1)[-1]
                    if name_key in attrs:
                        raise AxmlError("Ambiguous duplicate XML attribute")
                    attrs[name_key] = value
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

ANDROID_NS = "http://schemas.android.com/apk/res/android"
ANDROID_ATTR_NAMES = {
    16843392: "allowBackup",
    16842776: "authorities",
    16844014: "autoVerify",
    16842767: "debuggable",
    16842768: "exported",
    16842779: "grantUriPermissions",
    16842792: "host",
    16843276: "minSdkVersion",
    16842755: "name",
    16844071: "networkSecurityConfig",
    16842794: "path",
    16842796: "pathPattern",
    16842795: "pathPrefix",
    16842758: "permission",
    16842761: "protectionLevel",
    16842759: "readPermission",
    16842791: "scheme",
    16843376: "targetSdkVersion",
    16844012: "usesCleartextTraffic",
    16843292: "versionName",
    16842760: "writePermission",
}
MAX_POOL_STRINGS = 200000
MAX_POOL_BYTES = 8 * 1024 * 1024

UTF8_FLAG = 0x100
NO_INDEX = 0xFFFFFFFF


class AxmlError(ValueError):
    """AXML 파싱 실패."""


def _read_string(data: bytes | memoryview, pos: int, is_utf8: bool) -> str:
    if is_utf8:

        def length(at):
            first = data[at]
            return (((first & 0x7F) << 8) | data[at + 1], at + 2) if first & 0x80 else (first, at + 1)

        _units, pos = length(pos)
        size, pos = length(pos)
        if size > 65536 or pos + size >= len(data) or data[pos + size] != 0:
            raise AxmlError("Invalid/budgeted UTF-8 pool string")
        return bytes(data[pos : pos + size]).decode("utf-8", "replace")
    (size,) = struct.unpack_from("<H", data, pos)
    pos += 2
    if size & 0x8000:
        (low,) = struct.unpack_from("<H", data, pos)
        pos += 2
        size = ((size & 0x7FFF) << 16) | low
    if size > 32768 or pos + size * 2 + 2 > len(data):
        raise AxmlError("Invalid/budgeted UTF-16 pool string")
    return bytes(data[pos : pos + size * 2]).decode("utf-16-le", "replace")


def _read_string_pool(data: bytes, start: int) -> list:
    (_, header_size, size, count, styles, flags, strings_start, styles_start) = struct.unpack_from(
        "<HHIIIIII", data, start
    )
    if (
        header_size < 28
        or size < header_size
        or start + size > len(data)
        or count > MAX_POOL_STRINGS
        or header_size + 4 * (count + styles) > strings_start
        or strings_start > size
        or (styles_start and not strings_start <= styles_start <= size)
    ):
        raise AxmlError("Invalid/budgeted string pool")
    pool_end = start + (styles_start or size)
    pool_data = memoryview(data)[start + strings_start : pool_end]
    decoded, strings, total = {}, [], 0
    for i in range(count):
        (off,) = struct.unpack_from("<I", data, start + header_size + 4 * i)
        if off not in decoded:
            # Slice once per pool, not once per aliased offset.
            if not 0 <= off < len(pool_data):
                raise AxmlError("String-pool offset outside chunk")
            value = _read_string(pool_data, off, bool(flags & UTF8_FLAG))
            total += len(value.encode("utf-8"))
            if total > MAX_POOL_BYTES:
                raise AxmlError("Decoded string-pool budget exceeded")
            decoded[off] = value
        strings.append(decoded[off])
    return strings


def _pool_ref(strings: list, idx: int) -> str:
    if idx == NO_INDEX or idx >= len(strings):
        return ""
    return strings[idx]


def _decode_attr_value(strings: list, raw: int, data_type: int, data: int) -> str:
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
    if len(data) > 8 * 1024 * 1024 or fheader < 8 or fsize != len(data):
        raise AxmlError("AXML byte/header budget exceeded or truncated")
    strings: list = []
    resource_ids = None
    events: list = []
    pos = fheader
    limit = min(len(data), fsize)
    while pos + 8 <= limit:
        try:
            ctype, cheader, csize = struct.unpack_from("<HHI", data, pos)
            if cheader < 8 or csize < cheader or csize <= 0 or pos + csize > limit:
                raise AxmlError("Invalid/truncated AXML chunk")
            if ctype == RES_STRING_POOL_TYPE:
                strings = _read_string_pool(data, pos)
            elif ctype == RES_XML_RESOURCE_MAP_TYPE:
                if cheader != 8 or (csize - 8) % 4 or (csize - 8) // 4 > MAX_POOL_STRINGS:
                    raise AxmlError("Invalid resource map")
                resource_ids = list(struct.unpack_from("<" + "I" * ((csize - 8) // 4), data, pos + 8))
            elif ctype == RES_XML_START_ELEMENT_TYPE:
                ext = pos + max(cheader, 16)  # 확장부는 노드 headerSize 기반(변형 허용)
                (_ns, name, attr_start, attr_size, attr_count, _id, _cls, _style) = struct.unpack_from(
                    "<IIHHHHHH", data, ext
                )
                if (
                    ext + 20 > pos + csize
                    or attr_size < 20
                    or attr_count > 4096
                    or attr_start < 20
                    or ext + attr_start + attr_count * attr_size > pos + csize
                ):
                    raise AxmlError("Invalid/budgeted attribute table")
                attrs = {}
                for i in range(attr_count):
                    base = ext + attr_start + i * attr_size
                    ans, aname, raw = struct.unpack_from("<III", data, base)
                    _vsize, _res0, vtype, vdata = struct.unpack_from("<HBBI", data, base + 12)
                    namespace = _pool_ref(strings, ans)
                    key = _pool_ref(strings, aname) or "?"
                    if resource_ids is not None:
                        resource_id = resource_ids[aname] if aname < len(resource_ids) else 0
                        canonical = ANDROID_ATTR_NAMES.get(resource_id)
                        if canonical:
                            if namespace != ANDROID_NS:
                                raise AxmlError("Android resource attribute has wrong namespace")
                            key = canonical
                        elif key in ANDROID_ATTR_NAMES.values():
                            # Name strings cannot impersonate framework attribute IDs.
                            continue
                    elif namespace and namespace != ANDROID_NS:
                        continue
                    if key in attrs:
                        raise AxmlError("Ambiguous duplicate AXML attribute")
                    attrs[key] = _decode_attr_value(strings, raw, vtype, vdata)
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
        if len(events) > 12000:
            raise AxmlError("AXML event budget exceeded")
        pos += csize
    if pos != limit:
        raise AxmlError("Trailing/truncated AXML bytes")
    if not events:
        raise AxmlError("XML 요소를 찾지 못했습니다")
    return events
