"""Bounded AAPT2 XmlNode decoding; no bundletool/build execution or resource resolution."""

from __future__ import annotations

import re
from xml.etree import ElementTree as XML

MAX_BYTES = 2 * 1024 * 1024
MAX_NODES = 20_000
MAX_DEPTH = 64
REFERENCE = (
    "https://android.googlesource.com/platform/frameworks/base/+/refs/heads/main/tools/aapt2/Resources.proto"
)


def _varint(raw: bytes, cursor: int) -> tuple[int, int]:
    value = 0
    for index in range(10):
        if cursor >= len(raw):
            raise ValueError("Truncated protobuf integer")
        byte = raw[cursor]
        cursor += 1
        if index == 9 and byte > 1:
            raise ValueError("Protobuf integer exceeds 64 bits")
        value |= (byte & 127) << (index * 7)
        if byte < 128:
            return value, cursor
    raise ValueError("Invalid protobuf integer")


def _fields(raw: bytes) -> dict[int, list[tuple[int, bytes | int]]]:
    output: dict[int, list[tuple[int, bytes | int]]] = {}
    cursor = 0
    count = 0
    while cursor < len(raw):
        tag, cursor = _varint(raw, cursor)
        number, wire = tag >> 3, tag & 7
        if not 1 <= number <= (1 << 29) - 1:
            raise ValueError("Invalid protobuf field number")
        if wire == 0:
            value, cursor = _varint(raw, cursor)
        elif wire in {1, 5}:
            width = 8 if wire == 1 else 4
            if cursor + width > len(raw):
                raise ValueError("Truncated protobuf fixed value")
            value = raw[cursor : cursor + width]
            cursor += width
        elif wire == 2:
            length, cursor = _varint(raw, cursor)
            if cursor + length > len(raw):
                raise ValueError("Truncated protobuf message")
            value = raw[cursor : cursor + length]
            cursor += length
        else:
            raise ValueError("Unsupported protobuf group or wire type")
        output.setdefault(number, []).append((wire, value))
        count += 1
        if count > MAX_NODES:
            raise ValueError("Protobuf field budget exceeded")
    return output


def _one(fields: dict, number: int, wire: int = 2, default=None):
    values = fields.get(number, [])
    if len(values) > 1 or (values and values[0][0] != wire):
        raise ValueError("Duplicate or mistyped protobuf singular field")
    return values[0][1] if values else default


def _string(fields: dict, number: int, default: str = "") -> str:
    value = _one(fields, number)
    return value.decode("utf-8") if value is not None else default


def _bytes(fields: dict, number: int) -> bytes:
    value = _one(fields, number)
    if not isinstance(value, bytes):
        raise ValueError("Required protobuf message is absent")
    return value


def _compiled(raw: bytes) -> str | None:
    item = _fields(raw)
    variants = [key for key in range(1, 8) if key in item]
    if len(variants) != 1:
        raise ValueError("Invalid compiled attribute oneof")
    kind = variants[0]
    body = _fields(_bytes(item, kind))
    if kind in {2, 3}:
        return _string(body, 1)
    if kind == 7:
        values = [key for key in body if key in set(range(1, 15))]
        if len(values) != 1:
            raise ValueError("Invalid compiled primitive oneof")
        primitive = values[0]
        if primitive in {6, 7, 8}:
            value = _one(body, primitive, 0)
            if not isinstance(value, int):
                raise ValueError("Required primitive value is absent")
            if primitive == 8:
                if value not in {0, 1}:
                    raise ValueError("Noncanonical protobuf boolean")
                return "true" if value else "false"
            if value > 0xFFFFFFFF:
                return None
            return str(value)
    return None


def decode_manifest(raw: bytes) -> tuple[bytes, list[str]]:
    if not raw or len(raw) > MAX_BYTES:
        raise ValueError("AAB manifest exceeds byte budget or is empty")
    warnings = []
    remaining = MAX_NODES

    def element(node_raw: bytes, depth: int):
        nonlocal remaining
        remaining -= 1
        if depth > MAX_DEPTH or remaining < 0:
            raise ValueError("AAB XML depth/node budget exceeded")
        node = _fields(node_raw)
        if 2 in node or 1 not in node:
            if 1 in node:
                raise ValueError("Conflicting XML node oneof")
            if 2 not in node:
                raise ValueError("XML node has no supported value")
            _string(node, 2)
            return None
        value = _fields(_bytes(node, 1))
        name = _string(value, 3)
        namespace = _string(value, 2)
        if not re.fullmatch(r"[A-Za-z_][A-Za-z_0-9.-]*", name):
            raise ValueError("Invalid AAB XML element name")
        output = XML.Element(("{" + namespace + "}" if namespace else "") + name)
        for wire, attribute in value.get(4, []):
            if wire != 2 or not isinstance(attribute, bytes):
                raise ValueError("Mistyped XML attribute")
            attrs = _fields(attribute)
            key = _string(attrs, 2)
            uri = _string(attrs, 1)
            if not re.fullmatch(r"[A-Za-z_][A-Za-z_0-9.-]*", key):
                raise ValueError("Invalid AAB XML attribute name")
            qualified = ("{" + uri + "}" if uri else "") + key
            if qualified in output.attrib:
                raise ValueError("Duplicate AAB XML attribute")
            declared = _string(attrs, 3) if 3 in attrs else None
            compiled = _compiled(_bytes(attrs, 6)) if 6 in attrs else None
            if declared is not None and compiled is not None and declared != compiled:
                raise ValueError("Conflicting declared and compiled attribute")
            text = compiled if compiled is not None else declared
            if 6 in attrs and compiled is None:
                text = "unresolved-resource"
                warnings.append("AAB manifest compiled resource attribute remains unresolved: " + key)
            if text is None:
                raise ValueError("AAB attribute has no observable value")
            output.set(qualified, text)
        for wire, child in value.get(5, []):
            if wire != 2 or not isinstance(child, bytes):
                raise ValueError("Mistyped XML child")
            parsed = element(child, depth + 1)
            if parsed is not None:
                output.append(parsed)
        return output

    root = element(raw, 0)
    if root is None or root.tag != "manifest":
        raise ValueError("AAB base XML is not a manifest")
    return XML.tostring(root, encoding="utf-8"), list(dict.fromkeys(warnings))[:128]
