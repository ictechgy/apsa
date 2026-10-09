"""Narrow, byte-preserving parser adaptations; never execute or rewrite source files."""

from __future__ import annotations

import re
from typing import Any


def _comment_end(raw: bytes, cursor: int) -> int:
    depth = 1
    cursor += 2
    while cursor < len(raw) and depth:
        pair = raw[cursor : cursor + 2]
        if pair in {b"/*", b"*/"}:
            depth += 1 if pair == b"/*" else -1
            cursor += 2
        else:
            cursor += 1
    if depth:
        raise ValueError("Unterminated Kotlin comment")
    return cursor


def _literal_end(raw: bytes, cursor: int, depth: int = 0) -> int:
    if depth > 64:
        raise ValueError("Kotlin literal nesting budget exceeded")
    quote = raw[cursor : cursor + 1]
    delimiter = b'"""' if raw[cursor : cursor + 3] == b'"""' else quote
    cursor += len(delimiter)
    while cursor < len(raw):
        if raw[cursor : cursor + len(delimiter)] == delimiter:
            return cursor + len(delimiter)
        if quote == b'"' and raw[cursor : cursor + 2] == b"${":
            cursor = _template_end(raw, cursor + 2, depth + 1)
        else:
            cursor += 2 if raw[cursor : cursor + 1] == b"\\" and delimiter in {b'"', b"'"} else 1
    raise ValueError("Unterminated Kotlin literal")


def _template_end(raw: bytes, cursor: int, depth: int) -> int:
    braces = 1
    while cursor < len(raw):
        if raw[cursor : cursor + 2] == b"/*":
            cursor = _comment_end(raw, cursor)
        elif raw[cursor : cursor + 2] == b"//":
            end = raw.find(b"\n", cursor)
            cursor = len(raw) if end < 0 else end + 1
        elif raw[cursor : cursor + 1] in {b'"', b"'", b"`"}:
            cursor = _literal_end(raw, cursor, depth)
        else:
            if raw[cursor : cursor + 1] in {b"{", b"}"}:
                braces += 1 if raw[cursor : cursor + 1] == b"{" else -1
                if not braces:
                    return cursor + 1
            cursor += 1
    raise ValueError("Unterminated Kotlin template")


def kotlin_tokens(raw: bytes) -> list[tuple[bytes, int, int]]:
    """Read code tokens with opaque strings/backticks and nested block comments."""
    result = []
    cursor = 0
    while cursor < len(raw):
        if raw[cursor : cursor + 2] == b"//":
            end = raw.find(b"\n", cursor)
            cursor = len(raw) if end < 0 else end + 1
            continue
        if raw[cursor : cursor + 2] == b"/*":
            cursor = _comment_end(raw, cursor)
            continue
        start = cursor
        quote = raw[cursor : cursor + 1]
        if quote in {b'"', b"'", b"`"}:
            cursor = _literal_end(raw, cursor)
            result.append((b"literal", start, cursor))
        elif raw[cursor] >= 128 or chr(raw[cursor]).isalnum() or raw[cursor] == 95:
            cursor += 1
            while cursor < len(raw) and (
                raw[cursor] >= 128 or chr(raw[cursor]).isalnum() or raw[cursor] == 95
            ):
                cursor += 1
            result.append((raw[start:cursor], start, cursor))
        else:
            cursor += 1
            if not quote.isspace():
                result.append((quote, start, cursor))
        if len(result) > 100_000:
            raise ValueError("Kotlin compatibility token budget exceeded")
    return result


def adapted_source(raw: bytes, language: str, nodes: list[Any]) -> tuple[bytes, list[dict]]:
    """Preserve bytes/newlines/offsets; callers keep adapted files explicitly partial."""
    output = bytearray(raw)
    edits = 0
    kind = ""
    if language == "swift":
        kind = "swift-nonisolated-unsafe-variable"
        for node in nodes:
            fragment = raw[node.start_byte : node.end_byte]
            if (
                node.type == "ERROR"
                and re.fullmatch(rb"nonisolated\(unsafe\)", fragment)
                and re.match(rb"\s*(?:var|let)\b", raw[node.end_byte :])
            ):
                # The local flow analysis does not model concurrency isolation.
                start = node.start_byte
                output[start : node.end_byte] = b" " * (node.end_byte - start)
                edits += 1
    elif language == "kotlin":
        kind = "kotlin-open-identifier"
        try:
            stream = kotlin_tokens(raw)
        except ValueError:
            return raw, []
        modifier_targets = {
            b"class",
            b"fun",
            b"val",
            b"var",
            b"override",
            b"public",
            b"protected",
            b"internal",
            b"private",
            b"abstract",
            b"inner",
            b"suspend",
            b"expect",
            b"actual",
        }
        for index, (value, start, end) in enumerate(stream):
            following = stream[index + 1][0] if index + 1 < len(stream) else b""
            if value == b"open" and following not in modifier_targets:
                # Analyzer reads names and evidence from original bytes, not this placeholder.
                output[start:end] = b"op_n"
                edits += 1
    return bytes(output), ([{"kind": kind, "edits": edits}] if edits else [])
