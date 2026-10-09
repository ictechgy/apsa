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


def _constructor_gaps(raw: bytes, stream: list[tuple[bytes, int, int]]) -> list[tuple[int, int]]:
    gaps = []
    for index, (value, _, _) in enumerate(stream[:-2]):
        if value != b"class":
            continue
        name, _, end = stream[index + 1]
        following, start, _ = stream[index + 2]
        gap = raw[end:start]
        if not re.fullmatch(rb"[A-Za-z_][A-Za-z_0-9]*", name) or b"\n" not in gap or not gap.isspace():
            continue
        cursor = index + 2
        while cursor < len(stream) and stream[cursor][1] - end <= 4096:
            token = stream[cursor][0]
            if token == b"constructor" and cursor + 1 < len(stream) and stream[cursor + 1][0] == b"(":
                gaps.append((end, start))
                break
            if token in {b"public", b"private", b"protected", b"internal"}:
                cursor += 1
            elif token == b"@" and cursor + 1 < len(stream):
                cursor += 2
                if cursor < len(stream) and stream[cursor][0] == b"(":
                    depth = 1
                    cursor += 1
                    while cursor < len(stream) and depth:
                        depth += (stream[cursor][0] == b"(") - (stream[cursor][0] == b")")
                        cursor += 1
                    if depth:
                        break
            else:
                break
    return gaps


def adapted_source(raw: bytes, language: str, nodes: list[Any]) -> tuple[bytes, list[dict]]:
    """Preserve byte offsets; callers use original line coordinates and retain partial coverage."""
    output = bytearray(raw)
    edits = 0
    kind = ""
    additional = []
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
        async_edits = 0
        cast_edits = 0
        seen_casts = set()
        for node in nodes:
            if node.type != "ERROR":
                continue
            # Only an if-statement's leading await; local analysis does not model scheduling.
            if node.parent and node.parent.type in {
                "if_statement",
                "catch_block",
                "statements",
                "function_body",
            }:
                fragment = raw[node.start_byte : node.end_byte]
                if fragment.startswith(b"await "):
                    output[node.start_byte : node.start_byte + 5] = b" " * 5
                    async_edits += 1
                elif fragment.startswith(b"if await "):
                    output[node.start_byte + 3 : node.start_byte + 8] = b" " * 5
                    async_edits += 1
            # The grammar rejects this metatype, independently of its concurrency attribute.
            # Replace only the type argument of the known stdlib cast, never its value argument.
            args = node.parent
            if not args or args.type != "value_arguments" or args.start_byte in seen_casts:
                continue
            call = args.parent
            if call and call.type == "call_suffix":
                call = call.parent
            if not call or call.type != "call_expression" or not call.named_children:
                continue
            callee = call.named_children[0]
            if raw[callee.start_byte : callee.end_byte] != b"unsafeBitCast":
                continue
            fragment = raw[args.start_byte : args.end_byte + 5]
            match = re.search(
                rb"\bto:\s*(\(@Sendable\s+\([A-Za-z_][A-Za-z_0-9.]*\)\s*->\s*Void\))\.self", fragment
            )
            if match:
                start, end = (args.start_byte + offset for offset in match.span(1))
                replacement = bytearray(b" " * (end - start))
                replacement[:3] = b"Any"
                for offset, byte in enumerate(raw[start:end]):
                    if byte in (10, 13):
                        replacement[offset] = byte
                output[start:end] = replacement
                cast_edits += 1
                seen_casts.add(args.start_byte)
        if async_edits:
            additional.append({"kind": "swift-if-await", "edits": async_edits})
        if cast_edits:
            additional.append({"kind": "swift-sendable-cast-metatype", "edits": cast_edits})
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
        gaps = _constructor_gaps(raw, stream)
        for start, end in gaps:
            output[start:end] = b" " * (end - start)
        if gaps:
            additional.append({"kind": "kotlin-primary-constructor-linebreak", "edits": len(gaps)})
    return bytes(output), ([{"kind": kind, "edits": edits}] if edits else []) + additional
