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


def _blank(output: bytearray, start: int, end: int, replacement: bytes = b"") -> None:
    """Overwrite a span with a same-length replacement, keeping line breaks."""
    span = bytearray(b" " * (end - start))
    span[: len(replacement)] = replacement
    for offset, byte in enumerate(output[start:end]):
        if byte in (10, 13):
            span[offset] = byte
    output[start:end] = span


def _swift_extensions(raw: bytes, output: bytearray) -> list[dict]:
    """Attributes and empty-tuple arguments that the pinned Swift grammar rejects."""
    try:
        stream = kotlin_tokens(raw)
    except ValueError:
        return []
    counts = {
        "swift-documentation-attribute": 0,
        "swift-diagnostic-directive": 0,
        "swift-empty-tuple-argument": 0,
        "swift-nonisolated-unsafe-variable": 0,
    }
    for index, (value, start, _end) in enumerate(stream):
        following = stream[index + 1] if index + 1 < len(stream) else None
        if (
            value == b"nonisolated"
            and [token[0] for token in stream[index + 1 : index + 4]] == [b"(", b"unsafe", b")"]
            and index + 4 < len(stream)
            and stream[index + 4][0] in {b"var", b"let", b"static"}
            and output[start : start + 1] != b" "
        ):
            # The local flow analysis does not model concurrency isolation.
            _blank(output, start, stream[index + 3][2])
            counts["swift-nonisolated-unsafe-variable"] += 1
        elif value == b"@" and following and following[0] == b"_documentation":
            close = raw.find(b")", following[2])
            if close > 0 and re.fullmatch(rb"\s*\(\s*visibility\s*:\s*\w+\s*", raw[following[2] : close]):
                # Documentation visibility does not affect local flow analysis.
                _blank(output, start, close + 1)
                counts["swift-documentation-attribute"] += 1
        elif value == b"#" and following and following[0] in {b"warning", b"error"}:
            line_end = raw.find(b"\n", start)
            line_end = len(raw) if line_end < 0 else line_end
            if re.fullmatch(rb"#(?:warning|error)\s*\(\s*\"[^\n]*\"\s*\)\s*", raw[start:line_end]):
                _blank(output, start, line_end)
                counts["swift-diagnostic-directive"] += 1
        elif (
            value == b"("
            and following
            and following[0] == b")"
            and index
            and stream[index - 1][0] in {b"(", b",", b":", b"=", b"{", b"return", b"in"}
            and index + 2 < len(stream)
            and stream[index + 2][0] in {b")", b",", b"}"}
        ):
            # An empty tuple value; a literal keeps the call structure for analysis.
            _blank(output, start, following[2], b"0")
            counts["swift-empty-tuple-argument"] += 1
    return [{"kind": kind, "edits": edits} for kind, edits in counts.items() if edits]


ENUM_MACRO = re.compile(
    rb"\b(?:typedef\s+)?(?:NS_ENUM|NS_OPTIONS|NS_CLOSED_ENUM|NS_ERROR_ENUM|CF_ENUM|CF_OPTIONS|CF_CLOSED_ENUM)"
    rb"\s*\(\s*[A-Za-z_][A-Za-z_0-9 ]*?\s*,\s*([A-Za-z_][A-Za-z_0-9]*)\s*\)"
)
CONDITIONAL = re.compile(rb"[ \t]*#[ \t]*(if|ifdef|ifndef|elif|else|endif)\b([^\n]*)")
INCLUDE = re.compile(rb"[ \t]*#[ \t]*(?:import|include)\b")


def _objc_extensions(raw: bytes, output: bytearray, nodes: list[Any]) -> list[dict]:
    """Expand enum macros, drop Swift-style comment labels and keep first preprocessor branches."""
    try:
        stream = kotlin_tokens(raw)
    except ValueError:
        return []
    code_starts = {start for _, start, _ in stream}
    counts = {"objc-enum-macro": 0, "objc-localized-comment-label": 0, "objc-preprocessor-first-branch": 0}
    for match in ENUM_MACRO.finditer(raw):
        if match.start() in code_starts:
            _blank(output, match.start(), match.end(), b"enum " + match[1])
            counts["objc-enum-macro"] += 1
    callees: list[bytes] = []
    for index, (value, start, _end) in enumerate(stream):
        if value == b"(":
            callees.append(stream[index - 1][0] if index else b"")
        elif value == b")" and callees:
            callees.pop()
        elif (
            value == b"comment"
            and callees
            and callees[-1].startswith(b"NSLocalizedString")
            and index
            and stream[index - 1][0] == b","
            and index + 1 < len(stream)
            and stream[index + 1][0] == b":"
        ):
            _blank(output, start, stream[index + 1][2])
            counts["objc-localized-comment-label"] += 1
    if re.search(rb"(?m)^[ \t]*#[ \t]*(?:if|ifdef|ifndef)\b", raw):
        # Keep one branch per conditional so that statements split across branches
        # parse: the first branch, or the alternative of a literal `#if 0`. Other
        # branches are not analyzed and coverage stays partial. Conditional imports
        # are removed so they never become platform identity evidence.
        groups: list[list[bool]] = []  # [branch_active, a_branch_was_taken]
        cursor = 0
        for line in raw.splitlines(keepends=True):
            directive = CONDITIONAL.match(line)
            width = len(line.rstrip(b"\r\n"))
            if directive:
                word = directive[1]
                if word in {b"if", b"ifdef", b"ifndef"}:
                    dead = word == b"if" and directive[2].split(b"//")[0].strip() == b"0"
                    groups.append([not dead, not dead])
                elif word in {b"elif", b"else"} and groups:
                    groups[-1][0] = not groups[-1][1]
                    groups[-1][1] = True
                elif word == b"endif" and groups:
                    groups.pop()
                _blank(output, cursor, cursor + width)
                counts["objc-preprocessor-first-branch"] += 1
            elif not all(active for active, _ in groups) or (groups and INCLUDE.match(line)):
                _blank(output, cursor, cursor + width)
            cursor += len(line)
    return [{"kind": kind, "edits": edits} for kind, edits in counts.items() if edits]


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
        additional.extend(_swift_extensions(raw, output))
    elif language == "objc":
        additional.extend(_objc_extensions(raw, output, nodes))
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
