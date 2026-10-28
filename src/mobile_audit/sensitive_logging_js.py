"""Bounded JavaScript/TypeScript AST locations for sensitive-log candidates.

No application code is executed. A successful parse determines call arguments;
the rule remains a sensitive-name heuristic, not a dataflow or API proof.
Failures request partial, call-scoped recovery from the caller.
"""

from __future__ import annotations

import importlib
import re
import warnings
from bisect import bisect_left
from dataclasses import dataclass, field
from functools import lru_cache
from typing import Any

MAX_SOURCE_BYTES = 2 * 1024 * 1024
MAX_AST_NODES = 200_000
PARSE_TIMEOUT_MICROS = 250_000


@dataclass(frozen=True)
class JSMatches:
    spans: list[tuple[int, int]]
    reason: str = ""
    recovery: list[tuple[int, int]] = field(default_factory=list)
    visited_nodes: int = 0
    protected: list[tuple[int, int]] = field(default_factory=list)


@lru_cache(maxsize=3)
def _language(kind: str) -> Any:
    binding = importlib.import_module("tree_sitter")
    grammar = importlib.import_module(
        "tree_sitter_javascript" if kind == "javascript" else "tree_sitter_typescript"
    )
    factory = getattr(grammar, "language" if kind == "javascript" else "language_" + kind)
    return binding.Language(factory())


def _new_parser(suffix: str) -> Any:
    binding = importlib.import_module("tree_sitter")
    kind = "tsx" if suffix == ".tsx" else "typescript" if suffix == ".ts" else "javascript"
    parser = binding.Parser(_language(kind))
    # Match the pinned binding's existing native parser deadline convention.
    with warnings.catch_warnings(action="ignore", category=DeprecationWarning):
        parser.timeout_micros = PARSE_TIMEOUT_MICROS
    return parser


def _callee_tail(node: Any) -> int | None:
    """Locate a canonical identifier/member tail without rescanning large callees.

    The existing prefix patterns recognize names like print or console.log.
    Higher-order/computed receivers cannot acquire a match from unrelated
    strings. Their static terminal property still supports print/println/etc.
    Two member levels preserve qualified tails such as window.console.log.
    """
    if node is None:
        return None
    if node.type in {"identifier", "property_identifier"}:
        return node.start_byte
    if node.type != "member_expression":
        return None
    owner = node.child_by_field_name("object")
    if owner is None:
        return None
    if owner.type == "identifier":
        return owner.start_byte
    if owner.type == "member_expression":
        tail = owner.child_by_field_name("property")
        if tail is not None and tail.type in {
            "identifier",
            "property_identifier",
            "private_property_identifier",
        }:
            return tail.start_byte
    terminal = node.child_by_field_name("property")
    return (
        terminal.start_byte
        if terminal is not None and terminal.type in {"property_identifier", "private_property_identifier"}
        else None
    )


def _character_offsets(raw: bytes, positions: set[int]) -> dict[int, int]:
    offsets, previous, count = {}, 0, 0
    for position in sorted(positions):
        count += len(raw[previous:position].decode("utf-8"))
        offsets[position] = count
        previous = position
    return offsets


def ast_sensitive_log_matches(
    text: str, suffix: str, *, call_pattern: str, argument_pattern: str
) -> JSMatches:
    raw = text.encode("utf-8")
    if len(raw) > MAX_SOURCE_BYTES:
        return JSMatches([], "JS/TS AST source byte budget exceeded", [(0, len(text))])
    try:
        parser = _new_parser(suffix)
    except (ImportError, AttributeError, OSError, ValueError, RuntimeError, TimeoutError) as error:
        return JSMatches(
            [], "JS/TS AST grammar or parser unavailable (" + type(error).__name__ + ")", [(0, len(text))]
        )
    try:
        tree = parser.parse(raw)
    except (AttributeError, OSError, ValueError, RuntimeError, TimeoutError) as error:
        # The pinned binding raises ValueError on a native parse timeout rather
        # than returning None. Other parse failures share this conservative
        # diagnosis; they do not imply an unavailable grammar installation.
        return JSMatches(
            [], "JS/TS AST parse deadline or parse failure (" + type(error).__name__ + ")", [(0, len(text))]
        )
    if tree is None:
        return JSMatches([], "JS/TS AST parse deadline exceeded", [(0, len(text))])

    comments: list[tuple[int, int]] = []
    protected: list[tuple[int, int]] = []
    calls: list[tuple[int, int, int]] = []
    recovery: list[tuple[int, int]] = []
    reason = (
        "JS/TS grammar-reported parse error or unsupported syntax; unresolved call boundaries require review"
        if tree.root_node.has_error
        else ""
    )
    cursor, visited, recovery_work = tree.walk(), 0, 0
    while True:
        node = cursor.node
        visited += 1
        if visited > MAX_AST_NODES:
            reason = "JS/TS AST node budget exceeded"
            recovery = [(0, len(raw))]
            break
        if node.type == "comment":
            comments.append((node.start_byte, node.end_byte))
        if not node.has_error and (
            node.type in {"string", "regex", "comment", "jsx_text"}
            or (
                node.type == "string_fragment"
                and node.parent is not None
                and node.parent.type in {"string", "template_string"}
                and not node.parent.has_error
            )
        ):
            protected.append((node.start_byte, node.end_byte))
        if node.type == "ERROR":
            # ERROR may start after a callee (e.g. an unfinished quote). Recover
            # its containing statement, never an unrelated enclosing program.
            owner = node
            while owner.parent is not None and owner.parent.type not in {
                "program",
                "statement_block",
                "class_body",
            }:
                recovery_work += 1
                if recovery_work > MAX_AST_NODES:
                    break
                owner = owner.parent
            if recovery_work > MAX_AST_NODES:
                reason = "JS/TS AST recovery node budget exceeded"
                recovery = [(0, len(raw))]
                break
            recovery.append((owner.start_byte, owner.end_byte))
        elif node.type in {"call_expression", "new_expression"}:
            arguments = node.child_by_field_name("arguments")
            callee = node.child_by_field_name("function" if node.type == "call_expression" else "constructor")
            tail = _callee_tail(callee)
            # Tagged templates are also call_expression nodes, but their
            # template_string arguments cannot satisfy the canonical '(' prefix.
            # Traverse substitutions normally without invoking recovery.
            if arguments is not None and arguments.type == "arguments" and tail is not None:
                if (
                    node.has_error
                    or arguments.end_byte <= arguments.start_byte
                    or raw[arguments.end_byte - 1 : arguments.end_byte] != b")"
                ):
                    # A mismatched delimiter can leave later text in the same
                    # unresolved argument list. The bounded lexical recovery
                    # decides its own call boundaries and reports partial.
                    recovery.append((node.start_byte, len(raw)))
                else:
                    calls.append((tail, arguments.start_byte, arguments.end_byte))
        if cursor.goto_first_child():
            continue
        while not cursor.goto_next_sibling():
            if not cursor.goto_parent():
                break
        else:
            continue
        break

    if recovery and not reason:
        reason = "JS/TS unresolved call arguments require partial call-scoped recovery"
    if not reason:
        protected = []
    positions = {position for span in [*comments, *recovery, *protected] for position in span}
    positions.update(position for span in calls for position in span)
    offsets = _character_offsets(raw, positions)
    parts, previous = [], 0
    for start, end in sorted(comments):
        start, end = offsets[start], offsets[end]
        parts.extend((text[previous:start], " " * (end - start)))
        previous = end
    parts.append(text[previous:])
    cleaned = "".join(parts)
    markers = [match.start() for match in re.finditer(argument_pattern, cleaned, re.I)]
    prefix = re.compile(call_pattern, re.I)
    spans = []
    for tail, opening, end in calls:
        tail, opening, end = offsets[tail], offsets[opening], offsets[end]
        match = prefix.search(cleaned, tail, opening + 1)
        marker = bisect_left(markers, opening + 1)
        if (
            match is not None
            and match.end() == opening + 1
            and marker < len(markers)
            and markers[marker] < end - 1
        ):
            spans.append((match.start(), end - 1))
    return JSMatches(
        sorted(set(spans)),
        reason,
        [(offsets[start], offsets[end]) for start, end in recovery],
        visited,
        [(offsets[start], offsets[end]) for start, end in protected],
    )
