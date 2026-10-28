"""Call-local arguments for the sensitive-log pattern check.

This remains a sensitive-name heuristic, not a dataflow or API-identity proof.
It must not join a closed log call to a later statement on a minified line.
Unclosed/malformed candidate calls retain their remaining text conservatively.
JS/TS use the AST backend; lexical JS state is only a partial recovery heuristic.
"""

from __future__ import annotations

import re
from bisect import bisect_left
from dataclasses import dataclass

CALL = re.compile(
    r"(?<![\w$])(?:Log\.[divew]|println|print|NSLog|console\.log|logger\.\w+)\s*\(",
    re.I,
)
SENSITIVE = re.compile(r"token|password|secret|email|session", re.I)
EXPRESSION_WORDS = {
    "return",
    "throw",
    "case",
    "yield",
    "await",
    "typeof",
    "void",
    "delete",
    "in",
    "of",
    "new",
}
CONTROL_WORDS = {"if", "while", "for", "switch", "catch", "with"}
STATEMENT_WORDS = {"else", "do", "try", "catch", "finally"}
DECLARATION_PREFIXES = {"export", "default", "async", "declare", "abstract"}
TS_DECLARATIONS = {"interface", "enum", "namespace"}
MATCHER = "sensitive-log-call-arguments-v3"
JS_SUFFIXES = {".js", ".jsx", ".jsbundle", ".bundle", ".ts", ".tsx"}
MAX_FALLBACK_BYTES = 2 * 1024 * 1024
BLOCK_DELIMITERS = re.compile(r"/\*|\*/")
LINE_END = re.compile(r"\r\n|[\r\n]")
JS_LINE_END = re.compile(r"\r\n|[\r\n\u2028\u2029]")


@dataclass(frozen=True)
class String:
    closing: str
    interpolation: str
    multiline: bool
    escapes: bool


@dataclass(frozen=True)
class Delimiter:
    token: str
    position: int
    resume: String | None = None
    kind: str = "expression"
    body_after: bool | None = None


@dataclass(frozen=True)
class LogMatches:
    spans: list[tuple[int, int]]
    uncertain: bool
    regex_work: int = 0
    reason: str = ""
    parser_nodes: int = 0


@dataclass
class Header:
    """A declaration header owned by its lexical delimiter container."""

    kind: str
    depth: int
    declaration: bool
    phase: str = "name"
    angles: int = 0

    def accepts(self, token: str, identifier: str | None, depth: int, typescript: bool) -> bool:
        if depth < self.depth:
            return False
        if depth > self.depth:
            return self.phase in {"heritage-expression", "generics"}
        if self.phase == "generics":
            if token == "<":
                self.angles += 1
            elif token == ">":
                self.angles -= 1
                if not self.angles:
                    self.phase = "parameters" if self.kind == "function" else "heritage"
            return token != ";"
        if self.kind == "function":
            if token == "(" or (token == "*" and self.phase == "name"):
                return True
            if identifier is not None and self.phase == "name":
                self.phase = "parameters"
                return True
            if typescript and token == "<":
                self.phase, self.angles = "generics", 1
                return True
            return False
        if token == "{":
            return True
        if self.phase == "name" and identifier is not None:
            self.phase = "heritage-expression" if identifier in {"extends", "implements"} else "heritage"
            return True
        if self.phase == "qualified-name" and identifier is not None:
            self.phase = "heritage"
            return True
        if self.phase == "heritage":
            if identifier in {"extends", "implements"}:
                self.phase = "heritage-expression"
                return True
            if typescript and token == "<":
                self.phase, self.angles = "generics", 1
                return True
            if self.kind == "namespace" and token == ".":
                self.phase = "qualified-name"
                return True
            return False
        return token not in {";", ":", "="} and (token != "," or self.kind == "interface")


@dataclass
class Body:
    depth: int
    declaration: bool
    phase: str = "immediate"

    def accepts(self, token: str, depth: int, typescript: bool) -> bool:
        if depth < self.depth:
            return False
        if depth > self.depth:
            return self.phase == "return-type"
        if token == "{":
            return True
        if self.phase == "parameters" and typescript and token == ":":
            self.phase = "return-type"
            return True
        return self.phase == "return-type" and token not in {";", "="}


def sensitive_log_matches(
    text: str,
    suffix: str,
    *,
    call_pattern: str = CALL.pattern,
    argument_pattern: str = SENSITIVE.pattern,
) -> LogMatches:
    if suffix not in JS_SUFFIXES:
        return _lexical_sensitive_log_matches(
            text, suffix, call_pattern=call_pattern, argument_pattern=argument_pattern
        )
    if not re.search(argument_pattern, text, re.I):
        return LogMatches([], False)
    from .sensitive_logging_js import ast_sensitive_log_matches

    parsed = ast_sensitive_log_matches(
        text, suffix, call_pattern=call_pattern, argument_pattern=argument_pattern
    )
    spans = set(parsed.spans)
    remaining = MAX_FALLBACK_BYTES
    protected = _merged_recovery(parsed.protected)
    protected_starts = [start for start, _ in protected]
    for start, end in _merged_recovery(parsed.recovery):
        if remaining <= 0:
            break
        fragment = (
            text[start : min(end, start + remaining)]
            .encode("utf-8")[:remaining]
            .decode("utf-8", errors="ignore")
        )
        recovered = _lexical_sensitive_log_matches(
            fragment, suffix, call_pattern=call_pattern, argument_pattern=argument_pattern
        )
        for left, right in recovered.spans:
            candidate = start + left
            preceding = bisect_left(protected_starts, candidate + 1) - 1
            if preceding < 0 or candidate >= protected[preceding][1]:
                spans.add((candidate, start + right))
        remaining -= len(fragment.encode("utf-8"))
    return LogMatches(
        sorted(spans), bool(parsed.reason), reason=parsed.reason, parser_nodes=parsed.visited_nodes
    )


def _merged_recovery(ranges: list[tuple[int, int]]) -> list[tuple[int, int]]:
    merged: list[tuple[int, int]] = []
    for start, end in sorted(ranges):
        if merged and start <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(end, merged[-1][1]))
        else:
            merged.append((start, end))
    return merged


def _lexical_sensitive_log_matches(
    text: str,
    suffix: str,
    *,
    call_pattern: str = CALL.pattern,
    argument_pattern: str = SENSITIVE.pattern,
) -> LogMatches:
    """Find log calls whose own arguments contain a sensitive-name marker.

    One lexical pass resolves nested delimiters, quoted strings/interpolation
    and JS regular expressions. Sensitive offsets are indexed once, avoiding
    repeated scans of deeply nested or malformed calls. Comments are recognized
    in this same pass; a second comment lexer must not erase valid arguments.
    After the first unterminated multiline Swift raw regex, recovery in the
    malformed remainder is line-bounded for all delimiter hash counts. Later
    multiline bodies then remain unresolved/partial; recovered call candidates
    require manual review. Regex lookahead inspects at most twice the input size.
    """
    if not re.search(argument_pattern, text, re.I):
        return LogMatches([], False)
    javascript = suffix in {".js", ".jsx", ".jsbundle", ".ts", ".tsx"}
    typescript = suffix in {".ts", ".tsx"}
    kotlin_dart = suffix in {".kt", ".dart"}
    swift = suffix == ".swift"
    line_end = JS_LINE_END if javascript else LINE_END
    line_terminators = "\r\n\u2028\u2029" if javascript else "\r\n"
    stack: list[Delimiter] = []
    boundaries: dict[int, int] = {}
    comments: list[tuple[int, int]] = []
    active: String | None = None
    position, expression, word, uncertain, regex_scan = 0, True, "", False, True
    statement, last_token = True, ""
    headers: list[Header] = []
    next_body: Body | None = None
    restricted: tuple[str, int, bool] | None = None
    label_candidate = False
    case_depth: int | None = None
    conditional_depths: list[int] = []
    multiline_regex_recovery, regex_work = False, 0
    line_break = False

    def note_line_break() -> None:
        nonlocal line_break, regex_scan, expression, statement, word, last_token, restricted
        line_break, regex_scan = True, True
        # Restricted productions terminate here; property names such as
        # obj.return have a normalized empty `word` and are ordinary values.
        if javascript and restricted is not None:
            expression, statement, word, last_token = True, True, "", ";"
            restricted = None

    def record(opening: int, end: int) -> None:
        boundaries[opening] = max(boundaries.get(opening, -1), end)

    while position < len(text):
        token = text[position]
        if active is not None:
            if text.startswith(active.closing, position):
                position += len(active.closing)
                if suffix == ".kt" and active.closing == '"""':
                    # Kotlin raw text may end in a quote run: the final three
                    # quotes close it, and preceding quotes belong to its value.
                    while position < len(text) and text[position] == '"':
                        position += 1
                active = None
                expression = False
                statement = False
                last_token = "literal"
            elif active.interpolation and text.startswith(active.interpolation, position):
                opening = active.interpolation[-1]
                stack.append(Delimiter(opening, position, active, "interpolation"))
                position += len(active.interpolation)
                active = None
                expression = True
                statement = False
            elif active.escapes and token == "\\":
                position += 2
            elif token in "\r\n" and not active.multiline:
                # A malformed ordinary string cannot hide all later lines.
                active = None
                uncertain = True
                position += 1
                expression = True
            else:
                position += 1
            continue

        if text.startswith("//", position) or text.startswith("/*", position):
            line = text[position + 1] == "/"
            if not line and suffix in {".kt", ".swift", ".dart"}:
                depth, end = 1, -1
                for delimiter in BLOCK_DELIMITERS.finditer(text, position + 2):
                    depth += 1 if delimiter[0] == "/*" else -1
                    if depth == 0:
                        end = delimiter.start()
                        break
            elif line:
                terminator = line_end.search(text, position + 2)
                end = terminator.start() if terminator else -1
            else:
                end = text.find("*/", position + 2)
            if end < 0:
                end = len(text)
                uncertain = uncertain or not line
            elif not line:
                end += 2
            comments.append((position, end))
            if line_end.search(text, position, end):
                note_line_break()
            position = end
            continue

        newline_before = line_break
        if not token.isspace():
            line_break = False

        identifier, identifier_end = None, position
        if token.isalnum() or token in {"_", "$"}:
            identifier_end = position + 1
            while identifier_end < len(text) and (
                text[identifier_end].isalnum() or text[identifier_end] in {"_", "$"}
            ):
                identifier_end += 1
            identifier = text[position:identifier_end]
        statement_container = not stack or stack[-1].kind in {
            "statement-block",
            "declaration-body",
            "value-body",
        }
        if javascript and not token.isspace():
            # A pending header/body belongs to its own container and permitted
            # next token. Child headers cannot overwrite their parent's state.
            while headers and not headers[-1].accepts(token, identifier, len(stack), typescript):
                headers.pop()
            body_token = "=>" if text.startswith("=>", position) else token
            if next_body is not None and not next_body.accepts(body_token, len(stack), typescript):
                next_body = None
            if restricted is not None:
                kind, owner, label = restricted
                restricted = (
                    (kind, owner, False)
                    if kind in {"break", "continue"}
                    and label
                    and identifier is not None
                    and owner == len(stack)
                    else None
                )
            # These tokens cannot continue the previous completed expression.
            # Calls, indexing, tagged templates, division and binary operators
            # retain their operand context across the same line break.
            if (
                newline_before
                and not expression
                and statement_container
                and (token == "{" or (identifier is not None and last_token not in {".", "?."}))
            ):
                statement = True

        # Swift raw strings use matching # delimiters and \#(...) escapes.
        hashes = 0
        if swift and token == "#":
            end = position
            while end < len(text) and text[end] == "#":
                end += 1
            if end < len(text) and text[end] in {'"', "/"}:
                hashes = end - position
                position = end
                token = text[end]
            else:
                # A run of # outside a raw string is consumed only once.
                position = end
                continue
        if token in {"'", '"', "`"}:
            triple = token != "`" and text.startswith(token * 3, position)
            width = 3 if triple else 1
            raw_dart = (
                suffix == ".dart"
                and position > 0
                and text[position - 1] in {"r", "R"}
                and (position < 2 or not (text[position - 2].isalnum() or text[position - 2] == "_"))
            )
            interpolation = (
                "\\" + "#" * hashes + "("
                if swift and token == '"'
                else "${"
                if (javascript and token == "`") or (kotlin_dart and not raw_dart)
                else ""
            )
            active = String(
                token * width + "#" * hashes,
                interpolation,
                triple or token == "`",
                not (hashes or raw_dart or (suffix == ".kt" and triple)),
            )
            position += width
            continue
        if (javascript or swift) and token == "/" and (expression or hashes) and regex_scan:
            end, character_class = position + 1, False
            closing = "/" + "#" * hashes
            while end < len(text) and (
                (hashes and not multiline_regex_recovery) or text[end] not in line_terminators
            ):
                regex_work += 1
                if text[end] == "\\":
                    end += 2
                    continue
                if text[end] == "[":
                    character_class = True
                elif text[end] == "]":
                    character_class = False
                elif text.startswith(closing, end) and not character_class:
                    break
                end += 1
            if end < len(text) and text.startswith(closing, end):
                position = end + len(closing)
                expression = False
                statement = False
                last_token = "literal"
                continue
            # Keep scanning malformed regex-like text as code, conservatively.
            uncertain = True
            regex_scan = False
            # At most one failed multiline lookahead may inspect the remaining
            # suffix. Afterwards this already-malformed source uses line-bounded
            # recovery for every hash count, preserving later code candidates.
            # Successful scans consume their whole inspected range. Together
            # with one failed scan per recovery line, regex work is <= 2N.
            if hashes:
                multiline_regex_recovery = True
        if identifier is not None:
            property_name = javascript and last_token in {".", "?."}
            label_candidate = javascript and statement and not property_name and identifier.isidentifier()
            if javascript and not property_name:
                if identifier in {"function", "class"} or (
                    typescript and statement and statement_container and identifier in TS_DECLARATIONS
                ):
                    headers.append(Header(identifier, len(stack), statement))
                elif identifier == "case":
                    case_depth = len(stack)
                elif identifier == "default" and last_token != "export":
                    case_depth = len(stack)
                if statement_container and (
                    (statement and identifier in {"return", "break", "continue", "debugger"})
                    or identifier == "yield"
                ):
                    restricted = (identifier, len(stack), identifier in {"break", "continue"})
            # Property names are values even when spelled return/in/if/etc.
            # Normalize for-await to its controlling for keyword before `(`.
            word = (
                ""
                if property_name
                else "for"
                if identifier == "await" and last_token == "for"
                else identifier
            )
            expression = not property_name and identifier in EXPRESSION_WORDS
            statement = not property_name and (
                identifier in STATEMENT_WORDS or (identifier in DECLARATION_PREFIXES and statement)
            )
            last_token = identifier
            position = identifier_end
            continue
        if javascript and text.startswith("?.", position):
            position += 2
            expression, statement, word, last_token = False, False, "", "?."
            label_candidate = False
            continue
        if javascript and text.startswith("??", position):
            position += 2
            expression, statement, word, last_token = True, False, "", "??"
            label_candidate = False
            continue
        if javascript and token == "?":
            conditional_depths.append(len(stack))
        if javascript and token == ":":
            if conditional_depths and conditional_depths[-1] == len(stack):
                conditional_depths.pop()
                statement = False
            else:
                statement = label_candidate or case_depth == len(stack)
                if case_depth == len(stack):
                    case_depth = None
            position += 1
            expression, word, last_token, label_candidate = True, "", ":", False
            continue
        if text.startswith(("++", "--"), position):
            # Prefix update expects an operand; postfix update remains an operand.
            # Looking at each + separately would turn following division into regex.
            position += 2
            statement, word, last_token = False, "", "update"
            continue
        if (
            token == "!"
            and not expression
            and suffix in {".ts", ".tsx", ".swift"}
            and not text.startswith("!=", position)
        ):
            position += 1
            statement, word, last_token = False, "", "postfix"
            continue
        if javascript and text.startswith("=>", position):
            if next_body is None or next_body.phase != "return-type":
                next_body = Body(len(stack), False)
            expression, statement, last_token, word = True, False, "=>", ""
            position += 2
            continue
        if token in "([{":
            kind, body_after = "expression", None
            if token == "(":
                if word in CONTROL_WORDS:
                    kind = "control"
                elif (
                    headers
                    and headers[-1].kind == "function"
                    and headers[-1].depth == len(stack)
                    and headers[-1].phase != "generics"
                ):
                    kind, body_after = "function-parameters", headers.pop().declaration
            elif token == "{":
                if next_body is not None and next_body.depth == len(stack):
                    kind = "declaration-body" if next_body.declaration else "value-body"
                    next_body = None
                elif (
                    headers
                    and headers[-1].kind != "function"
                    and headers[-1].depth == len(stack)
                    and headers[-1].phase != "generics"
                ):
                    kind = "declaration-body" if headers.pop().declaration else "value-body"
                elif statement:
                    kind = "statement-block"
                elif last_token == ")":
                    # Method bodies are values in object/class expressions.
                    kind = "value-body"
                else:
                    kind = "object"
            stack.append(Delimiter(token, position, kind=kind, body_after=body_after))
            statement = token == "{" and kind != "object"
        elif token in ")]}":
            if stack and stack[-1].token == {")": "(", "]": "[", "}": "{"}[token]:
                opening = stack.pop()
                if token == ")":
                    record(opening.position, position)
                if opening.resume is not None:
                    active = opening.resume
                expression = opening.kind in {"control", "statement-block", "declaration-body"}
                statement = expression
                if opening.kind == "function-parameters":
                    next_body = Body(len(stack), bool(opening.body_after), "parameters")
            else:
                uncertain = True
            word = ""
            last_token = token
            position += 1
            continue
        if not token.isspace():
            expression = token in "=([{,:;!?&|+-*%^~<>/"
            if token not in "([{":
                statement = token == ";"
            last_token = token
            word = ""
            label_candidate = False
        elif token in line_terminators:
            note_line_break()
        position += 1
    if active is not None:
        uncertain = True
    for opening in stack:
        if opening.token == "(":
            record(opening.position, len(text))
            uncertain = True
    # Locate call prefixes after comments have been blanked. A comment between
    # a callee and `(` is whitespace, and must not hide its real arguments.
    # Only openings observed as code by the lexer can supply a boundary, so
    # quoted/regex/comment examples still cannot become call candidates.
    parts, previous = [], 0
    for start, end in comments:
        parts.extend((text[previous:start], " " * (end - start)))
        previous = end
    parts.append(text[previous:])
    located = "".join(parts)
    starts = {match.end() - 1: match.start() for match in re.finditer(call_pattern, located, re.I)}
    sensitive, comment_index = [], 0
    for match in re.finditer(argument_pattern, text, re.I):
        while comment_index < len(comments) and comments[comment_index][1] <= match.start():
            comment_index += 1
        if comment_index == len(comments) or match.start() < comments[comment_index][0]:
            sensitive.append(match.start())
    spans = []
    for opening, end in boundaries.items():
        if opening not in starts:
            continue
        index = bisect_left(sensitive, opening + 1)
        if index < len(sensitive) and sensitive[index] < end:
            spans.append((starts[opening], end))
    # Closing order is innermost first. Evidence and the finding cap use source order.
    return LogMatches(sorted(spans), uncertain, regex_work)
