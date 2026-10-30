"""Bounded structural flow for JS/TS/Dart mobile adapters.

This is a small token/block interpreter, not a full language compiler. Unknown
dispatch, closures, control-flow and native bridge implementations remain partial.
Only observed flows are emitted; absence never establishes application safety.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import PurePosixPath

from .core import code_excerpt, finding
from .input_snapshot import prioritized_paths
from .rules import strip_comments

MAX_BYTES = 2 * 1024 * 1024
MAX_TOTAL = 16 * 1024 * 1024
MAX_TOKENS = 100_000
MAX_FUNCTIONS = 2_000
MAX_FINDINGS = 200
MAX_ROUNDS = 6
MAX_OPERATIONS = 300_000
MAX_ORIGINS = 64
SUFFIXES = {".js", ".jsx", ".jsbundle", ".ts", ".tsx", ".dart"}
MAX_INPUT_DETAILS = 256
TEXT_BUNDLE_NAMES = {"index.android.bundle", "index.ios.bundle", "main.bundle"}
# Presence signatures only: no bytecode version, instruction or string-table analysis.
# https://github.com/facebook/hermes/blob/main/include/hermes/BCGen/HBC/BytecodeFileFormat.h
HERMES_MAGIC = 0x1F1903C103BC1FC6
HERMES_HEADERS = tuple(
    magic.to_bytes(8, order)
    for magic in (HERMES_MAGIC, HERMES_MAGIC ^ 0xFFFFFFFFFFFFFFFF)
    for order in ("little", "big")
)
RULES = {
    "HYBRID-UNTRUSTED-URL": ("External input reaches a hybrid WebView load", "MASVS-PLATFORM"),
    "HYBRID-JS-EVAL": ("External input reaches JavaScript execution", "MASVS-PLATFORM"),
    "HYBRID-SQL-INPUT": ("External input reaches SQL statement text", "MASVS-CODE"),
    "HYBRID-NATIVE-BRIDGE": ("External input is passed into a native bridge", "MASVS-PLATFORM"),
}
REFERENCE = "https://mas.owasp.org/MASTG/"
TOKEN = re.compile(
    r"(?P<string>'(?:\\.|[^'\\])*'|\"(?:\\.|[^\"\\])*\"|`(?:\\.|[^`\\])*`)"
    r"|(?P<identifier>[A-Za-z_$][\w$]*)|(?P<number>\d+(?:\.\d+)?)"
    r"|(?P<operator>=>|\?\.|===|!==|==|!=|&&|\|\||\?\?|[{}()[\].,;:=+?<>!*/\-])"
    r"|(?P<unknown>\S)",
    re.DOTALL,
)


def compiled_hybrid_input(path: str) -> dict | None:
    """Name-based compiled-artifact presence; never open an artifact here."""
    name = PurePosixPath(path)
    if name.suffix.lower() in {".hbc", ".hermes"}:
        framework, representation = "react-native", "hermes-bytecode-candidate"
    elif name.name == "libapp.so" or (name.name == "App" and "App.framework" in name.parts[:-1]):
        framework, representation = "flutter", "aot-candidate"
    elif name.name in {"vm_snapshot_data", "isolate_snapshot_data", "kernel_blob.bin"}:
        framework, representation = "flutter", "compiled-snapshot-candidate"
    else:
        return None
    return {
        "path": path,
        "framework": framework,
        "representation": representation,
        "basis": "recognized-artifact-name",
        "state": "skipped",
        "reason": "compiled artifact presence only; bytecode/AOT analysis unavailable",
    }


def hybrid_source_input(path: str, raw: bytes) -> tuple[dict | None, str | None]:
    """Classify an already bounded source blob before admitting it to token flow."""
    suffix = PurePosixPath(path).suffix.lower()
    if suffix not in SUFFIXES | {".bundle"}:
        return None, None
    record = {
        "path": path,
        "framework": "flutter"
        if suffix == ".dart"
        else "react-native"
        if suffix == ".jsbundle" or PurePosixPath(path).name in TEXT_BUNDLE_NAMES
        else "unknown"
        if suffix == ".bundle"
        else "javascript",
        "representation": "text-source",
        "basis": "source-extension",
        "state": "source-available",
    }
    if raw.startswith(HERMES_HEADERS):
        record.update(
            framework="react-native",
            representation="hermes-bytecode",
            basis="hermes-header-signature",
            state="skipped",
            reason="Hermes bytecode presence only; bytecode analysis unavailable",
        )
        return record, None
    try:
        text = raw.decode("utf-8")
        if any(ord(char) < 32 and char not in "\t\n\r" for char in text):
            raise ValueError("non-text control bytes")
    except (UnicodeError, ValueError):
        record.update(state="skipped", representation="non-text", reason="non-text hybrid input")
        return record, None
    if suffix == ".bundle":
        if PurePosixPath(path).name in TEXT_BUNDLE_NAMES:
            record["basis"] = "recognized-text-bundle-name"
        else:
            try:
                tokens = _tokens(text)
            except ValueError as error:
                record.update(state="skipped", reason=str(error))
                return record, None
            if any(
                token.kind == "identifier" and token.text in {"__d", "__r"} and tokens[index + 1].text == "("
                for index, token in enumerate(tokens[:-1])
            ):
                record["basis"] = "metro-bundle-marker"
                record["framework"] = "react-native"
            else:
                record.update(
                    state="skipped",
                    representation="unrecognized-bundle",
                    reason="bundle name/Metro marker not recognized",
                )
                return record, None
    return record, text


@dataclass(frozen=True)
class Token:
    text: str
    kind: str
    offset: int
    line: int


@dataclass(frozen=True)
class Origin:
    path: str
    line: int
    basis: str
    parameter: int = -1
    steps: tuple[tuple[str, int, str], ...] = ()


@dataclass
class Function:
    path: str
    name: str
    parameters: list[str]
    tokens: list[Token]
    line: int
    offset: int
    direct: bool
    bindings: set[str]

    @property
    def identity(self) -> tuple[str, int]:
        # Names and arities are not identities: nested declarations and members
        # can share both with an unrelated module function, even on one line.
        return self.path, self.offset


def _tokens(text: str) -> list[Token]:
    clean = strip_comments(text, templates=True)
    result, line, previous = [], 1, 0
    for match in TOKEN.finditer(clean):
        line += clean.count("\n", previous, match.start())
        result.append(Token(match[0], match.lastgroup or "unknown", match.start(), line))
        previous = match.start()
        if len(result) > MAX_TOKENS:
            raise ValueError("hybrid token budget reached")
    return result


def _pairs(tokens: list[Token]) -> dict[int, int]:
    stack, pairs = [], {}
    for index, token in enumerate(tokens):
        if token.text in {"(", "[", "{"}:
            stack.append(index)
            if len(stack) > 128:
                raise ValueError("hybrid nesting budget reached")
        elif token.text in {")", "]", "}"}:
            if not stack or tokens[stack[-1]].text != {")": "(", "]": "[", "}": "{"}[token.text]:
                raise ValueError("unbalanced hybrid source")
            start = stack.pop()
            pairs[start] = index
    if stack:
        raise ValueError("unbalanced hybrid source")
    return pairs


def _split(tokens: list[Token], separator: str = ",") -> list[list[Token]]:
    groups, start, depth = [], 0, 0
    for index, token in enumerate(tokens):
        if token.text in {"(", "[", "{"}:
            depth += 1
        elif token.text in {")", "]", "}"}:
            depth -= 1
        elif token.text == separator and depth == 0:
            groups.append(tokens[start:index])
            start = index + 1
    if start < len(tokens):
        groups.append(tokens[start:])
    return groups


def _bindings(
    tokens: list[Token],
    *,
    dart: bool = False,
    function_declarations: bool = True,
    work: list[int] | None = None,
) -> set[str]:
    """Conservative local declarations/writes, independent of execution order.

    This is deliberately not a lexical scope proof. A declaration in a nested
    block can prevent a summary lookup outside that block; it must never make
    us select an unrelated function as a sanitizer.
    """
    result = set()
    work = [0] if work is None else work
    pairs = _pairs(tokens)
    closing = {close: start for start, close in pairs.items()}

    def target(end: int) -> None:
        if end < 0 or end >= len(tokens):
            return
        if tokens[end].kind == "identifier":
            if (
                end == 0
                or tokens[end - 1].text not in {".", "?."}
                or (end >= 2 and tokens[end - 2].text in {"window", "globalThis", "self", "this"})
            ):
                result.add(tokens[end].text)
        elif end in closing and tokens[end].text in {"}", "]"}:
            opening = closing[end]
            if opening and tokens[opening - 1].text in {"window", "globalThis", "self", "this"}:
                if end == opening + 2 and tokens[opening + 1].kind == "string":
                    name = tokens[opening + 1].text[1:-1]
                    result.add(name if re.fullmatch(r"[A-Za-z_$][\w$]*", name) else "*")
                else:
                    result.add("*")
            result.update(part.text for part in tokens[opening + 1 : end] if part.kind == "identifier")

    for index, token in enumerate(tokens):
        if token.text in {"const", "let", "var", "final", "late"}:
            depth, initializer = 0, False
            for next_ in range(index + 1, len(tokens)):
                work[0] += 1
                if work[0] > MAX_OPERATIONS:
                    raise ValueError("hybrid declaration binding operation budget reached")
                part = tokens[next_]
                if depth == 0 and part.text in {";", ")", "in", "of", "const", "let", "var", "final", "late"}:
                    break
                if depth == 0 and part.text == "=":
                    initializer = True
                elif depth == 0 and part.text == ",":
                    initializer = False
                elif not initializer and part.kind == "identifier":
                    result.add(part.text)
                if part.text in {"(", "[", "{"}:
                    depth += 1
                elif part.text in {")", "]", "}"}:
                    depth -= 1
                    if depth < 0:
                        break
        elif token.text == "class" or (function_declarations and token.text == "function"):
            next_ = index + 1
            if next_ < len(tokens) and tokens[next_].text == "*":
                next_ += 1
            if next_ < len(tokens) and tokens[next_].kind == "identifier":
                result.add(tokens[next_].text)
        elif token.text == "catch" and index + 1 in pairs:
            result.update(
                part.text for part in tokens[index + 2 : pairs[index + 1]] if part.kind == "identifier"
            )
        elif token.text in {"=", "in", "of"} and index:
            previous = index - 1
            while previous >= 0 and tokens[previous].text in {
                "+",
                "-",
                "*",
                "/",
                "%",
                "?",
                "??",
                "&&",
                "||",
                "&",
                "|",
                "^",
                ">",
                "<",
            }:
                previous -= 1
            target(previous)
        elif token.text == "=>" and index:
            previous = index - 1
            if previous in closing and tokens[previous].text == ")":
                opening = closing[previous]
                result.update(
                    part.text for part in tokens[opening + 1 : previous] if part.kind == "identifier"
                )
                if opening and tokens[opening - 1].text == ":":
                    result.add("*")
            elif tokens[previous].kind == "identifier" and (
                previous == 0 or tokens[previous - 1].text != ":"
            ):
                result.add(tokens[previous].text)
            else:
                # An unmodeled typed arrow signature cannot establish a stable
                # lexical namespace for any callable in this bounded model.
                result.add("*")
        elif token.text in {"+", "-"} and index + 1 < len(tokens) and tokens[index + 1].text == token.text:
            target(index - 1)
            target(index + 2)
        elif token.text == "with" and index + 1 < len(tokens) and tokens[index + 1].text == "(":
            # Dynamic scope/binding changes cannot justify an empty summary.
            result.add("*")
        elif (
            dart
            and token.kind == "identifier"
            and index
            and index + 1 < len(tokens)
            and tokens[index + 1].text in {";", ","}
            and (tokens[index - 1].kind == "identifier" or tokens[index - 1].text in {">", "?", ")"})
        ):
            # Includes Dart typed declarations without an initializer. Extra
            # bindings here cost precision only; they cannot erase input taint.
            result.add(token.text)
    return result


def _functions(path: str, tokens: list[Token]) -> list[Function]:
    pairs = _pairs(tokens)
    found, consumed = [], set()
    # Writes in a callback or another function may change a module binding.
    # Without a complete execution/scope model, treat every observed write and
    # closure parameter as a possible conflict for the entire source file.
    binding_work = [0]
    module_bindings = _bindings(
        tokens, dart=path.endswith(".dart"), function_declarations=False, work=binding_work
    )
    depths, depth = [], 0
    for token in tokens:
        depths.append(depth)
        if token.text in {"(", "[", "{"}:
            depth += 1
        elif token.text in {")", "]", "}"}:
            depth -= 1
    for start, close in pairs.items():
        if tokens[start].text != "(" or start == 0 or tokens[start - 1].kind != "identifier":
            continue
        name = tokens[start - 1].text
        if name in {"if", "while", "for", "switch", "catch", "with", "await"}:
            continue
        body = close + 1
        # A TypeScript return type can intervene before the block.
        if body < len(tokens) and tokens[body].text == ":":
            body += 1
            while body < len(tokens) and tokens[body].text not in {"{", ";", "=", "}"}:
                body += 1
        if body >= len(tokens) or tokens[body].text != "{" or body not in pairs:
            continue
        before = tokens[max(0, start - 4) : start - 1]
        if any(token.text in {".", "?.", "new", "return"} for token in before[-1:]):
            continue
        parameters, parameter_bindings = [], set()
        for group in _split(tokens[start + 1 : close]):
            default = next((index for index, token in enumerate(group) if token.text == "="), len(group))
            names = [token.text for token in group[:default] if token.kind == "identifier"]
            if not names:
                continue
            # JS/TS name: type vs Dart type name. Destructuring is unsupported.
            parameters.append(names[-1] if path.endswith(".dart") else names[0])
            # Including type/property identifiers is conservative for unsupported
            # destructuring and function-typed parameters.
            parameter_bindings.update(names)
        direct = depths[start] == 0
        if not path.endswith(".dart"):
            keyword = start - 2
            if keyword >= 0 and tokens[keyword].text == "*":
                keyword -= 1
            direct &= keyword >= 0 and tokens[keyword].text == "function"
            # A named function expression belongs to its own lexical scope, not
            # to the file-level callable namespace.
            if direct:
                prefix = keyword - 1
                while prefix >= 0 and tokens[prefix].text in {"export", "default", "async"}:
                    prefix -= 1
                direct = (
                    prefix < 0
                    or tokens[prefix].text in {";", "}"}
                    or (
                        tokens[prefix].line < tokens[keyword].line
                        and (
                            tokens[prefix].kind in {"identifier", "string", "number"}
                            or tokens[prefix].text in {")", "]"}
                        )
                    )
                )
        body_tokens = tokens[body + 1 : pairs[body]]
        found.append(
            Function(
                path,
                name,
                parameters,
                body_tokens,
                tokens[start - 1].line,
                tokens[start - 1].offset,
                direct,
                parameter_bindings | _bindings(body_tokens, dart=path.endswith(".dart"), work=binding_work),
            )
        )
        consumed.update(range(start - 1, pairs[body] + 1))
    # Module-level statements can contain sources and direct calls.
    top = [token for index, token in enumerate(tokens) if index not in consumed]
    found.append(Function(path, "<module>", [], top, 1, -1, True, module_bindings))
    return found


def _relative_import(path: str, target: str) -> str | None:
    if target.startswith("/") or ":" in target or "\\" in target:
        return None
    parts = list(PurePosixPath(path).parent.parts)
    for part in PurePosixPath(target).parts:
        if part == "..":
            if not parts:
                return None
            parts.pop()
        elif part != ".":
            parts.append(part)
    return "/".join(parts) or None


def _imports(path: str, tokens: list[Token]) -> dict[str, str]:
    imports = {}
    pairs = _pairs(tokens)
    for index, token in enumerate(tokens[:-1]):
        if token.kind != "identifier" or token.text != "import":
            continue
        next_ = index + 1
        if path.endswith(".dart") and tokens[next_].kind == "string":
            end = next_ + 1
            if end < len(tokens) and tokens[end].text == ";":
                target = _relative_import(path, tokens[next_].text[1:-1])
                if target:
                    imports["*" + str(index)] = target
            continue
        if tokens[next_].text != "{" or next_ not in pairs:
            continue
        close = pairs[next_]
        if close + 2 >= len(tokens) or tokens[close + 1].text != "from" or tokens[close + 2].kind != "string":
            continue
        literal = tokens[close + 2].text[1:-1]
        target = _relative_import(path, literal) if literal.startswith(".") else None
        if target:
            for names in _split(tokens[next_ + 1 : close]):
                if len(names) == 1 and names[0].kind == "identifier":
                    imports[names[0].text] = target + ":" + names[0].text
                elif (
                    len(names) == 3
                    and names[1].text == "as"
                    and names[0].kind == names[2].kind == "identifier"
                ):
                    imports[names[2].text] = target + ":" + names[0].text
    return imports


class Flow:
    def __init__(self, functions: list[Function], imports: dict[str, dict[str, str]], texts: dict[str, str]):
        self.functions = functions
        self.imports = imports
        self.texts = texts
        self.summaries: dict[tuple[str, int], set[Origin]] = {}
        self.module_bindings = {f.path: f.bindings for f in functions if f.name == "<module>"}
        self.findings: dict[tuple[str, int, str, tuple], dict] = {}
        self.edges: set[tuple[str, int, str, str]] = set()
        self.truncated = False
        self.operations = 0
        self.operation_limit = MAX_OPERATIONS
        self.summaries_complete = False
        self.uncertain_assignments = False
        self.active: list[tuple[str, int]] = []
        self.uncertain_calls = False

    def bound(self, origins: set[Origin]) -> set[Origin]:
        if len(origins) > MAX_ORIGINS:
            self.truncated = True
            return set(
                sorted(origins, key=lambda o: (o.path, o.line, o.basis, o.parameter, o.steps))[:MAX_ORIGINS]
            )
        return origins

    def resolve(self, function: Function, name: str, arity: int) -> Function | None:
        if (
            not function.direct
            or name in function.bindings
            or "*" in function.bindings
            or name in self.module_bindings.get(function.path, set())
            or "*" in self.module_bindings.get(function.path, set())
        ):
            return None
        candidates = [
            f
            for f in self.functions
            if f.direct and f.path == function.path and f.name == name and len(f.parameters) == arity
        ]
        if not candidates and name in self.imports.get(function.path, {}):
            target, exported = self.imports[function.path][name].rsplit(":", 1)
            candidates = [
                f
                for f in self.functions
                if f.direct
                and f.name == exported
                and f.name not in self.module_bindings.get(f.path, set())
                and "*" not in self.module_bindings.get(f.path, set())
                and len(f.parameters) == arity
                and (f.path == target or str(PurePosixPath(f.path).with_suffix("")) == target)
            ]
        if not candidates and function.path.endswith(".dart"):
            targets = {
                value for key, value in self.imports.get(function.path, {}).items() if key.startswith("*")
            }
            candidates = [
                f
                for f in self.functions
                if f.direct
                and f.path in targets
                and f.name == name
                and f.name not in self.module_bindings.get(f.path, set())
                and "*" not in self.module_bindings.get(f.path, set())
                and len(f.parameters) == arity
            ]
        if len(candidates) > 1:
            self.truncated = True
        return candidates[0] if len(candidates) == 1 else None

    def expression(
        self, function: Function, tokens: list[Token], env: dict[str, set[Origin]], emit: bool
    ) -> set[Origin]:
        result: set[Origin] = set()
        pairs = _pairs(tokens)
        index = 0
        while index < len(tokens):
            if self.operations >= self.operation_limit:
                raise ValueError("hybrid flow operation budget reached")
            self.operations += 1
            token = tokens[index]
            if token.kind == "string":
                if token.text.startswith("`") or PurePosixPath(function.path).suffix == ".dart":
                    # Only explicit interpolation expressions carry taint.
                    for name in re.findall(r"\$\{\s*([A-Za-z_$][\w$]*)|\$([A-Za-z_]\w*)", token.text):
                        result.update(env.get(name[0] or name[1], set()))
                index += 1
                continue
            if token.kind != "identifier":
                index += 1
                continue
            end, parts = index, [token.text]
            while (
                end + 2 < len(tokens)
                and tokens[end + 1].text in {".", "?."}
                and tokens[end + 2].kind == "identifier"
            ):
                parts.append(tokens[end + 2].text)
                end += 2
            name = ".".join(parts)
            value = set(env.get(parts[0], set()))
            if name.startswith(("route.params", "window.location", "Uri.base.queryParameters")):
                value.add(Origin(function.path, token.line, name))
            open_ = end + 1
            if open_ < len(tokens) and tokens[open_].text == "(" and open_ in pairs:
                close = pairs[open_]
                uncertain = False
                args = [
                    self.expression(function, group, env, emit) for group in _split(tokens[open_ + 1 : close])
                ]
                if name.endswith(("Linking.getInitialURL", "getInitialLink")):
                    value.add(Origin(function.path, token.line, name))
                else:
                    callee = self.resolve(function, name, len(args)) if len(parts) == 1 else None
                    if callee:
                        self.edges.add((function.path, token.line, callee.path, callee.name))
                        for origin in self.summaries.get(callee.identity, set()):
                            actual = args[origin.parameter] if origin.parameter >= 0 else {origin}
                            for original in actual:
                                steps = (
                                    original.steps
                                    + origin.steps
                                    + ((function.path, token.line, "call " + name),)
                                )
                                value.add(
                                    Origin(
                                        original.path,
                                        original.line,
                                        original.basis,
                                        original.parameter,
                                        steps[-8:],
                                    )
                                )
                        if emit and not self.summaries_complete:
                            value.update(set().union(*args) if args else set())
                            self.uncertain_calls = True
                        if emit and (any(args) or not self.summaries_complete):
                            observed = self.run_function(callee, True, args)
                            if not self.summaries_complete:
                                value.update(observed)
                    else:
                        # Unknown calls propagate input conservatively; they never sanitize it.
                        value.update(set().union(*args) if args else set())
                        uncertain = True
                sink = None
                if parts[-1] in {"loadUrl", "loadRequest", "loadURL"}:
                    sink = "HYBRID-UNTRUSTED-URL"
                elif name == "eval" or parts[-1] in {
                    "injectJavaScript",
                    "evaluateJavascript",
                    "evaluateJavaScript",
                }:
                    sink = "HYBRID-JS-EVAL"
                elif parts[-1] in {"executeSql", "rawQuery", "rawInsert", "rawUpdate"}:
                    sink = "HYBRID-SQL-INPUT"
                elif parts[-1] in {"invokeMethod", "callHandler", "postMessage"} or name.startswith(
                    "NativeModules."
                ):
                    sink = "HYBRID-NATIVE-BRIDGE"
                if uncertain and sink is None:
                    self.uncertain_calls = True
                tainted = (
                    set().union(*args)
                    if sink == "HYBRID-NATIVE-BRIDGE" and args
                    else args[0]
                    if args
                    else set()
                )
                if sink and emit:
                    for origin in tainted:
                        if origin.parameter < 0:
                            self.emit(function, token, sink, name, origin)
                result.update(value)
                index = close + 1
            else:
                result.update(value)
                index = end + 1
        return self.bound(result)

    def emit(self, function: Function, token: Token, rule: str, sink: str, origin: Origin) -> None:
        key = (function.path, token.line, rule, (origin.path, origin.line, origin.basis))
        if len(self.findings) >= MAX_FINDINGS and key not in self.findings:
            self.truncated = True
            return
        evidence = {
            "path": function.path,
            "line": token.line,
            "sink": sink,
            "method": "bounded hybrid token/block flow",
            "scope": "partial language model",
            "source": {"path": origin.path, "line": origin.line, "basis": origin.basis},
            "trace": [{"path": origin.path, "line": origin.line, "role": "source"}]
            + [{"path": path, "line": line, "role": role} for path, line, role in origin.steps]
            + [{"path": function.path, "line": token.line, "role": "sink"}],
            "excerpt": code_excerpt(
                re.sub(r"`[^`]*`", '"…"', self.texts[function.path].split("\n")[token.line - 1])
            ),
        }
        self.findings[key] = finding(
            rule,
            RULES[rule][0],
            "medium" if rule == "HYBRID-NATIVE-BRIDGE" else "high",
            "candidate",
            [evidence],
            "Validate external input before the operation. Review the full language and native bridge implementation on the test build.",
            RULES[rule][1],
            [REFERENCE],
            origin="source",
            confidence="bounded-hybrid-flow",
        )

    def run_function(
        self, function: Function, emit: bool, actual: list[set[Origin]] | None = None
    ) -> set[Origin]:
        identity = function.identity
        if emit and (identity in self.active or len(self.active) >= 4):
            self.truncated = True
            return set()
        if emit:
            self.active.append(identity)
        env = {
            name: set(actual[index])
            if actual is not None
            else {Origin(function.path, function.line, "parameter", index)}
            for index, name in enumerate(function.parameters)
        }
        returned: set[Origin] = set()
        # Braces delimit modeled blocks; assignments merge conservatively across branches.
        chunks = _split(function.tokens, ";")
        for chunk in chunks:
            if not chunk:
                continue
            # Include statements separated by braces (loops/branches are not path proofs).
            pieces, current, expression_depth = [], [], 0
            for token in chunk:
                if token.text in {"(", "["}:
                    expression_depth += 1
                elif token.text in {")", "]"}:
                    expression_depth -= 1
                if token.text in {"{", "}", ";"} and expression_depth == 0:
                    if current:
                        pieces.append(current)
                    current = []
                else:
                    current.append(token)
            if current:
                pieces.append(current)
            for statement in pieces:
                assigned, depth = None, 0
                for index, token in enumerate(statement):
                    if token.text in {"(", "[", "{"}:
                        depth += 1
                    elif token.text in {")", "]", "}"}:
                        depth -= 1
                    elif token.text == "=" and depth == 0:
                        assigned = index
                        break
                if assigned is not None and assigned > 0:
                    value = self.expression(function, statement[assigned + 1 :], env, emit)
                    left = statement[:assigned]
                    while left and left[-1].text in {
                        "+",
                        "-",
                        "*",
                        "/",
                        "%",
                        "??",
                        "&&",
                        "||",
                        "&",
                        "|",
                        "^",
                        ">",
                        "<",
                    }:
                        left = left[:-1]
                    declaration = next(
                        (
                            index
                            for index, token in enumerate(left)
                            if token.text in {"const", "let", "var", "final", "late"}
                        ),
                        None,
                    )
                    name = None
                    if declaration is not None and not function.path.endswith(".dart"):
                        target = left[declaration + 1 :]
                        if target and target[0].kind == "identifier":
                            name = target[0].text
                    elif (
                        left
                        and left[-1].kind == "identifier"
                        and (len(left) < 2 or left[-2].text not in {".", "?."})
                    ):
                        name = left[-1].text
                    if name is not None:
                        env[name] = self.bound(env.get(name, set()) | value)
                    else:
                        self.uncertain_assignments = True
                    if any(token.text == "return" for token in statement):
                        returned.update(value)
                else:
                    value = self.expression(function, statement, env, emit)
                    if any(t.text == "return" for t in statement):
                        returned.update(value)
        if emit:
            self.active.pop()
        return self.bound(returned)


def analyze_hybrid(
    sources: list[tuple[str, str]],
    observed_inputs: list[dict] | None = None,
    *,
    observations_truncated: bool = False,
) -> dict:
    functions, texts, imports, files, warnings = [], {}, {}, [], []
    total = 0
    file_warnings: dict[tuple[str, str], list[str]] = {}
    for index in prioritized_paths([path for path, _ in sources]):
        path, text = sources[index]
        if PurePosixPath(path).suffix.lower() not in SUFFIXES | {".bundle"}:
            continue
        size = len(text.encode("utf-8"))
        record: dict = {
            "path": path,
            "framework": "flutter"
            if path.endswith(".dart")
            else "react-native"
            if PurePosixPath(path).suffix == ".jsbundle" or PurePosixPath(path).name in TEXT_BUNDLE_NAMES
            else "unknown"
            if PurePosixPath(path).suffix == ".bundle"
            else "javascript",
            "language": "dart"
            if path.endswith(".dart")
            else "typescript"
            if PurePosixPath(path).suffix in {".ts", ".tsx"}
            else "javascript",
            "state": "partial",
            "analysis_state": "skipped",
        }
        files.append(record)
        try:
            if size > MAX_BYTES or total + size > MAX_TOTAL:
                raise ValueError("hybrid byte budget reached")
            total += size
            observed, recognized_text = hybrid_source_input(path, text.encode("utf-8"))
            if observed is not None:
                record.update({key: value for key, value in observed.items() if key != "state"})
            if recognized_text is None:
                raise ValueError(record.get("reason", "unrecognized hybrid source"))
            tokens = _tokens(text)
            parsed = _functions(path, tokens)
            if len(functions) + len(parsed) > MAX_FUNCTIONS:
                raise ValueError("hybrid function budget reached")
            functions.extend(parsed)
            texts[path] = text
            imports[path] = _imports(path, tokens)
            record.update({"tokens": len(tokens), "functions": len(parsed) - 1, "analysis_state": "analyzed"})
        except ValueError as error:
            record["error"] = str(error)
            record["reason"] = str(error)
            file_warnings.setdefault(("analysis incomplete", str(error)), []).append(path)
    source_paths = {record["path"] for record in files}
    observations = sorted(observed_inputs or [], key=lambda item: item["path"])
    for observed in observations[:MAX_INPUT_DETAILS]:
        if observed["path"] in source_paths:
            continue
        files.append({**observed, "state": "partial", "analysis_state": "skipped"})
        reason = observed.get("reason", "source unavailable")
        file_warnings.setdefault(("source not analyzed", reason), []).append(observed["path"])
    # Keep every per-file state/reason above while bounding repeated diagnostics
    # for large repositories. A counted warning must never imply checked absence.
    for (kind, reason), paths in sorted(file_warnings.items()):
        if len(paths) <= 3:
            warnings.extend(f"Hybrid {kind} for {path}: {reason}" for path in paths)
        else:
            warnings.append(
                f"Hybrid {kind} for {len(paths)} files: {reason}; "
                "per-file reasons remain in inventory.hybrid_analysis.files; coverage incomplete"
            )
    observations_truncated |= len(observations) > MAX_INPUT_DETAILS
    if observations_truncated:
        warnings.append("Hybrid input observation budget reached; additional framework content is unknown")
    flow = Flow(functions, imports, texts)
    # Reserve emission work within the unchanged total operation cap. Summary
    # exhaustion cannot consume all work before direct sinks are inspected.
    flow.operation_limit = max(1, MAX_OPERATIONS // 2)
    try:
        for _ in range(MAX_ROUNDS):
            updated = {f.identity: flow.run_function(f, False) for f in functions}
            if updated == flow.summaries:
                flow.summaries_complete = not flow.truncated
                break
            flow.summaries = updated
        else:
            warnings.append("Hybrid callable summary iteration budget reached")
    except ValueError as error:
        warnings.append(f"Hybrid callable summaries incomplete: {error}")
    summary_operations = flow.operations
    flow.operation_limit = MAX_OPERATIONS
    try:
        for function in functions:
            flow.run_function(function, True)
    except ValueError as error:
        warnings.append(f"Hybrid modeled emission incomplete: {error}")
    if flow.truncated:
        warnings.append("Hybrid finding/origin/call-depth budget reached")
    if flow.uncertain_calls:
        warnings.append(
            "Hybrid callable identity unresolved or shadowed; uncertain calls retain argument taint"
        )
    if flow.uncertain_assignments:
        warnings.append(
            "Hybrid member or destructuring assignment target unresolved; bare local bindings are not assumed"
        )
    for record in files:
        if record["analysis_state"] == "analyzed":
            record["flow_state"] = "incomplete" if warnings else "bounded-modeled"
    frameworks = []
    for framework in sorted({record.get("framework", "javascript") for record in files}):
        members = [record for record in files if record.get("framework", "javascript") == framework]
        frameworks.append(
            {
                "framework": framework,
                "observed_files": len(members),
                "analyzed_text_files": sum(record["analysis_state"] == "analyzed" for record in members),
                "skipped_files": sum(record["analysis_state"] == "skipped" for record in members),
                "representations": sorted(
                    {record.get("representation", "text-source") for record in members}
                ),
                "compiled_analysis": "not-supported",
            }
        )
    note = "Bounded token/block argument-return flow only; no full JS/TS/Dart grammar, sanitizer proof, callback/lifecycle/native dispatch or exploitability proof."
    return {
        "findings": list(flow.findings.values()),
        "coverage": [
            {
                "rule_id": rule,
                "state": "partial" if files or observations_truncated else "not-applicable",
                "method": "hybrid-structural-flow",
                "note": note,
            }
            for rule in RULES
        ],
        "warnings": warnings,
        "metadata": {
            "engine": "bounded-hybrid-v1",
            "files": files,
            "frameworks": frameworks,
            "input_observations_truncated": observations_truncated,
            "file_warning_counts": [
                {"kind": kind, "reason": reason, "files": len(paths)}
                for (kind, reason), paths in sorted(file_warnings.items())
            ],
            "bytes": total,
            "operations": {
                "summary": summary_operations,
                "emission": flow.operations - summary_operations,
                "total": flow.operations,
                "max_total": MAX_OPERATIONS,
                "summaries_complete": flow.summaries_complete,
            },
            "call_edges": [
                {"path": path, "line": line, "callee_path": callee_path, "callee": name}
                for path, line, callee_path, name in sorted(flow.edges)
            ],
            "complete": not (files or observations_truncated),
            "limits": note,
        },
    }
