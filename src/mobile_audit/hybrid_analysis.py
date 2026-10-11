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


def _functions(path: str, tokens: list[Token]) -> list[Function]:
    pairs = _pairs(tokens)
    found, consumed = [], set()
    for start, close in pairs.items():
        if tokens[start].text != "(" or start == 0 or tokens[start - 1].kind != "identifier":
            continue
        name = tokens[start - 1].text
        if name in {"if", "while", "for", "switch", "catch", "with"}:
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
        parameters = []
        for group in _split(tokens[start + 1 : close]):
            names = [token.text for token in group if token.kind == "identifier"]
            if not names:
                continue
            # JS/TS name: type vs Dart type name. Destructuring is unsupported.
            parameters.append(names[0] if any(t.text == ":" for t in group) or len(names) == 1 else names[-1])
        found.append(Function(path, name, parameters, tokens[body + 1 : pairs[body]], tokens[start - 1].line))
        consumed.update(range(start - 1, pairs[body] + 1))
    # Module-level statements can contain sources and direct calls.
    top = [token for index, token in enumerate(tokens) if index not in consumed]
    found.append(Function(path, "<module>", [], top, 1))
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
        self.summaries: dict[tuple[str, str, int], set[Origin]] = {}
        self.findings: dict[tuple[str, int, str, tuple], dict] = {}
        self.edges: set[tuple[str, int, str, str]] = set()
        self.truncated = False
        self.operations = 0
        self.active: list[tuple[str, str, int]] = []

    def bound(self, origins: set[Origin]) -> set[Origin]:
        if len(origins) > MAX_ORIGINS:
            self.truncated = True
            return set(
                sorted(origins, key=lambda o: (o.path, o.line, o.basis, o.parameter, o.steps))[:MAX_ORIGINS]
            )
        return origins

    def resolve(self, function: Function, name: str, arity: int) -> Function | None:
        candidates = [
            f
            for f in self.functions
            if f.path == function.path and f.name == name and len(f.parameters) == arity
        ]
        if not candidates and name in self.imports.get(function.path, {}):
            target, exported = self.imports[function.path][name].rsplit(":", 1)
            candidates = [
                f
                for f in self.functions
                if f.name == exported
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
                if f.path in targets and f.name == name and len(f.parameters) == arity
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
            self.operations += 1
            if self.operations > MAX_OPERATIONS:
                raise ValueError("hybrid flow operation budget reached")
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
                args = [
                    self.expression(function, group, env, emit) for group in _split(tokens[open_ + 1 : close])
                ]
                if name.endswith(("Linking.getInitialURL", "getInitialLink")):
                    value.add(Origin(function.path, token.line, name))
                else:
                    callee = self.resolve(function, name, len(args)) if len(parts) == 1 else None
                    if callee:
                        self.edges.add((function.path, token.line, callee.path, callee.name))
                        for origin in self.summaries.get((callee.path, callee.name, len(args)), set()):
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
                        if emit and any(args):
                            self.run_function(callee, True, args)
                    else:
                        # Unknown calls propagate input conservatively; they never sanitize it.
                        value.update(set().union(*args) if args else set())
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
                re.sub(r"`[^`]*`", '"…"', self.texts[function.path].splitlines()[token.line - 1])
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
        identity = (function.path, function.name, function.line)
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
            pieces, current = [], []
            for token in chunk:
                if token.text in {"{", "}"}:
                    if current:
                        pieces.append(current)
                    current = []
                else:
                    current.append(token)
            if current:
                pieces.append(current)
            for statement in pieces:
                assigned = next((i for i, t in enumerate(statement) if t.text == "="), None)
                if assigned is not None and assigned > 0 and statement[assigned - 1].kind == "identifier":
                    value = self.expression(function, statement[assigned + 1 :], env, emit)
                    name = statement[assigned - 1].text
                    env[name] = self.bound(env.get(name, set()) | value)
                else:
                    value = self.expression(function, statement, env, emit)
                    if any(t.text == "return" for t in statement):
                        returned.update(value)
        if emit:
            self.active.pop()
        return self.bound(returned)


def analyze_hybrid(sources: list[tuple[str, str]]) -> dict:
    functions, texts, imports, files, warnings = [], {}, {}, [], []
    total = 0
    for index in prioritized_paths([path for path, _ in sources]):
        path, text = sources[index]
        if PurePosixPath(path).suffix not in SUFFIXES:
            continue
        size = len(text.encode("utf-8"))
        record: dict = {
            "path": path,
            "language": "dart"
            if path.endswith(".dart")
            else "typescript"
            if PurePosixPath(path).suffix in {".ts", ".tsx"}
            else "javascript",
            "state": "partial",
        }
        files.append(record)
        try:
            if size > MAX_BYTES or total + size > MAX_TOTAL:
                raise ValueError("hybrid byte budget reached")
            total += size
            tokens = _tokens(text)
            parsed = _functions(path, tokens)
            if len(functions) + len(parsed) > MAX_FUNCTIONS:
                raise ValueError("hybrid function budget reached")
            functions.extend(parsed)
            texts[path] = text
            imports[path] = _imports(path, tokens)
            record.update({"tokens": len(tokens), "functions": len(parsed) - 1})
        except ValueError as error:
            record["error"] = str(error)
            warnings.append(f"Hybrid analysis incomplete for {path}: {error}")
    flow = Flow(functions, imports, texts)
    try:
        for _ in range(MAX_ROUNDS):
            updated = {(f.path, f.name, len(f.parameters)): flow.run_function(f, False) for f in functions}
            if updated == flow.summaries:
                break
            flow.summaries = updated
        else:
            warnings.append("Hybrid callable summary iteration budget reached")
        for function in functions:
            flow.run_function(function, True)
    except ValueError as error:
        warnings.append(f"Hybrid modeled flow incomplete: {error}")
    if flow.truncated:
        warnings.append("Hybrid finding/origin/call-depth budget reached")
    note = "Bounded token/block argument-return flow only; no full JS/TS/Dart grammar, sanitizer proof, callback/lifecycle/native dispatch or exploitability proof."
    return {
        "findings": list(flow.findings.values()),
        "coverage": [
            {
                "rule_id": rule,
                "state": "partial" if files else "not-applicable",
                "method": "hybrid-structural-flow",
                "note": note,
            }
            for rule in RULES
        ],
        "warnings": warnings,
        "metadata": {
            "engine": "bounded-hybrid-v1",
            "files": files,
            "bytes": total,
            "call_edges": [
                {"path": path, "line": line, "callee_path": callee_path, "callee": name}
                for path, line, callee_path, name in sorted(flow.edges)
            ],
            "complete": False if files else True,
            "limits": note,
        },
    }
