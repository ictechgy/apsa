"""Offline, function-scoped mobile source checks over bundled Tree-sitter grammars.

These checks follow local assignments and known platform input APIs. They do not
resolve methods, prove that an Android component is exported, or model navigation
redirects, lifecycle state, reflection, or an arbitrary sanitizer's implementation.
Every result remains a candidate for validation on the application's test build.
"""

from __future__ import annotations

import importlib
import re
import warnings as python_warnings
from bisect import bisect_right
from dataclasses import dataclass, field
from pathlib import PurePath
from typing import Any

from .core import code_excerpt, finding
from .maswe import weaknesses_for
from .specs import SINK_KINDS

MAX_AST_BYTES = 2 * 1024 * 1024
MAX_AST_TOTAL = 32 * 1024 * 1024
MAX_AST_NODES = 100_000
MAX_AST_FINDINGS = 500
LANGUAGES = {".java": "java", ".kt": "kotlin", ".kts": "kotlin", ".swift": "swift", ".m": "objc"}
UNSUPPORTED_SOURCE = {".mm", ".dart", ".js", ".jsx", ".ts", ".tsx", ".cs"}
FUNCTIONS = {
    "method_declaration",
    "constructor_declaration",
    "function_declaration",
    "method_definition",
    "function_definition",
}
COMMENTS = {"comment", "line_comment", "block_comment", "multiline_comment"}
STRINGS = {"string_literal", "line_string_literal", "multi_line_string_literal", "character_literal"}
IDENTIFIERS = {"identifier", "simple_identifier"}
BLOCKS = {"block", "statements", "function_body"}
URI_REFERENCE = "https://developer.android.com/privacy-and-security/risks/unsafe-uri-loading"
# Framework flag names a PendingIntent flags expression may contain, with optional class prefix.
PENDING_INTENT_FLAGS = {
    "FLAG_ONE_SHOT",
    "FLAG_NO_CREATE",
    "FLAG_CANCEL_CURRENT",
    "FLAG_UPDATE_CURRENT",
    "FLAG_IMMUTABLE",
    "FLAG_MUTABLE",
    "FLAG_ALLOW_UNSAFE_IMPLICIT_INTENT",
}
FRAMEWORK_FLAG = re.compile(
    r"(?:(?:android\.app\.)?PendingIntent\.|(?:android\.content\.)?Intent\.)?"
    r"(FLAG_(?:ACTIVITY|RECEIVER|GRANT)_[A-Z_]+|" + "|".join(sorted(PENDING_INTENT_FLAGS)) + ")"
)
FLAG_TOKEN = re.compile(r"[A-Za-z_][\w.]*|0[xX][0-9A-Fa-f]+|\d+|\S")
UNKNOWN_INTENT = "Intent variable not built in this function; its target is unknown"
BRIDGE_REFERENCE = "https://developer.android.com/privacy-and-security/risks/insecure-webview-native-bridges"
SSL_REFERENCE = "https://developer.android.com/reference/android/webkit/WebViewClient#onReceivedSslError(android.webkit.WebView,%20android.webkit.SslErrorHandler,%20android.net.http.SslError)"
CRYPTO_REFERENCE = "https://developer.android.com/privacy-and-security/cryptography"
SQL_REFERENCE = "https://developer.android.com/privacy-and-security/risks/sql-injection"
RULES = {
    "AST-WEBVIEW-UNTRUSTED-URL": (
        "Platform-controlled input reaches a WebView without a recognized local validation guard",
        "high",
        "Parse the input and enforce an HTTPS scheme and an exact host allowlist before loading it. "
        "Avoid passing platform-controlled strings to JavaScript evaluation; use structured arguments.",
        URI_REFERENCE,
    ),
    "AST-WEBVIEW-HOST-ALLOWLIST": (
        "Partial string allowlist guards a WebView load",
        "high",
        "Validate a parsed URI's scheme and complete hostname. A subdomain suffix must include the "
        "leading dot; review redirects and subsequent navigation separately.",
        URI_REFERENCE,
    ),
    "AST-WEBVIEW-SSL-BYPASS": (
        "SSL error callback proceeds with a rejected certificate",
        "high",
        "Cancel the SSL error. Fix the server certificate or the application's trust configuration.",
        SSL_REFERENCE,
    ),
    "AST-WEBVIEW-JS-BRIDGE": (
        "A native JavaScript interface is present while platform-controlled content is loaded",
        "high",
        "Remove native interfaces before loading untrusted content, restrict origins, and expose only "
        "the minimum necessary functionality. Validate redirects and subframes on the test build.",
        BRIDGE_REFERENCE,
    ),
    "AST-CRYPTO-ECB": (
        "An explicit AES/ECB transformation is selected",
        "high",
        "Use an authenticated encryption construction such as AES-GCM with correctly managed keys and nonces.",
        CRYPTO_REFERENCE,
    ),
    "AST-CRYPTO-WEAK-HASH": (
        "A weak digest primitive is used; review its security purpose",
        "medium",
        "Replace collision-sensitive uses of MD5 or SHA-1. A digest API alone does not prove a security-sensitive use.",
        CRYPTO_REFERENCE,
    ),
    "AST-PENDINGINTENT-MUTABLE": (
        "Mutable PendingIntent wraps an Intent without a recognized explicit component",
        "medium",
        "Use FLAG_IMMUTABLE, or make the wrapped Intent explicit (class, component or package) when "
        "mutability is required.",
        "https://developer.android.com/privacy-and-security/risks/pending-intent",
    ),
    "AST-SQL-CONCAT": (
        "Platform-controlled data reaches an Android raw SQL statement",
        "high",
        "Keep the SQL statement constant and pass untrusted values as bound parameters. Review unknown helpers separately.",
        SQL_REFERENCE,
    ),
}
LIMITS_NOTE = (
    "Function-scoped local def-use analysis; no method dispatch, interprocedural flow, "
    "component reachability, redirect, or authentication-state proof."
)


def _walk(node: Any, *, descend_functions: bool = True):
    stack = [node]
    while stack:
        current = stack.pop()
        yield current
        if current.type in COMMENTS or (not descend_functions and current.type in FUNCTIONS):
            continue
        stack.extend(reversed(current.named_children))


def _field(node: Any, name: str) -> Any:
    return node.child_by_field_name(name)


def _fields(node: Any, name: str) -> list[Any]:
    return [child for i, child in enumerate(node.children) if node.field_name_for_child(i) == name]


@dataclass(frozen=True)
class Trace:
    origin: int
    source: Any
    description: str
    steps: tuple[Any, ...] = ()


@dataclass(frozen=True)
class Value:
    traces: tuple[Trace, ...] = ()
    category: str = "unknown"
    type_name: str = ""

    def bind(self, node: Any) -> Value:
        return Value(
            tuple(Trace(t.origin, t.source, t.description, (t.steps + (node,))[-12:]) for t in self.traces),
            self.category,
            self.type_name,
        )


def _union(values: list[Value], category: str = "unknown", type_name: str = "") -> Value:
    traces = {trace.origin: trace for value in values for trace in value.traces}
    return Value(tuple(traces.values())[:8], category, type_name)


@dataclass(frozen=True)
class Call:
    node: Any
    name: str
    receiver: Any
    args: tuple[Any, ...]


@dataclass
class Frame:
    values: dict[str, Value] = field(default_factory=dict)
    types: dict[str, str] = field(default_factory=dict)
    bridges: dict[tuple[str, str | None], Call] = field(default_factory=dict)
    javascript: dict[str, str] = field(default_factory=dict)

    def copy(self) -> Frame:
        return Frame(self.values.copy(), self.types.copy(), self.bridges.copy(), self.javascript.copy())


# SQL syntax argument per framework method (receiver type, method) -> argument index.
SQL_SINKS = {
    ("android.database.sqlite.SQLiteDatabase", "rawQuery"): 0,
    ("android.database.sqlite.SQLiteDatabase", "execSQL"): 0,
    ("android.database.sqlite.SQLiteDatabase", "rawQueryWithFactory"): 1,
    ("android.database.sqlite.SQLiteDatabase", "compileStatement"): 0,
    ("android.database.sqlite.SQLiteDatabase", "delete"): 1,
    ("android.database.sqlite.SQLiteDatabase", "update"): 2,
    ("android.database.sqlite.SQLiteDatabase", "query"): 2,
    ("android.database.sqlite.SQLiteQueryBuilder", "appendWhere"): 0,
}
PROVIDER_METHODS = {"query", "update", "delete", "insert", "call"}


class Analyzer:
    def __init__(
        self,
        path: str,
        text: str,
        language: str,
        specs: dict | None = None,
        exposed_providers: set[str] | None = None,
        android_levels: dict | None = None,
    ):
        self.path = path
        # Declared minSdk/targetSdk as integers, or None when unknown.
        self.android_levels = android_levels or {}
        self.specs = specs or {"source": [], "sink": []}
        # Simple class names of providers other apps can reach (exported, no permission).
        self.exposed_providers = exposed_providers or set()
        self.raw = text.encode("utf-8")
        self.line_offsets = [0] + [match.end() for match in re.finditer(b"\n", self.raw)]
        self.lines = text.split("\n")
        self.language = language
        self.findings: list[dict] = []
        self.scope = ""
        self.field_types: dict[str, str] = {}
        self.parameter_types: dict[str, str] = {}
        self.activity_scope = False
        self.imports: set[str] = set()
        self.class_names: set[str] = set()
        self.safe_local_types: set[str] = set()
        self.defined_functions: set[str] = set()
        self.pattern_exclusions: dict[str, set[tuple[int, int]]] = {}
        self.function_counts = {"observed": 0, "analyzed": 0, "skipped": 0, "without_body": 0}

    def text(self, node: Any) -> str:
        return self.raw[node.start_byte : node.end_byte].decode("utf-8", errors="replace") if node else ""

    def location(self, node: Any) -> dict:
        row = bisect_right(self.line_offsets, node.start_byte) - 1
        return {
            "path": self.path,
            "line": row + 1,
            "column": node.start_byte - self.line_offsets[row] + 1,
            "offset": node.start_byte,
        }

    def key(self, node: Any) -> str:
        return re.sub(r"[?!\s]", "", self.text(node)).removeprefix("this.").removeprefix("self.")

    def spec_entry(self, kind: str, call: Call, frame: Frame) -> dict | None:
        """The declared source or sink for this call: exact name and, if given, receiver.

        An entry naming this receiver wins over a receiver-less entry for the same method.
        """
        fallback = None
        for entry in self.specs.get(kind, []):
            if entry["method"] != call.name:
                continue
            receiver = entry.get("receiver")
            if receiver is None:
                fallback = fallback or entry
                continue
            if call.receiver is None:
                continue
            key = self.key(call.receiver)
            type_name = self.value(call.receiver, frame).type_name
            simple = receiver.rsplit(".", 1)[-1]
            if receiver in {key, type_name} or simple in {key, type_name.rsplit(".", 1)[-1]}:
                return entry
        return fallback

    def pending_intent_mutability(self, node: Any) -> str | None:
        """How a literal flags expression leaves a PendingIntent mutable; None when immutable or unknown.

        Only framework flag names, integer literals, or/|/+ and parentheses are read; a
        project constant or any other expression is a variable and is not followed.
        """
        names = set()
        for token in FLAG_TOKEN.findall(self.text(node)):
            flag = FRAMEWORK_FLAG.fullmatch(token)
            if flag:
                names.add(flag[1])
            elif not (re.fullmatch(r"0[xX][0-9A-Fa-f]+|\d+", token) or token in {"or", "|", "+", "(", ")"}):
                return None
        if "FLAG_MUTABLE" in names:
            return "FLAG_MUTABLE"
        if "FLAG_IMMUTABLE" in names:
            return None
        # Without FLAG_IMMUTABLE a PendingIntent is mutable on Android 11 and lower; with
        # targetSdk 31+ creating it throws on Android 12+. minSdk 31+ rules out the old devices.
        minimum = self.android_levels.get("min")
        if isinstance(minimum, int) and minimum >= 31:
            return None
        return "default (no FLAG_IMMUTABLE)"

    def intent_expression(self, node: Any, call_node: Any) -> tuple[str, str]:
        """Text that builds the Intent passed to a PendingIntent, following a local variable."""
        text = self.text(node)
        if node.type not in IDENTIFIERS:
            return text, "no class, component or package in the argument expression"
        function = call_node
        while function is not None and function.type not in FUNCTIONS:
            function = function.parent
        # Byte offsets: slice the encoded source, not decoded text, so non-ASCII stays aligned.
        body = (
            self.raw[function.start_byte : call_node.start_byte].decode("utf-8", errors="replace")
            if function
            else ""
        )
        name = re.escape(text)
        parts = []
        for match in re.finditer(rf"\b{name}\b\s*(?::\s*[\w.?]+\s*)?=(?!=)", body):
            end = body.find("\n", match.end())
            line = body[match.end() : len(body) if end < 0 else end]
            parts.append(line)
            # Kotlin scope functions configure the Intent in a following block.
            if re.search(r"\.(?:apply|also|run)\s*\{\s*$", line):
                depth, index = 1, end + 1
                while 0 < index < len(body) and depth:
                    depth += {"{": 1, "}": -1}.get(body[index], 0)
                    index += 1
                parts.append(body[end:index])
        parts += re.findall(
            rf"\b{name}\s*\.\s*(?:setClass\w*|setComponent|setPackage|component\s*=|`?package`?\s*=)", body
        )
        if not parts:
            return text, UNKNOWN_INTENT
        return " ".join(parts), "no class, component or package where the Intent variable is built"

    def literal(self, node: Any) -> str | None:
        if not node or node.type not in STRINGS:
            return None
        text = self.text(node)
        # Escapes and interpolation require runtime interpretation; never treat them as an allowlist.
        if "\\" in text or "${" in text or text.startswith('"""'):
            return None
        return text[1:-1] if text.startswith(('"', "'")) and text[-1:] == text[:1] else None

    def navigation(self, node: Any) -> tuple[Any, str] | None:
        if node.type == "field_access":
            return _field(node, "object"), self.text(_field(node, "field"))
        if node.type == "navigation_expression":
            target = _field(node, "target") or node.named_children[0]
            suffix = _field(node, "suffix") or node.named_children[-1]
            identifiers = [part for part in _walk(suffix) if part.type in IDENTIFIERS]
            return target, self.text(identifiers[-1]) if identifiers else self.text(suffix)
        return None

    def call(self, node: Any) -> Call | None:
        if node.type == "method_invocation":
            arguments = _field(node, "arguments")
            return Call(
                node, self.text(_field(node, "name")), _field(node, "object"), tuple(arguments.named_children)
            )
        if node.type == "object_creation_expression":
            arguments = _field(node, "arguments")
            return Call(node, self.text(_field(node, "type")), None, tuple(arguments.named_children))
        if node.type != "call_expression" or not node.named_children:
            return None
        callee = node.named_children[0]
        navigation = self.navigation(callee)
        receiver, name = navigation if navigation else (None, self.text(callee))
        arguments = next((part for part in node.named_children if part.type == "value_arguments"), None)
        if arguments is None:
            suffix = next((part for part in node.named_children if part.type == "call_suffix"), None)
            arguments = (
                next((part for part in suffix.named_children if part.type == "value_arguments"), None)
                if suffix
                else None
            )
        args = []
        if arguments:
            for arg in arguments.named_children:
                value = _field(arg, "value")
                if value is None:
                    values = [child for child in arg.named_children if child.type != "value_argument_label"]
                    value = values[-1] if values else None
                if value is not None:
                    args.append(value)
        return Call(node, name, receiver, tuple(args))

    def source(self, node: Any, description: str, category: str, prior: Value | None = None) -> Value:
        steps = prior.traces[0].steps if prior and prior.traces else ()
        return Value((Trace(node.start_byte, node, description, (steps + (node,))[-12:]),), category)

    def changed(self, node: Any, value: Value) -> Value:
        # Checking one URL must not bless a later concatenation or an unknown helper's return value.
        return Value(
            tuple(
                Trace(
                    hash((node.start_byte, trace.origin)),
                    trace.source,
                    trace.description,
                    (trace.steps + (node,))[-12:],
                )
                for trace in value.traces
            ),
            "unknown",
            value.type_name,
        )

    def value(self, node: Any, frame: Frame) -> Value:
        if node is None or node.type in COMMENTS:
            return Value()
        if node.type in STRINGS:
            interpolations = [
                part
                for part in _walk(node)
                if part.type in {"interpolated_expression", "interpolation", "interpolated_string_expression"}
            ]
            return self.changed(node, _union([self.value(part, frame) for part in interpolations], "text"))
        if node.type in IDENTIFIERS:
            name = self.text(node)
            if (
                name == "intent"
                and name not in frame.values
                and name not in self.field_types
                and self.activity_scope
            ):
                return self.source(node, "Activity.intent property", "intent")
            return frame.values.get(
                name, Value(type_name=frame.types.get(name, self.field_types.get(name, "")))
            )
        if node.type == "unary_expression" and self.text(node).rstrip().endswith("!!"):
            argument = _field(node, "argument")
            if argument is not None:
                return self.value(argument, frame)
        navigation = self.navigation(node)
        if navigation:
            base, member = navigation
            if self.text(base) in {"this", "self"}:
                return frame.values.get(member, Value(type_name=self.field_types.get(member, "")))
            value = self.value(base, frame)
            if value.category == "intent" and member in {"data", "dataString"}:
                return self.source(node, "Intent data", "url" if member == "data" else "text", value)
            if value.category in {"request", "navigation", "url-context"} and member == "url":
                return self.source(node, "Platform navigation URL", "url", value)
            if value.category == "navigation" and member == "request":
                return Value(value.traces, "request")
            if value.category == "url" and member in {"host", "scheme"}:
                return Value(value.traces, member)
            if value.traces and member == "queryItems":
                return self.source(node, "URL query items", "text", value)
            if member == "absoluteString" and value.category == "url":
                return Value(value.traces, "text")
            return self.changed(node, Value(value.traces, "unknown", value.type_name))
        call = self.call(node)
        if call:
            receiver = self.value(call.receiver, frame)
            args = [self.value(arg, frame) for arg in call.args]
            if call.name == "getIntent" and (call.receiver is None or self.text(call.receiver) == "this"):
                return self.source(node, "Activity Intent", "intent")
            if call.name in {"getData", "getDataString"} and receiver.category == "intent":
                return self.source(node, "Intent data", "url" if call.name == "getData" else "text", receiver)
            if call.name in {"getStringExtra", "getCharSequenceExtra"} and receiver.category == "intent":
                return self.source(node, "Intent string extra", "text", receiver)
            if call.name in {"getQueryParameter", "getQueryParameters"} and receiver.traces:
                return self.source(node, "URL query parameter", "text", receiver)
            if call.name in {"getUrl", "getURL"} and receiver.category in {"request", "navigation"}:
                return self.source(node, "Platform navigation URL", "url", receiver)
            if call.name in {"getHost", "getScheme"} and receiver.category == "url":
                return Value(receiver.traces, "host" if call.name == "getHost" else "scheme")
            if call.name == "parse" and self.key(call.receiver) in {"Uri", "URI"}:
                return _union(args, "url", "Uri")
            if call.name in {"URI", "URL", "URLComponents"}:
                return _union(args, "url", call.name)
            if call.name == "URLRequest":
                return _union(args, "request", "URLRequest")
            if call.name in {"WebView", "WKWebView", "UIWebView"}:
                return Value(type_name=call.name)
            if call.name in {"toString", "absoluteString"}:
                return _union([receiver], "text")
            declared = self.spec_entry("source", call, frame)
            if declared:
                return self.source(
                    node, f"Project specification source {declared['id']}", declared["returns"], receiver
                )
            # Unknown calls retain input provenance, with no assumed sanitization or return type.
            return self.changed(node, _union([receiver, *args]))
        if node.type in {
            "parenthesized_expression",
            "postfix_expression",
            "prefix_expression",
            "cast_expression",
        }:
            target = _field(node, "target") or _field(node, "value")
            if target:
                return self.value(target, frame)
            children = [
                self.value(child, frame)
                for child in node.named_children
                if child.type not in {"bang", "user_type", "type_identifier"}
            ]
            return children[-1] if children else Value()
        return self.changed(node, _union([self.value(child, frame) for child in node.named_children]))

    def declaration(self, node: Any) -> tuple[str, Any, str] | None:
        if node.type == "variable_declarator":
            parent = node.parent
            return self.text(_field(node, "name")), _field(node, "value"), self.text(_field(parent, "type"))
        if node.type != "property_declaration":
            return None
        if self.language == "swift":
            pattern = _field(node, "name")
            identifier = (
                next((part for part in _walk(pattern) if part.type in IDENTIFIERS), None) if pattern else None
            )
            annotation = next((part for part in node.named_children if part.type == "type_annotation"), None)
            return self.text(identifier), _field(node, "value"), self.text(annotation).lstrip(": ")
        declaration = next(
            (part for part in node.named_children if part.type == "variable_declaration"), None
        )
        if declaration is None:
            return None
        name = next((part for part in declaration.named_children if part.type in IDENTIFIERS), None)
        type_node = next((part for part in declaration.named_children if part != name), None)
        values = [
            part for part in node.named_children if part.type not in {"variable_declaration", "modifiers"}
        ]
        return self.text(name), values[-1] if values else None, self.text(type_node)

    def constraints(self, node: Any, frame: Frame) -> dict[int, set[str]]:
        if node is None:
            return {}
        if node.type == "parenthesized_expression" and node.named_children:
            return self.constraints(node.named_children[0], frame)
        left = _field(node, "left") or _field(node, "lhs")
        right = _field(node, "right") or _field(node, "rhs")
        if left and right:
            operator = self.raw[left.end_byte : right.start_byte].decode().strip()
            if operator == "&&":
                result = self.constraints(left, frame)
                for origin, checks in self.constraints(right, frame).items():
                    result.setdefault(origin, set()).update(checks)
                return result
            if operator != "==":
                return {}
            if self.text(right) == "true":
                return self.constraints(left, frame)
            return self.comparison(left, right, frame) or self.comparison(right, left, frame)
        call = self.call(node)
        if call and len(call.args) == 1:
            if call.name in {"equals", "equalsIgnoreCase"}:
                return self.comparison(call.receiver, call.args[0], frame) or self.comparison(
                    call.args[0], call.receiver, frame
                )
            if call.name in {"endsWith", "hasSuffix"}:
                receiver = self.value(call.receiver, frame)
                literal = self.literal(call.args[0])
                if (
                    receiver.category == "host"
                    and literal
                    and literal.startswith(".")
                    and self.hostname(literal[1:])
                ):
                    return {trace.origin: {"host"} for trace in receiver.traces}
        return {}

    @staticmethod
    def hostname(value: str) -> bool:
        return bool(re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?", value)) and ".." not in value

    def comparison(self, expression: Any, literal_node: Any, frame: Frame) -> dict[int, set[str]]:
        value = self.value(expression, frame)
        literal = self.literal(literal_node)
        valid = value.category == "scheme" and literal == "https"
        valid |= value.category == "host" and literal is not None and self.hostname(literal)
        return {trace.origin: {value.category} for trace in value.traces} if valid else {}

    def emit(self, rule: str, node: Any, *, traces: tuple[Trace, ...] = (), **details: Any) -> None:
        if len(self.findings) >= MAX_AST_FINDINGS:
            return
        title, severity, remediation, reference = RULES[rule]
        row = self.location(node)["line"] - 1
        evidence = {
            **self.location(node),
            "basis": "source-ast-local-flow",
            "language": self.language,
            "function": self.scope,
            "excerpt": code_excerpt(self.lines[row]) if row < len(self.lines) else "",
            **details,
        }
        if traces:
            evidence["sources"] = [
                {**self.location(trace.source), "kind": trace.description} for trace in traces
            ]
            evidence["flow"] = [{**self.location(step), "operation": step.type} for step in traces[0].steps]
        self.findings.append(
            finding(
                rule,
                title,
                severity,
                "candidate",
                [evidence],
                remediation,
                "MASVS-CRYPTO"
                if "CRYPTO" in rule
                else "MASVS-CODE"
                if "SQL" in rule
                else "MASVS-NETWORK"
                if "SSL" in rule
                else "MASVS-PLATFORM",
                [reference],
                confidence="structural",
                origin="source-analysis",
                analysis_limits=LIMITS_NOTE,
                mapping_scope="partial",
                mastg_tests=[],
                maswe=list(weaknesses_for(rule)),
            )
        )

    def is_webview(self, node: Any, frame: Frame) -> bool:
        value = self.value(node, frame)
        return bool(re.search(r"\b(?:WebView|WKWebView|UIWebView)\b", value.type_name))

    def risky_checks(self, conditions: list[Any], traces: tuple[Trace, ...], frame: Frame) -> list[Call]:
        origins = {trace.origin for trace in traces}
        results = []
        for condition in conditions:
            for node in _walk(condition):
                call = self.call(node)
                if (
                    not call
                    or call.name not in {"startsWith", "endsWith", "contains", "hasPrefix", "hasSuffix"}
                    or len(call.args) != 1
                ):
                    continue
                receiver = self.value(call.receiver, frame)
                literal = self.literal(call.args[0])
                if not literal or not origins.intersection(trace.origin for trace in receiver.traces):
                    continue
                if (
                    call.name in {"endsWith", "hasSuffix"}
                    and receiver.category == "host"
                    and literal.startswith(".")
                    and self.hostname(literal[1:])
                ):
                    continue
                results.append(call)
        return results

    def navigation_policy(self, condition: Any, branch: Any, frame: Frame) -> None:
        android_callback = self.scope == "shouldOverrideUrlLoading" and any(
            "WebView" in value for value in self.parameter_types.values()
        )
        ios_callback = self.scope == "webView" and any(
            "WKNavigationAction" in value for value in self.parameter_types.values()
        )
        if not condition or not branch or not (android_callback or ios_callback):
            return
        allowed = None
        for node in _walk(branch, descend_functions=False):
            if (
                android_callback
                and node.type in {"return_statement", "return_expression"}
                and re.fullmatch(r"return\s+false\s*;?", self.text(node).strip())
            ):
                allowed = node
                break
            call = self.call(node)
            if (
                ios_callback
                and call
                and call.name in self.parameter_types
                and "WKNavigationActionPolicy" in self.parameter_types[call.name]
                and call.args
                and self.text(call.args[0]).strip() == ".allow"
            ):
                allowed = node
                break
        if allowed is None:
            return
        receivers = []
        for node in _walk(condition):
            call = self.call(node)
            if call:
                receivers.append(self.value(call.receiver, frame))
        value = _union(receivers)
        for check in self.risky_checks([condition], value.traces, frame):
            self.emit(
                "AST-WEBVIEW-HOST-ALLOWLIST",
                check.node,
                traces=self.value(check.receiver, frame).traces,
                sink="WebView navigation policy allow decision",
                allowlist_operation=check.name,
                load_location=self.location(allowed),
                validation={
                    "policy_branch": "contains an explicit allow decision",
                    "callback_reachability": "not-proven",
                },
            )

    def check_call(
        self, call: Call, frame: Frame, guards: dict[int, set[str]], conditions: list[Any]
    ) -> None:
        receiver_key = self.key(call.receiver)
        self.check_security_call(call, frame)
        if call.name == "proceed" and self.scope == "onReceivedSslError":
            if "SslErrorHandler" in self.value(call.receiver, frame).type_name:
                self.emit(
                    "AST-WEBVIEW-SSL-BYPASS", call.node, sink="SslErrorHandler.proceed", callback=self.scope
                )
        if call.name == "proceed" and receiver_key.lower() in {"handler", "sslerrorhandler"}:
            receiver_type = self.value(call.receiver, frame).type_name
            if receiver_type in self.safe_local_types:
                self.pattern_exclusions.setdefault("WEBVIEW-SSL-BYPASS", set()).add(
                    (call.node.start_byte, call.node.end_byte)
                )
        if call.name == "addJavascriptInterface" and self.is_webview(call.receiver, frame):
            bridge_name = self.literal(call.args[1]) if len(call.args) > 1 else None
            frame.bridges[(receiver_key, bridge_name)] = call
        elif call.name == "removeJavascriptInterface" and self.is_webview(call.receiver, frame) and call.args:
            bridge_name = self.literal(call.args[0])
            if bridge_name is not None:
                frame.bridges.pop((receiver_key, bridge_name), None)
        elif call.name == "setJavaScriptEnabled" and call.args:
            settings = self.call(call.receiver) if call.receiver else None
            if settings and settings.name == "getSettings" and self.is_webview(settings.receiver, frame):
                frame.javascript[self.key(settings.receiver)] = self.text(call.args[0])
        declared = self.spec_entry("sink", call, frame)
        if declared and len(call.args) > declared["argument"]:
            value = self.value(call.args[declared["argument"]], frame)
            unsafe = tuple(
                trace
                for trace in value.traces
                if declared["kind"] == "sql" or guards.get(trace.origin, set()) != {"scheme", "host"}
            )
            if unsafe:
                self.emit(
                    SINK_KINDS[declared["kind"]],
                    call.node,
                    traces=unsafe,
                    sink=f"{call.name} (project specification sink {declared['id']})",
                    project_specification={"id": declared["id"], "kind": declared["kind"]},
                    unknown_helpers_are_sanitizers=False,
                )
        sink_names = {
            "loadUrl",
            "loadData",
            "loadDataWithBaseURL",
            "evaluateJavascript",
            "evaluateJavaScript",
            "load",
            "loadHTMLString",
        }
        if call.name not in sink_names or not self.is_webview(call.receiver, frame) or not call.args:
            return
        args = call.args[:2] if call.name == "loadDataWithBaseURL" else call.args[:1]
        value = _union([self.value(arg, frame) for arg in args])
        if not value.traces:
            return
        javascript_sink = call.name.lower().startswith("evaluatejava")
        unsafe = tuple(
            trace
            for trace in value.traces
            if javascript_sink or guards.get(trace.origin, set()) != {"scheme", "host"}
        )
        validation = {
            "recognized_guard": not bool(unsafe),
            "checks": sorted(set().union(*(guards.get(trace.origin, set()) for trace in value.traces))),
            "unknown_calls_are_sanitizers": False,
        }
        if unsafe:
            self.emit(
                "AST-WEBVIEW-UNTRUSTED-URL",
                call.node,
                traces=unsafe,
                sink=call.name,
                receiver=receiver_key,
                validation=validation,
                payload="javascript" if javascript_sink else "url-or-html",
            )
        for check in self.risky_checks(conditions, value.traces, frame):
            self.emit(
                "AST-WEBVIEW-HOST-ALLOWLIST",
                check.node,
                traces=value.traces,
                sink=call.name,
                load_location=self.location(call.node),
                allowlist_operation=check.name,
                validation=validation,
            )
        if unsafe and not javascript_sink:
            for (receiver, _), bridge in frame.bridges.items():
                if receiver == receiver_key:
                    self.emit(
                        "AST-WEBVIEW-JS-BRIDGE",
                        bridge.node,
                        traces=unsafe,
                        sink=call.name,
                        load_location=self.location(call.node),
                        receiver=receiver_key,
                        javascript_enabled=frame.javascript.get(
                            receiver_key, "not-observed-in-this-function"
                        ),
                        bridge_scope="same receiver and function; interface removal checked for literal names",
                    )

    def framework_receiver(self, call: Call, frame: Frame, qualified: str) -> bool:
        receiver = self.key(call.receiver)
        simple = qualified.rsplit(".", 1)[-1]
        if receiver.split(".")[0] in frame.values or receiver in frame.types or receiver in self.field_types:
            return False
        if receiver == qualified:
            return True
        return receiver == simple and qualified in self.imports and simple not in self.class_names

    def check_security_call(self, call: Call, frame: Frame) -> None:
        if call.name == "getInstance" and call.args:
            algorithm = self.literal(call.args[0])
            if algorithm:
                if self.framework_receiver(call, frame, "javax.crypto.Cipher") and re.fullmatch(
                    r"AES/ECB/[^/]+", algorithm, re.I
                ):
                    self.emit(
                        "AST-CRYPTO-ECB", call.node, algorithm=algorithm, constant_scope="literal argument"
                    )
                if self.framework_receiver(
                    call, frame, "java.security.MessageDigest"
                ) and algorithm.upper() in {"MD5", "SHA-1", "SHA1"}:
                    self.emit(
                        "AST-CRYPTO-WEAK-HASH", call.node, algorithm=algorithm, security_purpose="unverified"
                    )
        if self.language in {"java", "kotlin"} and call.args:
            receiver_type = self.value(call.receiver, frame).type_name
            for (qualified, method), index in SQL_SINKS.items():
                simple = qualified.rsplit(".", 1)[-1]
                sdk_type = receiver_type == qualified or (
                    receiver_type == simple and qualified in self.imports and simple not in self.class_names
                )
                if call.name != method or not sdk_type:
                    continue
                if method == "query" and call.args and self.text(call.args[0]) in {"true", "false"}:
                    index = 3  # query(distinct, table, columns, selection, ...)
                if len(call.args) <= index:
                    continue
                query = self.value(call.args[index], frame)
                if query.traces:
                    self.emit(
                        "AST-SQL-CONCAT",
                        call.node,
                        traces=query.traces,
                        # sink is part of the finding identity; 1.3 used the bare method name.
                        sink=call.name,
                        sink_api=f"{simple}.{method}",
                        statement_scope=f"argument {index} is SQL syntax; bound value arguments are not",
                        unknown_helpers_are_sanitizers=False,
                    )
        if (
            self.language in {"java", "kotlin"}
            and call.name
            in {"getActivity", "getActivities", "getBroadcast", "getService", "getForegroundService"}
            and self.key(call.receiver) in {"PendingIntent", "android.app.PendingIntent"}
            and len(call.args) >= 4
            and (mutability := self.pending_intent_mutability(call.args[3]))
        ):
            wrapped, basis = self.intent_expression(call.args[2], call.node)
            explicit = re.search(
                r"::class|\.class\b|setClass|setComponent|setPackage|ComponentName|\b(?:component|`?package`?)\s*=",
                wrapped,
            )
            # Default mutability on an Intent of unknown origin (a parameter, a field) is too weak
            # to report: helpers commonly pass explicit Intents with FLAG_UPDATE_CURRENT.
            if not explicit and not (mutability != "FLAG_MUTABLE" and basis == UNKNOWN_INTENT):
                self.emit(
                    "AST-PENDINGINTENT-MUTABLE",
                    call.node,
                    factory=f"PendingIntent.{call.name}",
                    intent_argument=basis,
                    mutability=mutability,
                    target_sdk_note="Android 14+ rejects mutable implicit PendingIntents for targetSdk 34+"
                    if mutability == "FLAG_MUTABLE"
                    else "Mutable on Android 11 and lower; with targetSdk 31+ creation throws on Android 12+",
                )
        logging = (self.key(call.receiver) == "Log" and call.name in {"d", "i", "v", "e", "w"}) or (
            call.receiver is None and call.name in {"print", "println", "NSLog"}
        )
        literals = [self.literal(argument) for argument in call.args]
        # Only literal arguments can establish that the redacted value is all
        # that gets logged. Dynamic values and throwable arguments retain alerts.
        if logging and literals and all(value is not None and "$" not in value for value in literals):
            sensitive = r"password|passwd|token|secret|authorization|credential|email|session"
            redacted = re.compile(rf"(?:[\w -]*(?:{sensitive})[\w -]*\s*[:=]\s*)?\[REDACTED\]", re.I)
            messages = [value for value in literals if value is not None]
            # Android Log's first argument is a tag, not the payload. A
            # redaction marker in a tag cannot establish that its message is safe.
            payload_is_redacted = (
                len(messages) == 2
                and self.key(call.receiver) == "Log"
                and redacted.fullmatch(messages[1])
                and not re.search(sensitive, messages[0], re.I)
            ) or (len(messages) == 1 and call.receiver is None and redacted.fullmatch(messages[0]))
            if payload_is_redacted:
                self.pattern_exclusions.setdefault("STORAGE-SENSITIVE-LOG", set()).add(
                    (call.node.start_byte, call.node.end_byte)
                )

    def visit(self, node: Any, frame: Frame, guards: dict[int, set[str]], conditions: list[Any]) -> None:
        if node.type in COMMENTS or node.type in FUNCTIONS:
            return
        if node.type in STRINGS:
            for part in node.named_children:
                if "interpolat" in part.type:
                    self.visit(part, frame, guards, conditions)
            return
        declaration = self.declaration(node)
        if declaration:
            name, expression, type_name = declaration
            if expression:
                self.visit(expression, frame, guards, conditions)
            value = self.value(expression, frame).bind(node)
            frame.values[name] = Value(value.traces, value.category, type_name or value.type_name)
            if type_name:
                frame.types[name] = type_name
            return
        if node.type in {"assignment_expression", "assignment", "directly_assignable_expression"}:
            left = _field(node, "left") or next(iter(node.named_children), None)
            right = _field(node, "right") or (
                node.named_children[-1] if len(node.named_children) > 1 else None
            )
            if left and right and left != right:
                self.visit(right, frame, guards, conditions)
                key = self.key(left)
                value = self.value(right, frame).bind(node)
                if key in frame.types or key in frame.values:
                    frame.values[key] = Value(
                        value.traces, value.category, frame.types.get(key, value.type_name)
                    )
                return
        if node.type in {"if_statement", "if_expression"}:
            condition = _field(node, "condition")
            if condition:
                self.visit(condition, frame, guards, conditions)
            children = [child for child in node.named_children if child != condition]
            then_node = _field(node, "consequence") or (children[0] if children else None)
            else_node = _field(node, "alternative") or (children[1] if len(children) > 1 else None)
            self.navigation_policy(condition, then_node, frame)
            positive = {origin: checks.copy() for origin, checks in guards.items()}
            for origin, checks in self.constraints(condition, frame).items():
                positive.setdefault(origin, set()).update(checks)
            before = frame.copy()
            branch = frame.copy()
            if then_node:
                self.visit(then_node, branch, positive, [*conditions, condition] if condition else conditions)
            alternative = before.copy()
            if else_node:
                self.visit(else_node, alternative, guards, conditions)
            # Conservatively retain both possible assignments after a branch. Do not apply its guard outside it.
            for key in before.values:
                values = [
                    branch.values.get(key, before.values[key]),
                    alternative.values.get(key, before.values[key]),
                ]
                frame.values[key] = _union(
                    values,
                    values[0].category if values[0].category == values[1].category else "unknown",
                    type_name=before.values[key].type_name,
                )
            frame.bridges.update(branch.bridges)
            frame.bridges.update(alternative.bridges)
            return
        if node.type == "guard_statement" and self.language == "swift":
            # The continuation is guarded only when the else body exits the function.
            bodies = [part for part in node.named_children if part.type == "statements"]
            exits = bodies and any(
                part.type == "control_transfer_statement" and self.text(part).startswith(("return", "throw"))
                for part in bodies[0].named_children
            )
            for condition in _fields(node, "condition"):
                self.visit(condition, frame, guards, conditions)
                if exits:
                    for origin, checks in self.constraints(condition, frame).items():
                        guards.setdefault(origin, set()).update(checks)
                    conditions.append(condition)
            return
        if node.type in BLOCKS:
            local = frame.copy()
            local_guards = {origin: checks.copy() for origin, checks in guards.items()}
            local_conditions = conditions.copy()
            declared = set()
            for child in node.named_children:
                declarations = child.named_children if child.type == "local_variable_declaration" else [child]
                for declaration_node in declarations:
                    declaration = self.declaration(declaration_node)
                    if declaration:
                        declared.add(declaration[0])
                self.visit(child, local, local_guards, local_conditions)
            for key in frame.values:
                if key not in declared:
                    frame.values[key] = local.values[key]
            frame.bridges = local.bridges
            frame.javascript = local.javascript
            return
        call = self.call(node)
        if call:
            if call.receiver:
                self.visit(call.receiver, frame, guards, conditions)
            for arg in call.args:
                self.visit(arg, frame, guards, conditions)
            self.check_call(call, frame, guards, conditions)
            return
        for child in node.named_children:
            self.visit(child, frame, guards, conditions)

    def parameters(self, function: Any) -> list[tuple[str, str, Any]]:
        parameters = _field(function, "parameters") or next(
            (node for node in function.named_children if node.type == "function_value_parameters"), None
        )
        nodes = (
            parameters.named_children
            if parameters
            else [node for node in function.named_children if node.type == "parameter"]
        )
        result = []
        for node in nodes:
            if self.language == "java":
                name, type_node = _field(node, "name"), _field(node, "type")
            else:
                name = next(
                    (
                        part
                        for part in node.named_children
                        if part.type in IDENTIFIERS
                        and node.field_name_for_child(node.children.index(part)) != "external_name"
                    ),
                    None,
                )
                type_node = next(
                    (
                        part
                        for part in node.named_children
                        if part.type in {"user_type", "nullable_type", "dictionary_type", "function_type"}
                    ),
                    None,
                )
            if name:
                result.append((self.text(name), self.text(type_node), node))
        return result

    def class_fields(self, function: Any) -> dict[str, str]:
        parent = function.parent
        while parent and parent.type not in {"class_body", "enum_body"}:
            parent = parent.parent
        fields = {}
        if parent:
            for declaration in parent.named_children:
                if declaration.type not in {"field_declaration", "property_declaration"}:
                    continue
                nodes = (
                    declaration.named_children if declaration.type == "field_declaration" else [declaration]
                )
                for node in nodes:
                    parsed = self.declaration(node)
                    if parsed:
                        name, expression, type_name = parsed
                        value = self.value(expression, Frame())
                        fields[name] = type_name or value.type_name
        return fields

    def analyze(self, root: Any) -> None:
        for node in _walk(root):
            if node.type in {"import_declaration", "import_header", "import"}:
                self.imports.add(re.sub(r"^import\s+|;\s*$", "", self.text(node)).strip())
            if node.type == "class_declaration":
                name = self.text(_field(node, "name"))
                self.class_names.add(name)
                if (
                    name
                    and not any(
                        part.type in {"superclass", "super_interfaces", "delegation_specifiers"}
                        for part in node.named_children
                    )
                    and not node.has_error
                ):
                    self.safe_local_types.add(name)
            if node.type in FUNCTIONS:
                self.defined_functions.add(self.text(_field(node, "name")))
        for function in _walk(root):
            if function.type not in FUNCTIONS:
                continue
            self.function_counts["observed"] += 1
            parent = function.parent
            uncertain = function.has_error
            while parent:
                uncertain = uncertain or parent.type == "ERROR"
                parent = parent.parent
            if uncertain:
                self.function_counts["skipped"] += 1
                continue
            name = _field(function, "name")
            self.scope = self.text(name)
            self.field_types = self.class_fields(function)
            enclosing = function.parent
            while enclosing and enclosing.type != "class_declaration":
                enclosing = enclosing.parent
            bases = (
                [
                    part
                    for part in enclosing.named_children
                    if part.type in {"superclass", "delegation_specifiers"}
                ]
                if enclosing
                else []
            )
            self.activity_scope = any(
                re.search(
                    r"\b(?:Activity|AppCompatActivity|ComponentActivity|FragmentActivity)\b", self.text(base)
                )
                for base in bases
            )
            provider_scope = (
                self.language in {"java", "kotlin"}
                and enclosing is not None
                and self.text(_field(enclosing, "name")) in self.exposed_providers
                and any(re.search(r"\bContentProvider\b", self.text(base)) for base in bases)
            )
            parameters = self.parameters(function)
            self.parameter_types = {name: type_name for name, type_name, _ in parameters}
            frame = Frame(types=self.parameter_types.copy())
            for name, type_name, node in parameters:
                category = None
                description = ""
                if re.search(r"\bIntent\b", type_name):
                    category, description = "intent", "Intent parameter (external origin requires validation)"
                elif "WebResourceRequest" in type_name:
                    category, description = "request", "WebView navigation request parameter"
                elif "WKNavigationAction" in type_name:
                    category, description = "navigation", "WKWebView navigation action parameter"
                elif "UIOpenURLContext" in type_name:
                    category, description = "url-context", "iOS scene URL context parameter"
                elif (
                    provider_scope
                    and self.scope in PROVIDER_METHODS
                    and re.search(r"\b(?:String|Uri)\b", type_name)
                ):
                    category = "url" if re.search(r"\bUri\b", type_name) else "text"
                    description = "ContentProvider caller-supplied argument"
                elif self.scope == "shouldOverrideUrlLoading" and re.search(r"\bString\b", type_name):
                    category, description = "text", "WebView navigation URL parameter"
                elif (
                    self.language == "swift"
                    and self.scope in {"application", "scene"}
                    and re.search(r"\bURL\b", type_name)
                ):
                    category, description = "url", "iOS application URL callback parameter"
                if category:
                    value = self.source(node, description, category)
                    frame.values[name] = Value(value.traces, value.category, type_name)
            body = _field(function, "body") or next(
                (node for node in function.named_children if node.type == "function_body"), None
            )
            if body:
                self.function_counts["analyzed"] += 1
                # Primitive selection needs no closure dataflow model. Inspect
                # Swift trailing closures syntactically without blessing guards.
                if self.language == "swift" and "CommonCrypto" in self.imports:
                    for node in _walk(body, descend_functions=False):
                        call = self.call(node)
                        if (
                            call
                            and call.name in {"CC_MD5", "CC_SHA1"}
                            and call.receiver is None
                            and call.name not in self.defined_functions
                        ):
                            self.emit(
                                "AST-CRYPTO-WEAK-HASH",
                                node,
                                algorithm=call.name,
                                security_purpose="unverified",
                            )
                self.visit(body, frame, {}, [])
            else:
                self.function_counts["without_body"] += 1


def analyze_sources(
    sources: list[Any],
    specs: dict | None = None,
    exposed_providers: set[str] | None = None,
    android_levels: dict | None = None,
) -> dict:
    """Return candidate findings, explicit partial coverage, and parser warnings.

    ``sources`` accepts the inventory loader's ``(path, text)`` tuples or the
    equivalent ``{"path": ..., "text": ...}`` records. Parsers import only local
    compiled grammar modules; this function never performs network requests.
    """
    parsers: dict[str, Any] = {}
    unavailable: dict[str, str] = {}
    findings: list[dict] = []
    warnings: list[str] = []
    parsed = skipped = total = 0
    seen_languages: set[str] = set()
    unsupported: set[str] = set()
    pattern_exclusions: dict[str, dict[str, list[dict[str, int]]]] = {}
    file_metrics = []
    function_totals = {"observed": 0, "analyzed": 0, "skipped": 0, "without_body": 0}
    normalized_files = 0
    remaining_records = 0
    for source_index, source in enumerate(sources):
        if isinstance(source, dict):
            path, text = source.get("path"), source.get("text")
        elif isinstance(source, (tuple, list)) and len(source) == 2:
            path, text = source
        else:
            warnings.append("AST source record skipped: expected a path/text record or pair.")
            skipped += 1
            continue
        if not isinstance(path, str) or not isinstance(text, str):
            warnings.append("AST source record skipped: path and text must be strings.")
            skipped += 1
            continue
        suffix = PurePath(path).suffix.lower()
        language = LANGUAGES.get(suffix)
        if not language:
            if suffix in UNSUPPORTED_SOURCE:
                unsupported.add(suffix)
                skipped += 1
            continue
        seen_languages.add(language)
        metric = {"path": path, "language": language, "state": "skipped", "functions": None}
        file_metrics.append(metric)
        size = len(text.encode("utf-8"))
        if size > MAX_AST_BYTES or total + size > MAX_AST_TOTAL:
            metric["reason"] = "parser byte budget exceeded"
            warnings.append(f"AST analysis skipped {path}: parser byte budget exceeded.")
            skipped += 1
            continue
        total += size
        if language not in parsers and language not in unavailable:
            try:
                tree_sitter = importlib.import_module("tree_sitter")
                grammar = importlib.import_module(f"tree_sitter_{language}")
                parser = tree_sitter.Parser(tree_sitter.Language(grammar.language()))
                # Keep the tested native timeout until the pinned binding's progress callback is safe.
                # Calls are additionally isolated by the audit parser worker.
                with python_warnings.catch_warnings(action="ignore", category=DeprecationWarning):
                    parser.timeout_micros = 250_000
                parsers[language] = parser
            except (ImportError, AttributeError, ValueError) as error:
                unavailable[language] = type(error).__name__
        if language in unavailable:
            metric["reason"] = "grammar unavailable: " + unavailable[language]
            skipped += 1
            continue
        try:
            tree = parsers[language].parse(text.encode("utf-8"))
            if tree is None:
                raise ValueError("native parser deadline exceeded")
            nodes = []
            for count, _node in enumerate(_walk(tree.root_node), 1):
                if count > MAX_AST_NODES:
                    raise ValueError("AST node budget exceeded")
                nodes.append(_node)
            metric["native_functions"] = {
                "observed": sum(n.type in FUNCTIONS for n in nodes),
                "with_errors": sum(n.type in FUNCTIONS and n.has_error for n in nodes),
            }
            metric["native_parse_errors"] = tree.root_node.has_error
            adaptations = []
            dropped: list[list[int]] = []
            if tree.root_node.has_error:
                from .parser_compat import adapted_source

                compatible, adaptations = adapted_source(text.encode("utf-8"), language, nodes)
                for adaptation in adaptations:
                    # Spans are for the analyzer only; the report keeps edit counts.
                    dropped.extend(adaptation.pop("spans", []))
                if adaptations:
                    parsers[language].reset()
                    tree = parsers[language].parse(compatible)
                    if tree is None:
                        raise ValueError("compatibility parser deadline exceeded")
                    for count, _node in enumerate(_walk(tree.root_node), 1):
                        if count > MAX_AST_NODES:
                            raise ValueError("compatibility AST node budget exceeded")
                    normalized_files += 1
                    warnings.append(
                        f"AST parser compatibility in {path}: {adaptations}; source remains partial."
                    )
            metric["adaptations"] = adaptations
            metric["parse_errors"] = tree.root_node.has_error
            if tree.root_node.has_error:
                warnings.append(
                    f"AST syntax recovery in {path}: functions containing parse errors were skipped."
                )
                skipped += 1
            elif adaptations:
                skipped += 1
            if language == "objc":
                from .objc_analysis import ObjCAnalyzer

                analyzer = ObjCAnalyzer(path, text, uncertain_spans=dropped)
                skipped += 1  # Preprocessing, dynamic dispatch and unsupported flows remain partial.
                metric["state"] = "partial"
            else:
                analyzer = Analyzer(path, text, language, specs, exposed_providers, android_levels)
            analyzer.analyze(tree.root_node)
            metric["state"] = "partial" if tree.root_node.has_error or adaptations else "checked"
            if language == "objc":
                metric["state"] = "partial"
            metric["functions"] = analyzer.function_counts
            for name, value in analyzer.function_counts.items():
                function_totals[name] += value
            findings.extend(analyzer.findings)
            if not tree.root_node.has_error and not adaptations and language != "objc":
                pattern_exclusions[path] = {
                    rule: [{"start": start, "end": end} for start, end in sorted(offsets)]
                    for rule, offsets in analyzer.pattern_exclusions.items()
                }
            parsed += 1
            if len(findings) >= MAX_AST_FINDINGS:
                findings = findings[:MAX_AST_FINDINGS]
                warnings.append("AST finding budget reached; remaining source functions were not checked.")
                skipped += 1
                remaining_records = len(sources) - source_index - 1
                break
        except (ValueError, RecursionError) as error:
            parsers[language].reset()
            warnings.append(f"AST analysis skipped {path}: {error}.")
            metric["reason"] = str(error)
            skipped += 1
    for language, reason in unavailable.items():
        warnings.append(
            f"AST grammar unavailable for {language} ({reason}); install the bundled grammar dependency."
        )
    if unsupported:
        warnings.append(
            f"AST mobile checks do not support these source languages: {', '.join(sorted(unsupported))}."
        )
    state = "partial" if parsed and skipped else "checked" if parsed else "not-run"
    coverage = [
        {
            "rule_id": rule,
            "state": "not-applicable"
            if rule.endswith(("SSL-BYPASS", "JS-BRIDGE", "CRYPTO-ECB", "SQL-CONCAT", "PENDINGINTENT-MUTABLE"))
            and seen_languages == {"swift"}
            and not unsupported
            else state,
            "method": "source-ast-local-flow",
            "mapping_scope": "partial",
            "languages": sorted(seen_languages),
            "unsupported_languages": sorted(unsupported),
            "parsed_files": parsed,
            "skipped_files": skipped,
            "functions_observed": function_totals["observed"],
            "functions_analyzed": function_totals["analyzed"],
            "functions_skipped": function_totals["skipped"],
            "functions_without_body": function_totals["without_body"],
            "function_inventory_complete": bool(parsed) and not skipped,
            "normalized_files": normalized_files,
            "note": LIMITS_NOTE
            + (
                " Native interface check currently covers Android addJavascriptInterface."
                if rule.endswith("JS-BRIDGE")
                else ""
            ),
        }
        for rule in RULES
    ]
    if "objc" in seen_languages:
        from .objc_analysis import RULES as OBJC_RULES

        coverage.extend(
            {
                "rule_id": rule,
                "state": "partial"
                if any(f["language"] == "objc" and f["functions"] is not None for f in file_metrics)
                else "not-run",
                "method": "objc-cst-local-flow",
                "mapping_scope": "partial",
                "note": "Known WebKit declared types and straight-line request flow; CommonCrypto direct calls. No preprocessing, ObjC++/dispatch/swizzling, interprocedural flow, guard or runtime proof.",
            }
            for rule in OBJC_RULES
        )
    return {
        "findings": list({item["id"]: item for item in findings}.values()),
        "coverage": coverage,
        "warnings": warnings,
        "pattern_exclusions": pattern_exclusions,
        "metadata": {
            "files": file_metrics,
            "functions": function_totals,
            "function_inventory_complete": bool(parsed) and not skipped,
            "remaining_source_records": remaining_records,
            "note": "Counts cover recognized AST function declarations only; errors, unsupported languages and budgets can hide additional functions. Adaptations retain original evidence offsets and remain partial. Closures and initializers are not a complete callable inventory.",
        },
    }
