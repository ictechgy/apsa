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
from bisect import bisect_left, bisect_right
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
# Framework flag values a PendingIntent flags expression may contain. Intent activity flags
# share bits with PendingIntent flags (FLAG_ACTIVITY_CLEAR_TOP is FLAG_IMMUTABLE's bit), so
# mutability is decided by value, not by name.
PENDING_INTENT_IMMUTABLE = 0x04000000
PENDING_INTENT_MUTABLE = 0x02000000
FRAMEWORK_FLAG_VALUES = {
    "PendingIntent": {
        "FLAG_ONE_SHOT": 0x40000000,
        "FLAG_NO_CREATE": 0x20000000,
        "FLAG_CANCEL_CURRENT": 0x10000000,
        "FLAG_UPDATE_CURRENT": 0x08000000,
        "FLAG_IMMUTABLE": PENDING_INTENT_IMMUTABLE,
        "FLAG_MUTABLE": PENDING_INTENT_MUTABLE,
        "FLAG_ALLOW_UNSAFE_IMPLICIT_INTENT": 0x01000000,
    },
    "Intent": {
        "FLAG_ACTIVITY_NO_HISTORY": 0x40000000,
        "FLAG_ACTIVITY_SINGLE_TOP": 0x20000000,
        "FLAG_ACTIVITY_NEW_TASK": 0x10000000,
        "FLAG_ACTIVITY_MULTIPLE_TASK": 0x08000000,
        "FLAG_ACTIVITY_CLEAR_TOP": 0x04000000,
        "FLAG_ACTIVITY_FORWARD_RESULT": 0x02000000,
        "FLAG_ACTIVITY_PREVIOUS_IS_TOP": 0x01000000,
        "FLAG_ACTIVITY_EXCLUDE_FROM_RECENTS": 0x00800000,
        "FLAG_ACTIVITY_BROUGHT_TO_FRONT": 0x00400000,
        "FLAG_ACTIVITY_RESET_TASK_IF_NEEDED": 0x00200000,
        "FLAG_ACTIVITY_LAUNCHED_FROM_HISTORY": 0x00100000,
        "FLAG_ACTIVITY_NEW_DOCUMENT": 0x00080000,
        "FLAG_ACTIVITY_NO_USER_ACTION": 0x00040000,
        "FLAG_ACTIVITY_REORDER_TO_FRONT": 0x00020000,
        "FLAG_ACTIVITY_NO_ANIMATION": 0x00010000,
        "FLAG_ACTIVITY_CLEAR_TASK": 0x00008000,
        "FLAG_ACTIVITY_TASK_ON_HOME": 0x00004000,
    },
}
FRAMEWORK_FLAG = re.compile(
    r"(?:(?:android\.app\.)?(PendingIntent)\.|(?:android\.content\.)?(Intent)\.)?(FLAG_[A-Z_]+)"
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
        "AES in ECB mode is selected",
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
    "AST-CRYPTO-WEAK-CIPHER": (
        "A broken cipher algorithm is selected",
        "high",
        "Use AES-GCM or ChaCha20-Poly1305 with keys from the Android Keystore. Do not use DES, 3DES, "
        "RC4, RC2 or Blowfish.",
        "https://developer.android.com/privacy-and-security/risks/broken-cryptographic-algorithm",
    ),
    "AST-CRYPTO-HARDCODED-KEY": (
        "Cryptographic key material comes from a constant in the app",
        "high",
        "Generate keys at runtime in the Android Keystore or the iOS Keychain or Secure Enclave, or fetch "
        "per-user keys from a server. Key material shipped in the app can be extracted.",
        "https://developer.android.com/privacy-and-security/risks/hardcoded-cryptographic-secrets",
    ),
    "AST-CRYPTO-STATIC-IV": (
        "A constant IV or nonce is used for encryption",
        "medium",
        "Generate a new random IV or nonce for every encryption (or let the cipher choose one) and store "
        "it with the ciphertext.",
        CRYPTO_REFERENCE,
    ),
    "AST-INTENT-REDIRECTION": (
        "An Intent taken from another Intent's extras is launched",
        "high",
        "Do not launch Intents received from other apps. If forwarding is required, check the nested "
        "Intent's component and package against an allowlist and drop URI permission grant flags first.",
        "https://developer.android.com/privacy-and-security/risks/intent-redirection",
    ),
    "AST-IMPLICIT-INTENT": (
        "An implicit Intent with an app-defined action is sent",
        "medium",
        "Make internal Intents explicit (setPackage, setClass or a component), protect broadcasts with a "
        "signature permission, and keep sensitive extras out of implicit Intents.",
        "https://developer.android.com/privacy-and-security/risks/implicit-intent-hijacking",
    ),
    "AST-PATH-TRAVERSAL": (
        "An externally controlled name reaches a file path",
        "high",
        "Reduce untrusted names to a basename (File(name).name, lastPathComponent) or generate file names, "
        "and check that the canonical path stays inside the intended directory before use.",
        "https://developer.android.com/privacy-and-security/risks/path-traversal",
    ),
}
# Android-only structural rules; a Swift-only project does not apply them.
ANDROID_ONLY = (
    "SSL-BYPASS",
    "JS-BRIDGE",
    "CRYPTO-ECB",
    "SQL-CONCAT",
    "PENDINGINTENT-MUTABLE",
    "CRYPTO-WEAK-CIPHER",
    "INTENT-REDIRECTION",
    "IMPLICIT-INTENT",
)
BROKEN_CIPHERS = {"DES", "DESEDE", "TRIPLEDES", "3DES", "RC4", "ARCFOUR", "RC2", "BLOWFISH"}
# Constructors whose argument is key material or an IV/nonce: name -> (rule, argument index or label).
KEY_SINKS = {
    "SecretKeySpec": ("AST-CRYPTO-HARDCODED-KEY", 0),
    "DESKeySpec": ("AST-CRYPTO-HARDCODED-KEY", 0),
    "DESedeKeySpec": ("AST-CRYPTO-HARDCODED-KEY", 0),
    "PBEKeySpec": ("AST-CRYPTO-HARDCODED-KEY", 0),
    "IvParameterSpec": ("AST-CRYPTO-STATIC-IV", 0),
    "GCMParameterSpec": ("AST-CRYPTO-STATIC-IV", 1),
    "SymmetricKey": ("AST-CRYPTO-HARDCODED-KEY", "data"),
    "PrivateKey": ("AST-CRYPTO-HARDCODED-KEY", None),
    "SecKeyCreateWithData": ("AST-CRYPTO-HARDCODED-KEY", 0),
    "Nonce": ("AST-CRYPTO-STATIC-IV", "data"),
}
# Conversions that keep a constant constant; decoders and byte builders of literal text.
CONSTANT_CONVERSIONS = {
    "toByteArray",
    "getBytes",
    "encodeToByteArray",
    "toCharArray",
    "data",
    "utf8",
    "decode",
    "decodeHex",
    "fromHex",
    "hexToBytes",
    "hexStringToByteArray",
    "byteArrayOf",
    "ubyteArrayOf",
    "intArrayOf",
    "charArrayOf",
    "arrayOf",
    "Data",
    "Array",
    "copyOf",
    "toUByteArray",
}
# Methods that read a value without changing it; any other call taking a constant may fill it.
PURE_METHODS = CONSTANT_CONVERSIONS | {
    "size",
    "count",
    "length",
    "isEmpty",
    "contentEquals",
    "equals",
    "toString",
    "hashCode",
    "base64EncodedString",
    "withUnsafeBytes",
    "map",
    "encodeToString",
    "encode",
    "joinToString",
    "contentToString",
    "print",
    "println",
    "NSLog",
}
# Implicit service Intents throw on API 21+, so only activities and broadcasts can be hijacked.
IMPLICIT_LAUNCHERS = {
    "startActivity",
    "startActivityForResult",
    "startActivityIfNeeded",
    "sendBroadcast",
    "sendOrderedBroadcast",
    "sendStickyBroadcast",
}
INTENT_LAUNCHERS = {
    "startActivity",
    "startActivityForResult",
    "startActivityIfNeeded",
    "startService",
    "startForegroundService",
    "bindService",
    "sendBroadcast",
    "sendOrderedBroadcast",
    "sendStickyBroadcast",
}
NESTED_INTENT = "Intent extra (an Intent supplied by the sender)"
BASENAME = " (reduced to a file name)"
SCOPE_FUNCTIONS = {"use", "let", "also", "apply", "run", "with"}
ENTRY_ITERATORS = {
    "nextEntry",
    "getNextEntry",
    "nextZipEntry",
    "getNextZipEntry",
    "nextJarEntry",
    "getNextJarEntry",
}
NESTED_INTENT_GETTERS = {"getParcelableExtra", "getParcelable"}
# Path containment checks: a canonical or normalized path compared by prefix, or a ".." test.
CANONICAL_PATHS = (
    "canonicalPath",
    "getCanonicalPath",
    "canonicalFile",
    "getCanonicalFile",
    "toRealPath",
    "normalize(",
    "standardizedFileURL",
    "resolvingSymlinksInPath",
    "standardized",
)
ARCHIVE_ENTRY = re.compile(
    r"(?:[\w.]*\.)?(?:ZipEntry|JarEntry|ZipArchiveEntry|TarArchiveEntry|ArchiveEntry)\??"
)
FILE_DESCRIPTOR = re.compile(r"(?:\bfileDescriptor|\bgetFileDescriptor\s*\(\s*\)|\.fd)\s*!*$")
ACTION_HINT = re.compile(r'\bIntent\s*\(\s*(?:"|[A-Z_][\w.]*\s*[,)])|\baction\s*=|\bsetAction\s*\(')
MAX_INTENT_CHECKS = 200
LOCAL_LITERAL = re.compile(
    rb'(?:\b(?:val|var|let)\s+(\w+)\b(?:\s*:\s*String\??)?|\bString\s+(\w+))\s*=\s*"([^"\\\n]*)"\s*;?[ \t]*$',
    re.M,
)
LOCAL_ASSIGNMENT = re.compile(rb"(?<![\w.])(\w+)\s*(?:\+=|=(?!=))")
LOCAL_BROADCASTERS = re.compile(
    r"\b(\w+)\b\s*(?::\s*(?:[\w.]*\.)?LocalBroadcastManager\b|=\s*(?:[\w.]*\.)?LocalBroadcastManager\b)"
    r"|\bLocalBroadcastManager\s+(\w+)\b"
)
CONSTANT_SCOPES = {"class_body", "source_file", "program", "enum_body", "enum_class_body", "protocol_body"}
NON_SCALAR_LITERALS = {
    "array_literal",
    "dictionary_literal",
    "collection_literal",
    "lambda_literal",
    "object_literal",
}
FILE_SINKS = {
    "File": "java.io.File",
    "FileOutputStream": "java.io.FileOutputStream",
    "FileInputStream": "java.io.FileInputStream",
    "FileWriter": "java.io.FileWriter",
    "FileReader": "java.io.FileReader",
    "RandomAccessFile": "java.io.RandomAccessFile",
}
LIMITS_NOTE = (
    "Function-scoped local def-use analysis; no method dispatch, interprocedural flow, "
    "component reachability, redirect, or authentication-state proof. Kotlin scope-function lambdas "
    "(let, also, use, apply, run, with) are followed as blocks that may not run; other lambdas and "
    "Swift closures are not analyzed."
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
    # Local names bound to constant key, IV or byte material in this function: name -> description.
    constants: dict[str, str] = field(default_factory=dict)

    def copy(self) -> Frame:
        return Frame(
            self.values.copy(),
            self.types.copy(),
            self.bridges.copy(),
            self.javascript.copy(),
            self.constants.copy(),
        )


# SQL syntax argument per framework method (receiver type, method) -> argument index.
SQL_SINKS = {
    ("android.database.sqlite.SQLiteDatabase", "rawQuery"): (0,),
    ("android.database.sqlite.SQLiteDatabase", "execSQL"): (0,),
    ("android.database.sqlite.SQLiteDatabase", "rawQueryWithFactory"): (1,),
    ("android.database.sqlite.SQLiteDatabase", "compileStatement"): (0,),
    ("android.database.sqlite.SQLiteDatabase", "delete"): (1,),
    ("android.database.sqlite.SQLiteDatabase", "update"): (2,),
    # query(table, columns, selection, args, groupBy, having, orderBy[, limit])
    ("android.database.sqlite.SQLiteDatabase", "query"): (2, 4, 5, 6, 7),
    ("android.database.sqlite.SQLiteQueryBuilder", "appendWhere"): (0,),
    # query(db, projection, selection, args, groupBy, having, sortOrder[, limit])
    ("android.database.sqlite.SQLiteQueryBuilder", "query"): (2, 4, 5, 6, 7),
}
PROVIDER_METHODS = {
    "query",
    "update",
    "delete",
    "insert",
    "call",
    "openFile",
    "openAssetFile",
    "openTypedAssetFile",
}


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
        # Immutable file-level constants (const/static final/let): name -> (description, string value).
        self.constants: dict[str, tuple[str, str | None]] = {}
        self.function: Any = None
        self.function_source = ""
        self.path_guarded: bool | None = None
        self.action_hint: bool | None = None
        self.intent_checks = 0
        # Kotlin lambda parameters bound to the receiver of let/also/use, for Intent text lookups.
        self.aliases: dict[str, Any] = {}
        package = re.search(r"^\s*package\s+([\w.]+)", text, re.M)
        parts = package[1].split(".") if package else []
        # Actions an app defines share its package namespace; other prefixes belong to other apps.
        self.package_prefix = ".".join(parts[: min(3, len(parts))])
        self.broadcaster_names: set[str] | None = None
        self.private_keys: bool | None = None
        self.checked_intents: dict[str, bool] = {}
        self.literal_table: tuple[dict[str, tuple[list[int], list[str]]], dict[str, list[int]]] | None = None
        # Rules whose checks stopped at a budget in this file; their coverage becomes partial.
        self.truncated_rules: set[str] = set()

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

        Only framework flag names with known values, integer literals, or/|/+ and parentheses
        are read, and their bits are combined; a project constant or any other expression is a
        variable and is not followed.
        """
        value = 0
        for token in FLAG_TOKEN.findall(self.text(node)):
            flag = FRAMEWORK_FLAG.fullmatch(token)
            if flag:
                owners = [flag[1] or flag[2]] if flag[1] or flag[2] else list(FRAMEWORK_FLAG_VALUES)
                known = [
                    FRAMEWORK_FLAG_VALUES[o][flag[3]] for o in owners if flag[3] in FRAMEWORK_FLAG_VALUES[o]
                ]
                if not known:
                    return None
                value |= known[0]
            elif re.fullmatch(r"0[xX][0-9A-Fa-f]+|\d+", token):
                value |= int(token, 0) if token[:2].lower() == "0x" else int(token)
            elif token not in {"or", "|", "+", "(", ")"}:
                return None
        if value & PENDING_INTENT_IMMUTABLE:
            # Both bits together is rejected at creation; immutable alone is safe.
            return None
        if value & PENDING_INTENT_MUTABLE:
            return "FLAG_MUTABLE"
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

    def unwrap(self, node: Any) -> Any:
        """The expression inside parentheses, casts, force-unwraps, try and value-argument wrappers."""
        while node is not None:
            if node.type == "value_argument":
                node = _field(node, "value") or (node.named_children[-1] if node.named_children else None)
            elif node.type in {
                "parenthesized_expression",
                "try_expression",
                "as_expression",
                "cast_expression",
            }:
                node = (
                    _field(node, "expr")
                    or _field(node, "value")
                    or next(
                        (
                            part
                            for part in node.named_children
                            if part.type
                            not in {"try_operator", "as_operator", "user_type", "type_identifier"}
                        ),
                        None,
                    )
                )
            elif node.type == "postfix_expression" and self.text(node).rstrip().endswith("!"):
                node = _field(node, "target") or (node.named_children[0] if node.named_children else None)
            else:
                return node
        return None

    def constant(self, node: Any, frame: Frame, depth: int = 0) -> str | None:
        """Describe an expression whose value is fixed in the app (literal key or IV material), else None.

        Literals, literal arrays, zero-filled arrays, immutable constants of this file, BuildConfig fields
        and byte conversions or decoders applied only to such values count. Anything read at runtime does not.
        """
        node = self.unwrap(node)
        if node is None or depth > 8:
            return None
        kind = node.type
        if kind in STRINGS:
            if any("interpolat" in part.type for part in _walk(node)):
                return None
            return "string literal"
        if kind.endswith("_literal") and kind not in NON_SCALAR_LITERALS:
            return "literal"
        if kind in {"array_initializer", "array_literal", "collection_literal"}:
            elements = node.named_children
            if elements and all(self.constant(element, frame, depth + 1) for element in elements):
                return "literal array"
            return None
        if kind == "array_creation_expression":
            initializer = _field(node, "value")
            if initializer is not None:
                return "literal array" if self.constant(initializer, frame, depth + 1) else None
            sizes = [
                part.named_children[0]
                for part in node.named_children
                if part.type == "dimensions_expr" and part.named_children
            ]
            return (
                "zero-filled array"
                if sizes and all(self.constant(size, frame, depth + 1) for size in sizes)
                else None
            )
        if kind in {"prefix_expression", "unary_expression"}:
            operands = node.named_children
            signed = self.text(node).lstrip().startswith(("-", "+"))
            return (
                "literal" if signed and operands and self.constant(operands[-1], frame, depth + 1) else None
            )
        if kind in {"additive_expression", "binary_expression"}:
            parts = node.named_children
            return (
                "string literal"
                if parts and all(self.constant(part, frame, depth + 1) for part in parts)
                else None
            )
        if kind in IDENTIFIERS:
            name = self.text(node)
            if name in frame.constants:
                return frame.constants[name]
            if name not in frame.values and name not in frame.types and name in self.constants:
                return self.constants[name][0]
            return None
        call = self.call(node)
        navigation = self.navigation(node)
        if navigation and call is None:
            base, member = navigation
            owner = self.text(base)
            if owner.split(".")[-1] == "BuildConfig":
                return "BuildConfig field (embedded in the app package)"
            if (
                owner.split(".")[0] in {"Companion", "this", "self", "Self", *self.class_names}
                and member in self.constants
            ):
                return self.constants[member][0]
            if member == "utf8":  # Swift "text".utf8
                return self.constant(base, frame, depth + 1)
            return None
        if call is None:
            return None
        name = call.name.rsplit(".", 1)[-1]
        if re.fullmatch(r"\[\w+\]", name):  # Swift [UInt8](...)
            name = "Array"
        if any(part.type == "annotated_lambda" for part in node.named_children):
            return None  # ByteArray(n) { init } fills values at runtime
        if name in {"ByteArray", "UByteArray", "CharArray"}:
            return (
                "zero-filled array"
                if len(call.args) == 1 and self.constant(call.args[0], frame, depth + 1)
                else None
            )
        if name not in CONSTANT_CONVERSIONS:
            return None
        values = [self.constant(argument, frame, depth + 1) for argument in call.args]
        settings = all(
            value or self.flag_argument(argument) for value, argument in zip(values, call.args, strict=True)
        )
        if not settings:
            return None
        if call.receiver is not None:
            base = self.constant(call.receiver, frame, depth + 1)
            if base:
                return base  # "text".toByteArray(UTF_8), KEY.getBytes()
            if not self.type_reference(call.receiver):
                return None
        if name in {"byteArrayOf", "ubyteArrayOf", "intArrayOf", "charArrayOf", "arrayOf"}:
            return "literal array" if values and all(values) else None
        # Base64.decode("..."), Data(base64Encoded: "..."), Data(literalBytes)
        return next((value for value in values if value), None)

    def type_reference(self, node: Any) -> bool:
        """A class or companion used as a call receiver, such as Base64 or Base64.getDecoder()."""
        return bool(re.fullmatch(r"(?:[a-z_]\w*\.)*[A-Z]\w*(?:\.\w+\(\))?", self.key(node)))

    def flag_argument(self, node: Any) -> bool:
        """Charset, flag and class arguments that do not make a conversion's result variable."""
        node = self.unwrap(node)
        text = self.text(node).strip() if node is not None else ""
        return bool(
            re.fullmatch(
                r"(?:[A-Z]\w*\.)*[A-Z][A-Z0-9_]*|\.\w+|(?:Charsets|StandardCharsets|Base64|String\.Encoding)\.\w+"
                r"|[A-Z]\w*(?:\.\w+)*::class(?:\.java)?",
                text,
            )
        )

    def call_arguments(self, call: Call) -> Any:
        """The call's own value_arguments node (Kotlin and Swift)."""
        arguments = next((part for part in call.node.named_children if part.type == "value_arguments"), None)
        if arguments is None:
            suffix = next((part for part in call.node.named_children if part.type == "call_suffix"), None)
            arguments = (
                next((part for part in suffix.named_children if part.type == "value_arguments"), None)
                if suffix
                else None
            )
        return arguments

    def labeled_argument(self, call: Call, label: str) -> Any:
        """The value of a Swift argument with this label."""
        arguments = self.call_arguments(call)
        for argument in arguments.named_children if arguments is not None else []:
            name = next(
                (part for part in argument.named_children if part.type == "value_argument_label"), None
            )
            if name is not None and self.text(name).strip() == label:
                return _field(argument, "value") or argument.named_children[-1]
        return None

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
            if member in ENTRY_ITERATORS:
                return Value(type_name="ZipEntry")
            if member == "name" and ARCHIVE_ENTRY.fullmatch(value.type_name.strip()):
                return self.source(node, "Archive entry name", "text")
            if (member in {"name", "fileName"} and value.category == "path") or member == "lastPathComponent":
                return self.basename(node, value)
            if member == "fileDescriptor":
                return Value(type_name="FileDescriptor")
            if member == "extras" and value.category == "intent":
                return Value(value.traces, "bundle")
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
            if call.name in {"getColumnIndex", "getColumnIndexOrThrow"} and call.args:
                if re.search(r"DISPLAY_NAME|_display_name", self.text(call.args[0])):
                    return Value(category="display-name-column")
            if call.name == "getString" and args and args[0].category == "display-name-column":
                return self.source(node, "Content provider display name", "text")
            if call.name in ENTRY_ITERATORS:
                return Value(type_name="ZipEntry")
            if call.name == "getName" and ARCHIVE_ENTRY.fullmatch(receiver.type_name.strip()):
                return self.source(node, "Archive entry name", "text")
            if (call.name in {"getName", "getFileName"} and receiver.category == "path") or (
                call.name == "substringAfterLast" and call.args and self.literal(call.args[0]) == "/"
            ):
                return self.basename(node, receiver)
            if call.name == "getName" and self.key(call.receiver) == "FilenameUtils" and args:
                return self.basename(node, args[0])
            if call.name == "getFileDescriptor":
                return Value(type_name="FileDescriptor")
            if call.name == "getExtras" and receiver.category == "intent":
                return Value(receiver.traces, "bundle")
            if call.name in NESTED_INTENT_GETTERS:
                holder = receiver
                if self.key(call.receiver) in {"IntentCompat", "BundleCompat"} and args:
                    holder = args[0]
                if holder.category in {"intent", "bundle"}:
                    return self.source(node, NESTED_INTENT, "nested-intent", holder)
            simple = call.name.rsplit(".", 1)[-1]
            if simple == "File" and call.receiver is None and self.language in {"java", "kotlin"}:
                # changed() would reset the category; a File keeps "path" so wrappers are not re-reported.
                return Value(self.changed(node, _union([receiver, *args])).traces, "path", "File")
            declared = self.spec_entry("source", call, frame)
            if declared:
                return self.source(
                    node, f"Project specification source {declared['id']}", declared["returns"], receiver
                )
            if (
                call.receiver is None
                and simple[:1].isupper()
                and simple not in self.class_names
                and any(item.endswith("." + simple) for item in self.imports)
            ):
                # A constructor of an imported class: keep input provenance and record the type.
                return self.changed(node, Value(_union([receiver, *args]).traces, "unknown", simple))
            # Unknown calls retain input provenance, with no assumed sanitization or return type.
            return self.changed(node, _union([receiver, *args]))
        if node.type == "binary_expression" and self.language == "kotlin":
            left, right = _field(node, "left"), _field(node, "right")
            if (
                left is not None
                and right is not None
                and self.raw[left.end_byte : right.start_byte].strip() == b"?:"
            ):
                kept = self.value(left, frame)
                return Value(_union([kept, self.value(right, frame)]).traces, kept.category, kept.type_name)
            generic = self.generic_call(node)
            if generic is not None:
                target, name = generic
                holder = self.value(target, frame)
                if name in NESTED_INTENT_GETTERS and holder.category in {"intent", "bundle"}:
                    return self.source(node, NESTED_INTENT, "nested-intent", holder)
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

    def basename(self, node: Any, value: Value) -> Value:
        """Mark input reduced to a final path component; it stays tainted for every other sink."""
        return Value(
            tuple(
                Trace(
                    hash((node.start_byte, trace.origin)),
                    trace.source,
                    trace.description + BASENAME,
                    trace.steps,
                )
                for trace in value.traces
            ),
            value.category,
            value.type_name,
        )

    def generic_call(self, node: Any) -> tuple[Any, str] | None:
        """Kotlin's grammar reads receiver.method<T>(args) as comparisons; recover receiver and method."""
        text = self.text(node).strip()
        if len(text) > 400 or "<" not in text or not text.endswith(")"):
            return None
        if not re.fullmatch(r"[\w.?!]{1,200}?\.\s*\w+\s*<[\w.?<> ]{1,100}>\s*\([^\n]*\)", text):
            return None
        left = node
        while left is not None and left.type == "binary_expression":
            left = _field(left, "left")
        navigation = self.navigation(left) if left is not None else None
        return navigation if navigation else None

    def string_value(self, node: Any, frame: Frame) -> str | None:
        """A string literal, or an immutable string constant of this file not shadowed locally."""
        literal = self.literal(node)
        if literal is not None:
            return literal
        node = self.unwrap(node)
        if node is not None and node.type in IDENTIFIERS:
            name = self.text(node)
            if name not in frame.values and name not in frame.types and name in self.constants:
                return self.constants[name][1]
        if node is not None and node.type in IDENTIFIERS and self.function is not None:
            # A local declared with a literal and not reassigned (=, +=) before this use.
            name = self.text(node)
            if name in self.parameter_types:
                return None
            declarations, assignments = self.local_literals()
            ends, values = declarations.get(name, ([], []))
            index = bisect_right(ends, node.start_byte) - 1
            if index >= 0:
                offsets = assignments.get(name, [])
                later = bisect_left(offsets, ends[index])
                if later >= len(offsets) or offsets[later] >= node.start_byte:
                    return values[index]
        navigation = self.navigation(node) if node is not None else None
        if navigation and self.text(navigation[0]).split(".")[0] in {
            "Companion",
            "this",
            "self",
            *self.class_names,
        }:
            entry = self.constants.get(navigation[1])
            return entry[1] if entry else None
        return None

    def local_literals(self) -> tuple[dict[str, tuple[list[int], list[str]]], dict[str, list[int]]]:
        """Literal string declarations and later assignments in this function, built once per function."""
        if self.literal_table is None:
            base = self.function.start_byte if self.function is not None else 0
            body = self.raw[base : self.function.end_byte] if self.function is not None else b""
            # Per name, declaration ends and values in source order (sorted for bisect).
            declarations: dict[str, tuple[list[int], list[str]]] = {}
            assignments: dict[str, list[int]] = {}
            for match in LOCAL_LITERAL.finditer(body):
                name = (match[1] or match[2]).decode("utf-8", errors="replace")
                ends, values = declarations.setdefault(name, ([], []))
                ends.append(base + match.end())
                values.append(match[3].decode("utf-8", errors="replace"))
            for match in LOCAL_ASSIGNMENT.finditer(body):
                assignments.setdefault(match[1].decode("utf-8", errors="replace"), []).append(
                    base + match.start()
                )
            self.literal_table = (declarations, assignments)
        return self.literal_table

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
                if "SQL" in rule or "PATH" in rule
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
        self.check_key_material(call, frame)
        self.check_intent_launch(call, frame)
        self.check_file_path(call, frame)
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

    def function_text(self) -> str:
        return self.function_source

    def private_key_function(self) -> bool:
        """Whether this function's key attributes name a private key class (computed once per function)."""
        if self.private_keys is None:
            self.private_keys = "kSecAttrKeyClassPrivate" in self.function_source
        return self.private_keys

    def path_guard(self) -> bool:
        """A containment or ".." check anywhere in this function (computed once per function)."""
        if self.path_guarded is None:
            text = self.function_source
            canonical = any(token in text for token in CANONICAL_PATHS)
            prefix = "startsWith" in text or "hasPrefix" in text
            # A containment test for "..", not a replace("..", ...) that a crafted name can bypass.
            dotdot = re.search(
                r'(?:contains|startsWith|endsWith|indexOf|equals)\s*\(\s*"\.\."|==\s*"\.\."', text
            )
            self.path_guarded = (canonical and prefix) or dotdot is not None
        return self.path_guarded

    def local_broadcaster(self, receiver: str) -> bool:
        """Whether a receiver is a LocalBroadcastManager declared or assigned anywhere in this file."""
        if self.broadcaster_names is None:
            text = self.raw.decode("utf-8", errors="replace")
            self.broadcaster_names = (
                {match[1] or match[2] for match in LOCAL_BROADCASTERS.finditer(text)}
                if "LocalBroadcastManager" in text
                else set()
            )
        return "LocalBroadcast" in receiver or receiver.rsplit(".", 1)[-1] in self.broadcaster_names

    def check_key_material(self, call: Call, frame: Frame) -> None:
        name = call.name.rsplit(".", 1)[-1]
        sink = KEY_SINKS.get(name)
        if sink is None or name in self.class_names:
            return
        rule, position = sink
        argument = None
        if self.language == "swift":
            receiver = self.text(call.receiver)
            if name == "PrivateKey" and re.search(r"\b(?:P256|P384|P521|Curve25519)\b", receiver):
                for label in (
                    "rawRepresentation",
                    "derRepresentation",
                    "pemRepresentation",
                    "x963Representation",
                ):
                    argument = argument or self.labeled_argument(call, label)
            elif name == "Nonce" and re.search(r"\b(?:AES\.GCM|ChaChaPoly)\b", receiver):
                argument = self.labeled_argument(call, "data")
            elif name == "SymmetricKey" and call.receiver is None:
                argument = self.labeled_argument(call, "data")
            elif name == "SecKeyCreateWithData" and call.args and self.private_key_function():
                argument = call.args[0]
        elif self.language in {"java", "kotlin"} and isinstance(position, int):
            argument = call.args[position] if len(call.args) > position else None
        described = self.constant(argument, frame) if argument is not None else None
        if described:
            self.emit(
                rule,
                call.node,
                api=name,
                material=described,
                constant_scope="literal, local value or immutable constant in this file",
            )

    def custom_action(self, expression: str) -> str | None:
        """An app-defined action named in the text that builds an Intent, resolving file constants."""
        for match in re.finditer(
            r'\bIntent\s*\(\s*(?:"([^"]+)"|([A-Za-z_][\w.]*))\s*[,)]|\baction\s*=\s*(?:"([^"]+)"|([A-Za-z_][\w.]*))'
            r'|\bsetAction\s*\(\s*(?:"([^"]+)"|([A-Za-z_][\w.]*))\s*\)',
            expression,
        ):
            literal = match[1] or match[3] or match[5]
            constant = match[2] or match[4] or match[6]
            if constant:
                entry = self.constants.get(constant.rsplit(".", 1)[-1])
                literal = entry[1] if entry else None
            if literal and self.package_prefix and literal.startswith(self.package_prefix + "."):
                return literal
        return None

    def check_intent_launch(self, call: Call, frame: Frame) -> None:
        if self.language not in {"java", "kotlin"} or call.name not in INTENT_LAUNCHERS or not call.args:
            return
        function = self.function_text()
        first = call.args[0]
        value = self.value(first, frame)
        nested = tuple(trace for trace in value.traces if trace.description == NESTED_INTENT)
        if value.category == "nested-intent" and nested:
            target = self.unwrap(first)
            name = self.text(target) if target is not None and target.type in IDENTIFIERS else None
            if name is not None and name not in self.checked_intents:
                # A comparison of the nested Intent's component or package, not a mere mention (such as a log).
                self.checked_intents[name] = bool(
                    re.search(
                        rf"\b{re.escape(name)}\b[^\n]{{0,80}}\b(?:component|getComponent|packageName|getPackage|className)\b"
                        r"[^\n]{0,60}(?:==|!=|\.equals\s*\(|\bin\b|\.contains\s*\(|\.startsWith\s*\()",
                        function,
                    )
                )
            checked = name is not None and self.checked_intents[name]
            if not checked:
                self.emit(
                    "AST-INTENT-REDIRECTION",
                    call.node,
                    traces=nested,
                    sink=call.name,
                    validation="no component or package check on the nested Intent in this function",
                )
            return
        if call.name not in IMPLICIT_LAUNCHERS:
            return
        if call.name in {"sendBroadcast", "sendOrderedBroadcast"} and len(call.args) > 1:
            if self.text(call.args[1]).strip() not in {"null"}:
                return  # receiver permission given
        receiver = self.key(call.receiver)
        if receiver and self.local_broadcaster(receiver):
            return
        if self.action_hint is None:
            self.action_hint = bool(ACTION_HINT.search(function))
        if not self.action_hint:
            return
        if self.intent_checks >= MAX_INTENT_CHECKS:
            self.truncated_rules.add("AST-IMPLICIT-INTENT")
            return
        self.intent_checks += 1
        target = self.unwrap(first) or first
        if target.type in IDENTIFIERS and self.text(target) in self.aliases:
            target = self.aliases[self.text(target)]
        expression, basis = self.intent_expression(target, call.node)
        action = self.custom_action(expression)
        explicit = re.search(
            r"::class|\.class\b|setClass|setComponent|setPackage|ComponentName|\b(?:component|`?package`?)\s*=",
            expression,
        )
        if action and not explicit:
            self.emit(
                "AST-IMPLICIT-INTENT",
                call.node,
                sink=call.name,
                action=action,
                intent_argument=basis,
            )

    def check_file_path(self, call: Call, frame: Frame) -> None:
        simple = call.name.rsplit(".", 1)[-1]
        args = list(call.args)
        argument = None
        if self.language in {"java", "kotlin"}:
            # Context.openFileOutput and similar reject path separators, so they are not sinks.
            if simple in FILE_SINKS and call.receiver is None and simple not in self.class_names and args:
                argument = args[1] if simple == "File" and len(args) >= 2 else args[0]
        elif self.language == "swift":
            if call.name == "appendingPathComponent" and args:
                argument = args[0]
            elif call.name == "appending":
                argument = self.labeled_argument(call, "path")
            elif call.name == "URL":
                argument = self.labeled_argument(call, "fileURLWithPath")
        if argument is None or self.name_only(call.node):
            return
        if FILE_DESCRIPTOR.search(self.text(argument).strip()):
            return  # a FileDescriptor opened by the platform is not a path
        value = self.value(argument, frame)
        if value.category == "path" or "FileDescriptor" in value.type_name:
            return  # the File it wraps was checked where it was built
        traces = tuple(trace for trace in value.traces if not trace.description.endswith(BASENAME))
        if not traces:
            return
        if self.path_guard():
            return
        self.emit(
            "AST-PATH-TRAVERSAL",
            call.node,
            traces=traces,
            sink=call.name,
            validation="no canonical-path containment or '..' check in this function",
            unknown_helpers_are_sanitizers=False,
        )

    def name_only(self, node: Any) -> bool:
        """File(x).name or new File(x).getName(): the File is built only to take its final component."""
        parent = node.parent
        if parent is None:
            return False
        if parent.type == "navigation_expression" and parent.named_children[0] == node:
            member = self.navigation(parent)
            return bool(member and member[1] in {"name", "fileName"})
        if parent.type == "method_invocation" and _field(parent, "object") == node:
            return self.text(_field(parent, "name")) in {"getName", "getFileName"}
        return False

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
            algorithm = self.string_value(call.args[0], frame)
            scope = "literal argument" if self.literal(call.args[0]) is not None else "constant in this file"
            if algorithm and self.framework_receiver(call, frame, "javax.crypto.Cipher"):
                parts = algorithm.split("/")
                base = parts[0].upper()
                if base in BROKEN_CIPHERS:
                    self.emit("AST-CRYPTO-WEAK-CIPHER", call.node, algorithm=algorithm, constant_scope=scope)
                elif re.fullmatch(r"AES(?:_\d+)?", base) and (len(parts) == 1 or parts[1].upper() == "ECB"):
                    self.emit(
                        "AST-CRYPTO-ECB",
                        call.node,
                        algorithm=algorithm,
                        constant_scope=scope,
                        mode="ECB" if len(parts) > 1 else "provider default (ECB)",
                    )
            if algorithm:
                if self.framework_receiver(
                    call, frame, "java.security.MessageDigest"
                ) and algorithm.upper() in {"MD5", "SHA-1", "SHA1"}:
                    self.emit(
                        "AST-CRYPTO-WEAK-HASH", call.node, algorithm=algorithm, security_purpose="unverified"
                    )
        if self.language in {"java", "kotlin"} and call.args:
            receiver_type = self.value(call.receiver, frame).type_name
            for (qualified, method), positions in SQL_SINKS.items():
                index = positions
                simple = qualified.rsplit(".", 1)[-1]
                sdk_type = receiver_type == qualified or (
                    receiver_type == simple and qualified in self.imports and simple not in self.class_names
                )
                if call.name != method or not sdk_type:
                    continue
                if method == "query" and call.args and self.text(call.args[0]) in {"true", "false"}:
                    index = tuple(position + 1 for position in index)  # query(distinct, table, ...)
                tainted = [
                    position
                    for position in index
                    if position < len(call.args) and self.value(call.args[position], frame).traces
                ]
                if tainted:
                    query = _union([self.value(call.args[position], frame) for position in tainted])
                    self.emit(
                        "AST-SQL-CONCAT",
                        call.node,
                        traces=query.traces,
                        # sink is part of the finding identity; 1.3 used the bare method name.
                        sink=call.name,
                        sink_api=f"{simple}.{method}",
                        statement_scope=f"argument {', '.join(map(str, tainted))} is SQL syntax; bound value arguments are not",
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
            intent_node = call.args[2]
            if intent_node.type in IDENTIFIERS and self.text(intent_node) in self.aliases:
                intent_node = self.aliases[self.text(intent_node)]
            wrapped, basis = self.intent_expression(intent_node, call.node)
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
            described = self.constant(expression, frame) if expression is not None else None
            if described:
                frame.constants[name] = described
            else:
                frame.constants.pop(name, None)
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
                if left.type in IDENTIFIERS:
                    described = self.constant(right, frame)
                    if described:
                        frame.constants[key] = described
                    else:
                        frame.constants.pop(key, None)
                else:
                    # An element or member write changes the array it belongs to.
                    base = next((part for part in _walk(left) if part.type in IDENTIFIERS), None)
                    if base is not None:
                        frame.constants.pop(self.text(base), None)
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
            frame.constants = {
                key: value for key, value in branch.constants.items() if key in alternative.constants
            }
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
            frame.constants = {
                **{key: value for key, value in local.constants.items() if key not in declared},
                **{key: value for key, value in frame.constants.items() if key in declared},
            }
            return
        if node.type == "enhanced_for_statement":
            name, type_node = _field(node, "name"), _field(node, "type")
            if name is not None and type_node is not None:
                frame.types[self.text(name)] = self.text(type_node)
        elif node.type == "for_statement" and self.language == "kotlin":
            variable = next(
                (part for part in node.named_children if part.type == "variable_declaration"), None
            )
            # ZipFile/JarFile.entries() yields entries; Kotlin enum and Map "entries" are properties.
            if variable is not None and re.search(r"\bentries\s*\(\s*\)", self.text(node).split("{", 1)[0]):
                frame.types[self.text(variable).split(":")[0].strip()] = "ZipEntry"
        call = self.call(node)
        if call:
            if call.receiver:
                self.visit(call.receiver, frame, guards, conditions)
            for arg in call.args:
                self.visit(arg, frame, guards, conditions)
            self.check_call(call, frame, guards, conditions)
            self.release_constants(call, frame)
            scope = self.scope_function(call)
            for lambda_node in self.trailing_lambdas(node):
                if scope is not None:
                    self.visit_scope_lambda(lambda_node, frame, guards, conditions, *scope)
                else:
                    # An unfollowed closure may fill any array it names.
                    for part in _walk(lambda_node):
                        if part.type in IDENTIFIERS:
                            frame.constants.pop(self.text(part), None)
            return
        for child in node.named_children:
            self.visit(child, frame, guards, conditions)

    @staticmethod
    def trailing_lambdas(node: Any) -> list[Any]:
        """Kotlin annotated lambdas and Swift trailing closures attached to a call."""
        found = []
        for part in node.named_children:
            if part.type == "annotated_lambda":
                found += [child for child in part.named_children if child.type == "lambda_literal"]
            elif part.type == "call_suffix":
                found += [child for child in part.named_children if child.type == "lambda_literal"]
        return found

    def scope_function(self, call: Call) -> tuple[str, Any] | None:
        """Kotlin scope function name and its receiver: x.let {}, x.use {}, with(x) {}."""
        if self.language != "kotlin":
            return None
        if call.name in SCOPE_FUNCTIONS:
            return call.name, call.receiver
        callee = call.node.named_children[0] if call.node.named_children else None
        inner = self.call(callee) if callee is not None and callee.type == "call_expression" else None
        if inner is not None and inner.name == "with" and inner.receiver is None and inner.args:
            return "with", inner.args[0]
        return None

    def visit_scope_lambda(
        self,
        node: Any,
        frame: Frame,
        guards: dict[int, set[str]],
        conditions: list[Any],
        scope: str,
        receiver: Any,
    ) -> None:
        """Follow a scope function's lambda once, as a block whose parameter is the receiver."""
        local = frame.copy()
        parameters = next((part for part in node.named_children if part.type == "lambda_parameters"), None)
        names = (
            [self.text(part) for part in _walk(parameters) if part.type in IDENTIFIERS] if parameters else []
        )
        declared = set()
        saved = dict(self.aliases)
        if scope in {"let", "also", "use"}:
            name = names[0] if names else "it"
            declared.add(name)
            local.values[name] = self.value(receiver, frame) if receiver is not None else Value()
            local.constants.pop(name, None)
            if receiver is not None:
                self.aliases[name] = receiver
        local_guards = {origin: checks.copy() for origin, checks in guards.items()}
        for child in node.named_children:
            if child is parameters:
                continue
            parsed = self.declaration(child)
            if parsed:
                declared.add(parsed[0])
            self.visit(child, local, local_guards, conditions.copy())
        self.aliases = saved
        # x?.let {} may not run: like a branch, keep the values from before and from the lambda.
        for key in frame.values:
            if key not in declared:
                values = [frame.values[key], local.values[key]]
                frame.values[key] = _union(
                    values,
                    values[0].category if values[0].category == values[1].category else "unknown",
                    type_name=frame.values[key].type_name,
                )
        frame.bridges.update(local.bridges)
        frame.javascript.update(local.javascript)
        frame.constants = {
            key: value
            for key, value in frame.constants.items()
            if key in declared or local.constants.get(key) == value
        }

    def release_constants(self, call: Call, frame: Frame) -> None:
        """A constant passed to or called on by a method that may fill it is no longer known to be constant."""
        name = call.name.rsplit(".", 1)[-1]
        if name in PURE_METHODS or name in KEY_SINKS:
            return
        targets = [*call.args, call.receiver]
        for target in targets:
            target = self.unwrap(target)
            if (
                target is not None
                and target.type == "prefix_expression"
                and self.text(target).startswith("&")
            ):
                target = target.named_children[-1] if target.named_children else None
            if target is not None and target.type in IDENTIFIERS:
                frame.constants.pop(self.text(target), None)

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

    def collect_constants(self, root: Any) -> None:
        """Immutable declarations outside functions: Kotlin val/const val, Java final fields, Swift let."""
        declarations = []
        for node in _walk(root, descend_functions=False):
            if node.parent is None or node.parent.type not in CONSTANT_SCOPES:
                continue
            if node.type == "field_declaration" and re.search(
                r"\bfinal\b", self.text(_field(node, "modifiers") or node.named_children[0])
            ):
                declarations += [part for part in node.named_children if part.type == "variable_declarator"]
            elif node.type == "property_declaration":
                keyword = r"\blet\b" if self.language == "swift" else r"\bval\b"
                head = self.text(node).split("=", 1)[0]
                if re.search(keyword, head):
                    declarations.append(node)
        # Two passes let one constant refer to another declared later in the file.
        for _ in range(2):
            for node in declarations:
                parsed = self.declaration(node)
                if not parsed or not parsed[0] or parsed[1] is None:
                    continue
                name, expression, _ = parsed
                described = self.constant(expression, Frame())
                # A zero-filled field is storage that constructors or init blocks fill; it is not a constant.
                if described and described != "zero-filled array":
                    self.constants[name] = (described, self.literal(self.unwrap(expression)))

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
            if node.type == "object_declaration":
                name = next(
                    (part for part in node.named_children if part.type in IDENTIFIERS | {"type_identifier"}),
                    None,
                )
                if name is not None:
                    self.class_names.add(self.text(name))
        self.collect_constants(root)
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
            self.function = function
            self.function_source = self.text(function)
            self.path_guarded = self.action_hint = None
            self.intent_checks = 0
            self.literal_table = None
            self.private_keys = None
            self.checked_intents = {}
            self.aliases = {}
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
                if self.language == "swift" and "CryptoKit" in self.imports:
                    for node in _walk(body, descend_functions=False):
                        if node.type == "navigation_expression" and re.fullmatch(
                            r"Insecure\.(?:MD5|SHA1)", self.key(node)
                        ):
                            self.emit(
                                "AST-CRYPTO-WEAK-HASH",
                                node,
                                algorithm=self.key(node),
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
    truncated_rules: set[str] = set()
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
            truncated_rules |= getattr(analyzer, "truncated_rules", set())
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
            if rule.endswith(ANDROID_ONLY) and seen_languages == {"swift"} and not unsupported
            else "partial"
            if rule in truncated_rules and state == "checked"
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
