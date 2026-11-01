"""Offline, function-scoped mobile source checks over bundled Tree-sitter grammars.

These checks follow local assignments, bounded direct calls and known platform input APIs. They do not
prove that an Android component is exported, or model navigation
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
from .input_snapshot import prioritized_paths
from .maswe import weaknesses_for
from .specs import SINK_KINDS

MAX_AST_BYTES = 2 * 1024 * 1024
MAX_AST_TOTAL = 32 * 1024 * 1024
MAX_AST_NODES = 100_000
MAX_AST_FINDINGS = 500
MAX_PATH_ROUTE_EVIDENCE = 32
LANGUAGES = {".java": "java", ".kt": "kotlin", ".kts": "kotlin", ".swift": "swift", ".m": "objc"}
UNSUPPORTED_SOURCE = {".mm", ".dart", ".js", ".jsx", ".ts", ".tsx", ".cs"}
# Property accessor bodies (Swift computed get/set/modify and willSet/didSet, Kotlin
# get()/set()) are analyzed like methods. Reading such a property elsewhere stays unmodelled.
ACCESSORS = {
    "computed_property",
    "computed_getter",
    "computed_setter",
    "computed_modify",
    "willset_clause",
    "didset_clause",
    "getter",
    "setter",
}
# Kotlin init blocks and secondary constructors and Swift init/deinit bodies are analyzed
# like methods. They have no name of their own, so they are never call targets by name.
INITIALIZERS = {"anonymous_initializer", "secondary_constructor", "init_declaration", "deinit_declaration"}
FUNCTIONS = {
    "method_declaration",
    "constructor_declaration",
    "function_declaration",
    "method_definition",
    "function_definition",
    *ACCESSORS,
    *INITIALIZERS,
}
COMMENTS = {"comment", "line_comment", "block_comment", "multiline_comment"}
STRINGS = {"string_literal", "line_string_literal", "multi_line_string_literal", "character_literal"}
IDENTIFIERS = {"identifier", "simple_identifier"}
# Statement lists; Java constructors have their own body type, Kotlin/Swift reuse block/function_body.
BLOCKS = {"block", "statements", "function_body", "constructor_body"}
URI_REFERENCE = "https://developer.android.com/privacy-and-security/risks/unsafe-uri-loading"
# Public suffixes anyone can register a subdomain under: shared hosting and common country
# second-level domains. A dot-anchored suffix check against one, or against a bare TLD,
# is no allowlist. WEBVIEW-HOST-MATCH in data/rules.json uses the same list.
SHARED_HOSTING_SUFFIXES = (
    r"(?:[\w-]+\.)*amazonaws\.com|github\.io|githubusercontent\.com|gitlab\.io"
    r"|firebaseapp\.com|firebaseio\.com|web\.app|herokuapp\.com"
    r"|(?:(?:[\w-]+\.)?r\.)?appspot\.com|(?:[\w-]+\.)?run\.app|cloudfunctions\.net"
    r"|cloudfront\.net|(?:[\w-]+\.)?elasticbeanstalk\.com"
    r"|(?:[a-z0-9]+-\d\d\.)?azurewebsites\.net|(?:[\w-]+\.)?azurestaticapps\.net"
    r"|azureedge\.net|cloudapp\.net|(?:[\w-]+\.)?cloudapp\.azure\.com|blob\.core\.windows\.net"
    r"|trafficmanager\.net|netlify\.app|vercel\.app|now\.sh|pages\.dev|workers\.dev"
    r"|blogspot\.com|wordpress\.com|wixsite\.com|glitch\.me|onrender\.com|fly\.dev|surge\.sh"
    r"|(?:(?:eu|ap|au|sa|jp|in|us)\.)?ngrok\.io|ngrok-free\.app|storage\.googleapis\.com"
    r"|firebasestorage\.app|(?:[\w-]+\.)?web\.core\.windows\.net"
    r"|(?:[\w-]+\.)?digitaloceanspaces\.com|ondigitalocean\.app|r2\.dev|up\.railway\.app"
    r"|deno\.dev|pythonanywhere\.com|repl\.co|(?:[\w-]+\.)?azurefd\.net"
    r"|(?:co|org|ac|gov|me)\.uk|(?:com|net|org)\.au|(?:co|ne|or)\.jp"
    r"|(?:co|pe|or|ne|go|ac|re)\.kr|com\.(?:br|cn|hk|sg|tw|mx|tr|ar|vn|my|ph)"
    r"|co\.(?:in|nz|za|id|th)"
)
SHARED_HOSTING = re.compile(SHARED_HOSTING_SUFFIXES, re.I)
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
    "PENDINGINTENT-MUTABLE",
    "INTENT-REDIRECTION",
    "IMPLICIT-INTENT",
)
SWIFT_UNIMPLEMENTED = {"AST-CRYPTO-ECB", "AST-CRYPTO-WEAK-CIPHER", "AST-SQL-CONCAT"}
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
# Path checks include canonical containment and separate lexical ".." constraints.
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
TARGET_TOKEN = re.compile(
    r"\b(?:component|getComponent|packageName|getPackageName|getPackage|className|getClassName)\b"
)
TARGET_ALIAS = re.compile(
    r"(\w+)\s*(?::\s*[\w.?]+\s*)?=\s*(\w+)\s*\??\.\s*(?:getComponent\s*\(\s*\)|component\b"
    r"|getPackage\s*\(\s*\)|`?package`?\b)"
)
COMPARISON = re.compile(r"==|!=|\.equals\s*\(|\bin\b|\.contains\s*\(|\.startsWith\s*\(")
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
    "Local def-use and bounded direct interprocedural flow; no dynamic method dispatch, unbounded interprocedural flow, "
    "component reachability, redirect, or authentication-state proof. Kotlin scope-function lambdas "
    "(let, also, use, apply, run, with) are followed as blocks that may not run; other closure arguments "
    "are inspected conservatively without transferring their guards. Unlabeled Kotlin lambda returns "
    "are conservatively joined into the enclosing return; unavailable inline-call identity remains partial. "
    "Kotlin returns to a resolved enclosing function label also join that function's return; "
    "lambda-local labeled Kotlin returns and Java/Swift closure returns remain local. "
    "Lexical path containment does not prove symlink-free storage "
    "or race-free filesystem access."
)
# A trace cut by a resource cap (an execution gap) and a trace the bounded model
# abstained on (a precision limit) carry distinct markers, so later calls and
# sinks keep the original kind. Either marker keeps the trace unsafe.
TRACE_PARTIAL = " [native-flow-partial]"
TRACE_LIMITED = " [native-flow-limited]"
TRACE_MARKERS = {TRACE_PARTIAL: "budget", TRACE_LIMITED: "precision"}
GuardKey = int | tuple[int, str]


def trace_cuts(description: str) -> set[str]:
    """The kinds ("budget", "precision") of cuts recorded on a trace description."""
    return {kind for marker, kind in TRACE_MARKERS.items() if marker in description}


def _walk(node: Any, *, descend_functions: bool = True):
    stack = [node]
    while stack:
        current = stack.pop()
        yield current
        if current.type in COMMENTS or (
            not descend_functions and current.type in FUNCTIONS and not _nested_initializer(current)
        ):
            continue
        stack.extend(reversed(current.named_children))


def _nested_initializer(node: Any) -> bool:
    """An init of a local or anonymous class runs in its enclosing function's scope.

    Such an initializer is analyzed inline with that function, which supplies the
    locals it captures; it is not an analysis unit of its own.
    """
    if node.type not in INITIALIZERS:
        return False
    parent = node.parent
    while parent is not None and parent.type not in FUNCTIONS:
        parent = parent.parent
    return parent is not None


def _field(node: Any, name: str) -> Any:
    return node.child_by_field_name(name)


def _accessor_property(node: Any) -> Any:
    """The property an accessor unit belongs to; None for subscripts and get/set containers."""
    explicit = {"computed_getter", "computed_setter", "computed_modify"}
    if node.type == "computed_property" and any(child.type in explicit for child in node.named_children):
        return None
    parent = node.parent
    if node.type in explicit | {"willset_clause", "didset_clause"} and parent is not None:
        parent = parent.parent
    return parent if parent is not None and parent.type == "property_declaration" else None


def _function_body(function: Any) -> Any:
    return _field(function, "body") or next(
        (
            node
            for node in function.named_children
            if node.type == "function_body"
            or node.type == "statements"
            and function.type in ACCESSORS
            or node.type == "block"
            and function.type in INITIALIZERS
        ),
        None,
    )


def _analysis_unit(node: Any) -> bool:
    """A counted, analyzed callable. An accessor needs a property and a body of its own."""
    if node.type in INITIALIZERS:
        return not _nested_initializer(node)
    if node.type not in ACCESSORS:
        return node.type in FUNCTIONS
    return _accessor_property(node) is not None and _function_body(node) is not None


def _fields(node: Any, name: str) -> list[Any]:
    return [child for i, child in enumerate(node.children) if node.field_name_for_child(i) == name]


def _package_name(text: str) -> str:
    """Extract once per file, including the negative result; whitespace stays on its line."""
    package = re.search(r"^[ \t]*package[ \t]+([\w.]+)", text, re.M)
    return package[1] if package else ""


@dataclass(frozen=True)
class SourceNode:
    """A trace step carries its own file location across callable boundaries."""

    node: Any
    location: dict

    @property
    def type(self) -> str:
        return self.node.type


@dataclass(frozen=True)
class Trace:
    origin: int
    source: Any
    description: str
    steps: tuple[Any, ...] = ()
    path_safe: bool = False
    path_route: str = ""


@dataclass(frozen=True)
class Value:
    traces: tuple[Trace, ...] = ()
    category: str = "unknown"
    type_name: str = ""
    identity: str = ""

    def bind(self, node: Any) -> Value:
        return Value(
            tuple(
                Trace(t.origin, t.source, t.description, (t.steps + (node,))[-12:], t.path_safe, t.path_route)
                for t in self.traces
            ),
            self.category,
            self.type_name,
            self.identity,
        )


def _union(values: list[Value], category: str = "unknown", type_name: str = "") -> Value:
    traces: dict[tuple[int, str], Trace] = {}
    for value in values:
        for trace in value.traces:
            key = (trace.origin, trace.path_route)
            previous = traces.get(key)
            if previous is not None:
                description = trace.description
                for marker in TRACE_MARKERS:
                    if marker in previous.description and marker not in description:
                        description += marker
                trace = Trace(
                    trace.origin,
                    trace.source,
                    description,
                    trace.steps,
                    previous.path_safe and trace.path_safe,
                    trace.path_route,
                )
            traces[key] = trace
    kept = tuple(traces.values())
    if len(kept) > 8:
        # Collapsing origins beyond the trace cap is a budget cut.
        last = kept[-1]
        kept = (
            *kept[:7],
            Trace(
                hash(("trace-budget", tuple(traces))),
                last.source,
                last.description + TRACE_PARTIAL,
                last.steps,
            ),
        )
    identities = {value.identity for value in values}
    return Value(kept, category, type_name, identities.pop() if len(identities) == 1 else "")


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
    object_fields: dict[Any, dict[Any, Value]] = field(default_factory=dict)
    call_results: dict[tuple, Value] = field(default_factory=dict)
    local_names: set[str] = field(default_factory=set)
    # Lambda spans whose scope receiver/parameter was bound in this frame.
    # Frame-local state cannot leak into a direct helper's fresh function frame.
    kotlin_bound_scopes: set[tuple[int, int]] = field(default_factory=set)

    def copy(self) -> Frame:
        return Frame(
            self.values.copy(),
            self.types.copy(),
            self.bridges.copy(),
            self.javascript.copy(),
            self.constants.copy(),
            {key: values.copy() for key, values in self.object_fields.items()},
            self.call_results.copy(),
            self.local_names.copy(),
            self.kotlin_bound_scopes.copy(),
        )


@dataclass(frozen=True)
class SwiftClause:
    """One comma-separated clause of a Swift `if`/`guard` condition list.

    A boolean clause has `condition`. An optional binding or `case` pattern has the
    names it binds (name, bound identifier node) and its `initializer`, which is None
    for the `if let x` shorthand that unwraps the existing binding under the same name.
    """

    condition: Any = None
    names: tuple[tuple[str, Any], ...] = ()
    initializer: Any = None
    pattern: bool = False

    @property
    def node(self) -> Any:
        """The node recorded in the enclosing condition list for this clause."""
        if self.condition is not None:
            return self.condition
        if self.initializer is not None:
            return self.initializer
        return self.names[0][1] if self.names else None


SQLITE_DATABASE = "android.database.sqlite.SQLiteDatabase"
# SDK accessors whose result is a SQLiteDatabase even when the helper type is a project class.
SQLITE_ACCESSORS = {"writableDatabase", "readableDatabase"}
SQLITE_GETTERS = {"getWritableDatabase", "getReadableDatabase"}
SQLITE_OPENERS = {"openOrCreateDatabase", "openDatabase"}
# Framework accessors and properties that return a Context.
CONTEXT_ACCESSORS = {
    "requireContext",
    "requireActivity",
    "getApplicationContext",
    "applicationContext",
    "getBaseContext",
    "baseContext",
    "getContext",
    "getActivity",
}
# Framework Service classes (each a Context) known by simple name.
CONTEXT_SERVICE_TYPES = {
    "Service",
    "IntentService",
    "JobIntentService",
    "JobService",
    "LifecycleService",
    "FirebaseMessagingService",
    "AccessibilityService",
    "InputMethodService",
    "WallpaperService",
    "NotificationListenerService",
    "MediaBrowserService",
    "MediaBrowserServiceCompat",
    "MediaSessionService",
    "TileService",
    "VpnService",
    "HostApduService",
    "DreamService",
    "RemoteViewsService",
    "ConnectionService",
    "InCallService",
}
# Common receiver types that declare no openOrCreateDatabase member.
NON_CONTEXT_TYPES = {
    "Any",
    "Object",
    "String",
    "CharSequence",
    "Int",
    "Integer",
    "Long",
    "Boolean",
    "Double",
    "Float",
    "Unit",
    "List",
    "MutableList",
    "Map",
    "MutableMap",
    "Set",
    "MutableSet",
    "Array",
    "Runnable",
    "Closeable",
    "AutoCloseable",
    "Comparable",
    "Serializable",
    "Parcelable",
    "Cloneable",
    "Intent",
    "Uri",
    "Bundle",
    "File",
    "SQLiteDatabase",
}
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
        self.finding_ids: set[str] = set()
        self.scope = ""
        self.field_types: dict[str, str] = {}
        self.static_fields: set[str] = set()
        self.unavailable_fields: set[str] = set()
        self.class_field_nodes: dict[tuple[int, int], list[Any]] = {}
        self.parameter_types: dict[str, str] = {}
        self.activity_scope = False
        self.imports: set[str] = set()
        self.class_names: set[str] = set()
        self.safe_local_types: set[str] = set()
        self.defined_functions: set[str] = set()
        self.kotlin_scope_shadows: set[str] = set()
        self.kotlin_scope_import_unavailable: Any = None
        self.kotlin_scope_import_reported = False
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
        # A receiverless opener that resolves to project code, which is always followed.
        self.opener_follow = False
        # The framework type certainly applies (override, declared, Context receiver).
        self.opener_certain = False
        # Every followed project opener declares its return type.
        self.opener_returns = False
        self.class_context_cache: dict[tuple[int, int], str] = {}
        self.package_name = _package_name(text)
        parts = self.package_name.split(".") if self.package_name else []
        # Actions an app defines share its package namespace; other prefixes belong to other apps.
        self.package_prefix = ".".join(parts[: min(3, len(parts))])
        self.broadcaster_names: set[str] | None = None
        self.private_keys: bool | None = None
        self.target_names: set[str] | None = None
        self.literal_table: tuple[dict[str, tuple[list[int], list[str]]], dict[str, list[int]]] | None = None
        # Rules whose checks stopped at a budget in this file; their coverage becomes partial.
        self.truncated_rules: set[str] = set()
        # Rules whose checks examined the file but whose bounded model abstained
        # on some paths (a precision limit, not an execution gap); coverage becomes limited.
        self.limited_rules: set[str] = set()
        self.native_flow: Any = None
        self.return_values: list[Value] = []
        self.closure_depth = 0
        self.guarded_paths: set[tuple[int, str]] = set()
        self.unguarded_paths: set[tuple[int, str]] = set()
        self.finding_start = 0
        self.pending_paths: list[tuple[Any, str, set[tuple[int, str]]]] = []
        self.active_guards: dict[GuardKey, set[str]] = {}

    def text(self, node: Any) -> str:
        return self.raw[node.start_byte : node.end_byte].decode("utf-8", errors="replace") if node else ""

    def location(self, node: Any) -> dict:
        if isinstance(node, SourceNode):
            return node.location.copy()
        row = bisect_right(self.line_offsets, node.start_byte) - 1
        return {
            "path": self.path,
            "line": row + 1,
            "column": node.start_byte - self.line_offsets[row] + 1,
            "offset": node.start_byte,
        }

    def point(self, node: Any) -> SourceNode:
        return node if isinstance(node, SourceNode) else SourceNode(node, self.location(node))

    def symbol_name(self, name: str) -> str:
        """Canonical ordinary Kotlin identifiers at symbol boundaries only.

        Escaping an ordinary name does not change its binding. Other escaped
        spellings stay unsupported; source text, literals and offsets are intact.
        """
        match = re.fullmatch(r"`([^\W\d]\w*)`", name) if self.language == "kotlin" else None
        return match[1] if match else name

    def import_name(self, imported: str) -> str:
        """Normalize a whole supported Kotlin import once, before indexing it."""
        normalized = self.normalized_import_name(imported)
        return imported if normalized is None else normalized

    def normalized_import_name(self, imported: str) -> str | None:
        """None means import identity is unavailable, never an absent shadow."""
        if self.language != "kotlin":
            return imported
        identifier = r"(?:[^\W\d]\w*|`[^\W\d]\w*`)"
        match = re.fullmatch(
            rf"({identifier}(?:\s*\.\s*{identifier})*(?:\s*\.\s*\*)?)(?:\s+as\s+({identifier}))?",
            imported,
        )
        if match is None:
            return None
        target = ".".join(self.symbol_name(part) for part in re.split(r"\s*\.\s*", match[1]))
        return target + (" as " + self.symbol_name(match[2]) if match[2] else "")

    def key(self, node: Any) -> str:
        if self.language == "kotlin" and node is not None:
            if node.type in IDENTIFIERS:
                return self.symbol_name(self.text(node))
            if node.type == "navigation_expression" and "`" in self.text(node):
                navigation = self.navigation(node)
                if navigation is not None:
                    target, name = navigation
                    return (self.key(target) + "." + name).removeprefix("this.")
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

    def kotlin_templates(self, node: Any) -> list[tuple[str, Any]]:
        """Kotlin `$name` templates in a string literal, with the node holding the name.

        The bundled grammar emits only `${...}` and raw-string templates as
        interpolation nodes; a simple `"a=$id"` is a `$` part followed by plain
        content, so it would otherwise read as constant text.
        """
        if self.language != "kotlin" or node is None or node.type not in STRINGS:
            return []
        parts = node.named_children
        found = []
        for current, following in zip(parts, parts[1:], strict=False):
            if (
                current.type == "string_content"
                and self.text(current) == "$"
                and following.type == "string_content"
            ):
                match = re.match(r"`[^`\r\n]+`|[A-Za-z_][A-Za-z0-9_]*", self.text(following))
                if match:
                    found.append((self.symbol_name(match.group(0)), following))
        return found

    def swift_clauses(self, node: Any) -> tuple[list[SwiftClause], Any, Any]:
        """Split a Swift if/guard into its condition clauses in source order, body and else arm.

        The grammar lays the clauses out as flat `condition`/`bound_identifier` children
        separated by unlabeled commas; a comma inside a `case` pattern is a `condition`.
        """
        clauses: list[SwiftClause] = []
        current: list[tuple[str | None, Any]] = []
        then_node = else_node = None
        seen_else = False
        for index, child in enumerate(node.children):
            field = node.field_name_for_child(index)
            if field in {"condition", "bound_identifier"}:
                current.append((field, child))
                continue
            clauses += self.swift_clause(current)
            current = []
            if child.type == "else":
                seen_else = True
            elif child.type in {"statements", "if_statement"}:
                if seen_else:
                    else_node = child
                elif then_node is None:
                    then_node = child
        clauses += self.swift_clause(current)
        return clauses, then_node, else_node

    def swift_clause(self, parts: list[tuple[str | None, Any]]) -> list[SwiftClause]:
        """Classify one clause: a boolean condition, an optional binding or a `case` pattern."""
        children = [child for _, child in parts]
        equals = next((index for index, child in enumerate(children) if child.type == "="), len(children))
        head = children[:equals]
        if not any(child.type in {"case", "value_binding_pattern"} for child in head):
            return [SwiftClause(condition=child) for child in children if child.is_named]
        initializer = next((child for child in children[equals + 1 :] if child.is_named), None)
        names: list[tuple[str, Any]] = []
        # `case let .x(a)` and `let (a, b)` bind every bare pattern name; `case .x(let a)` binds a.
        binds_all = False
        for label, child in parts[:equals]:
            if label == "bound_identifier":
                names.append((self.symbol_name(self.text(child)), child))
            elif child.type == "value_binding_pattern":
                binds_all = True
            elif child.type == "pattern":
                for part in _walk(child):
                    if part.type != "pattern":
                        continue
                    named = part.named_children
                    if binds_all and len(named) == 1 and named[0].type in IDENTIFIERS:
                        names.append((self.symbol_name(self.text(named[0])), named[0]))
                    names += [
                        (self.symbol_name(self.text(item)), item)
                        for index, item in enumerate(part.children)
                        if part.field_name_for_child(index) == "bound_identifier"
                    ]
        pattern = any(child.type in {"case", "pattern"} for child in head)
        return [SwiftClause(names=tuple(names), initializer=initializer, pattern=pattern)]

    def bind_swift_clause(self, clause: SwiftClause, frame: Frame) -> None:
        """Bind a clause's names in `frame` like local declarations initialized from its initializer.

        An optional binding holds the unwrapped value. A `case` or destructuring pattern
        binds part of the matched value, so its names keep only the value's taint.
        """
        if clause.initializer is None:
            # `if let x` / `guard let x` unwraps the existing binding under the same name.
            return
        value = self.value(clause.initializer, frame)
        if clause.pattern:
            value = Value(value.traces)
        for name, anchor in clause.names:
            bound = value.bind(self.point(anchor))
            if self.native_flow is not None:
                bound = self.native_flow.local_value(self, anchor, "", bound, frame, initialized=True)
            frame.local_names.add(name)
            frame.constants.pop(name, None)
            frame.values[name] = Value(bound.traces, bound.category, bound.type_name, bound.identity)

    def sqlite_database_call(self, call: Call, receiver: Value, frame: Frame) -> bool:
        """SDK calls that return a SQLiteDatabase: helper getters and Context/SQLiteDatabase openers."""
        self.opener_follow = False
        self.opener_certain = False
        self.opener_returns = False
        if self.language not in {"java", "kotlin"}:
            return False
        if call.name in SQLITE_GETTERS:
            return not call.args
        if call.name not in SQLITE_OPENERS:
            return False
        if call.receiver is None:
            return self.opener_database_type(call, receiver, frame)
        key = self.key(call.receiver)
        return (
            key in {"SQLiteDatabase", SQLITE_DATABASE}
            or bool(re.search(r"\b(?:Context|Activity|Application|Service)\b", receiver.type_name))
            or bool(re.fullmatch(r"(?i)(?:\w*context|ctx)(?:\(\))?", key or ""))
        )

    def opener_database_type(self, call: Call, receiver: Value, frame: Frame) -> bool:
        """Whether a receiverless opener's result is typed as the framework SQLiteDatabase.

        Without a project target the call is the framework opener. A project target the
        bounded flow's own resolution finds is always followed (`opener_follow`), so its
        sinks and returned taint stay in the analysis; the decision here only adds the
        database type to the result. It is added for an override, for a target declared to
        return SQLiteDatabase, and for a target shaped like Context.openOrCreateDatabase
        when an implicit receiver in scope may be a Context, whose inherited member wins.
        A wrong answer can therefore only add sink typing, never drop a flow.
        """
        flow = self.native_flow
        if flow is None:
            return True
        targets, relevant = flow.resolve(self, call, receiver, frame)
        if not targets:
            # A same-named project callable the call could reach (a value binding, a
            # callable of this file or package, a project import) that the flow cannot
            # resolve here is still followed, so the flow records why; the result keeps
            # the framework type. Framework imports and other classes' methods are not.
            self.opener_follow = relevant and self.opener_reachable(call, frame)
            return True
        self.opener_follow = True
        self.opener_returns = all(self.declared_return(target) for target in targets)
        for target in targets:
            modifiers = next(
                (child for child in target.node.named_children if child.type == "modifiers"), None
            )
            if "override" in flow.declaration_tokens(target.node) or re.search(
                r"@Override\b", target.analyzer.text(modifiers)
            ):
                self.opener_certain = True
                return True
        if all(self.declares_database(target) for target in targets):
            self.opener_certain = True
            return True
        if call.name != "openOrCreateDatabase" or not self.context_arguments(call, frame):
            return False
        kind = self.receiver_context(call.node, frame, classes=True)
        self.opener_certain = kind == "yes"
        return kind != "no"

    def opener_reachable(self, call: Call, frame: Frame) -> bool:
        """Whether an unresolved receiverless opener may still reach project code."""
        flow = self.native_flow
        if flow is None:
            return False
        if flow.value_binding(self, call, frame) is not None or flow.module_value_present(
            self, call.name, aliases=True
        ):
            return True
        namespace = flow.namespaces[id(self)]
        for target in flow.by_name.get(call.name, []):
            source = target.analyzer
            if source.language != self.language:
                continue
            if source.path == self.path or (
                not target.owner and namespace and flow.namespaces[id(source)] == namespace
            ):
                return True
        return any(
            not symbol.startswith(("android.", "androidx."))
            for symbol in flow.imported_symbols(self, call.name)
        )

    def context_arguments(self, call: Call, frame: Frame) -> bool:
        """Whether Context.openOrCreateDatabase(String, int, CursorFactory[, handler]) can
        take this call's arguments, so an implicit Context receiver's member would apply."""
        if len(call.args) not in {3, 4}:
            return False
        for index, argument in enumerate(call.args):
            text = self.text(argument).strip()
            value = frame.values.get(self.symbol_name(text)) if argument.type in IDENTIFIERS else None
            kind = value.type_name.rsplit(".", 1)[-1] if value is not None and value.type_name else ""
            if index == 0 and (
                argument.type in {"integer_literal", "decimal_integer_literal"} or kind in {"Int", "int"}
            ):
                return False
            if index == 1 and (argument.type in STRINGS or kind in {"String"}):
                return False
            if index >= 2 and (
                argument.type in STRINGS
                or argument.type in {"integer_literal", "decimal_integer_literal", "boolean_literal"}
                or (kind and kind not in {"CursorFactory", "DatabaseErrorHandler", "Any", "Object"})
            ):
                return False
        return True

    @staticmethod
    def declared_return(target: Any) -> str:
        """A project function's declared return type spelling, or "" when it declares none."""
        node = target.node
        declared = node.child_by_field_name("type") if target.analyzer.language == "java" else None
        if declared is None:
            after = False
            for child in node.children:
                if child.type in {"function_value_parameters", "formal_parameters"}:
                    after = True
                elif after and child.type in {"user_type", "nullable_type"}:
                    declared = child
                    break
                elif after and child.type in {"function_body", "block", "="}:
                    break
        return target.analyzer.text(declared) if declared is not None else ""

    @staticmethod
    def declares_database(target: Any) -> bool:
        """Whether a project function's declared return type is SQLiteDatabase."""
        node = target.node
        declared = node.child_by_field_name("type") if target.analyzer.language == "java" else None
        if declared is None:
            after = False
            for child in node.children:
                if child.type in {"function_value_parameters", "formal_parameters"}:
                    after = True
                elif after and child.type in {"user_type", "nullable_type"}:
                    declared = child
                    break
                elif after and child.type in {"function_body", "block", "="}:
                    break
        text = target.analyzer.text(declared) if declared is not None else ""
        return re.sub(r"\s+|\?$", "", text).rsplit(".", 1)[-1] == "SQLiteDatabase"

    def receiver_scope_lambda(self, node: Any) -> bool:
        """Whether a Kotlin lambda is the block of `x.run`, `x.apply` or `with(x)`."""
        return self.scope_receiver(node) is not None

    def scope_receiver(self, node: Any) -> Any:
        """The receiver expression of a `x.run`, `x.apply` or `with(x)` block lambda.

        The lambda may trail the call or be passed in parentheses (`x.run({ ... })`).
        """
        call = node.parent
        for _ in range(3):
            if call is None or call.type == "call_expression":
                break
            if call.type not in {"annotated_lambda", "value_argument", "value_arguments"}:
                return None
            call = call.parent
        if call is None or call.type != "call_expression" or not call.named_children:
            return None
        callee = call.named_children[0]
        arguments = call
        if callee.type == "call_expression" and callee.named_children:
            arguments, callee = callee, callee.named_children[0]  # `with(x) { }` wraps `with(x)`
        name = re.search(r"(\w+)\s*$", self.text(callee))
        if name is None:
            return None
        if name.group(1) == "with":
            values = next((part for part in arguments.named_children if part.type == "value_arguments"), None)
            entries = (
                [part for part in values.named_children if part.type == "value_argument"] if values else []
            )
            # `with(receiver = x)` names its receiver; otherwise it is the first argument.
            chosen = next(
                (
                    entry
                    for entry in entries
                    if entry.named_children and self.text(entry).startswith("receiver")
                ),
                entries[0] if entries else None,
            )
            return (
                chosen.named_children[-1] if chosen is not None and chosen.named_children else chosen
            ) or callee
        if callee.type == "navigation_expression" and name.group(1) in {"run", "apply"}:
            return callee.named_children[0] if callee.named_children else callee
        return None

    def scope_receiver_context(self, lambda_node: Any, frame: Frame, node: Any) -> str:
        """Whether the receiver bound by a `run`/`apply`/`with` block is a Context."""
        expression = self.scope_receiver(lambda_node)
        # `x!!`, `(x)` and `this.x` name the same receiver as `x`.
        for _ in range(4):
            if expression is None:
                break
            if expression.type == "parenthesized_expression" or (
                expression.type == "unary_expression" and self.text(expression).endswith("!!")
            ):
                expression = expression.named_children[0] if expression.named_children else None
            elif expression.type == "navigation_expression" and self.text(expression).startswith("this."):
                expression = expression.named_children[-1] if expression.named_children else None
                if expression is not None and expression.type == "navigation_suffix":
                    expression = expression.named_children[-1] if expression.named_children else None
            else:
                break
        if expression is None:
            return "maybe"
        if expression.type in STRINGS:
            return "no"
        accessor = re.search(r"(\w+)\s*(?:\(\s*\))?\s*$", self.text(expression))
        if accessor is not None and accessor.group(1) in CONTEXT_ACCESSORS:
            return "yes"  # requireContext(), getApplicationContext(), applicationContext ...
        if expression.type not in IDENTIFIERS:
            return "maybe"
        name = self.symbol_name(self.text(expression))
        bound = frame.values.get(name)
        if bound is not None and bound.type_name:
            return self.context_type(bound.type_name, node)
        current = lambda_node.parent
        while current is not None:
            if current.type in FUNCTIONS:
                declared = next((kind for pname, kind, _ in self.parameters(current) if pname == name), None)
                if declared:
                    return self.context_type(declared, node)
            current = current.parent
        if name in self.field_types:
            return self.context_type(self.field_types[name], node)
        return "maybe"

    def receiver_context(self, node: Any, frame: Frame, *, classes: bool) -> str:
        """Whether an implicit receiver in scope at `node` is a Context: "yes", "no" or "maybe".

        Walking outward from the call: a Kotlin scope-function receiver, an extension
        receiver (`fun Activity.f()`, `val Context.p get()`, an anonymous function with a
        receiver) and the block of `x.run`, `x.apply` or `with(x)` are receivers. With
        `classes`, the enclosing class-like scopes are too, as far as they reach: a nested
        class, object or companion (a Java static or implicitly static type) has no outer
        receiver, while inner and local classes, Kotlin anonymous objects, lambdas and
        local functions defer outward. Without `classes` (the target is a method of the
        enclosing class) the walk stops at the first class-like scope. Any receiver that
        is a Context wins; an unknown one leaves the answer open.
        """
        kotlin = self.language == "kotlin"
        answers: set[str] = set()
        aliased = kotlin and "this" in self.aliases
        unresolved_alias = False
        if aliased:
            # Use the value the scope lambda bound; re-evaluating the receiver could
            # re-run calls (or recurse through an opener used as its own receiver).
            bound = frame.values.get("this")
            answer = (
                "maybe"
                if bound is None
                else "no"
                if bound.category in {"text", "url", "intent", "request", "host", "scheme"}
                else self.context_type(bound.type_name, node)
                if bound.type_name
                else "maybe"
            )
            if answer == "maybe":
                # Let the innermost receiver block's own expression decide below.
                aliased, unresolved_alias = False, True
            else:
                answers.add(answer)
        current = node.parent
        while current is not None and "yes" not in answers:
            if (
                not kotlin
                and current.type == "method_declaration"
                and any(
                    child.type == "modifiers" and re.search(r"\bstatic\b", self.text(child))
                    for child in current.named_children
                )
            ):
                break  # a static method has no instance receiver
            if (
                kotlin
                and current.type in {"function_declaration", "anonymous_function", "property_declaration"}
                and any(child.type == "." for child in current.children)
            ):
                receiver_type = next(
                    (
                        child
                        for child in current.named_children
                        if child.type in {"user_type", "nullable_type"}
                        and child.end_byte
                        <= next(part.start_byte for part in current.children if part.type == ".")
                    ),
                    None,
                )
                answers.add(
                    self.context_type(self.text(receiver_type), node)
                    if receiver_type is not None
                    else "maybe"
                )
            elif kotlin and current.type == "lambda_literal" and self.receiver_scope_lambda(current):
                if aliased:
                    aliased = False  # the innermost receiver block is the bound alias above
                else:
                    answers.add(self.scope_receiver_context(current, frame, node))
                    unresolved_alias = False
            elif not kotlin and current.type == "object_creation_expression":
                if any(child.type == "class_body" for child in current.children):
                    if not classes:
                        break
                    kind = next((child for child in current.named_children if "type" in child.type), None)
                    answers.add(self.context_type(self.text(kind), node) if kind is not None else "maybe")
            elif current.type in {
                "class_declaration",
                "object_declaration",
                "companion_object",
                "object_literal",
                "enum_declaration",
                "record_declaration",
                "interface_declaration",
            }:
                if not classes:
                    break
                answers.add(self.class_context(current))
                modifiers = " ".join(
                    self.text(child) for child in current.named_children if child.type == "modifiers"
                )
                # A local class (declared in a function body) sees the enclosing
                # class's members, like an inner class.
                local = current.parent is not None and current.parent.type not in {
                    "source_file",
                    "program",
                    "class_body",
                    "enum_class_body",
                    "enum_body_declarations",
                    "interface_body",
                }
                if kotlin:
                    defers = current.type == "object_literal" or (
                        current.type == "class_declaration"
                        and (local or bool(re.search(r"\binner\b", modifiers)))
                    )
                else:
                    defers = (
                        current.type == "class_declaration"
                        and (local or not re.search(r"\bstatic\b", modifiers))
                        and current.parent is not None
                        and current.parent.type != "program"
                    )
                if not defers:
                    break
            current = current.parent
        if unresolved_alias:
            answers.add("maybe")
        return "yes" if "yes" in answers else "maybe" if "maybe" in answers else "no"

    def class_context(self, nominal: Any, depth: int = 0) -> str:
        """Whether a class-like declaration is a Context through its supertypes."""
        from .native_flow import NativeFlow

        key = (nominal.id, depth)
        if key in self.class_context_cache:
            return self.class_context_cache[key]
        self.class_context_cache[key] = "maybe"  # a cycle stays open
        references = NativeFlow.supertype_references(self, nominal)
        if references is None or depth >= 8:
            return "maybe"
        answers = {self.context_type(reference, nominal, depth + 1) for reference in references}
        answer = "yes" if "yes" in answers else "maybe" if "maybe" in answers else "no"
        self.class_context_cache[key] = answer
        return answer

    def context_type(self, spelling: str, node: Any, depth: int = 0) -> str:
        """Whether a type spelling names a Context: a source class by its ancestry, a
        framework Context type by name, a few common non-Context types, else unknown."""
        name = re.sub(r"<.*|\?$|\s+", "", spelling or "").rsplit(".", 1)[-1]
        if not name:
            return "maybe"
        flow = self.native_flow
        if flow is not None:
            owners = flow.class_owners(self, name, node)
            if len(owners) == 1:
                definitions = flow.class_definitions.get(next(iter(owners)), [])
                if len(definitions) == 1:
                    source, base = definitions[0]
                    return source.class_context(base, depth)
        imported = next(
            (
                declaration
                for declaration in self.imports
                if re.fullmatch(rf"[\w.]*\.{re.escape(name)}(?:\s+as\s+\w+)?", declaration)
            ),
            "",
        )
        if imported.startswith(("java.", "javax.", "kotlin.", "kotlinx.")) or name in NON_CONTEXT_TYPES:
            return "no"
        android = imported.startswith(("android.", "androidx.", "com.google.firebase."))
        if (imported and not android) or (
            flow is not None and not imported and flow.class_name_present(self, name)
        ):
            # A library type of another package (io.grpc.Context) or a source class the
            # flow cannot resolve (a nested class) is not known to be a Context by name.
            return "maybe"
        if re.fullmatch(r"Context|ContextWrapper|ContextThemeWrapper|\w*Activity|\w*Application", name):
            return "yes"
        if name in CONTEXT_SERVICE_TYPES or (name.endswith("Service") and android):
            return "yes"
        return "maybe"

    def identifier_value(self, name: str, frame: Frame, node: Any) -> Value:
        if (
            name == "intent"
            and name not in frame.values
            and name not in self.field_types
            and self.activity_scope
        ):
            return self.source(node, "Activity.intent property", "intent")
        if self.native_flow is not None:
            stored = self.native_flow.identifier(self, name, frame, node)
            if stored is not None:
                return stored
        return frame.values.get(name, Value(type_name=frame.types.get(name, self.field_types.get(name, ""))))

    def literal(self, node: Any) -> str | None:
        if not node or node.type not in STRINGS:
            return None
        text = self.text(node)
        # Escapes and interpolation require runtime interpretation; never treat them as an allowlist.
        if "\\" in text or "${" in text or text.startswith('"""') or self.kotlin_templates(node):
            return None
        return text[1:-1] if text.startswith(('"', "'")) and text[-1:] == text[:1] else None

    def unwrap(self, node: Any) -> Any:
        """The expression inside parentheses, casts, force-unwraps, try and value-argument wrappers."""
        while node is not None:
            if node.type == "value_argument":
                node = _field(node, "value") or (node.named_children[-1] if node.named_children else None)
            elif (
                self.language == "swift"
                and node.type == "tuple_expression"
                and len(node.named_children) == 1
                and not any(child.type == "," for child in node.children)
                and _field(node, "name") is None
            ):
                # Swift uses this node for ordinary parentheses too. Preserve
                # the enclosed binding/cast identity without flattening tuples.
                node = node.named_children[0]
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
            if any("interpolat" in part.type for part in _walk(node)) or self.kotlin_templates(node):
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
            name = self.symbol_name(self.text(node))
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

    @staticmethod
    def assignment_target(node: Any) -> Any:
        """The storage expression inside a grammar's assignable-target wrapper."""
        while (
            node is not None
            and node.type in {"directly_assignable_expression", "parenthesized_expression"}
            and len(node.named_children) == 1
        ):
            node = node.named_children[0]
        return node

    def navigation(self, node: Any) -> tuple[Any, str] | None:
        node = self.assignment_target(node)
        if node is None:
            return None
        if node.type == "field_access":
            return _field(node, "object"), self.text(_field(node, "field"))
        if node.type == "navigation_expression":
            target = _field(node, "target") or node.named_children[0]
            suffix = _field(node, "suffix") or node.named_children[-1]
            identifiers = [part for part in _walk(suffix) if part.type in IDENTIFIERS]
            return target, self.symbol_name(self.text(identifiers[-1]) if identifiers else self.text(suffix))
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
        receiver, name = navigation if navigation else (None, self.symbol_name(self.text(callee)))
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
        point = self.point(node)
        return Value(
            (Trace(hash((self.path, node.start_byte)), point, description, (steps + (point,))[-12:]),),
            category,
        )

    def archive_name(self, node: Any, entry: Value) -> Value:
        """Repeated immutable name reads share an origin only for the same known entry."""
        value = self.source(node, "Archive entry name", "text")
        if not entry.identity:
            return value
        trace = value.traces[0]
        return Value(
            (
                Trace(
                    hash((self.path, "archive-name", entry.identity)),
                    trace.source,
                    trace.description,
                    trace.steps,
                ),
            ),
            "text",
        )

    def changed(self, node: Any, value: Value) -> Value:
        # Checking one URL must not bless a later concatenation or an unknown helper's return value.
        return Value(
            tuple(
                Trace(
                    hash((node.start_byte, trace.origin)),
                    trace.source,
                    trace.description.removesuffix(BASENAME),
                    (trace.steps + (self.point(node),))[-12:],
                )
                for trace in value.traces
            ),
            "unknown",
            value.type_name,
        )

    def value(self, node: Any, frame: Frame) -> Value:
        if node is None or node.type in COMMENTS:
            return Value()
        if (
            self.language == "kotlin"
            and node.type in {"this", "this_expression"}
            and self.text(node).strip() == "this"
            and "this" in frame.values
        ):
            return frame.values["this"]
        if self.language == "swift" and node.type in {"tuple_expression", "as_expression"}:
            normalized = self.unwrap(node)
            if normalized is not node:
                # Parentheses/casts preserve the existing storage binding;
                # the written cast type establishes no concrete dispatch proof.
                return self.value(normalized, frame)
        if self.native_flow is not None:
            aggregate = self.native_flow.aggregate_value(self, node, frame)
            if aggregate is not None:
                return aggregate
            projected = self.native_flow.indexed_value(self, node, frame)
            if projected is not None:
                return projected
        if (
            self.native_flow is not None
            and node.type in {"this", "this_expression", "self_expression"}
            and self.text(node).strip() in {"this", "self"}
        ):
            return self.native_flow.self_value(self, frame)
        if node.type in STRINGS:
            interpolations = [
                part
                for part in _walk(node)
                if part.type in {"interpolated_expression", "interpolation", "interpolated_string_expression"}
            ]
            values = [self.value(part, frame) for part in interpolations]
            values += [self.identifier_value(name, frame, part) for name, part in self.kotlin_templates(node)]
            return self.changed(node, _union(values, "text"))
        if node.type in {"binary_expression", "additive_expression"}:
            rooted = self.rooted_path(node, frame)
            if rooted is not None:
                return rooted
        if node.type in IDENTIFIERS:
            return self.identifier_value(self.symbol_name(self.text(node)), frame, node)
        if node.type == "unary_expression" and self.text(node).rstrip().endswith("!!"):
            argument = _field(node, "argument")
            if argument is not None:
                return self.value(argument, frame)
        if node.type == "unary_expression" and self.text(node).lstrip().startswith("!"):
            # Kotlin attaches a prefix negation to the receiver of a following call.
            argument = _field(node, "argument")
            if argument is not None:
                return self.value(argument, frame)
        navigation = self.navigation(node)
        if navigation:
            base, member = navigation
            value = self.value(base, frame)
            if self.language == "kotlin" and member in SQLITE_ACCESSORS:
                return Value(type_name=SQLITE_DATABASE)
            if self.native_flow is not None:
                stored = self.native_flow.member(self, base, member, frame, value)
                if stored is not None:
                    return stored
            if self.text(base) in {"this", "self"}:
                return frame.values.get(member, Value(type_name=self.field_types.get(member, "")))
            if member in {"canonicalPath", "canonicalFile"} and value.category == "path":
                return Value(value.traces, "canonical-path", value.type_name)
            if member == "parentFile" and value.category in {"path", "canonical-path"}:
                return Value(value.traces, "path", "File")
            if member == "standardizedFileURL" and value.category in {"path", "url"}:
                return Value(value.traces, "canonical-path", value.type_name)
            if member == "path" and value.category == "canonical-path":
                return value
            if member in ENTRY_ITERATORS:
                return Value(type_name="ZipEntry", identity=f"{self.path}:{node.start_byte}")
            if member == "name" and ARCHIVE_ENTRY.fullmatch(value.type_name.strip()):
                return self.archive_name(node, value)
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
            if value.category == "user-activity" and member == "webpageURL":
                return self.source(node, "Universal link webpage URL", "url", value)
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
            database = self.sqlite_database_call(call, receiver, frame)
            follow, certain, returns = self.opener_follow, self.opener_certain, self.opener_returns
            self.opener_follow = self.opener_certain = self.opener_returns = False
            if follow and self.native_flow is not None:
                # A project opener is always followed; the framework type is only added,
                # and a possible (not certain) Context member never replaces a known
                # project return type.
                result = self.native_flow.call(self, call, frame, receiver, args)
                known = returns or (result is not None and bool(result.type_name))
                if database and (certain or not known):
                    return (
                        Value(result.traces, result.category, SQLITE_DATABASE, result.identity)
                        if result is not None
                        else Value(type_name=SQLITE_DATABASE)
                    )
                if database:
                    # A receiver that may be a Context could make the inherited framework
                    # member run instead; keeping the project type is a recorded guess.
                    self.native_flow.partial("opener receiver identity unresolved", self, call=call)
                if result is not None:
                    return result
            elif database:
                return Value(type_name=SQLITE_DATABASE)
            elif self.native_flow is not None:
                result = self.native_flow.call(self, call, frame, receiver, args)
                if result is not None:
                    return result
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
                if call.name == "URL" and self.labeled_argument(call, "fileURLWithPath") is not None:
                    return self.path_value(node, _union(args, "path", call.name))
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
                return Value(type_name="ZipEntry", identity=f"{self.path}:{node.start_byte}")
            if call.name == "getName" and ARCHIVE_ENTRY.fullmatch(receiver.type_name.strip()):
                return self.archive_name(node, receiver)
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
                return self.path_value(node, Value(_union([receiver, *args]).traces, "path", "File"))
            if call.name in {"getCanonicalPath", "getCanonicalFile"} and receiver.category == "path":
                return Value(receiver.traces, "canonical-path", receiver.type_name)
            if call.name == "getParentFile" and receiver.category in {"path", "canonical-path"}:
                return Value(receiver.traces, "path", "File")
            if call.name == "toPath" and receiver.category == "path":
                return Value(receiver.traces, "path", "Path")
            if call.name == "toRealPath" and receiver.category == "path":
                return Value(receiver.traces, "canonical-path", "Path")
            if call.name == "resolvingSymlinksInPath" and receiver.category in {"path", "url"}:
                return Value(receiver.traces, "canonical-path", receiver.type_name)
            if call.name in {"appendingPathComponent", "appending"} and self.language == "swift":
                return self.path_value(node, _union([receiver, *args], "path", "URL"))
            if simple in self.class_names and call.receiver is None:
                return Value(type_name=simple, identity=f"{self.path}:{node.start_byte}")
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
                from .native_guards import exits

                if exits(self, right):
                    return kept  # The fallback cannot reach this expression's continuation.
                merged = _union([kept, self.value(right, frame)])
                return Value(merged.traces, kept.category, kept.type_name, merged.identity)
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

    def path_value(self, node: Any, value: Value) -> Value:
        """Attach the exact construction and caller route without changing input provenance."""
        callers = self.native_flow.call_sites if self.native_flow is not None else []
        route = "|".join([*callers, f"{self.path}:{node.start_byte}"])
        point = self.point(node)
        return Value(
            tuple(
                Trace(
                    trace.origin,
                    trace.source,
                    trace.description,
                    (trace.steps + (point,))[-12:],
                    trace.path_safe,
                    route,
                )
                for trace in value.traces
            ),
            value.category,
            value.type_name,
            value.identity,
        )

    def rooted_path(self, node: Any, frame: Frame) -> Value | None:
        """Preserve only lexical path validation through a trusted absolute prefix."""
        left = _field(node, "left") or _field(node, "lhs")
        right = _field(node, "right") or _field(node, "rhs")
        if left is None or right is None or self.raw[left.end_byte : right.start_byte].strip() != b"+":
            return None
        prefix = self.literal(left)
        if (
            not prefix
            or prefix == "/"
            or prefix.startswith("//")
            or not prefix.startswith("/")
            or not prefix.endswith("/")
        ):
            return None
        if any(part in {".", ".."} for part in prefix.split("/")):
            return None
        value = self.value(right, frame)
        if not value.traces or any(
            trace_cuts(trace.description)
            or not (
                trace.path_safe
                or trace.description.endswith(BASENAME)
                or "no-parent-segments" in self.active_guards.get(trace.origin, set())
            )
            for trace in value.traces
        ):
            return None
        changed = self.changed(node, value)
        return Value(
            tuple(
                Trace(trace.origin, trace.source, trace.description, trace.steps, True)
                for trace in changed.traces
            ),
            "text",
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
            name = self.symbol_name(self.text(node))
            # Class fields are pre-bound in every frame; an immutable field stays
            # in frame.constants until a parameter, local or write shadows it.
            unshadowed_field = name in frame.constants and name not in frame.local_names
            if name in self.constants and (
                unshadowed_field or (name not in frame.values and name not in frame.types)
            ):
                return self.constants[name][1]
        if node is not None and node.type in IDENTIFIERS and self.function is not None:
            # A local declared with a literal and not reassigned (=, +=) before this use.
            name = self.symbol_name(self.text(node))
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
        return self.symbol_name(self.text(name)), values[-1] if values else None, self.text(type_node)

    def constraints(self, node: Any, frame: Frame) -> dict[GuardKey, set[str]]:
        if node is None:
            return {}
        if node.type == "parenthesized_expression" and node.named_children:
            return self.constraints(node.named_children[0], frame)
        left = _field(node, "left") or _field(node, "lhs")
        right = _field(node, "right") or _field(node, "rhs")
        if left and right:
            operator = self.raw[left.end_byte : right.start_byte].decode().strip()
            if operator == "&&":
                if re.search(r"\bfalse\b", self.text(node)):
                    return {}
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
            from .native_guards import receiver_negated

            if call.name in {"equals", "equalsIgnoreCase", "endsWith", "hasSuffix"} and receiver_negated(
                self, call.receiver
            ):
                return {}
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
                    and self.owned_suffix(literal[1:])
                ):
                    return {trace.origin: {"host"} for trace in receiver.traces}
        from .native_guards import path_predicate

        return path_predicate(self, node, frame)

    @staticmethod
    def hostname(value: str) -> bool:
        return bool(re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?", value)) and ".." not in value

    @classmethod
    def owned_suffix(cls, value: str) -> bool:
        """A host suffix only its owner can extend: a registrable domain, not a TLD or public suffix."""
        return cls.hostname(value) and "." in value and not SHARED_HOSTING.fullmatch(value)

    def comparison(self, expression: Any, literal_node: Any, frame: Frame) -> dict[GuardKey, set[str]]:
        value = self.value(expression, frame)
        literal = self.literal(literal_node)
        valid = value.category == "scheme" and literal == "https"
        valid |= value.category == "host" and literal is not None and self.hostname(literal)
        result: dict[GuardKey, set[str]] = (
            {trace.origin: {value.category} for trace in value.traces} if valid else {}
        )
        return result

    def emit(self, rule: str, node: Any, *, traces: tuple[Trace, ...] = (), **details: Any) -> None:
        if len(self.findings) >= MAX_AST_FINDINGS:
            self.truncated_rules.add(rule)
            return
        cuts = {kind for trace in traces for kind in trace_cuts(trace.description)}
        if "budget" in cuts:
            # A trace cut by the trace cap (an execution gap) may reach a sink
            # without a later call; record the budget so diagnostics match.
            self.truncated_rules.add(rule)
            if self.native_flow is not None:
                self.native_flow.partial("source trace budget", self, node=node)
        if "precision" in cuts:
            self.limited_rules.add(rule)
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
            # Distinct trace origins can share one source location and kind; report it once.
            sources: list[dict] = []
            for trace in traces:
                entry = {**self.location(trace.source), "kind": trace.description}
                if entry not in sources:
                    sources.append(entry)
            evidence["sources"] = sources
            evidence["flow"] = [{**self.location(step), "operation": step.type} for step in traces[0].steps]
        item = finding(
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
        if item["id"] not in self.finding_ids:
            self.finding_ids.add(item["id"])
            self.findings.append(item)
        elif rule == "AST-PATH-TRAVERSAL":
            existing = next(previous for previous in self.findings if previous["id"] == item["id"])
            previous_routes = {
                route for entry in existing["evidence"] for route in entry.get("modeled_routes", [])
            }
            if not set(evidence.get("modeled_routes", [])) <= previous_routes:
                if len(existing["evidence"]) < MAX_PATH_ROUTE_EVIDENCE:
                    existing["evidence"].append(evidence)
                else:
                    self.truncated_rules.add(rule)
                    if self.native_flow is not None:
                        self.native_flow.partial("path route evidence budget", self, node=node)
                    sentinel = (0, "unmodeled-path-route-budget")
                    if sentinel not in previous_routes:
                        existing["evidence"][-1].setdefault("modeled_routes", []).append(sentinel)

    def is_webview(self, node: Any, frame: Frame) -> bool:
        if node is None and self.language == "kotlin" and "this" in self.aliases:
            # Kotlin run/apply/with: an unqualified call targets the bound scope receiver.
            value = frame.values.get("this", Value())
        else:
            value = self.value(node, frame)
        return bool(re.search(r"\b(?:WebView|WKWebView|UIWebView)\b", value.type_name))

    def receiver_key(self, node: Any) -> str:
        """Bridge/JavaScript correlation key; Kotlin run/apply/with bind implicit and `this` receivers."""
        scope = self.aliases.get("this") if self.language == "kotlin" else None
        if scope is None or node is not None and self.text(node).strip() != "this":
            return self.key(node)
        key = self.key(scope)
        # Named receivers correlate by spelling like explicit calls; distinct
        # allocations such as two WebView(context).apply {} blocks never do.
        return key if re.fullmatch(r"[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*", key) else f"{key}@{scope.start_byte}"

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
                    and self.owned_suffix(literal[1:])
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
        self, call: Call, frame: Frame, guards: dict[GuardKey, set[str]], conditions: list[Any]
    ) -> None:
        receiver_key = self.receiver_key(call.receiver)
        self.check_security_call(call, frame)
        self.check_key_material(call, frame)
        self.check_intent_launch(call, frame)
        self.check_file_path(call, frame, guards, conditions)
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
                frame.javascript[self.receiver_key(settings.receiver)] = self.text(call.args[0])
        declared = self.spec_entry("sink", call, frame)
        if declared and len(call.args) > declared["argument"]:
            value = self.value(call.args[declared["argument"]], frame)
            unsafe = tuple(
                trace
                for trace in value.traces
                if declared["kind"] == "sql"
                or trace_cuts(trace.description)
                or not {"scheme", "host"} <= guards.get(trace.origin, set())
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
            if javascript_sink
            or trace_cuts(trace.description)
            or not {"scheme", "host"} <= guards.get(trace.origin, set())
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

    def compared_targets(self) -> set[str]:
        """Names whose component, package or class name a line of this function compares (built once).

        String contents are blanked, so a log message cannot pass for a comparison. A local assigned
        from an Intent's component or package counts for that Intent.
        """
        if self.target_names is None:
            code = re.sub(r'"(?:\\.|[^"\\\n])*"', '""', self.function_source)
            compared: set[str] = set()
            for line in code.splitlines():
                if TARGET_TOKEN.search(line) and COMPARISON.search(line):
                    compared.update(re.findall(r"[A-Za-z_]\w*", line))
            for match in TARGET_ALIAS.finditer(code):
                if match[1] in compared:
                    compared.add(match[2])
            self.target_names = compared
        return self.target_names

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
            # A comparison of the nested Intent's component or package, not a mere mention (such as a log).
            checked = name is not None and name in self.compared_targets()
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
        if target.type in IDENTIFIERS and self.symbol_name(self.text(target)) in self.aliases:
            target = self.aliases[self.symbol_name(self.text(target))]
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

    def check_file_path(
        self, call: Call, frame: Frame, guards: dict[GuardKey, set[str]], conditions: list[Any]
    ) -> None:
        simple = call.name.rsplit(".", 1)[-1]
        args = list(call.args)
        argument = None
        construction = simple == "File" or self.language == "swift"
        if self.language in {"java", "kotlin"}:
            # Context.openFileOutput and similar reject path separators, so they are not sinks.
            if simple in FILE_SINKS and call.receiver is None and simple not in self.class_names and args:
                argument = args[1] if simple == "File" and len(args) >= 2 else args[0]
            elif (
                self.language == "kotlin"
                and call.name
                in {"writeText", "writeBytes", "appendText", "appendBytes", "readText", "readBytes"}
                and self.value(call.receiver, frame).category in {"path", "canonical-path"}
            ):
                argument = call.receiver
                construction = False
            elif (
                self.key(call.receiver) in {"Files", "java.nio.file.Files"}
                and call.name
                in {
                    "newOutputStream",
                    "newInputStream",
                    "write",
                    "writeString",
                    "readAllBytes",
                    "readString",
                    "copy",
                    "move",
                }
                and args
            ):
                argument = args[0]
                construction = False
            elif call.name in {
                "mkdir",
                "mkdirs",
                "delete",
                "deleteRecursively",
                "createNewFile",
                "renameTo",
            } and self.value(call.receiver, frame).category in {"path", "canonical-path"}:
                argument = call.receiver
                construction = False
        elif self.language == "swift":
            if call.name == "appendingPathComponent" and args:
                argument = args[0]
            elif call.name == "appending":
                argument = self.labeled_argument(call, "path")
            elif call.name == "URL":
                argument = self.labeled_argument(call, "fileURLWithPath")
            elif call.name in {"write", "createFile"}:
                argument = (
                    self.labeled_argument(call, "to")
                    or self.labeled_argument(call, "toFile")
                    or self.labeled_argument(call, "atPath")
                )
                construction = False
            elif call.name in {"FileHandle", "Data", "NSData", "String", "NSString"}:
                argument = (
                    self.labeled_argument(call, "forWritingTo")
                    or self.labeled_argument(call, "forReadingFrom")
                    or self.labeled_argument(call, "contentsOfFile")
                    or self.labeled_argument(call, "contentsOf")
                )
                construction = False
        if argument is None or self.name_only(call.node):
            return
        if FILE_DESCRIPTOR.search(self.text(argument).strip()):
            return  # a FileDescriptor opened by the platform is not a path
        value = self.value(argument, frame)
        if construction:
            value = self.path_value(call.node, value)
        if "FileDescriptor" in value.type_name:
            return
        traces = tuple(
            trace
            for trace in value.traces
            if not trace.description.endswith(BASENAME) or trace_cuts(trace.description)
        )
        if not traces:
            return
        unsafe = tuple(
            trace
            for trace in traces
            if trace_cuts(trace.description)
            or (
                not trace.path_safe
                and "path-contained" not in guards.get(trace.origin, set())
                and "path-contained" not in guards.get((trace.origin, trace.path_route), set())
            )
        )
        if not unsafe:
            if not conditions:
                self.guarded_paths.update(
                    (trace.origin, trace.path_route) for trace in traces if trace.path_route
                )
            elif all(condition.type in {"lambda_expression", "lambda_literal"} for condition in conditions):
                # Within closures only, this dominated operation covers a construction
                # in the innermost closure; it never covers one from an enclosing scope.
                closure = conditions[-1]
                callers = self.native_flow.call_sites if self.native_flow is not None else []
                site = "|".join([*callers, f"{self.path}:"])
                self.guarded_paths.update(
                    (trace.origin, trace.path_route)
                    for trace in traces
                    if trace.path_route.startswith(site)
                    and trace.path_route[len(site) :].isdigit()
                    and closure.start_byte <= int(trace.path_route[len(site) :]) < closure.end_byte
                )
            return
        if not construction:
            self.unguarded_paths.update(
                (trace.origin, trace.path_route) for trace in unsafe if trace.path_route
            )
        if value.category in {"path", "canonical-path"} and not construction:
            # The corresponding path construction already carries a candidate.
            return
        self.emit(
            "AST-PATH-TRAVERSAL",
            call.node,
            traces=unsafe,
            sink=call.name,
            validation="same input is not contained by a dominating guard before this path operation",
            path_operation="construction" if construction else "file-io",
            modeled_routes=[(trace.origin, trace.path_route) for trace in unsafe],
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
        return receiver == simple and self.imports_type(qualified)

    def imports_type(self, qualified: str) -> bool:
        simple = qualified.rsplit(".", 1)[-1]
        if simple in self.class_names:
            return False
        explicit = {name for name in self.imports if name.rsplit(".", 1)[-1] == simple}
        if explicit:
            return qualified in explicit
        if qualified.rsplit(".", 1)[0] + ".*" not in self.imports:
            return False
        # A wildcard does not outrank a represented lexical or same-package
        # type. Do not turn project homonyms into framework API evidence.
        return self.native_flow is None or not (
            self.native_flow.lexical_type(self, simple) is not None
            or self.native_flow.class_owners(self, simple)
        )

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
                    receiver_type == simple and self.imports_type(qualified)
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
            if intent_node.type in IDENTIFIERS and self.symbol_name(self.text(intent_node)) in self.aliases:
                intent_node = self.aliases[self.symbol_name(self.text(intent_node))]
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

    def visit(self, node: Any, frame: Frame, guards: dict[GuardKey, set[str]], conditions: list[Any]) -> None:
        self.active_guards = guards
        if node.type in COMMENTS or node.type in FUNCTIONS and not _nested_initializer(node):
            return
        if node.type in {"lambda_expression", "lambda_literal"}:
            self.visit_scope_lambda(node, frame, guards, conditions, "", None, optional=True)
            return
        if node.type in STRINGS:
            for part in node.named_children:
                if "interpolat" in part.type:
                    self.visit(part, frame, guards, conditions)
            return
        if node.type in {
            "return_statement",
            "return_expression",
            "control_transfer_statement",
            "jump_expression",
        } and self.text(node).lstrip().startswith("return"):
            for part in node.named_children:
                self.visit(part, frame, guards, conditions)
            label_node = _field(node, "label") if self.language == "kotlin" else None
            expressions = [
                part
                for part in node.named_children
                if part.type not in {"return_keyword", "label"} and part != label_node
            ]
            labeled = self.language == "kotlin" and bool(re.match(r"return\s*@", self.text(node).lstrip()))
            label_target = self.kotlin_return_target(node, label_node) if labeled else True
            kotlin_nonlocal = self.language == "kotlin" and label_target is not False
            if (
                expressions
                and (not labeled or kotlin_nonlocal)
                and (not self.closure_depth or kotlin_nonlocal)
            ):
                if label_target is None or (
                    self.closure_depth and not self.kotlin_return_context_known(node, frame)
                ):
                    # Legal unlabeled Kotlin inline returns leave the function.
                    # Preserve possible values even when lookup/legality is not
                    # established; uncertainty must not sanitize a helper return.
                    if self.native_flow is not None:
                        self.native_flow.partial(
                            "Kotlin non-local return context unavailable", self, node=node
                        )
                    else:
                        self.limited_rules.update(RULES)
                self.return_values.append(self.value(expressions[-1], frame).bind(self.point(node)))
            return
        declaration = self.declaration(node)
        if declaration:
            name, expression, type_name = declaration
            frame.local_names.add(name)
            if expression:
                self.visit(expression, frame, guards, conditions)
            described = self.constant(expression, frame) if expression is not None else None
            if described:
                frame.constants[name] = described
            else:
                frame.constants.pop(name, None)
            value = self.value(expression, frame).bind(self.point(node))
            if self.native_flow is not None:
                value = self.native_flow.local_value(
                    self, node, type_name, value, frame, initialized=expression is not None
                )
            frame.values[name] = Value(
                value.traces, value.category, type_name or value.type_name, value.identity
            )
            if type_name:
                frame.types[name] = type_name
            return
        if node.type in {"assignment_expression", "assignment"}:
            left = self.assignment_target(
                _field(node, "left") or _field(node, "target") or next(iter(node.named_children), None)
            )
            right = (
                _field(node, "right")
                or _field(node, "result")
                or (node.named_children[-1] if len(node.named_children) > 1 else None)
            )
            if left and right and left != right:
                operator = self.text(_field(node, "operator"))
                previous = self.value(left, frame) if operator != "=" else None
                self.visit(right, frame, guards, conditions)
                key = self.key(left)
                if left.type in IDENTIFIERS:
                    described = self.constant(right, frame) if operator == "=" else None
                    if described:
                        frame.constants[key] = described
                    else:
                        frame.constants.pop(key, None)
                else:
                    # An element or member write changes the array it belongs to.
                    base = next((part for part in _walk(left) if part.type in IDENTIFIERS), None)
                    if base is not None:
                        frame.constants.pop(self.symbol_name(self.text(base)), None)
                value = self.value(right, frame).bind(self.point(node))
                if previous is not None:
                    value = (
                        self.native_flow.compound_value(
                            self, node, left, right, previous, value, operator, frame
                        )
                        if self.native_flow is not None
                        else self.changed(node, _union([previous, value], type_name=previous.type_name))
                    )
                if self.native_flow is not None and self.navigation(left) is not None:
                    self.native_flow.assign_member(self, left, value, frame)
                    return
                if key in frame.types or key in frame.values:
                    if self.native_flow is not None:
                        value = self.native_flow.local_value(
                            self,
                            left,
                            frame.types.get(key, ""),
                            value,
                            frame,
                            initialized=True,
                        )
                    frame.values[key] = Value(
                        value.traces, value.category, frame.types.get(key, value.type_name), value.identity
                    )
                    if self.native_flow is not None:
                        if left.type in IDENTIFIERS:
                            self.native_flow.assign_identifier(self, key, frame.values[key], frame)
                        else:
                            self.native_flow.assign_member(self, left, value, frame)
                elif self.native_flow is not None:
                    self.native_flow.assign_member(self, left, value, frame)
                return
        if node.type in {"if_statement", "if_expression"}:
            # Checks every clause of a multi-clause Swift condition establishes, in clause order.
            established: dict[GuardKey, set[str]] = {}
            bound: set[str] = set()
            if self.language == "swift":
                # Swift lays out `if let a = b, c { ... } else { ... }` as flat clauses that run
                # in source order like `&&`: each one sees the names bound and the checks
                # passed by the clauses before it, so it is evaluated in the branch frame.
                clauses, then_node, else_node = self.swift_clauses(node)
                branch = frame.copy()
                positive = {origin: checks.copy() for origin, checks in guards.items()}
                nested = conditions.copy()
                for clause in clauses:
                    if clause.condition is not None:
                        self.visit(clause.condition, branch, positive, nested)
                        self.navigation_policy(clause.condition, then_node, branch)
                        for origin, checks in self.constraints(clause.condition, branch).items():
                            positive.setdefault(origin, set()).update(checks)
                            established.setdefault(origin, set()).update(checks)
                    else:
                        if clause.initializer is not None:
                            self.visit(clause.initializer, branch, positive, nested)
                        self.bind_swift_clause(clause, branch)
                        bound.update(name for name, _ in clause.names)
                    if clause.node is not None:
                        nested.append(clause.node)
                # A clause's other effects reach both arms; the names it binds stay in the branch.
                for key in frame.values:
                    if key not in bound:
                        frame.values[key] = branch.values.get(key, frame.values[key])
                frame.bridges = branch.bridges.copy()
                frame.javascript = branch.javascript.copy()
                frame.object_fields = {key: values.copy() for key, values in branch.object_fields.items()}
                frame.constants = {
                    **{key: value for key, value in branch.constants.items() if key not in bound},
                    **{key: value for key, value in frame.constants.items() if key in bound},
                }
                single = len(clauses) == 1 and clauses[0].condition is not None
                condition = clauses[0].condition if single else None
                constraint_nodes = [clause.condition for clause in clauses if clause.condition is not None]
                before = frame.copy()
            else:
                condition = _field(node, "condition")
                if condition:
                    self.visit(condition, frame, guards, conditions)
                children = [child for child in node.named_children if child != condition]
                then_node = _field(node, "consequence") or (children[0] if children else None)
                else_node = _field(node, "alternative") or (children[1] if len(children) > 1 else None)
                constraint_nodes = [condition] if condition else []
                nested = [*conditions, condition] if condition else conditions
                self.navigation_policy(condition, then_node, frame)
                positive = {origin: checks.copy() for origin, checks in guards.items()}
                for part in constraint_nodes:
                    for origin, checks in self.constraints(part, frame).items():
                        positive.setdefault(origin, set()).update(checks)
                before = frame.copy()
                branch = frame.copy()
            if then_node:
                self.visit(then_node, branch, positive, nested)
            for name in bound:
                # Bindings end with the branch; an outer name one shadowed keeps its own value.
                if name in before.values:
                    branch.values[name] = before.values[name]
                else:
                    branch.values.pop(name, None)
                if name in before.constants:
                    branch.constants[name] = before.constants[name]
                else:
                    branch.constants.pop(name, None)
            alternative = before.copy()
            if else_node:
                # The else branch runs only when the condition is false; a guard it
                # establishes (for example an `else if ... return`) must not leak.
                alternative_guards = {origin: checks.copy() for origin, checks in guards.items()}
                self.visit(else_node, alternative, alternative_guards, nested)
            from .native_guards import exits, path_predicate

            # Continuation guards apply only to the statements that follow this `if`
            # in the same block, not to a switch case, when entry, loop body or else arm.
            statement = node.parent is not None and node.parent.type in BLOCKS
            if not statement or not constraint_nodes:
                pass
            elif condition is None:
                # A multi-clause Swift condition holds after the `if` only when its else exits.
                # Its checks are the ones made in clause order on the values the clauses saw,
                # never re-read through a name an `if let` shadowed.
                if exits(self, else_node):
                    for origin, checks in established.items():
                        guards.setdefault(origin, set()).update(checks)
            elif exits(self, then_node) and not else_node:
                continuation = path_predicate(self, condition, before, positive=False)
                for origin, checks in continuation.items():
                    guards.setdefault(origin, set()).update(checks)
                    if (
                        "path-contained" in checks
                        and not conditions
                        and not self.closure_depth
                        and isinstance(origin, tuple)
                    ):
                        self.guarded_paths.add(origin)
            elif exits(self, else_node):
                for origin, checks in self.constraints(condition, before).items():
                    guards.setdefault(origin, set()).update(checks)
                    if (
                        "path-contained" in checks
                        and not conditions
                        and not self.closure_depth
                        and isinstance(origin, tuple)
                    ):
                        self.guarded_paths.add(origin)
            # Conservatively retain both possible assignments after a branch. Do not apply its guard outside it.
            for key in before.values:
                previous = before.values[key]
                values = [branch.values.get(key, previous), alternative.values.get(key, previous)]
                # Untouched by both branches: the merge would rebuild the same value.
                if values[0] is previous and values[1] is previous and len(previous.traces) <= 8:
                    continue
                frame.values[key] = _union(
                    values,
                    values[0].category if values[0].category == values[1].category else "unknown",
                    type_name=before.values[key].type_name,
                )
            frame.bridges.update(branch.bridges)
            frame.bridges.update(alternative.bridges)
            for identity in branch.object_fields.keys() | alternative.object_fields.keys():
                one, two = branch.object_fields.get(identity, {}), alternative.object_fields.get(identity, {})
                frame.object_fields[identity] = {
                    key: _union(
                        [one.get(key, Value()), two.get(key, Value())],
                        one.get(key, Value()).category
                        if one.get(key, Value()).category == two.get(key, Value()).category
                        else "unknown",
                        one.get(key, Value()).type_name or two.get(key, Value()).type_name,
                    )
                    for key in one.keys() | two.keys()
                }
            frame.constants = {
                key: value for key, value in branch.constants.items() if key in alternative.constants
            }
            return
        if node.type == "guard_statement" and self.language == "swift":
            # Swift rejects a guard-else body that can fall through (return, throw, break,
            # continue or a Never call such as fatalError), so the continuation is guarded.
            clauses, _, body = self.swift_clauses(node)
            entry = frame.copy()
            entry_guards = {origin: checks.copy() for origin, checks in guards.items()}
            entry_conditions = conditions.copy()
            # Clauses run in source order in the enclosing scope, where `guard let` names stay
            # bound after the statement: a clause sees the names bound before it, and a later
            # binding replaces an earlier one that an earlier check was made on.
            for clause in clauses:
                if clause.condition is None:
                    if clause.initializer is not None:
                        self.visit(clause.initializer, frame, guards, conditions)
                    self.bind_swift_clause(clause, frame)
                    continue
                self.visit(clause.condition, frame, guards, conditions)
                for origin, checks in self.constraints(clause.condition, frame).items():
                    guards.setdefault(origin, set()).update(checks)
                    if (
                        "path-contained" in checks
                        and not conditions
                        and not self.closure_depth
                        and isinstance(origin, tuple)
                    ):
                        self.guarded_paths.add(origin)
                conditions.append(clause.condition)
            if body is not None:
                # The else body runs when a clause fails, from the state before the guard: no
                # condition or binding of the guard holds there, and it never falls through.
                markers = [clause.node for clause in clauses if clause.node is not None]
                alternative = entry.copy()
                self.visit(body, alternative, entry_guards, [*entry_conditions, *markers])
                self.active_guards = guards
                # Its stores to fields and objects outlive the exit: keep them as may-effects for
                # the continuation and the field summaries, as an `if` arm's are. Locals end here.
                for key, previous in entry.values.items():
                    value = alternative.values.get(key, previous)
                    if value is previous or key in entry.local_names:
                        continue
                    current = frame.values.get(key, previous)
                    frame.values[key] = _union(
                        [current, value],
                        current.category if current.category == value.category else "unknown",
                        type_name=previous.type_name,
                    )
                for identity, fields in alternative.object_fields.items():
                    stored = entry.object_fields.get(identity, {})
                    merged = frame.object_fields.setdefault(identity, {})
                    for key, value in fields.items():
                        if stored.get(key) is value:
                            continue
                        current = merged.get(key, Value())
                        merged[key] = _union(
                            [current, value],
                            current.category if current.category == value.category else "unknown",
                            current.type_name or value.type_name,
                        )
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
                if child.type == "guard_statement" and self.language == "swift":
                    # `guard let` names are locals of this block like declarations.
                    declared.update(
                        name for clause in self.swift_clauses(child)[0] for name, _ in clause.names
                    )
                self.visit(child, local, local_guards, local_conditions)
                from .native_guards import exits

                if exits(self, child):
                    break
            for key in frame.values:
                if key not in declared:
                    frame.values[key] = local.values[key]
            frame.bridges = local.bridges
            frame.javascript = local.javascript
            frame.object_fields = local.object_fields
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
            scope = self.scope_function(call)
            with_call = self.kotlin_with_call(call)
            with_arguments = self.kotlin_with_arguments(call) if with_call is not None else None
            if with_call is not None and with_arguments is None:
                if self.native_flow is not None:
                    self.native_flow.partial("Kotlin non-local return context unavailable", self, node=node)
                else:
                    self.limited_rules.update(RULES)
            if with_arguments is not None:
                receiver_lambda = self.scope_lambda_argument(with_arguments["receiver"])
                if receiver_lambda is not None and receiver_lambda.type == "lambda_literal":
                    # Inspect possible receiver-lambda sinks once, including
                    # trailing forms whose receiver belongs to the inner call.
                    # Only unshadowed stdlib identity excludes non-local returns.
                    self.visit_receiver_lambda(receiver_lambda, frame, guards, conditions)
            lambdas = self.trailing_lambdas(node)
            for arg in call.args:
                argument = self.scope_lambda_argument(arg)
                if with_arguments is not None and argument is not None and argument.type == "lambda_literal":
                    # Receiver-lambda evidence was inspected separately above.
                    # Only the block parameter gets an inline scope binding.
                    if arg == with_arguments.get("block"):
                        lambdas.append(argument)
                elif scope is not None and argument is not None and argument.type == "lambda_literal":
                    # Kotlin permits both f { ... } and f(block = { ... }).
                    # Bind either spelling once; the generic visitor has no
                    # receiver and cannot establish an inline return context.
                    lambdas.append(argument)
                else:
                    self.visit(arg, frame, guards, conditions)
            if self.native_flow is not None:
                self.native_flow.active_guards = guards
                self.native_flow.active_conditions = conditions
                self.value(call.node, frame)
            self.check_call(call, frame, guards, conditions)
            self.release_constants(call, frame)
            callee = self.text(node.named_children[0]) if node.named_children else ""
            for lambda_node in lambdas:
                if scope is not None:
                    # x?.let {} may not run, and return@ may leave the lambda early.
                    optional = bool(re.search(r"\?\.\s*\w+\s*$", callee)) or "return@" in self.text(
                        lambda_node
                    )
                    self.visit_scope_lambda(lambda_node, frame, guards, conditions, *scope, optional)
                elif self.language == "swift" and call.name == "onOpenURL":
                    self.visit_open_url_callback(lambda_node, frame, guards, conditions)
                else:
                    # An unfollowed closure may fill any array it names.
                    kotlin_return = False
                    for part in _walk(lambda_node):
                        if part.type in IDENTIFIERS:
                            frame.constants.pop(self.symbol_name(self.text(part)), None)
                        if self.language == "kotlin" and part.type in {
                            "return_expression",
                            "jump_expression",
                        }:
                            text = self.text(part).lstrip()
                            labeled = bool(re.match(r"return\s*@", text))
                            kotlin_return |= text.startswith("return") and (
                                not labeled
                                or self.kotlin_return_target(part, _field(part, "label")) is not False
                            )
                    if kotlin_return:
                        # Unknown/custom inline calls still have possible
                        # non-local values, but no receiver/parameter proof.
                        self.visit_scope_lambda(
                            lambda_node, frame, guards, conditions, "", None, optional=True
                        )
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
        with_call = self.kotlin_with_call(call)
        if with_call is not None:
            arguments = self.kotlin_with_arguments(call)
            return ("with", arguments["receiver"]) if arguments is not None else None
        if call.name in SCOPE_FUNCTIONS - {"with"}:
            return call.name, call.receiver
        return None

    def scope_lambda_argument(self, node: Any) -> Any:
        argument = self.unwrap(node)
        if argument is not None and argument.type == "labeled_expression" and argument.named_children:
            argument = self.unwrap(argument.named_children[-1])
        return argument

    def kotlin_with_call(self, call: Call) -> Call | None:
        """The argument-bearing with call, including a trailing-lambda outer call."""
        if self.language != "kotlin":
            return None
        if call.name == "with" and call.receiver is None:
            return call
        callee = call.node.named_children[0] if call.node.named_children else None
        inner = self.call(callee) if callee is not None and callee.type == "call_expression" else None
        return inner if inner is not None and inner.name == "with" and inner.receiver is None else None

    def kotlin_with_arguments(self, call: Call) -> dict[str, Any] | None:
        """Bind the two stdlib parameter names from CST labels, never lexical order.

        Positional arguments retain their declared slot. Duplicate/unknown names,
        multiple bodies and unsupported callback values do not certify a scope.
        """
        target = self.kotlin_with_call(call)
        if target is None:
            return None
        arguments = self.call_arguments(target)
        bound: dict[str, Any] = {}
        slots = ("receiver", "block")
        rows = arguments.named_children if arguments is not None else []
        if len(rows) > len(slots):
            return None
        for index, row in enumerate(rows):
            named = any(child.type == "=" for child in row.children)
            parts = row.named_children
            if not parts:
                return None
            name = self.text(parts[0]).strip("`") if named else slots[index]
            if name not in slots or name in bound:
                return None
            bound[name] = _field(row, "value") or parts[-1]
        trailing = self.trailing_lambdas(call.node)
        if target.node != call.node:
            trailing += self.trailing_lambdas(target.node)
        if "receiver" not in bound or len(trailing) > 1 or (trailing and "block" in bound):
            return None
        if "block" in bound:
            block = self.scope_lambda_argument(bound["block"])
            if block is None or block.type != "lambda_literal":
                return None
        elif not trailing:
            return None
        return bound

    def kotlin_return_context_known(self, node: Any, frame: Frame) -> bool:
        """Recognize only unshadowed built-in inline scope contexts, not Kotlin execution.

        The ancestor walk is bounded; declaration/import indexes are prepared
        once, and project callables are looked up by name without rescanning files.
        A custom inline/noninline/crossinline declaration never gains stdlib
        identity merely because its name is let/use/etc.
        """
        current = node.parent
        for _ in range(64):
            if current is None or current.type in FUNCTIONS:
                return current == self.function
            if current.type in {"lambda_expression", "lambda_literal"}:
                if (current.start_byte, current.end_byte) not in frame.kotlin_bound_scopes:
                    # The callee's spelling alone is insufficient: generic
                    # lambda visits do not bind it/this or an explicit parameter.
                    return False
                parent = current.parent
                while parent is not None and parent.type in {
                    "annotated_lambda",
                    "call_suffix",
                    "value_argument",
                    "value_arguments",
                    "parenthesized_expression",
                    "labeled_expression",
                }:
                    parent = parent.parent
                call = self.call(parent) if parent is not None else None
                scope = self.scope_function(call) if call is not None else None
                if scope is None:
                    return False
                name = scope[0]
                if not self.kotlin_scope_identity_known(name, frame):
                    return False
            current = current.parent
        return False

    def kotlin_scope_identity_known(self, name: str, frame: Frame) -> bool:
        """Only an unshadowed scope name can establish stdlib return semantics."""
        name = self.symbol_name(name)
        return not (
            self.kotlin_scope_import_unavailable is not None
            or name in self.kotlin_scope_shadows
            or name in self.defined_functions
            or name in frame.values
            or name in frame.local_names
            or self.native_flow is not None
            and (
                name in self.native_flow.by_name
                # Top-level callable val/var bindings also shadow scope names.
                # Reuse the prepared package/import visibility index; a possible
                # property binding supplies uncertainty, never stdlib identity.
                or self.native_flow.module_value_present(self, name)
            )
        )

    def kotlin_return_target(self, node: Any, label: Any) -> bool | None:
        """Resolve the nearest Kotlin function/lambda label; None remains partial.

        A named function has its own return label, but an intervening explicit
        lambda label or implicit callee label with the same name shadows it.
        The bounded ancestor walk never assumes that an unresolved label is local.
        """
        name = self.text(label).strip("`")
        if not name:
            return None
        current = node.parent
        for _ in range(64):
            if current is None:
                return None
            if current.type in FUNCTIONS:
                if self.text(_field(current, "name")).strip("`") == name:
                    return current == self.function
                return None
            if current.type in {"lambda_expression", "lambda_literal"}:
                parent = current.parent
                explicit = False
                for _ in range(8):
                    if parent is None or parent.type not in {
                        "annotated_lambda",
                        "labeled_expression",
                        "call_suffix",
                        "value_argument",
                        "value_arguments",
                        "parenthesized_expression",
                    }:
                        break
                    labels = [child for child in parent.named_children if child.type == "label"]
                    explicit |= bool(labels)
                    if any(self.text(child).rstrip("@ ").strip("`") == name for child in labels):
                        return False
                    parent = parent.parent
                call = self.call(parent) if parent is not None else None
                if call is not None and not explicit:
                    callee = call.node.named_children[0] if call.node.named_children else None
                    inner = (
                        self.call(callee) if callee is not None and callee.type == "call_expression" else None
                    )
                    if (inner or call).name.strip("`") == name:
                        return False
            current = current.parent
        return None

    def visit_receiver_lambda(
        self,
        node: Any,
        frame: Frame,
        guards: dict[GuardKey, set[str]],
        conditions: list[Any],
    ) -> None:
        """Inspect a callable receiver conservatively, without asserting execution.

        An unshadowed stdlib with receives a callable value, so its receiver's
        returns cannot supply the enclosing function's summary. A custom with
        may inline that lambda: retain possible non-local returns with the
        generic visitor's explicit uncertainty and optional closure effects.
        """
        if not self.kotlin_scope_identity_known("with", frame):
            self.visit_scope_lambda(node, frame, guards, conditions, "", None, optional=True)
            return
        returns = self.return_values
        self.return_values = []
        try:
            self.visit_scope_lambda(node, frame, guards, conditions, "", None, optional=True)
        finally:
            self.return_values = returns

    def visit_open_url_callback(
        self, node: Any, frame: Frame, guards: dict[GuardKey, set[str]], conditions: list[Any]
    ) -> None:
        """SwiftUI `.onOpenURL { url in ... }`: the closure parameter is an external URL.

        The callback runs later, so its body is analyzed in an isolated copy and
        does not change the enclosing frame.
        """
        signature = next((part for part in node.named_children if part.type == "lambda_function_type"), None)
        parameters = (
            next(
                (part for part in signature.named_children if part.type == "lambda_function_type_parameters"),
                None,
            )
            if signature is not None
            else None
        )
        names = (
            [self.symbol_name(self.text(part)) for part in _walk(parameters) if part.type in IDENTIFIERS]
            if parameters is not None
            else []
        )
        name = names[0] if names else "$0"
        local = frame.copy()
        local.local_names.add(name)
        local.constants.pop(name, None)
        local.values[name] = self.source(
            parameters if parameters is not None else node, "SwiftUI onOpenURL URL", "url"
        )
        local_guards = {origin: checks.copy() for origin, checks in guards.items()}
        self.closure_depth += 1
        try:
            for child in node.named_children:
                if child is not signature:
                    self.visit(child, local, local_guards, [*conditions, node])
        finally:
            self.closure_depth -= 1

    def visit_scope_lambda(
        self,
        node: Any,
        frame: Frame,
        guards: dict[GuardKey, set[str]],
        conditions: list[Any],
        scope: str,
        receiver: Any,
        optional: bool = False,
    ) -> None:
        """Follow a scope function's lambda once, as a block whose parameter is the receiver."""
        local = frame.copy()
        if scope:
            local.kotlin_bound_scopes.add((node.start_byte, node.end_byte))
        parameters = next((part for part in node.named_children if part.type == "lambda_parameters"), None)
        names = (
            [self.symbol_name(self.text(part)) for part in _walk(parameters) if part.type in IDENTIFIERS]
            if parameters
            else []
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
        elif scope in {"run", "apply", "with"} and receiver is not None:
            # Receiver-style scopes introduce a lexical this. Keep it in the
            # copied frame so nested scopes restore their enclosing receiver,
            # and a non-local return sees the scope value, not the class object.
            declared.add("this")
            local.values["this"] = self.value(receiver, frame)
            # An unqualified member call in this lambda targets the scope receiver.
            self.aliases["this"] = receiver
        local_guards = {origin: checks.copy() for origin, checks in guards.items()}
        self.closure_depth += 1
        try:
            for child in node.named_children:
                if child is parameters:
                    continue
                parsed = self.declaration(child)
                if parsed:
                    declared.add(parsed[0])
                self.visit(child, local, local_guards, [*conditions, node])
        finally:
            self.closure_depth -= 1
        self.aliases = saved
        for key in frame.values:
            changed = local.values[key]
            if key in declared or changed is frame.values[key]:
                continue
            if optional:
                # Like a branch without else: keep the value from before and the lambda's.
                values = [frame.values[key], changed]
                frame.values[key] = _union(
                    values,
                    values[0].category if values[0].category == values[1].category else "unknown",
                    type_name=frame.values[key].type_name,
                )
            else:
                frame.values[key] = changed
        if optional:
            frame.bridges.update(local.bridges)
            frame.javascript.update(local.javascript)
            for identity in frame.object_fields.keys() | local.object_fields.keys():
                previous, written = (
                    frame.object_fields.get(identity, {}),
                    local.object_fields.get(identity, {}),
                )
                frame.object_fields[identity] = {
                    key: _union(
                        [previous.get(key, Value()), written.get(key, Value())],
                        previous.get(key, Value()).category
                        if previous.get(key, Value()).category == written.get(key, Value()).category
                        else "unknown",
                        previous.get(key, Value()).type_name or written.get(key, Value()).type_name,
                    )
                    for key in previous.keys() | written.keys()
                }
            frame.constants = {
                key: value
                for key, value in frame.constants.items()
                if key in declared or local.constants.get(key) == value
            }
        else:
            frame.bridges = local.bridges
            frame.javascript = local.javascript
            frame.object_fields = local.object_fields
            frame.constants = {
                **{key: value for key, value in local.constants.items() if key not in declared},
                **{key: value for key, value in frame.constants.items() if key in declared},
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
                frame.constants.pop(self.symbol_name(self.text(target)), None)

    def parameters(self, function: Any) -> list[tuple[str, str, Any]]:
        parameters = _field(function, "parameters") or next(
            (node for node in function.named_children if node.type == "function_value_parameters"), None
        )
        if function.type == "anonymous_initializer":
            # A Kotlin init block sees the primary constructor's parameters.
            owner = function.parent.parent if function.parent is not None else None
            primary = (
                next((node for node in owner.named_children if node.type == "primary_constructor"), None)
                if owner is not None
                else None
            )
            parameters = (
                next((node for node in primary.named_children if node.type == "class_parameters"), None)
                if primary is not None
                else None
            )
            if parameters is None:
                return []
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
                        if part.type
                        in {
                            "user_type",
                            "nullable_type",
                            "dictionary_type",
                            "function_type",
                            "array_type",
                            "tuple_type",
                        }
                    ),
                    None,
                )
            if name:
                result.append((self.symbol_name(self.text(name)), self.text(type_node), node))
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

    def nominal_fields(self, nominal: Any) -> list[tuple[str, Any, str, bool]]:
        from .native_flow import NOMINAL_BODIES

        key = (nominal.start_byte, nominal.end_byte)
        if key not in self.class_field_nodes:
            declarations = []
            for body in nominal.named_children:
                if body.type in NOMINAL_BODIES:
                    for node in body.named_children:
                        if node.type == "enum_body_declarations":
                            declarations.extend(node.named_children)
                        else:
                            declarations.append(node)
                elif body.type == "formal_parameters" and nominal.type == "record_declaration":
                    declarations.extend(body.named_children)
                elif body.type == "primary_constructor":
                    for parameters in body.named_children:
                        if parameters.type == "class_parameters":
                            declarations.extend(
                                node
                                for node in parameters.named_children
                                if any(child.type in {"val", "var"} for child in node.children)
                            )
            self.class_field_nodes[key] = [
                node
                for node in declarations
                if node.type
                in {"field_declaration", "property_declaration", "formal_parameter", "class_parameter"}
            ]
        result = []
        implicit_static = nominal.type in {
            "interface_declaration",
            "annotation_type_declaration",
            "object_declaration",
        }
        for declaration in self.class_field_nodes[key]:
            modifiers = next(
                (child for child in declaration.named_children if child.type == "modifiers"), None
            )
            static = implicit_static or bool(
                modifiers is not None and re.search(r"\b(?:static|class)\b", self.text(modifiers))
            )
            if declaration.type == "formal_parameter":
                result.append(
                    (
                        self.text(_field(declaration, "name")),
                        None,
                        self.text(_field(declaration, "type")),
                        False,
                    )
                )
                continue
            if declaration.type == "class_parameter":
                name = next(
                    (child for child in declaration.named_children if child.type in IDENTIFIERS), None
                )
                type_node = next(
                    (
                        child
                        for child in declaration.named_children
                        if child.type in {"user_type", "nullable_type", "function_type"}
                    ),
                    None,
                )
                result.append((self.symbol_name(self.text(name)), None, self.text(type_node), False))
                continue
            nodes = declaration.named_children if declaration.type == "field_declaration" else [declaration]
            for node in nodes:
                parsed = self.declaration(node)
                if parsed:
                    result.append((*parsed, static))
        return result

    def class_fields(self, function: Any) -> dict[str, str]:
        from .native_flow import NativeFlow

        boundary = NativeFlow.enclosing_scope(function)
        self.static_fields = set()
        self.unavailable_fields = set()
        fields = {}
        if boundary is not None and boundary.kind == "nominal":
            modifiers = NativeFlow.declaration_tokens(
                _accessor_property(function) if function.type in ACCESSORS else function
            )
            static_method = bool(modifiers & {"static", "class"})
            for name, expression, type_name, static in self.nominal_fields(boundary.node):
                if static_method and not static:
                    continue
                if static:
                    self.static_fields.add(name)
                fields[name] = type_name or self.value(expression, Frame()).type_name
            key = (boundary.node.start_byte, boundary.node.end_byte)
            for declaration in self.class_field_nodes.get(key, []):
                if declaration.type == "property_declaration" and any(
                    child.type in {"computed_property", "getter", "setter", "property_delegate"}
                    for child in declaration.named_children
                ):
                    parsed = self.declaration(declaration)
                    if parsed:
                        self.unavailable_fields.add(parsed[0])
        return fields

    def start_function(self, function: Any) -> Frame:
        self.finding_start = len(self.findings)
        self.pending_paths = []
        self.active_guards = {}
        name = _field(function, "name")
        self.scope = self.symbol_name(self.text(name))
        if function.type in ACCESSORS:
            # Accessor findings name their property.
            self.scope = (self.declaration(_accessor_property(function)) or ("",))[0]
        elif function.type in INITIALIZERS:
            self.scope = "deinit" if function.type == "deinit_declaration" else "init"
        self.function = function
        self.function_source = self.text(function)
        self.path_guarded = self.action_hint = None
        self.intent_checks = 0
        self.literal_table = None
        self.private_keys = None
        self.target_names = None
        self.aliases = {}
        self.field_types = self.class_fields(function)
        self.return_values = []
        self.closure_depth = 0
        self.guarded_paths = set()
        self.unguarded_paths = set()
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
                # Framework activities and project bases such as BaseActivity<VB>().
                r"\b\w*Activity\b",
                self.text(base),
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
        frame = Frame(types={**self.field_types, **self.parameter_types})
        frame.values.update({name: Value(type_name=kind) for name, kind in self.field_types.items()})
        # Typed field values must not hide immutable material from this file.
        # Parameters shadow fields; subsequent local writes still invalidate it.
        frame.constants.update(
            {
                name: self.constants[name][0]
                for name in self.field_types
                if name in self.constants and name not in self.parameter_types
            }
        )
        if self.native_flow is not None:
            frame.values.update(self.native_flow.initial_fields(self, function))
            self.native_flow.initialize_fields(self, frame)
        for name, type_name, node in parameters:
            frame.local_names.add(name)
            frame.values[name] = (
                self.native_flow.parameter_value(self, node, type_name)
                if self.native_flow is not None
                else Value(type_name=type_name)
            )
            if ARCHIVE_ENTRY.fullmatch(type_name.strip()):
                frame.values[name] = Value(type_name=type_name, identity=f"{self.path}:{node.start_byte}")
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
                self.language == "swift"
                and self.scope in {"application", "scene"}
                and re.search(r"\bNSUserActivity\b", type_name)
            ):
                category, description = "user-activity", "iOS universal link user activity parameter"
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
                frame.values[name] = Value(
                    value.traces, value.category, type_name, frame.values[name].identity
                )
        if function.type in ACCESSORS:
            # set(value), willSet/didSet names and Kotlin's backing `field` are accessor
            # locals holding what was stored in the property, not same-named class fields.
            names = [self.text(node) for node in function.named_children if node.type in IDENTIFIERS]
            implicit = {
                "computed_setter": "newValue",
                "willset_clause": "newValue",
                "didset_clause": "oldValue",
            }
            if not names and function.type in implicit:
                names = [implicit[function.type]]
            for name in [*names, *(["field"] if self.language == "kotlin" else [])]:
                frame.local_names.add(name)
                frame.values[name] = frame.values.get(self.scope, Value())
        return frame

    def finish_paths(self) -> None:
        safe = self.guarded_paths - self.unguarded_paths
        if not safe:
            return
        self.close_path_routes(safe, scope=self.scope)
        for analyzer, identity, origins in self.pending_paths:
            if origins and origins <= safe:
                analyzer.close_path_routes(origins, identity=identity)

    def close_path_routes(
        self, safe: set[tuple[int, str]], *, identity: str | None = None, scope: str | None = None
    ) -> None:
        retained = []
        for item in self.findings:
            if item["rule_id"] != "AST-PATH-TRAVERSAL" or identity is not None and item["id"] != identity:
                retained.append(item)
                continue
            evidence = []
            for entry in item["evidence"]:
                routes = set(entry.get("modeled_routes", []))
                if (
                    entry.get("path_operation") == "construction"
                    and routes
                    and routes <= safe
                    and (scope is None or entry.get("function") == scope)
                ):
                    continue
                evidence.append(entry)
            if evidence:
                item["evidence"] = evidence
                retained.append(item)
        self.findings[:] = retained
        self.finding_ids = {item["id"] for item in self.findings}

    def prepare(self, root: Any, nodes: list[Any]) -> None:
        self.class_field_nodes.clear()
        self.kotlin_scope_import_unavailable = None
        self.kotlin_scope_import_reported = False
        for node in nodes:
            if (
                self.language == "kotlin"
                and node.type == "ERROR"
                and node.parent == root
                and re.match(r"import\b", self.text(node).lstrip())
            ):
                # Recovery may not retain a complete import node. Its absence
                # cannot establish that stdlib scope identities are unshadowed.
                if self.kotlin_scope_import_unavailable is None:
                    self.kotlin_scope_import_unavailable = node
                self.limited_rules.update(RULES)
            if node.type in {"import_declaration", "import_header", "import"}:
                raw_import = re.sub(r"^import\s+|;\s*$", "", self.text(node)).strip()
                imported = self.normalized_import_name(raw_import)
                self.imports.add(raw_import if imported is None else imported)
                if self.language == "kotlin":
                    following = node.next_named_sibling
                    comment_nodes = 0
                    # Comments may sit between the represented import prefix
                    # and its recovered tail. Inspect only adjacent CST siblings
                    # once at prepare, bounded by the existing node inventory.
                    while following is not None and following.type in COMMENTS and comment_nodes < len(nodes):
                        comment_nodes += 1
                        following = following.next_named_sibling
                    recovered_tail = following is not None and (
                        following.type in COMMENTS
                        or following.type == "ERROR"
                        and (comment_nodes > 0 or following.start_point[0] == node.end_point[0])
                    )
                    if imported is None or node.has_error or recovered_tail:
                        # Unsupported comments, aliases and exotic forms are
                        # unresolved imports; keep raw evidence and withdraw all
                        # stdlib scope identities rather than guessing a leaf.
                        if self.kotlin_scope_import_unavailable is None:
                            self.kotlin_scope_import_unavailable = node
                        self.limited_rules.update(RULES)
                        continue
                    parts = re.split(r"\s+as\s+", imported, maxsplit=1)
                    target = parts[0]
                    visible = parts[-1] if len(parts) == 2 else target.rsplit(".", 1)[-1]
                    if visible == "*" and target not in {"kotlin.*", "kotlin.io.*"}:
                        self.kotlin_scope_shadows.update(SCOPE_FUNCTIONS)
                    elif visible in SCOPE_FUNCTIONS and target != (
                        "kotlin.io.use" if visible == "use" else "kotlin." + visible
                    ):
                        self.kotlin_scope_shadows.add(visible)
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
            if node.type in FUNCTIONS and node.type not in ACCESSORS | INITIALIZERS:
                self.defined_functions.add(self.symbol_name(self.text(_field(node, "name"))))
            if node.type == "object_declaration":
                name = next(
                    (part for part in node.named_children if part.type in IDENTIFIERS | {"type_identifier"}),
                    None,
                )
                if name is not None:
                    self.class_names.add(self.text(name))
        self.collect_constants(root)

    def analyze(self, root: Any, nodes: list[Any] | None = None, *, prepared: bool = False) -> None:
        nodes = list(_walk(root)) if nodes is None else nodes
        if not prepared:
            self.prepare(root, nodes)
        if (
            self.kotlin_scope_import_unavailable is not None
            and self.native_flow is not None
            and not self.kotlin_scope_import_reported
        ):
            self.native_flow.partial(
                "Kotlin scope import identity unavailable", self, node=self.kotlin_scope_import_unavailable
            )
            self.kotlin_scope_import_reported = True
        for function in nodes:
            if not _analysis_unit(function):
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
            frame = self.start_function(function)
            body = _function_body(function)
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
                if self.native_flow is not None:
                    self.native_flow.finish(self, function, frame)
                self.finish_paths()
            else:
                self.function_counts["without_body"] += 1


def _source_path(source: Any) -> str:
    path = (
        source.get("path")
        if isinstance(source, dict)
        else source[0]
        if isinstance(source, (tuple, list)) and source
        else ""
    )
    return path if isinstance(path, str) else ""


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
    parsed = skipped = total = unsupported_files = 0
    seen_languages: set[str] = set()
    unsupported: set[str] = set()
    pattern_exclusions: dict[str, dict[str, list[dict[str, int]]]] = {}
    file_metrics = []
    # Execution gaps (budgets) make a rule partial; precision limits make it limited.
    truncated_rules: set[str] = set()
    limited_rules: set[str] = set()
    findings_truncated = False
    function_totals = {"observed": 0, "analyzed": 0, "skipped": 0, "without_body": 0}
    native_files: list[tuple[Analyzer, Any, list[Any]]] = []
    native_metrics: list[tuple[Analyzer, dict]] = []
    normalized_files = 0
    remaining_records = 0
    # Share staging priorities and module fairness so vendored code cannot consume
    # the AST budget before the app's own sources.
    sources = [sources[index] for index in prioritized_paths([_source_path(source) for source in sources])]
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
                unsupported_files += 1
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
                "observed": sum(_analysis_unit(n) for n in nodes),
                "with_errors": sum(_analysis_unit(n) and n.has_error for n in nodes),
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
                    nodes = []
                    for count, _node in enumerate(_walk(tree.root_node), 1):
                        if count > MAX_AST_NODES:
                            raise ValueError("compatibility AST node budget exceeded")
                        nodes.append(_node)
                    normalized_files += 1
                    if any(not adaptation.get("lossless") for adaptation in adaptations):
                        warnings.append(
                            f"AST parser compatibility in {path}: {adaptations}; source remains partial."
                        )
            metric["adaptations"] = adaptations
            # Offset- and semantics-preserving whitespace edits do not reduce coverage.
            lossy = [adaptation for adaptation in adaptations if not adaptation.get("lossless")]
            metric["parse_errors"] = tree.root_node.has_error
            if tree.root_node.has_error:
                warnings.append(
                    f"AST syntax recovery in {path}: functions containing parse errors were skipped."
                )
                skipped += 1
            elif lossy:
                skipped += 1
            if language == "objc":
                from .objc_analysis import ObjCAnalyzer

                analyzer = ObjCAnalyzer(path, text, uncertain_spans=dropped)
                analyzer.analyze(tree.root_node)
            else:
                analyzer = Analyzer(path, text, language, specs, exposed_providers, android_levels)
                native_files.append((analyzer, tree.root_node, nodes))
                native_metrics.append((analyzer, metric))
            # An analyzed ObjC function is examined only through the reduced model
            # (no preprocessing, dispatch or interprocedural flow): a precision
            # limit. A skipped ObjC function (inside #if/#ifdef/#elif/#else, a
            # recovered error or a lossy adaptation span) was not examined: an
            # execution gap, like parse errors and lossy adaptations.
            objc_skipped = language == "objc" and analyzer.function_counts["skipped"] > 0
            if objc_skipped and not (tree.root_node.has_error or lossy):
                warnings.append(
                    f"Objective-C analysis skipped {analyzer.function_counts['skipped']} conditionally "
                    f"compiled function(s) in {path}; source remains partial."
                )
                skipped += 1
            metric["state"] = (
                "partial"
                if tree.root_node.has_error or lossy or objc_skipped
                else "limited"
                if language == "objc"
                else "checked"
            )
            metric["functions"] = analyzer.function_counts
            if language == "objc":
                for name, value in analyzer.function_counts.items():
                    function_totals[name] += value
                findings.extend(analyzer.findings)
            parsed += 1
            if len(findings) >= MAX_AST_FINDINGS:
                findings = findings[:MAX_AST_FINDINGS]
                findings_truncated = True
                warnings.append("AST finding budget reached; remaining source functions were not checked.")
                skipped += 1
                remaining_records = len(sources) - source_index - 1
                break
        except (ValueError, RecursionError) as error:
            parsers[language].reset()
            warnings.append(f"AST analysis skipped {path}: {error}.")
            metric["reason"] = str(error)
            skipped += 1
    flow_metadata = {"state": "not-run", "reasons": [], "budget_reasons": [], "precision_reasons": []}
    if native_files:
        from .native_flow import NativeFlow

        flow = NativeFlow(native_files)
        flow.run()
        flow_metadata = flow.metadata()
        for analyzer, metric in native_metrics:
            metric["functions"] = analyzer.function_counts
            metric["native_flow_reasons"] = sorted(
                {
                    detail["reason"]
                    for detail in flow_metadata["partial_details"]
                    if detail["path"] in {None, analyzer.path}
                }
            )
            metric["native_flow_diagnostics_complete"] = not flow_metadata["partial_details_truncated"]
            if "native flow recursion budget" in metric["native_flow_reasons"]:
                metric["state"] = "partial"
            for name, value in analyzer.function_counts.items():
                function_totals[name] += value
            for item in analyzer.findings:
                for evidence in item["evidence"]:
                    evidence.pop("modeled_routes", None)
            findings.extend(analyzer.findings)
            truncated_rules |= analyzer.truncated_rules
            limited_rules |= analyzer.limited_rules
            if metric["state"] == "checked":
                pattern_exclusions[analyzer.path] = {
                    rule: [{"start": start, "end": end} for start, end in sorted(offsets)]
                    for rule, offsets in analyzer.pattern_exclusions.items()
                }
        # Diagnostics stay conservative for every native rule: a budget reason
        # leaves them partial; abstention alone (precision) leaves them limited.
        if flow_metadata["budget_reasons"]:
            truncated_rules.update(RULES)
            warnings.append(
                "Native flow remains partial: " + "; ".join(flow_metadata["budget_reasons"]) + "."
            )
        if flow_metadata["precision_reasons"]:
            limited_rules.update(RULES)
            warnings.append(
                "Native flow remains limited: " + "; ".join(flow_metadata["precision_reasons"]) + "."
            )
    if len(findings) >= MAX_AST_FINDINGS:
        findings = findings[:MAX_AST_FINDINGS]
        findings_truncated = True
        truncated_rules.update(RULES)
        warnings.append("AST finding budget reached; remaining candidates were truncated.")
    for language, reason in unavailable.items():
        warnings.append(
            f"AST grammar unavailable for {language} ({reason}); install the bundled grammar dependency."
        )
    if unsupported:
        warnings.append(
            f"AST mobile checks do not support these source languages: {', '.join(sorted(unsupported))}."
        )
    # A recognized source file or record dropped before parsing (byte or node
    # budget, unavailable grammar, parser failure) is an execution gap even when
    # nothing else parsed; unsupported-language files alone stay not-run.
    state = (
        "partial"
        if (parsed and skipped) or skipped > unsupported_files
        else "checked"
        if parsed
        else "not-run"
    )
    objc_files = [metric for metric in file_metrics if metric["language"] == "objc"]
    # AST rules never examine Objective-C or Objective-C++ (.mm); OBJC-* rules
    # cover .m through a reduced model. Beside a language AST rules analyze, the
    # unexamined ObjC-family sources are an execution gap (partial); as the only
    # source languages they leave AST rules not-run. Android-only rules are out
    # of scope for ObjC, as for Swift.
    ast_languages = seen_languages - {"objc"}
    objc_family = bool(objc_files) or ".mm" in unsupported
    other_unsupported = unsupported - {".mm"}
    objc_only = objc_family and not ast_languages and not other_unsupported
    ios_only = (
        bool(seen_languages or unsupported) and seen_languages <= {"swift", "objc"} and not other_unsupported
    )
    declared_sql = any(item.get("kind") == "sql" for item in (specs or {}).get("sink", []))

    def ast_state(rule: str) -> str:
        android_only = rule.endswith(ANDROID_ONLY)
        if android_only and ios_only:
            return "not-applicable"
        if objc_only:
            return "not-run"
        objc_gap = objc_family and not android_only
        swift = "swift" in ast_languages
        if rule == "AST-SQL-CONCAT" and swift and declared_sql:
            # Swift files are examined for the exact declared sinks only: a precision limit.
            examined = state == "checked" and rule not in truncated_rules and not objc_gap
            return "limited" if examined else "partial"
        # The built-in check is not implemented for Swift. Swift alone leaves it
        # not-run; beside another AST language the Swift files are still parsed and
        # examined by the AST engine, so the missing Swift model is a precision
        # limit: it turns checked into limited and never hides a partial state.
        swift_unmodelled = rule in SWIFT_UNIMPLEMENTED and swift
        if swift_unmodelled and ast_languages == {"swift"} and not other_unsupported:
            return "not-run"
        if objc_gap:
            return "partial"
        if rule in truncated_rules and state == "checked":
            return "partial"
        if (rule in limited_rules or swift_unmodelled) and state == "checked":
            return "limited"
        return state

    inventory_complete = (
        bool(parsed)
        and not skipped
        and "native flow recursion budget" not in flow_metadata["reasons"]
        # Unexpanded ObjC macros can declare functions the CST never shows. Such
        # unobserved functions are a documented precision limit (OBJC rules stay
        # limited); the inventory is never claimed complete.
        and not any(metric["functions"] is not None for metric in objc_files)
    )
    coverage = [
        {
            "rule_id": rule,
            "state": ast_state(rule),
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
            "function_inventory_complete": inventory_complete,
            "normalized_files": normalized_files,
            "note": LIMITS_NOTE
            + (
                " Native interface check currently covers Android addJavascriptInterface."
                if rule.endswith("JS-BRIDGE")
                else ""
            )
            + (
                " The built-in check is not implemented for Swift; project-declared SQL sinks cover only their exact specifications."
                if rule in SWIFT_UNIMPLEMENTED and "swift" in ast_languages
                else ""
            )
            + (
                " AST rules do not examine Objective-C sources; OBJC-* rules cover them through a reduced model."
                if objc_family and not rule.endswith(ANDROID_ONLY)
                else ""
            ),
        }
        for rule in RULES
    ]
    if objc_family:
        from .objc_analysis import RULES as OBJC_RULES

        objc_analyzed = any(metric["functions"] is not None for metric in objc_files)
        # OBJC rules are limited by the reduced model only when every observed
        # ObjC function was analyzed (a declaration without a body has nothing
        # to examine). A skipped function, a skipped or partially parsed file,
        # or a truncated AST pass is an execution gap, as is any Objective-C++
        # (.mm) file, which the reduced model never examines. Functions hidden by
        # unexpanded macros are never observed: a documented precision limit
        # recorded as function_inventory_complete = false, not a gap.
        objc_gap = (
            ".mm" in unsupported
            or any(metric["state"] != "limited" for metric in objc_files)
            or any((metric["functions"] or {}).get("skipped") for metric in objc_files)
            or findings_truncated
            or remaining_records > 0
        )
        coverage.extend(
            {
                "rule_id": rule,
                # Every ObjC-family file dropped before analysis is still a gap.
                "state": "partial" if objc_gap else "limited" if objc_analyzed else "not-run",
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
            "native_flow": flow_metadata,
            "files": file_metrics,
            "functions": function_totals,
            "function_inventory_complete": inventory_complete,
            "remaining_source_records": remaining_records,
            "note": "Counts cover recognized AST function declarations and property accessor bodies only; errors, unsupported languages and budgets can hide additional functions. Adaptations retain original evidence offsets; lossy adaptations remain partial. Closures and initializers are not a complete callable inventory.",
        },
    }
