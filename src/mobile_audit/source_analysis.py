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
from collections.abc import Iterator
from contextlib import contextmanager
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
# Links of a call or getter chain followed to the object it is rooted at.
MAX_CHAIN = 256
MAX_CLOSURE_CLASSIFICATIONS = 65_536
# First segments of package paths a standard builder is called through (`kotlinx.coroutines.flow.flow { }`).
PACKAGE_ROOTS = {"kotlin", "kotlinx", "java", "javax", "android", "androidx"}
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
# Text literals for content and template roots, with tree-sitter-kotlin 1.1.0's raw string
# (`"""..."""`), which STRINGS does not name.
TEXT_LITERALS = (STRINGS - {"character_literal"}) | {"multiline_string_literal"}
NUMBERS = {
    "number_literal",
    "integer_literal",
    "real_literal",
    "decimal_integer_literal",
    "decimal_floating_point_literal",
    "hex_integer_literal",
    "long_literal",
}
IDENTIFIERS = {"identifier", "simple_identifier"}
# Kotlin/Swift lambda literals and Java lambda expressions.
CLOSURES = {"lambda_literal", "lambda_expression"}
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
# Collection and predicate functions whose closure receives elements of the receiver
# (or, for takeIf/takeUnless, the receiver itself): parameter positions that do.
# Binding them only adds the receiver's provenance; it proves nothing about the callee.
ELEMENT_FUNCTIONS = {
    **dict.fromkeys(
        (
            "forEach",
            "onEach",
            "map",
            "mapNotNull",
            "flatMap",
            "compactMap",
            "filter",
            "filterNot",
            "any",
            "all",
            "none",
            "count",
            "first",
            "firstOrNull",
            "last",
            "lastOrNull",
            "find",
            "findLast",
            "single",
            "singleOrNull",
            "takeWhile",
            "dropWhile",
            "sortedBy",
            "sortedByDescending",
            "groupBy",
            "associate",
            "associateBy",
            "associateWith",
            "partition",
            "sumOf",
            "maxByOrNull",
            "minByOrNull",
            "distinctBy",
            "takeIf",
            "takeUnless",
            "contains",
            "allSatisfy",
            "firstIndex",
            "lastIndex",
            "drop",
            "prefix",
            "removeIf",
            "anyMatch",
            "allMatch",
            "noneMatch",
            "peek",
        ),
        (0,),
    ),
    **dict.fromkeys(
        ("forEachIndexed", "mapIndexed", "mapIndexedNotNull", "filterIndexed", "fold", "runningFold", "scan"),
        (1,),
    ),
    # A reduce accumulator starts as an element (Swift's reduce takes an initial value instead).
    **dict.fromkeys(("sorted", "sortedWith", "max", "min", "reduce", "runningReduce"), (0, 1)),
    **dict.fromkeys(("reduceIndexed", "runningReduceIndexed"), (1, 2)),
    "foldIndexed": (2,),
}
# Accumulator parameter positions of folds: the accumulator starts as the first data argument.
ACCUMULATORS = {"fold": 0, "runningFold": 0, "scan": 0, "foldIndexed": 1}
# Standard top-level functions a receiverless call in a lambda resolves to that write into
# no implicit receiver; any other receiverless call there may be the receiver's member.
NON_WRITERS = {
    "println",
    "print",
    "readLine",
    "require",
    "requireNotNull",
    "check",
    "checkNotNull",
    "assert",
    "error",
    "TODO",
    "repeat",
    "run",
    "with",
    "let",
    "also",
    "apply",
    "takeIf",
    "takeUnless",
    "lazy",
    "synchronized",
    "runCatching",
    "listOf",
    "listOfNotNull",
    "mutableListOf",
    "arrayListOf",
    "setOf",
    "mutableSetOf",
    "mapOf",
    "mutableMapOf",
    "hashMapOf",
    "arrayOf",
    "emptyList",
    "emptySet",
    "emptyMap",
    "maxOf",
    "minOf",
    "delay",
    "launch",
    "async",
    "withContext",
    "runBlocking",
    "coroutineScope",
    "supervisorScope",
    "withTimeout",
    "withTimeoutOrNull",
    "ensureActive",
    "measureTimeMillis",
    "measureNanoTime",
}
# Members that read a supplied object without writing into it (`b.contains(q)`).
READ_ONLY_MEMBERS = {
    "contains",
    "containsKey",
    "containsValue",
    "get",
    "getOrNull",
    "getOrDefault",
    "startsWith",
    "endsWith",
    "equals",
    "isEmpty",
    "isNotEmpty",
    "isBlank",
    "isNotBlank",
    "indexOf",
    "lastIndexOf",
    "toString",
    "hashCode",
    "compareTo",
    "matches",
    "first",
    "last",
    "firstOrNull",
    "lastOrNull",
    "count",
    "any",
    "all",
    "none",
    "find",
    "hasPrefix",
    "hasSuffix",
    "contentEquals",
    "regionMatches",
    "equalsIgnoreCase",
    "compareToIgnoreCase",
    "containsAll",
    "getOrElse",
    "elementAt",
    "elementAtOrNull",
    "single",
    "singleOrNull",
    "subSequence",
    "substring",
    "subList",
    "charAt",
    "codePointAt",
    "length",
    "size",
    "isNullOrEmpty",
    "isNullOrBlank",
    "commonPrefixWith",
    "commonSuffixWith",
    "joinToString",
    "toList",
    "toSet",
    "toMap",
    "toTypedArray",
    "toCharArray",
    "starts",
    "elementsEqual",
    "firstIndex",
    "lastIndex",
}
# Standard APIs that store their closure's result into the receiver, for a later read.
RESULT_STORING_CALLS = frozenset(
    {
        "compute",
        "computeIfAbsent",
        "computeIfPresent",
        "merge",
        "replaceAll",
        "updateAndGet",
        "getAndUpdate",
        "accumulateAndGet",
        "getAndAccumulate",
        "getOrPut",
        "update",
    }
)
# Callees whose lambda has no receiver holding data their value returns (a coroutine
# scope, or none): a receiverless call in it writes into nothing that call returns.
NO_DATA_RECEIVERS = {
    "withContext",
    "runCatching",
    "synchronized",
    "lazy",
    "launch",
    "async",
    "coroutineScope",
    "supervisorScope",
    "runBlocking",
    "withTimeout",
    "withTimeoutOrNull",
    "repeat",
    "thread",
    "measureTimeMillis",
    "measureNanoTime",
    "post",
    "postDelayed",
    "runOnUiThread",
    "remember",
    "derivedStateOf",
    "submit",
    "execute",
}
# Of those, the standard top-level functions: on an object receiver (`dsl.remember { }`) the
# name is that object's own member, a DSL entry point like any other.
TOP_LEVEL_RUNNERS = {
    "synchronized",
    "lazy",
    "repeat",
    "thread",
    "measureTimeMillis",
    "measureNanoTime",
    "remember",
    "derivedStateOf",
}
# Classes whose calls transform a value they are given (`String.format(..)`).
VALUE_CLASSES = {
    "String",
    "Uri",
    "URLEncoder",
    "URLDecoder",
    "Html",
    "HtmlCompat",
    "TextUtils",
    "Base64",
    "Objects",
    "Optional",
    "Arrays",
    "Regex",
    "Pattern",
}
# Event-handler registrations take a callback, not a builder (`b.onClick { }`,
# `view.setOnClickListener { }`, `doOnTextChanged { }`, `doAfterTextChanged { }`): its
# lambda writes into nothing.
CALLBACK_REGISTRATIONS = re.compile(
    r"(?:on|doOn|doAfter|doBefore|addOn)[A-Z]|set\w*(?:Listener|Callback)$|add\w*(?:Listener|Callback)$"
)
# Members that read a value out of an object; passing it hands over no part of the object
# (`b.length`, `b.id`, `m.getName()`).
VALUE_MEMBERS = {
    "id",
    "name",
    "key",
    "type",
    "index",
    "status",
    "version",
    "ordinal",
    "enabled",
    "visible",
    "checked",
    "selected",
    "width",
    "height",
    "position",
    "length",
    "size",
    "count",
    "indices",
    "lastIndex",
    "isEmpty",
    "isNotEmpty",
    "isBlank",
    "isNotBlank",
    "capacity",
    "hashCode",
}
# Keyed reads of a scalar (`b.getInt("rows")`, `doc.attr("id")`, `m.optString("k")`): a
# value, not a part of the object, though their arguments are literals.
SCALAR_GETTERS = re.compile(
    r"(?:get|opt)(?:Int|Long|Boolean|Bool|Double|Float|Short|Byte|Char|String|Number|CharSequence)(?:Extra)?"
    r"|attr|getAttribute|getAttributeValue|getAttributeNS|getHeader|header|getParameter|getQueryParameter"
    r"|getProperty|getResourceString|getResourceName"
)
# Receiverless string transforms in a `run`/`with` block on data (`q.run { trim() }`).
STRING_TRANSFORMS = {
    "trim",
    "trimStart",
    "trimEnd",
    "trimIndent",
    "trimMargin",
    "lowercase",
    "uppercase",
    "toLowerCase",
    "toUpperCase",
    "substring",
    "substringBefore",
    "substringAfter",
    "replace",
    "replaceFirst",
    "take",
    "takeLast",
    "drop",
    "dropLast",
    "padStart",
    "padEnd",
    "removePrefix",
    "removeSuffix",
    "removeSurrounding",
    "format",
    "plus",
    "reversed",
    "toString",
    "orEmpty",
    "split",
    "lines",
    # Java and Swift spellings.
    "concat",
    "replaceAll",
    "strip",
    "lowercased",
    "uppercased",
    "capitalized",
    "trimmingCharacters",
    "replacingOccurrences",
    "appending",
    "appendingFormat",
    "appendingPathComponent",
    "padding",
    "ifEmpty",
    "ifBlank",
    "formatted",
    "repeat",
}
# String transforms that insert their arguments' text (`tpl.format(q)`, `prefix.plus(q)`).
TEMPLATE_FILLS = {
    "format",
    "replace",
    "replaceFirst",
    "replaceAll",
    "plus",
    "concat",
    "appending",
    "appendingFormat",
    "appendingPathComponent",
    "replacingOccurrences",
    "formatted",
}
# The names of the new text a `replace` inserts (`replace(newValue = q, oldValue = "{q}")`,
# `replace(regex, replacement)`, Swift `replacingOccurrences(of:with:)`).
REPLACEMENT_LABELS = {"newValue", "newChar", "replacement", "transform", "with"}
# Classes whose calls give a number or a number's text (`Integer.parseInt(q)`, `Math.max(1, n)`).
NUMERIC_CLASSES = {"Integer", "Long", "Double", "Float", "Short", "Byte", "Math", "Boolean"}
# A number's text and operations, read on a number receiver (`n.toString()`, `n.plus(1)`).
NUMBER_OPERATIONS = {
    "toString",
    "plus",
    "minus",
    "times",
    "div",
    "rem",
    "inc",
    "dec",
    "coerceAtLeast",
    "coerceAtMost",
    "coerceIn",
}
# Declared types of a number or a flag (`val n: Int = repo.count(q)`, Swift `let ok: Bool`).
NUMBER_TYPES = {
    "Int",
    "Long",
    "Short",
    "Byte",
    "Double",
    "Float",
    "Boolean",
    "UInt",
    "ULong",
    "Bool",
    "CGFloat",
    "Int32",
    "Int64",
    "UInt32",
    "UInt64",
    "Integer",
    "int",
    "long",
    "short",
    "byte",
    "double",
    "float",
    "boolean",
}
# Members whose result is a flag or a number, not text (`b.visible { q.isNotEmpty() }`,
# `q.length`, `template.contains(q)`).
SCALAR_RESULTS = {
    "contains",
    "containsKey",
    "containsValue",
    "startsWith",
    "endsWith",
    "equals",
    "equalsIgnoreCase",
    "contentEquals",
    "compareTo",
    "compareToIgnoreCase",
    "indexOf",
    "lastIndexOf",
    "indexOfFirst",
    "indexOfLast",
    "length",
    "size",
    "count",
    "lastIndex",
    "isEmpty",
    "isNotEmpty",
    "isBlank",
    "isNotBlank",
    "isNullOrEmpty",
    "isNullOrBlank",
    "matches",
    "hashCode",
    "hasPrefix",
    "hasSuffix",
    "any",
    "all",
    "none",
    "toInt",
    "toIntOrNull",
    "toLong",
    "toLongOrNull",
    "toDouble",
    "toFloat",
    "toBoolean",
}
# Value classes and standard factories whose result is a value built from their arguments
# (`String(format: "%@", q)`, `StringBuilder(q)`, `URL(string: q)`, `listOf(title, q)`).
VALUE_CONSTRUCTORS = {
    "String",
    "StringBuilder",
    "URL",
    "URLComponents",
    "Pair",
    "Triple",
    "listOf",
    "listOfNotNull",
    "mutableListOf",
    "arrayListOf",
    "setOf",
    "mutableSetOf",
    "hashSetOf",
    "linkedSetOf",
    "mapOf",
    "mutableMapOf",
    "hashMapOf",
    "linkedMapOf",
    "arrayOf",
    "requireNotNull",
    "checkNotNull",
}
# Words naming an analytics tracker, also an analytics vendor's (`firebaseTracker`).
ANALYTICS_WORDS = (
    "analytics",
    "event",
    "screen",
    "usage",
    "user",
    "app",
    "error",
    "crash",
    "firebase",
    "mixpanel",
    "amplitude",
    "segment",
    "adjust",
    "braze",
    "appsFlyer",
    "appsflyer",
)
# A word between an analytics word and `Tracker` (`screenViewTracker`, `userSessionTracker`).
TRACKING_WORDS = "View|Event|Action|Click|Activity|Session|Engagement"
# Logging and analytics calls write into none of their arguments (`Log.d(TAG, b.body)`,
# `Timber.d("%s", this)`, `Analytics.track(b.text, q)`).
LOGGING_NAME = re.compile(
    r"(?i)(?:m_?|s_|_)?(?:log|logger|analytics|timber|napier|kermit|flogger|tracker|tracking|metrics|sentry|bugsnag)"
    # A static field's `s` prefix as a camel-case word (`sLog`, `sLogger`; not `slog`).
    r"|(?-i:s(?:Log|Logger|LOG|LOGGER|Timber|Tracker|Tracking|Metrics|Analytics))"
    # A log named by an App, My, Debug, Base, Common, File, Remote, Crash or Error word, as for
    # the wrappers below (`debugLog`, `app_log`; not `eventLog`, `change_log` or `audit_log`).
    r"|(?-i:(?:app|my|debug|base|common|file|remote|crash|error|App|My|Debug|Base|Common|File|Remote|Crash|Error)Log)"
    r"|_?(?:app|my|debug|base|common|file|remote|crash|error)_log"
    # Loggers and analytics by a snake_case word (`app_logger`, `firebase_analytics`; not
    # `change_log`, `call_log` or `app_metrics`), and analytics trackers by one, with one more
    # tracking word between (`event_tracker`, `screen_view_tracker`; not `selection_tracker`,
    # `app_state_tracker` or `order_tracking`).
    r"|_?(?:[a-z0-9]+_)+(?:logger|analytics|crashlytics|telemetry)"
    r"|_?(?:[a-z0-9]+_)*(?:"
    + "|".join(ANALYTICS_WORDS)
    + r")_(?:(?:"
    + TRACKING_WORDS
    + r")_)?track(?:er|ing)"
    # Loggers and analytics by a camel-case word (`appLogger`, `mFirebaseAnalytics`, `LOGGER`;
    # not `blogger`).
    r"|(?-i:\w*(?:Logger|Analytics|Crashlytics|Telemetry)|(?:logger|analytics|crashlytics|telemetry)"
    r"|[A-Z0-9_]*(?:LOGGER|ANALYTICS|CRASHLYTICS|TELEMETRY))"
    # Analytics trackers by a camel-case word before `Tracker` or `Tracking`, with one more
    # tracking word between (`eventTracker`, `screenViewTracker`, `userSessionTracker`,
    # `userTracking`, `AppsFlyerTracker`; not `selectionTracker`, `appStateTracker` or
    # `orderTracking`).
    r"|(?-i:(?:\w*[a-z0-9])?(?:"
    + "|".join(word[:1].upper() + word[1:] for word in ANALYTICS_WORDS)
    + r")(?:"
    + TRACKING_WORDS
    + r")?Track(?:er|ing))"
    r"|(?-i:(?:" + "|".join(ANALYTICS_WORDS) + r")(?:" + TRACKING_WORDS + r")?Track(?:er|ing))"
    # Logging wrappers: `Log` + Utils/Helper/Wrapper, also after m/s/_ or an App, My, Debug,
    # Base, Common, File, Remote, Crash or Error word (`LogUtils`, `mLogHelper`, `AppLogHelper`;
    # not `CallLogHelper`, `ChangeLogUtils` or `catalogHelper`).
    r"|(?-i:(?:m|s|_)?(?:App|My|Debug|Base|Common|File|Remote|Crash|Error)?Log(?:Utils?|Helper|Wrapper)"
    r"|(?:m|s|_)?(?:app|my|debug|base|common|file|remote|crash|error)?[lL]og(?:Utils?|Helper|Wrapper))"
)
LOGGING_FUNCTIONS = {"println", "print", "debugPrint", "NSLog", "os_log", "dump"}
# A receiverless logging function whose lambda builds a lazy message (`logcat { "msg $q" }`).
# A star-imported package that can supply such a function (`import logcat.*`, `com.lib.log.*`).
LOGGING_PACKAGE = re.compile(
    r"(?i)(?:^|\.)(?:log|logs|logging|logger|loggers|logcat|timber|napier|kermit)(?:\.|$)"
)
LAZY_LOGGERS = re.compile(r"log(?:cat|[A-Z]\w*)?|[a-z]\w*Log|verbose|debug|info|warn(?:ing)?|trace")
# Calls whose lambda's implicit receiver is a builder they create and return, with the
# members (and standard extensions) that write data into it. A receiverless call by one
# of these names is the receiver's member even where a project function has that name.
_SENDS = frozenset({"send", "trySend", "trySendBlocking", "offer", "sendBlocking"})
_EMITS = frozenset({"emit", "emitAll"})
BUILDER_MEMBERS = {
    "buildString": frozenset(
        {
            "append",
            "appendLine",
            "appendln",
            "appendRange",
            "appendCodePoint",
            "insert",
            "insertRange",
            "set",
            "setRange",
            "setCharAt",
            "replace",
        }
    ),
    "buildList": frozenset({"add", "addAll", "set", "addFirst", "addLast", "fill", "replaceAll"}),
    "buildSet": frozenset({"add", "addAll"}),
    "buildMap": frozenset(
        {
            "put",
            "putAll",
            "set",
            "getOrPut",
            "putIfAbsent",
            "merge",
            "compute",
            "computeIfAbsent",
            "computeIfPresent",
            "replace",
            "replaceAll",
        }
    ),
    "buildJsonObject": frozenset({"put", "putJsonObject", "putJsonArray"}),
    "buildJsonArray": frozenset({"add", "addAll", "addJsonObject", "addJsonArray"}),
    "buildAnnotatedString": frozenset(
        {
            "append",
            "appendInlineContent",
            "withStyle",
            "withAnnotation",
            "withLink",
            "pushStringAnnotation",
            "addStringAnnotation",
            "addUrlAnnotation",
            "addTtsAnnotation",
            "addLink",
            "pushLink",
            "pushUrlAnnotation",
            "pushTtsAnnotation",
        }
    ),
    "buildSpannedString": frozenset(
        {
            "append",
            "appendLine",
            "insert",
            "replace",
            "inSpans",
            "bold",
            "italic",
            "underline",
            "strikeThrough",
            "subscript",
            "superscript",
            "color",
            "backgroundColor",
            "scale",
        }
    ),
    "sequence": frozenset({"yield", "yieldAll"}),
    "iterator": frozenset({"yield", "yieldAll"}),
    "flow": _EMITS,
    "channelFlow": _SENDS,
    "callbackFlow": _SENDS,
    "produce": _SENDS,
    "liveData": frozenset({"emit", "emitSource"}),
    # Flow operators whose block runs with the flow's collector (`onStart { emit(q) }`).
    "onStart": _EMITS,
    "onEmpty": _EMITS,
    "onCompletion": _EMITS,
    "onSubscription": _EMITS,
}
FLOW_OPERATORS = {"onStart", "onEmpty", "onCompletion", "onSubscription"}
# Another `build…` callee's receiver is unknown: these names are taken as its members.
BUILDER_MEMBER_NAMES = frozenset().union(*BUILDER_MEMBERS.values())
# The receiver types of the builders above and their writable supertypes, for project
# extensions of them (`fun Appendable.appendQuoted(..)`, `fun <T : Appendable> T.q(..)`).
_PRODUCER = frozenset({"ProducerScope", "SendChannel"})
_COLLECTOR = frozenset({"FlowCollector"})
BUILDER_RECEIVERS = {
    "buildString": frozenset({"StringBuilder", "Appendable"}),
    "buildList": frozenset({"MutableList", "MutableCollection", "MutableIterable"}),
    "buildSet": frozenset({"MutableSet", "MutableCollection", "MutableIterable"}),
    "buildMap": frozenset({"MutableMap"}),
    "buildJsonObject": frozenset({"JsonObjectBuilder"}),
    "buildJsonArray": frozenset({"JsonArrayBuilder"}),
    "buildAnnotatedString": frozenset({"Builder", "Appendable"}),
    "buildSpannedString": frozenset({"SpannableStringBuilder", "Editable", "Spannable", "Appendable"}),
    "sequence": frozenset({"SequenceScope"}),
    "iterator": frozenset({"SequenceScope"}),
    "flow": _COLLECTOR,
    "channelFlow": _PRODUCER,
    "callbackFlow": _PRODUCER,
    "produce": _PRODUCER,
    "liveData": frozenset({"LiveDataScope"}),
    "onStart": _COLLECTOR,
    "onEmpty": _COLLECTOR,
    "onCompletion": _COLLECTOR,
    "onSubscription": _COLLECTOR,
}
# Coroutine builders and runners: their lambda's receiver is a scope, on any receiver.
COROUTINE_BUILDERS = {
    "launch",
    "async",
    "withContext",
    "runBlocking",
    "coroutineScope",
    "supervisorScope",
    "withTimeout",
    "withTimeoutOrNull",
    "launchWhenCreated",
    "launchWhenStarted",
    "launchWhenResumed",
    "repeatOnLifecycle",
}
# Element functions whose closure decides (a predicate, a comparator) or acts per element:
# its result is not part of the call's value, which is the receiver's elements, a count,
# a flag or nothing.
SELECTING_FUNCTIONS = {
    "filterTo",
    "filterNotTo",
    "filterIndexedTo",
    "forEach",
    "forEachIndexed",
    "onEach",
    "peek",
    "filter",
    "filterNot",
    "filterIndexed",
    "any",
    "all",
    "none",
    "count",
    "first",
    "firstOrNull",
    "last",
    "lastOrNull",
    "find",
    "findLast",
    "single",
    "singleOrNull",
    "takeWhile",
    "dropWhile",
    "takeLastWhile",
    "dropLastWhile",
    "sortedBy",
    "sortedByDescending",
    "sortedWith",
    "sorted",
    "sortBy",
    "sortByDescending",
    "sortWith",
    "maxBy",
    "minBy",
    "maxByOrNull",
    "minByOrNull",
    "max",
    "min",
    "distinctBy",
    "partition",
    "takeIf",
    "takeUnless",
    "contains",
    "allSatisfy",
    "firstIndex",
    "lastIndex",
    "indexOfFirst",
    "indexOfLast",
    "drop",
    "prefix",
    "removeIf",
    "removeAll",
    "retainAll",
    "anyMatch",
    "allMatch",
    "noneMatch",
    # Comparator builders: their closure decides an order.
    "compareBy",
    "compareByDescending",
    "thenBy",
    "thenByDescending",
    "thenComparing",
    "comparing",
    "comparingInt",
    "comparingLong",
    "comparingDouble",
    "Comparator",
    "maxWith",
    "minWith",
}
# Element functions whose lambda's result is the element or key it produces.
MAPPING_FUNCTIONS = {
    "map",
    "mapNotNull",
    "mapIndexed",
    "mapIndexedNotNull",
    "flatMap",
    "flatMapIndexed",
    "associate",
    "associateBy",
    "associateWith",
    "groupBy",
    "sumOf",
    "maxOf",
    "minOf",
    "fold",
    "foldIndexed",
    "reduce",
    "reduceIndexed",
    "runningFold",
    "scan",
    "maxOfOrNull",
    "minOfOrNull",
    "joinToString",
    "mapValues",
    "mapKeys",
    "mapTo",
    "mapNotNullTo",
    "flatMapTo",
    "associateTo",
    "groupByTo",
    "firstNotNullOfOrNull",
    "sumBy",
    "zip",
}
# Mapping functions that store their lambda's result into a destination wherever they stand.
MAPPING_INTO = {
    "mapTo",
    "mapNotNullTo",
    "mapIndexedTo",
    "mapIndexedNotNullTo",
    "flatMapTo",
    "flatMapIndexedTo",
    "associateTo",
    "associateByTo",
    "associateWithTo",
    "groupByTo",
    "mapKeysTo",
    "mapValuesTo",
}
# Result members that pass a runCatching block's value on, and those that drop it.
RESULT_VALUE_CALLS = {
    "also",
    "map",
    "mapCatching",
    "fold",
    "onFailure",
    "onSuccess",
    "getOrNull",
    "getOrElse",
    "getOrDefault",
    "getOrThrow",
    "recover",
    "recoverCatching",
}
RESULT_DISCARDS = {"exceptionOrNull", "isSuccess", "isFailure"}
# Callee spellings that name the called function; any other callee expression is evaluated first.
# Builders whose lambda runs later, when their result is iterated or collected.
LAZY_BUILDERS = {
    "sequence",
    "iterator",
    "flow",
    "channelFlow",
    "callbackFlow",
    "produce",
    "liveData",
} | FLOW_OPERATORS
# Standard functions that run their closure before they return: an assignment of their
# value stores after anything the closure writes.
INLINE_CALLEES = (
    SCOPE_FUNCTIONS
    | set(ELEMENT_FUNCTIONS)
    | SELECTING_FUNCTIONS
    | set(ACCUMULATORS)
    | (set(BUILDER_MEMBERS) - LAZY_BUILDERS)
    | {
        "repeat",
        "runCatching",
        "synchronized",
        "withContext",
        "runBlocking",
        "coroutineScope",
        "supervisorScope",
        "withTimeout",
        "withTimeoutOrNull",
        "measureTimeMillis",
        "measureNanoTime",
        "getOrElse",
        "getOrPut",
    }
)
DIRECT_CALLEES = {
    "identifier",
    "simple_identifier",
    "navigation_expression",
    "this",
    "this_expression",
    "super_expression",
    "self_expression",
    "user_type",
    "type_identifier",
}
# Statements whose value is the value of one of their branches.
BRANCHING = {"if_expression", "if_statement", "when_expression", "switch_statement", "try_expression"}
# Statements that are no closure's result value.
STATEMENT_ONLY = {
    "assignment",
    "assignment_expression",
    "return_statement",
    "return_expression",
    "jump_expression",
    "control_transfer_statement",
    "throw_statement",
    "throw_expression",
    "for_statement",
    "while_statement",
    "do_while_statement",
    "repeat_while_statement",
    "class_declaration",
    "object_declaration",
    "function_declaration",
    "local_variable_declaration",
    "property_declaration",
    "expression_statement",
}
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
    "(let, also, use, apply, run, with) are inlined, optional after ?. or return@; other closures, in "
    "parentheses or trailing, are followed once where written as blocks that may not run: guards they set "
    "do not hold after them, captured locals are read there, and parameters carry only collection elements "
    "or fold initial values. Unlabeled Kotlin lambda returns are joined into the enclosing return "
    "(unavailable inline-call identity is limited), as are returns to a resolved enclosing function label; "
    "lambda-local labeled Kotlin returns and Java/Swift closure returns give the closure's result. "
    "Lexical path containment does not prove symlink-free storage or race-free filesystem access."
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


def _closure_parts(node: Any):
    """A closure's own nodes: a nested closure, with its own `$0`, is not entered."""
    stack = [node]
    while stack:
        current = stack.pop()
        yield current
        if current.type in COMMENTS or current is not node and current.type in CLOSURES:
            continue
        stack.extend(reversed(current.named_children))


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


def _same_node(first: Any, second: Any) -> bool:
    """Whether two tree-sitter nodes are the same node (same span and type)."""
    return (first.start_byte, first.end_byte, first.type) == (second.start_byte, second.end_byte, second.type)


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


@dataclass
class ClosureEffects:
    """What a followed closure hands back through objects its callee supplies.

    ``names`` maps each declared parameter to the value it was bound to (a later
    shadowing or assignment replaces that object); ``implicit`` marks a Kotlin
    lambda without parameters, whose receiverless calls may target an implicit
    receiver; ``values`` collects what the closure wrote into them.
    """

    names: dict[str, Value]
    implicit: bool
    values: list[Value]
    # For a known builder's lambda (buildString, flow, sequence, ...), the receiver's
    # members that write into it: found before any project function of the same name.
    members: frozenset[str] = frozenset()
    # The receiver types of a builder whose members are all known (`StringBuilder` and its
    # writable supertypes): any other receiverless call is no member of it, unless a project
    # extension of one of them.
    receiver_types: frozenset[str] = frozenset()
    # The `this` binding around the lambda when it was followed: `this` inside it is the
    # lambda's receiver unless a nested scope block rebound it.
    outer_this: Value | None = None
    expressions: list[Any] = field(default_factory=list)


@dataclass(frozen=True)
class Call:
    """A call site. ``args`` lists every argument in order, trailing lambdas last.

    ``trailing`` holds the trailing lambda/closure nodes (also in ``args``) and
    ``arguments`` the node carrying the parenthesized or bracketed arguments,
    which for a Kotlin `f(x) { }` or a nested Swift initializer call lies on
    the inner call node rather than on ``node``.
    """

    node: Any
    name: str
    receiver: Any
    args: tuple[Any, ...]
    trailing: tuple[Any, ...] = ()
    arguments: Any = None


@dataclass
class ClosureScope:
    node: Any
    parent: int | None
    names: dict[str, list[int]] = field(default_factory=dict)


@dataclass
class ClosureLocal:
    name: str
    scope: int
    position: int
    kinds: int = 0
    typed_scalar: bool = False
    excluded: tuple[int, int] | None = None


@dataclass
class ClosureValue:
    owner: int
    node: Any
    scope: int
    initializer: bool = False


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
# Return types that cannot be a SQLiteDatabase.
NON_DATABASE_RETURNS = {
    "Unit",
    "void",
    "Nothing",
    "String",
    "CharSequence",
    "Int",
    "int",
    "Integer",
    "Long",
    "long",
    "Boolean",
    "boolean",
    "Double",
    "double",
    "Float",
    "float",
    "File",
    "Cursor",
    "SQLiteStatement",
    "SQLiteQueryBuilder",
    "ContentValues",
    "Uri",
    "Intent",
    "Bundle",
    "List",
    "MutableList",
    "Map",
    "MutableMap",
    "Set",
    "MutableSet",
    "Array",
}
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
        # Names of the file's String properties, fields and constants outside functions (class,
        # companion object, object and top-level declarations): template roots; with the class
        # or object declaring each ("" at the top level), which NativeFlow joins across files.
        self.string_constants: set[str] = set()
        self.string_members: set[tuple[str, str]] = set()
        # Functions the file declares to return a String (`fun displayName(): String`).
        self.string_functions: set[str] = set()
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
        # The best guess for an uncertain opener is the framework member.
        self.opener_prefers_framework = False
        # A framework-typed opener whose possible project callee is recorded, not followed.
        self.opener_record = False
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
        # A closure's result, recorded where it was last followed (keyed by its span), and the
        # values returned to closures being followed now (Swift/Java returns, Kotlin return@label).
        self.closure_values: dict[tuple[int, int], Value] = {}
        self.closure_returns: dict[tuple[int, int], list[Value]] = {}
        # The value the visitor computed for each call it evaluated in this function. A
        # closure's result and a call's inputs read it back (reuse_visited) instead of
        # evaluating the call again, which would repeat an unresolved call's effects.
        self.visited_values: dict[tuple[int, int, str], Value] = {}
        self.format_argument_offsets: dict[tuple[int, int], int] = {}
        self.reuse_visited = False
        # A call's receiver and data argument values, computed by the visitor before its
        # closures run, reused once by value() for that call.
        self.evaluated_inputs: tuple[tuple[int, int], Value, dict[int, Value]] | None = None
        # Followed closures whose result an enclosing expression uses: the values written
        # into their declared parameters or, for a Kotlin lambda without parameters, passed
        # to receiverless calls (an implicit receiver such as buildString's StringBuilder).
        self.closure_effects: list[ClosureEffects] = []
        # What a followed closure wrote into the objects its callee supplied (by span):
        # a nested builder call hands it on to the enclosing builder.
        self.closure_written: dict[tuple[int, int], Value] = {}
        self.closure_write_nodes: dict[tuple[int, int], tuple[Any, ...]] = {}
        self.implicit_formats: dict[tuple[int, int], Any] = {}
        self.string_builder_results: set[tuple[int, int]] = set()
        # The value each assignment inside a followed closure stored (by assignment span).
        self.assigned_values: dict[tuple[int, int], Value] = {}
        # result_position and statement_position per node: structural, so kept for the file.
        self.result_positions: dict[tuple[int, int, str], bool] = {}
        self.statement_positions: dict[tuple[int, int, str], bool] = {}
        # A declaration or assignment being visited with the value tree-sitter glued a
        # misparsed `where(..)` line onto (glued_line): the line's own value.
        self.gluing: dict[tuple[int, int, str], Any] = {}
        # The class bodies around each node, innermost first (structural).
        self.enclosing_bodies: dict[tuple[int, int, str], tuple[Any, ...]] = {}
        # The last statement of each block or lambda, by the parent's span (structural).
        self.last_parts: dict[tuple[int, int, str], tuple[int, int, str] | None] = {}
        # Braced branch bodies whose last statement is a value of a `when (val u = ..)` entry.
        self.value_blocks: set[tuple[int, int]] = set()
        # Functions declared in each class body (and its companion), by name.
        self.class_functions: dict[tuple[int, int], dict[str, list[Any]]] = {}
        self.class_members: dict[tuple[int, int], dict[str, bool]] = {}
        self.closure_classification_work: int | None = None
        self.closure_classification_cut = False
        self.closure_contexts: dict[tuple[int, int, int, str], list[tuple[Frame, Any]]] = {}
        self.class_string_functions: dict[tuple[int, int], dict[str, bool]] = {}
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
        self.opener_prefers_framework = False
        self.opener_record = False
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

        Candidates are the Java and Kotlin source callables of that name that could take the
        call's arguments and are visible at the call, plus properties of that name. Without
        any candidate, binding or reachable callable the call is the framework opener. A
        resolved project target is always followed (`opener_follow`). The callee is certain
        only when resolution returned every candidate, no property or framework static
        import shares the name, and then either every target declares a SQLiteDatabase
        return (directly, through a typealias or a bounded type parameter), or the name is
        `openDatabase` or the arity cannot fit Context.openOrCreateDatabase while every
        target's return is provably not a database (`not_database_return`). Every other
        case is a guess: the receiver and the arguments only pick the result type, and the
        guess is recorded (`limited`).
        """
        flow = self.native_flow
        if flow is None:
            return True
        targets, relevant = flow.resolve(self, call, receiver, frame)
        arity = self.call_arity(call)
        # Every source callable of that name (either language) that could take this many
        # arguments may be the callee: name resolution through inheritance, receivers
        # and imports is not modelled completely, so certainty needs all of them resolved.
        candidates = [
            target
            for target in flow.by_name.get(call.name, [])
            if target.analyzer.language in {"java", "kotlin"}
            and self.accepts_arity(target, arity)
            and self.visible_member(target, call.node)
        ]
        framework_import = any(
            symbol.startswith(("android.", "androidx.")) for symbol in flow.imported_symbols(self, call.name)
        ) or any(
            # Only SQLiteDatabase declares static openers; a package wildcard
            # (`import android.os.*`) imports classes, not its members.
            re.fullmatch(r"(?:static\s+)?android\.database\.sqlite\.SQLiteDatabase\.\*", declaration.strip())
            and (self.language == "kotlin" or declaration.strip().startswith("static "))
            for declaration in self.imports
        )
        # A function-typed property of that name (inherited, on an outer class, anywhere)
        # may be the callee too; the value-binding check sees only the current scope.
        bound = (
            flow.value_binding(self, call, frame) is not None
            or flow.module_value_present(self, call.name, aliases=True)
            or self.property_homonym(call.name)
        )
        if not targets:
            if not candidates and not bound and not (relevant and self.opener_reachable(call, frame)):
                return True  # the framework opener: no source callable could run instead
            self.opener_follow = relevant and (bound or self.opener_reachable(call, frame))
            self.opener_record = True
            return True
        self.opener_follow = True
        self.opener_returns = all(self.declared_return(target) for target in targets)
        resolved = {id(target.node) for target in targets}
        complete = (
            not framework_import and not bound and all(id(target.node) in resolved for target in candidates)
        )
        if all(self.declares_database(target) for target in targets):
            # Every reading returns a SQLiteDatabase, so the type is kept either way; an
            # incomplete resolution still records which callee runs as a guess.
            self.opener_certain = complete
            self.opener_prefers_framework = True
            return True
        if (
            complete
            and (call.name == "openDatabase" or arity not in {3, 4})
            and all(self.not_database_return(target) for target in targets)
        ):
            # Context declares no openDatabase, and its openOrCreateDatabase takes three or
            # four arguments; every other candidate is a resolved target.
            self.opener_certain = True
            return False
        # The receiver walk and the arguments only pick the more likely result type.
        kind = self.receiver_context(call.node, frame, classes=True)
        self.opener_prefers_framework = kind == "yes" and self.context_arguments(call, frame)
        return True

    def property_homonym(self, name: str) -> bool:
        """Whether any Java or Kotlin source declares a property or field of that name."""
        flow = self.native_flow
        if flow is None:
            return False
        cache: dict[str, bool] = flow.__dict__.setdefault("opener_property_names", {})
        if name not in cache:
            found = False
            for analyzer, root, _nodes in flow.files:
                if found or analyzer.language not in {"java", "kotlin"}:
                    continue
                for node in _walk(root):
                    if node.type == "property_declaration":
                        names = [
                            child.named_children[0]
                            for child in node.named_children
                            if child.type == "variable_declaration" and child.named_children
                        ]
                    elif node.type == "class_parameter" and any(
                        child.type in {"val", "var"} for child in node.children
                    ):
                        names = [child for child in node.named_children if child.type in IDENTIFIERS][:1]
                    elif node.type == "field_declaration":
                        names = [
                            child.named_children[0]
                            for child in node.named_children
                            if child.type == "variable_declarator" and child.named_children
                        ]
                    else:
                        continue
                    if any(analyzer.text(item) == name for item in names):
                        found = True
                        break
            cache[name] = found
        return cache[name]

    def visible_member(self, target: Any, node: Any) -> bool:
        """Whether a callable may be visible at `node`: a private member is visible only
        inside its declaring class (Java: inside its top-level class)."""
        if not target.analyzer.has_modifier(target.node, "private"):
            return True
        if target.analyzer.path != self.path:
            return False  # private members, and Kotlin private top-level functions, are file-local
        if not target.owner:
            return True
        declaring = target.node.parent
        while declaring is not None and declaring.type not in {
            "class_declaration",
            "object_declaration",
            "companion_object",
            "object_literal",
            "enum_declaration",
            "record_declaration",
            "interface_declaration",
        }:
            declaring = declaring.parent
        if declaring is None:
            return True
        if target.analyzer.language == "java":
            while declaring.parent is not None and declaring.parent.type != "program":
                declaring = declaring.parent
        current = node
        while current is not None:
            if current.start_byte == declaring.start_byte and current.end_byte == declaring.end_byte:
                return True
            current = current.parent
        return False

    def call_arity(self, call: Call) -> int:
        """Argument count of a call; a trailing lambda (a SAM argument) is one of its args."""
        return sum(1 for argument in call.args if argument.type not in COMMENTS)

    @staticmethod
    def accepts_arity(target: Any, arity: int) -> bool:
        """Whether a source callable's parameter list may take `arity` arguments."""
        parameters = next(
            (
                child
                for child in target.node.named_children
                if child.type in {"function_value_parameters", "formal_parameters"}
            ),
            None,
        )
        if parameters is None:
            return True
        # A receiver parameter (`Foo this`) takes no argument; a parameter followed by `=`
        # has a default; a vararg (Kotlin modifier or Java `...`) takes any number.
        children = [child for child in parameters.children if child.type not in COMMENTS]
        required = maximum = 0
        unbounded = False
        for index, child in enumerate(children):
            if child.type not in {"parameter", "formal_parameter", "spread_parameter"}:
                continue
            default = index + 1 < len(children) and children[index + 1].type == "="
            vararg = child.type == "spread_parameter" or (
                index > 0
                and children[index - 1].type == "parameter_modifiers"
                and "vararg" in target.analyzer.text(children[index - 1])
            )
            maximum += 1
            unbounded = unbounded or vararg
            if not default and not vararg:
                required += 1
        return required <= arity and (unbounded or arity <= maximum)

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
        ancestors: set[str] | None = None
        receiver_scoped: bool | None = None
        arity = self.call_arity(call)
        for target in flow.by_name.get(call.name, []):
            source = target.analyzer
            if (
                source.language != self.language
                or not self.accepts_arity(target, arity)
                or not self.visible_member(target, call.node)
            ):
                continue
            if source.path == self.path or (
                not target.owner and namespace and flow.namespaces[id(source)] == namespace
            ):
                return True
            if target.owner:
                # A method of a scope-function or extension receiver's class, or one
                # inherited from an in-source base class (in any file), is reachable;
                # unreadable ancestry is treated as possibly reaching it.
                if receiver_scoped is None:
                    receiver_scoped = self.receiver_in_scope(call.node)
                if receiver_scoped:
                    return True
                if ancestors is None:
                    ancestors = self.source_ancestors(call.node)
                if ancestors is None or target.owner in ancestors:
                    return True
                ancestors = ancestors or set()
        return any(
            not symbol.startswith(("android.", "androidx."))
            for symbol in flow.imported_symbols(self, call.name)
        )

    def has_modifier(self, declaration: Any, keyword: str) -> bool:
        """Whether a declaration carries a modifier keyword (annotations excluded)."""
        for modifiers in declaration.named_children:
            if modifiers.type != "modifiers":
                continue
            for child in modifiers.children:
                if "annotation" in child.type:
                    continue
                if child.type == keyword or self.text(child).strip() == keyword:
                    return True
        return False

    def receiver_in_scope(self, node: Any) -> bool:
        """Whether a Kotlin scope-function or extension receiver is in scope at `node`."""
        if self.language != "kotlin":
            return False
        if "this" in self.aliases:
            return True
        current = node.parent
        while current is not None:
            if current.type in {"function_declaration", "anonymous_function", "property_declaration"} and any(
                child.type == "." for child in current.children
            ):
                return True
            if current.type == "lambda_literal" and self.receiver_scope_lambda(current):
                return True
            current = current.parent
        return False

    def source_ancestors(self, node: Any) -> set[str] | None:
        """Owner identities of the in-source base classes of the classes enclosing `node`.

        None when a supertype list cannot be read, so callers stay conservative.
        """
        from .native_flow import NativeFlow

        flow = self.native_flow
        owners: set[str] = set()
        if flow is None:
            return owners
        pending: list[tuple[Analyzer, Any, int]] = []
        current = node.parent
        while current is not None:
            if current.type in {
                "class_declaration",
                "object_declaration",
                "companion_object",
                "object_literal",
                "enum_declaration",
                "record_declaration",
                "interface_declaration",
            }:
                pending.append((self, current, 0))
            elif current.type == "object_creation_expression" and any(
                child.type == "class_body" for child in current.children
            ):
                # A Java anonymous class extends the instantiated type.
                kind = next((child for child in current.named_children if "type" in child.type), None)
                if kind is None:
                    return None
                for owner in flow.class_owners(self, re.sub(r"<.*", "", self.text(kind)), current):
                    owners.add(owner)
                    for source, base in flow.class_definitions.get(owner, []):
                        pending.append((source, base, 1))
            current = current.parent
        seen: set[int] = set()
        while pending:
            analyzer, nominal, depth = pending.pop()
            if nominal.id in seen or depth >= 8:
                continue
            seen.add(nominal.id)
            references = NativeFlow.supertype_references(analyzer, nominal)
            if references is None:
                return None
            for reference in references:
                for owner in flow.class_owners(analyzer, reference, nominal.parent or nominal):
                    owners.add(owner)
                    for source, base in flow.class_definitions.get(owner, []):
                        pending.append((source, base, depth + 1))
        return owners

    def context_arguments(self, call: Call, frame: Frame) -> bool:
        """Whether Context.openOrCreateDatabase(String, int, CursorFactory[, handler]) can
        take this call's arguments, so an implicit Context receiver's member would apply."""
        if len(call.args) not in {3, 4}:
            return False
        integers = {"integer_literal", "decimal_integer_literal", "number_literal"}
        incompatible = {
            "String",
            "CharSequence",
            "Int",
            "Integer",
            "Long",
            "Boolean",
            "Double",
            "Float",
            "File",
        }
        for index, argument in enumerate(call.args):
            text = self.text(argument).strip()
            value = frame.values.get(self.symbol_name(text)) if argument.type in IDENTIFIERS else None
            spelling = value.type_name if value is not None and value.type_name else ""
            kind = re.sub(r"<.*|\?$|\s+", "", spelling).rsplit(".", 1)[-1]
            if index == 0 and (argument.type in integers or kind in {"Int", "int"}):
                return False
            if index == 1 and (argument.type in STRINGS or kind == "String"):
                return False
            # A factory or handler argument rules Context's member out only when its type
            # cannot be a CursorFactory/DatabaseErrorHandler; unknown or project types can.
            if index >= 2 and (
                argument.type in STRINGS
                or argument.type in integers
                or argument.type == "boolean_literal"
                or kind in incompatible
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

    def declares_database(self, target: Any) -> bool:
        """Whether a project function's declared return type is SQLiteDatabase: by name,
        through a Kotlin typealias of it, or as a type parameter bounded by it."""
        name = re.sub(r"<.*|\s+|\?$", "", self.declared_return(target)).rsplit(".", 1)[-1]
        if not name:
            return False
        if name == "SQLiteDatabase":
            return True
        # Type parameters of the function or its enclosing classes, bounded in their
        # declaration or in a `where` clause.
        scopes = [target.node]
        current = target.node.parent
        while current is not None:
            if current.type in {"class_declaration", "interface_declaration", "object_declaration"}:
                scopes.append(current)
            current = current.parent
        pattern = rf"\b{re.escape(name)}\s*(?::|extends)\s*[\w.]*SQLiteDatabase\b"
        for scope in scopes:
            for child in scope.named_children:
                if child.type in {"type_parameters", "type_constraints"} and re.search(
                    pattern, target.analyzer.text(child)
                ):
                    return True
        return name in self.database_aliases()

    def not_database_return(self, target: Any) -> bool:
        """Whether a function's return type is provably not SQLiteDatabase: Unit/void, a
        Kotlin block body without a declared type, a common non-database type, or a source
        class (SQLiteDatabase is final). Aliases, type parameters and unknown library types
        are not provable, so such a call stays a recorded guess."""
        if not self.return_known(target):
            return False
        declared = self.declared_return(target)
        if not declared:
            return True  # a Kotlin block body returns Unit
        name = re.sub(r"<.*|\s+|\?$", "", declared).rsplit(".", 1)[-1]
        if name in NON_DATABASE_RETURNS:
            return True
        if name == "SQLiteDatabase" or name in self.database_aliases():
            return False
        flow = self.native_flow
        return flow is not None and any(
            source.language == target.analyzer.language and node.type != "type_alias"
            for owner in flow.classes.get(name, set())
            for source, node in flow.class_definitions.get(owner, [])
        )

    def return_known(self, target: Any) -> bool:
        """Whether a function's return type is stated: declared, or Unit for a Kotlin block
        body. An expression body infers its type, which the flow may not know."""
        if self.declared_return(target) or target.analyzer.language == "java":
            return True
        body = next((child for child in target.node.named_children if child.type == "function_body"), None)
        return body is not None and target.analyzer.text(body).lstrip().startswith("{")

    def database_aliases(self) -> set[str]:
        """Kotlin typealiases that name SQLiteDatabase, directly or through other aliases."""
        flow = self.native_flow
        if flow is None:
            return set()
        aliases: set[str] | None = flow.__dict__.get("opener_database_aliases")
        if aliases is None:
            edges: list[tuple[str, str]] = []
            for analyzer, root, _nodes in flow.files:
                if analyzer.language != "kotlin":
                    continue
                for node in _walk(root):
                    if node.type != "type_alias":
                        continue
                    named = [child for child in node.named_children if child.type != "modifiers"]
                    alias = next((child for child in named if child.type in IDENTIFIERS), None)
                    if alias is None or len(named) < 2:
                        continue
                    target = re.sub(r"<.*|\?$|\s+", "", analyzer.text(named[-1])).rsplit(".", 1)[-1]
                    edges.append((analyzer.text(alias), target))
            aliases = set()
            changed = True
            while changed:
                changed = False
                for alias_name, target in edges:
                    if alias_name not in aliases and (target == "SQLiteDatabase" or target in aliases):
                        aliases.add(alias_name)
                        changed = True
            flow.__dict__["opener_database_aliases"] = aliases
        return aliases

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
            elif (
                expression.type == "navigation_expression"
                and expression.named_children
                and expression.named_children[0].type == "this_expression"
            ):
                # Only `this.x`; a longer chain names another object's member.
                expression = expression.named_children[-1]
                if expression.type == "navigation_suffix":
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
            if not kotlin and current.type == "method_declaration" and self.has_modifier(current, "static"):
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
                        current.type == "class_declaration" and (local or self.has_modifier(current, "inner"))
                    )
                else:
                    defers = (
                        current.type == "class_declaration"
                        and (local or not self.has_modifier(current, "static"))
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
        if (imported and not android) or (flow is not None and not imported and bool(flow.classes.get(name))):
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
            elif (
                node.type == "postfix_expression"
                and self.text(node).rstrip().endswith("!")
                or node.type == "unary_expression"
                and node.children
                and node.children[-1].type == "!!"
            ):
                # Swift `b!` and Kotlin `b!!` are the object itself.
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
        if any(self.closure_argument(argument) is not None for argument in call.args):
            # ByteArray(n) { init }, [UInt8](unsafeUninitializedCapacity: n) { fill }:
            # a closure fills the values at runtime.
            return None
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
        """The call's own value_arguments node (Kotlin and Swift), on the inner node of `f(x) { }`."""
        if call.arguments is not None:
            return call.arguments
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
        head = self.call_head(node)
        callee = head.named_children[0]
        navigation = self.navigation(callee)
        receiver, name = navigation if navigation else (None, self.symbol_name(self.text(callee)))
        arguments = next((part for part in head.named_children if part.type == "value_arguments"), None)
        if arguments is None:
            suffix = next((part for part in head.named_children if part.type == "call_suffix"), None)
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
        # A trailing lambda is the call's last argument (Kotlin, Swift SE-0279/0286).
        trailing = tuple(self.trailing_lambdas(node))
        return Call(node, name, receiver, (*args, *trailing), trailing, arguments)

    def call_head(self, node: Any) -> Any:
        """The call node that holds the callee and parenthesized arguments of `node`.

        tree-sitter nests a call written with parentheses and a trailing lambda:
        Kotlin `f(x) { }` is call(call(f, (x)), { }) in every context, and Swift
        does the same in property initializers (`let r = f(x) { }`, also inside
        try/await). Exactly one level is merged, only when the outer node adds
        nothing but lambdas and the inner call ends in its own argument list and
        carries no lambda. `f(x) {} {}` and `f(x)(y)` invoke a result instead.
        """
        parts = [part for part in node.named_children if part.type not in COMMENTS]
        if len(parts) != 2:
            return node
        inner, suffix = parts
        if self.language == "kotlin":
            if suffix.type != "annotated_lambda" or inner.type != "call_expression":
                return node
            inner_parts = [part for part in inner.named_children if part.type not in COMMENTS]
            if (
                len(inner_parts) >= 2
                and inner_parts[-1].type == "value_arguments"
                and not any(part.type == "annotated_lambda" for part in inner_parts)
            ):
                return inner
            return node
        if self.language != "swift" or suffix.type != "call_suffix":
            return node
        if any(part.type == "value_arguments" for part in suffix.named_children) or not any(
            part.type == "lambda_literal" for part in suffix.named_children
        ):
            return node
        while inner is not None and inner.type in {"try_expression", "await_expression"}:
            inner = _field(inner, "expr")
        if inner is None or inner.type != "call_expression":
            return node
        inner_parts = [part for part in inner.named_children if part.type not in COMMENTS]
        if len(inner_parts) != 2 or inner_parts[1].type != "call_suffix":
            return node
        inner_suffix = inner_parts[1].named_children
        if any(part.type == "value_arguments" for part in inner_suffix) and not any(
            part.type == "lambda_literal" for part in inner_suffix
        ):
            return inner
        return node

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
        if self.reuse_visited:
            visited = self.visited_values.get((node.start_byte, node.end_byte, node.type))
            if visited is not None:
                return visited
        if node.type == "when_subject":
            subject = [
                part for part in node.named_children if part.type not in COMMENTS | {"variable_declaration"}
            ]
            return self.value(subject[-1], frame) if subject else Value()
        if node.type == "switch_statement" and self.language == "swift":
            # A switch expression evaluates to one of its cases' values, not its subject.
            return self.changed(
                node,
                _union(
                    [
                        self.value(entry, frame)
                        for entry in node.named_children
                        if entry.type == "switch_entry"
                    ]
                ),
            )
        if node.type == "switch_entry" and self.language == "swift":
            # A case's value is its last statement, read while its names are bound; its
            # pattern and where clause are conditions.
            body = next((part for part in node.named_children if part.type == "statements"), None)
            last = self.last_statement(body) if body is not None else None
            if last is None:
                return Value()
            with self.names_bound(frame, self.switch_entry_values(node, frame)):
                return self.changed(node, self.value(last, frame))
        binding = self.when_binding(node)
        if binding is not None:
            # A `when (val u = x)` evaluates to an entry's value, read while u is bound;
            # x is part of it only where an entry returns u.
            key, variable, expression = binding
            subject = self.value(expression, frame).bind(self.point(variable))
            with self.subject_bound(frame, key, subject):
                # Each entry's value is its body's last statement; its conditions are not values.
                entries = [
                    self.value(self.last_statement(branch), frame)
                    for branch in self.branch_bodies(node) or []
                    if branch is not None
                ]
            return self.changed(node, _union(entries))
        if node.type in CLOSURES:
            # A closure is followed where it is written; its value is the result
            # recorded there, never a second walk of its body in another frame.
            return self.closure_values.get((node.start_byte, node.end_byte), Value())
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
            known = self.evaluated_inputs
            if known is not None and known[0] == (node.start_byte, node.end_byte):
                # Bound before the call's closures could run (the visitor computed them).
                self.evaluated_inputs = None
                receiver, given = known[1], known[2]
                args = [
                    given[index] if index in given else self.value(arg, frame)
                    for index, arg in enumerate(call.args)
                ]
            else:
                receiver = self.value(call.receiver, frame)
                args = [self.value(arg, frame) for arg in call.args]
            database = self.sqlite_database_call(call, receiver, frame)
            follow, certain, returns, prefers, record = (
                self.opener_follow,
                self.opener_certain,
                self.opener_returns,
                self.opener_prefers_framework,
                self.opener_record,
            )
            self.opener_follow = self.opener_certain = self.opener_returns = False
            self.opener_prefers_framework = self.opener_record = False
            if follow and self.native_flow is not None:
                # A project opener is always followed. Unless the framework type is certain
                # (an override or a declared SQLiteDatabase return), which callee runs is a
                # guess between the project function and an inherited framework member:
                # the guess picks the result type and is always recorded (limited).
                result = self.native_flow.call(self, call, frame, receiver, args)
                if not certain:
                    self.native_flow.partial("opener receiver identity unresolved", self, call=call)
                known = returns or (result is not None and bool(result.type_name))
                if database and (certain or prefers or not known):
                    return (
                        Value(result.traces, result.category, SQLITE_DATABASE, result.identity)
                        if result is not None
                        else Value(type_name=SQLITE_DATABASE)
                    )
                if result is not None:
                    return result
            elif database:
                if record and self.native_flow is not None:
                    # A source callable of that name may run instead; the flow cannot follow it.
                    self.native_flow.partial("opener receiver identity unresolved", self, call=call)
                return Value(type_name=SQLITE_DATABASE)
            elif self.native_flow is not None:
                result = self.native_flow.call(self, call, frame, receiver, args)
                if result is not None:
                    return result
            if (
                call.receiver is None
                and call.name.rsplit(".", 1)[-1] in STRING_TRANSFORMS
                and "this" in self.aliases
                and frame.kotlin_bound_scopes
            ):
                # Project callees were resolved above. An unresolved String transform in
                # a bound run/with/apply scope reads that scope's implicit receiver.
                bound = frame.values.get("this", receiver)
                receiver = bound
                for builder in reversed(self.closure_effects):
                    if not builder.implicit:
                        continue
                    if bound is not builder.outer_this or not builder.receiver_types:
                        break  # a nearer scope rebind or unknown DSL ends the known receiver tower
                    if self.builder_transform(call, builder.receiver_types, frame):
                        receiver = _union(builder.values)
                        break
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
                return self.changed(
                    node, Value(_union(self.call_inputs(call, receiver, args)).traces, "unknown", simple)
                )
            # Unknown calls retain input provenance, with no assumed sanitization or return type.
            return self.changed(node, _union(self.call_inputs(call, receiver, args)))
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

    def call_inputs(self, call: Call, receiver: Value, args: list[Value]) -> list[Value]:
        """The receiver and argument values a call's own result is built from.

        A followed closure's result that derives from the call's other inputs (an
        element of the receiver, a captured argument) repeats their sources under
        new origins. Each source is kept once, so chains such as
        `xs.map { }.filter { }` do not double their traces at every call; a trace
        with a cut marker is always kept.
        """
        if len(args) != len(call.args):
            return [receiver, *args]
        closures = {index for index, node in enumerate(call.args) if self.closure_argument(node) is not None}
        if not closures:
            return [receiver, *args]
        if call.name.rsplit(".", 1)[-1] in SELECTING_FUNCTIONS:
            # A predicate, comparator or per-element action decides what the call returns;
            # its own result is not part of the value (an element, a count or a flag).
            return [receiver, *(Value() if index in closures else value for index, value in enumerate(args))]
        seen = {
            self.source_key(trace)
            for value in [receiver, *(value for index, value in enumerate(args) if index not in closures)]
            for trace in value.traces
        }
        kept = []
        for index, value in enumerate(args):
            if index in closures:
                value = Value(
                    tuple(
                        self.possible_result(trace)
                        for trace in value.traces
                        if trace_cuts(trace.description) or self.source_key(trace) not in seen
                    ),
                    value.category,
                    value.type_name,
                    value.identity,
                )
            kept.append(value)
        return [receiver, *kept]

    @staticmethod
    def possible_result(trace: Trace) -> Trace:
        """A closure result in an unresolved call's value, which the callee may never return.

        Folding it in is an over-approximation, so a trace-cap cut in it is a precision
        limit there, not an execution gap of the call.
        """
        if TRACE_PARTIAL not in trace.description:
            return trace
        description = trace.description.replace(TRACE_PARTIAL, "")
        if TRACE_LIMITED not in description:
            description += TRACE_LIMITED
        return Trace(trace.origin, trace.source, description, trace.steps, trace.path_safe, trace.path_route)

    def source_key(self, trace: Trace) -> tuple[str, int]:
        """Where a trace's input was read: one source, whichever route its value took."""
        location = (
            trace.source.location if isinstance(trace.source, SourceNode) else self.location(trace.source)
        )
        return location.get("path", ""), location.get("offset", -1)

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
            if condition.type in CLOSURES:
                # A closure marker scopes the closure; its body is not a condition.
                continue
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
        if (
            self.language in {"java", "kotlin"}
            and call.args
            and any(call.name == method for _qualified, method in SQL_SINKS)
        ):
            # Only a sink method name needs its receiver type.
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
        if node.type in CLOSURES:
            self.visit_closure(node, frame, guards, conditions)
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
                self.return_values.append(self.reused(expressions[-1], frame).bind(self.point(node)))
            elif expressions and self.closure_depth:
                # A Swift/Java closure return, or Kotlin return@label to a lambda, leaves only
                # that closure: its value is the closure's result, not the function's.
                target = self.closure_return_target(node, label_node if labeled else None)
                if target is not None:
                    # Its calls were evaluated by the visit above: reuse, never repeat them.
                    self.closure_returns[target].append(self.reused(expressions[-1], frame))
            return
        line = (node.start_byte, node.end_byte, node.type)
        if self.closure_effects and line not in self.gluing:
            glued = self.glued_line(node)
            if glued is not None:
                # tree-sitter-kotlin 1.1.0 glued `where(..)` lines onto this one: declare or
                # assign the line's own value first, then each glued call reads the name bound.
                self.gluing[line] = glued[0]
                try:
                    self.visit(node, frame, guards, conditions)
                finally:
                    del self.gluing[line]
                for infix, misparsed in glued[1]:
                    parts = [part for part in infix.named_children if part.type not in COMMENTS]
                    for part in parts[1:]:
                        self.visit(part, frame, guards, conditions)
                    self.statement_positions[(infix.start_byte, infix.end_byte, infix.type)] = True
                    self.record_visited(misparsed, frame, Value())
                return
        declaration = self.declaration(node)
        if declaration:
            name, expression, type_name = declaration
            expression = self.gluing.get(line, expression)
            frame.local_names.add(name)
            if expression:
                self.visit(expression, frame, guards, conditions)
            described = self.constant(expression, frame) if expression is not None else None
            if described:
                frame.constants[name] = described
            else:
                frame.constants.pop(name, None)
            value = self.reused(expression, frame)
            if self.closure_depth and expression is not None:
                # Content classification happens later in the enclosing frame. Preserve
                # computed initializers while this closure's own names are still bound.
                self.visited_values[(expression.start_byte, expression.end_byte, expression.type)] = value
            value = value.bind(self.point(node))
            if self.native_flow is not None:
                value = self.native_flow.local_value(
                    self, node, type_name, value, frame, initialized=expression is not None
                )
            literal = expression is not None and self.string_initializer(expression)
            frame.values[name] = Value(
                value.traces,
                value.category,
                type_name or value.type_name or ("String" if literal else ""),
                value.identity,
            )
            if type_name:
                frame.types[name] = type_name
            if self.closure_effects and expression is not None:
                self.alias_supplied(name, expression, frame)
            return
        if node.type in {"assignment_expression", "assignment"}:
            left = self.assignment_target(
                _field(node, "left") or _field(node, "target") or next(iter(node.named_children), None)
            )
            right = self.gluing.get(
                line,
                _field(node, "right")
                or _field(node, "result")
                or (node.named_children[-1] if len(node.named_children) > 1 else None),
            )
            if left and right and left != right:
                operator = self.text(_field(node, "operator"))
                previous = self.value(left, frame) if operator != "=" else None
                target = self.symbol_name(self.text(left)) if left.type in IDENTIFIERS else None
                self.visit(right, frame, guards, conditions)
                # A closure on the right that assigns the target may run after the assignment:
                # keep what it wrote (not the value from before the assignment).
                deferred = self.deferred_write(right, target) if target is not None else None
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
                value = self.reused(right, frame)
                if self.closure_depth:
                    self.visited_values[(right.start_byte, right.end_byte, right.type)] = value
                value = value.bind(self.point(node))
                if deferred is not None:
                    value = _union([value, deferred], "unknown", value.type_name)
                if previous is not None:
                    value = (
                        self.native_flow.compound_value(
                            self, node, left, right, previous, value, operator, frame
                        )
                        if self.native_flow is not None
                        else self.changed(node, _union([previous, value], type_name=previous.type_name))
                    )
                if self.closure_effects:
                    base = (
                        left.named_children[0]
                        if left.type in {"indexing_expression", "index_expression"} and left.named_children
                        else left
                    )
                    if self.implicit_this(base, frame):
                        # `this += q`, `this["k"] = q` in a builder lambda write into its receiver.
                        self.record_effect(None, frame, value, expressions=(right,))
                    elif left.type not in IDENTIFIERS:
                        self.record_effect(left, frame, value, receiverless=False, expressions=(right,))
                    elif not (
                        {key, self.symbol_name(self.text(left))}
                        & (frame.values.keys() | frame.types.keys() | frame.local_names)
                    ):
                        # A name that is no local or field: a property of an implicit receiver.
                        self.record_effect(None, frame, value, expressions=(right,))
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
                    if self.closure_depth:
                        # A callback that may run after an enclosing assignment stored this.
                        self.assigned_values[(node.start_byte, node.end_byte)] = frame.values[key]
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
            # A Kotlin lambda's statements are its direct children (no block node).
            statement = node.parent is not None and (
                node.parent.type in BLOCKS
                or self.language == "kotlin"
                and node.parent.type == "lambda_literal"
            )
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
            exited = False
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
                    exited = True
                    break
            self.record_block_result(node, local, exited)
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
        if node.type == "switch_entry" and self.language == "swift":
            values = self.switch_entry_values(node, frame)
            if values:
                with self.names_bound(frame, values):
                    for child in node.named_children:
                        self.visit(child, frame, guards, conditions)
                return
        binding = self.when_binding(node)
        if binding is not None:
            # `when (val u = x)` binds u for its entries only, shadowing an outer u.
            key, variable, expression = binding
            self.visit(expression, frame, guards, conditions)
            used = self.closure_depth and self.result_position(node) or not self.discarded(node)
            if used:
                # A braced entry's value is its last statement, read in the entry's own frame
                # (`else -> { val v = u.trim(); v }`) by record_block_result.
                self.mark_value_blocks(node)
            with self.subject_bound(frame, key, self.reused(expression, frame).bind(self.point(variable))):
                for child in node.named_children:
                    if child.type != "when_subject":
                        self.visit(child, frame, guards, conditions)
                if used:
                    # A bare entry value is read later, as the closure's result or the
                    # when's value; read it now, while the subject's name is bound.
                    self.record_branch_leaves(node, frame)
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
        misparsed = self.misparsed_call(node) if self.closure_effects else None
        if misparsed is not None:
            # `append(..)` and a `where(..)` line read as one infix expression: two statements.
            # The expression keeps its value (a closure's result may be it); the call writes where
            # the line stands, also where tree-sitter glued it onto the last operand of a
            # declaration's or assignment's value (`val n = limit ?: 10` then `where(..)`; a
            # line glued to the value itself: glued_line). That is known before the operands
            # are visited, so an earlier glued line among them stands where this one does.
            if self.glued_operand(node):
                self.statement_positions[(node.start_byte, node.end_byte, node.type)] = True
            for child in node.named_children:
                self.visit(child, frame, guards, conditions)
            self.record_visited(misparsed, frame, self.reused(node, frame))
            return
        call = self.call(node)
        if call:
            if call.receiver:
                self.visit(call.receiver, frame, guards, conditions)
            head = self.call_head(node) if node.type == "call_expression" else None
            callee = head.named_children[0] if head is not None and head.named_children else None
            if callee is not None and call.receiver is None and callee.type not in DIRECT_CALLEES:
                # A computed callee (f()() { }, pick(x)(), { }(), handlers[0] { }) is
                # evaluated before the call; its own calls and closures run. A member
                # callee's receiver was visited above.
                self.visit(callee, frame, guards, conditions)
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
            open_url = self.language == "swift" and call.name == "onOpenURL"
            # Each lambda argument, in parentheses or trailing, is visited exactly once.
            # Scope-function and onOpenURL lambdas are bound after the call. Any other
            # closure may run while the call runs: it is followed after the data
            # arguments are evaluated and before the call's value is taken.
            lambdas = []
            closures = []
            for index, arg in enumerate(call.args):
                argument = self.closure_argument(arg)
                if argument is None:
                    self.visit(arg, frame, guards, conditions)
                elif with_arguments is not None and argument.type == "lambda_literal":
                    # Receiver-lambda evidence was inspected separately above.
                    # Only the block parameter gets an inline scope binding.
                    if arg == with_arguments.get("block") or arg in call.trailing:
                        lambdas.append(argument)
                elif (scope is not None and argument.type == "lambda_literal") or open_url:
                    # Kotlin permits both f { ... } and f(block = { ... }).
                    # Bind either spelling once; the generic visitor has no
                    # receiver and cannot establish an inline return context.
                    lambdas.append(argument)
                else:
                    closures.append((index, argument))
            if self.closure_depth:
                if (
                    self.language == "kotlin"
                    and call.receiver is None
                    and call.name == "format"
                    and frame.kotlin_bound_scopes
                    and "this" in self.aliases
                    and self.string_template_root(self.aliases["this"], frame)
                    and not (
                        self.native_flow is not None
                        and self.native_flow.resolve(self, call, Value(), frame)[0]
                    )
                ):
                    template = self.aliases["this"]
                    self.implicit_formats[(call.node.start_byte, call.node.end_byte)] = template
                    self.visited_values[(template.start_byte, template.end_byte, template.type)] = (
                        frame.values.get("this", Value())
                    )
                formatted = self.format_parts(call, frame)
                if formatted is not None:
                    for index, argument in enumerate(call.args):
                        if _same_node(argument, formatted[0]):
                            self.format_argument_offsets[(call.node.start_byte, call.node.end_byte)] = index
                            break
                kept = [formatted[0], *formatted[1]] if formatted is not None else []
                if call.name.rsplit(".", 1)[-1] in TEMPLATE_FILLS:
                    kept.extend(self.inserted_arguments(call))
                for argument in kept:
                    if self.closure_argument(argument) is None:
                        self.visited_values[(argument.start_byte, argument.end_byte, argument.type)] = (
                            self.reused(argument, frame)
                        )
            # The receiver and data arguments are bound before a closure can run. They are
            # computed once here and shared with the closures' element parameters, the
            # call's value and its sink checks.
            inputs = (
                self.call_input_values(call, frame) if closures or lambdas and scope is not None else None
            )
            if inputs is not None and closures:
                # A builder call on a supplied object (`b.body { .. }`) writes into that object.
                used = (
                    not self.discarded(call.node)
                    or bool(self.closure_effects)
                    and (
                        self.supplied(call.receiver, frame)
                        or call.receiver is None
                        and self.implicit_write(call)
                    )
                )
                for index, argument in closures:
                    self.visit_closure(
                        argument, frame, guards, conditions, call, index, inputs[0], used, inputs[1]
                    )
            for lambda_node in lambdas:
                # Their result is read after the scope binding below, not before.
                self.closure_values.pop((lambda_node.start_byte, lambda_node.end_byte), None)
            if self.native_flow is not None:
                self.native_flow.active_guards = guards
                self.native_flow.active_conditions = conditions
                if inputs is not None:
                    self.evaluated_inputs = ((call.node.start_byte, call.node.end_byte), *inputs)
                # Its arguments' and receiver's calls were visited above: reuse their values.
                self.record_visited(call, frame, self.reused(call.node, frame))
                self.evaluated_inputs = None
            # The sink checks read the receiver and arguments as the visit computed them,
            # before any closure ran (also for a sink whose argument is such a call).
            reuse = self.reuse_visited
            self.reuse_visited = True
            try:
                self.check_call(call, frame, guards, conditions)
            finally:
                self.reuse_visited = reuse
            self.release_constants(call, frame)
            callee_text = self.text(callee) if callee is not None else ""
            for lambda_node in lambdas:
                if open_url:
                    self.visit_open_url_callback(lambda_node, frame, guards, conditions)
                elif scope is not None:
                    # x?.let {} may not run, and return@ may leave the lambda early.
                    optional = bool(re.search(r"\?\.\s*\w+\s*$", callee_text)) or "return@" in self.text(
                        lambda_node
                    )
                    self.visit_scope_lambda(lambda_node, frame, guards, conditions, *scope, optional)
            if (
                inputs is not None
                and lambdas
                and scope is not None
                and scope[0] in {"let", "run", "with", "use"}
            ):
                # The scope call's value carries its block's result, known only now. It is
                # built from the bound inputs and that result, never by running the call again.
                receiver, given = inputs
                args = [
                    given[index] if index in given else self.value(arg, frame)
                    for index, arg in enumerate(call.args)
                ]
                key = (call.node.start_byte, call.node.end_byte, call.node.type)
                previous = self.visited_values.get(key, Value())
                result = self.changed(call.node, _union(self.call_inputs(call, receiver, args)))
                merged = _union([previous, result], previous.category, previous.type_name)
                if not any(
                    TRACE_PARTIAL in trace.description
                    for value in (previous, receiver, *args)
                    for trace in value.traces
                ):
                    # A cut no input carried comes from folding the block's result in.
                    merged = Value(
                        tuple(self.possible_result(trace) for trace in merged.traces),
                        merged.category,
                        merged.type_name,
                        merged.identity,
                    )
                self.visited_values[key] = merged
            return
        if (
            node.type == "unary_expression"
            and self.language == "kotlin"
            and self.closure_effects
            and re.match(r"\+(?!\+)", self.text(node).lstrip())
            and node.named_children
        ):
            # `+q` in a DSL lambda (kotlinx.html) adds q to the implicit receiver.
            for child in node.named_children:
                self.visit(child, frame, guards, conditions)
            self.record_effect(
                None,
                frame,
                self.reused(node.named_children[-1], frame),
                expressions=(node.named_children[-1],),
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

    def closure_argument(self, node: Any) -> Any:
        """The lambda or closure literal an argument is (through parentheses and labels), or None."""
        argument = self.scope_lambda_argument(node)
        return argument if argument is not None and argument.type in CLOSURES else None

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
        rows = (
            [row for row in arguments.named_children if row.type not in COMMENTS]
            if arguments is not None
            else []
        )
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

    def visit_closure(
        self,
        node: Any,
        frame: Frame,
        guards: dict[GuardKey, set[str]],
        conditions: list[Any],
        owner: Call | None = None,
        position: int = -1,
        receiver: Value | None = None,
        used: bool = False,
        given: dict[int, Value] | None = None,
    ) -> None:
        """Follow a closure that is not a scope-function block, as a block that may not run.

        It is inspected once where it is written: guards that hold there apply inside,
        guards it establishes do not apply after it, and its writes may or may not
        have happened. Declared parameters (and Swift `$0`) are locals that shadow
        outer names; they carry no value, except that an element parameter of a
        known collection function keeps the receiver's provenance, as `first()` does.
        A Kotlin `it` is bound only for those functions: for any other callee the
        lambda may take no parameter, and an enclosing `it` stays visible. When the
        call's value is used, what the closure writes into its other parameters
        (or passes to receiverless calls, for a Kotlin lambda without parameters)
        is part of its value: the callee supplied those objects and may return them.
        """
        positions: tuple[int, ...] = ()
        element = Value()
        accumulator: int | None = None
        arity = self.closure_arity(node)
        dollars = (
            {
                int(self.text(part)[1:])
                for part in _closure_parts(node)
                if part.type in IDENTIFIERS and re.fullmatch(r"\$\d+", self.text(part))
            }
            if node.type == "lambda_literal" and self.language == "swift" and arity is None
            else set()
        )
        if owner is not None and position == len(owner.args) - 1:
            name = owner.name.rsplit(".", 1)[-1]
            positions = ELEMENT_FUNCTIONS.get(name, ())
            if (
                positions == (0,)
                and (arity == 2 or dollars == {0, 1} or dollars == {1})
                and (self.language == "swift" or name == "forEach")
            ):
                positions = (0, 1)  # Map.forEach { key, value -> }, Swift dictionary (key, value) elements
            elif self.language == "swift" and name == "reduce":
                positions, accumulator = (1,), 0  # Swift's accumulator starts as the initial value
            accumulator = ACCUMULATORS.get(name, accumulator)
            if positions and owner.receiver is not None:
                if receiver is None:
                    receiver = self.value(owner.receiver, frame)
                element = self.changed(node, Value(receiver.traces)) if receiver.traces else Value()
        accumulated = Value()
        if accumulator is not None and given:
            initial = given[min(given)]
            accumulated = (
                self.changed(node, _union([initial, element]))
                if initial.traces or element.traces
                else Value()
            )
        parameters = self.closure_parameters(node)
        bindings: dict[str, Value] = {}
        for name, declared_type, index in parameters:
            value = element if index in positions else accumulated if index == accumulator else Value()
            bindings[name] = Value(value.traces, value.category, declared_type or value.type_name)
        supplied = {
            name: bindings[name]
            for name, _, index in parameters
            if index not in positions and index != accumulator
        }
        if node.type == "lambda_literal" and self.language == "swift":
            for capture in (part for part in node.named_children if part.type == "capture_list"):
                for item in capture.named_children:
                    name, initializer = _field(item, "name"), _field(item, "value")
                    if name is not None and initializer is not None:
                        bindings[self.text(name)] = self.value(initializer, frame)
            for number in sorted(dollars):
                text = f"${number}"
                if text not in bindings:
                    bindings[text] = (
                        element if number in positions else accumulated if number == accumulator else Value()
                    )
                    if number not in positions and number != accumulator:
                        supplied[text] = bindings[text]
        elif arity is None and node.type == "lambda_literal" and positions == (0,):
            # Only a lambda that declares no parameter list has an implicit `it`.
            bindings["it"] = element
        elif arity is None and node.type == "lambda_literal" and not positions and "it" not in frame.values:
            # With no enclosing `it`, an `it` here can only be this lambda's own parameter.
            bindings["it"] = Value()
            supplied["it"] = bindings["it"]
        effects = None
        if used:
            callee = owner.name.rsplit(".", 1)[-1] if owner is not None else ""
            receiver_text = (
                re.sub(r"\s+", "", self.text(owner.receiver))
                if owner is not None and owner.receiver is not None
                else ""
            )
            # `Sql.execute { }`: an entry point of a project or library object (a capitalized
            # object or class path, not a constructor or factory call such as `Handler(..)`).
            on_object = bool(re.fullmatch(r"[A-Z]\w*(?:\.[A-Za-z_]\w*)*", receiver_text))
            # `kotlin.concurrent.thread { }`, `kotlinx.coroutines.flow.flow { }`: through a package.
            standard_receiver = not receiver_text or (
                re.fullmatch(r"[a-z]\w*(?:\.[a-z]\w*)+", receiver_text) is not None
                and receiver_text.split(".", 1)[0] in PACKAGE_ROOTS
                and receiver_text.split(".", 1)[0] not in frame.values
            )
            # A SAM constructor or composable (`Runnable { }`, `Column { }`), a coroutine or
            # runner callee (`withContext`, `runCatching`, `lazy`) and an event-handler
            # registration give their lambda no receiver whose data their value returns.
            # A standard top-level runner's name on an object (`dsl.remember { }`) is its member.
            implicit = (
                self.language == "kotlin"
                and node.type == "lambda_literal"
                and arity is None
                and not positions
                and callee not in COROUTINE_BUILDERS
                and not (
                    callee in NO_DATA_RECEIVERS
                    and not on_object
                    and (callee not in TOP_LEVEL_RUNNERS or standard_receiver)
                )
                and not callee[:1].isupper()
                and (callee in FLOW_OPERATORS or not CALLBACK_REGISTRATIONS.match(callee))
            )
            if supplied or implicit:
                # The standard builders (`buildString { }`, `flow { }`) are called without a
                # receiver, through their package, or (`produce`) on a coroutine scope;
                # `Ext.flow { }` and `repo.flow { }` are other objects' DSLs. The flow
                # operators (`pages.onStart { }`) are called on a flow.
                standard = (
                    implicit
                    and callee in BUILDER_MEMBERS
                    and (
                        standard_receiver or callee in FLOW_OPERATORS or callee == "produce" and not on_object
                    )
                )
                members = (
                    BUILDER_MEMBERS[callee]
                    if standard
                    else BUILDER_MEMBER_NAMES
                    if implicit and callee.startswith("build")
                    else frozenset()
                )
                effects = ClosureEffects(
                    supplied,
                    implicit,
                    [],
                    members,
                    BUILDER_RECEIVERS.get(callee, frozenset()) if standard else frozenset(),
                    frame.values.get("this"),
                )
                if (
                    standard
                    and callee == "buildString"
                    and owner is not None
                    and not (
                        self.native_flow is not None
                        and self.native_flow.resolve(self, owner, Value(), frame)[0]
                    )
                ):
                    self.string_builder_results.add((node.start_byte, node.end_byte))
        self.visit_scope_lambda(
            node, frame, guards, conditions, "", None, optional=True, bindings=bindings, effects=effects
        )

    def record_visited(self, call: Call, frame: Frame, value: Value) -> None:
        """Keep the value the visitor computed for a call, and what it hands to a closure's parameter."""
        self.visited_values[(call.node.start_byte, call.node.end_byte, call.node.type)] = value
        if not self.closure_effects:
            return
        data = [arg for arg in call.args if self.closure_argument(arg) is None]
        # Only the object itself, or a part of it, handed over can be written into
        # (not `b.length`), by a call written as a statement (not a condition) that is
        # no logging call (`Log.d(TAG, b.body)`).
        statement = self.statement_position(call.node) and not self.logging_call(call)
        targets = [arg for arg in data if self.handed_over(arg, frame)] if statement else []
        # `appendFilter(this, q)` in a builder lambda hands the implicit receiver itself.
        handed_this = statement and any(self.implicit_this(arg, frame) for arg in data)
        name = call.name.rsplit(".", 1)[-1]
        owner = next((effects for effects in reversed(self.closure_effects) if effects.implicit), None)
        bound_transform = (
            call.receiver is None
            and name in STRING_TRANSFORMS
            and "this" in self.aliases
            and frame.kotlin_bound_scopes
            and owner is not None
            and frame.values.get("this") is not owner.outer_this
            and self.string_template_root(self.aliases["this"], frame)
        )
        writes = (
            call.receiver is not None
            and name not in READ_ONLY_MEMBERS
            and self.supplied(call.receiver, frame)
            or (call.receiver is None and not bound_transform and self.implicit_write(call))
        )
        # `append("<p>").append(q)` and `this.append(q)` write into the implicit receiver.
        chain = (
            []
            if writes or call.receiver is None or name in READ_ONLY_MEMBERS
            else self.implicit_chain(call, frame)
        )
        if not writes and not chain and not targets and not handed_this:
            return
        # What the call writes into the supplied object is its data, whichever callee
        # runs (a followed project function of the same name returns nothing), what a
        # nested builder closure wrote into its own supplied object, and the result of a
        # closure the receiver stores (`m.getOrPut(k) { q }`) or takes as content
        # (`b.section { q }`).
        nested = [self.closure_argument(arg) for arg in call.args if self.closure_argument(arg) is not None]
        content_closures = [
            closure
            for closure in nested
            if closure is not None
            and (
                name in RESULT_STORING_CALLS
                # `b.section { q }`, a DSL's `title { q }` and a Java supplier `() -> q` give
                # content; an imported logging function's lambda (`logcat { "msg $q" }`) is a
                # lazy message.
                or (writes or chain or targets or handed_this)
                and (call.receiver is not None or not self.lazy_logger(name))
                and self.closure_arity(closure) in (None, 0)
                and name not in SELECTING_FUNCTIONS | INLINE_CALLEES | READ_ONLY_MEMBERS
                and name not in ELEMENT_FUNCTIONS
                and not CALLBACK_REGISTRATIONS.match(name)
                and self.content_closure(closure, frame)
            )
        ]
        content = [
            self.closure_values.get((closure.start_byte, closure.end_byte), Value())
            for closure in content_closures
        ]
        expressions = [
            arg for arg in data if not self.supplied(arg, frame) and not self.implicit_this(arg, frame)
        ]
        expressions.extend(arg for link in chain for arg in link.args if self.closure_argument(arg) is None)
        expressions.extend(
            closure
            for closure in nested
            if closure is not None
            and (
                closure in content_closures
                or self.closure_written.get((closure.start_byte, closure.end_byte), Value()).traces
            )
        )
        written = _union(
            [
                self.reused(arg, frame)
                for arg in data
                if not self.supplied(arg, frame) and not self.implicit_this(arg, frame)
            ]
            + [
                self.reused(arg, frame)
                for link in chain
                for arg in link.args
                if self.closure_argument(arg) is None
            ]
            + [
                self.closure_written.get((closure.start_byte, closure.end_byte), Value())
                for closure in nested
                if closure is not None
            ]
            + content
        )
        if (targets or handed_this) and call.receiver is not None and not self.supplied(call.receiver, frame):
            # `parts.joinTo(b)`, `parts.joinTo(this)` write their receiver into the handed object.
            handed = _union([written, self.reused(call.receiver, frame)])
            expressions.append(call.receiver)
        else:
            handed = written
        if call.receiver is not None and writes:
            self.record_effect(call.receiver, frame, written, expressions=tuple(expressions))
        elif writes or chain:
            self.record_effect(None, frame, written, expressions=tuple(expressions))
        elif handed_this:
            self.record_effect(None, frame, handed, expressions=tuple(expressions))
        written = handed
        for arg in targets:
            # A helper handed the supplied object (`fill(b, q)`) may write into it.
            for part in self.handed_parts(arg):
                self.record_effect(part, frame, written, receiverless=False, expressions=tuple(expressions))

    def reused(self, node: Any, frame: Frame) -> Value:
        """value() of a node the visit just walked: its calls keep the values they were visited with."""
        reuse = self.reuse_visited
        self.reuse_visited = True
        try:
            return self.value(node, frame)
        finally:
            self.reuse_visited = reuse

    def record_block_result(self, node: Any, frame: Frame, exited: bool) -> None:
        """Keep the final value of a branch block whose value can be a followed closure's result.

        It is computed in the block's own frame, where names the branch declares or
        binds (`{ val t = ..; t }`, Swift `if let`) are still visible; a block that
        always exits leaves no value. Also kept for a braced entry of a `when (val u = ..)`
        whose value is read (value_blocks), which reads its entries' last statements.
        """
        if (node.start_byte, node.end_byte) not in self.value_blocks and (
            not self.closure_depth or not self.result_position(node)
        ):
            return
        statements = [part for part in node.named_children if part.type not in COMMENTS]
        if not statements:
            return
        last = statements[-1]
        key = (last.start_byte, last.end_byte, last.type)
        if exited:
            self.visited_values[key] = Value()
        elif self.branching(last):
            self.record_branch_leaves(last, frame)
        elif last.type not in STATEMENT_ONLY and not self.declaration(last):
            self.visited_values[key] = self.reused(last, frame)

    def result_position(self, node: Any) -> bool:
        """Whether a node's value can be the value of the closure that encloses it.

        Each step up is decided once per node (tree-sitter's parent walk costs the
        depth), so long branch chains stay linear.
        """
        path = []
        current = node
        result = False
        while True:
            key = (current.start_byte, current.end_byte, current.type)
            cached = self.result_positions.get(key)
            if cached is not None:
                result = cached
                break
            path.append(key)
            parent = current.parent
            if parent is None:
                break
            if parent.type == "lambda_expression":
                result = _field(parent, "body") == current
                break
            if parent.type == "lambda_literal":
                result = self.last_part(parent) == key
                break
            if parent.type in {"block", "statements", "control_structure_body"}:
                # The last statement of each parent is found once (a flat lambda of n braced
                # statements stays linear).
                if self.last_part(parent) != key:
                    break
                if (
                    parent.type == "statements"
                    and parent.parent is not None
                    and parent.parent.type in CLOSURES
                ):
                    result = len([part for part in parent.named_children if part.type not in COMMENTS]) == 1
                    break
            elif parent.type not in BRANCHING | {"when_entry", "switch_entry", "catch_block"}:
                break
            current = parent
        for key in path:
            self.result_positions[key] = result
        return result

    def lazy_logger(self, name: str) -> bool:
        """A logging function this file imports, by name or through a star import
        (`import logcat.logcat`, `import logcat.*`), whose lambda is a lazy message."""
        if not LAZY_LOGGERS.fullmatch(name) or self.native_flow is None:
            return False
        return bool(self.native_flow.imported_symbols(self, name)) or any(
            declaration.strip().endswith(".*") and LOGGING_PACKAGE.search(declaration)
            for declaration in self.imports
        )

    def logging_call(self, call: Call) -> bool:
        """A logging or analytics call (`Log.d(..)`, `Timber.d(..)`, `logger.info(..)`,
        `println(..)`, `analytics.track(..)`)."""
        if call.receiver is None:
            return call.name in LOGGING_FUNCTIONS
        text = re.sub(r'"(?:[^"\\]|\\.)*"', "", self.text(call.receiver))
        previous = None
        while previous != text:
            # `Fill.with(tracker).into(..)` names Fill and with, not its argument.
            previous, text = text, re.sub(r"\([^()]*\)", "", text)
        names = re.findall(r"[A-Za-z_]\w*", text)
        if not names:
            return False
        if names[0] == "System":
            return len(names) > 1 and names[1] in {"out", "err"}  # not `System.arraycopy(..)`
        return bool(LOGGING_NAME.fullmatch(names[0]) or LOGGING_NAME.fullmatch(names[-1]))

    def content_closure(self, closure: Any, frame: Frame) -> bool:
        """A closure whose result is a value (`{ q }`, `{ "a" + q }`, `{ q.trim() }`, also on its
        own locals, `{ val t = q.trim(); t.uppercase() }`), not the result of a call it makes
        (`{ analytics.track(q) }`, `{ [weak self] in self?.log(q) }`)."""
        # A classification of visited code: its re-reads record no precision reasons.
        outer = self.closure_classification_work is None
        if outer:
            self.closure_classification_work = 0
            self.closure_classification_cut = False
            self.closure_contexts = {}
        if self.native_flow is not None:
            self.native_flow.muted += 1
        try:
            data, results, scalars = self.closure_data_locals(closure, frame, frozenset())
            return self.value_result(
                self.last_statement(closure), frame, data=data, results=results, scalars=scalars
            )
        finally:
            if self.native_flow is not None:
                self.native_flow.muted -= 1
            if outer:
                self.closure_classification_work = None
                self.closure_contexts = {}
                if self.closure_classification_cut and self.native_flow is not None:
                    self.native_flow.partial("closure value classification budget", self, node=closure)

    def closure_declarations(self, closure: Any) -> list[tuple[str, Any, str]]:
        return [(name, value, kind) for _, name, value, kind, _ in self.closure_declaration_rows(closure)]

    def closure_declaration_rows(
        self, closure: Any
    ) -> list[tuple[int, str, Any, str, tuple[int, int] | None]]:
        """The locals a closure or block body declares in its own statements (not in a nested
        block, whose locals that block's last statement reads), with their initializers and
        declared types, in source order."""
        found: list[tuple[int, str, Any, str, tuple[int, int] | None]] = []
        pending = [part for part in closure.named_children]
        while pending:
            node = pending.pop()
            if node.type in CLOSURES or node.type in FUNCTIONS:
                continue
            if node.type in BLOCKS | {"control_structure_body"} and not _same_node(node.parent, closure):
                continue  # a nested block: `if (c) { val t = .. }`
            if node.type == "guard_statement":
                # `guard let t = Optional(q) else { .. }`: t is a local after the guard holding its
                # initializer; the shorthand `guard let query else { .. }` unwraps the outer name.
                clauses, _, alternative = self.swift_clauses(node)
                excluded = (alternative.start_byte, alternative.end_byte) if alternative is not None else None
                for clause in clauses:
                    for name, bound in clause.names:
                        value = clause.initializer if clause.initializer is not None else bound
                        found.append((value.end_byte, name, value, "", excluded))
            for item in node.named_children if node.type == "local_variable_declaration" else [node]:
                declared = self.declaration(item)
                if declared:
                    found.append((item.end_byte, declared[0], declared[1], declared[2], None))
            if node.type not in STRINGS:
                pending.extend(node.named_children)
        return sorted(found, key=lambda row: row[0])

    def closure_work(self) -> bool:
        """Charge classification work across the scopes of one content closure."""
        if self.closure_classification_work is None:
            return True
        self.closure_classification_work += 1
        if self.closure_classification_work > MAX_CLOSURE_CLASSIFICATIONS:
            self.closure_classification_cut = True
            return False
        return True

    def closure_data_locals(
        self,
        closure: Any,
        frame: Frame,
        data: frozenset[str],
        on_receiver: bool = False,
        results: frozenset[str] = frozenset(),
        scalars: frozenset[str] = frozenset(),
        depth: int = 0,
        at: Any = None,
    ) -> tuple[frozenset[str], frozenset[str], frozenset[str]]:
        """Read a compatible lexical graph during one content-closure classification."""
        active = self.closure_classification_work is not None
        if depth > 16:
            return data, results, scalars
        if active:
            key = id(frame), closure.start_byte, closure.end_byte, closure.type
            for owner, query in reversed(self.closure_contexts.get(key, [])):
                if not self.closure_work():
                    return data, results, scalars
                if owner is frame:
                    classified = query(closure, data, on_receiver, results, scalars, at)
                    if classified is not None:
                        return classified
        return self.classify_closure_locals(closure, frame, data, on_receiver, results, scalars, depth, at)

    def classify_closure_locals(
        self,
        closure: Any,
        frame: Frame,
        data: frozenset[str],
        on_receiver: bool = False,
        results: frozenset[str] = frozenset(),
        scalars: frozenset[str] = frozenset(),
        depth: int = 0,
        at: Any = None,
    ) -> tuple[frozenset[str], frozenset[str], frozenset[str]]:
        """Classify lexical bindings by all their values, using a finite dependency worklist.

        Scope/assignment ownership is collected once per context. Contained scopes query
        that graph's current kind bits rather than rebuilding or caching partial results.
        Each value is read at its source
        position, with an initializer's own binding excluded. Kinds only accumulate:
        scalar, data, or another result. A binding is scalar only when scalar is its sole
        possible kind; data takes precedence over mixed kinds. This handles aliases and
        self updates without optimistic assumptions about a shadowing initializer.
        """
        if depth > 16:
            return data, results, scalars
        scalar_kind, data_kind, result_kind = 1, 2, 4
        scopes = [ClosureScope(closure, None)]
        bindings: list[ClosureLocal] = []
        values: list[ClosureValue] = []
        receivers: dict[int, int] = {}
        node_scopes: dict[tuple[int, int, str], int] = {
            (closure.start_byte, closure.end_byte, closure.type): 0
        }
        declarations: set[tuple[int, str]] = set()

        def span(node: Any) -> tuple[int, int, str]:
            return node.start_byte, node.end_byte, node.type

        def bind(
            scope: int,
            position: int,
            name: str,
            kind: str,
            value: Any,
            value_scope: int,
            excluded: tuple[int, int] | None = None,
        ) -> int:
            index = len(bindings)
            numeric = re.sub(r"\s+", "", kind).rstrip("?!") in NUMBER_TYPES
            bindings.append(
                ClosureLocal(name, scope, position, scalar_kind if numeric else 0, numeric, excluded)
            )
            scopes[scope].names.setdefault(name, []).append(index)
            if value is not None:
                values.append(ClosureValue(index, value, value_scope, position >= 0))
            return index

        def declare(scope: int) -> None:
            subject = self.when_binding(scopes[scope].node)
            if subject is not None:
                name, variable, value = subject
                key = value.end_byte, name
                if key not in declarations:
                    declarations.add(key)
                    bind(scope, value.end_byte, name, "", value, scope)
            for position, name, value, kind, excluded in self.closure_declaration_rows(scopes[scope].node):
                key = position, name
                if key not in declarations:
                    declarations.add(key)
                    bind(scope, position, name, kind, value, scope, excluded)

        def lookup(name: str, scope: int, position: int) -> int | None:
            current: int | None = scope
            while current is not None:
                if not self.closure_work():
                    return None
                for index in reversed(scopes[current].names.get(name, [])):
                    binding = bindings[index]
                    if binding.position <= position and not (
                        binding.excluded is not None and binding.excluded[0] <= position < binding.excluded[1]
                    ):
                        return index
                current = scopes[current].parent
            return None

        declare(0)
        assignments: list[tuple[Any, Any, int]] = []
        pending = [(child, 0) for child in reversed(closure.named_children)]
        while pending and self.closure_work():
            node, scope = pending.pop()
            if node.type in FUNCTIONS:
                continue
            if self.when_binding(node) is not None:
                parent = scope
                scope = len(scopes)
                scopes.append(ClosureScope(node, parent))
                declare(scope)
            elif node.type in CLOSURES:
                owner = self.closure_owner(node)
                name = owner.name.rsplit(".", 1)[-1] if owner is not None else ""
                if owner is None or name not in SCOPE_FUNCTIONS | {
                    "takeIf",
                    "takeUnless",
                    "forEach",
                    "forEachIndexed",
                    "onEach",
                }:
                    continue
                parent = scope
                scope = len(scopes)
                scopes.append(ClosureScope(node, parent))
                subject = (
                    owner.args[0]
                    if name == "with" and owner.receiver is None and owner.args
                    else owner.receiver
                )
                parameters = self.closure_parameters(node)
                if name in {"with", "apply", "run"} and subject is not None:
                    index = bind(scope, -1, "this", "", subject, parent)
                    receivers[index] = len(values) - 1
                else:
                    if not parameters and name in {
                        "let",
                        "also",
                        "use",
                        "takeIf",
                        "takeUnless",
                        "forEach",
                        "onEach",
                    }:
                        parameters = [("$0" if self.language == "swift" else "it", "", 0)]
                    for parameter, kind, index in parameters:
                        if name == "forEachIndexed" and index == 0:
                            kind = "Int"
                        bind(scope, -1, parameter, kind, subject, parent)
                declare(scope)
            elif node.type in BLOCKS | {"control_structure_body"} and (
                node.parent != closure
                or self.branching(closure)
                or closure.type in {"ternary_expression", "switch_expression"}
            ):
                parent = scope
                scope = len(scopes)
                scopes.append(ClosureScope(node, parent))
                declare(scope)
                if (
                    self.language == "swift"
                    and node.parent is not None
                    and node.parent.type == "if_statement"
                    and self.then_block(node.parent, node)
                ):
                    for clause in self.swift_clauses(node.parent)[0]:
                        for name, bound in clause.names:
                            bind(
                                scope,
                                -1,
                                name,
                                "",
                                clause.initializer if clause.initializer is not None else bound,
                                parent,
                            )
            node_scopes[span(node)] = scope
            if node.type in {"assignment", "assignment_expression"}:
                left = self.assignment_target(
                    _field(node, "left") or _field(node, "target") or next(iter(node.named_children), None)
                )
                right = (
                    _field(node, "right")
                    or _field(node, "result")
                    or (node.named_children[-1] if len(node.named_children) > 1 else None)
                )
                if left is not None and left.type in IDENTIFIERS and right is not None and right != left:
                    assignments.append((left, right, scope))
            pending.extend((child, scope) for child in reversed(node.named_children))

        for record in values:
            if record.initializer:
                record.scope = node_scopes.get(span(record.node), record.scope)
        for left, right, scope in assignments:
            owner = lookup(self.symbol_name(self.text(left)), scope, left.start_byte)
            if owner is not None:
                values.append(ClosureValue(owner, right, scope))

        # Resolve only names read by a value. Rebuilding every visible name set for each
        # independent declaration would turn a flat closure into quadratic work.
        references: list[set[str]] = []
        dependencies: list[set[int]] = []
        dependents: dict[int, set[int]] = {}
        for number, record in enumerate(values):
            names = {"this"}
            needed: set[int] = set()
            for part in _walk(record.node, descend_functions=False):
                if not self.closure_work():
                    break
                read = []
                if part.type in IDENTIFIERS:
                    parent = part.parent
                    navigation = self.navigation(parent) if parent is not None else None
                    if (
                        navigation is not None
                        and navigation[0] is not None
                        and part.start_byte >= navigation[0].end_byte
                    ):
                        continue  # a member spelling is not a local read
                    read = [self.symbol_name(self.text(part))]
                elif part.type in TEXT_LITERALS and self.language == "kotlin":
                    read = list(self.template_names(part))
                for name in read:
                    names.add(name)
                    found = lookup(name, node_scopes.get(span(part), record.scope), part.start_byte)
                    if found is not None:
                        needed.add(found)
            receiver = lookup("this", record.scope, record.node.start_byte)
            if receiver is not None:
                needed.add(receiver)
            references.append(names)
            dependencies.append(needed)
            for index in needed:
                dependents.setdefault(index, set()).add(number)

        def context(
            scope: int, position: int, names: set[str]
        ) -> tuple[frozenset[str], frozenset[str], frozenset[str], bool]:
            local_data = set(data & names)
            local_results = set(results & names)
            local_scalars = set(scalars & names)
            receiver_data = on_receiver
            for name in names:
                index = lookup(name, scope, position)
                if index is None:
                    continue
                local_data.discard(name)
                local_results.discard(name)
                local_scalars.discard(name)
                kinds = bindings[index].kinds
                if kinds & data_kind:
                    local_data.add(name)
                else:
                    if name == "this" and index in receivers and kinds != scalar_kind:
                        number = receivers[index]
                        subject = values[number]
                        _, subject_results, _, _ = context(
                            subject.scope, subject.node.start_byte, references[number]
                        )
                        if not self.call_result(subject.node, frame, subject_results):
                            receiver_data = False
                            continue  # an input-free receiver is neither data nor a traced call result
                    local_results.add(name)
                    if kinds == scalar_kind:
                        local_scalars.add(name)
                if name == "this":
                    receiver_data = bool(kinds & data_kind)
            return frozenset(local_data), frozenset(local_results), frozenset(local_scalars), receiver_data

        def classified_at(node: Any, at: Any) -> tuple[frozenset[str], frozenset[str], frozenset[str]]:
            target_scope = node_scopes.get(span(at if at is not None else node), 0)
            names = set(data | results | scalars)
            current: int | None = target_scope
            while current is not None:
                names.update(scopes[current].names)
                current = scopes[current].parent
            classified = context(target_scope, at.start_byte if at is not None else node.end_byte, names)
            return classified[0], classified[1], classified[2]

        def reuse_context(
            node: Any,
            incoming_data: frozenset[str],
            incoming_receiver: bool,
            incoming_results: frozenset[str],
            incoming_scalars: frozenset[str],
            at: Any,
        ) -> tuple[frozenset[str], frozenset[str], frozenset[str]] | None:
            scope = node_scopes.get(span(node))
            if scope is None or at is not None and span(at) not in node_scopes:
                return None  # a skipped callback needs its own bindings
            if incoming_receiver != on_receiver and lookup("this", scope, node.start_byte) is None:
                return None
            changed = (incoming_data ^ data) | (incoming_results ^ results) | (incoming_scalars ^ scalars)
            if any(lookup(name, scope, node.start_byte) is None for name in changed):
                return None  # an outer binding's kind changed: build a separate context
            return classified_at(node, at)

        if self.closure_classification_work is not None:
            # Index represented spans so unrelated sibling callbacks are never scanned.
            # Retaining the frame also prevents an id from being reused during this boundary.
            for start, end, kind in node_scopes:
                self.closure_contexts.setdefault((id(frame), start, end, kind), []).append(
                    (frame, reuse_context)
                )

        queue = list(range(len(values)))
        queued = set(queue)
        cursor = 0
        seeded = False
        while not self.closure_classification_cut:
            if cursor == len(queue):
                if seeded:
                    break
                # A seedless alias cycle or a null-only local has no known data. Give
                # it a result kind once, then allow its dependents to finish.
                seeded = True
                for index, binding in enumerate(bindings):
                    if not binding.kinds:
                        binding.kinds = result_kind
                        for dependent in dependents.get(index, set()):
                            if dependent not in queued:
                                queue.append(dependent)
                                queued.add(dependent)
                if cursor == len(queue):
                    break
            if not self.closure_work():
                break
            number = queue[cursor]
            cursor += 1
            queued.discard(number)
            record = values[number]
            binding = bindings[record.owner]
            local_data, local_results, local_scalars, receiver_data = context(
                record.scope,
                record.node.start_byte,
                references[number],
            )
            if binding.typed_scalar:
                continue  # declared numeric locals and inline indices remain numeric
            if self.scalar_result(record.node, local_scalars, frame) or self.scalar_format(
                record.node, frame, local_scalars
            ):
                kind = scalar_kind
            elif any(not bindings[index].kinds for index in dependencies[number]):
                continue  # do not turn an unclassified alias into data
            elif self.unwrap(record.node) is not None and self.text(self.unwrap(record.node)).strip() in {
                "null",
                "nil",
            }:
                continue  # an empty initial value does not make numeric updates text
            elif self.data_expression(
                record.node, frame, local_data, receiver_data, local_results, local_scalars
            ) or (
                (target := self.unwrap(record.node)) is not None
                and self.navigation(target) is None
                and self.reused(record.node, frame).traces
                and self.value_result(
                    record.node, frame, depth + 1, local_data, receiver_data, local_results, local_scalars
                )
            ):
                kind = data_kind
            else:
                kind = result_kind
            updated = binding.kinds | kind
            if updated != binding.kinds:
                binding.kinds = updated
                for dependent in dependents.get(record.owner, set()):
                    if dependent not in queued:
                        queue.append(dependent)
                        queued.add(dependent)

        return classified_at(closure, at)

    def call_result(self, node: Any, frame: Frame, results: frozenset[str]) -> bool:
        """Whether an expression is another call's result: a closure's local holding one
        (`results`), or a call whose value carries input (`repo.lookup(q)`)."""
        target = self.unwrap(node)
        if target is None:
            return False
        if self.mentions(self.chain_base(target), results):
            return True
        return self.call(target) is not None and bool(self.reused(target, frame).traces)

    def result_transform(
        self, call: Call, frame: Frame, results: frozenset[str], scalars: frozenset[str] = frozenset()
    ) -> bool:
        """A String transform of a value that is not data itself: a call's result over input,
        which an unresolved callee may return (`repo.lookup(q).trim()`), or a closure's other
        local (`t.trim()` on `val t = repo.lookup(q)`; `results`). Another call on such a local
        (`t.track("open")`) is a side effect."""
        if call.receiver is None or call.name.rsplit(".", 1)[-1] not in STRING_TRANSFORMS:
            return False
        if self.scalar_result(
            self.unwrap(call.receiver) or call.receiver, scalars, frame
        ) or self.scalar_format(call.receiver, frame, scalars):
            # A number's text can still be filled with input (`n.toString().plus(q)`).
            return call.name.rsplit(".", 1)[-1] in TEMPLATE_FILLS and any(
                not self.scalar_result(argument, scalars, frame)
                and self.argument_data(argument, frame, results)
                for argument in self.inserted_arguments(call)
            )
        if self.mentions(self.chain_base(call.receiver), results):
            return True  # read by name: the enclosing frame does not bind a closure's names
        return bool(self.reused(call.receiver, frame).traces)

    def last_statement(self, node: Any) -> Any:
        """The last statement of a closure or block body, past signatures and capture lists."""
        for _ in range(8):
            if node is None or node.type not in CLOSURES | BLOCKS | {"control_structure_body"}:
                return node
            parts = [
                part
                for part in node.named_children
                if part.type not in COMMENTS
                and part.type not in {"lambda_parameters", "lambda_function_type", "capture_list", "label"}
            ]
            if not parts:
                return None
            node = parts[-1]
        return node

    def value_result(
        self,
        node: Any,
        frame: Frame,
        depth: int = 0,
        data: frozenset[str] = frozenset(),
        on_receiver: bool = False,
        results: frozenset[str] = frozenset(),
        scalars: frozenset[str] = frozenset(),
    ) -> bool:
        """Whether an expression's value can be a value it holds rather than only a call's result.

        `data` names a closure's own locals and a scope block's parameters over data
        (`q.let { it.trim() }`); `on_receiver` marks a `run`/`with` block on data, whose
        receiverless string transforms are calls on it (`q.run { trim() }`); `results` names
        a closure's locals holding a call's result over input (`val t = repo.lookup(q)`), and
        `scalars` those of them holding a flag or a number (`val n = q.length`).
        """
        node = self.unwrap(node)
        if node is None or depth > 16:
            return False
        if node.type in {
            "jump_expression",
            "control_transfer_statement",
            "return_statement",
            "return_expression",
        }:
            values = [part for part in node.named_children if part.type not in COMMENTS | {"label"}]
            if (
                self.language == "kotlin"
                and values
                and _field(node, "label") is None
                and re.match(r"return\s*@", self.text(node).lstrip())
            ):
                values = values[1:]  # tree-sitter-kotlin 1.1.0: `return@section q` names its label first
            return bool(values) and self.value_result(
                values[-1], frame, depth + 1, data, on_receiver, results, scalars
            )
        if node.type in STATEMENT_ONLY:
            return False
        project = self.project_transform_result(self.call(node), frame, scalars)
        if project is not None:
            return project[0]
        if self.scalar_result(node, scalars, frame):
            return False  # a flag or a number read from data (`q.isNotEmpty()`, `q == "x"`)
        if node.type in {"null_literal", "nil"} or self.text(node).strip() in {"Unit", "null", "nil", "()"}:
            return False  # `{ audit.track(it); Unit }`
        if (
            node.type in IDENTIFIERS | {"this_expression", "self_expression", "this"}
            and self.symbol_name(self.text(node)) in results - data
        ):
            return False  # `{ val row = db.query(q); row }`: a call's result, an object or a flag
        if self.branching(node):
            # A braced branch's own locals are visible in that branch only (an `else if` is a
            # branching branch whose own blocks decide).
            for branch in self.branch_bodies(node) or []:
                if branch is None:
                    continue
                branch_data, branch_results, branch_scalars = (
                    self.closure_data_locals(branch, frame, data, on_receiver, results, scalars, depth + 1)
                    if branch.type in BLOCKS | {"control_structure_body"}
                    else (data, results, scalars)
                )
                if self.value_result(
                    self.last_statement(branch),
                    frame,
                    depth + 1,
                    branch_data,
                    on_receiver,
                    branch_results,
                    branch_scalars,
                ):
                    return True
            return False
        call = self.call(node)
        if call is None:
            return True
        name = call.name.rsplit(".", 1)[-1]
        if self.scalar_format(node, frame, scalars):
            return False
        block = self.closure_argument(call.args[-1]) if call.args else None
        if call.receiver is None and name == "with" and block is not None and len(call.args) == 2:
            # `with(config) { "$host/$q" }` is its block's result; on data (`with(q) { trim() }`)
            # its receiverless string transforms are calls on that data.
            subject = self.data_expression(call.args[0], frame, data, results=results, scalars=scalars)
            # Over another call's result (`with(t) { uppercase() }`) its transforms read it; the
            # block rebinds `this`, so an outer block's receiver is no longer read.
            other = not subject and self.call_result(call.args[0], frame, results)
            block_data, block_results, block_scalars = self.closure_data_locals(
                block,
                frame,
                data,
                subject,
                results - {"this"} | ({"this"} if other else set()),
                scalars - {"this"}
                | (
                    {"this"}
                    if self.scalar_result(call.args[0], scalars, frame)
                    or self.scalar_format(call.args[0], frame, scalars)
                    else set()
                ),
                depth + 1,
            )
            return self.value_result(
                self.last_statement(block),
                frame,
                depth + 1,
                block_data,
                subject,
                block_results,
                block_scalars,
            )
        # A transform of data (`q.trim()`, `"$q".lowercase()`, `String.format(..)`) is a value:
        # a call whose chain starts at data. A receiverless call or one on a service
        # (`analytics.track(q)`, `prefs.edit().putString("k", q).apply()`) is a side effect.
        if call.receiver is None and name == "run" and block is not None and len(call.args) == 1:
            # `run { "$prefix/$q" }` is its block's result, like `with`.
            block_data, block_results, block_scalars = self.closure_data_locals(
                block, frame, data, on_receiver, results, scalars, depth + 1
            )
            return self.value_result(
                self.last_statement(block),
                frame,
                depth + 1,
                block_data,
                on_receiver,
                block_results,
                block_scalars,
            )
        if call.receiver is None:
            if self.format_parts(call, frame) is not None:
                return True  # a non-scalar receiverless format retains its visited template/fills
            if "this" in scalars and name in NUMBER_OPERATIONS:
                return name in TEMPLATE_FILLS and any(
                    not self.scalar_result(argument, scalars, frame)
                    and self.argument_data(argument, frame, data | results)
                    for argument in self.inserted_arguments(call)
                )
            # `String(format: "%@", q)`: a value built from its arguments; an own function
            # declared to return a String (`displayName()`); in a run/with block, a String
            # transform of its receiver (data, or another call's result).
            return (
                name in VALUE_CONSTRUCTORS
                or self.string_function(node, name)
                or (on_receiver or "this" in results)
                and name in STRING_TRANSFORMS
            )
        if self.key(call.receiver) in {"this", "self"} and self.string_function(node, name):
            return True  # `this.displayName()`
        if name in {"also", "apply", "takeIf", "takeUnless"} and block is not None:
            # `t.trim().also { log(it) }` is its receiver's value.
            return self.value_result(call.receiver, frame, depth + 1, data, on_receiver, results, scalars)
        receiver_data = self.data_expression(
            call.receiver, frame, data | ({"this"} if on_receiver else set()), on_receiver, results, scalars
        ) or self.result_transform(call, frame, results, scalars)
        if (
            not receiver_data
            and name not in {"let", "run", "use"}
            and self.string_template(
                call, frame, data | results | ({"this"} if on_receiver else set()), scalars
            )
        ):
            return True
        if name in {"let", "run", "use"} and block is not None:
            # `title?.let { "$it: $q" }` is its block's result; over data (`q.let { it.trim() }`)
            # its parameter is data too, otherwise another value (`audit.let { it.track(q) }`
            # is a call's result).
            # `let`/`use` bind their parameters or `it`, `run` binds `this`; the block's own names
            # hide the same names outside it (`tag.let { t -> audit.let { it.track(t) } }`).
            parameters = {declared for declared, _, _ in self.closure_parameters(block)}
            names = set() if name == "run" else parameters or {"it"}
            numbers = scalars - names
            # `run` rebinds `this`: an outer block's receiver is no longer read.
            outer = results - {"this"} if name == "run" else results
            scalar_receiver = self.scalar_result(call.receiver, scalars, frame) or self.scalar_format(
                call.receiver, frame, scalars
            )
            if receiver_data and not scalar_receiver:
                scope, held = data | names, outer - names
            else:
                scope, held = data - names, outer | names
                if scalar_receiver:
                    numbers = numbers | (names if name != "run" else {"this"})
                if name == "run" and self.call_result(call.receiver, frame, results):
                    held = held | {"this"}  # `t.run { trim() }` over another call's result
            block_data, block_results, block_scalars = self.closure_data_locals(
                block,
                frame,
                frozenset(scope),
                name == "run" and receiver_data,
                frozenset(held),
                frozenset(numbers),
                depth + 1,
            )
            return self.value_result(
                self.last_statement(block),
                frame,
                depth + 1,
                block_data,
                name == "run" and receiver_data,
                block_results,
                block_scalars,
            )
        if not receiver_data or name in {"forEach", "forEachIndexed"}:
            return False
        return True

    def project_transform_result(
        self, call: Call | None, frame: Frame | None, scalars: frozenset[str] = frozenset()
    ) -> tuple[bool, bool] | None:
        """A resolved project's text/numeric result takes precedence over name shortcuts.

        Return (content, scalar-or-input-free); None leaves an unresolved standard
        transform to its receiver model. A traced object return remains a call result.
        """
        if (
            call is None
            or call.receiver is not None
            or frame is None
            or self.native_flow is None
            or call.name.rsplit(".", 1)[-1] not in STRING_TRANSFORMS | NUMBER_OPERATIONS
        ):
            return None
        name = call.name.rsplit(".", 1)[-1]
        if (
            "this" in scalars
            and name in NUMBER_OPERATIONS
            and len(call.args) <= (2 if name == "coerceIn" else 1)
            and all(self.scalar_result(argument, scalars, frame) for argument in call.args)
        ):
            return None  # keep an applicable numeric receiver operation ahead of an outer helper
        targets = self.native_flow.resolve(self, call, Value(), frame)[0]
        if not targets:
            return None
        value = self.reused(call.node, frame)
        text = any(target.analyzer.string_function_header(target.node) for target in targets)
        numeric = all(
            re.sub(r"\s+", "", self.declared_return(target)).rstrip("?!").rsplit(".", 1)[-1] in NUMBER_TYPES
            for target in targets
        )
        return bool(text and value.traces), numeric or not value.traces

    def scalar_result(
        self, node: Any, scalars: frozenset[str] = frozenset(), frame: Frame | None = None
    ) -> bool:
        """An expression whose value is a flag or a number, not text: a comparison or a logical
        operation (`q == "x"`, `!ok`, `q in xs`, `q is String`), a member read or call by such a
        name (`q.isNotEmpty()`, `q.length`, `template.contains(q)`), a closure's name holding
        one (`scalars`), arithmetic on numbers (`q.length + 1`), a number's text or operation
        (`n.toString()`, `n.plus(1)`, Swift `n.description` and `String(n)`, Java
        `String.valueOf(n)`), a constant format they fill (`"LIMIT %d".format(n)`), branches of
        them (a constant text branch aside; a branch declaring its own locals is left to the
        value check), or a string that only interpolates them (`"${q.length} results"`,
        `"$n results"`). Up to MAX_CHAIN nodes are read; beyond that the expression counts as
        text."""
        pending, seen = [node], 0
        while pending:
            current = pending.pop()
            seen += 1
            if current is None or seen > MAX_CHAIN:
                return False
            current = self.unwrap(current) or current
            if current.type in NUMBERS:
                continue
            if current.type in IDENTIFIERS | {"this_expression", "self_expression", "this"}:
                if self.symbol_name(self.text(current)) in scalars:
                    continue
                return False
            arithmetic = self.arithmetic_operands(current)
            if arithmetic is not None:
                # An empty text operand only makes a number text (Java `"" + q.length()`).
                operands = [part for part in arithmetic if not self.empty_text(part)]
                if not operands:
                    return False
                pending.extend(operands)
                continue
            if current.type == "ternary_expression" or self.branching(current):
                # Every result of `c ? 0 : q.length()`, `if (c) 0 else q.length`.
                parts = [part for part in current.named_children if part.type not in COMMENTS]
                bodies = parts[1:] if current.type == "ternary_expression" else self.branch_bodies(current)
                if not bodies or len(bodies) < 2:
                    return False
                if any(
                    body is not None
                    and body.type in BLOCKS | {"control_structure_body"}
                    and self.closure_declarations(body)
                    for body in bodies
                ):
                    return False  # `if (c) { val n = q.trim(); n } else ..`: the branch's own names
                # A constant text branch only makes the others' numbers text (`if (c) n.toString() else "0"`).
                results = [self.last_statement(body) for body in bodies]
                results = [result for result in results if result is None or not self.constant_text(result)]
                if not results:
                    return False
                pending.extend(results)
                continue
            interpolated = self.interpolated_parts(current)
            if interpolated is not None:
                parts, names = interpolated
                if not parts and not names or not names <= scalars:
                    return False  # a constant or `$t` text
                pending.extend(parts)
                continue
            call = self.call(current)
            project = self.project_transform_result(call, frame, scalars)
            if project is not None:
                if project[1]:
                    continue
                return False
            if self.flag_or_number(current):
                continue
            if (
                call is not None
                and call.receiver is None
                and call.name.rsplit(".", 1)[-1] in NUMBER_OPERATIONS
                and "this" in scalars
            ):
                pending.extend(call.args)
                continue
            numbers = self.number_values(current)
            if numbers is not None:
                pending.extend(numbers)
                continue
            if not self.flag_or_number(current):
                return False
        return True

    def number_values(self, node: Any) -> list[Any] | None:
        """What a number's text or operation reads, its receiver and arguments (`n.toString()`,
        `n.toString(16)`, `n.plus(1)`, `n.coerceAtLeast(1)`, Swift `n.description` and
        `String(n)`, Java `String.valueOf(n)`), or the values a constant format inserts
        (`"LIMIT %d".format(n)`, `String.format("%d", n)`, Swift `String(format: "%d", n)`,
        Java `"%d".formatted(n)`); None for another node."""
        call = self.call(node)
        if call is not None:
            member = call.name.rsplit(".", 1)[-1]
            on_string = call.receiver is not None and self.key(call.receiver) == "String"
            swift_string = self.language == "swift" and call.receiver is None and member == "String"
            if (
                member in NUMBER_OPERATIONS
                and call.receiver is not None
                and len(call.args) <= (2 if member == "coerceIn" else 1)
            ):
                return [call.receiver, *call.args]
            formatted = self.format_parts(call)
            if formatted is not None and self.constant_text(formatted[0]):
                return formatted[1]
            if len(call.args) == 1 and (swift_string or member == "valueOf" and on_string):
                return [call.args[0]]
            return None
        if self.language == "swift" and node.type == "navigation_expression":
            navigation = self.navigation(node)
            if navigation is not None and navigation[0] is not None and navigation[1] == "description":
                return [navigation[0]]
        return None

    def scalar_format(self, node: Any, frame: Frame, scalars: frozenset[str]) -> bool:
        """Numeric or input-free fills of an input-free format, also through String transforms. The visit
        preserves the template's value in its own scope, so a named or local format can be
        read here without hiding input in the template itself (`String.format(saved, n)`).
        A later transform that inserts input makes it text again (`tpl.format(n).plus(q)`)."""
        current = self.unwrap(node)
        for _ in range(MAX_CHAIN):
            if current is not None and self.scalar_result(current, scalars, frame):
                return True
            call = self.call(current) if current is not None else None
            if call is None:
                return False
            name = call.name.rsplit(".", 1)[-1]
            if call.receiver is None and "this" in scalars and name in STRING_TRANSFORMS:
                if self.native_flow is not None and self.native_flow.resolve(self, call, Value(), frame)[0]:
                    return False  # a resolved project helper does not transform numeric this
                return not (
                    name in TEMPLATE_FILLS
                    and any(
                        not self.scalar_result(argument, scalars, frame)
                        and self.reused(argument, frame).traces
                        for argument in self.inserted_arguments(call)
                    )
                )
            formatted = self.format_parts(call, frame)
            if formatted is not None:
                template, arguments = formatted
                return not self.reused(template, frame).traces and all(
                    self.scalar_result(argument, scalars, frame) or not self.reused(argument, frame).traces
                    for argument in arguments
                )
            if call.receiver is None or name not in STRING_TRANSFORMS:
                return False
            if name in TEMPLATE_FILLS and any(
                not self.scalar_result(argument, scalars, frame) and self.reused(argument, frame).traces
                for argument in self.inserted_arguments(call)
            ):
                return False
            current = self.unwrap(call.receiver)
        return False

    def format_parts(self, call: Call, frame: Frame | None = None) -> tuple[Any, list[Any]] | None:
        """A format's template and inserted values, including static and Swift spellings."""
        implicit = self.implicit_formats.get((call.node.start_byte, call.node.end_byte))
        if implicit is not None:
            return implicit, list(call.args)
        cached = self.format_argument_offsets.get((call.node.start_byte, call.node.end_byte))
        if cached is not None and len(call.args) > cached + 1:
            return call.args[cached], list(call.args[cached + 1 :])
        name = call.name.rsplit(".", 1)[-1]
        if (
            name == "format"
            and call.receiver is not None
            and self.key(call.receiver) in {"String", "java.lang.String"}
            or self.language == "swift"
            and call.receiver is None
            and name == "String"
            and call.args
            and self.argument_label(call.args[0]) == "format"
        ):
            offset = 0
            if len(call.args) > 2:
                first = self.unwrap(call.args[0])
                text = self.text(first).strip() if first is not None else ""
                first_value = (
                    self.reused(first, frame) if first is not None and frame is not None else Value()
                )
                declared = first_value.type_name
                alias = None
                if first is not None and first.type in IDENTIFIERS and frame is not None:
                    name = self.symbol_name(text)
                    alias = self.aliases.get(name)
                    if alias is not None and first_value != self.reused(alias, frame):
                        alias = None  # a later local replaced the scope parameter's value
                    # A local or scope parameter can shadow a Locale field of the same
                    # name. Its actual bound value takes precedence over file/type indexes.
                    if not declared and name not in frame.local_names and alias is None:
                        declared = (
                            frame.types.get(name, "")
                            or self.parameter_types.get(name, "")
                            or self.field_types.get(name, "")
                        )
                    if alias is not None:
                        text = self.text(alias).strip()
                string = (
                    first_value.category == "text"
                    or declared.rstrip("?").rsplit(".", 1)[-1] in {"String", "CharSequence"}
                    or (
                        first is not None
                        and self.qualified_string(first)
                        or alias is not None
                        and self.qualified_string(alias)
                    )
                )
                if not string and (
                    re.match(r"(?:java\.util\.)?Locale(?:\.|\()", text)
                    or declared.rstrip("?")
                    in {
                        "Locale",
                        "java.util.Locale",
                    }
                ):
                    offset = 1
            return (call.args[offset], list(call.args[offset + 1 :])) if len(call.args) > offset + 1 else None
        if name in {"format", "formatted"} and call.receiver is not None and call.args:
            return call.receiver, list(call.args)
        return None

    def constant_text(self, node: Any) -> bool:
        """A string literal that inserts nothing (`"0"`, `"LIMIT %d"`)."""
        literal = self.unwrap(node)
        parts = self.interpolated_parts(literal) if literal is not None else None
        return parts is not None and not parts[0] and not parts[1]

    def arithmetic_operands(self, node: Any) -> list[Any] | None:
        """The operands of `+ - * / %` (`q.length + 1`), or None."""
        if node.type not in {
            "binary_expression",
            "additive_expression",
            "multiplicative_expression",
            "nil_coalescing_expression",
            "range_expression",
        }:
            return None
        parts = [part for part in node.named_children if part.type not in COMMENTS]
        if len(parts) != 2:
            return None
        operator = self.operator_between(parts[0], parts[1])
        # Also a number's elvis fallback (`q.toIntOrNull() ?: 0`, Swift `Int(q) ?? 0`).
        return parts if operator in {b"+", b"-", b"*", b"/", b"%", b"?:", b"??", b"..", b"..<"} else None

    def operator_between(self, left: Any, right: Any) -> bytes:
        """The operator between two operands, without comments (`q.length /* c */ + 1`)."""
        return re.sub(
            rb"/\*.*?\*/|//[^\n]*", b"", self.raw[left.end_byte : right.start_byte], flags=re.S
        ).strip()

    def empty_text(self, node: Any) -> bool:
        """An empty string literal (`""`)."""
        literal = self.unwrap(node)
        return (
            literal is not None
            and literal.type in TEXT_LITERALS
            and not self.text(literal).strip().strip('"')
        )

    def interpolated_parts(self, node: Any) -> tuple[list[Any], set[str]] | None:
        """The expressions a string literal interpolates (`"${q.length} results"`, Swift
        `"\\(q.count) results"`) and the names its Kotlin short templates read (`"$n results"`),
        None for no string."""
        if node.type not in TEXT_LITERALS:
            return None
        parts = [
            part.named_children[0] if part.named_children else part
            for part in node.named_children
            if part.type in {"interpolation", "interpolated_expression"}
        ]
        names = (
            {self.symbol_name(name) for name in self.template_names(node)}
            if self.language == "kotlin"
            else set()
        )
        return parts, names

    def flag_or_number(self, node: Any) -> bool:
        """A comparison, a logical operation or a member read or call naming a flag or a number."""
        if node.type in {
            "equality_expression",
            "comparison_expression",
            "conjunction_expression",
            "disjunction_expression",
            "in_expression",
            "is_expression",
            "check_expression",
            "instanceof_expression",
        }:
            return True
        text = self.text(node).lstrip()
        if (
            node.type in {"prefix_expression", "unary_expression"}
            and text.startswith("!")
            and not text.startswith("!!")
        ):
            return True
        if node.type == "binary_expression":
            parts = [part for part in node.named_children if part.type not in COMMENTS]
            operator = self.operator_between(parts[0], parts[1]) if len(parts) == 2 else b""
            return operator in {b"==", b"!=", b"===", b"!==", b"<", b">", b"<=", b">=", b"&&", b"||"}
        if node.type == "interpolated_expression" and node.named_children:
            node = node.named_children[0]  # Swift `\(q.count)`
        call = self.call(node)
        if call is not None and call.receiver is not None:
            # `Integer.parseInt(q)`, `Integer.toString(n)`, `java.lang.Long.parseLong(q)`.
            *package, named = self.key(call.receiver).split(".")
            if named in NUMERIC_CLASSES and not any(segment[:1].isupper() for segment in package):
                return True
        if call is not None and call.receiver is None and call.name in NUMBER_TYPES:
            return True  # Swift `Int(q)`, `Double(q)`
        if call is not None:
            member = call.name.rsplit(".", 1)[-1]
        elif node.type in {"navigation_expression", "field_access"} and node.named_children:
            member = re.sub(r"^\W+", "", self.text(node.named_children[-1]))
            navigation = self.navigation(node)
            if (
                navigation is not None
                and navigation[0] is not None
                and self.text(navigation[0]).strip() in {"this", "self"}
                and self.class_member(node, navigation[1]) is True
            ):
                return False  # `this.size` of a class whose own `size` is a String
        else:
            return False
        return member in SCALAR_RESULTS or bool(re.fullmatch(r"(?:is|has|can|should)[A-Z]\w*", member))

    def string_template_root(self, base: Any, frame: Frame, data: frozenset[str] = frozenset()) -> bool:
        """A literal or lexically resolved String root, including an implicit scope receiver."""
        base = self.unwrap(base)
        if base is not None and (self.constant_text(base) or self.reused(base, frame).category == "text"):
            return True
        if base is None:
            return False
        if base.type in IDENTIFIERS:
            root = self.symbol_name(self.text(base))
            declared = (
                self.parameter_types.get(root, "")
                or frame.types.get(root, "")
                # A closure's own name (`data`) is not this frame's.
                or ("" if root in data else self.reused(base, frame).type_name)
            )
            local = root in frame.local_names or root in self.parameter_types or root in data
            # The enclosing class's property of that name, else a companion, object or top-level
            # constant (`WHERE.format(q)`); a same-named String elsewhere in the file is not it.
            member = None if local else self.class_member(base, root)
            template = (
                declared.rstrip("?")
                in {"String", "CharSequence", "java.lang.String", "kotlin.String", "Swift.String"}
                or member is True
                or member is None
                and not local
                and (
                    root in self.string_constants
                    or ("", root) in self.project_string_members()
                    or self.inherited_string(base, root)
                )
            )
        else:
            # `this.template`, `self.template`, `Repository.WHERE`, `Sql.BY_NAME`.
            navigation = self.navigation(base)
            if navigation is None or navigation[0] is None:
                return False
            qualifier = self.text(navigation[0]).strip()
            # `this.template`: the enclosing class's own property, else (an inherited or enum
            # member, `super.template`) a String of that name in the file.
            own = self.class_member(base, navigation[1]) if qualifier in {"this", "self"} else None
            template = (
                own is True
                or own is None
                and (navigation[1] in self.string_constants or self.inherited_string(base, navigation[1]))
                if qualifier in {"this", "self", "super"}
                else self.qualified_string(base)
                or navigation[1] in self.string_constants
                and qualifier[:1].isupper()
            )
        return bool(template)

    def string_template(
        self,
        call: Call,
        frame: Frame,
        data: frozenset[str] = frozenset(),
        scalars: frozenset[str] = frozenset(),
    ) -> bool:
        """A transform of a String held in a name that inserts input (`tpl.format(q)`,
        `tpl.replace("{q}", q)`, `prefix.plus(q)`): the template's root is a String constant
        or a String-typed parameter, the String transforms that start the chain fill it
        (TEMPLATE_FILLS) with an argument that carries input; a later call is a call on that
        data (`template.replace("{q}", q).encodeForWeb()`). A predicate
        (`template.contains(q)`) holds no input."""
        base = self.unwrap(call.receiver) if call.receiver is not None else None
        chain = [call]
        for _ in range(MAX_CHAIN):
            inner = self.call(base) if base is not None else None
            if inner is None or inner.receiver is None:
                break
            chain.append(inner)
            base = self.unwrap(inner.receiver)
        filling: list[Call] = []
        for link in reversed(chain):  # from the template outward
            if link.name.rsplit(".", 1)[-1] not in STRING_TRANSFORMS | TEMPLATE_FILLS:
                break
            filling.append(link)
        if not any(link.name.rsplit(".", 1)[-1] in TEMPLATE_FILLS for link in filling):
            return False
        arguments = [argument for link in filling for argument in self.inserted_arguments(link)]
        template = self.string_template_root(base, frame, data)
        # A fill of numbers only is a number's text (`"LIMIT %d".format(q.length)`).
        return bool(template) and any(
            self.argument_data(argument, frame, data) and not self.scalar_result(argument, scalars, frame)
            for argument in arguments
        )

    def inserted_arguments(self, call: Call) -> list[Any]:
        """The arguments a String transform inserts: all of `format`'s or `plus`'s, only the new
        text of `replace(old, new)`, by its name when the call names its arguments
        (`replace(newValue = q, oldValue = "{q}")`)."""
        if (
            call.name.rsplit(".", 1)[-1]
            not in {"replace", "replaceFirst", "replaceAll", "replacingOccurrences"}
            or len(call.args) < 2
        ):
            return list(call.args)
        named = [argument for argument in call.args if self.argument_label(argument) in REPLACEMENT_LABELS]
        return named or list(call.args[1:])

    def argument_label(self, argument: Any) -> str:
        """The name a Kotlin or Swift argument is passed by (`newValue` in `newValue = q`, Swift
        `with:`), or ""."""
        parent = argument.parent
        if parent is None or parent.type != "value_argument" or _same_node(parent, argument):
            return ""
        label = next((part for part in parent.named_children if part.type == "value_argument_label"), None)
        if label is not None:
            return self.text(label).strip()
        children = parent.children
        if len(children) >= 3 and children[0].type in IDENTIFIERS and children[1].type == "=":
            return self.symbol_name(self.text(children[0]))
        return ""

    def argument_data(self, argument: Any, frame: Frame, data: frozenset[str]) -> bool:
        """An argument that carries input: its visited value wins over a name's content kind.
        Otherwise it reads data or a closure's own name (`it` in
        `q.let { tpl.format(it) }`, `"$t"`), or its value has traces (also a lambda's result,
        `tpl.replace(Regex("x")) { q }`)."""
        visited = self.visited_values.get((argument.start_byte, argument.end_byte, argument.type))
        if visited is not None:
            return bool(visited.traces)  # a content-kind name may still hold input-free text
        if self.mentions(self.unwrap(argument), data):
            return True
        return bool(self.reused(argument, frame).traces)

    def string_function(self, node: Any, name: str) -> bool:
        """An own function declared to return a String (`displayName()`): the innermost class
        around the node that declares a function of that name decides; without one, a function
        of that name elsewhere in the file (top level, a base class) does."""
        for body in self.class_bodies(node):
            functions = self.body_string_functions(body)
            if name in functions:
                return functions[name]
        return name in self.string_functions

    def body_string_functions(self, body: Any) -> dict[str, bool]:
        """Whether a class body's functions and Java methods (and its companion object's) return a
        String, by name, an overload returning one counting; read once per body."""
        key = (body.start_byte, body.end_byte)
        cached = self.class_string_functions.get(key)
        if cached is not None:
            return cached
        found = {
            name: any(self.string_function_header(member) for member in members)
            for name, members in self.body_functions(body).items()
        }
        for member in body.named_children:
            if member.type == "method_declaration":
                name = self.text(_field(member, "name"))
                found[name] = found.get(name, False) or self.string_function_header(member)
        self.class_string_functions[key] = found
        return found

    def string_function_header(self, node: Any) -> bool:
        """A function or method declared to return a String (`fun name(): String`, Swift
        `-> String`, Java `String name(..)`), or a Kotlin expression body that is a String
        initializer (`fun profileUrl() = "https://docs.example.test/" + handle`)."""
        if node.type == "method_declaration":
            returned = _field(node, "type")
        elif self.language == "swift":
            # `func title() async throws -> String`: the type after `->`.
            arrow = next((index for index, part in enumerate(node.children) if part.type == "->"), None)
            returned = (
                next((part for part in node.children[arrow + 1 :] if part.is_named), None)
                if arrow is not None
                else None
            )
        else:
            # `fun title(): String`: the type after the parameter list (`(): () -> String` is none;
            # without a type, the body is never a String's name).
            parameters = next(
                (part for part in node.named_children if part.type == "function_value_parameters"), None
            )
            returned = next(
                (
                    part
                    for part in node.named_children
                    if parameters is not None and part.start_byte > parameters.end_byte
                ),
                None,
            )
            if returned is not None and returned.type == "function_body":
                # No declared type: an expression body's value (`= ".." + handle`).
                children = returned.children
                body = next((part for part in children[1:] if part.is_named), None)
                return (
                    bool(children)
                    and children[0].type == "="
                    and body is not None
                    and (
                        self.string_initializer(body)
                        # `fun label() = saved` over a String property
                        or body.type in IDENTIFIERS
                        and self.class_member(body, self.symbol_name(self.text(body))) is True
                    )
                )
        text = re.sub(r"\s+", "", self.text(returned)) if returned is not None else ""
        return text.rstrip("?!") in {"String", "kotlin.String", "Swift.String", "java.lang.String"}

    def member_owner(self, node: Any) -> str:
        """The class or object a member declaration belongs to ("" at the top level; a companion
        object's constants belong to its class)."""
        body = node.parent
        owner = body.parent if body is not None else None
        if owner is not None and owner.type == "companion_object":
            owner = owner.parent.parent if owner.parent is not None else None
        if owner is None or owner.type in {"source_file", "program"}:
            return ""
        name = _field(owner, "name") or next(
            (part for part in owner.named_children if part.type in IDENTIFIERS | {"type_identifier"}), None
        )
        return self.text(name) if name is not None else ""

    def inherited_string(self, node: Any, name: str) -> bool:
        """A String member of that name that a source supertype of a class around the node
        declares, also in another file (`class Page : BasePage()` or Java
        `class Page implements Urls` reading `SEARCH`)."""
        flow = self.native_flow
        if flow is None:
            return False
        members = self.project_string_members()
        for body in self.class_bodies(node):
            for ancestor in flow.project_ancestry(flow.owner(self, body)):
                if (ancestor.rsplit(".", 1)[-1], name) in members:
                    return True
        return False

    def project_string_members(self) -> set[tuple[str, str]]:
        """String members of every analyzed file (owner, name)."""
        return self.native_flow.string_members() if self.native_flow is not None else self.string_members

    def string_initializer(self, node: Any) -> bool:
        """A String-valued initializer: a string literal, a `+` with one, a String transform of
        one (`\"\"\"..\"\"\".trimIndent()`), `String.format(..)` or a resource string
        (`getString(R.string.where)`)."""
        for _ in range(MAX_CHAIN):
            node = self.unwrap(node)
            if node is None:
                return False
            if node.type in TEXT_LITERALS:
                return True
            if node.type in {"binary_expression", "additive_expression"}:
                parts = [part for part in node.named_children if part.type not in COMMENTS]
                if len(parts) != 2 or self.raw[parts[0].end_byte : parts[1].start_byte].strip() != b"+":
                    return False
                right = self.unwrap(parts[1])
                if right is not None and right.type in TEXT_LITERALS:
                    return True
                node = parts[0]
                continue
            call = self.call(node)
            if call is None:
                return False
            name = call.name.rsplit(".", 1)[-1]
            if name == "getString" or name == "format" and self.key(call.receiver) == "String":
                return True
            if call.receiver is None or name not in STRING_TRANSFORMS:
                return False
            node = call.receiver
        return False

    def string_field(self, node: Any, name: str) -> bool:
        """A property of a class around the node declared as a String or from a string literal
        (`private val template = "name = %s"`)."""
        return self.class_member(node, name) is True

    def class_member(self, node: Any, name: str) -> bool | None:
        """Whether a property or field of the innermost class around the node that declares
        `name` is a String (declared, or initialized from a String initializer); None when no
        class around the node declares it."""
        for body in self.class_bodies(node):
            members = self.body_members(body)
            if name in members:
                return members[name]
        return None

    def body_members(self, body: Any) -> dict[str, bool]:
        """The properties and fields a class body declares, also its primary constructor's
        `val`/`var` parameters (`class R(.., private var query: String?)`), each with whether it
        is a String; read once per body."""
        key = (body.start_byte, body.end_byte)
        cached = self.class_members.get(key)
        if cached is not None:
            return cached
        strings = {"String", "CharSequence", "kotlin.String", "java.lang.String", "Swift.String"}
        found: dict[str, bool] = {}
        for member in body.named_children:
            items = (
                [part for part in member.named_children if part.type == "variable_declarator"]
                if member.type == "field_declaration"
                else [member]
                if member.type == "property_declaration"
                else []
            )
            for item in items:
                declared = self.declaration(item)
                if declared and declared[0] not in found:
                    found[declared[0]] = re.sub(r"\s+", "", declared[2]).rstrip("?!") in strings or (
                        declared[1] is not None and self.string_initializer(declared[1])
                    )
        owner = body.parent
        constructor = (
            next((part for part in owner.named_children if part.type == "primary_constructor"), None)
            if owner is not None
            else None
        )
        for group in constructor.named_children if constructor is not None else []:
            for parameter in group.named_children if group.type == "class_parameters" else []:
                if parameter.type != "class_parameter" or not any(
                    child.type in {"val", "var"} for child in parameter.children
                ):
                    continue  # a plain constructor parameter is no property
                identifier = next(
                    (part for part in parameter.named_children if part.type in IDENTIFIERS), None
                )
                kind = next(
                    (
                        part
                        for part in parameter.named_children
                        if part.type in {"user_type", "nullable_type"}
                    ),
                    None,
                )
                if identifier is not None and self.symbol_name(self.text(identifier)) not in found:
                    found[self.symbol_name(self.text(identifier))] = (
                        kind is not None and re.sub(r"\s+", "", self.text(kind)).rstrip("?") in strings
                    )
        self.class_members[key] = found
        return found

    def data_expression(
        self,
        node: Any,
        frame: Frame,
        data: frozenset[str],
        on_receiver: bool = False,
        results: frozenset[str] = frozenset(),
        scalars: frozenset[str] = frozenset(),
    ) -> bool:
        """An expression whose call chain starts at data: a literal, a value class
        (`String.format`), a name in `data`, a receiverless call or constructor that took input
        (`listOf(title, q)`, `StringBuilder(q)`, `requireNotNull(q)`), a local or parameter
        holding input, or a field or other reference holding an input value (`field = q`,
        `intent`, a String property holding a value derived from input). A service in a field,
        local or parameter (`tracker`, `prefs`) holds none; one an earlier call weak-wrote
        input into keeps no input value of its own. A closure's own names (`data`, `results`)
        are read by name: the enclosing frame does not bind them."""
        base = self.chain_base(node)
        if base is None:
            return False
        if (
            self.scalar_result(node, scalars, frame)
            or self.scalar_result(base, scalars, frame)
            or self.scalar_format(node, frame, scalars)
        ):
            return False  # a flag or a number (`q.length.toString()`, `n` on `val n = q.length`)
        if base.type in STRINGS | TEXT_LITERALS:
            return True
        # `+String.format(..)` parses with `+String` as the receiver: the unaryPlus of a call.
        path = self.text(base).strip().lstrip("+-")
        root = re.split(r"[.?!(\[]", path, maxsplit=1)[0]
        member = root in {"this", "self", "super"} and "." in path and root not in data
        if member:
            # `this.field`, `self.query`: the member, never a local of that name.
            root = re.split(r"[.?!(\[]", path.split(".", 1)[1], maxsplit=1)[0]
        # `java.net.URLEncoder.encode(..)`: the class a qualified path names.
        named = next((segment for segment in path.split(".") if segment[:1].isupper()), "")
        if re.split(r"[?!(\[]", named, maxsplit=1)[0] in VALUE_CLASSES or not member and root in data:
            return True
        if root in {"this", "self", "super"}:
            # `this.displayName().escapeSql()`: an own String function on `this` starts the chain.
            own = self.this_call(node)
            return (
                own is not None
                and self.string_function(own.node, own.name.rsplit(".", 1)[-1])
                and bool(self.reused(own.node, frame).traces)
            )
        receiverless = self.call(base)
        if (
            (on_receiver or "this" in results)
            and receiverless is not None
            and receiverless.receiver is None
            and receiverless.name in STRING_TRANSFORMS
        ):
            return True  # in `q.run { trim().lowercase() }`, on q
        root_call = self.call(base) if base.type not in IDENTIFIERS and not self.navigation(base) else None
        if root_call is not None:
            # A value factory's result (`listOf(title, q)`, `StringBuilder(q)`, also over a
            # closure's own local) or a source call itself (`getIntent()`); another call's result
            # is data only through a String transform (`lookup(q).trim()`), and an object built
            # from input is none (`Uploader(q).start()`, `File(dir, t).delete()`). The visit
            # kept the call's value where the closure's names were bound.
            value = self.reused(base, frame)
            origin = hash((self.path, base.start_byte))
            called = root_call.name.rsplit(".", 1)[-1]
            return bool(value.traces) and (
                called in VALUE_CONSTRUCTORS
                or any(trace.origin == origin for trace in value.traces)
                # An own function declared to return a String (`displayName().ifBlank { .. }`).
                or root_call.receiver is None
                and self.string_function(base, called)
            )
        if self.mentions(base, data):
            return True  # computed from a closure's data (`(t + "x")` on `val t = q.trim()`)
        if self.reads_names(base, results):
            # A closure's other local (`val t = repo.lookup(q)`) or its `it`, also inside a call
            # (`Ext.wrap(r) + "x"`), unless the expression joins input from outside
            # (`(col + " = '" + q + "'")`).
            return self.outer_input(base, frame, data, results, scalars)
        value = self.reused(base, frame)
        if not value.traces:
            return False
        if base.type not in IDENTIFIERS and not self.navigation(base):
            return True  # an expression computed from input (`(q + "x").trim()`)
        if not member and (root in frame.local_names or root in self.parameter_types):
            return True
        # A value derived from input has no category (`query = q.trim()`), nor has a service an
        # earlier unresolved call weak-wrote input into; a String property is no service.
        return value.category != "unknown" or self.string_field(base, root) or self.qualified_string(base)

    def qualified_string(self, node: Any) -> bool:
        """A String member reached through its class or object (`Session.query`, Java
        `Notes.last`, `com.example.Sql.BY_NAME`), declared in any analyzed file."""
        navigation = self.navigation(node)
        if navigation is None or navigation[0] is None:
            return False
        qualifier = self.text(navigation[0]).strip()
        if not re.fullmatch(r"(?:[a-z_]\w*\.)*[A-Z]\w*(?:\.[A-Z]\w*)*", qualifier):
            return False
        owner = qualifier.removesuffix(".Companion").rsplit(".", 1)[-1]
        return (owner, navigation[1]) in self.project_string_members()

    def this_call(self, node: Any) -> Call | None:
        """The call of a chain made on `this` or `self` (`this.displayName()` in
        `this.displayName().escapeSql()`), or None."""
        current = self.unwrap(node)
        for _ in range(MAX_CHAIN):
            call = self.call(current) if current is not None else None
            if call is None or call.receiver is None:
                return None
            receiver = self.unwrap(call.receiver)
            if receiver is not None and self.text(receiver).strip() in {"this", "self"}:
                return call
            current = receiver
        return None

    def chain_base(self, node: Any) -> Any:
        """The receiver a call chain starts at (`repo` in `repo.lookup(q).trim()`), or the node
        itself when it is no call on a receiver."""
        base = self.unwrap(node)
        for _ in range(MAX_CHAIN):
            call = self.call(base) if base is not None else None
            if call is None or call.receiver is None:
                break
            base = self.unwrap(call.receiver)
        return base

    def mentions(self, node: Any, names: frozenset[str]) -> bool:
        """Whether an expression reads one of `names` itself: not as a member name, and not
        inside a call or lambda, whose values a re-read keeps from the visit."""
        if node is None or not names:
            return False
        pending = [node]
        while pending:
            current = pending.pop()
            if current.type in IDENTIFIERS or current.type in {"this_expression", "self_expression", "this"}:
                if self.symbol_name(self.text(current)) in names:
                    return True
                continue
            if (
                current.type in TEXT_LITERALS
                and self.language == "kotlin"
                and names & self.template_names(current)
            ):
                return True  # `"$t"`: tree-sitter-kotlin 1.1.0 keeps a short template as text
            if current is not node and (current.type in CLOSURES or self.call(current) is not None):
                continue
            if current.type in {"navigation_expression", "field_access"}:
                pending.extend(current.named_children[:1])  # `t.name` reads t, not name
            elif current.type not in CLOSURES:
                pending.extend(current.named_children)
        return False

    def template_names(self, node: Any) -> set[str]:
        """The names a Kotlin string's short templates read (`"$t and ${u}"` reads t)."""
        text = self.text(node)
        for part in node.named_children:
            if part.type == "interpolation":
                text = text.replace(self.text(part), "")
        return {match for match in re.findall(r"\$([^\W\d]\w*)", text)}

    def closure_value_expressions(self, closure: Any) -> list[Any]:
        """Only a closure's returned values, excluding nested callbacks and side effects."""
        returned = []
        jumps = {"jump_expression", "control_transfer_statement", "return_statement", "return_expression"}
        last = self.last_statement(closure)
        if (
            self.language == "kotlin"
            and last is not None
            and last.type not in STATEMENT_ONLY
            and not self.declaration(last)
            and self.conditional_branches(last) != []
        ):
            returned.append(last)
        elif closure.type == "lambda_expression":
            body = _field(closure, "body")
            if body is not None and body.type not in BLOCKS:
                returned.append(body)
        elif self.language == "swift":
            body = next((part for part in closure.named_children if part.type == "statements"), None)
            statements = (
                [part for part in body.named_children if part.type not in COMMENTS]
                if body is not None
                else []
            )
            if (
                len(statements) == 1
                and statements[0].type not in STATEMENT_ONLY
                and not self.declaration(statements[0])
                and self.conditional_branches(statements[0]) != []
            ):
                returned.append(statements[0])
        pending = list(closure.named_children)
        while pending and self.closure_work():
            node = pending.pop()
            if node.type in CLOSURES | FUNCTIONS:
                continue
            if node.type in jumps and self.text(node).lstrip().startswith("return"):
                if self.language == "kotlin" and not re.match(r"return\s*@", self.text(node).lstrip()):
                    continue  # a non-local return leaves the surrounding function
                parts = [part for part in node.named_children if part.type not in COMMENTS | {"label"}]
                if (
                    self.language == "kotlin"
                    and _field(node, "label") is None
                    and re.match(r"return\s*@", self.text(node).lstrip())
                ):
                    parts = parts[1:]
                if parts:
                    returned.append(parts[-1])
                continue
            pending.extend(node.named_children)
        return returned

    def closure_value_context(
        self,
        closure: Any,
        frame: Frame,
        data: frozenset[str],
        results: frozenset[str],
        scalars: frozenset[str],
        at: Any,
    ) -> tuple[frozenset[str], frozenset[str], frozenset[str]]:
        """The lexical parameter/receiver and local bindings at one returned expression."""
        declared = self.closure_parameters(closure)
        names = {name for name, _, _ in declared}
        numeric = {name for name, kind, _ in declared if kind.rstrip("?!") in NUMBER_TYPES}
        owner = self.closure_owner(closure)
        name = owner.name.rsplit(".", 1)[-1] if owner is not None else ""
        subject = None
        receiver = False
        if owner is not None and name in SCOPE_FUNCTIONS | {"takeIf", "takeUnless", "forEach", "onEach"}:
            subject = (
                owner.args[0] if name == "with" and owner.receiver is None and owner.args else owner.receiver
            )
            if name in {"with", "run", "apply"} and subject is not None:
                names = {"this"}
            elif not names and name in {"let", "also", "use", "takeIf", "takeUnless", "forEach", "onEach"}:
                names = {"$0" if self.language == "swift" else "it"}
        scope, held, numbers = data - names, results - names, scalars - names
        if subject is not None:
            if self.scalar_result(subject, scalars, frame) or self.scalar_format(subject, frame, scalars):
                held, numbers = held | names, numbers | names
            elif self.data_expression(subject, frame, data, results=results, scalars=scalars) or (
                self.reused(subject, frame).traces
                and self.value_result(subject, frame, data=data, results=results, scalars=scalars)
            ):
                scope = scope | names
                receiver = "this" in names
            else:
                held = held | names
        else:
            held = held | names
            numbers = numbers | numeric
        return self.closure_data_locals(closure, frame, scope, receiver, held, numbers, at=at)

    def outer_input(
        self,
        node: Any,
        frame: Frame,
        data: frozenset[str],
        results: frozenset[str],
        scalars: frozenset[str] = frozenset(),
    ) -> bool:
        """Whether an expression that reads a closure's call-result names (`results`) also reads
        input: a closure data name, a name of the enclosing frame or a call over neither that
        carries input (`(col + " = '" + q + "'")` on `val col = settings.sortColumn()`,
        `(Ext.wrap(t) + col)` on `val t = q.trim()`), also among the other arguments of a call
        over a call-result name (`(Ext.quote(col, q) + " ASC")`). A call over such a name alone
        (`Ext.wrap(col) + "x"`) carries that result's input, not input of its own."""
        pending = [node]
        while pending and self.closure_work():
            current = pending.pop()
            if self.scalar_result(current, scalars, frame) or self.scalar_format(current, frame, scalars):
                continue
            if current.type in IDENTIFIERS:
                name = self.symbol_name(self.text(current))
                if name in data or name not in results and self.reused(current, frame).traces:
                    return True
                continue
            call = self.call(current)
            if call is not None:
                builders = [
                    closure
                    for arg in call.args
                    if (closure := self.closure_argument(arg)) is not None
                    and (closure.start_byte, closure.end_byte) in self.string_builder_results
                ]
                if builders:
                    if any(
                        self.written_outer_input(closure, frame, data, results, scalars)
                        for closure in builders
                    ):
                        return True
                    continue  # buildString returns its written text, not append's receiver or capacity
                implicit_result = (
                    call.receiver is None
                    and "this" in results
                    and call.name.rsplit(".", 1)[-1] in STRING_TRANSFORMS
                )
                if not implicit_result and not self.reads_names(current, results):
                    if self.reused(current, frame).traces:
                        return True
                    continue
                selecting = call.name.rsplit(".", 1)[
                    -1
                ] in SELECTING_FUNCTIONS or CALLBACK_REGISTRATIONS.match(call.name.rsplit(".", 1)[-1])
                pending.extend(
                    argument
                    for argument in call.args
                    if not selecting or self.closure_argument(argument) is None
                )
                if call.receiver is not None:
                    pending.append(call.receiver)
                continue
            if current.type in CLOSURES:
                if self.written_outer_input(current, frame, data, results, scalars):
                    return True
                if self.reused(current, frame).traces:
                    for expression in self.closure_value_expressions(current):
                        local_data, local_results, local_scalars = self.closure_value_context(
                            current, frame, data, results, scalars, expression
                        )
                        if self.outer_input(expression, frame, local_data, local_results, local_scalars):
                            return True
                continue
            branches = self.conditional_branches(current)
            if branches is not None:
                for branch in branches:
                    if branch is None:
                        continue
                    expression = self.last_statement(branch)
                    if expression is None:
                        continue
                    local_data, local_results, local_scalars = self.closure_data_locals(
                        current, frame, data, results=results, scalars=scalars, at=expression
                    )
                    if self.outer_input(expression, frame, local_data, local_results, local_scalars):
                        return True
                continue
            if current.type in TEXT_LITERALS and self.language == "kotlin":
                for name in self.template_names(current) - results:
                    if name in data or frame.values.get(name) is not None and frame.values[name].traces:
                        return True
            if current.type in {"navigation_expression", "field_access"}:
                pending.extend(current.named_children[:1])
            else:
                pending.extend(current.named_children)
        return False

    def written_outer_input(
        self,
        closure: Any,
        frame: Frame,
        data: frozenset[str],
        results: frozenset[str],
        scalars: frozenset[str],
    ) -> bool:
        """Classify written expressions in their own scopes; call-result provenance alone is insufficient."""
        written = self.closure_written.get((closure.start_byte, closure.end_byte))
        if written is None or not written.traces:
            return False
        for expression in self.closure_write_nodes.get((closure.start_byte, closure.end_byte), ()):
            local_data, local_results, local_scalars = self.closure_value_context(
                closure, frame, data, results, scalars, expression
            )
            if self.outer_input(expression, frame, local_data, local_results, local_scalars):
                return True
        return False

    def reads_names(self, node: Any, names: frozenset[str]) -> bool:
        """Whether any identifier under a node (also inside calls) is one of `names`."""
        return any(
            part.type in IDENTIFIERS and self.symbol_name(self.text(part)) in names for part in _walk(node)
        ) or (node.type in TEXT_LITERALS and bool(names & self.template_names(node)))

    def implicit_chain(self, call: Call, frame: Frame) -> list[Call]:
        """The calls of a chain written into a Kotlin lambda's implicit receiver.

        `append("<p>").append(q)` starts at a receiverless write, `this.append(q)` at
        the lambda's `this` (not one an `apply`/`run`/`with` block rebound); the chain is
        a statement. Empty for any other chain.
        """
        links = []
        node = call.receiver
        for _ in range(MAX_CHAIN):
            if node is None:
                return []
            node = self.unwrap(node)
            if node is None:
                return []
            if self.implicit_this(node, frame) or self.producer_channel(node, frame):
                return [call, *links] if self.implicit_write(call, call.node) else []
            inner = self.call(node)
            if inner is None:
                return []
            if inner.receiver is None:
                return [call, *links, inner] if self.implicit_write(inner, call.node) else []
            if inner.name.rsplit(".", 1)[-1] in READ_ONLY_MEMBERS:
                return []
            links.append(inner)
            node = inner.receiver
        self.chain_cut(call.node)
        return []

    def producer_channel(self, node: Any, frame: Frame) -> bool:
        """`channel` in a channelFlow/callbackFlow/produce lambda: its receiver's own SendChannel
        (`channel.send(q)`), not a local of that name."""
        if node.type not in IDENTIFIERS or self.text(node) != "channel" or "channel" in frame.local_names:
            return False
        owner = next((effects for effects in reversed(self.closure_effects) if effects.implicit), None)
        return owner is not None and "ProducerScope" in owner.receiver_types

    def implicit_this(self, node: Any, frame: Frame) -> bool:
        """`this` in a Kotlin lambda with a possible implicit receiver, not rebound by a scope block."""
        node = self.unwrap(node)
        if node is None or node.type not in {"this_expression", "this"} or self.text(node).strip() != "this":
            return False
        owner = next((effects for effects in reversed(self.closure_effects) if effects.implicit), None)
        # A `with`/`apply` around the builder call bound `this` before the lambda: still its own.
        return owner is not None and frame.values.get("this") is owner.outer_this

    def builder_transform(self, call: Call, types: frozenset[str], frame: Frame) -> bool:
        """Whether a known builder can receive this modeled transform/overload.

        String-only extensions keep looking outward; collection receivers can own
        shared spellings such as take/toString before an outer StringBuilder.
        """
        name, count = call.name.rsplit(".", 1)[-1], len(call.args)
        if name == "toString":
            return count == 0
        if types & {"MutableCollection", "MutableMap"}:
            if name == "plus":
                return count == 1
            if name == "orEmpty":
                return count == 0
            if name == "ifEmpty":
                return count == 1
        if "MutableIterable" in types:
            if name in {"take", "drop"} or name in {"takeLast", "dropLast"} and "MutableList" in types:
                return count == 1
            if name == "reversed":
                return count == 0
        if not types & {"StringBuilder", "SpannableStringBuilder"}:
            return False
        if name in {"trim", "trimStart", "trimEnd", "split"}:
            return True
        if name in {"lines", "reversed"}:
            return count == 0
        if name in {
            "take",
            "takeLast",
            "drop",
            "dropLast",
            "repeat",
            "removePrefix",
            "removeSuffix",
            "ifEmpty",
            "ifBlank",
        }:
            return count == 1
        if name in {"padStart", "padEnd", "removeSurrounding", "substring"}:
            return 1 <= count <= 2
        if name not in {"replace", "replaceFirst"} or count < 2:
            return False
        first = self.unwrap(call.args[0])
        if first is None:
            return False
        value = self.reused(first, frame)
        kind = value.type_name
        if first.type in IDENTIFIERS:
            local = self.symbol_name(self.text(first))
            kind = frame.types.get(local, "") or self.parameter_types.get(local, "") or kind
        kind = kind.rstrip("?").rsplit(".", 1)[-1]
        constructor = self.call(first)
        regex = (
            self.argument_label(call.args[0]) == "regex"
            or kind == "Regex"
            or (constructor is not None and constructor.name.rsplit(".", 1)[-1] in {"Regex", "toRegex"})
        )
        if regex:
            return count == 2
        # JVM StringBuilder.replace(start, end, text) is a member; the two-String
        # replacement overload is an extension on String, not CharSequence.
        return name == "replace" and count == 3 and (first.type in NUMBERS or kind in {"Int", "int"})

    def statement_position(self, node: Any) -> bool:
        """An expression written as a statement of a block or lambda (also its last one,
        and a Java lambda's expression body), also under Swift `try`/`await`, `_ =` or
        `let _ =`.

        A Kotlin if/when/try branch (unbraced, or the last statement of a braced one), an
        elvis fallback and a labeled expression are statements only where the if, when,
        try, elvis or label itself is one: `val ok = if (c) check(q) else true` is an
        initializer. Each step up is decided once per node, so long chains stay linear.
        """
        path = []
        current = node
        result = False
        while True:
            key = (current.start_byte, current.end_byte, current.type)
            cached = self.statement_positions.get(key)
            if cached is not None:
                result = cached
                break
            path.append(key)
            step = self.statement_step(current)
            if step is None or isinstance(step, bool):
                result = bool(step)
                break
            current = step
        for key in path:
            self.statement_positions[key] = result
        return result

    def statement_step(self, node: Any) -> Any:
        """Whether a node stands as a statement, or the enclosing node whose position decides."""
        parent = node.parent
        if self.language == "swift":
            while parent is not None and parent.type in {"try_expression", "await_expression"}:
                parent = parent.parent
            if (
                parent is not None
                and parent.type == "property_declaration"
                and any(
                    part.type == "pattern" and self.text(part).strip() == "_"
                    for part in parent.named_children
                )
            ):
                parent = parent.parent  # `let _ = Fill.into(b, q)` discards the value
        if (
            parent is not None
            and parent.type == "assignment"
            and parent.named_children
            and self.text(parent.named_children[0]).strip() == "_"
        ):
            parent = parent.parent
        if parent is None:
            return False
        if parent.type in {
            "statements",
            "block",
            "lambda_literal",
            "lambda_expression",
            "control_structure_body",
            "expression_statement",
        }:
            if self.language == "kotlin" and parent.type == "lambda_literal":
                last = self.last_part(parent) == (node.start_byte, node.end_byte, node.type)
                scope = self.closure_owner(parent) if last else None
                name = scope.name.rsplit(".", 1)[-1] if scope is not None else ""
                if scope is not None and name == "runCatching":
                    return self.result_chain(scope.node)
                if scope is not None and name in MAPPING_INTO:
                    return False  # `items.mapTo(out) { describe(it) }` stores the result
                if scope is not None and name in {"let", "run", "with", "use"} | MAPPING_FUNCTIONS:
                    return scope.node  # `val n = q.let { if (..) parse(q) else 0 }`: the block's value
                if name in SELECTING_FUNCTIONS - {"forEach", "forEachIndexed", "onEach", "peek"}:
                    return False  # a predicate, key or comparison (`items.filter { isAllowed(q) }`)
            if self.language == "kotlin" and parent.type == "block":
                owner = parent.parent
                if (
                    owner is not None
                    and owner.type in {"if_expression", "when_entry", "try_expression", "catch_block"}
                    and self.last_part(parent) == (node.start_byte, node.end_byte, node.type)
                ):
                    # The last statement of a braced branch is the branch's value.
                    return owner.parent if owner.type in {"when_entry", "catch_block"} else owner
            return True
        if self.language != "kotlin":
            return False
        if parent.type == "infix_expression" and self.misparsed_call(parent) is not None:
            # `text(q)` on the line before a misparsed `where(..)` line stands where the pair does.
            first = next((part for part in parent.named_children if part.type not in COMMENTS), None)
            if first is None or not _same_node(first, node):
                return False
            # The first operand of a glued declaration or assignment is that line's value, unless
            # it is an earlier glued line itself (`val (a, b) = p` then two `where(..)` lines).
            outer = parent
            while outer.parent is not None and self.misparsed_call(outer.parent) is not None:
                outer = outer.parent
            owner = outer.parent
            return (
                False
                if (
                    owner is not None
                    and owner.type in {"property_declaration", "assignment"}
                    or self.glued_operand(outer)
                )
                and self.misparsed_call(node) is None
                else parent
            )
        if parent.type not in {
            "if_expression",
            "when_entry",
            "for_statement",
            "while_statement",
            "do_while_statement",
            "labeled_expression",
            "parenthesized_expression",
            "binary_expression",
        }:
            return False
        # tree-sitter-kotlin 1.1.0 hangs an unbraced body directly under its statement.
        parts = [part for part in parent.named_children if part.type not in COMMENTS]
        position = next((index for index, part in enumerate(parts) if _same_node(part, node)), None)
        if position is None:
            return False
        if parent.type == "if_expression":
            condition = _field(parent, "condition") or parts[0]
            return False if _same_node(condition, node) else parent
        if parent.type == "when_entry":
            # The body follows the entry's conditions.
            return parent.parent if position == len(parts) - 1 else False
        children = parent.children
        index = next((index for index, child in enumerate(children) if _same_node(child, node)), 0)
        if parent.type in {"for_statement", "while_statement"}:
            # The body follows the header's `)`: `while (advance(q)) ;` has none.
            return any(child.type == ")" for child in children[:index])
        if parent.type == "do_while_statement":
            return not any(child.type == "while" for child in children[:index])
        if parent.type in {"labeled_expression", "parenthesized_expression"}:
            return parent
        if parent.type == "binary_expression" and self.elvis(parent):
            operand = node
            while operand.type == "parenthesized_expression" and operand.named_children:
                operand = operand.named_children[0]
            scope = self.call(operand)
            scoped = scope is not None and scope.name.rsplit(".", 1)[-1] in SCOPE_FUNCTIONS
            if position == 1:
                inner, outer = parent, parent.parent
                while outer is not None and outer.type == "parenthesized_expression":
                    inner, outer = outer, outer.parent  # `(cached ?: load(q)) ?: return@page`
                if (
                    not scoped
                    and outer is not None
                    and outer.type == "binary_expression"
                    and self.elvis(outer)
                    and _same_node(
                        next(part for part in outer.named_children if part.type not in COMMENTS), inner
                    )
                ):
                    return False  # `cached ?: load(q) ?: return@page`: the outer elvis tests load(q)
                return parent  # `x ?: append(q)`
            if scoped or operand.type == "binary_expression" and self.elvis(operand):
                # `x?.let { text(it) } ?: footer()` runs the block for its effects, also in a
                # chain (`a?.let { .. } ?: b?.let { .. } ?: c`, read as `(a ?: b) ?: c`).
                return parent
        return False

    def result_chain(self, node: Any) -> Any:
        """Where a runCatching call's block value goes: through the Result calls that pass it
        on (`runCatching { .. }.onFailure { .. }`, `.getOrNull()`) to the node whose position
        decides; dropped (True) by `exceptionOrNull()`, `isSuccess` and `isFailure`."""
        for _ in range(MAX_CHAIN):
            parent = node.parent
            if parent is None or parent.type != "navigation_expression" or not parent.named_children:
                return node
            if not _same_node(parent.named_children[0], node):
                return node
            member = re.sub(r"^\W+", "", self.text(parent.named_children[-1]))
            if member in RESULT_DISCARDS:
                return True
            outer = parent.parent
            call = self.call(outer) if outer is not None else None
            if call is None or member not in RESULT_VALUE_CALLS:
                return node
            node = outer
        return node

    def elvis(self, node: Any) -> bool:
        """A Kotlin `a ?: b` binary expression."""
        parts = [part for part in node.named_children if part.type not in COMMENTS]
        return len(parts) == 2 and self.raw[parts[0].end_byte : parts[1].start_byte].strip() == b"?:"

    def misparsed_call(self, node: Any) -> Call | None:
        """A statement call that tree-sitter-kotlin 1.1.0 reads as the infix operator of the
        line before it (`append(..)` then `where(c)`, also `by(..)` and `constructor(..)`).

        Kotlin ends a statement at a newline before an infix function name, so a newline
        there and a parenthesized operand mean a receiverless call written on its own line.
        """
        if node.type != "infix_expression" or self.language != "kotlin":
            return None
        parts = [part for part in node.named_children if part.type not in COMMENTS]
        if len(parts) != 3 or parts[1].type not in IDENTIFIERS or parts[2].type != "parenthesized_expression":
            return None
        if b"\n" not in self.raw[parts[0].end_byte : parts[1].start_byte]:
            return None
        if self.raw[parts[1].end_byte : parts[2].start_byte].strip():
            return None
        arguments = tuple(part for part in parts[2].named_children if part.type not in COMMENTS)
        return Call(node, self.text(parts[1]), None, arguments, (), parts[2])

    def glued_line(self, node: Any) -> tuple[Any, list[tuple[Any, Call]]] | None:
        """A Kotlin declaration or assignment that tree-sitter-kotlin 1.1.0 glued to misparsed
        `where(..)` lines after it (`val c = "n = '$q'"` then `where(c)`): the line's own value
        (the innermost infix's first operand) and each glued infix with its call, first first."""
        if self.language != "kotlin" or node.type not in {"property_declaration", "assignment"}:
            return None
        if node.type == "property_declaration" and self.declaration(node) is None:
            return None  # `val (a, b) = pair` then `where(..)`: glued_operand
        current = node.named_children[-1] if node.named_children else None
        glued: list[tuple[Any, Call]] = []
        while current is not None and current.type == "infix_expression":
            misparsed = self.misparsed_call(current)
            if misparsed is None:
                break
            glued.append((current, misparsed))
            current = next((part for part in current.named_children if part.type not in COMMENTS), None)
        if not glued or current is None:
            return None
        return current, list(reversed(glued))

    def glued_operand(self, node: Any) -> bool:
        """Whether a misparsed infix ends a declaration's or assignment's value through last
        operands (`limit ?: (10 where (..))`, `if (c) "ASC" else ("DESC" where (..))`)."""
        child, parent = node, node.parent
        for _ in range(MAX_CHAIN):
            if parent is None:
                return False
            if parent.type in {"property_declaration", "assignment"}:
                return bool(parent.named_children) and _same_node(parent.named_children[-1], child)
            # tree-sitter-kotlin 1.1.0 reads comparisons and logical operations as binary_expression.
            if parent.type not in {
                "binary_expression",
                "in_expression",
                "if_expression",
                "control_structure_body",
            }:
                return False
            parts = [part for part in parent.named_children if part.type not in COMMENTS]
            if not parts or not _same_node(parts[-1], child):
                return False
            child, parent = parent, parent.parent
        return False

    def last_part(self, parent: Any) -> tuple[int, int, str] | None:
        """The span of a block's or lambda's last statement, decided once per parent."""
        key = (parent.start_byte, parent.end_byte, parent.type)
        if key in self.last_parts:
            return self.last_parts[key]
        skip = COMMENTS | {"lambda_parameters", "label"}
        last = next((part for part in reversed(parent.named_children) if part.type not in skip), None)
        found = (last.start_byte, last.end_byte, last.type) if last is not None else None
        self.last_parts[key] = found
        return found

    def implicit_write(self, call: Call, position: Any = None) -> bool:
        """A receiverless call that may write into a Kotlin lambda's implicit receiver.

        Any call may be the receiver's member (a DSL's text or parameter), except a
        standard top-level function that writes into nothing (println, require, ...)
        and a project function this call can bind to (a function of a class, companion
        or object around it, of a class this one extends, or of the top level). A
        known builder's writing members (buildString's append, flow's emit) are found
        on its receiver before a project function of that name.
        """
        name = call.name.rsplit(".", 1)[-1]
        owner = next((effects for effects in reversed(self.closure_effects) if effects.implicit), None)
        if owner is not None and self.language == "kotlin" and name.startswith("+"):
            # tree-sitter-kotlin reads `+format(q)` as a call of `+format`: a DSL unaryPlus of its result.
            return self.statement_position(position if position is not None else call.node)
        if owner is None or name in NON_WRITERS or not (name[:1].islower() or name[:1] == "_"):
            # A capitalized callee is a constructor (`File(q)`, `IllegalStateException(q)`);
            # tree-sitter-kotlin reads `!isAllowed(q)` as a call of `!isAllowed`, a negation.
            return False
        if name in owner.members:
            return True  # A known builder's writing member writes wherever it stands (`if (add(q))`).
        if not self.statement_position(position if position is not None else call.node):
            # A write is a statement: not a condition, an argument, an initializer or a throw.
            return False
        if self.native_flow is None:
            return True
        if owner.receiver_types:
            # A known builder's receiver has no other member: only a project extension of
            # it or a writable supertype (`fun StringBuilder.appendSql(..)`,
            # `fun Appendable.appendQuoted(..)`) writes into it.
            return self.project_extension(name, call, set(owner.receiver_types))
        if self.enclosing_function(call, name):
            return False
        classes = self.native_flow.project_ancestry(self.native_flow.owner(self, self.function))
        if self.project_extension(name, call, {owner_class.rsplit(".", 1)[-1] for owner_class in classes}):
            return False  # `fun Repo.log(..)` called in a Repo method binds to this.
        return not any(
            # A Kotlin class can extend a Java one and call its members receiverless.
            (target.analyzer.language == self.language or target.owner and target.analyzer.language == "java")
            and (
                target.owner in classes
                if target.owner
                else self.native_flow.top_level_visible(self, target, call.name)
            )
            and (
                self.native_flow.signature_visible(self, target, call)
                or target.analyzer.language == "kotlin"
                and target.analyzer.accepts_arguments(target.node, len(call.args))
            )
            and self.native_flow.lexical_visible(self, target, call)
            for alias in {
                name,
                *(symbol.rsplit(".", 1)[-1] for symbol in self.native_flow.imported_symbols(self, name)),
            }
            for target in self.native_flow.by_name.get(alias, [])
        )

    def project_extension(self, name: str, call: Call, receivers: set[str]) -> bool:
        """A Kotlin project extension function of this name on one of these receiver types."""
        if self.native_flow is None:
            return False
        for target in self.native_flow.by_name.get(name, []):
            if target.analyzer.language != "kotlin":
                continue
            declared = _field(target.node, "name")
            receiver = next(
                (
                    child
                    for child in target.node.named_children
                    if declared is not None
                    and child.end_byte <= declared.start_byte
                    and child.type in {"user_type", "nullable_type", "type_identifier"}
                ),
                None,
            )
            if receiver is None:
                continue
            if self.receiver_names(target.analyzer, target.node, receiver) & receivers and (
                target.analyzer.accepts_arguments(target.node, len(call.args))
            ):
                return True
        return False

    def receiver_names(self, analyzer: Analyzer, function: Any, receiver: Any) -> set[str]:
        """The simple type names an extension's receiver spells: the type itself, a type
        parameter's bounds (`fun <T : Appendable> T.x()`) or a project typealias's target."""
        simple = re.sub(r"<.*", "", analyzer.text(receiver)).rstrip("?").strip().rsplit(".", 1)[-1]
        names = {simple}
        parameters = [part for part in function.named_children if part.type == "type_parameters"]
        constraints = [part for part in function.named_children if part.type == "type_constraints"]
        for declared in (
            *(item for part in parameters for item in part.named_children if item.type == "type_parameter"),
            *(item for part in constraints for item in part.named_children if item.type == "type_constraint"),
        ):
            identifier = next((child for child in declared.named_children if child.type in IDENTIFIERS), None)
            if identifier is not None and analyzer.text(identifier) == simple:
                names.update(
                    re.sub(r"<.*", "", analyzer.text(bound)).rstrip("?").strip().rsplit(".", 1)[-1]
                    for bound in declared.named_children
                    if bound.type in {"user_type", "nullable_type"}
                )
        if self.native_flow is not None:
            for source, alias in self.native_flow.module_type_aliases.get(simple, []):
                if source.language == "kotlin":
                    names.update(
                        re.sub(r"<.*", "", source.text(aliased)).rstrip("?").strip().rsplit(".", 1)[-1]
                        for aliased in alias.named_children
                        if aliased.type in {"user_type", "nullable_type"}
                    )
        return names

    def enclosing_function(self, call: Call, name: str) -> bool:
        """A function of this name that can take the call's arguments, declared in a Kotlin
        class, companion object or object body around the call (no extension function)."""
        for body in self.class_bodies(call.node):
            for member in self.body_functions(body).get(name, []):
                if self.accepts_arguments(member, len(call.args)):
                    return True
        return False

    def class_bodies(self, node: Any) -> tuple[Any, ...]:
        """The class bodies around a node, innermost first.

        Each ancestor's answer is kept (tree-sitter's parent walk costs the depth), so the
        calls of a long branch chain share one walk.
        """
        path = []
        current = node.parent
        found: tuple[Any, ...] = ()
        while current is not None:
            cached = self.enclosing_bodies.get((current.start_byte, current.end_byte, current.type))
            if cached is not None:
                found = cached
                break
            path.append(current)
            current = current.parent
        for ancestor in reversed(path):
            if ancestor.type == "class_body":
                found = (ancestor, *found)
            self.enclosing_bodies[(ancestor.start_byte, ancestor.end_byte, ancestor.type)] = found
        return found

    def body_functions(self, body: Any) -> dict[str, list[Any]]:
        """The non-extension functions a class body and its companion object declare, by name."""
        key = (body.start_byte, body.end_byte)
        cached = self.class_functions.get(key)
        if cached is not None:
            return cached
        members = list(body.named_children)
        for companion in (part for part in body.named_children if part.type == "companion_object"):
            members += [
                member
                for part in companion.named_children
                if part.type == "class_body"
                for member in part.named_children
            ]
        functions: dict[str, list[Any]] = {}
        for member in members:
            declared = _field(member, "name") if member.type == "function_declaration" else None
            if declared is not None and not any(
                child.type == "." for child in member.children if child.end_byte <= declared.start_byte
            ):
                functions.setdefault(self.text(declared), []).append(member)
        self.class_functions[key] = functions
        return functions

    def accepts_arguments(self, function: Any, count: int) -> bool:
        """Whether a Kotlin function declaration can take this many arguments."""
        parameters = next(
            (part for part in function.named_children if part.type == "function_value_parameters"), None
        )
        if parameters is None:
            return count == 0
        declared = [part for part in parameters.named_children if part.type == "parameter"]
        if any(
            part.type == "parameter_modifiers" and "vararg" in self.text(part)
            for part in parameters.named_children
        ):
            return True
        defaults = len(
            [
                part
                for part in parameters.named_children
                if part.type not in {"parameter", "parameter_modifiers"} | COMMENTS
            ]
        )
        return len(declared) - defaults <= count <= len(declared)

    def call_input_values(self, call: Call, frame: Frame) -> tuple[Value, dict[int, Value]]:
        """A call's receiver and data argument values, bound before any of its closures runs."""
        reuse = self.reuse_visited
        self.reuse_visited = True
        try:
            receiver = self.value(call.receiver, frame)
            given = {
                index: self.value(arg, frame)
                for index, arg in enumerate(call.args)
                if self.closure_argument(arg) is None
            }
        finally:
            self.reuse_visited = reuse
        # The sink checks of this call read these values, not ones its closures changed.
        for node, value in [
            (call.receiver, receiver),
            *((call.args[index], value) for index, value in given.items()),
        ]:
            if node is not None:
                self.visited_values[(node.start_byte, node.end_byte, node.type)] = value
        return receiver, given

    def discarded(self, node: Any) -> bool:
        """A call written as a statement whose value nothing reads."""
        parent = node.parent
        if parent is None:
            return False
        if parent.type == "expression_statement":
            return True
        if parent.type not in {"statements", "block", "lambda_literal", "control_structure_body"}:
            return False
        if self.last_part(parent) != (node.start_byte, node.end_byte, node.type):
            return True  # the last statement of each parent is found once
        statements = [
            part
            for part in parent.named_children
            if part.type not in COMMENTS and part.type != "lambda_parameters"
        ]
        # A last statement is the value of a closure or of an if/when/try branch.
        owner = parent if parent.type == "lambda_literal" else parent.parent
        if (
            self.language == "swift"
            and parent.type == "statements"
            and len(statements) == 1
            and owner is not None
            and owner.type in {"function_body", "computed_property", "computed_getter"}
        ):
            return False  # A single-expression Swift body returns its value.
        return owner is None or owner.type not in {
            "lambda_literal",
            "if_expression",
            "if_statement",
            "when_entry",
            "switch_entry",
            "try_expression",
            "catch_block",
            "control_structure_body",
        }

    def chain_cut(self, node: Any) -> None:
        """A chain longer than MAX_CHAIN links: what it reaches is not followed (a precision limit)."""
        if self.native_flow is not None:
            self.native_flow.partial("object alias identity unavailable", self, node=node)

    def effect_root(self, node: Any) -> Any:
        """The name an expression's object is reached through: `b` in `b.items[0].text`."""
        start = node
        for _ in range(MAX_CHAIN):
            if node is None or node.type in IDENTIFIERS:
                return node
            navigation = self.navigation(node)
            if navigation:
                node = navigation[0]
                continue
            if (
                self.language == "swift"
                and node.type == "call_expression"
                and len(node.named_children) == 2
                and node.named_children[1].type == "call_suffix"
                and self.text(node.named_children[1]).lstrip().startswith("[")
            ):
                node = node.named_children[0]  # `m["q"]`: a subscript of m
                continue
            call = self.call(node)
            if call is not None:
                node = call.receiver
                continue
            if (
                node.type
                in {"indexing_expression", "index_expression", "subscript_expression", "array_access"}
                and node.named_children
            ):
                node = node.named_children[0]
                continue
            if node.type in {"value_argument", "parenthesized_expression"} and node.named_children:
                node = node.named_children[-1]
                continue
            unwrapped = self.unwrap(node)
            if unwrapped is not None and unwrapped is not node:
                node = unwrapped  # `b!!.append(q)`, `(b as StringBuilder).append(q)`
                continue
            return None
        self.chain_cut(start)
        return None

    def supplied(self, node: Any, frame: Frame) -> bool:
        """Whether an expression is rooted at an object a followed closure's callee supplied."""
        root = self.effect_root(node) if node is not None else None
        if root is None:
            return False
        name = self.symbol_name(self.text(root))
        for effects in reversed(self.closure_effects):
            bound = effects.names.get(name)
            if bound is not None:
                return frame.values.get(name) is bound
        return False

    def deferred_write(self, right: Any, target: str) -> Value | None:
        """What followed closures inside an assignment's right side assigned to its target name.

        A closure of a standard function that runs it before returning (`also`, `map`) and a
        lambda invoked where it is written (`{ .. }()`) write before the assignment stores; a
        callback, and any closure nested in it, may write after it. Each callback is read
        once (callback_writes), so nested callbacks and many assignments stay linear.
        """
        written: list[Value] = []
        pending = [right]
        while pending:
            node = pending.pop()
            if node.type in CLOSURES and not self.inline_closure(node):
                written.extend(self.callback_writes(node, target))
                continue
            pending.extend(node.named_children)
        return _union(written) if written else None

    def inline_closure(self, closure: Any) -> bool:
        """A closure that runs before its call returns: a standard function's (`also`, `map`) or
        one invoked where it is written (`{ .. }()`)."""
        owner = self.closure_owner(closure)
        if owner is not None and owner.name.rsplit(".", 1)[-1] in INLINE_CALLEES:
            return True
        parent = closure.parent
        return (
            parent is not None
            and parent.type == "call_expression"
            and bool(parent.named_children)
            and _same_node(parent.named_children[0], closure)
        )

    def callback_writes(self, closure: Any, target: str) -> list[Value]:
        """What a callback and the closures in it assigned to `target` (`u = requested`, also an
        alias of the value from before, not that value where it did not assign), read top
        down: a local of that name a block or lambda declares (also by destructuring or a Swift
        `guard` binding) shadows the target after it, and a Swift `if` binding in its
        then-block (`refresh { var url = requested; url = url.trim() }` writes its own url)."""
        found: list[Value] = []
        pending: list[tuple[Any, bool]] = [(closure, False)]
        while pending:
            node, shadowed = pending.pop()
            if node.type in {"assignment", "assignment_expression"} and not shadowed:
                left = self.assignment_target(
                    _field(node, "left") or _field(node, "target") or next(iter(node.named_children), None)
                )
                stored = self.assigned_values.get((node.start_byte, node.end_byte))
                if (
                    left is not None
                    and left.type in IDENTIFIERS
                    and self.symbol_name(self.text(left)) == target
                    and stored is not None
                ):
                    found.append(stored)
            if node.type in BLOCKS | CLOSURES | {"control_structure_body"}:
                inner = shadowed
                for child in node.named_children:
                    pending.append((child, inner))
                    if not inner and target in self.declared_names(child):
                        inner = True
            elif node.type == "if_statement":
                bound = target in self.binding_names(node)
                pending.extend(
                    (child, shadowed or bound and self.then_block(node, child))
                    for child in node.named_children
                )
            else:
                pending.extend((child, shadowed) for child in node.named_children)
        return found

    def binding_names(self, node: Any) -> set[str]:
        """The names a Swift `if` or `guard` statement binds (`if var page = ..`)."""
        names = set()
        children = node.named_children
        for index, child in enumerate(children[:-1]):
            if child.type == "value_binding_pattern":
                bound = children[index + 1]
                identifier = (
                    bound
                    if bound.type in IDENTIFIERS
                    else next((part for part in _walk(bound) if part.type in IDENTIFIERS), None)
                )
                if identifier is not None:
                    names.add(self.text(identifier))
        return names

    def then_block(self, statement: Any, child: Any) -> bool:
        """Whether a child of a Swift `if` statement is its then-block (before any `else`), where
        the statement's bindings are visible."""
        if child.type not in BLOCKS:
            return False
        otherwise = next((part for part in statement.children if part.type == "else"), None)
        return otherwise is None or child.start_byte < otherwise.start_byte

    def declared_names(self, node: Any) -> set[str]:
        """The names a statement declares for the statements after it: a local (also each Java
        declarator), a Kotlin destructuring declaration (`var (a, page) = ..`), or a Swift
        `guard` binding (`guard var page = .. else { .. }`; an `if` binding is its then-block's)."""
        if node.type == "guard_statement":
            return self.binding_names(node)
        if node.type == "property_declaration":
            destructured = next(
                (part for part in node.named_children if part.type == "multi_variable_declaration"), None
            )
            if destructured is not None:
                return {
                    self.symbol_name(self.text(identifier))
                    for part in destructured.named_children
                    if part.type == "variable_declaration"
                    for identifier in part.named_children[:1]
                }
        items = node.named_children if node.type == "local_variable_declaration" else [node]
        return {declared[0] for item in items if (declared := self.declaration(item))}

    def closure_owner(self, closure: Any) -> Call | None:
        """The call a closure literal is an argument (or the trailing lambda) of."""
        node = closure.parent
        for _ in range(5):
            if node is None:
                return None
            call = self.call(node)
            if call is not None:
                for arg in call.args:
                    found = self.closure_argument(arg)
                    if found is not None and (found.start_byte, found.end_byte) == (
                        closure.start_byte,
                        closure.end_byte,
                    ):
                        return call
            node = node.parent
        return None

    def handed_over(self, node: Any, frame: Frame) -> bool:
        """An argument that is a supplied object itself or a part of it (`b.body`), not a
        value read from it (`b.length`, `b.toString()`)."""
        target = node.named_children[-1] if node.type == "value_argument" and node.named_children else node
        target = self.unwrap(target)
        if target is None:
            return False
        if target.type in IDENTIFIERS:
            return self.supplied(target, frame)
        branches = self.conditional_branches(target)
        if branches:
            # `q == null ? m.getBody() : m.getHead()`: either part may be the one handed over.
            return any(
                self.handed_over(self.last_statement(branch), frame)
                for branch in branches
                if branch is not None
            )
        getter = self.call(target)
        if getter is not None:
            # `m.getBody()`, `m.getChild("body")`: a part returned by a getter of the object,
            # not a value read from it (`m.getId()`, `m.isReady()`, `b.getInt("rows")`).
            name = getter.name.rsplit(".", 1)[-1]
            return (
                getter.receiver is not None
                and all(self.literal_argument(arg) for arg in getter.args)
                and name not in READ_ONLY_MEMBERS
                and not self.value_member(name)
                and not (getter.args and SCALAR_GETTERS.fullmatch(name))
                and self.supplied(target, frame)
            )
        navigation = self.navigation(target)
        return bool(navigation and not self.value_member(navigation[1]) and self.supplied(target, frame))

    def handed_parts(self, node: Any) -> list[Any]:
        """The objects an argument hands over: each branch of a conditional, else itself."""
        target = node.named_children[-1] if node.type == "value_argument" and node.named_children else node
        target = self.unwrap(target)
        if target is None:
            return []
        branches = self.conditional_branches(target)
        if not branches:
            return [target]
        return [
            part
            for branch in branches
            if branch is not None
            for part in self.handed_parts(self.last_statement(branch))
        ]

    def conditional_branches(self, target: Any) -> list[Any] | None:
        """The values a conditional expression may take: if/when/switch branches, a ternary's
        two sides, or a Java switch expression's rule bodies and yields; None otherwise."""
        if self.branching(target):
            return self.branch_bodies(target)
        if target.type == "ternary_expression":
            return [
                _field(target, "consequence") or _field(target, "if_true"),
                _field(target, "alternative") or _field(target, "if_false"),
            ]
        if target.type != "switch_expression" or self.language != "java":
            return None
        branches = []
        for block in (part for part in target.named_children if part.type == "switch_block"):
            for rule in (part for part in block.named_children if part.type == "switch_rule"):
                body = next(
                    (child for child in reversed(rule.named_children) if child.type not in COMMENTS), None
                )
                if body is not None and body.type == "expression_statement" and body.named_children:
                    branches.append(body.named_children[0])  # `case 1 -> m.getBody();`
        for part in _walk(target):
            if part.type == "yield_statement" and part.named_children:
                owner = part.parent
                while owner is not None and owner.type != "switch_expression":
                    owner = owner.parent
                if owner is not None and _same_node(owner, target):
                    branches.append(part.named_children[0])
        return branches

    def value_member(self, name: str) -> bool:
        """A member that reads a value (`length`, `id`), its getter (`getId()`), or a flag
        (`isReady()`, `hasBody()`, `b.isVisible`)."""
        if re.fullmatch(r"(?:is|has|can|should)[A-Z]\w*", name):
            return True
        if name.startswith("get") and name[3:4].isupper():
            name = name[3:4].lower() + name[4:]
        return name in VALUE_MEMBERS

    def literal_argument(self, node: Any) -> bool:
        """An argument that is a literal or a named constant (`"body"`, `0`, `MAIN`, `Keys.BODY`)."""
        target = self.unwrap(node)
        if target is None:
            return False
        if target.type in STRINGS | {
            "integer_literal",
            "number_literal",
            "boolean_literal",
            "decimal_integer_literal",
        }:
            return True
        text = self.text(target).strip()
        return (
            bool(re.fullmatch(r"(?:[A-Za-z_]\w*\.)*[A-Z][A-Z0-9_]*", text))
            and len(text.rsplit(".", 1)[-1]) > 1
        )

    def alias_supplied(self, name: str, expression: Any, frame: Frame) -> None:
        """`val c = b` for a supplied object b: what is written through c is written into b."""
        target = self.unwrap(expression)
        if target is None or target.type not in IDENTIFIERS:
            return
        source = self.symbol_name(self.text(target))
        for effects in reversed(self.closure_effects):
            bound = effects.names.get(source)
            if bound is not None:
                if frame.values.get(source) is bound and name in frame.values:
                    effects.names[name] = frame.values[name]
                return

    def record_effect(
        self,
        target: Any,
        frame: Frame,
        value: Value,
        receiverless: bool = True,
        expressions: tuple[Any, ...] = (),
    ) -> None:
        """Note a value passed to a call on, or written into, a followed closure's supplied object."""
        if not value.traces:
            return
        if target is None:
            if receiverless:
                for effects in reversed(self.closure_effects):
                    if effects.implicit:
                        effects.values.append(value)
                        effects.expressions.extend(expressions)
                        return
            return
        root = self.effect_root(target)
        if root is None:
            return
        name = self.symbol_name(self.text(root))
        for effects in reversed(self.closure_effects):
            bound = effects.names.get(name)
            if bound is not None:
                if frame.values.get(name) is bound:
                    effects.values.append(value)
                    effects.expressions.extend(expressions)
                return

    def closure_parameters(self, node: Any) -> list[tuple[str, str, int]]:
        """Declared closure parameters as (name, declared type, position); `_` binds nothing."""
        found: list[tuple[str, str, int]] = []
        if node.type == "lambda_expression":
            parameters = _field(node, "parameters")
            rows = (
                []
                if parameters is None
                else [parameters]
                if parameters.type == "identifier"
                else [part for part in parameters.named_children if part.type not in COMMENTS]
            )
            for index, row in enumerate(rows):
                name = row if row.type == "identifier" else _field(row, "name")
                declared = _field(row, "type") if row.type != "identifier" else None
                if name is not None:
                    found.append(
                        (self.text(name), self.text(declared) if declared is not None else "", index)
                    )
            return found
        if self.language == "swift":
            signature = next(
                (part for part in node.named_children if part.type == "lambda_function_type"), None
            )
            parameters = next(
                (
                    part
                    for part in (signature.named_children if signature is not None else [])
                    if part.type == "lambda_function_type_parameters"
                ),
                None,
            )
            rows = (
                [part for part in parameters.named_children if part.type == "lambda_parameter"]
                if parameters
                else []
            )
            for index, row in enumerate(rows):
                named = [
                    row.children[i] for i in range(len(row.children)) if row.field_name_for_child(i) == "name"
                ]
                name = next((part for part in named if part.type == "simple_identifier"), None)
                declared = next((part for part in named if part.type != "simple_identifier"), None)
                if name is not None and self.text(name) != "_":
                    found.append(
                        (self.text(name), self.text(declared) if declared is not None else "", index)
                    )
            return found
        parameters = next((part for part in node.named_children if part.type == "lambda_parameters"), None)
        rows = [part for part in parameters.named_children if part.type not in COMMENTS] if parameters else []
        for index, row in enumerate(rows):
            variables = (
                [row]
                if row.type == "variable_declaration"
                else [part for part in row.named_children if part.type == "variable_declaration"]
            )
            for variable in variables:
                name = next((part for part in variable.named_children if part.type in IDENTIFIERS), None)
                declared = next(
                    (
                        part
                        for part in variable.named_children
                        if part.type in {"user_type", "nullable_type", "function_type"}
                    ),
                    None,
                )
                if name is not None and self.text(name) != "_":
                    text = self.text(declared) if declared is not None and row is variable else ""
                    found.append((self.symbol_name(self.text(name)), text, index))
        return found

    def closure_arity(self, node: Any) -> int | None:
        """How many parameters a closure literal declares (`_` included); None when it declares none."""
        if node.type == "lambda_expression":
            parameters = _field(node, "parameters")
            if parameters is None:
                return None
            if parameters.type == "identifier":
                return 1
            return sum(1 for part in parameters.named_children if part.type not in COMMENTS)
        if self.language == "swift":
            signature = next(
                (part for part in node.named_children if part.type == "lambda_function_type"), None
            )
            parameters = next(
                (
                    part
                    for part in (signature.named_children if signature is not None else [])
                    if part.type == "lambda_function_type_parameters"
                ),
                None,
            )
            return (
                sum(1 for part in parameters.named_children if part.type == "lambda_parameter")
                if parameters is not None
                else None
            )
        parameters = next((part for part in node.named_children if part.type == "lambda_parameters"), None)
        return (
            sum(1 for part in parameters.named_children if part.type not in COMMENTS)
            if parameters is not None
            else None
        )

    def closure_result(
        self,
        node: Any,
        frame: Frame,
        returned: list[Value],
        fell_through: bool = True,
        effects: ClosureEffects | None = None,
    ) -> Value:
        """What a followed closure evaluates to: its result expression and the returns that leave it.

        Kotlin returns its last expression, Java an expression body, and Swift the
        expression of a single-expression closure; Swift and Java blocks return
        explicitly, and Kotlin with `return@label`. A body that always exits has no
        last value. The visit already evaluated the last expression's calls: their
        values are reused, never evaluated again. A standard builder's lambda
        (`buildString { }`, `flow { }`) returns Unit: its value is what it wrote, and a
        final statement other than a call on an object or a non-writing function (a
        receiverless call chain that may be a library extension of its receiver,
        `buildString { appendSql(q) }`, `appendHTML().html { }`).
        """
        unit = effects is not None and bool(effects.receiver_types)
        values = [] if unit else list(returned)
        if node.type == "lambda_expression":
            body = _field(node, "body")
            statements = [] if body is None or body.type == "block" else [body]
        elif self.language == "swift":
            block = next((part for part in node.named_children if part.type == "statements"), None)
            statements = [part for part in block.named_children if part.type not in COMMENTS] if block else []
            statements = statements if len(statements) == 1 else []
        else:
            statements = [
                part
                for part in node.named_children
                if part.type not in COMMENTS and part.type not in {"lambda_parameters", "label"}
            ]
        if statements and fell_through:
            reuse = self.reuse_visited
            self.reuse_visited = True
            try:
                last = (
                    self.builder_result(statements[-1], frame)
                    if unit
                    else self.block_result(statements[-1], frame)
                )
            finally:
                self.reuse_visited = reuse
            if last is not None:
                values.append(last)
        if effects is None or not effects.values:
            self.closure_written.pop((node.start_byte, node.end_byte), None)
            self.closure_write_nodes.pop((node.start_byte, node.end_byte), None)
        if effects is not None and effects.values:
            self.closure_written[(node.start_byte, node.end_byte)] = self.distinct_sources(effects.values)
            self.closure_write_nodes[(node.start_byte, node.end_byte)] = tuple(effects.expressions)
            # A write already in the result (`b.child(inner)` ending a nested builder) adds no route.
            seen = {self.source_key(trace) for value in values for trace in value.traces}
            extra = tuple(
                trace
                for trace in self.distinct_sources(effects.values).traces
                if trace_cuts(trace.description) or self.source_key(trace) not in seen
            )
            if extra:
                values.append(Value(extra))
        if len(values) == 1:
            return values[0]
        return _union(values) if values else Value()

    def builder_result(self, node: Any, frame: Frame) -> Value | None:
        """block_result for a standard builder's final statement: a value that is a call on an
        object or a non-writing function (`Log.d(t, q)`, also as a branch of a final if/when)
        is no part of the builder's value."""
        if node is None or node.type in STATEMENT_ONLY or self.declaration(node):
            return None
        if node.type in {"block", "statements", "control_structure_body"}:
            statements = [part for part in node.named_children if part.type not in COMMENTS]
            return self.builder_result(statements[-1], frame) if statements else None
        branches = self.branch_bodies(node)
        if branches is None:
            target = self.unwrap(node)
            for _ in range(MAX_CHAIN):
                navigation = self.navigation(target) if target is not None else None
                if not navigation:
                    break
                target = self.unwrap(navigation[0])  # `Pair(q, 1).first`: the call it reads from
            if target is not None and self.call(target) is not None:
                root = self.chain_root(target)
                if (
                    root is None
                    or root.name in NON_WRITERS
                    or not (root.name[:1].islower() or root.name[:1] == "_")
                ):
                    return None  # also `File(dir, q).delete()`: a constructor's chain
            return self.value(node, frame)
        values = [value for branch in branches if (value := self.builder_result(branch, frame)) is not None]
        return _union(values) if values else None

    def chain_root(self, node: Any) -> Call | None:
        """The receiverless call a call chain starts from (`appendHTML()` in
        `appendHTML().html { }`), or None for a chain on a name or value."""
        call = self.call(node)
        for _ in range(MAX_CHAIN):
            if call is None or call.receiver is None:
                return call
            call = self.call(self.unwrap(call.receiver))
        self.chain_cut(node)
        return None

    def block_result(self, node: Any, frame: Frame) -> Value | None:
        """The value a final statement leaves, or None when it leaves none.

        A declaration, assignment, loop or jump leaves no value, nor does an `if`
        without an else. An if/when/switch/try leaves its branches' values; its
        condition is not part of them.
        """
        if node is None or node.type in STATEMENT_ONLY or self.declaration(node):
            return None
        if node.type in {"block", "statements", "control_structure_body"}:
            statements = [part for part in node.named_children if part.type not in COMMENTS]
            return self.block_result(statements[-1], frame) if statements else None
        branches = self.branch_bodies(node)
        if branches is None:
            return self.value(node, frame)
        values = [value for branch in branches if (value := self.block_result(branch, frame)) is not None]
        return _union(values) if values else None

    def branch_bodies(self, node: Any) -> list[Any] | None:
        """The bodies whose value an if/when/switch/try leaves, or None for another node.

        An `if` without an else leaves none; a condition is never one of them.
        """
        if node.type == "if_statement" and self.language == "swift":
            _, then_node, else_node = self.swift_clauses(node)
            return [then_node, else_node] if else_node is not None else []
        if node.type == "if_expression":
            condition = _field(node, "condition")
            children = [
                child for child in node.named_children if child != condition and child.type not in COMMENTS
            ]
            then_node = _field(node, "consequence") or (children[0] if children else None)
            else_node = _field(node, "alternative") or (children[1] if len(children) > 1 else None)
            return [then_node, else_node] if else_node is not None else []
        if node.type in {"when_expression", "switch_statement"}:
            # A trailing or own-line comment attaches to the entry before it.
            bodies = [
                [part for part in entry.named_children if part.type not in COMMENTS]
                for entry in node.named_children
                if entry.type in {"when_entry", "switch_entry"}
            ]
            return [body[-1] for body in bodies if body]
        if self.branching(node):
            # Kotlin try/catch: the try block and each catch block; Swift's `try` is an operator.
            catches = [
                [child for child in part.named_children if child.type not in COMMENTS]
                for part in node.named_children
                if part.type == "catch_block"
            ]
            return [part for part in node.named_children if part.type == "block"] + [
                body[-1] for body in catches if body
            ]
        return None

    def when_binding(self, node: Any) -> tuple[str, Any, Any] | None:
        """The name, declaration and expression of a Kotlin `when (val u = x)` subject."""
        if node.type != "when_expression" or self.language != "kotlin":
            return None
        subject = next((part for part in node.named_children if part.type == "when_subject"), None)
        if subject is None:
            return None
        variable = next(
            (part for part in subject.named_children if part.type == "variable_declaration"), None
        )
        expression = next(
            (part for part in subject.named_children if part.type not in COMMENTS | {"variable_declaration"}),
            None,
        )
        name = (
            next((part for part in variable.named_children if part.type in IDENTIFIERS), None)
            if variable is not None
            else None
        )
        if name is None or expression is None:
            return None
        return self.symbol_name(self.text(name)), variable, expression

    @staticmethod
    @contextmanager
    def subject_bound(frame: Frame, key: str, value: Value) -> Iterator[None]:
        """Bind a pattern name for a when's entries, then restore what it shadowed."""
        previous, was_local, constant = (
            frame.values.get(key),
            key in frame.local_names,
            frame.constants.get(key),
        )
        frame.values[key] = value
        frame.local_names.add(key)
        frame.constants.pop(key, None)
        try:
            yield
        finally:
            if previous is None:
                frame.values.pop(key, None)
            else:
                frame.values[key] = previous
            if not was_local:
                frame.local_names.discard(key)
            if constant is not None:
                frame.constants[key] = constant

    def mark_value_blocks(self, node: Any) -> None:
        """Note a when's braced entry bodies, whose last statement is the entry's value, and
        the braced branches of a final if/when/try in one (`else -> { val v = ..; if (c)
        { "x/$v" } else HOME }`), which are read with the entry's locals too."""
        pending = [node]
        while pending:
            current = pending.pop()
            for branch in self.branch_bodies(current) or []:
                if branch is None:
                    continue
                last = branch
                if branch.type in BLOCKS:
                    self.value_blocks.add((branch.start_byte, branch.end_byte))
                    last = self.last_statement(branch)
                if last is not None and self.branching(last):
                    pending.append(last)

    def record_branch_leaves(self, node: Any, frame: Frame) -> None:
        """Keep the values of an if/when/try's unbraced branches, read in the enclosing block's frame.

        A braced branch records its own value; a value already recorded (a call, or an
        entry of a `when (val u = ..)` read while u was bound) is kept.
        """
        for branch in self.branch_bodies(node) or []:
            if branch is None or branch.type in BLOCKS:
                continue
            if branch.type == "control_structure_body":
                parts = [part for part in branch.named_children if part.type not in COMMENTS]
                if len(parts) != 1:
                    continue
                branch = parts[0]
            if self.branching(branch):
                self.record_branch_leaves(branch, frame)
                continue
            if branch.type in STATEMENT_ONLY or self.declaration(branch):
                continue
            key = (branch.start_byte, branch.end_byte, branch.type)
            if key not in self.visited_values:
                self.visited_values[key] = self.reused(branch, frame)

    def switch_bindings(self, entry: Any) -> list[tuple[str, tuple]]:
        """Names a Swift switch case binds with `let`/`var`, each with the path to what it binds.

        A path is a sequence of steps from the subject: ("tuple", i) is element i of a tuple
        pattern (`(let a, _)`, `let (a, b)`), ("payload",) an enum case's associated value
        (`.open(let url)`); no step is the value itself (`let x`, `let x?`, `.some(let x)`).
        Enum case names and labels (`url:` in `.open(url: let dest)`) bind nothing.
        """
        found: list[tuple[str, tuple]] = []
        for pattern in (part for part in entry.named_children if part.type == "switch_pattern"):
            for top in (part for part in pattern.named_children if part.type == "pattern"):
                self.pattern_bindings(top, False, (), found)
        return found

    def pattern_bindings(self, node: Any, binding: bool, path: tuple, found: list[tuple[str, tuple]]) -> None:
        binding = binding or any(child.type == "value_binding_pattern" for child in node.named_children)
        children = node.children
        subpatterns = [part for part in node.named_children if part.type == "pattern"]
        dot = next((index for index, child in enumerate(children) if child.type == "."), None)
        if dot is not None:
            case = children[dot + 1] if dot + 1 < len(children) else None
            unwrap = case is not None and self.text(case) == "some" and len(subpatterns) == 1
            for part in subpatterns:
                self.pattern_bindings(part, binding, path if unwrap else (*path, ("payload",)), found)
            return
        if len(subpatterns) > 1:
            for index, part in enumerate(subpatterns):
                self.pattern_bindings(part, binding, (*path, ("tuple", index)), found)
            return
        for index, child in enumerate(children):
            if child.type in IDENTIFIERS and binding:
                following = children[index + 1] if index + 1 < len(children) else None
                if following is None or following.type != ":":
                    found.append((self.text(child), path))
        for part in subpatterns:
            self.pattern_bindings(part, binding, path, found)

    def switch_entry_values(self, entry: Any, frame: Frame) -> dict[str, Value]:
        """What a Swift case binds: the subject (`case let p?`, with its identity and
        fields, as `if let` binds it), an element of a tuple subject, or an enum case's
        associated value (the subject's sources and category and what is stored in its
        payload, without the enum's type or identity)."""
        bindings = self.switch_bindings(entry)
        switch = entry.parent
        subject = next(
            (
                part
                for part in (switch.named_children if switch is not None else [])
                if part.type not in COMMENTS | {"switch_entry"}
            ),
            None,
        )
        if not bindings or subject is None:
            return {}
        whole = self.reused(subject, frame)
        return {name: self.pattern_value(subject, whole, path, frame) for name, path in bindings}

    def pattern_value(self, node: Any, value: Value, path: tuple, frame: Frame) -> Value:
        """The value a pattern path reaches: tuple literal elements by position, then an
        enum case's payload (sources, category and stored payload, no type or identity).

        Only the node the tuple steps reach is evaluated, once: a nested literal's outer
        elements are not, so deep tuple patterns stay linear.
        """
        current: Value | None = value
        for step in path:
            if step[0] == "tuple" and node is not None:
                elements = self.tuple_elements(self.unwrap(node))
                if step[1] < len(elements):
                    node, current = elements[step[1]], None
                    continue
            reached = current if current is not None else self.reused(node, frame)
            if step[0] == "tuple":
                node, current = None, Value(reached.traces, reached.category)
            else:
                stored = (
                    list(frame.object_fields.get(reached.identity, {}).values()) if reached.identity else []
                )
                node, current = None, Value(_union([reached, *stored]).traces, reached.category)
        return current if current is not None else self.reused(node, frame)

    def tuple_elements(self, literal: Any) -> list[Any]:
        """The element expressions of a Swift tuple literal, labeled (`(a: x, b: y)`) or not."""
        if literal is None or literal.type != "tuple_expression":
            return []
        children = literal.children
        return [
            child
            for index, child in enumerate(children)
            if child.is_named
            and child.type not in COMMENTS
            and not (index + 1 < len(children) and children[index + 1].type == ":")
        ]

    @staticmethod
    @contextmanager
    def names_bound(frame: Frame, values: dict[str, Value]) -> Iterator[None]:
        """Bind pattern names for a case's body, then restore what they shadowed."""
        saved = {
            name: (frame.values.get(name), name in frame.local_names, frame.constants.get(name))
            for name in values
        }
        for name, value in values.items():
            frame.values[name] = value
            frame.local_names.add(name)
            frame.constants.pop(name, None)
        try:
            yield
        finally:
            for name, (previous, was_local, constant) in saved.items():
                if previous is None:
                    frame.values.pop(name, None)
                else:
                    frame.values[name] = previous
                if not was_local:
                    frame.local_names.discard(name)
                if constant is not None:
                    frame.constants[name] = constant

    def branching(self, node: Any) -> bool:
        """A statement whose value is the value of one of its branches."""
        if node.type == "try_expression":
            return any(part.type in {"block", "catch_block"} for part in node.named_children)
        return node.type in BRANCHING

    def distinct_sources(self, values: list[Value]) -> Value:
        """One trace per source location: possible inputs, not routes (a cut is always kept)."""
        kept: dict[Any, Trace] = {}
        for value in values:
            for trace in value.traces:
                key = ("cut", trace.origin) if trace_cuts(trace.description) else self.source_key(trace)
                kept.setdefault(key, trace)
        return Value(tuple(kept.values()))

    def closure_return_target(self, node: Any, label: Any) -> tuple[int, int] | None:
        """The followed closure a closure-local return leaves: Swift/Java innermost, Kotlin by label."""
        name = self.text(label).strip("`").rstrip("@ ") if label is not None else ""
        current = node.parent
        for _ in range(64):
            if current is None or current.type in FUNCTIONS:
                return None
            if current.type in CLOSURES:
                span = (current.start_byte, current.end_byte)
                if self.language != "kotlin":
                    return span if span in self.closure_returns else None
                if name and name in self.closure_labels(current):
                    return span if span in self.closure_returns else None
            current = current.parent
        return None

    def closure_labels(self, node: Any) -> set[str]:
        """A Kotlin lambda's return labels: its explicit label, else the name of the call it is passed to."""
        labels = set()
        parent = node.parent
        for _ in range(8):
            if parent is None or parent.type not in {
                "annotated_lambda",
                "labeled_expression",
                "value_argument",
                "value_arguments",
                "parenthesized_expression",
            }:
                break
            labels.update(
                self.text(child).strip().rstrip("@ ").strip("`")
                for child in parent.named_children
                if child.type == "label"
            )
            parent = parent.parent
        if not labels and parent is not None and parent.type == "call_expression":
            call = self.call(parent)
            if call is not None:
                labels.add(call.name.strip("`"))
        return labels

    def visit_scope_lambda(
        self,
        node: Any,
        frame: Frame,
        guards: dict[GuardKey, set[str]],
        conditions: list[Any],
        scope: str,
        receiver: Any,
        optional: bool = False,
        bindings: dict[str, Value] | None = None,
        effects: ClosureEffects | None = None,
    ) -> None:
        """Follow a scope function's lambda once, as a block whose parameter is the receiver.

        With no scope this follows any other closure: `bindings` are its parameters,
        locals that shadow outer names, and `effects` collects what it writes into
        the objects its callee supplies. The closure's result is recorded for value().
        """
        local = frame.copy()
        span = (node.start_byte, node.end_byte)
        if scope:
            local.kotlin_bound_scopes.add(span)
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
            local.local_names.add(name)
            bound = self.reused(receiver, frame) if receiver is not None else Value()
            kind = next(
                (kind for parameter, kind, _ in self.closure_parameters(node) if parameter == name), ""
            )
            local.values[name] = (
                Value(bound.traces, bound.category, kind, bound.identity)
                if kind and kind != bound.type_name
                else bound
            )
            if kind or bound.type_name:
                local.types[name] = kind or bound.type_name
            else:
                local.types.pop(name, None)
            local.constants.pop(name, None)
            if receiver is not None:
                self.aliases[name] = receiver
                if self.closure_effects:
                    # `b.let { it.append(q) }` writes into the supplied b.
                    self.alias_supplied(name, receiver, local)
        elif scope in {"run", "apply", "with"} and receiver is not None:
            # Receiver-style scopes introduce a lexical this. Keep it in the
            # copied frame so nested scopes restore their enclosing receiver,
            # and a non-local return sees the scope value, not the class object.
            declared.add("this")
            bound = self.reused(receiver, frame)
            # A value of its own: a scope inside a builder that rebinds `this` to the object of
            # an enclosing `with` is still a rebinding (`with(sb) { buildString { sb.apply { } } }`).
            local.values["this"] = Value(bound.traces, bound.category, bound.type_name, bound.identity)
            # An unqualified member call in this lambda targets the scope receiver.
            self.aliases["this"] = receiver
        for name, value in (bindings or {}).items():
            declared.add(name)
            local.local_names.add(name)
            local.values[name] = value
            if value.type_name:
                local.types[name] = value.type_name
            local.constants.pop(name, None)
            self.aliases.pop(name, None)
        local_guards = {origin: checks.copy() for origin, checks in guards.items()}
        local_conditions = [*conditions, node]
        outer_returns = self.closure_returns.get(span)
        self.closure_returns[span] = []
        self.closure_depth += 1
        if effects is not None:
            self.closure_effects.append(effects)
        from .native_guards import exits

        try:
            exited = False
            for child in node.named_children:
                if child is parameters or child.type in {"lambda_function_type", "capture_list"}:
                    continue
                parsed = self.declaration(child)
                if parsed:
                    declared.add(parsed[0])
                self.visit(child, local, local_guards, local_conditions)
                if exits(self, child):
                    exited = True
                    break  # A Kotlin lambda body is a statement list: what follows is dead.
            if scope in {"", "let", "run", "with", "use"}:
                # also/apply evaluate to their receiver, which their call value already carries.
                self.active_guards = local_guards
                if self.native_flow is not None:
                    self.native_flow.active_guards = local_guards
                    self.native_flow.active_conditions = local_conditions
                self.closure_values[span] = self.closure_result(
                    node, local, self.closure_returns[span], not exited, effects
                )
        finally:
            if effects is not None:
                self.closure_effects.pop()
            self.closure_depth -= 1
            self.closure_returns.pop(span, None)
            if outer_returns is not None:
                self.closure_returns[span] = outer_returns
            # Guards established inside the closure apply only within it.
            self.active_guards = guards
            if self.native_flow is not None:
                self.native_flow.active_guards = guards
                self.native_flow.active_conditions = conditions
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
                    # A field the lambda left alone keeps its value (the join would rebuild it, as
                    # for a branch); only what it wrote is joined, so one lambda among thousands
                    # of fields stays linear.
                    key: previous[key]
                    if key in previous
                    and key in written
                    and previous[key] is written[key]
                    and len(previous[key].traces) <= 8
                    else _union(
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
            # A Kotlin default value is a sibling of its parameter, not another parameter.
            [node for node in parameters.named_children if node.type in {"parameter", "class_parameter"}]
            if parameters and self.language == "kotlin"
            else parameters.named_children
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
                            "optional_type",
                            "parenthesized_type",
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
        self.closure_returns = {}
        self.visited_values = {}
        self.format_argument_offsets = {}
        self.reuse_visited = False
        self.evaluated_inputs = None
        self.closure_effects = []
        self.assigned_values = {}
        self.closure_written = {}
        self.closure_write_nodes = {}
        self.implicit_formats = {}
        self.string_builder_results = set()
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
        self.string_constants.clear()
        self.string_members.clear()
        self.string_functions.clear()
        for node in nodes:
            if node.type in {"function_declaration", "method_declaration"} and self.string_function_header(
                node
            ):
                name = _field(node, "name") or next(
                    (part for part in node.named_children if part.type in IDENTIFIERS), None
                )
                if name is not None:
                    self.string_functions.add(self.symbol_name(self.text(name)))
            if node.type in {"field_declaration", "constant_declaration"}:
                # Java fields, also an interface's constants (`interface Urls { String SEARCH = .. }`).
                items = [part for part in node.named_children if part.type == "variable_declarator"]
            elif (
                node.type == "property_declaration"
                and node.parent is not None
                and node.parent.type
                in {
                    "class_body",
                    "source_file",
                    "enum_class_body",
                }
            ):
                items = [node]
            else:
                continue
            for item in items:
                declared = self.declaration(item)
                if declared and (
                    declared[2].rstrip("?") in {"String", "CharSequence"}
                    or declared[1] is not None
                    and self.string_initializer(declared[1])
                ):
                    self.string_constants.add(declared[0])
                    self.string_members.add((self.member_owner(node), declared[0]))
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
