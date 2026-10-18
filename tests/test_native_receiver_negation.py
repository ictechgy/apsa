"""Negated receiver guards must not manufacture safety.

Complete-context engine cases copy public r1 source templates into new strings;
no corpus labels, denominators or retained legacy bytes are changed. Swift path
cases below test parser/head-chain polarity only, not full Swift path support.
"""

from __future__ import annotations

import importlib

import pytest

from mobile_audit import native_guards
from mobile_audit.source_analysis import Analyzer, analyze_sources

URL_RULE = "AST-WEBVIEW-UNTRUSTED-URL"
PATH_RULE = "AST-PATH-TRAVERSAL"

KOTLIN_URL = 'import android.content.Intent\nimport android.net.Uri\nimport android.webkit.WebView\nopen class OwnedBase\nclass Intake : OwnedBase() {\n    lateinit var reader: WebView\n    fun onCreate(intent: Intent) {\n        val link = intent.data\n        val destination = link?.getQueryParameter("destination")\n        val parsed = Uri.parse(destination)\n        if (parsed.scheme == "https" && parsed.host == "guide.example.test") {\n            reader.loadUrl(destination!!)\n        }\n    }\n}\n'
SWIFT_URL = 'import class UIKit.UIApplication\nimport class WebKit.WKWebView\nimport struct Foundation.URLRequest\nimport struct Foundation.URL\nclass OwnedBase {}\nclass Intake: OwnedBase {\n    let reader: WKWebView\n    init(reader: WKWebView) { self.reader = reader }\n    @MainActor func application(_ app: UIApplication, open link: URL, options: [String: Any]) -> Bool {\n        guard link.scheme == "https", link.host == "guide.example.test" else { return false }\n        reader.load(URLRequest(url: link))\n        return true\n    }\n}\n'
KOTLIN_PATH = 'import android.content.Intent\nimport java.io.File\nimport java.io.FileOutputStream\nclass Saver {\n fun save(intent: Intent, base: File) {\n  val name = intent.getStringExtra("name")!!\n  val target = File(base, name)\n  \n  FileOutputStream(target.getCanonicalPath())\n }\n}\n'


def assert_engine(text, language, rule, *, unsafe):
    suffix = "kt" if language == "kotlin" else "swift"
    report = analyze_sources([("app/Entry." + suffix, text)])
    matches = [item for item in report["findings"] if item["rule_id"] == rule]
    assert bool(matches) is unsafe, report
    assert all(item["status"] == "candidate" for item in matches)
    assert report["metadata"]["native_flow"]["state"] == "checked", report
    assert report["metadata"]["native_flow"]["reasons"] == [], report
    assert report["warnings"] == [], report
    assert next(row["state"] for row in report["coverage"] if row["rule_id"] == rule) == "checked"


@pytest.mark.parametrize("form", ["if", "else-exit"])
@pytest.mark.parametrize("predicate", ["host-equals", "scheme-equals", "host-suffix", "host-force-equals"])
@pytest.mark.parametrize("polarity", ["positive", "receiver-negated", "true-unary"])
def test_kotlin_url_receiver_negation_cannot_supply_allowlist(form, predicate, polarity):
    expressions = {
        "host-equals": 'parsed.host.equals("guide.example.test")',
        "host-force-equals": 'parsed.host!!.equals("guide.example.test")',
        "scheme-equals": 'parsed.scheme.equals("https")',
        "host-suffix": 'parsed.host.endsWith(".example.test")',
    }
    expression = expressions[predicate]
    condition = (
        expression
        if polarity == "positive"
        else "!" + expression
        if polarity == "receiver-negated"
        else "!(" + expression + ")"
    )
    other = (
        'parsed.host == "guide.example.test"' if predicate == "scheme-equals" else 'parsed.scheme == "https"'
    )
    condition = other + " && " + condition
    old = 'if (parsed.scheme == "https" && parsed.host == "guide.example.test") {\n            reader.loadUrl(destination!!)\n        }'
    replacement = (
        "if (" + condition + ") {\n            reader.loadUrl(destination!!)\n        }"
        if form == "if"
        else "if (" + condition + ") { } else return\n        reader.loadUrl(destination!!)"
    )
    assert old in KOTLIN_URL
    assert_engine(KOTLIN_URL.replace(old, replacement), "kotlin", URL_RULE, unsafe=polarity != "positive")


@pytest.mark.parametrize("form", ["guard", "if", "else-exit"])
@pytest.mark.parametrize("polarity", ["positive", "receiver-negated", "true-unary"])
def test_swift_url_force_unwrap_receiver_negation_cannot_supply_host(form, polarity):
    expression = 'link.host!.hasSuffix(".example.test")'
    host = (
        expression
        if polarity == "positive"
        else "!" + expression
        if polarity == "receiver-negated"
        else "!(" + expression + ")"
    )
    old = 'guard link.scheme == "https", link.host == "guide.example.test" else { return false }\n        reader.load(URLRequest(url: link))'
    if form == "guard":
        # Preserve the actually supported comma-separated Swift conditions.
        replacement = (
            'guard link.scheme == "https", '
            + host
            + " else { return false }\n        reader.load(URLRequest(url: link))"
        )
    else:
        replacement = 'guard link.scheme == "https" else { return false }\n        '
        replacement += (
            "if " + host + " { reader.load(URLRequest(url: link)) }"
            if form == "if"
            else "if " + host + " { } else { return false }\n        reader.load(URLRequest(url: link))"
        )
    assert old in SWIFT_URL
    assert_engine(SWIFT_URL.replace(old, replacement), "swift", URL_RULE, unsafe=polarity != "positive")


@pytest.mark.parametrize(
    "guard,unsafe",
    [
        ("", True),
        ("if (PREDICATE) { } else return", False),
        ("if (!PREDICATE) { } else return", True),
        ("if (!PREDICATE) return", False),
        ("if (!(PREDICATE)) return", False),
    ],
    ids=[
        "unguarded",
        "positive-else-exit",
        "negative-else-exit",
        "receiver-early-reject",
        "true-unary-reject",
    ],
)
def test_kotlin_call_chain_containment_respects_guard_polarity(guard, unsafe):
    predicate = "target.getCanonicalPath().startsWith(base.canonicalPath + File.separator)"
    # The original construction remains, and the final FileOutputStream is a
    # real modeled file sink. A later false guard must not delete either trace.
    insertion = guard.replace("PREDICATE", predicate)
    text = KOTLIN_PATH.replace("  \n  FileOutputStream", "  " + insertion + "\n  FileOutputStream")
    assert (not insertion) or insertion in text
    assert_engine(text, "kotlin", PATH_RULE, unsafe=unsafe)


@pytest.mark.parametrize("language", ["kotlin", "swift"])
@pytest.mark.parametrize(
    "expression,expected",
    [
        ("target.path", False),
        ("!target.path", True),
        ("!target.call().path", True),
        ("target.call(!flag).path", False),
        ("target.call(flag && !other).path", False),
        ("!flag && target.call().path", False),
        ("flag || !target.call().path", False),
        ("!(!target.path)", False),
    ],
)
def test_receiver_helper_only_follows_expression_head(language, expression, expected):
    # Parser-only scope: these expressions test the head-chain contract. They
    # do not assert SDK typing, application semantics or full Swift path flow.
    import tree_sitter

    grammar = importlib.import_module("tree_sitter_" + language)
    parser = tree_sitter.Parser(tree_sitter.Language(grammar.language()))
    source = (
        "fun probe() { val result = " + expression + " }"
        if language == "kotlin"
        else "func probe() { let result = " + expression + " }"
    )
    raw = source.encode()
    tree = parser.parse(raw)
    assert not tree.root_node.has_error

    def walk(node):
        yield node
        for child in node.named_children:
            yield from walk(child)

    node = next(
        node for node in walk(tree.root_node) if raw[node.start_byte : node.end_byte].decode() == expression
    )
    analyzer = Analyzer("Probe." + ("kt" if language == "kotlin" else "swift"), source, language)
    assert native_guards.receiver_negated(analyzer, node) is expected


def test_receiver_helper_swift_canonical_call_chain_is_parser_only():
    # Complete Swift path fixtures currently have separate unresolved alias/call
    # reasons. This regression deliberately claims only actual parser polarity.
    import tree_sitter
    import tree_sitter_swift

    expression = '!target.resolvingSymlinksInPath().path.hasPrefix("/owned/")'
    source = "func probe() { let result = " + expression + " }"
    raw = source.encode()
    parser = tree_sitter.Parser(tree_sitter.Language(tree_sitter_swift.language()))
    tree = parser.parse(raw)
    assert not tree.root_node.has_error

    def walk(node):
        yield node
        for child in node.named_children:
            yield from walk(child)

    node = next(
        node for node in walk(tree.root_node) if raw[node.start_byte : node.end_byte].decode() == expression
    )
    analyzer = Analyzer("Probe.swift", source, "swift")
    call = analyzer.call(node)
    assert call is not None and call.name == "hasPrefix"
    assert native_guards.receiver_negated(analyzer, call.receiver) is True
