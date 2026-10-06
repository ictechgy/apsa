from __future__ import annotations

import importlib
import textwrap

import pytest

from mobile_audit import source_analysis
from mobile_audit.source_analysis import analyze_sources


def scan(suffix: str, text: str) -> dict:
    return analyze_sources([{"path": f"app/LinkHandler.{suffix}", "text": textwrap.dedent(text).strip()}])


def rules(report: dict) -> set[str]:
    return {item["rule_id"] for item in report["findings"]}


URL_RULE = "AST-WEBVIEW-UNTRUSTED-URL"
HOST_RULE = "AST-WEBVIEW-HOST-ALLOWLIST"
SSL_RULE = "AST-WEBVIEW-SSL-BYPASS"
BRIDGE_RULE = "AST-WEBVIEW-JS-BRIDGE"


@pytest.mark.parametrize(
    ("suffix", "source", "function", "source_line", "sink_line"),
    [
        (
            "java",
            """
            class LinkHandler extends Activity {
                private WebView browser;
                void onNewIntent(Intent incoming) {
                    String destination = incoming.getStringExtra("destination");
                    String alias = destination;
                    browser.loadUrl(alias);
                }
            }
            """,
            "onNewIntent",
            4,
            6,
        ),
        (
            "kt",
            """
            class LinkHandler : AppCompatActivity() {
                private lateinit var browser: WebView
                override fun onCreate(state: Bundle?) {
                    val incoming = intent.data
                    val destination = incoming?.getQueryParameter("destination")
                    browser.loadUrl(destination!!)
                }
            }
            """,
            "onCreate",
            5,
            6,
        ),
        (
            "swift",
            """
            class LinkHandler: UIViewController {
                private var browser: WKWebView!
                func application(_ app: UIApplication, open incoming: URL, options: [String: Any]) -> Bool {
                    let components = URLComponents(url: incoming, resolvingAgainstBaseURL: false)
                    let destination = components?.queryItems?.first?.value
                    browser.load(URLRequest(url: URL(string: destination!)!))
                    return true
                }
            }
            """,
            "application",
            5,
            6,
        ),
    ],
)
def test_platform_input_alias_reaches_typed_webview(suffix, source, function, source_line, sink_line):
    report = scan(suffix, source)
    assert report["warnings"] == []
    assert rules(report) == {URL_RULE}
    item = report["findings"][0]
    evidence = item["evidence"][0]
    assert item["status"] == "candidate"
    assert item["confidence"] == "structural"
    assert evidence["function"] == function
    assert evidence["line"] == sink_line
    assert evidence["sources"][0]["line"] == source_line
    assert evidence["path"] == f"app/LinkHandler.{suffix}"
    assert evidence["flow"]
    assert "interprocedural" in item["analysis_limits"]


@pytest.mark.parametrize(
    ("suffix", "source"),
    [
        (
            "java",
            """
            class LinkHandler {
                private WebView browser;
                void open(Intent incoming) {
                    String destination = incoming.getStringExtra("destination");
                    Uri parsed = Uri.parse(destination);
                    if ("https".equals(parsed.getScheme()) && "docs.example.test".equals(parsed.getHost())) {
                        browser.loadUrl(destination);
                    }
                }
            }
            """,
        ),
        (
            "kt",
            """
            class LinkHandler {
                private val browser = WebView(context)
                fun open(incoming: Intent) {
                    val destination = incoming.getStringExtra("destination")
                    val parsed = Uri.parse(destination)
                    if (parsed.scheme == "https" && parsed.host == "docs.example.test") {
                        browser.loadUrl(destination)
                    }
                }
            }
            """,
        ),
        (
            "swift",
            """
            class LinkHandler {
                private let browser = WKWebView()
                func application(_ app: UIApplication, open incoming: URL, options: [String: Any]) -> Bool {
                    guard incoming.scheme == "https", incoming.host == "docs.example.test" else { return false }
                    browser.load(URLRequest(url: incoming))
                    return true
                }
            }
            """,
        ),
    ],
)
def test_fixed_exact_scheme_and_host_guard_is_recognized(suffix, source):
    report = scan(suffix, source)
    assert report["warnings"] == []
    assert report["findings"] == []
    assert report["coverage"][0]["state"] == "checked"


@pytest.mark.parametrize(
    "method,literal,expected",
    [
        ("startsWith", "docs.example.test", True),
        ("contains", "docs.example.test", True),
        ("endsWith", "docs.example.test", True),
        ("endsWith", ".docs.example.test", False),
    ],
)
def test_host_allowlist_pair_respects_subdomain_boundary(method, literal, expected):
    report = scan(
        "java",
        f"""
        class LinkHandler {{
            WebView browser;
            void open(Intent incoming) {{
                Uri uri = incoming.getData();
                if (uri.getScheme().equals("https") && uri.getHost().{method}("{literal}")) {{
                    browser.loadUrl(uri.toString());
                }}
            }}
        }}
    """,
    )
    assert report["warnings"] == []
    assert (HOST_RULE in rules(report)) == expected
    assert (URL_RULE in rules(report)) == expected
    if expected:
        evidence = next(item for item in report["findings"] if item["rule_id"] == HOST_RULE)["evidence"][0]
        assert evidence["allowlist_operation"] == method
        assert evidence["load_location"]["line"] == 6


@pytest.mark.parametrize(
    "suffix,source",
    [
        (
            "kt",
            """
        class LinkHandler {
            lateinit var browser: WebView
            fun open(incoming: Intent) {
                val destination = incoming.getStringExtra("destination")
                if (destination?.startsWith("https://docs.example.test") == true) {
                    browser.loadUrl(destination)
                }
            }
        }
    """,
        ),
        (
            "swift",
            """
        class LinkHandler {
            var browser: WKWebView!
            func application(_ app: UIApplication, open incoming: URL, options: [String: Any]) -> Bool {
                if incoming.host!.hasPrefix("docs.example.test") {
                    browser.load(URLRequest(url: incoming))
                }
                return true
            }
        }
    """,
        ),
    ],
)
def test_partial_host_allowlists_are_scoped_to_a_load(suffix, source):
    report = scan(suffix, source)
    assert rules(report) == {URL_RULE, HOST_RULE}


@pytest.mark.parametrize("proceed,expected", [(True, True), (False, False)])
@pytest.mark.parametrize("suffix", ["java", "kt"])
def test_ssl_callback_pair_requires_typed_handler(suffix, proceed, expected):
    action = "proceed" if proceed else "cancel"
    if suffix == "java":
        source = f"""
            class Client extends WebViewClient {{
                public void onReceivedSslError(WebView view, SslErrorHandler handler, SslError error) {{
                    handler.{action}();
                }}
                void unrelated() {{ workflow.proceed(); }}
            }}
        """
    else:
        source = f"""
            class Client : WebViewClient() {{
                override fun onReceivedSslError(view: WebView, handler: SslErrorHandler, error: SslError) {{
                    handler.{action}()
                }}
                fun unrelated() {{ workflow.proceed() }}
            }}
        """
    report = scan(suffix, source)
    assert (SSL_RULE in rules(report)) == expected
    assert not (rules(report) - {SSL_RULE})


@pytest.mark.parametrize("remove,expected", [(False, True), (True, False)])
def test_bridge_exposure_pair_matches_receiver_and_removal(remove, expected):
    removal = 'browser.removeJavascriptInterface("native");' if remove else ""
    report = scan(
        "java",
        f"""
        class LinkHandler {{
            WebView browser;
            WebView otherBrowser;
            void open(Intent incoming) {{
                browser.getSettings().setJavaScriptEnabled(true);
                browser.addJavascriptInterface(new Bridge(), "native");
                {removal}
                String destination = incoming.getStringExtra("destination");
                browser.loadUrl(destination);
            }}
            void unrelated(Intent incoming) {{
                browser.addJavascriptInterface(new Bridge(), "native");
                otherBrowser.loadUrl(incoming.getStringExtra("destination"));
            }}
        }}
    """,
    )
    assert URL_RULE in rules(report)
    bridge = [item for item in report["findings"] if item["rule_id"] == BRIDGE_RULE]
    assert len(bridge) == int(expected)
    if expected:
        assert bridge[0]["evidence"][0]["javascript_enabled"] == "true"
        assert bridge[0]["evidence"][0]["function"] == "open"


def test_javascript_evaluation_is_not_sanitized_by_url_host_checks():
    report = scan(
        "kt",
        """
        class LinkHandler {
            lateinit var browser: WebView
            fun open(incoming: Intent) {
                val payload = incoming.getStringExtra("javascript")
                val parsed = Uri.parse(payload)
                if (parsed.scheme == "https" && parsed.host == "docs.example.test") {
                    browser.evaluateJavascript(payload, null)
                }
            }
        }
    """,
    )
    assert rules(report) == {URL_RULE}
    assert report["findings"][0]["evidence"][0]["payload"] == "javascript"


def test_comments_literals_unrelated_types_and_cross_function_hints_are_ignored():
    report = scan(
        "java",
        """
        class LinkHandler {
            WebView browser;
            OtherClient client;
            void obtain(Intent incoming) { String destination = incoming.getStringExtra("destination"); }
            void loadTrusted() { browser.loadUrl("https://docs.example.test"); }
            void nonWebView(Intent incoming) { client.loadUrl(incoming.getStringExtra("destination")); }
            void log() {
                // browser.loadUrl(getIntent().getDataString());
                String documentation = "browser.loadUrl(getIntent().getDataString())";
                boolean prefix = documentation.startsWith("docs.example.test");
            }
            void onReceivedSslError(Object handler) { handler.proceed(); }
        }
    """,
    )
    assert report["warnings"] == []
    assert report["findings"] == []


def test_guard_for_outer_link_does_not_sanitize_a_nested_destination():
    report = scan(
        "java",
        """
        class LinkHandler {
            WebView browser;
            void open(Intent incoming) {
                Uri outer = incoming.getData();
                if (outer.getScheme().equals("https") && outer.getHost().equals("docs.example.test")) {
                    String destination = outer.getQueryParameter("destination");
                    browser.loadUrl(destination);
                }
            }
        }
    """,
    )
    assert rules(report) == {URL_RULE}
    assert report["findings"][0]["evidence"][0]["sources"][0]["kind"] == "URL query parameter"


@pytest.mark.parametrize(
    "condition",
    [
        'uri.getScheme().equals("https") || uri.getHost().equals("docs.example.test")',
        '!uri.getScheme().equals("https") && !uri.getHost().equals("docs.example.test")',
        'uri.getHost().equals("docs.example.test")',
    ],
)
def test_incomplete_or_negated_checks_do_not_suppress_candidate(condition):
    report = scan(
        "java",
        f"""
        class LinkHandler {{
            WebView browser;
            void open(Intent incoming) {{
                Uri uri = incoming.getData();
                if ({condition}) {{ browser.loadUrl(uri.toString()); }}
            }}
        }}
    """,
    )
    assert rules(report) == {URL_RULE}


def test_safe_branch_does_not_guard_else_or_later_sink():
    report = scan(
        "java",
        """
        class LinkHandler {
            WebView browser;
            void open(Intent incoming) {
                Uri uri = incoming.getData();
                if (uri.getScheme().equals("https") && uri.getHost().equals("docs.example.test")) {
                    browser.loadUrl(uri.toString());
                } else {
                    browser.loadUrl(uri.toString());
                }
                browser.loadUrl(uri.toString());
            }
        }
    """,
    )
    assert rules(report) == {URL_RULE}
    assert {item["evidence"][0]["line"] for item in report["findings"]} == {8, 10}


def test_constant_reassignment_and_local_shadowing_remove_irrelevant_flow():
    report = scan(
        "java",
        """
        class LinkHandler {
            WebView browser;
            void open(Intent incoming) {
                String destination = incoming.getStringExtra("destination");
                destination = "https://docs.example.test";
                browser.loadUrl(destination);
                { String destination2 = incoming.getStringExtra("destination"); }
                String destination2 = "https://docs.example.test";
                browser.loadUrl(destination2);
            }
        }
    """,
    )
    assert report["findings"] == []


def test_unrecognized_sanitizer_keeps_provenance_and_candid_limit():
    report = scan(
        "java",
        """
        class LinkHandler {
            WebView browser;
            void open(Intent incoming) {
                String destination = validateDestination(incoming.getStringExtra("destination"));
                browser.loadUrl(destination);
            }
        }
    """,
    )
    assert rules(report) == {URL_RULE}
    assert report["findings"][0]["evidence"][0]["validation"]["unknown_calls_are_sanitizers"] is False


def test_unsupported_missing_and_malformed_parsers_are_reported(monkeypatch):
    real_import = importlib.import_module

    def unavailable(name):
        if name == "tree_sitter_kotlin":
            raise ImportError("grammar missing")
        return real_import(name)

    monkeypatch.setattr(source_analysis.importlib, "import_module", unavailable)
    report = analyze_sources(
        [
            ("A.kt", "fun open() {}"),
            ("A.swift", "class A { let browser = WKWebView(); func broken( { browser.load("),
            ("A.m", "[browser loadRequest:request];"),
            ("A.java", "class A { void open() {} }"),
        ]
    )
    assert report["findings"] == []
    assert any("grammar unavailable for kotlin" in warning for warning in report["warnings"])
    assert any("syntax recovery" in warning for warning in report["warnings"])
    assert any(".m" in warning for warning in report["warnings"])
    assert report["coverage"][0]["state"] == "partial"


def test_parser_byte_budget_skips_file_without_network(monkeypatch):
    monkeypatch.setattr(source_analysis, "MAX_AST_BYTES", 30)
    monkeypatch.setattr(
        source_analysis.importlib,
        "import_module",
        lambda _: pytest.fail("parser imported for oversized input"),
    )
    report = scan("java", "class A { void open() { String destination = getIntent().getDataString(); } }")
    assert report["findings"] == []
    assert report["coverage"][0]["state"] == "not-run"
    assert any("byte budget" in warning for warning in report["warnings"])


def test_source_record_tuple_contract_and_stable_location_identity():
    source = "class A { WebView browser; void open(Intent i) { browser.loadUrl(i.getDataString()); } }"
    tuple_result = analyze_sources([("A.java", source)])
    record_result = analyze_sources([{"path": "A.java", "text": source}])
    assert tuple_result == record_result
    assert tuple_result["findings"]
    assert len({item["id"] for item in tuple_result["findings"]}) == len(tuple_result["findings"])


@pytest.mark.parametrize(
    "mutation",
    [
        'uri.toString() + ".attacker.test"',
        "rewriteHost(uri.toString())",
    ],
)
def test_guard_does_not_trust_a_later_string_transformation(mutation):
    report = scan(
        "java",
        f"""
        class LinkHandler {{
            WebView browser;
            void open(Intent incoming) {{
                Uri uri = incoming.getData();
                if (uri.getScheme().equals("https") && uri.getHost().equals("docs.example.test")) {{
                    browser.loadUrl({mutation});
                }}
            }}
        }}
    """,
    )
    assert rules(report) == {URL_RULE}


def test_branch_keeps_platform_parameter_provenance_and_unsafe_assignment():
    report = scan(
        "java",
        """
        class LinkHandler {
            WebView browser;
            void open(Intent incoming, boolean alternate) {
                if (alternate) { logger.debug("alternate"); }
                String destination = "https://docs.example.test";
                if (alternate) { destination = incoming.getStringExtra("destination"); }
                browser.loadUrl(destination);
            }
        }
    """,
    )
    assert rules(report) == {URL_RULE}
    assert report["findings"][0]["evidence"][0]["sources"][0]["kind"] == "Intent string extra"


def test_node_budget_and_invalid_record_do_not_look_like_a_clean_scan(monkeypatch):
    monkeypatch.setattr(source_analysis, "MAX_AST_NODES", 4)
    report = analyze_sources([{}, ("broken",), ("A.java", "class A { void open() {} }")])
    assert report["findings"] == []
    assert report["coverage"][0]["state"] == "not-run"
    assert report["coverage"][0]["skipped_files"] == 3
    assert any("node budget" in warning for warning in report["warnings"])


@pytest.mark.parametrize(
    "suffix,source",
    [
        (
            "java",
            """
        class Client extends WebViewClient {
            public boolean shouldOverrideUrlLoading(WebView view, String url) {
                if (url.startsWith("https://docs.example.test")) { return false; }
                return true;
            }
        }
    """,
        ),
        (
            "kt",
            """
        class Client : WebViewClient() {
            override fun shouldOverrideUrlLoading(view: WebView, request: WebResourceRequest): Boolean {
                if (request.url.host!!.contains("docs.example.test")) { return false }
                return true
            }
        }
    """,
        ),
        (
            "swift",
            """
        class Client {
            func webView(_ view: WKWebView, decidePolicyFor navigation: WKNavigationAction,
                         decision: @escaping (WKNavigationActionPolicy) -> Void) {
                if navigation.request.url!.host!.hasPrefix("docs.example.test") {
                    decision(.allow)
                } else { decision(.cancel) }
            }
        }
    """,
        ),
    ],
)
def test_allowlist_in_explicit_navigation_policy_allow_branch(suffix, source):
    report = scan(suffix, source)
    assert report["warnings"] == []
    assert rules(report) == {HOST_RULE}
    assert report["findings"][0]["evidence"][0]["sink"] == "WebView navigation policy allow decision"


def test_irrelevant_partial_string_check_in_navigation_callback_is_not_a_policy():
    report = scan(
        "java",
        """
        class Client extends WebViewClient {
            public boolean shouldOverrideUrlLoading(WebView view, String url) {
                if (url.startsWith("https://docs.example.test")) { logger.debug("seen"); }
                return true;
            }
        }
    """,
    )
    assert report["findings"] == []


def test_distinct_same_line_sinks_keep_distinct_findings():
    source = "class A { WebView browser; void open(Intent i) { String url = i.getDataString(); browser.loadUrl(url); browser.loadUrl(url); } }"
    report = scan("java", source)
    assert len(report["findings"]) == 2
    assert len({item["id"] for item in report["findings"]}) == 2
    assert len({item["evidence"][0]["offset"] for item in report["findings"]}) == 2


def test_nested_swift_local_shadow_does_not_clear_outer_source():
    report = scan(
        "swift",
        """
        class LinkHandler {
            let browser = WKWebView()
            func application(_ app: UIApplication, open incoming: URL, options: [String: Any]) -> Bool {
                let destination = incoming
                do {
                    let destination = URL(string: "https://docs.example.test")!
                    browser.load(URLRequest(url: destination))
                }
                browser.load(URLRequest(url: destination))
                return true
            }
        }
    """,
    )
    assert rules(report) == {URL_RULE}
    assert len(report["findings"]) == 1
    assert report["findings"][0]["evidence"][0]["line"] == 9


@pytest.mark.parametrize("expression", ["destination", "destination!!"])
def test_kotlin_nonnull_assertion_preserves_guarded_destination(expression):
    report = scan(
        "kt",
        f"""
        class LinkHandler {{
            lateinit var browser: WebView
            fun open(incoming: Intent) {{
                val destination = incoming.getStringExtra("destination")
                val parsed = Uri.parse(destination)
                if (parsed.scheme == "https" && parsed.host == "docs.example.test") {{
                    browser.loadUrl({expression})
                }}
            }}
        }}
    """,
    )
    assert report["warnings"] == []
    assert report["findings"] == []
