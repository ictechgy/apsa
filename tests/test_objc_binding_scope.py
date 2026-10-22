"""API identity follows lexical bindings in newly generated Objective-C source."""

from __future__ import annotations

import pytest

from mobile_audit.source_analysis import analyze_sources

CRYPTO_IMPORT = "#import <CommonCrypto/CommonDigest.h>\n"
CRYPTO_RULE = "OBJC-CRYPTO-WEAK-HASH"
WEB_RULE = "OBJC-WEBVIEW-UNTRUSTED-REQUEST"
CALL = "CC_MD5(bytes, length, output);"
DIGEST = f"void digest(const void *bytes, CC_LONG length, unsigned char *output) {{ {CALL} }}\n"
WEB = """#import <WebKit/WebKit.h>
@implementation Handler
- (void)webView:(WKWebView *)webView decidePolicyForNavigationAction:(WKNavigationAction *)action {
    NSURL *url = action.request.URL;
    NSURLRequest *request = [NSURLRequest requestWithURL:url];
    [webView loadRequest:request];
}
@end
"""


def evidence(source, rule):
    report = analyze_sources([("Synthetic.m", source)])
    assert not report["metadata"]["files"][0]["parse_errors"]
    return [
        item for finding in report["findings"] if finding["rule_id"] == rule for item in finding["evidence"]
    ]


@pytest.mark.parametrize("name", ["CC_MD5", "CC_SHA1"])
@pytest.mark.parametrize(
    "unrelated",
    [
        "void unrelated(int NAME) {}\n",
        "void unrelated(NAME) int NAME; {}\n",
        "void unrelated(void) { int NAME = 1; }\n",
        "void unrelated(void) { typedef int NAME; }\n",
        "void unrelated(int NAME);\n",
        "@implementation Other\n- (void)unrelated:(int)NAME {}\n@end\n",
        "@implementation Other\n- (void)unrelated { int NAME = 1; }\n@end\n",
    ],
)
@pytest.mark.parametrize("before", [False, True])
def test_unrelated_crypto_bindings_do_not_hide_platform_calls(name, unrelated, before):
    digest = DIGEST.replace("CC_MD5", name)
    unrelated = unrelated.replace("NAME", name)
    source = CRYPTO_IMPORT + (unrelated + digest if before else digest + unrelated)
    matches = evidence(source, CRYPTO_RULE)
    assert len(matches) == 1
    assert matches[0]["offset"] == source.index(f"{name}(bytes")


@pytest.mark.parametrize(
    "declaration",
    [
        "int CC_MD5;",
        "void (*CC_MD5)(const void *, CC_LONG, unsigned char *);",
        "void CC_MD5(void) {}",
        "#define CC_MD5(...) other_digest(__VA_ARGS__)",
        "void unrelated(void) {\n#define CC_MD5 other_digest\n}",
    ],
)
def test_global_declarations_and_macros_still_block_crypto_identity(declaration):
    assert not evidence(CRYPTO_IMPORT + declaration + "\n" + DIGEST, CRYPTO_RULE)


@pytest.mark.parametrize(
    "function",
    [
        f"void digest(int CC_MD5) {{ {CALL} }}",
        f"void digest(CC_MD5) int CC_MD5; {{ {CALL} }}",
        f"void digest(void (*CC_MD5)(const void *, CC_LONG, unsigned char *)) {{ {CALL} }}",
        f"void digest(void) {{ int CC_MD5 = 1; {CALL} }}",
        f"void digest(void) {{ void (*CC_MD5)(void) = other; {CALL} }}",
        f"@implementation Handler\n- (void)digest:(id)CC_MD5 {{ {CALL} }}\n@end",
        f"@implementation Handler\n- (void)digest {{ int CC_MD5 = 1; {CALL} }}\n@end",
    ],
)
def test_actual_function_and_method_bindings_block_crypto_identity(function):
    assert not evidence(CRYPTO_IMPORT + function, CRYPTO_RULE)


@pytest.mark.parametrize(
    "nested",
    [
        f"{{ int CC_MD5 = 1; {CALL} }}",
        f"for (int CC_MD5 = 0; CC_MD5 < 1; ++CC_MD5) {{ {CALL} }}",
        f"for (id CC_MD5 in callbacks) {{ {CALL} }}",
        f"void (^callback)(int CC_MD5) = ^(int CC_MD5) {{ {CALL} }};",
    ],
)
def test_nested_bindings_only_hide_calls_inside_their_scope(nested):
    source = CRYPTO_IMPORT + f"void digest(void) {{\n{CALL}\n{nested}\n{CALL}\n}}"
    matches = evidence(source, CRYPTO_RULE)
    assert [item["line"] for item in matches] == [3, 5]


def test_local_binding_begins_at_its_declaration():
    source = CRYPTO_IMPORT + f"void digest(void) {{\n{CALL}\nint CC_MD5 = 1;\n{CALL}\n}}"
    assert [item["line"] for item in evidence(source, CRYPTO_RULE)] == [3]


@pytest.mark.parametrize(
    "function",
    [
        f"void digest(void (*callback)(int CC_MD5)) {{ {CALL} }}",
        f"void digest(void) {{ void callback(int CC_MD5); {CALL} }}",
        f"void (*digest(void))(int CC_MD5) {{ {CALL} return 0; }}",
    ],
)
def test_callback_prototype_parameter_names_do_not_bind_the_enclosing_body(function):
    assert len(evidence(CRYPTO_IMPORT + function, CRYPTO_RULE)) == 1


@pytest.mark.parametrize("name", ["WKWebView", "WKNavigationAction", "NSURLRequest"])
@pytest.mark.parametrize(
    "unrelated",
    [
        "void unrelated(int NAME) {}\n",
        "void unrelated(NAME) int NAME; {}\n",
        "void unrelated(void) { int NAME = 1; }\n",
        "void unrelated(void) { typedef int NAME; }\n",
        "void unrelated(int NAME);\n",
        "@implementation Other\n- (void)unrelated:(id)NAME {}\n@end\n",
        "@implementation Other\n- (void)unrelated { id NAME = other; }\n@end\n",
    ],
)
@pytest.mark.parametrize("before", [False, True])
def test_unrelated_web_bindings_do_not_hide_declared_navigation_flow(name, unrelated, before):
    unrelated = unrelated.replace("NAME", name)
    source = unrelated + WEB if before else WEB + unrelated
    matches = evidence(source, WEB_RULE)
    assert len(matches) == 1
    assert matches[0]["offset"] == source.index("[webView loadRequest:request]")


@pytest.mark.parametrize("name", ["WKWebView", "WKNavigationAction", "NSURLRequest"])
@pytest.mark.parametrize("declaration", ["int NAME;", "typedef int NAME;", "#define NAME Other"])
def test_global_web_bindings_still_block_platform_identity(name, declaration):
    assert not evidence(declaration.replace("NAME", name) + "\n" + WEB, WEB_RULE)


@pytest.mark.parametrize(
    "source",
    [
        WEB.replace("*)action {", "*)action factory:(id)NSURLRequest {"),
        WEB.replace("    NSURL *url", "    id NSURLRequest = factory;\n    NSURL *url"),
        WEB.replace("- (void)webView:", "- (void)shadow:(int)WKWebView webView:"),
        WEB.replace("- (void)webView:", "- (void)shadow:(int)WKNavigationAction webView:"),
    ],
)
def test_actual_web_factory_and_parameter_type_shadows_block_identity(source):
    assert not evidence(source, WEB_RULE)


def test_local_type_shadow_blocks_a_subsequent_receiver_type_declaration():
    source = WEB.replace("webView:(WKWebView *)webView", "webView:(id)unused")
    source = source.replace(
        "    NSURL *url", "    id WKWebView = other;\n    WKWebView *webView = other;\n    NSURL *url"
    )
    assert not evidence(source, WEB_RULE)


@pytest.mark.parametrize("name", ["WKWebView", "WKNavigationAction", "NSURLRequest"])
def test_later_nested_web_binding_does_not_retroactively_hide_the_flow(name):
    source = WEB.replace(
        "    [webView loadRequest:request];", f"    [webView loadRequest:request];\n    {{ int {name} = 1; }}"
    )
    assert len(evidence(source, WEB_RULE)) == 1


def test_request_factory_shadow_only_affects_constructions_after_its_declaration():
    source = WEB.replace(
        "    [webView loadRequest:request];",
        "    [webView loadRequest:request];\n"
        "    id NSURLRequest = factory;\n"
        "    NSURLRequest *second = [NSURLRequest requestWithURL:url];\n"
        "    [webView loadRequest:second];",
    )
    assert [item["line"] for item in evidence(source, WEB_RULE)] == [6]
