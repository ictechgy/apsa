"""Byte-preserving grammar adaptations on newly written synthetic sources."""

from __future__ import annotations

import pytest

from mobile_audit.source_analysis import analyze_sources
from tests.test_next_hardening import OBJC

SWIFT = """import WebKit
@_documentation(visibility: private)
public struct Generated {}
class LinkHandler {
 let browser = WKWebView()
 let done = { () }
 func application(_ app: UIApplication, open incoming: URL, options: [String: Any]) {
  #warning("synthetic reminder")
  complete(.success(()))
  browser.load(URLRequest(url: incoming))
 }
 func complete(_ result: Result<Void, Error>) {}
}"""


def adaptations(report):
    return {a["kind"] for a in report["metadata"]["files"][0]["adaptations"]}


def test_swift_attributes_directives_and_empty_tuples_parse_with_original_offsets():
    report = analyze_sources([("App.swift", SWIFT)])
    metadata = report["metadata"]["files"][0]
    assert metadata["native_parse_errors"] and not metadata["parse_errors"]
    assert {
        "swift-documentation-attribute",
        "swift-diagnostic-directive",
        "swift-empty-tuple-argument",
    } <= adaptations(report)
    assert metadata["state"] == "partial"
    finding = next(f for f in report["findings"] if f["rule_id"] == "AST-WEBVIEW-UNTRUSTED-URL")
    assert finding["evidence"][0]["line"] == 10
    assert finding["evidence"][0]["offset"] == SWIFT.encode().index(b"browser.load")


@pytest.mark.parametrize(
    "text",
    [
        'let note = "@_documentation(visibility: private) ()"',
        '// #warning("comment") complete(.success(()))',
    ],
)
def test_swift_adaptations_ignore_strings_and_comments(text):
    report = analyze_sources([("App.swift", SWIFT.replace("let done = { () }", text))])
    assert report["metadata"]["files"][0]["native_parse_errors"]
    assert "AST-WEBVIEW-UNTRUSTED-URL" in {f["rule_id"] for f in report["findings"]}


OBJC_PARTS = OBJC.replace(
    "@implementation",
    "typedef NS_ENUM(NSInteger, SyntheticStyle) {\n  SyntheticStylePlain,\n};\n\n@implementation",
    1,
)


def test_objc_enum_macro_and_split_conditional_parse_without_new_identity():
    text = OBJC_PARTS.replace(
        "[webView loadRequest:request];",
        'NSString *title = NSLocalizedString(@"TITLE", comment: @"");\n'
        "    [webView loadRequest:request];\n"
        "#if TARGET_OS_IOS\n    if (title) {\n#else\n    if (!title) {\n#endif\n"
        "        title = nil;\n    }",
    )
    report = analyze_sources([("Handler.m", text)])
    metadata = report["metadata"]["files"][0]
    assert metadata["native_parse_errors"] and not metadata["parse_errors"]
    assert {
        "objc-enum-macro",
        "objc-localized-comment-label",
        "objc-preprocessor-first-branch",
    } <= adaptations(report)
    assert metadata["state"] == "partial"
    # The method containing the normalized conditional may have lost a branch.
    assert "OBJC-WEBVIEW-UNTRUSTED-REQUEST" not in {f["rule_id"] for f in report["findings"]}
    assert metadata["functions"]["skipped"] >= 1


def test_objc_adapted_conditional_imports_never_establish_platform_identity():
    text = OBJC_PARTS.replace(
        "#import <WebKit/WebKit.h>", "#if TARGET_OS_IOS\n#import <WebKit/WebKit.h>\n#endif"
    )
    text = text.replace(
        "[webView loadRequest:request];",
        "#if 1\n    if (request) {\n#endif\n    [webView loadRequest:request];\n    }",
    )
    report = analyze_sources([("Handler.m", text)])
    assert report["metadata"]["files"][0]["native_parse_errors"]
    assert "OBJC-WEBVIEW-UNTRUSTED-REQUEST" not in {f["rule_id"] for f in report["findings"]}


def test_objc_dead_branch_is_not_the_kept_branch():
    text = OBJC_PARTS.replace(
        "[webView loadRequest:request];",
        "#if 0\n    if (request) {\n#else\n    if (!request) {\n#endif\n    [webView loadRequest:request];\n    }",
    )
    report = analyze_sources([("Handler.m", text)])
    assert not report["metadata"]["files"][0]["parse_errors"]


def test_aab_feature_manifest_components_keep_module_and_delivery(tmp_path):
    import zipfile

    from mobile_audit.inputs import inspect_target
    from tests.test_next_hardening import attribute, bundle, field, xmlnode

    android = "http://schemas.android.com/apk/res/android"
    dist = "http://schemas.android.com/apk/distribution"
    true = field(7, field(8, 1))

    def element(name, *, namespace="", attrs=b"", children=()):
        body = (field(2, namespace) if namespace else b"") + field(3, name) + attrs
        return field(1, body + b"".join(field(5, child) for child in children))

    module = element(
        "module",
        namespace=dist,
        attrs=attribute("title", "@string/feature_title", namespace=dist),
        children=(element("delivery", namespace=dist, children=(element("on-demand", namespace=dist),)),),
    )
    view = xmlnode("action", attribute("name", "android.intent.action.VIEW", namespace=android))
    data = xmlnode(
        "data",
        attribute("scheme", "https", namespace=android)
        + attribute("host", "feature.example", namespace=android),
    )
    activity = xmlnode(
        "activity",
        attribute("name", "audit.synthetic.feature.Entry", namespace=android)
        + attribute("exported", namespace=android, compiled=true),
        children=(xmlnode("intent-filter", children=(view, data)),),
    )
    feature = xmlnode(
        "manifest",
        attribute("package", "audit.synthetic") + attribute("split", "feature"),
        children=(module, xmlnode("application", children=(activity,))),
    )
    path = bundle(tmp_path)
    with zipfile.ZipFile(path, "a") as archive:
        archive.writestr("checkout/manifest/AndroidManifest.xml", feature)
        archive.writestr("checkout/dex/classes.dex", b"")
    inventory, _ = inspect_target(path)
    assert inventory["package"] == "audit.synthetic"
    assert len(inventory["android_config"]) == 1
    entry = next(m for m in inventory["aab_feature_manifests"] if m["module"] == "checkout")
    assert entry["split"] == "feature" and entry["installation_state"] == "unknown"
    assert entry["delivery"] == "on-demand" and entry["title_resource"] == "@string/feature_title"
    assert entry["components"] == 1 and entry["deep_links"] == 1
    component = next(c for c in inventory["components"] if c.get("module") == "checkout")
    assert component["name"] == "audit.synthetic.feature.Entry" and component["exported"] == "true"
    assert component["module_delivery"] == "on-demand"
    link = next(d for d in inventory["deep_links"] if d.get("module") == "checkout")
    assert link["host"] == "feature.example"
    assert inventory["partial"]


def signed_macho(*, tamper_code=False, tamper_entitlements=False):
    import hashlib
    import plistlib
    import struct

    entitlements = plistlib.dumps({"get-task-allow": False})
    blob = struct.pack(">II", 0xFADE7171, len(entitlements) + 8) + entitlements
    code_limit, page, slots, special = 4196, 4096, 2, 5
    ident = b"audit.synthetic\0"
    hash_offset = 44 + len(ident) + special * 32
    cd_length = hash_offset + slots * 32
    total = 28 + cd_length + len(blob)
    header = struct.pack("<IiiIIIII", 0xFEEDFACF, 0x100000C, 0, 2, 1, 16, 0x200000, 0)
    command = struct.pack("<IIII", 0x1D, 16, code_limit, total)
    code = bytearray(header + command)
    code += bytes((index * 7) % 251 for index in range(code_limit - len(code)))
    pages = b"".join(
        hashlib.sha256(bytes(code[i * page : min((i + 1) * page, code_limit)])).digest() for i in range(slots)
    )
    specials = hashlib.sha256(blob).digest() + bytes(32 * 4)
    directory = (
        struct.pack(
            ">IIIIIIIIIBBBBI",
            0xFADE0C02,
            cd_length,
            0x20001,
            0,
            hash_offset,
            44,
            special,
            slots,
            code_limit,
            32,
            2,
            0,
            12,
            0,
        )
        + ident
        + specials
        + pages
    )
    if tamper_code:
        code[300] ^= 1
    if tamper_entitlements:
        blob = blob.replace(b"<false/>", b"<true/> ")
    superblob = (
        struct.pack(">III", 0xFADE0CC0, total, 2)
        + struct.pack(">II", 0, 28)
        + struct.pack(">II", 5, 28 + cd_length)
        + directory
        + blob
    )
    return bytes(code) + superblob


@pytest.mark.parametrize(
    "tamper,integrity,bound",
    [
        ({}, "consistent", True),
        ({"tamper_code": True}, "modified", True),
        ({"tamper_entitlements": True}, "modified", False),
    ],
)
def test_code_directory_page_and_entitlement_hashes_are_recomputed(tamper, integrity, bound):
    from mobile_audit.binary_analysis import _macho_slice

    raw = signed_macho(**tamper)
    signature = _macho_slice(raw, 0, len(raw))["code_signature"]
    directory = signature["code_directories"][0]
    assert directory["hash_type"] == "sha256" and directory["code_slots"] == 2
    assert directory["identifier"] == "audit.synthetic"
    assert directory["entitlements_bound"] is bound
    assert signature["integrity"] == integrity
    assert signature["signature_verified"] is False


def test_encrypted_pages_are_unverifiable_not_modified():
    import struct

    from mobile_audit.binary_analysis import _macho_slice

    raw = bytearray(signed_macho())
    # Add an encryption command over the first page; that page no longer matches.
    assert struct.unpack_from("<I", raw, 16)[0] == 1
    command = struct.pack("<IIIIII", 0x2C, 24, 64, 4000, 1, 0)
    raw[16:24] = struct.pack("<II", 2, 40)
    raw[48:72] = command
    signature = _macho_slice(bytes(raw), 0, len(raw))["code_signature"]
    assert signature["code_directories"][0]["integrity"] == "unverifiable-encrypted-pages"
    assert signature["integrity"] == "unverifiable"


def large_signed_macho(pages):
    import hashlib
    import struct

    page, slots, special = 4096, pages, 0
    code_limit = page * pages
    ident = b"audit.large\0"
    hash_offset = 44 + len(ident)
    cd_length = hash_offset + slots * 32
    total = 20 + cd_length
    code = bytearray(struct.pack("<IiiIIIII", 0xFEEDFACF, 0x100000C, 0, 2, 2, 40, 0x200000, 0))
    code += struct.pack("<IIII", 0x1D, 16, code_limit, total)
    code += struct.pack("<IIIIII", 0x2C, 24, page, page * (pages - 1), 1, 0)
    code += bytes((index * 13) % 251 for index in range(code_limit - len(code)))
    hashes = b"".join(hashlib.sha256(bytes(code[i * page : (i + 1) * page])).digest() for i in range(slots))
    directory = (
        struct.pack(
            ">IIIIIIIIIBBBBI",
            0xFADE0C02,
            cd_length,
            0x20001,
            0,
            hash_offset,
            44,
            special,
            slots,
            code_limit,
            32,
            2,
            0,
            12,
            0,
        )
        + ident
        + hashes
    )
    for index in range(1, pages):
        code[index * page] ^= 0xFF  # stands in for FairPlay-encrypted pages
    superblob = struct.pack(">III", 0xFADE0CC0, total, 1) + struct.pack(">II", 0, 20) + directory
    return bytes(code) + superblob


def test_large_encrypted_region_is_unverifiable_not_modified():
    from mobile_audit.binary_analysis import _macho_slice

    raw = large_signed_macho(80)
    signature = _macho_slice(raw, 0, len(raw))["code_signature"]
    directory = signature["code_directories"][0]
    assert directory["pages_mismatched"] == 79 and len(directory["mismatched_pages"]) == 64
    assert directory["integrity"] == "unverifiable-encrypted-pages"
    assert signature["integrity"] == "unverifiable"


def test_encrypted_ipa_leaves_code_integrity_not_run(tmp_path):
    from mobile_audit.binary_analysis import analyze_binary
    from mobile_audit.inputs import inspect_target
    from tests.test_binary_analysis import _ipa

    path = _ipa(tmp_path, large_signed_macho(80))
    inventory, _ = inspect_target(path)
    report = analyze_binary(path, inventory)
    check = next(c for c in report["coverage"] if c["rule_id"] == "BINARY-IOS-CODE-INTEGRITY")
    assert check["state"] == "not-run"
    assert not any("changed after signing" in warning for warning in report["warnings"])


@pytest.mark.parametrize(
    "guard",
    [
        "#if TARGET_OS_SIMULATOR\n#else\n    if (![self allowed:request]) { return; }\n#endif\n",
        "#ifndef AUDIT_SKIP_GUARD\n#else\n    if (![self allowed:request]) { return; }\n#endif\n",
        "#if 0 /* legacy */\n    [self unused];\n#else\n    if (![self allowed:request]) { return; }\n#endif\n",
    ],
)
def test_dropped_branch_guard_never_yields_an_adapted_finding(guard):
    text = OBJC_PARTS.replace(
        "    [webView loadRequest:request];", guard + "    [webView loadRequest:request];"
    )
    report = analyze_sources([("Handler.m", text)])
    assert report["metadata"]["files"][0]["native_parse_errors"]
    assert "OBJC-WEBVIEW-UNTRUSTED-REQUEST" not in {f["rule_id"] for f in report["findings"]}
    assert all("spans" not in a for a in report["metadata"]["files"][0]["adaptations"])


def test_enum_macro_scan_is_linear_on_crafted_spacing():
    import time

    from mobile_audit.parser_compat import ENUM_MACRO

    started = time.perf_counter()
    assert ENUM_MACRO.search(b"NS_ENUM(a" + b" " * 200_000) is None
    assert time.perf_counter() - started < 1


def test_kept_branch_methods_stay_uncertain():
    duplicate = OBJC_PARTS.replace(
        "@implementation Handler\n",
        "@implementation Handler\n#if TARGET_OS_SIMULATOR\n",
        1,
    ).replace(
        "@end\n",
        "#else\n- (void)release {}\n#endif\n@end\n",
        1,
    )
    report = analyze_sources([("Handler.m", duplicate)])
    assert report["metadata"]["files"][0]["native_parse_errors"]
    assert "OBJC-WEBVIEW-UNTRUSTED-REQUEST" not in {f["rule_id"] for f in report["findings"]}


def test_uncertain_span_checks_are_fast_on_crafted_files():
    import time

    body = "\n".join(f"- (void)m{i} {{ }}" for i in range(2000))
    text = OBJC_PARTS.replace("@end\n", "#if 0\n" + "\n" * 200_000 + "#endif\n" + body + "\n@end\n", 1)
    started = time.perf_counter()
    analyze_sources([("Handler.m", text)])
    assert time.perf_counter() - started < 10
