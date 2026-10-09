"""Format, provenance and failure-boundary regressions on newly generated inputs."""

from __future__ import annotations

import json
import plistlib
import socket
import struct
import sys
import zipfile

import pytest

from mobile_audit import engine, parser_sandbox
from mobile_audit._parser_worker import analyze
from mobile_audit.aab_manifest import decode_manifest
from mobile_audit.binary_analysis import analyze_binary
from mobile_audit.inputs import inspect_target
from mobile_audit.source_analysis import analyze_sources
from mobile_audit.source_context import plist_references
from tests.test_binary_analysis import FIXTURES, _macho


def test_kotlin_constructor_newline_keeps_original_evidence_coordinates():
    text = (
        '// 합성 fixture\nclass Handler\n@JvmOverloads\n@SuppressLint("Synthetic")\n'
        "constructor(val browser: WebView) {\n"
        'fun handle(input: Intent, browser: WebView) { browser.loadUrl(input.getStringExtra("url")); }\n}'
    )
    report = analyze_sources([("Handler.kt", text)])
    metadata = report["metadata"]["files"][0]
    assert metadata["native_parse_errors"] and not metadata["parse_errors"]
    assert metadata["state"] == "partial" and not report["pattern_exclusions"]
    finding = next(f for f in report["findings"] if f["rule_id"] == "AST-WEBVIEW-UNTRUSTED-URL")
    evidence = finding["evidence"][0]
    assert evidence["line"] == 6
    assert evidence["offset"] == text.encode().find(b"browser.loadUrl")
    assert "browser.loadUrl" in evidence["excerpt"]


@pytest.mark.parametrize(
    "fragment",
    [
        "if await state.isReady { print(state) }",
        "let casted = unsafeBitCast(handler, to: (@Sendable (Data) -> Void).self)",
    ],
)
def test_swift_known_syntax_recovers_function_without_complete_coverage(fragment):
    text = (
        "import CommonCrypto\nfunc digest(handler: (Data) -> Void) async {\n"
        + fragment
        + "\nCC_MD5(data, count, output)\n}"
    )
    report = analyze_sources([("Digest.swift", text)])
    metrics = report["metadata"]["files"][0]
    assert metrics["native_parse_errors"] and not metrics["parse_errors"]
    assert metrics["functions"]["analyzed"] == 1 and metrics["state"] == "partial"
    assert not report["pattern_exclusions"]
    finding = next(f for f in report["findings"] if f["rule_id"] == "AST-CRYPTO-WEAK-HASH")
    assert finding["evidence"][0]["line"] == 4


def test_streamed_pbx_references_cross_old_token_budget_and_keep_strings_opaque():
    text = "other = 1;\n" * 60_000
    text += 'note = "INFOPLIST_FILE = Fake.plist;";\n/* INFOPLIST_FILE = Nope.plist; */\n'
    text += 'INFOPLIST_FILE = "$(SRCROOT)/Brand/Main.plist";\n'
    references, warnings = plist_references([("Project.xcodeproj/project.pbxproj", text)])
    assert not warnings
    assert references == {"Brand/Main.plist": [{"path": "Project.xcodeproj/project.pbxproj", "line": 60_003}]}


@pytest.mark.parametrize(
    "value", ['"../Outside.plist"', '"$(UNKNOWN)/Info.plist"', '"https://example.test/Info.plist"']
)
def test_pbx_unsafe_or_computed_paths_stay_unknown(value):
    references, warnings = plist_references(
        [("A.xcodeproj/project.pbxproj", "INFOPLIST_FILE = " + value + ";")]
    )
    assert not references and warnings


def varint(value):
    output = bytearray()
    while value >= 128:
        output.append((value & 127) | 128)
        value >>= 7
    output.append(value)
    return bytes(output)


def field(number, value):
    if isinstance(value, int):
        return varint(number << 3) + varint(value)
    if isinstance(value, str):
        value = value.encode()
    return varint(number << 3 | 2) + varint(len(value)) + value


def attribute(name, value=None, *, namespace="", compiled=None):
    output = field(2, name)
    if namespace:
        output += field(1, namespace)
    if value is not None:
        output += field(3, value)
    if compiled is not None:
        output += field(6, compiled)
    return field(4, output)


def xmlnode(name, attrs=b"", children=()):
    return field(1, field(3, name) + attrs + b"".join(field(5, child) for child in children))


def manifest(*, unknown=False):
    android = "http://schemas.android.com/apk/res/android"
    compiled = field(1, field(2, 123)) if unknown else field(7, field(8, 1))
    app = xmlnode("application", attribute("debuggable", namespace=android, compiled=compiled))
    sdk = xmlnode(
        "uses-sdk", attribute("targetSdkVersion", namespace=android, compiled=field(7, field(6, 35)))
    )
    return xmlnode("manifest", attribute("package", "audit.synthetic"), (sdk, app))


def bundle(tmp_path, *, unknown=False):
    path = tmp_path / "Synthetic.aab"
    with zipfile.ZipFile(FIXTURES / "unsafe.apk") as source:
        dex = source.read("classes.dex")
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("base/manifest/AndroidManifest.xml", manifest(unknown=unknown))
        archive.writestr("base/dex/classes.dex", dex)
        archive.writestr("feature/dex/classes.dex", dex)
        archive.writestr("feature/manifest/AndroidManifest.xml", xmlnode("manifest"))
    return path


def test_aab_protobuf_base_identity_and_declared_module_dex_are_inspected(tmp_path):
    path = bundle(tmp_path)
    inventory, _ = inspect_target(path)
    assert inventory["package"] == "audit.synthetic"
    assert inventory["android_config"][0]["debuggable"] == "true"
    assert inventory["android_sdk"]["target"] == "35"
    assert inventory["android_modules"] == ["base", "feature"]
    report = analyze_binary(path, inventory)
    assert {d["module"] for d in report["metadata"]["dex"]} == {"base", "feature"}
    assert all(d["installation_state"] == "unknown" for d in report["metadata"]["dex"])
    assert {f["evidence"][0]["path"] for f in report["findings"]} == {
        "base/dex/classes.dex",
        "feature/dex/classes.dex",
    }
    assert all(f["status"] == "candidate" for f in report["findings"])
    assert inventory["partial"]


def test_unknown_aab_resource_is_partial_configuration_not_false_default(tmp_path):
    report = analyze(bundle(tmp_path, unknown=True), None)
    inventory = report["inventory"]
    assert inventory["android_config"][0]["debuggable"] == "unresolved-resource"
    assert inventory["aab_manifest"]["unresolved_attributes"]
    assert next(c for c in report["coverage"] if c["rule_id"] == "ANDROID-CONFIG")["state"] == "partial"
    assert "ANDROID-DEBUG" not in {f["rule_id"] for f in report["findings"]}


@pytest.mark.parametrize(
    "raw",
    [
        b"\x80",
        b"\x00",
        b"\x0a\xff\xff",
        field(1, field(3, "manifest") + field(3, "duplicate")),
        field(1, field(3, "manifest")) + field(2, "conflict"),
        xmlnode("notmanifest"),
    ],
)
def test_malformed_protobuf_fails_closed(raw):
    with pytest.raises(ValueError):
        decode_manifest(raw)


def embedded_ipa(tmp_path, *, unsafe=False):
    path = tmp_path / "Embedded.ipa"
    info = {"CFBundleIdentifier": "audit.main", "CFBundleExecutable": "Main"}
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("Payload/Main.app/Info.plist", plistlib.dumps(info))
        archive.writestr("Payload/Main.app/Main", _macho())
        for suffix, directory in (("appex", "PlugIns"), ("framework", "Frameworks")):
            prefix = f"Payload/Main.app/{directory}/Child.{suffix}"
            archive.writestr(
                prefix + "/Info.plist",
                plistlib.dumps(
                    {
                        "CFBundleIdentifier": "audit.child",
                        "CFBundleExecutable": "../Escape" if unsafe else "Child",
                    }
                ),
            )
            raw = bytearray(_macho(pie=False, entitlements={"get-task-allow": True}))
            if suffix == "framework":
                struct.pack_into("<I", raw, 12, 6)  # MH_DYLIB does not require MH_PIE.
            archive.writestr(prefix + "/Child", raw)
    return path


def test_ipa_extensions_and_frameworks_keep_main_identity_and_header_scope(tmp_path):
    path = embedded_ipa(tmp_path)
    inventory, _ = inspect_target(path)
    report = analyze_binary(path, inventory)
    assert inventory["package"] == "audit.main"
    assert len(report["metadata"]["apps"]) == 1
    assert {e["kind"] for e in report["metadata"]["embedded"]} == {"appex", "framework"}
    assert all(e["complete"] for e in report["metadata"]["embedded"])
    embedded_findings = [f for f in report["findings"] if f["evidence"][0].get("embedded_kind")]
    assert len(embedded_findings) == 3  # PIE for the extension, debug XML for both.
    assert all(f["evidence"][0]["parent_app"] == "Payload/Main.app" for f in embedded_findings)
    assert (
        next(c for c in report["coverage"] if c["rule_id"] == "BINARY-IOS-CODE-PATHS")["state"] == "not-run"
    )


def test_unsafe_embedded_executable_names_remain_incomplete(tmp_path):
    report = analyze_binary(embedded_ipa(tmp_path, unsafe=True), {})
    assert all(not e["complete"] for e in report["metadata"]["embedded"])
    assert (
        next(c for c in report["coverage"] if c["rule_id"] == "BINARY-IOS-EMBEDDED-MACHO")["state"]
        == "partial"
    )


OBJC = """#import <WebKit/WebKit.h>
#import <CommonCrypto/CommonDigest.h>
@implementation Handler
- (void)webView:(WKWebView *)webView decidePolicyForNavigationAction:(WKNavigationAction *)action {
    NSURL *url = action.request.URL;
    NSURLRequest *request = [NSURLRequest requestWithURL:url];
    [webView loadRequest:request];
    CC_MD5(data, size, output);
}
@end
"""


def test_objc_declared_navigation_flow_and_crypto_are_candidates():
    report = analyze_sources([("Handler.m", OBJC)])
    assert {f["rule_id"] for f in report["findings"]} == {
        "OBJC-WEBVIEW-UNTRUSTED-REQUEST",
        "OBJC-CRYPTO-WEAK-HASH",
    }
    assert all(f["status"] == "candidate" for f in report["findings"])
    assert report["metadata"]["files"][0]["state"] == "partial"
    assert not report["pattern_exclusions"]
    flow = next(f for f in report["findings"] if f["rule_id"] == "OBJC-WEBVIEW-UNTRUSTED-REQUEST")
    assert flow["evidence"][0]["line"] == 7
    assert flow["evidence"][0]["sources"][0]["line"] == 4


@pytest.mark.parametrize(
    "replacement",
    [
        "[webView loadRequest:[NSURLRequest requestWithURL:fixedURL]];",
        "if (ready) { request = replacement; } [webView loadRequest:request];",
        "request = replacement; [webView loadRequest:request];",
        'NSString *note = @"[webView loadRequest:request]";',
    ],
)
def test_objc_fixed_unknown_and_joined_values_do_not_gain_taint(replacement):
    report = analyze_sources([("Handler.m", OBJC.replace("[webView loadRequest:request];", replacement))])
    assert "OBJC-WEBVIEW-UNTRUSTED-REQUEST" not in {f["rule_id"] for f in report["findings"]}
    assert any(
        c["rule_id"] == "OBJC-WEBVIEW-UNTRUSTED-REQUEST" and c["state"] == "partial"
        for c in report["coverage"]
    )


def test_objc_missing_platform_imports_do_not_establish_api_identity():
    report = analyze_sources([("Handler.m", OBJC.replace("#import", "// #import"))])
    assert not report["findings"]


@pytest.mark.parametrize("name", ["WKWebView", "WKNavigationAction", "NSURLRequest"])
def test_objc_local_class_homonyms_do_not_establish_platform_flow(name):
    text = f"@interface {name}\n@end\n" + OBJC
    report = analyze_sources([("Handler.m", text)])
    assert "OBJC-WEBVIEW-UNTRUSTED-REQUEST" not in {f["rule_id"] for f in report["findings"]}


@pytest.mark.parametrize("definition", ["#define CC_MD5(...) 0", "#define CC_MD5 OtherDigest"])
def test_objc_macro_digest_homonyms_do_not_establish_platform_call(definition):
    report = analyze_sources([("Handler.m", definition + "\n" + OBJC)])
    assert "OBJC-CRYPTO-WEAK-HASH" not in {f["rule_id"] for f in report["findings"]}


def test_objc_conditional_import_is_not_a_platform_identity_proof():
    text = OBJC.replace("#import <WebKit/WebKit.h>", "#if 0\n#import <WebKit/WebKit.h>\n#endif")
    report = analyze_sources([("Handler.m", text)])
    assert "OBJC-WEBVIEW-UNTRUSTED-REQUEST" not in {f["rule_id"] for f in report["findings"]}


def test_undeclared_aab_module_dex_is_skipped_with_partial_coverage(tmp_path):
    target = bundle(tmp_path)
    with zipfile.ZipFile(target, "a") as archive:
        archive.writestr("junk/dex/classes.dex", archive.read("base/dex/classes.dex"))
    report = analyze_binary(target, {})
    assert {d["module"] for d in report["metadata"]["dex"]} == {"base", "feature"}
    assert report["metadata"]["undeclared_module_dex"] == ["junk/dex/classes.dex"]
    assert all(c["state"] == "partial" for c in report["coverage"])


def test_unused_catalog_versions_are_observed_without_dependency_cve_match():
    from mobile_audit.audit import correlate
    from mobile_audit.inputs import parse_dependencies

    dependencies = parse_dependencies(
        "libs.versions.toml", b'[libraries]\nunused = { module = "example:unused", version = "1.0" }\n'
    )
    assert dependencies[0]["version"] == "1.0" and dependencies[0]["confidence"] == "unknown"
    record = {
        "id": "CVE-2099-12345",
        "title": "Synthetic unused dependency",
        "query_match": {"name": "example:unused", "ecosystem": "Maven", "version": "1.0"},
    }
    findings, _ = correlate({"dependencies": dependencies, "platforms": ["android"]}, [record])
    assert not findings


def test_parent_staging_preserves_authorized_bytes_and_excludes_symlinks_and_store(tmp_path):
    from mobile_audit.input_snapshot import stage_input

    target = tmp_path / "input"
    target.mkdir()
    (target / "Main.java").write_text("class Main {}")
    outside = tmp_path / "Outside.java"
    outside.write_text("class Outside {}")
    (target / "Linked.java").symlink_to(outside)
    store = target / "reports"
    store.mkdir()
    (store / "existing.json").write_text('{"synthetic":"private"}')
    staged = tmp_path / "snapshot"
    metadata = stage_input(target, staged, hidden=(store,))
    assert (staged / "Main.java").read_bytes() == (target / "Main.java").read_bytes()
    assert not (staged / "Linked.java").exists() and not (staged / "reports").exists()
    assert metadata["files"] == 1 and metadata["warnings"]


def test_staging_growth_between_stat_checks_cannot_exceed_total_bytes(tmp_path, monkeypatch):
    import stat
    from types import SimpleNamespace

    from mobile_audit import input_snapshot

    target = tmp_path / "input"
    target.mkdir()
    (target / "Main.java").write_text("four")
    monkeypatch.setattr(input_snapshot, "MAX_SOURCE_TOTAL", 3)
    original = input_snapshot.os.fstat
    regular_calls = 0

    def changed(fd):
        nonlocal regular_calls
        value = original(fd)
        if stat.S_ISREG(value.st_mode):
            regular_calls += 1
            if regular_calls == 1:
                return SimpleNamespace(st_size=2)
        return value

    monkeypatch.setattr(input_snapshot.os, "fstat", changed)
    with pytest.raises(ValueError, match="within byte limits"):
        input_snapshot.stage_input(target, tmp_path / "snapshot")


def test_selected_demo_subtree_does_not_grant_report_store_sibling_access(tmp_path):
    from mobile_audit.input_snapshot import stage_input

    store = tmp_path / "store"
    target = store / "demo" / "generated"
    target.mkdir(parents=True)
    (target / "Main.java").write_text("class Main {}")
    (store / "private.json").write_text('{"synthetic":"secret"}')
    staged = tmp_path / "snapshot"
    metadata = stage_input(target, staged, hidden=(store,))
    assert not metadata["warnings"] and metadata["files"] == 1
    assert (staged / "Main.java").read_text() == "class Main {}"
    assert not (staged / "private.json").exists()


@pytest.mark.skipif(
    __import__("os").environ.get("APSA_SANDBOX_TEST") != "1",
    reason="Explicit disposable-runner staged input race test only",
)
def test_actual_sandbox_input_swap_cannot_mount_replacement(tmp_path):
    from mobile_audit.input_snapshot import stage_input
    from mobile_audit.processes import command

    target = tmp_path / "original"
    target.mkdir()
    (target / "Main.java").write_text("original")
    replacement = tmp_path / "replacement"
    replacement.mkdir()
    (replacement / "Main.java").write_text("replacement")
    staged = tmp_path / "staged" / "input"
    stage_input(target, staged)
    scratch = tmp_path / "work"
    scratch.mkdir()
    script = """
from pathlib import Path
import sys
assert Path(sys.argv[1], 'Main.java').read_text() == 'original'
try: Path(sys.argv[2], 'Main.java').read_bytes()
except OSError: print('replacement-denied')
else: raise AssertionError('Replacement input unexpectedly mounted')
"""
    wrapped, _ = parser_sandbox.sandbox_command(
        [sys.executable, "-I", "-B", "-c", script, str(staged), str(target)],
        staged,
        None,
        scratch,
        mode="required",
    )
    target.rename(tmp_path / "saved-original")
    target.symlink_to(replacement, target_is_directory=True)
    assert command(wrapped, timeout=10, cwd=scratch).strip() == b"replacement-denied"


def test_os_sandbox_unavailable_is_reported_and_required_fails(monkeypatch, tmp_path):
    monkeypatch.setattr(parser_sandbox, "backend", lambda: None)
    args = [sys.executable, "-c", "pass"]
    wrapped, metadata = parser_sandbox.sandbox_command(args, tmp_path, None, tmp_path, mode="auto")
    assert wrapped == args and metadata["state"] == "unavailable"
    assert metadata["network_denied_by_os"] is False
    with pytest.raises(ValueError, match="unavailable"):
        parser_sandbox.sandbox_command(args, tmp_path, None, tmp_path, mode="required")


def test_sandbox_launch_failure_never_retries_without_isolation(monkeypatch, tmp_path):
    target = tmp_path / "input"
    target.mkdir()
    monkeypatch.setenv("APSA_PARSER_LOCK_DIR", str(tmp_path / "locks"))
    monkeypatch.setenv("APSA_PARSER_SANDBOX", "required")
    monkeypatch.setattr(parser_sandbox, "backend", lambda: "/usr/bin/bwrap")
    monkeypatch.setattr(parser_sandbox.sys, "platform", "linux")
    calls = []

    def failed(args, **kwargs):
        calls.append(args)
        raise ValueError("Synthetic namespace denial")

    monkeypatch.setattr(engine, "command", failed)
    with pytest.raises(ValueError, match="namespace denial"):
        engine.analyze_target(target)
    assert len(calls) == 1 and calls[0][0] == "/usr/bin/bwrap"


@pytest.mark.skipif(
    __import__("os").environ.get("APSA_SANDBOX_TEST") != "1",
    reason="Explicit disposable-runner OS isolation test only",
)
def test_actual_sandbox_denies_sibling_reads_input_writes_store_and_host_network(tmp_path):
    from mobile_audit.processes import command

    target = tmp_path / "input"
    target.mkdir()
    (target / "allowed.txt").write_text("synthetic")
    store = target / "reports"
    store.mkdir()
    (store / "private.txt").write_text("synthetic secret")
    secret = tmp_path / "sibling.txt"
    secret.write_text("synthetic secret")
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen()
        port = listener.getsockname()[1]
        script = """
import json,socket,sys
from pathlib import Path
target,store,secret,scratch,port=sys.argv[1:]
result={}
result['input_read']=Path(target,'allowed.txt').read_text()=='synthetic'
for key,path in [('store',Path(store,'private.txt')),('sibling',Path(secret))]:
 try: path.read_bytes(); result[key]=False
 except OSError: result[key]=True
try: Path(target,'write.txt').write_text('bad'); result['input_write']=False
except OSError: result['input_write']=True
Path(scratch,'write.txt').write_text('allowed'); result['scratch_write']=True
try:
 connection=socket.create_connection(('127.0.0.1',int(port)),timeout=1)
 connection.close(); result['network']=False
except OSError: result['network']=True
print(json.dumps(result))
"""
        args = [
            sys.executable,
            "-I",
            "-B",
            "-c",
            script,
            str(target),
            str(store),
            str(secret),
            str(scratch),
            str(port),
        ]
        wrapped, metadata = parser_sandbox.sandbox_command(
            args, target, None, scratch, mode="required", report_home=store
        )
        result = json.loads(command(wrapped, timeout=10, cwd=scratch))
    assert all(result.values()), result
    assert metadata["state"] == "enforced"
