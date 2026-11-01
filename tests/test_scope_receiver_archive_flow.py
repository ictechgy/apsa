"""Kotlin implicit scope receivers and archive entry names under the native flow layer."""

from __future__ import annotations

import textwrap

import pytest

from mobile_audit.source_analysis import analyze_sources

URL_RULE = "AST-WEBVIEW-UNTRUSTED-URL"
BRIDGE_RULE = "AST-WEBVIEW-JS-BRIDGE"
PATH_RULE = "AST-PATH-TRAVERSAL"


def scan(path: str, text: str) -> dict:
    return analyze_sources([{"path": path, "text": textwrap.dedent(text).strip()}])


def matches(report: dict, rule: str) -> list[dict]:
    return [item for item in report["findings"] if item["rule_id"] == rule]


def functions(report: dict, rule: str) -> set[str]:
    return {item["evidence"][0]["function"] for item in matches(report, rule)}


SCOPE_ACTIVITY = """
package app

import android.app.Activity
import android.webkit.WebView

class Scopes : Activity() {{
    fun open(webView: WebView?) {{
        val url = {url}
        {statement}
    }}
}}
"""


@pytest.mark.parametrize(
    "statement",
    [
        "webView!!.apply { loadUrl(url) }",
        "webView!!.run { loadUrl(url) }",
        "with(webView!!) { loadUrl(url) }",
        "webView?.apply { loadUrl(url) }",
        "webView!!.apply { this.loadUrl(url) }",
        "webView!!.also { it.loadUrl(url) }",
    ],
)
@pytest.mark.parametrize("tainted", [True, False])
def test_kotlin_receiver_scope_unqualified_webview_load_is_a_sink(statement, tainted):
    url = 'intent.getStringExtra("url")!!' if tainted else '"https://docs.example.test/"'
    report = scan("app/Scopes.kt", SCOPE_ACTIVITY.format(url=url, statement=statement))
    found = matches(report, URL_RULE)
    if not tainted:
        assert report["findings"] == [], report
        return
    assert [(item["evidence"][0]["line"], item["evidence"][0]["function"]) for item in found] == [(9, "open")]
    assert [source["kind"] for source in found[0]["evidence"][0]["sources"]] == ["Intent string extra"]


@pytest.mark.parametrize("tainted", [True, False])
def test_kotlin_apply_on_new_webview_reports_load_and_same_receiver_bridge(tainted):
    url = 'intent.getStringExtra("url") ?: return' if tainted else '"https://docs.example.test/"'
    report = scan(
        "app/Browser.kt",
        f"""
        package app

        import android.app.Activity
        import android.os.Bundle
        import android.webkit.WebView

        class Browser : Activity() {{
            override fun onCreate(savedInstanceState: Bundle?) {{
                super.onCreate(savedInstanceState)
                val url = {url}
                val webView = WebView(this).apply {{
                    settings.javaScriptEnabled = true
                    addJavascriptInterface(Bridge(), "native")
                    loadUrl(url)
                }}
            }}
        }}
        """,
    )
    if not tainted:
        assert report["findings"] == [], report
        return
    assert [item["evidence"][0]["line"] for item in matches(report, URL_RULE)] == [14]
    bridge = matches(report, BRIDGE_RULE)
    assert [item["evidence"][0]["line"] for item in bridge] == [13], report
    assert bridge[0]["evidence"][0]["load_location"]["line"] == 14


def test_kotlin_implicit_receiver_bridge_correlation_follows_receiver_identity():
    report = scan(
        "app/Bridges.kt",
        """
        package app

        import android.app.Activity
        import android.webkit.WebView

        class Bridges : Activity() {
            fun named(webView: WebView) {
                webView.addJavascriptInterface(Bridge(), "native")
                val url = intent.getStringExtra("url")!!
                webView.apply { loadUrl(url) }
            }
            fun forced(webView: WebView?) {
                webView!!.addJavascriptInterface(Bridge(), "native")
                val url = intent.getStringExtra("url")!!
                webView!!.apply { loadUrl(url) }
            }
            fun explicit(webView: WebView) {
                val url = intent.getStringExtra("url")!!
                webView.apply {
                    this.addJavascriptInterface(Bridge(), "native")
                    loadUrl(url)
                }
            }
            fun separate() {
                WebView(this).apply { addJavascriptInterface(Bridge(), "native") }
                val url = intent.getStringExtra("url")!!
                WebView(this).apply { loadUrl(url) }
            }
        }
        """,
    )
    assert functions(report, URL_RULE) == {"named", "forced", "explicit", "separate"}
    # Two allocations spelled alike are distinct receivers; named receivers share their bridge.
    assert sorted(item["evidence"][0]["line"] for item in matches(report, BRIDGE_RULE)) == [8, 13, 20]


def test_kotlin_implicit_call_resolves_only_through_receiver_scopes():
    report = scan(
        "app/Loaders.kt",
        """
        package app

        import android.app.Activity
        import android.webkit.WebView

        class Loader {
            fun loadUrl(value: String) {}
            fun addJavascriptInterface(target: Any, name: String) {}
        }

        class Loaders : Activity() {
            fun other(loader: Loader) {
                val url = intent.getStringExtra("url")!!
                loader.apply { loadUrl(url) }
                loader.run { loadUrl(url) }
                with(loader) { loadUrl(url) }
            }
            fun nested(loader: Loader, webView: WebView) {
                val url = intent.getStringExtra("url")!!
                // let/also bind `it`; the enclosing `this` remains the Loader.
                loader.apply { webView.let { loadUrl(url) } }
                loader.apply { webView.also { loadUrl(url) } }
                webView.apply { loader.apply { addJavascriptInterface(Bridge(), "native") } }
            }
        }
        """,
    )
    assert report["findings"] == [], report


def test_kotlin_implicit_receiver_load_keeps_exact_scheme_and_host_guard():
    report = scan(
        "app/Guarded.kt",
        """
        package app

        import android.content.Intent
        import android.net.Uri
        import android.webkit.WebView

        class Guarded {
            fun guarded(webView: WebView, incoming: Intent) {
                val destination = incoming.getStringExtra("url") ?: return
                val parsed = Uri.parse(destination)
                if (parsed.scheme == "https" && parsed.host == "docs.example.test") {
                    webView.apply { loadUrl(destination) }
                    with(webView) { loadUrl(destination) }
                }
            }
            fun unguarded(webView: WebView, incoming: Intent) {
                val destination = incoming.getStringExtra("url") ?: return
                webView.run { loadUrl(destination) }
            }
        }
        """,
    )
    assert functions(report, URL_RULE) == {"unguarded"}, report


def test_java_unqualified_call_is_not_a_webview_receiver():
    report = scan(
        "app/Handler.java",
        """
        package app;

        import android.app.Activity;

        class Handler extends Activity {
            void loadUrl(String value) {}
            void open() { loadUrl(getIntent().getStringExtra("url")); }
        }
        """,
    )
    assert report["findings"] == [], report


ARCHIVE_SINKS = [
    (
        "app/Unzip.java",
        """
        package app;

        import java.io.File;
        import java.io.FileOutputStream;
        import java.io.InputStream;
        import java.util.zip.ZipEntry;
        import java.util.zip.ZipInputStream;

        class Unzip {
            void local(InputStream in, File dest) throws Exception {
                ZipInputStream zis = new ZipInputStream(in);
                ZipEntry entry;
                while ((entry = zis.getNextEntry()) != null) {
                    new FileOutputStream(new File(dest, entry.getName())).close();
                }
            }
            void parameter(ZipInputStream zis, File dest) throws Exception {
                ZipEntry entry = zis.getNextEntry();
                new FileOutputStream(new File(dest, entry.getName())).close();
            }
            void loop(ZipInputStream zis, File dest) throws Exception {
                for (ZipEntry e = zis.getNextEntry(); e != null; e = zis.getNextEntry()) {
                    new File(dest, e.getName());
                }
            }
            void entry(ZipEntry entry, File dest) throws Exception {
                new FileOutputStream(new File(dest, entry.getName())).close();
            }
        }
        """,
        {"local", "parameter", "loop", "entry"},
    ),
    (
        "app/Unzip.kt",
        """
        package app

        import java.io.File
        import java.io.InputStream
        import java.util.zip.ZipInputStream

        class Unzip {
            fun scoped(input: InputStream, dest: File) {
                ZipInputStream(input).use { zis ->
                    var entry = zis.nextEntry
                    while (entry != null) {
                        File(dest, entry.name).writeBytes(zis.readBytes())
                        entry = zis.nextEntry
                    }
                }
            }
            fun local(input: InputStream, dest: File) {
                val zis = ZipInputStream(input)
                var entry = zis.nextEntry
                while (entry != null) {
                    File(dest, entry.name).writeBytes(zis.readBytes())
                    entry = zis.nextEntry
                }
            }
            fun parameter(zis: ZipInputStream, dest: File) {
                val entry = zis.nextEntry ?: return
                File(dest, entry.name).writeBytes(zis.readBytes())
            }
            fun getter(input: InputStream, dest: File) {
                val zis = ZipInputStream(input)
                val entry = zis.getNextEntry() ?: return
                File(dest, entry.getName()).writeBytes(zis.readBytes())
            }
        }
        """,
        {"scoped", "local", "parameter", "getter"},
    ),
]


@pytest.mark.parametrize(("path", "source", "expected"), ARCHIVE_SINKS, ids=["java", "kotlin"])
def test_archive_entry_name_reaches_path_sink_under_native_flow(path, source, expected):
    report = scan(path, source)
    assert functions(report, PATH_RULE) == expected, report
    for item in matches(report, PATH_RULE):
        assert [source["kind"] for source in item["evidence"][0]["sources"]] == ["Archive entry name"]


ARCHIVE_GUARDS = [
    (
        "app/Safe.java",
        """
        package app;

        import java.io.File;
        import java.io.FileOutputStream;
        import java.io.InputStream;
        import java.util.zip.ZipEntry;
        import java.util.zip.ZipInputStream;

        class Safe {
            void inline(InputStream in, File dest) throws Exception {
                ZipInputStream zis = new ZipInputStream(in);
                ZipEntry entry;
                while ((entry = zis.getNextEntry()) != null) {
                    File out = new File(dest, entry.getName());
                    if (!out.getCanonicalPath().startsWith(dest.getCanonicalPath() + File.separator)) {
                        throw new SecurityException("zip slip");
                    }
                    new FileOutputStream(out).close();
                }
            }
            void root(InputStream in, File dest) throws Exception {
                ZipInputStream zis = new ZipInputStream(in);
                ZipEntry entry;
                String destCanonical = dest.getCanonicalPath();
                while ((entry = zis.getNextEntry()) != null) {
                    File out = new File(dest, entry.getName());
                    String target = out.getCanonicalPath();
                    if (!target.startsWith(destCanonical + File.separator)) {
                        throw new SecurityException("zip slip");
                    }
                    new FileOutputStream(out).close();
                }
            }
        }
        """,
    ),
    (
        "app/Safe.kt",
        """
        package app

        import java.io.File
        import java.io.FileOutputStream
        import java.io.InputStream
        import java.util.zip.ZipInputStream

        class Safe {
            fun scoped(input: InputStream, dest: File) {
                ZipInputStream(input).use { zis ->
                    var entry = zis.nextEntry
                    while (entry != null) {
                        val out = File(dest, entry.name)
                        if (!out.canonicalPath.startsWith(dest.canonicalPath + File.separator)) {
                            throw SecurityException("zip slip")
                        }
                        FileOutputStream(out).use { zis.copyTo(it) }
                        entry = zis.nextEntry
                    }
                }
            }
            fun scopedRoot(input: InputStream, dest: File) {
                val destCanonical = dest.canonicalPath
                ZipInputStream(input).use { zis ->
                    var entry = zis.nextEntry
                    while (entry != null) {
                        val out = File(dest, entry.name)
                        if (!out.canonicalPath.startsWith(destCanonical + File.separator)) {
                            throw SecurityException("zip slip")
                        }
                        out.writeBytes(zis.readBytes())
                        entry = zis.nextEntry
                    }
                }
            }
            fun local(input: InputStream, dest: File) {
                val destCanonical: String = dest.canonicalPath
                val zis = ZipInputStream(input)
                var entry = zis.nextEntry
                while (entry != null) {
                    val out = File(dest, entry.name)
                    if (!out.canonicalPath.startsWith(destCanonical + File.separator)) {
                        throw SecurityException("zip slip")
                    }
                    out.writeBytes(zis.readBytes())
                    entry = zis.nextEntry
                }
            }
        }
        """,
    ),
]


@pytest.mark.parametrize(("path", "source"), ARCHIVE_GUARDS, ids=["java", "kotlin"])
def test_canonical_containment_keeps_fixed_archive_extraction_clean(path, source):
    report = scan(path, source)
    assert report["findings"] == [], report


def test_canonical_root_and_closure_guards_require_an_unambiguous_dominating_check():
    report = scan(
        "app/Unsafe.kt",
        """
        package app

        import android.content.Intent
        import java.io.File
        import java.io.FileOutputStream
        import java.io.InputStream
        import java.util.zip.ZipInputStream

        class Unsafe {
            fun reassigned(input: InputStream, dest: File, other: String) {
                var root = dest.canonicalPath
                root = other
                val entry = ZipInputStream(input).nextEntry ?: return
                val out = File(dest, entry.name)
                if (!out.canonicalPath.startsWith(root + File.separator)) throw SecurityException("zip slip")
                FileOutputStream(out).close()
            }
            fun lexical(input: InputStream, dest: File) {
                val root = dest.path
                val entry = ZipInputStream(input).nextEntry ?: return
                val out = File(dest, entry.name)
                if (!out.canonicalPath.startsWith(root + File.separator)) throw SecurityException("zip slip")
                FileOutputStream(out).close()
            }
            fun sibling(input: InputStream, dest: File) {
                val root = dest.canonicalPath
                val entry = ZipInputStream(input).nextEntry ?: return
                val out = File(dest, entry.name)
                if (!out.canonicalPath.startsWith(root)) throw SecurityException("zip slip")
                FileOutputStream(out).close()
            }
            fun external(input: InputStream, dest: File, intent: Intent) {
                val root = File(intent.getStringExtra("root")!!).canonicalPath
                val entry = ZipInputStream(input).nextEntry ?: return
                val out = File(dest, entry.name)
                if (!out.canonicalPath.startsWith(root + File.separator)) throw SecurityException("zip slip")
                FileOutputStream(out).close()
            }
            fun shadowed(input: InputStream, dest: File, other: String) {
                val root = dest.canonicalPath
                val zis = ZipInputStream(input)
                other.let { root ->
                    val entry = zis.nextEntry ?: return
                    val out = File(dest, entry.name)
                    if (!out.canonicalPath.startsWith(root + File.separator)) throw SecurityException("zip slip")
                    FileOutputStream(out).close()
                }
            }
            fun looped(input: InputStream, dest: File, roots: List<String>) {
                val root = dest.canonicalPath
                val entry = ZipInputStream(input).nextEntry ?: return
                for (root in roots) {
                    val out = File(dest, entry.name)
                    if (!out.canonicalPath.startsWith(root + File.separator)) throw SecurityException("zip slip")
                    FileOutputStream(out).close()
                }
            }
            fun outside(input: InputStream, dest: File) {
                val entry = ZipInputStream(input).nextEntry ?: return
                val out = File(dest, entry.name)
                dest.let {
                    if (!out.canonicalPath.startsWith(dest.canonicalPath + File.separator)) throw SecurityException("zip slip")
                    FileOutputStream(out).close()
                }
            }
            fun conditional(input: InputStream, dest: File, check: Boolean) {
                ZipInputStream(input).use { zis ->
                    val entry = zis.nextEntry ?: return
                    val out = File(dest, entry.name)
                    if (check) {
                        if (!out.canonicalPath.startsWith(dest.canonicalPath + File.separator)) throw SecurityException("zip slip")
                        FileOutputStream(out).close()
                    }
                }
            }
            fun escaped(input: InputStream, dest: File) {
                var out: File? = null
                ZipInputStream(input).use { zis ->
                    val entry = zis.nextEntry ?: return
                    out = File(dest, entry.name)
                    if (!out!!.canonicalPath.startsWith(dest.canonicalPath + File.separator)) throw SecurityException("zip slip")
                }
                FileOutputStream(out!!).close()
            }
        }
        """,
    )
    assert functions(report, PATH_RULE) == {
        "reassigned",
        "lexical",
        "sibling",
        "external",
        "shadowed",
        "looped",
        "outside",
        "conditional",
        "escaped",
    }, report


def test_java_canonical_root_must_be_the_single_visible_declaration():
    report = scan(
        "app/Unsafe.java",
        """
        package app;

        import java.io.File;
        import java.io.FileOutputStream;
        import java.util.zip.ZipEntry;
        import java.util.zip.ZipInputStream;

        class Unsafe {
            String root;
            void reassigned(ZipInputStream zis, File dest, String other) throws Exception {
                String root = dest.getCanonicalPath();
                root = other;
                ZipEntry entry = zis.getNextEntry();
                File out = new File(dest, entry.getName());
                if (!out.getCanonicalPath().startsWith(root + File.separator)) throw new SecurityException("zip slip");
                new FileOutputStream(out).close();
            }
            void lexical(ZipInputStream zis, File dest) throws Exception {
                String root = dest.getPath();
                ZipEntry entry = zis.getNextEntry();
                File out = new File(dest, entry.getName());
                if (!out.getCanonicalPath().startsWith(root + File.separator)) throw new SecurityException("zip slip");
                new FileOutputStream(out).close();
            }
            void field(ZipInputStream zis, File dest, boolean b) throws Exception {
                if (b) { String root = dest.getCanonicalPath(); }
                ZipEntry entry = zis.getNextEntry();
                File out = new File(dest, entry.getName());
                if (!out.getCanonicalPath().startsWith(root + File.separator)) throw new SecurityException("zip slip");
                new FileOutputStream(out).close();
            }
        }
        """,
    )
    assert functions(report, PATH_RULE) == {"reassigned", "lexical", "field"}, report


def test_finding_reports_each_source_location_and_kind_once():
    report = scan(
        "app/Guards.java",
        """
        package app;

        import com.vendor.VendorScreen;
        import android.net.Uri;
        import android.webkit.WebView;

        public class Guards extends VendorScreen {
            void open(WebView webView) {
                Uri uri = Uri.parse(getIntent().getStringExtra("url"));
                if ("https".equals(uri.getScheme()) && "example.com".equals(uri.getHost())) {
                    webView.loadUrl(uri.toString());
                }
            }
        }
        """,
    )
    # An unknown (non-framework) base may supply a member type named Uri, so this
    # guard stays uncredited; its several trace origins share one source expression.
    sources = matches(report, URL_RULE)[0]["evidence"][0]["sources"]
    keys = [(source["line"], source["column"], source["kind"]) for source in sources]
    assert len(keys) == len(set(keys)), sources
    assert {(line, kind.split(" [")[0]) for line, _column, kind in keys} == {(9, "Intent string extra")}
    assert report["metadata"]["native_flow"]["state"] == "partial", report
