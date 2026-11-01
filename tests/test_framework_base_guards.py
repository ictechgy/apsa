"""Guards in Android framework subclasses are credited only for resolved, curated bases."""

from __future__ import annotations

import pytest

from mobile_audit import native_flow
from mobile_audit.source_analysis import analyze_sources

URL_RULE = "AST-WEBVIEW-UNTRUSTED-URL"
PATH_RULE = "AST-PATH-TRAVERSAL"

JAVA_GUARD = """package app;

IMPORT
import android.content.Intent;
import android.net.Uri;
import android.webkit.WebView;

public class Screen extends BASE {
    void open(WebView webView, Intent launch) {
        Uri uri = Uri.parse(launch.getStringExtra("url"));
        if (CHECK) {
            webView.loadUrl(uri.toString());
        }
    }
}
"""
JAVA_CHECK = '"https".equals(uri.getScheme()) && "example.com".equals(uri.getHost())'

KOTLIN_GUARD = """package app

IMPORT
import android.content.Intent
import android.net.Uri
import android.webkit.WebView

class Screen : BASE {
    fun open(webView: WebView, launch: Intent) {
        val uri = Uri.parse(launch.getStringExtra("url"))
        if (CHECK) {
            webView.loadUrl(uri.toString())
        }
    }
}
"""
KOTLIN_CHECK = 'uri.scheme == "https" && uri.host == "example.com"'


def scan(*files: tuple[str, str]) -> dict:
    return analyze_sources(list(files))


def rules(report: dict) -> set[str]:
    return {item["rule_id"] for item in report["findings"]}


def java(imports: str, base: str, guarded: bool = True) -> tuple[str, str]:
    text = JAVA_GUARD.replace("IMPORT", imports).replace("BASE", base)
    return "app/Screen.java", text.replace("CHECK", JAVA_CHECK if guarded else "uri != null")


def kotlin(imports: str, base: str, guarded: bool = True) -> tuple[str, str]:
    text = KOTLIN_GUARD.replace("IMPORT", imports).replace("BASE", base)
    return "app/Screen.kt", text.replace("CHECK", KOTLIN_CHECK if guarded else "uri != null")


FRAMEWORK_BASES = [
    (java, "import android.app.Activity;", "Activity"),
    (java, "import androidx.appcompat.app.AppCompatActivity;", "AppCompatActivity"),
    (java, "", "android.app.Activity"),
    (java, "import android.app.*;", "Activity"),
    (kotlin, "import android.app.Activity", "Activity()"),
    (kotlin, "import androidx.appcompat.app.AppCompatActivity", "AppCompatActivity()"),
    (kotlin, "import androidx.appcompat.app.AppCompatActivity as Base", "Base()"),
    (kotlin, "import android.app.*", "Activity()"),
]


@pytest.mark.parametrize(("build", "imports", "base"), FRAMEWORK_BASES)
def test_exact_scheme_and_host_guard_is_credited_in_framework_subclass(build, imports, base):
    report = scan(build(imports, base))
    assert URL_RULE not in rules(report), report
    assert report["metadata"]["native_flow"]["state"] == "checked", report


@pytest.mark.parametrize(("build", "imports", "base"), FRAMEWORK_BASES)
def test_unguarded_load_in_framework_subclass_is_still_reported(build, imports, base):
    assert URL_RULE in rules(scan(build(imports, base, guarded=False)))


@pytest.mark.parametrize(
    ("build", "imports", "base"),
    [
        # Kotlin and Java have no default Android imports: an unimported name is unknown.
        (java, "", "Activity"),
        (kotlin, "", "Activity()"),
        (java, "import com.vendor.VendorActivity;", "VendorActivity"),
        (kotlin, "import com.vendor.VendorActivity", "VendorActivity()"),
        # Another on-demand import may supply the simple name.
        (java, "import android.app.*;\nimport com.vendor.*;", "Activity"),
        (kotlin, "import android.app.*\nimport com.vendor.*", "Activity()"),
        # Every supertype must be known, including interfaces.
        (
            java,
            "import android.app.Activity;\nimport android.view.View;",
            "Activity implements View.OnClickListener",
        ),
        (kotlin, "import android.app.Activity\nimport android.view.View", "Activity(), View.OnClickListener"),
    ],
)
def test_unresolved_base_keeps_guard_uncredited(build, imports, base):
    report = scan(build(imports, base))
    assert URL_RULE in rules(report), report
    assert report["metadata"]["native_flow"]["state"] == "partial", report


BASE_ACTIVITY = """package app

import androidx.appcompat.app.AppCompatActivity

abstract class BaseActivity<VB> : AppCompatActivity() {
    BODY
}
"""


@pytest.mark.parametrize(
    ("body", "credited"),
    [
        ("abstract fun binding(): VB", True),
        ("class Uri", False),
        ("companion object {\n        class Uri\n    }", False),
    ],
)
def test_source_base_activity_is_credited_unless_it_declares_the_member_type(body, credited):
    report = scan(
        kotlin("", "BaseActivity<String>()"),
        ("app/BaseActivity.kt", BASE_ACTIVITY.replace("BODY", body)),
    )
    assert (URL_RULE in rules(report)) is not credited, report


def test_source_base_chain_needs_every_link_resolved():
    middle = (
        "app/Middle.kt",
        "package app\n\nopen class Middle : BaseActivity<Int>() {\n    fun x() {}\n}\n",
    )
    known = ("app/BaseActivity.kt", BASE_ACTIVITY.replace("BODY", "fun y() {}"))
    unknown = (
        "app/BaseActivity.kt",
        "package app\n\nimport com.vendor.VendorActivity\n\nopen class BaseActivity<VB> : VendorActivity()\n",
    )
    assert URL_RULE not in rules(scan(kotlin("", "Middle()"), middle, known))
    assert URL_RULE in rules(scan(kotlin("", "Middle()"), middle, unknown))
    cycle = ("app/Loop.kt", "package app\n\nopen class A : B()\nopen class B : A()\n")
    assert URL_RULE in rules(scan(kotlin("", "A()"), cycle))


def test_same_package_class_outranks_on_demand_framework_import():
    shadow = ("app/Activity.kt", "package app\n\nopen class Activity {\n    class Uri\n}\n")
    assert URL_RULE in rules(scan(kotlin("import android.app.*", "Activity()"), shadow))


def test_only_listed_framework_member_types_shadow(monkeypatch):
    source = java("import android.app.Activity;", "Activity")
    assert URL_RULE not in rules(scan(source))
    monkeypatch.setitem(native_flow.FRAMEWORK_BASE_MEMBER_TYPES, "android.app.Activity", frozenset({"Uri"}))
    assert URL_RULE in rules(scan(source))


def test_curated_framework_bases_list_their_member_types():
    bases = native_flow.FRAMEWORK_BASE_MEMBER_TYPES
    assert {
        "android.app.Activity",
        "android.app.Service",
        "android.app.IntentService",
        "android.app.Application",
        "android.app.Fragment",
        "android.content.BroadcastReceiver",
        "android.content.ContentProvider",
        "androidx.activity.ComponentActivity",
        "androidx.appcompat.app.AppCompatActivity",
        "androidx.fragment.app.FragmentActivity",
        "androidx.fragment.app.Fragment",
        "android.webkit.WebViewClient",
        "android.webkit.WebChromeClient",
    } <= set(bases)
    assert {"SavedState", "InstantiationException"} <= bases["androidx.fragment.app.Fragment"]
    assert {"SavedState", "InstantiationException"} <= bases["android.app.Fragment"]
    assert "PendingResult" in bases["android.content.BroadcastReceiver"]
    assert {"CustomViewCallback", "FileChooserParams"} <= bases["android.webkit.WebChromeClient"]
    # Inherited member types are listed too: Context.BindServiceFlags reaches every Activity.
    assert bases["android.app.Activity"] <= bases["androidx.appcompat.app.AppCompatActivity"]
    assert "BindServiceFlags" in bases["android.app.Service"]


ZIP = """package app

import android.app.Activity
import java.io.File
import java.io.FileOutputStream
import java.util.zip.ZipInputStream

class Unzip : Activity() {
    fun unzip(zis: ZipInputStream, dest: File) {
        val entry = zis.nextEntry ?: return
        val out = File(dest, entry.name)
        CHECK
        FileOutputStream(out)
    }
}
"""


@pytest.mark.parametrize(
    ("check", "reported"),
    [
        ("if (!out.canonicalPath.startsWith(dest.canonicalPath + File.separator)) return", False),
        ('if (entry.name.contains("..")) return', True),
        ("", True),
    ],
)
def test_zip_slip_canonical_containment_is_credited_in_activity(check, reported):
    report = scan(("app/Unzip.kt", ZIP.replace("CHECK", check)))
    assert (PATH_RULE in rules(report)) is reported, report
