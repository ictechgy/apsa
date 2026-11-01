"""A Java constructor body is a statement block: its early exits guard the statements after them."""

from __future__ import annotations

import pytest

from mobile_audit.source_analysis import analyze_sources

URL = """package a;
import android.content.Intent;
import android.net.Uri;
import android.webkit.WebView;
class Loader {
    MEMBER(Intent intent, WebView webView) {
        Uri u = intent.getData();
        GUARD
        webView.loadUrl(u.toString());
    }
}
"""
PATH = """package a;
import android.content.Intent;
import java.io.File;
import java.io.FileOutputStream;
class Saver {
    MEMBER(Intent intent, File base) throws Exception {
        String name = intent.getStringExtra("name");
        File target = new File(base, name);
        String canonical = target.getCanonicalPath();
        GUARD
        new FileOutputStream(canonical);
    }
}
"""
URL_GUARD = 'if ("https".equals(u.getScheme()) && "example.com".equals(u.getHost())) { } else { return; }'
PATH_GUARD = "if (!canonical.startsWith(base.getCanonicalPath() + File.separator)) return;"


def rules(template: str, member: str, guard: str) -> set[str]:
    path = "app/Loader.java" if template is URL else "app/Saver.java"
    report = analyze_sources([(path, template.replace("MEMBER", member).replace("GUARD", guard))])
    assert report["metadata"]["native_flow"]["state"] == "checked", report["metadata"]["native_flow"]
    return {item["rule_id"] for item in report["findings"]}


@pytest.mark.parametrize(
    ("template", "member", "rule"),
    [
        (URL, "void load", "AST-WEBVIEW-UNTRUSTED-URL"),
        (URL, "Loader", "AST-WEBVIEW-UNTRUSTED-URL"),
        (PATH, "void save", "AST-PATH-TRAVERSAL"),
        (PATH, "Saver", "AST-PATH-TRAVERSAL"),
    ],
    ids=["url-method", "url-constructor", "path-method", "path-constructor"],
)
def test_early_exit_guards_constructor_like_method(template, member, rule):
    guard = URL_GUARD if template is URL else PATH_GUARD
    assert rules(template, member, "") == {rule}
    assert rules(template, member, guard) == set()
