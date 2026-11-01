"""Common logging, preference, host-allowlist and file-mode spellings for regex source rules."""

from __future__ import annotations

import pytest

from mobile_audit.audit import scan

FILES = {
    "app/Logs.kt": """package a
import android.util.Log
import timber.log.Timber
class Logs {
    fun f(token: String, pw: String) {
        Timber.d("token=%s", token)
        Timber.tag("Auth").w("session %s", token)
        Log.wtf("T", "password " + pw)
        Timber.d("screen loaded")
    }
}
""",
    "web/app.js": """export function f(token) {
  console.error("token", token);
  console.info("ready");
}
""",
    "ios/Logs.swift": """import os
func f(token: String, password: String) {
    debugPrint(token)
    os_log("password %{public}@", password)
    debugPrint("ready")
}
""",
    "ios/Prefs.swift": """import Foundation
func save(token: String) {
    UserDefaults.standard.setValue(token, forKey: "authToken")
    UserDefaults.standard
        .set(token, forKey: "sessionToken")
    UserDefaults.standard.set(true, forKey: "onboarded")
}
""",
    "ios/Prefs.m": """#import <Foundation/Foundation.h>
void save(NSString *token) {
    [[NSUserDefaults standardUserDefaults] setObject:token forKey:@"authToken"];
    [[NSUserDefaults standardUserDefaults] setBool:YES forKey:@"onboarded"];
}
""",
    "app/Hosts.kt": """package a
import android.net.Uri
import android.webkit.WebView
class Hosts {
    fun f(web: WebView, uri: Uri, url: String) {
        if (uri.host == "example.com" || uri.host?.endsWith(".example.com") == true) web.loadUrl(url)
        if (uri.host?.endsWith("example.com") == true) web.loadUrl(url)
        if (url.endsWith(".example.com")) web.loadUrl(url)
    }
}
""",
    "app/Files.java": """package a;
import android.content.Context;
class Files {
    void f(Context context) throws Exception {
        context.openFileOutput("shared.txt", Context.MODE_WORLD_READABLE);
        context.getSharedPreferences("p", Context.MODE_WORLD_WRITEABLE);
        context.openFileOutput("private.txt", Context.MODE_PRIVATE);
    }
}
""",
}


@pytest.fixture
def report(store, tmp_path, monkeypatch):
    monkeypatch.setenv("APSA_PARSER_SANDBOX", "off")
    root = tmp_path / "patterns"
    for name, text in FILES.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
    return scan(store, root)


def lines(report, rule):
    return sorted(
        (item["evidence"][0]["path"], item["evidence"][0].get("line"))
        for item in report["findings"]
        if item["rule_id"] == rule
    )


def test_sensitive_log_calls_cover_timber_wtf_console_levels_and_swift_logging(report):
    assert lines(report, "STORAGE-SENSITIVE-LOG") == [
        ("app/Logs.kt", 6),
        ("app/Logs.kt", 7),
        ("app/Logs.kt", 8),
        ("ios/Logs.swift", 3),
        ("ios/Logs.swift", 4),
        ("web/app.js", 2),
    ]


def test_token_preferences_cover_set_value_chained_calls_and_objective_c(report):
    assert lines(report, "STORAGE-TOKEN-PREFS") == [
        ("ios/Prefs.m", 3),
        ("ios/Prefs.swift", 3),
        ("ios/Prefs.swift", 4),
    ]


def test_host_match_spares_dot_boundary_suffix_but_not_bare_or_url_suffix(report):
    assert lines(report, "WEBVIEW-HOST-MATCH") == [("app/Hosts.kt", 7), ("app/Hosts.kt", 8)]


def test_world_accessible_file_modes(report):
    assert lines(report, "SOURCE-WORLD-ACCESSIBLE-FILE") == [("app/Files.java", 5), ("app/Files.java", 6)]


AWS = "AKIA" + "SYNTHETIC123456X"


def test_xcconfig_is_screened_but_private_env_files_stay_excluded(store, tmp_path, monkeypatch):
    monkeypatch.setenv("APSA_PARSER_SANDBOX", "off")
    root = tmp_path / "creds"
    (root / "ios/Config").mkdir(parents=True)
    (root / "ios/Config/Release.xcconfig").write_text(f"AWS_KEY = {AWS}\n")
    (root / ".env").write_text(f"AWS_ACCESS_KEY_ID={AWS}\n")
    report = scan(store, root)
    assert lines(report, "SOURCE-HARDCODED-SECRET") == [("ios/Config/Release.xcconfig", 1)]
    assert AWS not in str(report["findings"])


HYBRID = {
    "src/Screens.js": """export function B(props) {
  const url = props.route.params.url;
  webRef.current.loadUrl(url);
}
export class C extends React.Component {
  go() {
    const url = this.props.route.params.url;
    webRef.current.loadUrl(url);
  }
}
export function Safe(props) {
  webRef.current.loadUrl("https://example.com/help");
}
""",
    "lib/db.dart": """import 'package:sqflite/sqflite.dart';

Future<void> b(Database db, Uri link) async {
  final id = Uri.base.queryParameters['id'];
  await db.rawDelete('DELETE FROM t WHERE id = $id');
  await db.execute('DELETE FROM t WHERE id = ${id}');
  await db.rawDelete('DELETE FROM t WHERE id = ?', [id]);
  await worker.execute('job $id');
}
""",
    "pubspec.yaml": "name: demo\ndependencies:\n  sqflite: ^2.0.0\n",
    "package.json": '{"name": "demo", "dependencies": {"react-native-webview": "13.0.0"}}\n',
}


def test_hybrid_props_route_params_and_sqflite_statement_sinks(store, tmp_path, monkeypatch):
    monkeypatch.setenv("APSA_PARSER_SANDBOX", "off")
    root = tmp_path / "hybrid"
    for name, text in HYBRID.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
    report = scan(store, root)
    assert lines(report, "HYBRID-UNTRUSTED-URL") == [("src/Screens.js", 3), ("src/Screens.js", 8)]
    assert lines(report, "HYBRID-SQL-INPUT") == [("lib/db.dart", 5), ("lib/db.dart", 6)]
