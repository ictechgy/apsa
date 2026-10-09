"""verify_finding, project taint specifications and the added SQL sinks (1.5)."""

from __future__ import annotations

import json

import pytest

from mobile_audit.audit import scan
from mobile_audit.cli import main
from mobile_audit.source_analysis import analyze_sources
from mobile_audit.specs import load_specs, normalize
from mobile_audit.verify import verify_claim
from tests.test_jobs import terminal

PROVIDER = """package com.example.files;

import android.content.ContentProvider;
import android.database.sqlite.SQLiteDatabase;
import android.database.sqlite.SQLiteQueryBuilder;
import android.net.Uri;

public class FilesProvider extends ContentProvider {
    private SQLiteDatabase db;

    @Override
    public int delete(Uri uri, String where, String[] whereArgs) {
        return db.delete("files", "parent = 1 AND " + where, whereArgs);
    }

    @Override
    public int update(Uri uri, android.content.ContentValues values, String where, String[] args) {
        return db.update("files", values, "1 = 1", args);
    }

    public void build(SQLiteQueryBuilder builder, String where) {
        builder.appendWhere(where);
    }
}
"""

MANIFEST = """<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.example.files">
  <application>
    <provider android:name=".FilesProvider" android:authorities="com.example.files" android:exported="true" />
  </application>
</manifest>
"""

WRAPPERS = """package com.example.calls

import android.app.Activity
import android.os.Bundle

class CallActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val link = callState.currentLink()
        InAppBrowser.open(link)
        InAppBrowser.open("https://example.com/help")
        Analytics.open(link)
    }
}
"""

SPEC = """version = 1

[[source]]
id = "call-link"
method = "currentLink"
returns = "url"

[[sink]]
id = "in-app-browser"
kind = "webview-load"
method = "open"
receiver = "InAppBrowser"
"""


def rules_at(findings: list[dict]) -> list[tuple[str, int, str]]:
    return sorted(
        (item["rule_id"], item["evidence"][0]["line"], item["evidence"][0].get("sink", ""))
        for item in findings
    )


def test_provider_arguments_reach_added_sql_sinks():
    # A provider no other app can reach has no caller-supplied arguments.
    assert analyze_sources([("FilesProvider.java", PROVIDER)])["findings"] == []
    result = analyze_sources([("FilesProvider.java", PROVIDER)], None, {"FilesProvider"})
    found = rules_at(result["findings"])
    assert ("AST-SQL-CONCAT", 13, "SQLiteDatabase.delete") in found
    # A constant where clause with bound arguments is not SQL syntax from the caller.
    assert not any(line == 18 for _, line, _ in found)
    # appendWhere outside a provider override has no recognized source.
    assert not any(sink == "SQLiteQueryBuilder.appendWhere" for _, _, sink in found)


def test_specification_sources_and_sinks_add_candidates_only_where_declared(tmp_path):
    path = tmp_path / "specs.toml"
    path.write_text(SPEC)
    specs = load_specs(path)
    without = analyze_sources([("CallActivity.kt", WRAPPERS)])
    assert without["findings"] == []
    result = analyze_sources([("CallActivity.kt", WRAPPERS)], specs)
    assert rules_at(result["findings"]) == [
        ("AST-WEBVIEW-UNTRUSTED-URL", 10, "open (project specification sink in-app-browser)")
    ]
    finding = result["findings"][0]
    assert finding["status"] == "candidate"
    assert finding["evidence"][0]["project_specification"] == {"id": "in-app-browser", "kind": "webview-load"}
    assert "Project specification source call-link" in json.dumps(finding["evidence"][0]["sources"])


@pytest.mark.parametrize(
    "document",
    [
        {"version": 2, "source": []},
        {"version": 1},
        {"version": 1, "source": [{"id": "x", "method": "a.b"}]},
        {"version": 1, "source": [{"id": "Bad Id", "method": "a"}]},
        {"version": 1, "sink": [{"id": "x", "method": "a", "kind": "shell"}]},
        {"version": 1, "sink": [{"id": "x", "method": "a", "kind": "sql", "argument": 99}]},
        {"version": 1, "sink": [{"id": "x", "method": "a", "kind": "sql", "pattern": ".*"}]},
        {"version": 1, "source": [{"id": "x", "method": "a"}, {"id": "x", "method": "b"}]},
        {"version": 1, "extra": True, "source": [{"id": "x", "method": "a"}]},
    ],
)
def test_specifications_reject_patterns_unknown_fields_and_bad_values(document):
    with pytest.raises(ValueError):
        normalize(document)


def test_scan_records_the_specification_and_verify_cross_checks_claims(store, tmp_path, monkeypatch):
    monkeypatch.setenv("APSA_PARSER_SANDBOX", "off")
    app = tmp_path / "app"
    app.mkdir()
    (app / "CallActivity.kt").write_text(WRAPPERS)
    (app / "FilesProvider.java").write_text(PROVIDER)
    (app / "AndroidManifest.xml").write_text(MANIFEST)
    (tmp_path / "specs.toml").write_text(SPEC)
    specs = load_specs(tmp_path / "specs.toml")
    report = scan(store, app, specs=specs)
    assert report["inventory"]["project_specification"]["sinks"] == ["in-app-browser"]
    corroborated = verify_claim(report, path="CallActivity.kt", line=10, weakness="MASWE-0035")
    assert corroborated["verdict"] == "corroborated" and corroborated["strongest_status"] == "candidate"
    elsewhere = verify_claim(report, path=str(app / "CallActivity.kt"), line=40, weakness="MASWE-0035")
    assert elsewhere["verdict"] == "same-file-other-location"
    sql = verify_claim(report, path="FilesProvider.java", weakness="CWE-89")
    assert sql["verdict"] == "corroborated"
    not_observed = verify_claim(report, path="CallActivity.kt", weakness="MASWE-0008")
    assert not_observed["verdict"] == "not-observed" and "not proof" in not_observed["note"]
    assert verify_claim(report, weakness="MASWE-0051")["verdict"] == "not-assessed"
    assert verify_claim(report, weakness="MASWE-0044")["verdict"] == "not-run"
    bad_claims: list[dict] = [
        {"weakness": "MASWE-9999"},
        {"rule": "NOPE"},
        {},
        {"weakness": "MASWE-0001", "line": 3},
    ]
    for bad in bad_claims:
        with pytest.raises(ValueError):
            verify_claim(report, **bad)


def test_cli_specs_validate_and_verify(tmp_path, demo, monkeypatch, capsys):
    monkeypatch.setenv("APSA_PARSER_SANDBOX", "off")
    home = str(tmp_path / "home")
    spec = tmp_path / "specs.toml"
    spec.write_text(SPEC)
    assert main(["--json", "--home", home, "specs", "validate", str(spec)]) == 0
    assert json.loads(capsys.readouterr().out)["data"]["sha256"]
    spec.write_text("version = 1\n")
    assert main(["--json", "--home", home, "specs", "validate", str(spec)]) != 0
    capsys.readouterr()
    args = ["--json", "--home", home, "verify", str(demo), "--weakness", "MASWE-0027"]
    assert main([*args, "--path", "MainActivity.kt", "--line", "11"]) == 0
    assert json.loads(capsys.readouterr().out)["data"]["verdict"] == "corroborated"
    assert main([*args, "--report", "audit_missing", "--rescan"]) == 2
    assert main(["--json", "--home", home, "verify", str(demo), "--rule", "NOPE"]) == 2


def test_background_scans_carry_the_validated_specification(store, tmp_path, monkeypatch):
    from mobile_audit import jobs

    monkeypatch.setenv("APSA_PARSER_SANDBOX", "off")
    app = tmp_path / "app"
    app.mkdir()
    (app / "CallActivity.kt").write_text(WRAPPERS)
    (tmp_path / "specs.toml").write_text(SPEC)
    specs = load_specs(tmp_path / "specs.toml")
    job = jobs.start(store, {"kind": "scan", "target": str(app), "specs": specs})
    result = terminal(store, job["id"])
    assert result["state"] == "completed", result
    report = store.report(result["report_id"])
    assert report["inventory"]["project_specification"]["sha256"] == specs["sha256"]
    assert any("in-app-browser" in f["evidence"][0].get("sink", "") for f in report["findings"])
