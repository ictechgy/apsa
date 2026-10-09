"""verify_finding, project taint specifications and the added SQL sinks (1.4)."""

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
        (
            item["rule_id"],
            item["evidence"][0]["line"],
            item["evidence"][0].get("sink_api") or item["evidence"][0].get("sink", ""),
        )
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
        {"version": True, "source": [{"id": "x", "method": "a"}]},
        {"version": 1.0, "source": [{"id": "x", "method": "a"}]},
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


def test_sql_sink_identity_keeps_the_method_name():
    result = analyze_sources([("FilesProvider.java", PROVIDER)], None, {"FilesProvider"})
    delete = next(f for f in result["findings"] if f["evidence"][0]["line"] == 13)
    assert delete["evidence"][0]["sink"] == "delete"
    assert delete["evidence"][0]["sink_api"] == "SQLiteDatabase.delete"


def test_receiver_specific_specification_entries_win(tmp_path):
    path = tmp_path / "specs.toml"
    path.write_text(
        SPEC.replace(
            '[[sink]]\nid = "in-app-browser"',
            '[[sink]]\nid = "any-open"\nkind = "sql"\nmethod = "open"\n\n[[sink]]\nid = "in-app-browser"',
        )
    )
    result = analyze_sources([("CallActivity.kt", WRAPPERS)], load_specs(path))
    sinks = {f["evidence"][0]["line"]: f["evidence"][0]["sink"] for f in result["findings"]}
    assert sinks[10] == "open (project specification sink in-app-browser)"


def test_verify_matches_files_by_path_not_by_bare_name(store, tmp_path, monkeypatch):
    monkeypatch.setenv("APSA_PARSER_SANDBOX", "off")
    app = tmp_path / "repo" / "android"
    (app / "feature").mkdir(parents=True)
    (app / "feature/CallActivity.kt").write_text(WRAPPERS)
    (tmp_path / "specs.toml").write_text(SPEC)
    report = scan(store, app, specs=load_specs(tmp_path / "specs.toml"))
    claim = {"line": 10, "weakness": "MASWE-0035"}
    assert verify_claim(report, path="feature/CallActivity.kt", **claim)["verdict"] == "corroborated"
    # A repository-relative claim whose prefix ends at the audited target.
    assert verify_claim(report, path="android/feature/CallActivity.kt", **claim)["verdict"] == "corroborated"
    assert verify_claim(report, path="ios/feature/CallActivity.kt", **claim)["verdict"] != "corroborated"
    # A bare file name could be any CallActivity.kt.
    bare = verify_claim(report, path="CallActivity.kt", **claim)
    assert bare["verdict"] == "path-unmatched" and bare["candidate_paths"] == ["feature/CallActivity.kt"]
    module = verify_claim(report, path="src/feature/CallActivity.kt", **claim)
    assert module["verdict"] == "path-unmatched" and "path-unmatched" in module["note"]
    assert verify_claim(report, path="feature/Missing.kt", **claim)["verdict"] == "file-not-analyzed"
    assert (
        verify_claim(report, path="AndroidManifest.xml", weakness="MASWE-0035")["verdict"]
        != "file-not-analyzed"
    )
    for outside in ("/etc/passwd", "../other/CallActivity.kt", str(tmp_path / "elsewhere.kt")):
        with pytest.raises(ValueError):
            verify_claim(report, path=outside, **claim)
    assert (
        verify_claim(report, path=str(app / "feature/CallActivity.kt"), **claim)["verdict"] == "corroborated"
    )
    assert (
        verify_claim(report, weakness="CWE-089")["weaknesses"]
        == verify_claim(report, weakness="CWE-89")["weaknesses"]
    )


def test_verify_accepts_symlinked_and_whole_target_claims(store, tmp_path, monkeypatch):
    monkeypatch.setenv("APSA_PARSER_SANDBOX", "off")
    real = tmp_path / "real"
    (real / "feature").mkdir(parents=True)
    (real / "feature/CallActivity.kt").write_text(WRAPPERS)
    link = tmp_path / "link"
    link.symlink_to(real, target_is_directory=True)
    (tmp_path / "specs.toml").write_text(SPEC)
    report = scan(store, link, specs=load_specs(tmp_path / "specs.toml"))
    claim = {"line": 10, "weakness": "MASWE-0035"}
    for spelling in (link / "feature/CallActivity.kt", real / "feature/CallActivity.kt"):
        assert verify_claim(report, path=str(spelling), **claim)["verdict"] == "corroborated"
    whole = verify_claim(report, path=str(link), weakness="MASWE-0035")
    assert whole["claim"]["path"] is None and whole["verdict"] == "corroborated"
