"""Imported SARIF results as candidate external evidence (1.5)."""

from __future__ import annotations

import json

import pytest

from mobile_audit.audit import scan
from mobile_audit.cli import main
from mobile_audit.ingest import external_findings, ingest
from mobile_audit.maswe import coverage_matrix
from mobile_audit.verify import verify_claim


def document(results: list[dict]) -> dict:
    return {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "OtherScanner",
                        "version": "9.9",
                        "rules": [
                            {
                                "id": "tls/accept-all",
                                "shortDescription": {"text": "TLS errors ignored"},
                                "helpUri": "https://example.com/tls",
                                "properties": {
                                    "tags": ["security", "external/cwe/cwe-295"],
                                    "security-severity": "8.1",
                                },
                            },
                            {"id": "style/naming", "properties": {"tags": ["maintainability"]}},
                        ],
                    }
                },
                "results": results,
            }
        ],
    }


def result(
    uri: str, line: int | None = 11, rule: str = "tls/accept-all", message: str = "proceed() called"
) -> dict:
    region = {"startLine": line} if line else {}
    return {
        "ruleId": rule,
        "level": "error",
        "message": {"text": message},
        "locations": [{"physicalLocation": {"artifactLocation": {"uri": uri}, "region": region}}],
    }


def test_parsing_is_bounded_sanitized_and_mapped():
    raw = json.dumps(
        document(
            [
                result("app/MainActivity.kt", message="token=abc123 leaked"),
                result("/etc/passwd"),
                result("../outside.kt"),
                result("app/Other.kt", rule="style/naming"),
            ]
        )
    ).encode()
    findings, record = external_findings(raw, "other scanner", root="app")
    assert record["results"] == 4 and record["imported"] == 2 and record["skipped"] == 2
    tls = findings[0]
    assert tls["rule_id"] == "EXT-other-scanner-tls-accept-all" and tls["status"] == "candidate"
    assert tls["severity"] == "high" and "MASWE-0027" in tls["maswe"] and tls["cwe"] == ["CWE-295"]
    assert tls["evidence"][0]["path"] == "MainActivity.kt" and "abc123" not in json.dumps(tls)
    assert findings[1]["severity"] == "medium" and findings[1]["maswe"] == []
    with pytest.raises(ValueError):
        external_findings(b'{"version": "2.0.0"}', "x")


def test_ingest_links_corroboration_and_replaces_reimports(store, demo, tmp_path, monkeypatch):
    monkeypatch.setenv("APSA_PARSER_SANDBOX", "off")
    base = scan(store, demo)
    sarif = tmp_path / "other.sarif"
    sarif.write_text(json.dumps(document([result("MainActivity.kt"), result("Demo.swift", line=None)])))
    derived = ingest(store, base["id"], sarif, "other")
    assert derived["parent_report"] == base["id"]
    external = [f for f in derived["findings"] if f.get("origin") == "external"]
    assert len(external) == 2
    linked = external[0]["evidence"][0]["corroborated_by"]
    native = {f["id"]: f for f in derived["findings"] if f.get("origin") != "external"}
    assert linked and all(native[i]["rule_id"].endswith("SSL-BYPASS") for i in linked)
    assert native[linked[0]]["external_corroboration"][0]["tool"] == "other"
    coverage = {c["rule_id"]: c for c in derived["coverage"]}
    assert coverage["EXTERNAL-other"]["state"] == "not-applicable"
    assert derived["external_inputs"][-1]["imported"] == 2
    again = ingest(store, derived["id"], sarif, "other")
    assert sum(f.get("origin") == "external" for f in again["findings"]) == 2
    assert len(native[linked[0]].get("external_corroboration", [])) == 1
    rows = {r["id"]: r for r in coverage_matrix(again)["weaknesses"]}
    assert set(f["id"] for f in external) & set(rows["MASWE-0027"]["findings"])
    assert (
        verify_claim(again, weakness="CWE-295", path="MainActivity.kt", line=11)["verdict"] == "corroborated"
    )


def test_cli_ingest_reports_errors(store, demo, tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("APSA_PARSER_SANDBOX", "off")
    home = str(store.home)
    assert main(["--json", "--home", home, "scan", str(demo)]) == 0
    capsys.readouterr()
    good = tmp_path / "ok.sarif"
    good.write_text(json.dumps(document([result("MainActivity.kt")])))
    assert (
        main(
            [
                "--json",
                "--home",
                home,
                "reports",
                "ingest",
                "latest",
                "--sarif",
                str(good),
                "--tool",
                "codeql",
            ]
        )
        == 0
    )
    assert json.loads(capsys.readouterr().out)["data"]["external_input"]["imported"] == 1
    bad = tmp_path / "bad.sarif"
    bad.write_text("{}")
    assert (
        main(["--json", "--home", home, "reports", "ingest", "latest", "--sarif", str(bad), "--tool", "x"])
        == 2
    )
