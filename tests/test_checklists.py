"""Checklist views and finding history (1.4)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from mobile_audit.audit import scan
from mobile_audit.checklists import builtin_masvs, checklist_view, load_checklist, timeline
from mobile_audit.cli import main

TEMPLATE = Path(__file__).parents[1] / "examples/checklists/organization-template.toml"


def test_builtin_masvs_covers_every_weakness_once_per_control():
    items = builtin_masvs()["items"]
    assert {i["id"] for i in items} >= {"MASVS-STORAGE-1", "MASVS-NETWORK-1", "MASVS-PRIVACY-4"}
    assert all(i["maswe"] for i in items)


def test_template_statuses_never_claim_a_pass(store, demo, monkeypatch):
    monkeypatch.setenv("APSA_PARSER_SANDBOX", "off")
    report = scan(store, demo)
    view = checklist_view(report, load_checklist(str(TEMPLATE)))
    status = {row["id"]: row["status"] for row in view["items"]}
    assert status["EX-NETWORK-01"] == "findings"
    assert status["EX-RESILIENCE-01"] == "not-assessed"
    assert status["EX-CODE-01"] == "not-run"
    assert status["EX-STORAGE-01"] == "no-findings-in-checked-scope"
    assert "pass" not in json.dumps(view["summary"])


def test_checklist_status_follows_the_weakest_related_check(store, demo, monkeypatch, tmp_path):
    monkeypatch.setenv("APSA_PARSER_SANDBOX", "off")
    report = scan(store, demo)
    path = tmp_path / "c.toml"
    path.write_text('version = 1\nname = "x"\n[[item]]\nid = "ecb"\nrules = ["AST-CRYPTO-ECB"]\n')
    checklist = load_checklist(str(path))
    others = [c for c in report["coverage"] if c.get("rule_id") != "AST-CRYPTO-ECB"]

    def status(*states):
        coverage = others + [{"rule_id": "AST-CRYPTO-ECB", "state": s} for s in states]
        return checklist_view({**report, "coverage": coverage}, checklist)["items"][0]["status"]

    assert status("checked") == "no-findings-in-checked-scope"
    assert status("checked", "not-run") == "partial"
    assert status("checked", "not-applicable") == "no-findings-in-checked-scope"
    assert status("not-run") == "not-run"
    assert status() == "not-run"


@pytest.mark.parametrize(
    "text",
    [
        'version = 2\nname = "x"\n[[item]]\nid = "a"\n',
        'version = 1\nname = "x"\n',
        'version = 1\nname = "x"\n[[item]]\nid = "a"\nmaswe = ["MASWE-0999"]\n',
        'version = 1\nname = "x"\n[[item]]\nid = "a"\nrules = ["NOPE"]\n',
        'version = 1\nname = "x"\n[[item]]\nid = "a"\n[[item]]\nid = "a"\n',
        'version = 1\nname = "x"\n[[item]]\nid = "a"\nextra = 1\n',
    ],
)
def test_checklist_validation(tmp_path, text):
    path = tmp_path / "c.toml"
    path.write_text(text)
    with pytest.raises(ValueError):
        load_checklist(str(path))


def test_history_tracks_first_last_and_resolution(store, demo, monkeypatch):
    monkeypatch.setenv("APSA_PARSER_SANDBOX", "off")
    first = scan(store, demo)
    source = demo / "MainActivity.kt"
    source.write_text(source.read_text().replace("handler.proceed()", "handler.cancel()"))
    second = scan(store, demo)
    result = timeline(store, str(demo.resolve()))
    assert result["reports"] == [first["id"], second["id"]]
    resolved = [f for f in result["findings"] if f.get("resolved_in")]
    assert resolved and all(f["resolved_in"] == second["id"] for f in resolved)
    assert {f["rule_id"] for f in resolved} >= {"WEBVIEW-SSL-BYPASS"}
    assert result["open"] + result["resolved"] == len(result["findings"])


def test_cli_checklist_export_and_history(store, demo, tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("APSA_PARSER_SANDBOX", "off")
    home = str(store.home)
    assert main(["--json", "--home", home, "scan", str(demo)]) == 0
    out = tmp_path / "masvs.md"
    args = ["--json", "--home", home, "reports", "export", "latest", "--format", "checklist"]
    assert main([*args, "--checklist", "masvs-v2", "--out", str(out)]) == 0
    assert out.read_text().startswith("# OWASP MASVS v2.1 controls")
    assert main([*args, "--out", str(out)]) == 2
    capsys.readouterr()
    assert main(["--json", "--home", home, "reports", "history", str(demo)]) == 0
    assert json.loads(capsys.readouterr().out)["data"]["findings"]
