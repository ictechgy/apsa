"""Regression controls for independently reproduced external report findings."""

from copy import deepcopy
from typing import cast

import pytest

from mobile_audit.checklists import checklist_view, timeline
from mobile_audit.output import sarif
from mobile_audit.verify import verify_claim


def report(identifier="first", findings=None):
    return {
        "id": identifier,
        "created": identifier,
        "target": "/synthetic/app",
        "tool_version": "same",
        "rule_version": "same",
        "inventory": {
            "input_kind": "source",
            "platforms": ["android"],
            "source_selection": {"module": "app"},
        },
        "coverage": [
            {"rule_id": "ANDROID-CONFIG", "state": "checked"},
            {"rule_id": "AST-SQL-CONCAT", "state": "checked"},
        ],
        "findings": findings or [],
        "summary": {},
        "scope": "synthetic",
        "intel_snapshot": {},
        "warnings": [],
    }


def finding(status="candidate", rule="ANDROID-DEBUG", identifier="F-synthetic"):
    return {
        "id": identifier,
        "rule_id": rule,
        "status": status,
        "severity": "high",
        "title": "Synthetic finding",
        "remediation": "Review evidence",
        "masvs": "MASVS-CODE",
        "evidence": [{"path": "App.java", "line": 1}],
        "references": [],
    }


class History:
    def __init__(self, reports):
        self.reports = reports

    def target_reports(self, target, limit=200):
        return [{"id": r["id"]} for r in reversed(self.reports)]

    def report(self, identifier):
        return next(r for r in self.reports if r["id"] == identifier)


@pytest.mark.parametrize(
    "mutation",
    ["partial", "module", "not-run", "input-kind", "rule-version", "tool-version", "missing-coverage"],
)
def test_timeline_absence_is_inconclusive_without_comparable_complete_execution(mutation):
    first = report(findings=[finding()])
    after = report("second")
    if mutation == "partial":
        after["partial"] = True
    elif mutation == "module":
        after["inventory"]["source_selection"]["module"] = "library"
    elif mutation == "not-run":
        after["coverage"][0]["state"] = "not-run"
    elif mutation == "input-kind":
        after["inventory"]["input_kind"] = "apk"
    elif mutation == "rule-version":
        after["rule_version"] = "new"
    elif mutation == "tool-version":
        after["tool_version"] = "new"
    else:
        after["coverage"] = []
    result = timeline(History([first, after]), first["target"])
    assert result["resolved"] == 0
    assert result["findings"][0]["inconclusive_in"] == "second"


def test_complete_comparable_timeline_resolves_alias_and_reopens_on_observation():
    first = report(findings=[finding()])
    second = report("second")
    result = timeline(History([first, second]), first["target"])
    assert result["resolved"] == 1
    third = report("third", [finding()])
    reopened = timeline(History([first, second, third]), first["target"])
    assert reopened["open"] == 1
    assert "resolved_in" not in reopened["findings"][0]


def test_explicit_missing_check_remains_in_checklist_denominator():
    checklist = {
        "name": "synthetic",
        "items": [
            {"id": "one", "title": "one", "maswe": [], "rules": ["AST-SQL-CONCAT", "AST-PATH-TRAVERSAL"]}
        ],
    }
    assert checklist_view(report(), checklist)["items"][0]["status"] == "partial"


def test_checklist_resolves_config_coverage_alias():
    checklist = {
        "name": "synthetic",
        "items": [{"id": "one", "title": "one", "maswe": [], "rules": ["ANDROID-DEBUG"]}],
    }
    assert checklist_view(report(), checklist)["items"][0]["status"] == "no-findings-in-checked-scope"


@pytest.mark.parametrize("mutation", ["partial", "snapshot", "truncation", "online"])
def test_negative_claim_preserves_report_incompleteness(mutation):
    value = report()
    if mutation == "partial":
        value["partial"] = True
    elif mutation == "snapshot":
        value["inventory"]["input_snapshot"] = {"app_scope_complete": False}
    elif mutation == "truncation":
        value["inventory"]["source_analysis"] = {"input_observations_truncated": True}
    else:
        value["online_query"] = {"requested": True, "errors": ["Synthetic service failure"]}
    result = verify_claim(value, rule="AST-SQL-CONCAT")
    assert result["verdict"] == "partial"
    assert result["report_incomplete"] is True
    value["findings"] = [finding(rule="AST-SQL-CONCAT")]
    assert verify_claim(value, rule="AST-SQL-CONCAT")["verdict"] == "corroborated"


def test_complete_claim_retains_not_observed():
    assert verify_claim(report(), rule="AST-SQL-CONCAT")["verdict"] == "not-observed"


@pytest.mark.parametrize(
    "identifier", ["../escape", "a/b", "..", ".hidden", "/tmp/escape", "a" * 129, "a\\b", "a\x00b"]
)
def test_report_id_rejects_path_components_before_any_write(store, identifier):
    with pytest.raises(ValueError, match="report ID"):
        store.save_report(report(identifier))
    assert store.reports() == []
    assert not (store.home / "reports").exists()


@pytest.mark.parametrize("value", [None, [], "bad", {"source": "apple", "provenance": []}])
def test_malformed_vendor_record_is_controlled_error(store, value):
    with pytest.raises(ValueError):
        store.replace_vendor_documents("apple", [value], ["https://example.invalid/synthetic"])


@pytest.mark.parametrize("reverse", [False, True])
def test_sarif_candidate_does_not_inherit_confirmed_rule_rating(reverse):
    confirmed = finding("configuration-confirmed", identifier="F-confirmed")
    candidate = finding(identifier="F-candidate")
    findings = [confirmed, candidate]
    if reverse:
        findings.reverse()
    value = report(findings=findings)
    original = deepcopy(value)
    run = sarif(value)["runs"][0]
    descriptors = {r["id"]: r for r in run["tool"]["driver"]["rules"]}
    results = {r["properties"]["status"]: r for r in run["results"]}
    weak = results["candidate"]
    strong = results["configuration-confirmed"]
    assert weak["ruleId"] != strong["ruleId"]
    assert "security-severity" not in descriptors[weak["ruleId"]]["properties"]
    assert descriptors[strong["ruleId"]]["properties"]["security-severity"] == "8.0"
    assert weak["properties"]["apsaRuleId"] == "ANDROID-DEBUG"
    assert weak["partialFingerprints"]["apsaFindingIdentity/v1"] == "F-candidate"
    assert value == original


def test_sarif_candidate_descriptor_never_collides_with_input_rule_id():
    value = report(
        findings=[
            finding("configuration-confirmed"),
            finding(identifier="F-candidate"),
            finding(rule="ANDROID-DEBUG/candidate", identifier="F-other"),
        ]
    )
    run = sarif(value)["runs"][0]
    assert len({r["id"] for r in run["tool"]["driver"]["rules"]}) == 3


def test_empty_tui_enter_never_starts_scan():
    from types import SimpleNamespace

    from textual.widgets import Input

    from mobile_audit.tui import AuditApp

    calls = []
    double = SimpleNamespace(
        start_scan=lambda value: calls.append(value),
        query_one=lambda *args: SimpleNamespace(update=lambda value: None),
    )
    # The handler's app port is isolated; the submitted event is the real type.
    AuditApp.on_input_submitted(cast(AuditApp, double), Input.Submitted(Input(id="target"), "   "))
    assert calls == []


@pytest.mark.parametrize("command", ["verify", "demo"])
def test_cli_generated_or_rescan_target_has_explicit_binding(tmp_path, monkeypatch, capsys, command):
    from mobile_audit import cli

    calls = []
    target = tmp_path / "source"
    target.mkdir()

    def scan(store, path, **kwargs):
        calls.append((path, kwargs))
        return report()

    monkeypatch.setattr(cli, "scan", scan)
    args = ["--json", "--home", str(tmp_path / "home"), command]
    if command == "verify":
        args += [str(target), "--rescan", "--rule", "AST-SQL-CONCAT"]
    else:
        args += ["--out", str(tmp_path / "demo")]
    assert cli.main(args) == 0
    capsys.readouterr()
    assert len(calls) == 1
    path, options = calls[0]
    assert options["expected_target"] == path.resolve()


def test_intel_reverted_content_is_latest_without_mutating_snapshot(store):
    first = {"id": "CVE-2099-12345", "source": "synthetic", "modified": "same", "summary": "A"}
    second = {**first, "summary": "B"}
    store.upsert_intel([first])
    original = store.intel_history(first["id"])[0]
    snapshot = store.home / "intel-records" / (original["snapshot_hash"] + ".json")
    before = snapshot.read_bytes()
    store.upsert_intel([second])
    store.upsert_intel([first])
    rows = store.intel_history(first["id"])
    assert [row["summary"] for row in rows] == ["A", "B", "A"]
    assert rows[0]["snapshot_hash"] == rows[2]["snapshot_hash"]
    assert rows[0]["observation_kind"] == "content-change"
    assert snapshot.read_bytes() == before
    store.upsert_intel([rows[0]])
    assert len(store.intel_history(first["id"])) == 3


def test_v2_intel_migration_records_current_cached_state_and_is_idempotent(store):
    from mobile_audit.core import canonical_json
    from mobile_audit.store import Store

    first = {"id": "CVE-2099-12345", "source": "synthetic", "modified": "same", "summary": "A"}
    store.upsert_intel([first])
    store.upsert_intel([{**first, "summary": "B"}])
    # Reproduce a v2 cache that reverted A while its distinct payload history ended B.
    store.db.execute("UPDATE intel SET body=? WHERE id=?", (canonical_json(first), first["id"]))
    store.db.execute("DROP TABLE intel_observations")
    store.db.execute("PRAGMA user_version=2")
    store.db.commit()
    migrated = Store(store.home)
    try:
        rows = migrated.intel_history(first["id"])
        assert rows[0]["summary"] == "A"
        assert rows[0]["observation_kind"] == "cache-migration"
        assert len(rows) == 3
    finally:
        migrated.close()
    reopened = Store(store.home)
    try:
        assert len(reopened.intel_history(first["id"])) == 3
    finally:
        reopened.close()


def test_non_findings_context_page_does_not_assert_empty_findings():
    from mobile_audit.model_context import report_context

    value = report(findings=[finding()])
    result = report_context(value, section="coverage")
    assert "findings" not in result
    assert result["page"]["section"] == "coverage"
    assert result["section_counts"]["findings"] == 1


def test_cancelled_cli_job_is_incomplete_not_success(tmp_path, monkeypatch, capsys):
    import json

    from mobile_audit import cli

    monkeypatch.setattr(
        cli.jobs, "get", lambda *args: {"id": "synthetic", "state": "cancelled", "report_id": None}
    )
    assert cli.main(["--json", "--home", str(tmp_path / "home"), "jobs", "status", "synthetic"]) == 3
    result = json.loads(capsys.readouterr().out)
    assert result["ok"] is False and result["data"]["state"] == "cancelled"


@pytest.mark.parametrize("name", ["apsa", "quaygate", "mobile-audit"])
def test_known_prior_canonical_skill_upgrades_without_overwriting_edits(tmp_path, name):
    from pathlib import Path

    from mobile_audit.skills import install_skill, skill_status

    raw = (Path(__file__).parent / "fixtures/skills" / f"{name}-1.6.2prereview.md").read_bytes()
    destination = tmp_path / name
    destination.mkdir()
    installed = destination / "SKILL.md"
    installed.write_bytes(raw)
    assert skill_status(name, destination) == "outdated"
    assert install_skill(name, destination)["status"] == "installed"
    assert skill_status(name, destination) == "current"
    installed.write_bytes(raw + b"\nUser-authored change\n")
    assert skill_status(name, destination) == "modified"
    with pytest.raises(FileExistsError):
        install_skill(name, destination)
