import os
import subprocess
from copy import deepcopy

import pytest

from mobile_audit import __version__
from mobile_audit.audit import correlate, os_cve_coverage
from mobile_audit.cli import integration_config
from mobile_audit.policy import evaluate
from mobile_audit.rules import static_checks
from mobile_audit.source_analysis import analyze_sources


def test_mixed_supported_and_unsupported_language_cannot_pass_required_ast():
    result = analyze_sources([("App.swift", "func safe() {}"), ("Legacy.m", "@implementation Legacy\n@end")])
    check = next(c for c in result["coverage"] if c["rule_id"] == "AST-WEBVIEW-UNTRUSTED-URL")
    assert check["state"] == "partial" and check["skipped_files"] == 1
    assert check["unsupported_languages"] == [".m"]
    report = {"findings": [], "coverage": result["coverage"]}
    assert evaluate(report, {"schema_version": 1, "required_rules": [check["rule_id"]]})["exit_code"] == 3


@pytest.mark.parametrize("count,state", [(29, "checked"), (30, "checked"), (31, "partial")])
def test_pattern_limit_reports_actual_truncation(count, state):
    inventory = {"platforms": ["android"], "android_config": [], "ios_config": []}
    findings, coverage = static_checks(inventory, [("App.java", 'Log.d("x", token);\n' * count)])
    assert len([f for f in findings if f["rule_id"] == "STORAGE-SENSITIVE-LOG"]) == min(count, 30)
    check = next(c for c in coverage if c["rule_id"] == "STORAGE-SENSITIVE-LOG")
    assert check["state"] == state
    assert check["truncated"] is (count > 30)


def test_dependency_match_status_tracks_version_evidence():
    dep = {"name": "example:lib", "ecosystem": "Maven", "version": "1.0", "confidence": "declared"}
    record = {"id": "CVE-2026-12345", "title": "Example", "severity": "high", "query_match": dep}
    inventory = {"platforms": ["android"], "dependencies": [dep]}
    findings, _ = correlate(inventory, [record])
    assert findings[0]["status"] == "candidate"
    assert evaluate({"findings": findings, "coverage": []}, {"schema_version": 1})["exit_code"] == 0
    exact = deepcopy(inventory)
    exact["dependencies"][0]["confidence"] = "exact"
    findings, _ = correlate(exact, [record])
    assert findings[0]["status"] == "version-affected"
    assert evaluate({"findings": findings, "coverage": []}, {"schema_version": 1})["exit_code"] == 4


@pytest.mark.parametrize("status,stale", [("ok", False), ("error", False), ("ok", True)])
def test_recent_intelligence_never_claims_historical_completeness(status, stale):
    check = os_cve_coverage(
        {"platform": "android"},
        [{"platform": "android"}],
        [{"source": "android", "status": status, "stale": stale}],
    )
    assert check["state"] == "partial"
    assert check["historical_backfill_complete"] is False
    assert (
        evaluate({"findings": [], "coverage": [check]}, {"schema_version": 1, "required_rules": ["OS-CVE"]})[
            "exit_code"
        ]
        == 3
    )


def test_os_correlation_no_environment_or_no_platform_data_is_not_run():
    assert os_cve_coverage(None, [], [])["state"] == "not-run"
    assert os_cve_coverage({"platform": "android"}, [{"platform": "ios"}], [])["state"] == "not-run"


def test_mcp_fallback_ignores_hostile_client_import_paths(store, tmp_path, monkeypatch):
    monkeypatch.setattr("mobile_audit.cli.shutil.which", lambda _: None)
    hostile = tmp_path / "client"
    hostile.mkdir()
    (hostile / "apsa.py").write_text('raise RuntimeError("client module executed")')
    config = integration_config(store.home, [tmp_path])["mcpServers"]["apsa"]
    completed = subprocess.run(
        [config["command"], *config["args"][:3], "--version"],
        cwd=hostile,
        env={**os.environ, "PYTHONPATH": str(hostile)},
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert completed.returncode == 0
    assert completed.stdout.strip() == __version__
    assert "client module executed" not in completed.stderr
