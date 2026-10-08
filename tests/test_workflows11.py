"""Model and portable team workflows exercised with synthetic inputs only."""

import copy
import json
from pathlib import Path

import pytest

from mobile_audit import mcp_server
from mobile_audit.audit import scan
from mobile_audit.baselines import baseline_artifact, load_baseline
from mobile_audit.cli import main
from mobile_audit.core import canonical_json, digest, finding, report_incomplete, write_json
from mobile_audit.model_context import finding_context, report_context
from mobile_audit.output import markdown
from mobile_audit.policy import evaluate
from mobile_audit.selection import select_source_module
from mobile_audit.skills import install_skill, skill_status
from tests.test_jobs import terminal


def source(path: Path, package="owned.app", *, debug=True):
    path.mkdir(parents=True, exist_ok=True)
    (path / "AndroidManifest.xml").write_text(
        '<manifest xmlns:android="http://schemas.android.com/apk/res/android" '
        f'package="{package}"><application android:debuggable="{str(debug).lower()}"/></manifest>'
    )
    (path / "Main.java").write_text("class Main {}")
    return path


def context_report():
    return {
        "id": "audit_synthetic",
        "created": "2026-10-08T00:00:00+00:00",
        "inventory": {"input_kind": "source", "fingerprint_complete": True},
        "findings": [
            finding(
                "TEST",
                "한글 증거 " + str(index),
                "high" if index % 2 else "medium",
                "candidate",
                [{"path": f"Main{index}.java", "line": index + 1, "excerpt": "PRIVATE_SOURCE"}],
                "Review this location",
            )
            for index in range(200)
        ],
        "summary": {"findings": 200, "incomplete": True},
        "coverage": [{"rule_id": "TEST", "state": "partial"}],
        "intel_snapshot": [],
        "warnings": ["Review partial coverage"],
        "runtime": [],
    }


def test_model_pages_recover_all_filtered_findings_without_leaking_excerpts():
    report = context_report()
    expected = [item["id"] for item in report["findings"] if item["severity"] == "high"]
    cursor, observed = 0, []
    while True:
        result = report_context(report, cursor=cursor, limit=17, max_bytes=4096, severity="high")
        raw = json.dumps(result, ensure_ascii=False).encode()
        assert len(raw) == result["response_bytes"] <= 4096
        assert result["audit_incomplete"] is True
        assert result["page"]["total"] == 100
        assert not result["page"]["oversized_indices"]
        assert b"PRIVATE_SOURCE" not in raw
        observed.extend(item["id"] for item in result["findings"])
        next_cursor = result["page"]["next_cursor"]
        if next_cursor is None:
            break
        assert next_cursor > cursor
        cursor = next_cursor
    assert observed == expected
    assert report["findings"][0]["evidence"][0]["excerpt"] == "PRIVATE_SOURCE"
    assert report_context(report, section="coverage")["coverage"][0]["state"] == "partial"


def test_oversized_record_advances_with_explicit_omission_and_evidence_is_pageable():
    report = context_report()
    report["findings"][0]["remediation"] = "한" * 10000
    result = report_context(report, limit=1, max_bytes=4096)
    assert result["findings"] == []
    assert result["page"]["oversized_indices"] == [0]
    assert result["page"]["next_cursor"] == 1
    assert result["partial_response"] is True
    item = report["findings"][1]
    item["evidence"] *= 25
    page = finding_context(item, cursor=20, limit=5)
    assert len(page["evidence"]) == 5 and page["page"]["next_cursor"] is None
    assert "excerpt" not in json.dumps(page)
    report["inventory"]["package"] = "large" * 10000
    reduced = report_context(report, cursor=1, max_bytes=4096)
    assert reduced["metadata_truncated"] and reduced["audit_incomplete"]
    assert reduced["report_id"] == report["id"]


@pytest.mark.parametrize(
    "options",
    [
        {"cursor": -1},
        {"cursor": True},
        {"cursor": 201},
        {"limit": 0},
        {"limit": 101},
        {"max_bytes": 4095},
        {"max_bytes": 262145},
        {"section": "unknown"},
        {"section": "coverage", "severity": "high"},
        {"severity": "unknown"},
        {"status": "safe"},
    ],
)
def test_bad_page_contract_is_explicit(options):
    with pytest.raises(ValueError):
        report_context(context_report(), **options)


def test_source_configuration_selection_does_not_merge_app_variants(store, tmp_path):
    root = tmp_path / "repository"
    source(root / "debug", debug=True)
    source(root / "release", debug=False)
    ambiguous = scan(store, root)
    assert report_incomplete(ambiguous) and ambiguous["inventory"]["configuration_ambiguous"]
    assert all(item["status"] == "candidate" for item in ambiguous["findings"])
    debug = scan(store, root, configuration="debug/AndroidManifest.xml")
    release = scan(store, root, configuration="release/AndroidManifest.xml")
    assert not report_incomplete(debug) and not report_incomplete(release)
    assert [item["path"] for item in release["inventory"]["android_config"]] == [
        "release/AndroidManifest.xml"
    ]
    assert any(item["rule_id"] == "ANDROID-DEBUG" for item in debug["findings"])
    assert not any(item["rule_id"] == "ANDROID-DEBUG" for item in release["findings"])
    assert evaluate(release, {"schema_version": 1, "only_new": True}, debug)["exit_code"] == 3
    assert "Audit execution: **incomplete**" in markdown(ambiguous)


@pytest.mark.parametrize(
    "configuration",
    ["../AndroidManifest.xml", "/AndroidManifest.xml", "missing/Info.plist", "./debug/AndroidManifest.xml"],
)
def test_bad_configuration_cannot_become_a_complete_report(store, tmp_path, configuration):
    root = source(tmp_path / "owned")
    with pytest.raises(ValueError):
        scan(store, root, configuration=configuration)
    assert store.reports() == []


def test_mcp_selected_module_background_job_preserves_scope(store, tmp_path):
    root = tmp_path / "repository"
    source(root / "owned")
    source(root / "other", package="other.app")
    server = mcp_server.create_server(store.home, roots=[root])
    tool = server._tool_manager.get_tool("audit_start")
    assert tool is not None
    queued = tool.fn(target=str(root), source_module="owned", configuration="AndroidManifest.xml")
    result = terminal(store, queued["id"])
    assert result["state"] == "completed", result
    report = store.report(result["report_id"])
    assert report["inventory"]["package"] == "owned.app"
    assert report["inventory"]["source_selection"]["module"] == "owned"
    assert report["target"] == str(root / "owned")
    alias = root / "alias"
    alias.symlink_to(root / "other", target_is_directory=True)
    for module in ("../other", "/other", "alias", "missing", "./owned"):
        with pytest.raises(ValueError):
            select_source_module(root, module)


def test_cli_portable_baseline_works_in_fresh_store_and_exports_decision(tmp_path, capsys):
    root = source(tmp_path / "source")
    home_a, home_b = tmp_path / "state-a", tmp_path / "state-b"
    prefix = ["--json", "--home", str(home_a)]
    assert main(prefix + ["scan", str(root)]) == 0
    before = json.loads(capsys.readouterr().out)["data"]
    baseline = tmp_path / "approved-baseline.json"
    assert (
        main(
            prefix
            + [
                "reports",
                "export",
                before["id"],
                "--format",
                "baseline",
                "--out",
                str(baseline),
                "--approved-by",
                "Fixture reviewer",
                "--approval-reference",
                "fixture-review/11",
            ]
        )
        == 0
    )
    exported = json.loads(capsys.readouterr().out)["data"]
    assert exported["sha256"] == digest(baseline.read_bytes())
    assert "excerpt" not in baseline.read_text()
    policy = tmp_path / "policy.json"
    policy.write_text(json.dumps({"schema_version": 1, "only_new": True}))
    output = tmp_path / "report.json"
    args = [
        "--json",
        "--home",
        str(home_b),
        "scan",
        str(root),
        "--policy",
        str(policy),
        "--baseline-file",
        str(baseline),
        "--baseline-sha256",
        exported["sha256"],
        "--out",
        str(output),
    ]
    assert main(args) == 0
    result = json.loads(capsys.readouterr().out)["data"]
    decision = json.loads(output.with_name(output.name + ".decision.json").read_text())
    assert decision["gate"] == result["gate"] and decision["gate"]["counts"]["baseline_existing"] > 0
    assert decision["report_sha256"] == digest(canonical_json(result["report"]).encode())
    assert decision["policy_sha256"] == digest(canonical_json(decision["policy"]).encode())
    assert decision["baseline_provenance"]["artifact_sha256"] == exported["sha256"]
    baseline.write_bytes(baseline.read_bytes() + b" ")
    assert main(args) == 1
    assert "approved SHA-256" in json.loads(capsys.readouterr().out)["error"]["message"]


def test_portable_baseline_requires_approval_completeness_and_external_hash(store, tmp_path):
    report = scan(store, source(tmp_path / "owned"))
    for approver, reference in (("", "review"), ("reviewer", "")):
        with pytest.raises(ValueError, match="explicit approver"):
            baseline_artifact(report, approver, reference)
    incomplete = copy.deepcopy(report)
    incomplete["coverage"][0]["state"] = "partial"
    with pytest.raises(ValueError, match="incomplete"):
        baseline_artifact(incomplete, "reviewer", "review")
    artifact = baseline_artifact(report, "reviewer", "review")
    path = tmp_path / "baseline.json"
    write_json(path, artifact)
    with pytest.raises(ValueError, match="externally approved"):
        load_baseline(path, "")
    loaded = load_baseline(path, digest(path.read_bytes()))
    other = copy.deepcopy(report)
    other["inventory"]["apps"][0]["package"] = "other.app"
    assert evaluate(other, {"schema_version": 1, "only_new": True}, loaded)["exit_code"] == 3
    artifact["report"]["coverage"] = ["malformed"]
    artifact["report_sha256"] = digest(canonical_json(artifact["report"]).encode())
    write_json(path, artifact)
    with pytest.raises(ValueError, match="unsupported"):
        load_baseline(path, digest(path.read_bytes()))


def test_mcp_baseline_export_authorizes_paths_and_does_not_follow_replaced_parent(
    store, tmp_path, monkeypatch
):
    root = source(tmp_path / "owned")
    report = scan(store, root)
    server = mcp_server.create_server(store.home, roots=[root])
    export = server._tool_manager.get_tool("reports_export_baseline")
    assert export is not None
    with pytest.raises(ValueError, match="outside configured"):
        export.fn(
            report_id=report["id"],
            output_path=str(tmp_path / "outside.json"),
            approved_by="reviewer",
            approval_reference="review",
        )
    output = root / "baseline.json"
    result = export.fn(
        report_id=report["id"], output_path=str(output), approved_by="reviewer", approval_reference="review"
    )
    assert digest(output.read_bytes()) == result["sha256"]
    with pytest.raises(FileExistsError):
        export.fn(
            report_id=report["id"],
            output_path=str(output),
            approved_by="reviewer",
            approval_reference="review",
        )
    destination = root / "exports"
    destination.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    original = mcp_server.open_directory

    def replaced(path):
        destination.rename(root / "old-exports")
        destination.symlink_to(outside, target_is_directory=True)
        return original(path)

    monkeypatch.setattr(mcp_server, "open_directory", replaced)
    with pytest.raises(OSError):
        export.fn(
            report_id=report["id"],
            output_path=str(destination / "baseline.json"),
            approved_by="reviewer",
            approval_reference="review",
        )
    assert not (outside / "baseline.json").exists()


def test_mcp_dependency_errors_cannot_exceed_model_budget(store, tmp_path, monkeypatch):
    root = source(tmp_path / "owned")
    report = scan(store, root)
    server = mcp_server.create_server(store.home, roots=[root])
    tool = server._tool_manager.get_tool("dependency_check")
    assert tool is not None
    monkeypatch.setattr(mcp_server, "query_dependencies", lambda *args: ([], ["한" * 10000] * 100))
    result = tool.fn(report_id=report["id"])
    assert len(json.dumps(result, ensure_ascii=False).encode()) == result["response_bytes"] < 65536
    assert result["dependency_query_error_count"] == 100
    assert result["dependency_query_errors_truncated"] and result["partial_response"]


@pytest.mark.parametrize("name", ["apsa", "quaygate", "mobile-audit"])
def test_106_skills_upgrade_and_preserve_user_customizations(tmp_path, name):
    old = (Path(__file__).parent / "fixtures/skills" / f"{name}-1.0.6.md").read_bytes()
    destination = tmp_path / name
    destination.mkdir()
    path = destination / "SKILL.md"
    path.write_bytes(old)
    assert skill_status(name, destination) == "outdated"
    assert install_skill(name, destination)["status"] == "installed"
    assert skill_status(name, destination) == "current"
    path.write_bytes(old + b"\nUser customization\n")
    with pytest.raises(FileExistsError):
        install_skill(name, destination)
