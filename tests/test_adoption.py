"""Code scanning, MASWE traceability, agent distribution and MCP surface (1.4)."""

from __future__ import annotations

import asyncio
import json
import re
import subprocess
import sys
import tomllib
from importlib.resources import files
from pathlib import Path

import pytest
import yaml

from mobile_audit.audit import scan
from mobile_audit.cli import main
from mobile_audit.core import canonical_json, digest
from mobile_audit.maswe import RULE_WEAKNESSES, UNMAPPED, coverage_matrix, weakness_index, weaknesses_for
from mobile_audit.model_context import report_context
from mobile_audit.output import markdown, sarif
from mobile_audit.output import sarif_root as output_sarif_root
from mobile_audit.rules import rules
from mobile_audit.store import Store
from scripts.action_summary import sarif_root, summary
from scripts.check_sarif import problems

ROOT = Path(__file__).parents[1]
VERSION = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]["version"]
SCRIPTS = ROOT / "scripts"


@pytest.fixture
def demo_report(store, demo, monkeypatch):
    monkeypatch.setenv("APSA_PARSER_SANDBOX", "off")
    return scan(store, demo)


def test_maswe_index_is_the_complete_v1_release():
    index = weakness_index()
    ids = [w["id"] for w in index["weaknesses"]]
    assert ids == [f"MASWE-{n:04d}" for n in range(1, 79)]
    assert index["license"] == "CC-BY-SA-4.0" and re.fullmatch(r"[0-9a-f]{64}", index["source_sha256"])
    assert all(w["title"] and w["masvs"] and w["platform"] for w in index["weaknesses"])


def test_every_rule_has_a_reviewed_mapping_to_existing_weaknesses():
    known = {w["id"] for w in weakness_index()["weaknesses"]}
    assert set(RULE_WEAKNESSES).isdisjoint(UNMAPPED)
    for rule in rules():
        assert rule["id"] in RULE_WEAKNESSES or rule["id"] in UNMAPPED, rule["id"]
        assert rule["maswe"] == list(RULE_WEAKNESSES.get(rule["id"], ()))
    assert {w for mapped in RULE_WEAKNESSES.values() for w in mapped} <= known
    declared = json.loads(files("mobile_audit").joinpath("data", "rules.json").read_text())
    for rule in declared:
        assert rule["maswe"] == list(RULE_WEAKNESSES[rule["id"]]), rule["id"]
    assert weaknesses_for("CVE-2024-12345") == weaknesses_for("GHSA-xxxx") == ("MASWE-0044",)


def test_coverage_matrix_reports_states_findings_and_unassessed_weaknesses(demo_report):
    matrix = coverage_matrix(demo_report)
    rows = {row["id"]: row for row in matrix["weaknesses"]}
    assert len(rows) == 78 and sum(matrix["summary"].values()) == 78
    certificate = rows["MASWE-0027"]
    assert certificate["state"] == "checked" and certificate["scope"] == "partial"
    assert certificate["findings"] and "WEBVIEW-SSL-BYPASS" in certificate["checks"]
    assert rows["MASWE-0051"]["state"] == "not-assessed" and rows["MASWE-0051"]["checks"] == []
    assert rows["MASWE-0044"]["state"] == "not-run"
    assert rows["MASWE-0024"]["state"] == "not-run"
    android_only = {**demo_report, "inventory": {**demo_report["inventory"], "platforms": ["android"]}}
    assert {r["id"]: r for r in coverage_matrix(android_only)["weaknesses"]}["MASWE-0031"]["state"] == (
        "not-applicable"
    )
    partial = {
        **demo_report,
        "coverage": [*demo_report["coverage"], {"rule_id": "AST-CRYPTO-ECB", "state": "partial"}],
    }
    assert {r["id"]: r for r in coverage_matrix(partial)["weaknesses"]}["MASWE-0007"]["state"] == "partial"
    assert "## OWASP MASWE coverage" in markdown(demo_report)


def test_model_context_pages_the_maswe_section(demo_report):
    page = report_context(demo_report, section="maswe", limit=5)
    assert page["section_counts"]["maswe"] == 78
    assert len(page["maswe"]) == 5 and page["maswe"][0]["id"] == "MASWE-0001"


def test_sarif_meets_code_scanning_constraints_for_source_targets(demo_report):
    document = sarif(demo_report, "apps/mobile/")
    run = document["runs"][0]
    descriptors = {rule["id"]: rule for rule in run["tool"]["driver"]["rules"]}
    assert problems(json.dumps(document).encode()) == []
    for result in run["results"]:
        finding = next(f for f in demo_report["findings"] if f["id"] == result["properties"]["findingId"])
        assert result["partialFingerprints"] == {"apsaFindingIdentity/v1": finding["id"]}
        assert all(
            location["physicalLocation"]["artifactLocation"]["uri"].startswith("apps/mobile/")
            for location in result["locations"]
        )
        assert result["properties"]["status"] == finding["status"]
    ssl = descriptors["WEBVIEW-SSL-BYPASS"]["properties"]
    assert ssl["security-severity"] == "8.0" and "MASWE-0027" in ssl["tags"] and ssl["precision"] == "medium"
    notes = run["invocations"][0]["toolExecutionNotifications"]
    assert {n["associatedRule"]["id"] for n in notes if "associatedRule" in n} >= {"DEPENDENCY-CVE", "OS-CVE"}
    assert run["properties"]["maswe"]["summary"] == coverage_matrix(demo_report)["summary"]


def test_sarif_places_binary_findings_on_the_archive_and_never_omits_locations(store, monkeypatch):
    monkeypatch.setenv("APSA_PARSER_SANDBOX", "off")
    report = scan(store, ROOT / "tests/fixtures/binary_analysis/unsafe.apk")
    run = sarif(report, "build/app.apk")["runs"][0]
    assert run["results"]
    for result in run["results"]:
        for location in result["locations"]:
            assert location["physicalLocation"]["artifactLocation"]["uri"] == "build/app.apk"
    assert any(location.get("logicalLocations") for r in run["results"] for location in r["locations"])
    bare = {
        **report,
        "findings": [{**report["findings"][0], "evidence": [{"basis": "no path"}]}],
    }
    assert sarif(bare)["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"][
        "uri"
    ] == ("unsafe.apk")
    assert problems(json.dumps(sarif(report)).encode()) == []


def test_sarif_notifications_are_aggregated_and_bounded(demo_report):
    many = [{"rule_id": "DEPENDENCY-CVE", "state": "not-run"} for _ in range(50)]
    many += [{"rule_id": f"R-{n}", "state": "partial"} for n in range(300)]
    notes = sarif({**demo_report, "coverage": many})["runs"][0]["invocations"][0][
        "toolExecutionNotifications"
    ]
    assert len(notes) == 201 and "101 more" in notes[-1]["message"]["text"]
    assert any("(50 entries)" in n["message"]["text"] for n in notes)
    assert all(n["associatedRule"]["id"] for n in notes[:-1])
    unnamed = sarif(
        {**demo_report, "coverage": [{"rule_id": None, "state": "not-run"}, {"state": "partial"}]}
    )
    assert {
        n["associatedRule"]["id"] for n in unnamed["runs"][0]["invocations"][0]["toolExecutionNotifications"]
    } == {"unknown"}


def _finding(rule_id, status="candidate", severity="high", **evidence):
    return {
        "id": f"{rule_id}-id",
        "rule_id": rule_id,
        "title": rule_id,
        "severity": severity,
        "status": status,
        "evidence": [evidence],
        "remediation": "Fix it.",
        "masvs": "MASVS-CODE",
        "references": [],
    }


def test_sarif_locations_are_encoded_relative_and_never_local_paths(demo_report):
    findings = [
        _finding("WEBVIEW-SSL-BYPASS", path="src/My Activity#1.kt", line=3),
        _finding("SOURCE-TRUST-ALL-CERTS", path="/Users/someone/build/Gen.java"),
        _finding("ANDROID-ALLOW-BACKUP", path="../outside/AndroidManifest.xml"),
        _finding("DEPENDENCY-CVE", status="version-affected", dependency={"path": "app/build.gradle"}),
    ]
    run = sarif({**demo_report, "findings": findings}, "./apps//mobile/")["runs"][0]
    uris = [r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] for r in run["results"]]
    assert uris == [
        "apps/mobile/src/My%20Activity%231.kt",
        "apps/mobile",
        "apps/mobile",
        "apps/mobile/app/build.gradle",
    ]
    assert run["results"][1]["locations"][0]["logicalLocations"] == [
        {"fullyQualifiedName": "Gen.java", "kind": "resource"}
    ]
    assert "/Users/" not in json.dumps(run["results"])
    assert problems(json.dumps({"version": "2.1.0", "runs": [run]}).encode()) == []


def test_sarif_keeps_candidates_below_error_and_tags_candidate_rules(demo_report):
    findings = [
        _finding("WEBVIEW-SSL-BYPASS", path="a.kt"),
        _finding("SOURCE-TRUST-ALL-CERTS", status="configuration-confirmed", path="b.kt"),
        _finding("SOURCE-TRUST-ALL-CERTS", status="candidate", path="c.kt"),
    ]
    run = sarif({**demo_report, "findings": findings})["runs"][0]
    assert [r["level"] for r in run["results"]] == ["warning", "error", "warning"]
    rules = {rule["id"]: rule for rule in run["tool"]["driver"]["rules"]}
    assert "candidate" in rules["WEBVIEW-SSL-BYPASS"]["properties"]["tags"]
    assert rules["WEBVIEW-SSL-BYPASS"]["defaultConfiguration"]["level"] == "warning"
    assert "candidate" not in rules["SOURCE-TRUST-ALL-CERTS"]["properties"]["tags"]
    assert rules["SOURCE-TRUST-ALL-CERTS"]["defaultConfiguration"]["level"] == "error"


@pytest.mark.parametrize(
    ("value", "expected"),
    [(None, None), ("", ""), (".", ""), ("./a//b/", "a/b"), ("a\\b", "a/b")],
)
def test_sarif_root_normalizes_repository_paths(value, expected):
    assert output_sarif_root(value) == expected


@pytest.mark.parametrize("value", ["/abs", "C:/repo", "c:", "a/../../b", "..", "https://x/y"])
def test_sarif_root_rejects_paths_outside_the_repository(value):
    with pytest.raises(ValueError):
        output_sarif_root(value)


def test_maswe_states_never_overstate_execution(demo_report):
    rows = lambda report: {r["id"]: r for r in coverage_matrix(report)["weaknesses"]}  # noqa: E731
    checked_only = [c for c in demo_report["coverage"] if c.get("rule_id") != "AST-CRYPTO-ECB"]
    mixed = {
        **demo_report,
        "coverage": [
            *checked_only,
            {"rule_id": "AST-CRYPTO-ECB", "state": "checked"},
            {"rule_id": "AST-CRYPTO-ECB", "state": "not-run"},
        ],
    }
    assert rows(mixed)["MASWE-0007"]["state"] == "partial"
    neutral = {
        **demo_report,
        "coverage": [
            *checked_only,
            {"rule_id": "AST-CRYPTO-ECB", "state": "checked"},
            {"rule_id": "AST-CRYPTO-ECB", "state": "not-applicable"},
        ],
    }
    assert (
        rows(neutral)["MASWE-0007"]["state"]
        == rows(
            {**demo_report, "coverage": [*checked_only, {"rule_id": "AST-CRYPTO-ECB", "state": "checked"}]}
        )["MASWE-0007"]["state"]
    )
    found = {
        **demo_report,
        "coverage": [c for c in demo_report["coverage"] if c.get("rule_id") != "DEPENDENCY-CVE"],
        "findings": [_finding("CVE-2099-0001", status="version-affected") | {"origin": "intelligence"}],
    }
    row = rows(found)["MASWE-0044"]
    assert row["state"] == "partial" and row["findings"] == ["CVE-2099-0001-id"]
    many = {
        **demo_report,
        "findings": [_finding("WEBVIEW-SSL-BYPASS") | {"id": f"f{n:03d}"} for n in range(80)],
    }
    capped = rows(many)["MASWE-0027"]
    assert len(capped["findings"]) == 50 and capped["finding_count"] == 80
    assert "| partial |" in markdown(demo_report) or "| checked |" in markdown(demo_report)


def test_check_sarif_rejects_what_code_scanning_rejects(demo_report):
    document = sarif(demo_report)
    run = document["runs"][0]
    run["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] = "/abs/path.kt"
    run["results"][1].pop("partialFingerprints")
    run["tool"]["driver"]["rules"][0]["properties"]["security-severity"] = "high"
    found = problems(json.dumps(document).encode())
    assert any("repository-relative" in p for p in found)
    assert any("fingerprint" in p for p in found)
    assert any("security-severity" in p for p in found)


def test_cli_exports_maswe_and_validates_sarif_root(tmp_path, demo, monkeypatch, capsys):
    monkeypatch.setenv("APSA_PARSER_SANDBOX", "off")
    home = str(tmp_path / "home")
    out = tmp_path / "scan.sarif"
    assert (
        main(
            [
                "--json",
                "--home",
                home,
                "scan",
                str(demo),
                "--format",
                "sarif",
                "--out",
                str(out),
                "--sarif-root",
                "app",
            ]
        )
        == 0
    )
    assert json.loads(out.read_text())["runs"][0]["results"][0]["locations"][0]["physicalLocation"][
        "artifactLocation"
    ]["uri"].startswith("app/")
    capsys.readouterr()
    assert (
        main(
            [
                "--json",
                "--home",
                home,
                "reports",
                "export",
                "latest",
                "--format",
                "maswe",
                "--out",
                str(tmp_path / "m.json"),
            ]
        )
        == 0
    )
    exported = json.loads((tmp_path / "m.json").read_text())
    assert exported["report_id"].startswith("audit_") and len(exported["weaknesses"]) == 78
    capsys.readouterr()
    assert (
        main(
            [
                "--json",
                "--home",
                home,
                "reports",
                "export",
                "latest",
                "--format",
                "json",
                "--out",
                str(tmp_path / "r.json"),
                "--sarif-root",
                "x",
            ]
        )
        == 2
    )
    assert main(["--json", "--home", home, "scan", str(demo), "--sarif-root", "x"]) == 2
    saved = Store(Path(home))
    before = len(saved.reports(100))
    for bad in ("/abs", "../up"):
        capsys.readouterr()
        code = main(
            [
                "--json",
                "--home",
                home,
                "scan",
                str(demo),
                "--format",
                "sarif",
                "--out",
                str(out),
                "--sarif-root",
                bad,
            ]
        )
        assert code == 2 and "repository" in capsys.readouterr().out
    # Rejected before scanning: no report was saved.
    assert len(saved.reports(100)) == before
    saved.close()


def test_action_helper_paths_and_summary(tmp_path):
    workspace = tmp_path / "repo"
    (workspace / "android").mkdir(parents=True)
    assert sarif_root(str(workspace), str(workspace)) == ""
    assert sarif_root(str(workspace / "android"), str(workspace)) == "android"
    with pytest.raises(SystemExit):
        sarif_root(str(tmp_path), str(workspace))
    envelope = tmp_path / "result.json"
    envelope.write_text(
        json.dumps(
            {
                "ok": True,
                "exit_code": 3,
                "data": {
                    "id": "audit_x",
                    "tool_version": VERSION,
                    "rule_version": "r",
                    "findings": [{"severity": "high", "status": "candidate"}],
                    "coverage": [{"state": "partial"}],
                },
            }
        )
    )
    text = summary(str(envelope), "3")
    assert "incomplete" in text and "audit_x" in text and "high 1" in text
    envelope.write_text(json.dumps({"ok": False, "error": {"message": "boom"}, "exit_code": 2}))
    assert "did not complete: boom" in summary(str(envelope), "2")
    result = subprocess.run(
        [sys.executable, "-I", str(SCRIPTS / "action_summary.py"), "--report-id", str(envelope)],
        capture_output=True,
        text=True,
        check=True,
    )
    assert result.stdout == ""


def test_action_pins_dependencies_and_release_version():
    action = yaml.safe_load((ROOT / "action.yml").read_text())
    assert action["inputs"]["version"]["default"] == VERSION
    uses = [step["uses"] for step in action["runs"]["steps"] if "uses" in step]
    assert uses and all(re.fullmatch(r"[\w./-]+@[0-9a-f]{40}", value) for value in uses)
    for step in action["runs"]["steps"]:
        # Inputs reach shell code only through environment variables.
        assert "${{ inputs." not in step.get("run", ""), step.get("name")


def test_registry_and_plugin_metadata_follow_the_package_version():
    server = json.loads((ROOT / "server.json").read_text())
    assert server["name"] == "io.github.ictechgy/apsa" and server["version"] == VERSION
    assert [p["version"] for p in server["packages"]] == [VERSION]
    assert "<!-- mcp-name: io.github.ictechgy/apsa -->" in (ROOT / "README.md").read_text()
    marketplace = json.loads((ROOT / ".claude-plugin/marketplace.json").read_text())
    plugin_root = ROOT / marketplace["plugins"][0]["source"]
    plugin = json.loads((plugin_root / ".claude-plugin/plugin.json").read_text())
    assert plugin["version"] == VERSION
    command = json.loads((plugin_root / ".mcp.json").read_text())["mcpServers"]["apsa"]
    assert f"apsa@{VERSION}" in command["args"] and "${CLAUDE_PROJECT_DIR}" in command["args"]
    packaged = files("mobile_audit").joinpath("data", "skills", "apsa", "SKILL.md").read_bytes()
    assert (plugin_root / "skills/apsa/SKILL.md").read_bytes() == packaged


def test_mcp_tool_surface_is_fixed_and_annotated(tmp_path):
    from mobile_audit.mcp_server import create_server, manifest_sha256, tool_manifest

    snapshot = json.loads((ROOT / "tests/fixtures/mcp_tool_manifest.json").read_text())
    root = tmp_path / "root"
    root.mkdir()
    for variant, runtime in (("default", False), ("runtime", True)):
        server = create_server(tmp_path / "home", allow_runtime=runtime, roots=[root])
        manifest = tool_manifest(server)
        assert [(t["name"], t["annotations"]) for t in manifest] == [
            (name, annotations) for name, annotations in snapshot[variant]["tools"]
        ]
        # Update the snapshot deliberately when tool names, descriptions or schemas change.
        assert digest(canonical_json(manifest).encode()) == snapshot[variant]["sha256"]
        for tool in manifest:
            if tool["annotations"].get("readOnlyHint"):
                assert tool["annotations"].get("idempotentHint") is True
        options = server._mcp_server.create_initialization_options()
        assert options.capabilities.tools and options.capabilities.tools.listChanged is False
        # A client recomputes the hash from tools/list exactly as served.
        served = [
            tool.model_dump(by_alias=True, exclude_none=True) for tool in asyncio.run(server.list_tools())
        ]
        assert manifest_sha256(served) == snapshot[variant]["sha256"]


def test_mcp_security_document_publishes_the_pinned_manifest_hashes():
    snapshot = json.loads((ROOT / "tests/fixtures/mcp_tool_manifest.json").read_text())
    document = (ROOT / "docs/MCP_SECURITY.md").read_text()
    assert snapshot["default"]["sha256"] in document and snapshot["runtime"]["sha256"] in document
    assert f"APSA {VERSION}" in document
