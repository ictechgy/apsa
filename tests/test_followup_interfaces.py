"""Fresh report pairs and real stdio calls for the follow-up workflow."""

from __future__ import annotations

import copy
import json
import sys

import pytest

from mobile_audit.audit import scan
from mobile_audit.cli import main
from mobile_audit.core import canonical_json, digest, finding
from mobile_audit.followup import assess_finding_followup


@pytest.fixture
def saved_pair(store, tmp_path):
    root = tmp_path / "app"
    root.mkdir()
    item = finding(
        "AST-PATH-TRAVERSAL",
        "Synthetic path candidate",
        "medium",
        "candidate",
        [{"path": "Probe.kt", "line": 6, "function": "unpack", "sink": "File", "excerpt": "private canary"}],
        "Validate the destination.",
        origin="source-analysis",
    )
    before = {
        "id": "audit_followup_before",
        "created": "2026-10-23T00:00:00Z",
        "target": str(root),
        "tool_version": "synthetic-1",
        "rule_version": "synthetic-1",
        "inventory": {
            "input_kind": "source",
            "platforms": ["android"],
            "apps": [{"platform": "android", "package": "test.synthetic"}],
            "fingerprint": "a" * 64,
            "fingerprint_complete": True,
            "source_analysis": {"files": [{"path": "Probe.kt", "state": "checked"}]},
        },
        "findings": [item],
        "coverage": [
            {"rule_id": "AST-PATH-TRAVERSAL", "state": "checked", "method": "source-ast-local-flow"}
        ],
        "runtime": [],
    }
    after = copy.deepcopy(before)
    after.update(id="audit_followup_after", created="2026-10-23T00:01:00Z")
    after["inventory"]["fingerprint"] = "b" * 64
    shifted = copy.deepcopy(item["evidence"])
    shifted[0]["line"] = 16
    after["findings"] = [
        finding(
            item["rule_id"],
            item["title"],
            "medium",
            "candidate",
            shifted,
            item["remediation"],
            origin=item["origin"],
        )
    ]
    store.save_report(before)
    store.save_report(after)
    return root, before, after, item["id"]


def test_cli_followup_exports_the_same_bounded_evidence_without_changing_reports(
    store, saved_pair, tmp_path, capsys
):
    _, before, after, identifier = saved_pair
    expected = assess_finding_followup(before, after, identifier)
    out = tmp_path / "followup.json"
    assert (
        main(
            [
                "--json",
                "--home",
                str(store.home),
                "reports",
                "followup",
                before["id"],
                after["id"],
                "--finding",
                identifier,
                "--out",
                str(out),
            ]
        )
        == 0
    )
    envelope = json.loads(capsys.readouterr().out)
    assert envelope["data"] == json.loads(out.read_text()) == expected
    assert expected["observation"]["state"] == "possible-continuation"
    assert expected["comparability"]["state"] == "comparable"
    assert expected["remediation_proven"] is False
    assert "private canary" not in out.read_text()
    assert store.report(before["id"]) == before and store.report(after["id"]) == after
    unsigned = {key: value for key, value in expected.items() if key != "artifact_sha256"}
    assert expected["artifact_sha256"] == digest(canonical_json(unsigned).encode())


def test_cli_followup_unknown_finding_does_not_create_artifact(store, saved_pair, tmp_path, capsys):
    _, before, after, _ = saved_pair
    out = tmp_path / "absent.json"
    assert (
        main(
            [
                "--json",
                "--home",
                str(store.home),
                "reports",
                "followup",
                before["id"],
                after["id"],
                "--finding",
                "missing-finding",
                "--out",
                str(out),
            ]
        )
        != 0
    )
    assert json.loads(capsys.readouterr().out)["ok"] is False
    assert not out.exists()


@pytest.mark.asyncio
async def test_actual_mcp_followup_schema_parity_and_both_report_roots(store, saved_pair, tmp_path):
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client

    root, before, after, identifier = saved_pair
    outside = copy.deepcopy(after)
    outside.update(id="audit_followup_outside", target=str(tmp_path / "outside"))
    store.save_report(outside)
    params = StdioServerParameters(
        command=sys.executable,
        args=["-m", "apsa", "--home", str(store.home), "mcp", "--root", str(root)],
    )
    async with stdio_client(params) as streams:
        async with ClientSession(*streams) as session:
            await session.initialize()
            tool = next(
                tool for tool in (await session.list_tools()).tools if tool.name == "reports_followup"
            )
            assert tool.annotations is not None and tool.annotations.readOnlyHint is True
            assert tool.annotations.openWorldHint is False and tool.annotations.idempotentHint is True
            assert set(tool.inputSchema["required"]) == {"before", "after", "finding_id"}
            assert tool.inputSchema["properties"]["portable_inputs"]["default"] is False
            args = {"before": before["id"], "after": after["id"], "finding_id": identifier}
            result = await session.call_tool("reports_followup", args)
            assert not result.isError
            assert result.structuredContent == assess_finding_followup(before, after, identifier)
            for side in ("before", "after"):
                denied = await session.call_tool("reports_followup", {**args, side: outside["id"]})
                assert denied.isError
            assert (await session.call_tool("reports_followup", {**args, "finding_id": "missing"})).isError


def test_fresh_scans_track_line_movement_and_keep_partial_absence_visible(store, tmp_path, monkeypatch):
    monkeypatch.setenv("APSA_PARSER_SANDBOX", "off")
    root = tmp_path / "fresh-app"
    root.mkdir()
    source = root / "Probe.java"
    code = """import android.webkit.WebViewClient;
import android.webkit.WebView;
import android.webkit.SslErrorHandler;
import android.net.http.SslError;
class Probe extends WebViewClient {
    public void onReceivedSslError(WebView view, SslErrorHandler handler, SslError error) {
        handler.proceed();
    }
}
"""
    source.write_text(code)
    before = scan(store, root)
    identifier = next(
        item["id"] for item in before["findings"] if item["rule_id"] == "AST-WEBVIEW-SSL-BYPASS"
    )
    source.write_text("\n\n\n" + code)
    moved = scan(store, root)
    followup = assess_finding_followup(before, moved, identifier)
    assert followup["observation"]["state"] == "possible-continuation"
    assert followup["comparability"]["state"] == "limited"
    source.write_text(code.replace("handler.proceed()", "handler.cancel()"))
    changed = scan(store, root)
    followup = assess_finding_followup(before, changed, identifier)
    assert followup["observation"]["state"] == "no-compatible-observation"
    assert followup["comparability"]["state"] == "limited"
    assert followup["remediation_proven"] is False
