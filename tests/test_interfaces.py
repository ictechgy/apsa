import asyncio
import json
import os
import subprocess
import sys

import pytest
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from pydantic import AnyUrl
from textual.widgets import DataTable, Input, Markdown, Static, TabbedContent, TextArea

from mobile_audit import jobs
from mobile_audit.audit import scan
from mobile_audit.cli import main
from mobile_audit.runtime import plan
from mobile_audit.tui import AuditApp


def test_cli_machine_errors_and_ci_threshold(store, demo, capsys):
    args = ["--home", str(store.home), "--json"]
    assert main(args + ["scan", str(demo), "--fail-on", "medium"]) == 4
    value = json.loads(capsys.readouterr().out)
    assert value["ok"] is True and value["exit_code"] == 4
    assert main(args + ["scan", "/does/not/exist"]) == 1
    assert json.loads(capsys.readouterr().out)["ok"] is False
    assert main(args + ["unknown-command"]) == 2
    assert json.loads(capsys.readouterr().out)["error"]["type"] == "UsageError"


def test_watch_partial_exit_matches_machine_envelope(store, capsys, monkeypatch):
    monkeypatch.setattr("mobile_audit.cli.sync", lambda *args: {"partial": True, "sources": []})
    assert main(["--home", str(store.home), "--json", "intel", "watch", "--cycles", "1", "--no-reaudit"]) == 3
    value = json.loads(capsys.readouterr().out)
    assert value["exit_code"] == 3 and value["data"]["partial"] is True


def test_foreground_cli_rejects_target_swap_before_parser_start(store, demo, tmp_path, capsys, monkeypatch):
    from mobile_audit import engine

    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "Private.java").write_text("class Private {}")
    original = engine.command

    def replaced(args, **options):
        demo.rename(tmp_path / "intended-source")
        demo.symlink_to(outside, target_is_directory=True)
        return original(args, **options)

    monkeypatch.setattr(engine, "command", replaced)
    assert main(["--home", str(store.home), "--json", "scan", str(demo)]) == 1
    result = json.loads(capsys.readouterr().out)
    assert "Authorized input moved" in result["error"]["message"]
    assert store.reports() == []


def test_cli_runs_from_unrelated_working_directory(tmp_path):
    env = dict(os.environ, MOBILE_AUDIT_HOME=str(tmp_path / "state"))
    result = subprocess.run(
        [sys.executable, "-m", "mobile_audit", "--json", "demo"],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["data"]["summary"]["findings"] >= 8


@pytest.mark.asyncio
async def test_mcp_stdio_discovery_scan_report_and_path_boundaries(store, demo):
    outside = scan(store, demo.parent)
    params = StdioServerParameters(
        command=sys.executable,
        args=["-m", "mobile_audit", "--home", str(store.home), "mcp", "--root", str(demo)],
    )
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            tools = await session.list_tools()
            names = {tool.name for tool in tools.tools}
            assert {"capabilities", "audit_scan", "reports_get", "runtime_plan"} <= names
            assert "runtime_execute" not in names
            result = await session.call_tool("audit_scan", {"target": str(demo)})
            assert not result.isError
            report = result.structuredContent
            assert report is not None
            assert report["summary"]["findings"] >= 8
            detail = await session.call_tool(
                "reports_get", {"report_id": report["report_id"], "finding_id": report["findings"][0]["id"]}
            )
            assert detail.structuredContent is not None and detail.structuredContent["evidence"]
            denied = await session.call_tool("audit_scan", {"target": str(demo.parent)})
            assert denied.isError is True
            assert (await session.call_tool("reports_get", {"report_id": outside["id"]})).isError
            listed = (await session.call_tool("reports_list", {})).structuredContent
            assert listed is not None and {r["id"] for r in listed["reports"]} == {report["report_id"]}
            newer = scan(store, demo.parent)
            latest = (await session.call_tool("reports_get", {})).structuredContent
            assert latest is not None and latest["report_id"] == report["report_id"]
            for name, arguments in [
                ("audit_reassess", {"report_id": newer["id"]}),
                ("dependency_check", {"report_id": newer["id"]}),
                ("runtime_plan", {"report_id": newer["id"]}),
                ("reports_compare", {"before": report["report_id"], "after": newer["id"]}),
            ]:
                assert (await session.call_tool(name, arguments)).isError, name
            with pytest.raises(Exception, match="outside configured MCP roots"):
                await session.read_resource(AnyUrl(f"mobile-audit://reports/{outside['id']}"))
            resources = await session.list_resources()
            assert any(str(r.uri) == "mobile-audit://rules" for r in resources.resources)
            prompts = await session.list_prompts()
            assert any(p.name == "audit_mobile_app" for p in prompts.prompts)


@pytest.mark.asyncio
async def test_mcp_runtime_opt_in_preview_and_report_boundary(store, demo):
    report = scan(store, demo)
    path = demo / "scenario.json"
    path.write_text(json.dumps(plan(report)))
    outside = scan(store, demo.parent)
    params = StdioServerParameters(
        command=sys.executable,
        args=["-m", "mobile_audit", "--home", str(store.home), "mcp", "--root", str(demo), "--allow-runtime"],
    )
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            assert "runtime_execute" in {t.name for t in (await session.list_tools()).tools}
            assert "runtime_start" in {t.name for t in (await session.list_tools()).tools}
            preview = await session.call_tool("runtime_execute", {"scenario_path": str(path)})
            assert preview.structuredContent is not None and preview.structuredContent["preview"] is True
            denied = await session.call_tool(
                "runtime_execute", {"scenario_path": str(path), "report_id": outside["id"]}
            )
            assert denied.isError
            assert store.report(report["id"])["runtime"] == []


def test_cli_policy_exits_baseline_and_read_only_evaluation(store, demo, tmp_path, capsys):
    args = ["--home", str(store.home), "--json"]
    policy = tmp_path / "policy.json"
    policy.write_text(json.dumps({"schema_version": 1, "allowed_statuses": ["candidate"]}))
    assert main(args + ["scan", str(demo), "--policy", str(policy)]) == 4
    first = json.loads(capsys.readouterr().out)["data"]
    baseline = first["report"]["id"]
    policy.write_text(json.dumps({"schema_version": 1, "allowed_statuses": ["candidate"], "only_new": True}))
    assert main(args + ["scan", str(demo), "--policy", str(policy), "--baseline", baseline]) == 0
    after = json.loads(capsys.readouterr().out)["data"]
    assert after["gate"]["counts"]["baseline_existing"] > 0
    before_count = len(store.reports())
    assert main(args + ["policy", "evaluate", after["report"]["id"], "--policy", str(policy)]) == 3
    assert json.loads(capsys.readouterr().out)["data"]["state"] == "incomplete"
    assert len(store.reports()) == before_count


@pytest.mark.asyncio
async def test_mcp_background_policy_and_job_boundaries(store, demo, tmp_path):
    outside = jobs.start(store, {"kind": "scan", "target": str(demo.parent)})
    policy = demo / "policy.json"
    policy.write_text(json.dumps({"schema_version": 1, "allowed_statuses": ["candidate"]}))
    params = StdioServerParameters(
        command=sys.executable,
        args=["-m", "mobile_audit", "--home", str(store.home), "mcp", "--root", str(demo)],
    )
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            names = {tool.name for tool in (await session.list_tools()).tools}
            assert {"audit_start", "jobs_status", "jobs_list", "jobs_cancel", "policy_evaluate"} <= names
            assert "runtime_start" not in names
            assert (await session.call_tool("audit_start", {"target": str(demo.parent)})).isError
            assert (await session.call_tool("jobs_status", {"job_id": outside["id"]})).isError
            assert (await session.call_tool("jobs_cancel", {"job_id": outside["id"]})).isError
            started = await session.call_tool("audit_start", {"target": str(demo)})
            assert not started.isError and started.structuredContent is not None
            identifier = started.structuredContent["id"]
            status = None
            for _ in range(100):
                status = (await session.call_tool("jobs_status", {"job_id": identifier})).structuredContent
                assert status is not None and "payload" not in status
                if status["state"] in jobs.TERMINAL:
                    break
                await asyncio.sleep(0.05)
            assert status is not None and status["state"] == "completed" and status["progress"] == 100
            listed = (await session.call_tool("jobs_list", {})).structuredContent
            assert listed is not None and {entry["id"] for entry in listed["jobs"]} == {identifier}
            gate = await session.call_tool(
                "policy_evaluate", {"policy_path": str(policy), "report_id": status["report_id"]}
            )
            assert gate.structuredContent is not None and gate.structuredContent["exit_code"] == 4
            assert (
                await session.call_tool("policy_evaluate", {"policy_path": str(tmp_path / "outside.json")})
            ).isError
            detail = await session.call_tool(
                "reports_get",
                {
                    "report_id": status["report_id"],
                    "finding_id": store.report(status["report_id"])["findings"][0]["id"],
                },
            )
            assert detail.structuredContent is not None and "excerpt" not in json.dumps(
                detail.structuredContent
            )


@pytest.mark.asyncio
async def test_tui_evaluates_policy_without_mutating_report(store, demo):
    initial = scan(store, demo)
    policy = demo / "policy.json"
    policy.write_text(json.dumps({"schema_version": 1, "allowed_statuses": ["candidate"]}))
    app = AuditApp(store.home)
    async with app.run_test(size=(140, 45)) as pilot:
        await pilot.click(app.query_one(TabbedContent).get_tab("policy"))
        app.query_one("#policy-path", Input).value = str(policy)
        await pilot.click("#policy-evaluate")
        await pilot.pause()
        assert "failed · exit 4" in app.query_one("#policy-result", Markdown)._markdown
        assert app.report is not None and app.report["id"] == initial["id"]
        assert len(store.reports()) == 1


@pytest.mark.asyncio
async def test_tui_scan_details_history_and_model_connection(store, demo):
    scan(store, demo)
    app = AuditApp(store.home)
    async with app.run_test(size=(140, 45)) as pilot:
        assert app.query_one("#findings", DataTable).row_count >= 8
        app.query_one("#findings", DataTable).focus()
        await pilot.press("enter")
        await pilot.pause()
        assert app.report is not None
        assert app.report["findings"][0]["title"] in app.query_one("#detail", Markdown)._markdown
        await pilot.click(app.query_one(TabbedContent).get_tab("models"))
        await pilot.pause()
        assert "mcpServers" in app.query_one("#model-help", Markdown)._markdown
        await pilot.click(app.query_one(TabbedContent).get_tab("reports"))
        await pilot.pause()
        assert app.query_one("#report-list", DataTable).row_count == 1
        await pilot.click(app.query_one(TabbedContent).get_tab("runtime"))
        await pilot.pause()
        await pilot.click("#runtime-plan")
        await pilot.pause()
        editor = app.query_one("#scenario-editor", TextArea)
        scenario = json.loads(editor.text)
        assert scenario["package"] == "com.example.mobileauditdemo"
        scenario["precondition"] = "Prepared my signed-in test app with the declared canary."
        editor.load_text(json.dumps(scenario))
        await pilot.click("#runtime-preview")
        await pilot.pause()
        assert "미리보기" in str(app.query_one("#runtime-status", Static).render())


@pytest.mark.asyncio
async def test_tui_demo_button_runs_audit_worker(store):
    app = AuditApp(store.home)
    async with app.run_test(size=(140, 45)) as pilot:
        await pilot.click("#demo")
        await pilot.pause()
        await asyncio.wait_for(app.workers.wait_for_complete(), timeout=10)
        assert app.report is not None and app.report["summary"]["findings"] >= 8
        assert app.busy is False
