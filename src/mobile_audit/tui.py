from __future__ import annotations

import json
import time
from pathlib import Path

import tree_sitter_json
from textual import work
from textual.app import App, ComposeResult
from textual.containers import Horizontal, VerticalScroll
from textual.widgets import (
    Button,
    Checkbox,
    DataTable,
    Footer,
    Header,
    Input,
    Label,
    Markdown,
    Static,
    TabbedContent,
    TabPane,
    TextArea,
)
from tree_sitter import Language

from . import jobs
from .cli import demo_target, integration_config
from .core import write_json
from .intel import source_health, sync
from .policy import evaluate, load_policy
from .runtime import plan, validate_scenario
from .store import Store


class AuditApp(App):
    TITLE = "APSA (앱사)"
    SUB_TITLE = "Android · iOS · evidence · MCP"
    BINDINGS = [
        ("ctrl+q", "quit", "Quit"),
        ("ctrl+d", "demo", "Demo"),
        ("ctrl+r", "reload_reports", "Reports"),
    ]
    CSS = """
    Screen { background: #0b1220; }
    Header { background: #17263b; }
    TabPane { padding: 1 2; }
    #target { width: 1fr; }
    #controls { height: 3; margin-bottom: 1; }
    Button { margin-right: 1; }
    #status { height: auto; min-height: 2; color: #65d6d1; }
    #summary { height: auto; margin: 1 0; }
    #findings { height: 12; border: solid #29425d; }
    #detail-scroll { height: 1fr; border: solid #29425d; padding: 0 1; }
    #report-list { height: 1fr; }
    #feed-table { height: 12; }
    #intel-results { height: 12; }
    #intel-detail { height: 1fr; }
    #scenario-editor { height: 1fr; border: solid #29425d; }
    #runtime-controls { height: 3; }
    #runtime-status { height: auto; min-height: 2; }
    .hint { color: #a6b5c9; height: auto; margin-bottom: 1; }
    """

    def __init__(self, home: Path):
        super().__init__()
        self.home = home
        self.report: dict | None = None
        self.busy = False
        self.intel_rows = {}
        self.job_id: str | None = None

    def compose(self) -> ComposeResult:
        yield Header()
        with TabbedContent(initial="audit"):
            with TabPane("감사 / Audit", id="audit"):
                yield Label("소스 폴더, APK 또는 IPA 경로를 입력하세요.", classes="hint")
                yield Input(placeholder="/absolute/path/to/app or app.apk", id="target")
                with Horizontal(id="controls"):
                    yield Button("검사 / Scan", id="scan", variant="primary")
                    yield Button("데모 / Demo", id="demo")
                    yield Button("중단", id="cancel", disabled=True)
                    yield Checkbox("의존성 온라인 조회", id="online")
                yield Static("오프라인 검사와 데모는 API 키 없이 실행됩니다.", id="status")
                yield Static("검사 전입니다. 결과에는 실행하지 못한 검사도 표시됩니다.", id="summary")
                yield DataTable(id="findings", cursor_type="row")
                with VerticalScroll(id="detail-scroll"):
                    yield Markdown(
                        "발견 항목을 선택하면 근거, 수정 안내, 검사 범위를 확인할 수 있습니다.", id="detail"
                    )
            with TabPane("이력 / Reports", id="reports"):
                yield Button("새로고침", id="reload")
                yield DataTable(id="report-list", cursor_type="row")
            with TabPane("재현 / Runtime", id="runtime"):
                yield Label(
                    "테스트 앱의 상태·로그아웃 절차·고유 canary를 지정하세요. 미리보기는 기기를 변경하지 않습니다.",
                    classes="hint",
                )
                with Horizontal(id="runtime-controls"):
                    yield Button("계획 생성", id="runtime-plan")
                    yield Button("미리보기", id="runtime-preview")
                    yield Button("시나리오 실행", id="runtime-run", variant="primary")
                    yield Button("중단", id="runtime-cancel", disabled=True)
                editor = TextArea("", id="scenario-editor", show_line_numbers=True)
                editor.register_language(
                    "json",
                    Language(tree_sitter_json.language()),
                    "(string) @string (number) @number [(true) (false)] @boolean (null) @json.null",
                )
                editor.language = "json"
                yield editor
                yield Static("먼저 앱을 검사한 뒤 계획을 생성하세요.", id="runtime-status")
            with TabPane("취약점 정보 / Intel", id="intel"):
                yield Label("공식 공지의 수집 상태와 마지막 성공 시점을 확인하세요.", classes="hint")
                yield Button("최신 정보 동기화", id="sync", variant="primary")
                yield DataTable(id="feed-table", cursor_type="row")
                yield Input(placeholder="CVE ID, WebView, MASTG… Enter로 검색", id="intel-query")
                yield DataTable(id="intel-results", cursor_type="row")
                with VerticalScroll(id="intel-detail"):
                    yield Markdown(
                        "동기화 후 검색할 수 있습니다. 실패한 소스의 이전 캐시는 유지됩니다.",
                        id="intel-description",
                    )
            with TabPane("모델 연결 / MCP", id="models"):
                with VerticalScroll():
                    yield Markdown("", id="model-help")
            with TabPane("CI 정책", id="policy"):
                yield Label(
                    "apsa policy init으로 정책을 만든 뒤 경로를 입력하세요. 예외에는 사유와 만료일이 필요합니다.",
                    classes="hint",
                )
                yield Input(placeholder="/absolute/path/mobile-audit.toml", id="policy-path")
                yield Input(placeholder="기준 보고서 ID (only_new 정책에서 필요)", id="policy-baseline")
                yield Button("현재 보고서 평가", id="policy-evaluate", variant="primary")
                with VerticalScroll():
                    yield Markdown("아직 정책을 평가하지 않았습니다.", id="policy-result")
        yield Footer()

    def on_mount(self):
        self.query_one("#findings", DataTable).add_columns("Severity", "Status", "Finding", "Evidence")
        self.query_one("#report-list", DataTable).add_columns("Report ID", "Created", "Target")
        self.query_one("#feed-table", DataTable).add_columns("Source", "Status", "Last success", "Records")
        self.query_one("#intel-results", DataTable).add_columns("ID", "Source", "Title")
        config = integration_config(self.home)
        self.query_one("#model-help", Markdown).update(
            "# 여러 모델에서 사용하기\n\nMCP를 지원하는 모델 클라이언트에 아래 서버 설정을 추가하세요. "
            "도구는 특정 LLM API 키를 요구하지 않습니다. 모델 인증은 클라이언트가 관리합니다.\n\n"
            "```json\n"
            + json.dumps({"mcpServers": config["mcpServers"]}, ensure_ascii=False, indent=2)
            + "\n```\n\n"
            "1. `capabilities`로 검사 범위를 확인합니다.\n2. `audit_scan`으로 검사합니다.\n3. `reports_get`으로 근거를 읽습니다.\n"
            "4. `runtime_plan`으로 재현 계획을 만듭니다.\n\n"
            "스킬: `" + config["skill"] + "`\n\n"
            "CLI로 컨텍스트 전달: `apsa --json context --report latest`\n\n"
            "기본 MCP는 기기에서 시나리오를 실행하지 않습니다. 허가된 테스트 기기에서 실행할 때 "
            "서버 인자에 `--allow-runtime`을 추가하세요. `--root`로 검사 경로를 제한할 수 있습니다."
        )
        self.action_reload_reports()
        self.reload_feeds()
        store = Store(self.home)
        try:
            if store.reports(1):
                self.show_report(store.report("latest"))
        finally:
            store.close()

    def set_busy(self, state: bool, text: str):
        self.busy = state
        for name in ["scan", "demo", "sync", "runtime-run", "runtime-plan", "runtime-preview"]:
            self.query_one(f"#{name}", Button).disabled = state
        self.query_one("#status", Static).update(text)
        self.query_one("#runtime-status", Static).update(text)

    def on_button_pressed(self, event: Button.Pressed):
        if event.button.id in {"cancel", "runtime-cancel"} and self.job_id:
            store = Store(self.home)
            try:
                jobs.cancel(store, self.job_id)
                self.query_one("#status", Static).update(
                    "중단 요청을 보냈습니다. 작업 종료 상태를 확인하고 있습니다…"
                )
            finally:
                store.close()
        elif event.button.id == "policy-evaluate":
            store = Store(self.home)
            try:
                if not self.report:
                    raise ValueError("먼저 앱 검사를 실행하세요.")
                policy = load_policy(Path(self.query_one("#policy-path", Input).value.strip()).expanduser())
                baseline_id = self.query_one("#policy-baseline", Input).value.strip()
                gate = evaluate(self.report, policy, store.report(baseline_id) if baseline_id else None)
                self.query_one("#policy-result", Markdown).update(
                    f"**{gate['state']} · exit {gate['exit_code']}**\n\n```json\n"
                    + json.dumps(gate, ensure_ascii=False, indent=2)
                    + "\n```"
                )
            except (ValueError, OSError) as error:
                self.query_one("#policy-result", Markdown).update(f"정책 오류: {error}")
            finally:
                store.close()
        elif event.button.id == "scan":
            path = self.query_one("#target", Input).value.strip()
            if not path:
                self.query_one("#status", Static).update(
                    "입력 경로를 지정하세요. 먼저 데모를 실행해도 됩니다."
                )
                return
            self.start_scan(Path(path))
        elif event.button.id == "demo":
            self.action_demo()
        elif event.button.id == "sync":
            if not self.busy:
                self.set_busy(True, "공식 보안 공지를 동기화하고 있습니다…")
                self.sync_worker()
        elif event.button.id == "reload":
            self.action_reload_reports()
        elif event.button.id == "runtime-plan":
            if self.report:
                self.query_one("#scenario-editor", TextArea).load_text(
                    json.dumps(plan(self.report), ensure_ascii=False, indent=2)
                )
                self.query_one("#runtime-status", Static).update(
                    "생성된 계획을 실제 앱 동작과 준비 상태에 맞게 수정하세요."
                )
            else:
                self.query_one("#runtime-status", Static).update("먼저 앱 검사를 실행하세요.")
        elif event.button.id in {"runtime-preview", "runtime-run"}:
            try:
                scenario = validate_scenario(json.loads(self.query_one("#scenario-editor", TextArea).text))
                if not self.report:
                    raise ValueError("먼저 앱 검사를 실행하세요.")
                if event.button.id == "runtime-preview":
                    self.query_one("#runtime-status", Static).update(
                        f"미리보기: {scenario['platform']} · {scenario['package']} · {len(scenario['steps'])} steps. 기기 실행은 하지 않았습니다."
                    )
                elif not self.busy:
                    self.set_busy(True, "테스트 앱에서 시나리오를 실행하고 있습니다…")
                    self.runtime_worker(scenario, self.report["id"])
            except (ValueError, TypeError, KeyError) as error:
                self.query_one("#runtime-status", Static).update(f"시나리오 오류: {error}")

    def on_input_submitted(self, event: Input.Submitted):
        if event.input.id == "target":
            self.start_scan(Path(event.value))
        elif event.input.id == "intel-query":
            store = Store(self.home)
            try:
                records = store.intelligence(event.value, 50)
            finally:
                store.close()
            table = self.query_one("#intel-results", DataTable)
            table.clear()
            self.intel_rows = {str(i): row for i, row in enumerate(records)}
            for key, row in self.intel_rows.items():
                table.add_row(row["id"], row["source"], row["title"], key=key)

    def start_scan(self, path: Path | None = None):
        if self.busy:
            return
        self.set_busy(True, "앱 구성과 검사 근거를 분석하고 있습니다…")
        online = self.query_one("#online", Checkbox).value
        self.scan_worker(path, online)

    def action_demo(self):
        self.start_scan()

    @work(thread=True)
    def scan_worker(self, path: Path | None, online: bool):
        store = Store(self.home)
        try:
            if path is None:
                import time

                path = demo_target(store.home / "demo" / str(time.time_ns()))
            job = jobs.start(store, {"kind": "scan", "target": str(path), "online": online})
            report = self.wait_job(store, job)
            self.call_from_thread(self.show_report, report)
            self.call_from_thread(self.action_reload_reports)
            self.call_from_thread(
                self.set_busy, False, "검사가 완료됐습니다. 후보와 미실행 항목을 함께 확인하세요."
            )
        except Exception as error:
            if self.is_running:
                self.call_from_thread(self.set_busy, False, f"검사 실패: {error}")
        finally:
            store.close()

    @work(thread=True)
    def sync_worker(self):
        store = Store(self.home)
        try:
            result = sync(store, limit=3)
            self.call_from_thread(self.reload_feeds)
            message = (
                "일부 소스 수집 실패: Intel 탭에서 상태를 확인하세요."
                if result["partial"]
                else "취약점 정보가 갱신됐습니다. 다시 검사해 적용하세요."
            )
            self.call_from_thread(self.set_busy, False, message)
            self.call_from_thread(self.notify, message)
        except Exception as error:
            self.call_from_thread(self.set_busy, False, f"동기화 실패: {error}")
        finally:
            store.close()

    @work(thread=True)
    def runtime_worker(self, scenario: dict, report_id: str):
        import time

        store = Store(self.home)
        try:
            path = store.home / "scenarios" / f"scenario-{time.time_ns()}.json"
            write_json(path, scenario)
            previous = store.report(report_id)
            job = jobs.start(
                store,
                {
                    "kind": "runtime",
                    "target": previous["target"],
                    "scenario": str(path),
                    "report_id": report_id,
                },
            )
            report = self.wait_job(store, job)
            self.call_from_thread(self.show_report, report)
            self.call_from_thread(self.action_reload_reports)
            results = report["runtime"][-1]
            message = (
                "일부 재현 검사를 완료하지 못했습니다. 보고서의 기기·surface 상태를 확인하세요."
                if results["partial"]
                else "재현 완료. 판정과 관찰 범위를 보고서에서 확인하세요."
            )
            self.call_from_thread(self.set_busy, False, message)
        except Exception as error:
            if self.is_running:
                self.call_from_thread(self.set_busy, False, f"재현 실패: {error}")
        finally:
            store.close()

    def track_job(self, identifier: str | None):
        self.job_id = identifier
        for name in ("cancel", "runtime-cancel"):
            self.query_one(f"#{name}", Button).disabled = identifier is None

    def wait_job(self, store: Store, job: dict) -> dict:
        self.call_from_thread(self.track_job, job["id"])
        try:
            while True:
                if not self.is_running:
                    raise RuntimeError("TUI closed; background job remains available through jobs status")
                value = jobs.get(store, job["id"])
                if value["state"] in jobs.TERMINAL:
                    if value["state"] != "completed":
                        raise ValueError(value["error"] or value["state"])
                    return store.report(value["report_id"])
                self.call_from_thread(
                    self.query_one("#status", Static).update,
                    f"{value['progress']}% · {value['stage']} · {job['id']}",
                )
                time.sleep(0.1)
        finally:
            if self.is_running:
                self.call_from_thread(self.track_job, None)

    def action_reload_reports(self):
        store = Store(self.home)
        try:
            records = store.reports(100)
        finally:
            store.close()
        table = self.query_one("#report-list", DataTable)
        table.clear()
        for row in records:
            table.add_row(row["id"], row["created"], row["target"], key=row["id"])

    def reload_feeds(self):
        store = Store(self.home)
        try:
            rows = source_health(store)
        finally:
            store.close()
        table = self.query_one("#feed-table", DataTable)
        table.clear()
        for row in rows:
            table.add_row(
                row["source"],
                "stale" if row["stale"] else row["status"],
                row["succeeded"] or "never",
                str(row["count"]),
                key=row["source"],
            )

    def show_report(self, report: dict):
        self.report = report
        self.query_one("#target", Input).value = report["target"]
        summary = report["summary"]
        self.query_one("#summary", Static).update(
            f"{len(report['findings'])} findings · {summary['candidates']} candidates · {summary['not_run']} not-run · {summary.get('partial', 0)} partial · {summary['environment_advisories']} OS advisories"
        )
        table = self.query_one("#findings", DataTable)
        table.clear()
        for item in report["findings"]:
            first = item["evidence"][0] if item["evidence"] else {}
            table.add_row(
                item["severity"], item["status"], item["title"], str(first.get("path", "")), key=item["id"]
            )
        details = (
            "## 검사 범위\n\n"
            + report["scope"]
            + "\n\n```json\n"
            + json.dumps(report["coverage"], ensure_ascii=False, indent=2)
            + "\n```"
        )
        self.query_one("#detail", Markdown).update(details)

    def on_data_table_row_selected(self, event: DataTable.RowSelected):
        key = str(event.row_key.value)
        if event.data_table.id == "findings" and self.report:
            item = next(f for f in self.report["findings"] if f["id"] == key)
            self.query_one("#detail", Markdown).update(
                "## "
                + item["title"]
                + "\n\n"
                + item["status"]
                + " · "
                + item["masvs"]
                + "\n\n"
                + item["remediation"]
                + "\n\n```json\n"
                + json.dumps(item["evidence"], ensure_ascii=False, indent=2)
                + "\n```\n\n"
                + "\n".join(f"- {url}" for url in item["references"])
            )
        elif event.data_table.id == "report-list":
            store = Store(self.home)
            try:
                self.show_report(store.report(key))
            finally:
                store.close()
            self.query_one(TabbedContent).active = "audit"
        elif event.data_table.id == "intel-results":
            row = self.intel_rows[key]
            self.query_one("#intel-description", Markdown).update(
                "## "
                + row["title"]
                + "\n\n```json\n"
                + json.dumps(row, ensure_ascii=False, indent=2)
                + "\n```"
            )
