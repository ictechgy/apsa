from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
import time
from importlib import metadata
from pathlib import Path

from rich.console import Console
from rich.table import Table

from . import __version__, jobs
from .audit import compare, refresh_report, scan
from .baselines import baseline_artifact, load_baseline
from .core import canonical_json, digest, read_json, redact, report_incomplete, severity_rank, write_json
from .intel import DEFAULT_SOURCES, Fetcher, fetch_record, source_health, sync
from .model_context import SECTIONS, report_context
from .output import markdown, sarif
from .policy import evaluate, load_policy, template
from .rules import rules
from .runtime import devices, plan, run, validate_scenario
from .selection import select_source_module
from .specs import load_specs
from .store import Store, default_home
from .tools import android_sdks, resolve_tool


class UsageError(ValueError):
    pass


class Parser(argparse.ArgumentParser):
    def error(self, message):
        raise UsageError(message)


def parser() -> Parser:
    root = Parser(
        prog="apsa",
        description="APSA (앱사). Evidence-first security audits for Android & iOS, public vulnerability intelligence, TUI and model-neutral MCP.",
        epilog="Global flags work before or after commands: --json, --home PATH. With no command, launch TUI. Compatibility lint: apk PATH, ipa PATH, device (--json/--sarif after the command; exits 0/1/2).",
    )
    root.add_argument("--version", action="version", version=__version__)
    commands = root.add_subparsers(dest="command")
    commands.add_parser("doctor", help="Check installation, device tools, cache and offline readiness")
    scan_parser = commands.add_parser("scan", help="Audit source folder, APK or IPA")
    scan_parser.add_argument("target", type=Path)
    scan_parser.add_argument(
        "--online", action="store_true", help="Query OSV for discovered dependency versions"
    )
    scan_parser.add_argument("--sbom", type=Path, help="CycloneDX JSON inventory for the actual build")
    scan_parser.add_argument(
        "--device-info", type=Path, help="Observed environment JSON; no OS state inferred from targetSdk"
    )
    scan_parser.add_argument("--out", type=Path)
    scan_parser.add_argument("--format", choices=["json", "markdown", "sarif", "maswe"], default="json")
    scan_parser.add_argument(
        "--sarif-root",
        help="Repository-relative path of the target, used for SARIF locations (code scanning upload)",
    )
    scan_parser.add_argument("--fail-on", choices=["low", "medium", "high", "critical"])
    scan_parser.add_argument("--policy", type=Path, help="Apply a project TOML/JSON CI policy")
    scan_parser.add_argument("--baseline", help="Baseline report ID for policy only_new")
    scan_parser.add_argument("--baseline-file", type=Path)
    scan_parser.add_argument("--baseline-sha256", help="Externally approved baseline artifact SHA-256")
    scan_parser.add_argument("--decision-out", type=Path)
    scan_parser.add_argument(
        "--specs", type=Path, help="Project taint specification (TOML/JSON) declaring extra sources and sinks"
    )
    scan_parser.add_argument("--source-module", help="Relative source module directory")
    scan_parser.add_argument(
        "--configuration",
        help="Relative manifest/.plist within selected source module; no build-system merge",
    )
    scan_parser.add_argument(
        "--background", action="store_true", help="Return a persistent job ID and track it with jobs status"
    )
    scan_parser.add_argument(
        "--include-candidates",
        action="store_true",
        help="Also apply CI severity threshold to heuristic candidates",
    )
    specs_parser = commands.add_parser("specs", help="Validate project taint specifications").add_subparsers(
        dest="action", required=True
    )
    specs_validate = specs_parser.add_parser("validate")
    specs_validate.add_argument("file", type=Path)
    verify_parser = commands.add_parser(
        "verify", help="Cross-check a finding claimed elsewhere against APSA evidence; never refutes"
    )
    verify_parser.add_argument("target", type=Path)
    verify_parser.add_argument("--weakness", help="MASWE-NNNN or CWE-N identifier")
    verify_parser.add_argument("--rule", help="APSA rule ID")
    verify_parser.add_argument("--path", help="Claimed file, absolute or relative to the target")
    verify_parser.add_argument("--line", type=int)
    verify_parser.add_argument("--report", help="Report ID to check instead of the latest for the target")
    verify_parser.add_argument("--rescan", action="store_true", help="Scan the target first")
    job_commands = commands.add_parser("jobs", help="Track and cancel background audits").add_subparsers(
        dest="action", required=True
    )
    job_list = job_commands.add_parser("list")
    job_list.add_argument("--limit", type=int, default=30)
    for action in ("status", "cancel"):
        job_command = job_commands.add_parser(action)
        job_command.add_argument("id")
    policy_commands = commands.add_parser(
        "policy", help="Configure and evaluate team CI gates"
    ).add_subparsers(dest="action", required=True)
    policy_init = policy_commands.add_parser("init")
    policy_init.add_argument("--out", type=Path, default=Path("apsa.toml"))
    policy_gate = policy_commands.add_parser("evaluate")
    policy_gate.add_argument("report", nargs="?", default="latest")
    policy_gate.add_argument("--policy", type=Path, required=True)
    policy_gate.add_argument("--baseline")
    policy_gate.add_argument("--baseline-file", type=Path)
    policy_gate.add_argument("--baseline-sha256")
    policy_gate.add_argument("--decision-out", type=Path)
    intel = commands.add_parser(
        "intel", help="Synchronize, search or monitor official vulnerability sources"
    ).add_subparsers(dest="action", required=True)
    for action in ["sync", "watch"]:
        sub = intel.add_parser(action)
        sub.add_argument("--sources", default=",".join(DEFAULT_SOURCES))
        sub.add_argument("--limit", type=int, default=3, help="Recent vendor advisories per source (1–50)")
        if action == "watch":
            sub.add_argument("--interval", type=int, default=900, help="Poll interval, minimum 60 seconds")
            sub.add_argument("--cycles", type=int, default=0, help="0 runs until Ctrl-C")
            sub.add_argument("--no-reaudit", action="store_true")
            sub.add_argument(
                "--online",
                action="store_true",
                help="Explicitly query OSV for latest saved targets; sends dependency names/versions",
            )
    backfill_parser = intel.add_parser(
        "backfill", help="Fetch an explicit month range of Android security bulletins"
    )
    backfill_parser.add_argument("--source", choices=["android"], default="android")
    backfill_parser.add_argument("--since", required=True, help="First month, YYYY-MM (2015-08 or later)")
    backfill_parser.add_argument("--until", help="Last month, YYYY-MM; defaults to the current month")
    intel.add_parser("status")
    search = intel.add_parser("search")
    search.add_argument("query", nargs="?", default="")
    search.add_argument("--limit", type=int, default=20)
    get = intel.add_parser("get")
    get.add_argument("id")
    get.add_argument("--refresh", action="store_true")
    request = intel.add_parser("request", help="Read a raw public official-source document")
    request.add_argument("source", choices=DEFAULT_SOURCES)
    request.add_argument("--out", required=True, type=Path)
    reports = commands.add_parser(
        "reports", help="List, inspect, compare and export immutable report snapshots"
    ).add_subparsers(dest="action", required=True)
    ls = reports.add_parser("list")
    reports.add_parser("verify", help="Verify report hashes and exported JSON files")
    ls.add_argument("--limit", type=int, default=30)
    get = reports.add_parser("get")
    get.add_argument("id", nargs="?", default="latest")
    get.add_argument("--finding")
    export = reports.add_parser("export")
    export.add_argument("id")
    export.add_argument("--out", type=Path, required=True)
    export.add_argument(
        "--format",
        choices=["json", "markdown", "sarif", "maswe", "cyclonedx", "baseline"],
        default="markdown",
    )
    export.add_argument(
        "--sarif-root",
        help="Repository-relative path of the scanned target, used for SARIF locations",
    )
    export.add_argument("--approved-by")
    export.add_argument("--approval-reference")
    comparison = reports.add_parser("compare")
    comparison.add_argument("before")
    comparison.add_argument("after")
    refresh = reports.add_parser("reassess")
    refresh.add_argument("id", nargs="?", default="latest")
    runtime = commands.add_parser(
        "runtime", help="Plan and run authorized test-app scenarios"
    ).add_subparsers(dest="action", required=True)
    runtime.add_parser("devices")
    planning = runtime.add_parser("plan")
    planning.add_argument("--report", default="latest")
    planning.add_argument("--out", type=Path)
    planning.add_argument("--platform", choices=["android", "ios"])
    planning.add_argument("--package")
    execution = runtime.add_parser("run")
    execution.add_argument("scenario", type=Path)
    execution.add_argument("--report", default="latest")
    execution.add_argument("--dry-run", action="store_true")
    execution.add_argument("--screenshots", action="store_true")
    execution.add_argument(
        "--background", action="store_true", help="Execute as a cancellable persistent device job"
    )
    rules_cmd = commands.add_parser("rules", help="Discover implemented rules and OWASP mappings")
    rules_cmd.add_argument("--id")
    explain = commands.add_parser("context", help="Export sanitized evidence context for any model")
    explain.add_argument("--report", default="latest")
    explain.add_argument("--section", choices=SECTIONS, default="findings")
    explain.add_argument("--cursor", type=int, default=0)
    explain.add_argument("--limit", type=int, default=20)
    explain.add_argument("--max-bytes", type=int, default=65536)
    explain.add_argument("--severity")
    explain.add_argument("--status")
    mcp = commands.add_parser("mcp", help="Serve tools/resources/prompts over MCP stdio")
    mcp.add_argument(
        "--allow-runtime",
        action="store_true",
        help="Expose device-execution tool; default exposes planning only",
    )
    mcp.add_argument(
        "--root", type=Path, action="append", help="Restrict MCP input paths; repeat for multiple roots"
    )
    mcp.add_argument(
        "--allow-any-root", action="store_true", help="Explicitly allow all readable local target paths"
    )
    integrations = commands.add_parser(
        "integrations", help="Print portable MCP client configuration and skill status"
    )
    integrations.add_argument(
        "--root", type=Path, action="append", help="Allowed project roots; default is current directory"
    )
    skill = commands.add_parser("skill", help="Install packaged model-neutral skills").add_subparsers(
        dest="action", required=True
    )
    install = skill.add_parser("install")
    install.add_argument("--name", choices=["apsa", "quaygate", "mobile-audit"], default="apsa")
    install.add_argument("--dest", type=Path, help="Skill directory; defaults to ~/.codex/skills/NAME")
    install.add_argument("--force", action="store_true", help="Replace an existing modified skill")
    commands.add_parser("tui", help="Open the guided terminal interface")
    demo = commands.add_parser("demo", help="Create and scan an intentionally vulnerable offline example")
    demo.add_argument("--out", type=Path, help="Where to create example files")
    return root


def global_flags(argv: list[str]) -> tuple[list[str], bool, Path]:
    args = list(argv)
    use_json = False
    home = default_home()
    output = []
    i = 0
    while i < len(args):
        item = args[i]
        if item == "--json":
            use_json = True
        elif item == "--home":
            if i + 1 >= len(args):
                raise UsageError("--home requires a path")
            i += 1
            home = Path(args[i]).expanduser()
        elif item.startswith("--home="):
            home = Path(item.split("=", 1)[1]).expanduser()
        else:
            output.append(item)
        i += 1
    return output, use_json, home


def doctor(store: Store) -> dict:
    from .parser_sandbox import backend

    packages = {}
    missing = []
    for package in (
        "tree-sitter",
        "tree-sitter-java",
        "tree-sitter-kotlin",
        "tree-sitter-objc",
        "tree-sitter-swift",
        "tree-sitter-json",
        "androguard",
        "mcp",
        "psutil",
    ):
        try:
            packages[package] = metadata.version(package)
        except metadata.PackageNotFoundError:
            missing.append(package)
    supported_host = sys.platform in {"darwin", "linux"}
    return {
        "version": __version__,
        "product": "apsa",
        "engines": ["mobile-audit", "quaygate-lint"],
        "python": sys.version.split()[0],
        "home": str(store.home),
        "offline_ready": supported_host and not missing,
        "supported_host": supported_host,
        "parser_os_sandbox": {
            "mode": os.environ.get("APSA_PARSER_SANDBOX", "auto"),
            "backend_path": backend(),
            "availability_is_not_execution_proof": True,
        },
        "parser_packages": packages,
        "missing_packages": missing,
        "auth_required": False,
        "model_interface": "MCP stdio / reusable skill; model credentials belong to the client",
        "tools": {
            tool: resolve_tool(tool)
            for tool in ["adb", "emulator", "apkanalyzer", "xcrun", "jadx", "apktool", "openssl"]
        },
        "android_sdks": [str(path) for path in android_sdks()],
        "intel_sources": source_health(store),
        "saved_reports": len(store.reports(10000)),
        "next_steps": [
            "apsa demo",
            "apsa tui",
            "apsa intel sync",
            "apsa integrations",
        ],
        "device_notes": "adb is required for Android runtime; Xcode and an iOS simulator build are required for iOS runtime.",
    }


def integration_config(home: Path, roots: list[Path] | None = None) -> dict:
    from .skills import skill_status

    binary = shutil.which("apsa")
    command = binary or sys.executable
    arguments = [] if binary else ["-I", "-m", "apsa"]
    arguments += ["--home", str(home.resolve()), "mcp"]
    for root in roots or [Path.cwd()]:
        arguments += ["--root", str(root.expanduser().resolve())]
    skill_path = Path.home() / ".codex/skills/apsa/SKILL.md"
    return {
        "mcpServers": {"apsa": {"command": command, "args": arguments}},
        "skill": str(skill_path),
        "skill_installed": skill_path.is_file(),
        "skill_status": skill_status("apsa"),
        "model_independent": True,
        "transport": "stdio",
        "note": "MCP is restricted to the listed roots (current directory by default). Run apsa skill install to install the packaged skill. Add --allow-runtime only for authorized device tests. Client configuration format may differ; command/args are portable.",
    }


def demo_target(directory: Path) -> Path:
    from importlib.resources import files

    directory.mkdir(parents=True, exist_ok=True)
    for name in ["AndroidManifest.xml", "MainActivity.kt", "build.gradle.kts", "Info.plist", "Demo.swift"]:
        destination = directory / name
        if destination.exists():
            raise ValueError(f"Demo destination exists; choose a new folder: {destination}")
        destination.write_bytes(files("mobile_audit").joinpath("data/demo", name).read_bytes())
    return directory


def first_observed(store: Store, report: dict, limit: int = 200) -> dict[str, str]:
    """Earliest saved report time at which each finding ID appeared for the same target."""
    seen: dict[str, str] = {}
    history = [
        item
        for item in store.reports(limit, roots=[Path(report["target"])])
        if item["target"] == report["target"] and item["created"] <= report["created"]
    ]
    for item in reversed(history):
        for finding_item in store.report(item["id"]).get("findings", []):
            seen.setdefault(finding_item["id"], item["created"])
    return seen


def export_report(report: dict, path: Path, format_: str, sarif_root: str | None = None):
    if sarif_root is not None and format_ != "sarif":
        raise UsageError("--sarif-root applies only to --format sarif")
    if format_ == "markdown":
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(markdown(report), encoding="utf-8")
    elif format_ == "sarif":
        write_json(path, sarif(report, sarif_root))
    elif format_ == "maswe":
        from .maswe import coverage_matrix

        write_json(path, {"report_id": report["id"], **coverage_matrix(report)})
    else:
        write_json(path, report)


def policy_baseline(args, store: Store) -> dict | None:
    if args.baseline and args.baseline_file:
        raise UsageError("Choose --baseline or --baseline-file")
    if bool(args.baseline_file) != bool(args.baseline_sha256):
        raise UsageError("--baseline-file requires --baseline-sha256 and vice versa")
    return (
        load_baseline(args.baseline_file, args.baseline_sha256)
        if args.baseline_file
        else store.report(args.baseline)
        if args.baseline
        else None
    )


def decision_artifact(report: dict, gate: dict, baseline: dict | None, policy: dict) -> dict:
    return {
        "schema_version": 1,
        "kind": "apsa-policy-decision",
        "tool_version": __version__,
        "report_id": report["id"],
        "report_sha256": digest(canonical_json(report).encode()),
        "policy": policy,
        "policy_sha256": digest(canonical_json(policy).encode()),
        "baseline_provenance": (baseline or {}).get("baseline_provenance"),
        "gate": gate,
    }


def dispatch(args, store: Store, use_json=False) -> tuple[dict | list | None, int]:
    cmd = args.command
    if cmd in {None, "tui"}:
        if use_json:
            raise UsageError("TUI is interactive. Use scan --json or reports get --json for automation.")
        from .tui import AuditApp

        AuditApp(store.home).run()
        return None, 0
    if cmd == "doctor":
        return doctor(store), 0
    if cmd == "policy":
        if args.action == "init":
            args.out.parent.mkdir(parents=True, exist_ok=True)
            with args.out.open("x", encoding="utf-8") as output:
                output.write(template())
            return {
                "path": str(args.out.resolve()),
                "next_step": "Edit thresholds and required checks, then run policy evaluate",
            }, 0
        report = store.report(args.report)
        baseline = policy_baseline(args, store)
        policy = load_policy(args.policy)
        gate = evaluate(report, policy, baseline)
        if args.decision_out:
            write_json(args.decision_out, decision_artifact(report, gate, baseline, policy))
        return gate, gate["exit_code"]
    if cmd == "jobs":
        if args.action == "list":
            return {"jobs": jobs.listing(store, args.limit)}, 0
        result = jobs.cancel(store, args.id) if args.action == "cancel" else jobs.get(store, args.id)
        return result, 3 if result["state"] in {"failed", "interrupted"} else 0
    if cmd == "scan":
        if (
            args.baseline or args.baseline_file or args.baseline_sha256 or args.decision_out
        ) and not args.policy:
            raise UsageError("Baseline and decision options require --policy")
        if args.policy and (args.fail_on or args.include_candidates):
            raise UsageError(
                "Project policy defines evidence statuses and thresholds; remove --fail-on/--include-candidates"
            )
        if args.background:
            if args.out or args.fail_on or args.policy:
                raise UsageError(
                    "Background scans return a job ID; export or evaluate the completed report afterward"
                )
            return jobs.start(
                store,
                {
                    "kind": "scan",
                    "target": str(select_source_module(args.target.resolve(), args.source_module)),
                    "configuration": args.configuration,
                    "source_module": args.source_module,
                    "online": args.online,
                    "sbom": str(args.sbom.resolve()) if args.sbom else None,
                    "environment": read_json(args.device_info) if args.device_info else None,
                    "specs": load_specs(args.specs) if args.specs else None,
                },
            ), 0
        baseline = policy_baseline(args, store) if args.policy else None
        policy = load_policy(args.policy) if args.policy else None
        result = scan(
            store,
            select_source_module(args.target.resolve(), args.source_module),
            args.online,
            args.sbom,
            read_json(args.device_info) if args.device_info else None,
            configuration=args.configuration,
            source_module=args.source_module,
            specs=load_specs(args.specs) if args.specs else None,
        )
        if args.out:
            export_report(result, args.out, args.format, args.sarif_root)
        elif args.sarif_root is not None:
            raise UsageError("--sarif-root requires --out")
        if policy is not None:
            gate = evaluate(result, policy, baseline)
            decision = decision_artifact(result, gate, baseline, policy)
            decision_path = args.decision_out or (
                args.out.with_name(args.out.name + ".decision.json") if args.out else None
            )
            if decision_path:
                write_json(decision_path, decision)
            return {"report": result, "gate": gate, "decision": decision}, gate["exit_code"]
        failing = args.fail_on and any(
            severity_rank(f["severity"]) >= severity_rank(args.fail_on)
            and (args.include_candidates or f["status"] != "candidate")
            for f in result["findings"]
        )
        incomplete = report_incomplete(result)
        return result, 3 if incomplete else 4 if failing else 0
    if cmd == "specs":
        return {"valid": True, **load_specs(args.file)}, 0
    if cmd == "verify":
        from .verify import verify_claim

        target = args.target.resolve()
        if args.report and args.rescan:
            raise UsageError("Choose --report or --rescan")
        if args.report:
            report = store.report(args.report)
            if Path(report["target"]) != target:
                raise UsageError("Report target differs from the requested target")
        else:
            saved = [item for item in store.reports(50, roots=[target]) if Path(item["target"]) == target]
            report = scan(store, target) if args.rescan or not saved else store.report(saved[0]["id"])
        try:
            return verify_claim(
                report, path=args.path, line=args.line, weakness=args.weakness, rule=args.rule
            ), 0
        except ValueError as error:
            raise UsageError(str(error)) from error
    if cmd == "demo":
        directory = args.out or store.home / "demo" / str(time.time_ns())
        return scan(store, demo_target(directory)), 0
    if cmd == "rules":
        values = [r for r in rules() if not args.id or r["id"] == args.id]
        return {"rules": values}, 0
    if cmd == "context":
        return report_context(
            store.report(args.report),
            section=args.section,
            cursor=args.cursor,
            limit=args.limit,
            max_bytes=args.max_bytes,
            severity=args.severity,
            status=args.status,
        ), 0
    if cmd == "integrations":
        return integration_config(store.home, args.root), 0
    if cmd == "skill":
        from .skills import install_skill

        return install_skill(args.name, args.dest, args.force), 0
    if cmd == "mcp":
        from .mcp_server import create_server

        create_server(store.home, args.allow_runtime, args.root, allow_any_root=args.allow_any_root).run(
            transport="stdio"
        )
        return None, 0
    if cmd == "intel":
        if args.action == "status":
            return {"sources": source_health(store)}, 0
        if args.action == "search":
            if not 1 <= args.limit <= 1000:
                raise UsageError("limit must be 1–1000")
            return {"records": store.intelligence(args.query, args.limit)}, 0
        if args.action == "get":
            values = fetch_record(store, args.id) if args.refresh else store.intel_by_id(args.id)
            return {"records": values}, 0
        if args.action == "request":
            from .intel import SOURCES

            fetcher = Fetcher()
            try:
                raw = fetcher.get(SOURCES[args.source], max_bytes=32 * 1024 * 1024)
                args.out.parent.mkdir(parents=True, exist_ok=True)
                args.out.write_bytes(raw)
                return {"source": args.source, "path": str(args.out), "bytes": len(raw)}, 0
            finally:
                fetcher.close()
        if args.action == "backfill":
            from .intel import backfill

            try:
                result = backfill(store, args.source, args.since, args.until)
            except ValueError as error:
                raise UsageError(str(error)) from None
            return result, 3 if result["partial"] else 0
        if args.action == "sync":
            result = sync(store, args.sources.split(","), args.limit)
            return result, 3 if result["partial"] else 0
        if args.action == "watch":
            if args.interval < 60 or args.cycles < 0:
                raise UsageError("Watch interval must be >=60; cycles must be >=0")
            cycle = 0
            while True:
                result = sync(store, args.sources.split(","), args.limit)
                result["reaudited_reports"] = []
                if not args.no_reaudit:
                    from .watch import reassess_targets

                    result.update(reassess_targets(store, online=args.online))
                    result["partial"] = result["partial"] or bool(result["reaudit_errors"])
                emit(result, use_json, 3 if result["partial"] else 0)
                cycle += 1
                if args.cycles and cycle >= args.cycles:
                    return None, 3 if result["partial"] else 0
                time.sleep(args.interval)
    if cmd == "reports":
        if args.action == "verify":
            result = store.verify_reports()
            return result, 3 if result["failures"] else 0
        if args.action == "list":
            if not 1 <= args.limit <= 1000:
                raise UsageError("limit must be 1–1000")
            return {"reports": store.reports(args.limit)}, 0
        if args.action == "get":
            report = store.report(args.id)
            if args.finding:
                item = next((f for f in report["findings"] if f["id"] == args.finding), None)
                if item is None:
                    raise ValueError("Finding not found in report")
                return item, 0
            return report, 0
        if args.action == "compare":
            return compare(store, args.before, args.after), 0
        if args.action == "reassess":
            return refresh_report(store, args.id), 0
        if args.action == "export":
            if args.format == "baseline":
                if args.sarif_root is not None:
                    raise UsageError("--sarif-root applies only to --format sarif")
                artifact = baseline_artifact(
                    store.report(args.id), args.approved_by or "", args.approval_reference or ""
                )
                write_json(args.out, artifact)
                return {
                    "path": str(args.out),
                    "format": "baseline",
                    "sha256": digest(args.out.read_bytes()),
                    "approval": artifact["approval"],
                }, 0
            report = store.report(args.id)
            if args.format == "cyclonedx":
                from .sbom import cyclonedx

                if args.sarif_root is not None:
                    raise UsageError("--sarif-root applies only to --format sarif")
                write_json(args.out, cyclonedx(report, first_observed(store, report)))
                return {"path": str(args.out), "format": args.format}, 0
            export_report(report, args.out, args.format, args.sarif_root)
            return {"path": str(args.out), "format": args.format}, 0
    if cmd == "runtime":
        if args.action == "devices":
            return devices(), 0
        if args.action == "plan":
            result = plan(store.report(args.report), args.platform, args.package)
            if args.out:
                write_json(args.out, result)
            return result, 0
        if args.action == "run":
            if args.dry_run:
                result = validate_scenario(read_json(args.scenario))
                return {
                    "preview": True,
                    "platform": result["platform"],
                    "package": result["package"],
                    "steps": len(result["steps"]),
                    "precondition": result["precondition"],
                }, 0
            if args.background:
                original = store.report(args.report)
                validate_scenario(read_json(args.scenario))
                return jobs.start(
                    store,
                    {
                        "kind": "runtime",
                        "target": original["target"],
                        "report_id": original["id"],
                        "scenario": str(args.scenario.resolve()),
                        "screenshots": args.screenshots,
                    },
                ), 0
            report = run(store, args.scenario, args.report, args.screenshots)
            return report, 3 if report["runtime"][-1]["partial"] else 0
    raise UsageError("Unknown command")


def emit(value, use_json: bool, code=0):
    if use_json:
        print(json.dumps({"ok": code in {0, 4}, "data": value, "exit_code": code}, ensure_ascii=False))
    elif isinstance(value, dict) and "findings" in value and "inventory" in value:
        console = Console()
        console.print(f"[bold cyan]APSA (앱사)[/]  {value['id']}")
        console.print(str(value["target"]), markup=False)
        table = Table("Severity", "Status", "Finding", "Location")
        for item in value["findings"]:
            evidence = item["evidence"][0] if item["evidence"] else {}
            location = str(evidence.get("path", evidence.get("dependency", {}).get("name", "")))
            table.add_row(item["severity"], item["status"], item["title"], location)
        console.print(table)
        console.print(json.dumps(value["summary"], ensure_ascii=False), markup=False)
        for warning in value["warnings"]:
            console.print(f"Coverage: {warning}", markup=False)
        console.print("Details: apsa reports get " + value["id"])
    else:
        print(json.dumps(value, ensure_ascii=False, indent=2))


def main(argv: list[str] | None = None) -> int:
    raw = sys.argv[1:] if argv is None else argv
    use_json = "--json" in raw
    store = None
    try:
        cleaned, use_json, home = global_flags(raw)
        args = parser().parse_args(cleaned)
        store = Store(home)
        result, code = dispatch(args, store, use_json)
        if result is not None:
            emit(result, use_json, code)
        return code
    except KeyboardInterrupt:
        return 130
    except Exception as error:
        code = 2 if isinstance(error, UsageError) else 1
        message = redact(str(error))[:800]
        if use_json:
            print(
                json.dumps(
                    {
                        "ok": False,
                        "error": {"type": type(error).__name__, "message": message},
                        "exit_code": code,
                    },
                    ensure_ascii=False,
                )
            )
        else:
            print(f"apsa: {message}", file=sys.stderr)
        return code
    finally:
        if store:
            store.close()


def entrypoint():
    raise SystemExit(main())
