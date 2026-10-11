"""New synthetic source/archive/report fixtures exercising public option seams."""

import ast
import zipfile
from contextlib import contextmanager
from pathlib import Path
from typing import Any

import pytest

from mobile_audit import audit
from mobile_audit._parser_worker import analyze
from mobile_audit.cli import dispatch, parser
from mobile_audit.inputs import inspect_target
from mobile_audit.run_options import build_selection, transmission_policy
from mobile_audit.verify import verify_claim
from tests.test_competitive_binaries import message, primitive, reference, resource_table


def project(root):
    (root / "app").mkdir(parents=True)
    (root / "settings.gradle").write_text("include ':app'\n")
    (root / "app/build.gradle").write_text("plugins { id 'com.android.application' }\n")
    (root / "app/gradle.lockfile").write_text(
        "synthetic.public:lib:1.0=releaseRuntimeClasspath\nsynthetic.public:lib:2.0=debugRuntimeClasspath\n"
    )
    (root / "app/AndroidManifest.xml").write_text(
        '<manifest package="synthetic.app"><application /></manifest>'
    )
    (root / "app/index.ts").write_text("function open() { view.loadUrl(route.params.url); }")
    return root


def test_selected_resolution_reaches_parser_inventory_and_hybrid_evidence(tmp_path):
    root = project(tmp_path / "source")
    selection = build_selection("app", "releaseRuntimeClasspath", ["app/gradle.lockfile"])
    report = analyze(root, None, dependency_selection=selection)
    inv = report["inventory"]
    assert {d["version"] for d in inv["dependencies"]} == {"1.0"}
    assert inv["source_selection"]["dependency_build"]["runtime_configuration"] == "releaseRuntimeClasspath"
    assert all(d["build_evidence"]["freshness"] == "unverified" for d in inv["dependencies"])
    assert any(
        f["rule_id"] == "HYBRID-UNTRUSTED-URL" and f["evidence"][0]["trace"] for f in report["findings"]
    )


def test_selected_resolution_survives_real_parser_staging(tmp_path):
    from mobile_audit.engine import analyze_target

    root = project(tmp_path / "source")
    selection = build_selection("app", "releaseRuntimeClasspath")
    result = analyze_target(root, dependency_selection=selection, report_home=tmp_path / "state")
    assert {d["version"] for d in result["inventory"]["dependencies"]} == {"1.0"}
    assert any(f["rule_id"] == "HYBRID-UNTRUSTED-URL" for f in result["findings"])


def test_cli_foreground_and_background_forward_identical_options(tmp_path, store, monkeypatch):
    root = project(tmp_path / "source")
    calls = []
    monkeypatch.setattr(
        "mobile_audit.cli.scan",
        lambda *a, **kw: calls.append(kw) or {"findings": [], "coverage": [], "inventory": {}},
    )
    monkeypatch.setattr(
        "mobile_audit.cli.jobs.start", lambda _, payload: calls.append(payload) or {"id": "synthetic-job"}
    )
    options = [
        "scan",
        str(root),
        "--dependency-module",
        "app",
        "--runtime-configuration",
        "releaseRuntimeClasspath",
        "--dependency-evidence",
        "app/gradle.lockfile",
        "--osv-exclude-name",
        "synthetic.private:*",
        "--osv-query-mode",
        "batch",
    ]
    dispatch(parser().parse_args(options), store)
    dispatch(parser().parse_args(options + ["--background"]), store)
    for key in ("dependency_selection", "osv_policy", "osv_query_mode"):
        assert calls[0][key] == calls[1][key]
    assert calls[0]["osv_policy"]["exclude_names"] == ("synthetic.private:*",)


def test_partial_build_options_fail_before_work():
    with pytest.raises(ValueError, match="requires both"):
        build_selection("app", None)
    with pytest.raises(ValueError):
        build_selection("../private", "releaseRuntimeClasspath")
    with pytest.raises(ValueError):
        transmission_policy(names=["\ninvalid"])


def test_reassessed_excluded_dependency_cannot_inherit_checked_cache(tmp_path, store, monkeypatch):
    root = project(tmp_path / "source")
    monkeypatch.setattr(audit, "analyze_target", lambda target, *a, **kw: analyze(target, None))
    report = audit.scan(store, root)
    dep = report["inventory"]["dependencies"][0]
    store.feed(f"osv:{dep['ecosystem']}:{dep['name']}:{dep['version']}", "ok", fetched=True)
    query = {
        "mode": "batch",
        "packages": [
            {
                **{k: dep[k] for k in ("ecosystem", "name", "version")},
                "state": "excluded",
                "checked": False,
                "transmitted": False,
            }
        ],
    }
    after = audit.refresh_report(store, report["id"], dependency_query=query)
    checks = [c for c in after["coverage"] if c.get("dependency", {}).get("version") == dep["version"]]
    assert checks and all(c["state"] == "not-run" for c in checks)
    assert after["inventory"]["dependencies"][0]["osv_query"]["state"] == "excluded"
    result, _ = dispatch(
        parser().parse_args(["reports", "compare", report["id"], after["id"], "--verification"]), store
    )
    assert isinstance(result, dict)
    assert result["verification"]["scope_pairing"]["state"] == "unchanged"
    assert result["verification"]["build_pairing"]["state"] == "same-build"


def test_aab_archive_resources_are_used_and_conflicts_remain_unknown(tmp_path):
    ns = b"http://schemas.android.com/apk/res/android"
    attr = message(1, ns) + message(2, b"debuggable") + message(6, reference(0x7F010001))
    application = message(1, message(3, b"application") + message(4, attr))
    manifest = message(
        1,
        message(3, b"manifest")
        + message(4, message(2, b"package") + message(3, b"synthetic.app"))
        + message(5, application),
    )
    for conflicting in (False, True):
        target = tmp_path / ("conflict.aab" if conflicting else "resolved.aab")
        with zipfile.ZipFile(target, "w") as archive:
            archive.writestr("base/manifest/AndroidManifest.xml", manifest)
            archive.writestr("base/resources.pb", resource_table([(1, "flag", [(primitive(8, 1), b"")])]))
            if conflicting:
                archive.writestr(
                    "feature/resources.pb", resource_table([(1, "flag", [(primitive(8, 0), b"")])])
                )
        inv, _ = inspect_target(target)
        assert inv["partial"] and inv["aab_resources"]["installed_split_verified"] is False
        assert inv["aab_resources"]["evidence"][-1]["state"] == ("unresolved" if conflicting else "resolved")
        assert inv["aab_manifest"]["unresolved_attributes"] is conflicting


def test_dart_import_and_comment_import_boundaries():
    from mobile_audit.hybrid_analysis import analyze_hybrid

    helper = ("helper.dart", "void forward(String value) { controller.loadRequest(value); }")
    risky = ("main.dart", "import 'helper.dart'; void open() { forward(Uri.base.queryParameters.url); }")
    assert any(f["rule_id"] == "HYBRID-UNTRUSTED-URL" for f in analyze_hybrid([risky, helper])["findings"])
    fake_import = (
        "main.ts",
        "/* import { forward } from './helper'; */ function open() { forward(route.params.url); }",
    )
    safe_helper = ("helper.ts", "function forward(value: string) { controller.loadUrl(value); }")
    assert not analyze_hybrid([fake_import, safe_helper])["findings"]


@pytest.mark.parametrize("suffix", [".js", ".jsx", ".jsbundle", ".ts", ".tsx", ".dart"])
def test_hybrid_claim_retains_partial_file_state_and_alternative_paths(tmp_path, suffix):
    report = {
        "target": str(tmp_path),
        "inventory": {"hybrid_analysis": {"files": [{"path": "app/safe" + suffix, "state": "partial"}]}},
        "coverage": [{"rule_id": "HYBRID-UNTRUSTED-URL", "state": "partial"}],
        "findings": [],
    }
    result = verify_claim(report, path="app/safe" + suffix, rule="HYBRID-UNTRUSTED-URL")
    assert result["verdict"] == result["source_file_state"] == "partial"
    alternative = verify_claim(report, path="safe" + suffix, rule="HYBRID-UNTRUSTED-URL")
    assert alternative["verdict"] == "path-unmatched"
    assert alternative["candidate_paths"] == ["app/safe" + suffix]
    missing = verify_claim(report, path="missing" + suffix, rule="HYBRID-UNTRUSTED-URL")
    assert missing["verdict"] == "file-not-analyzed"


def test_cli_and_mcp_body_hybrid_claim_contract(tmp_path, store, monkeypatch):
    root = project(tmp_path / "source")
    (root / "app/safe.ts").write_text("function open() { view.loadUrl('https://owned.example/'); }")
    monkeypatch.setattr(audit, "analyze_target", lambda target, *a, **kw: analyze(target, None))
    report = audit.scan(store, root)
    result, _ = dispatch(
        parser().parse_args(
            [
                "verify",
                str(root),
                "--report",
                report["id"],
                "--path",
                "app/safe.ts",
                "--rule",
                "HYBRID-UNTRUSTED-URL",
            ]
        ),
        store,
    )
    assert isinstance(result, dict)
    assert result["source_file_state"] == "partial"
    # Exercise the actual trusted tool body without importing the privacy-denied
    # SDK prompts dependency. This does not validate MCP serving/serialization.
    tree = ast.parse((Path(__file__).parents[1] / "src/mobile_audit/mcp_server.py").read_text())
    tool = next(
        node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef) and node.name == "verify_finding"
    )
    tool.decorator_list = []

    @contextmanager
    def database():
        yield store

    namespace = {
        "Any": Any,
        "Path": Path,
        "database": database,
        "authorize": lambda path: Path(path).resolve(),
        "load_report": lambda store, identifier: store.report(identifier),
        "verify_claim": verify_claim,
    }
    exec(compile(ast.Module(body=[tool], type_ignores=[]), "trusted-mcp-tool-body", "exec"), namespace)
    mcp_result = namespace["verify_finding"](
        str(root), path="app/safe.ts", rule="HYBRID-UNTRUSTED-URL", report_id=report["id"]
    )
    assert mcp_result == result
