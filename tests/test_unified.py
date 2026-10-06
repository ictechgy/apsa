"""Observable integration contracts: common evidence, policies, jobs and MCP."""

import asyncio
import json
import plistlib
import shutil
import sys
import zipfile
from pathlib import Path

import pytest
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from pydantic import AnyUrl

from mobile_audit import jobs, quaygate_analysis
from mobile_audit.audit import compare, refresh_report, scan
from mobile_audit.core import file_digest
from mobile_audit.output import assistant_context, sarif
from mobile_audit.policy import evaluate
from mobile_audit.store import default_home
from quaygate.axml import AxmlError, parse_axml
from quaygate.checks import Finding
from quaygate.cli import main
from tests.test_binary_analysis import _macho


def test_android_both_engines_share_input_report(store, apk):
    report = scan(store, apk)
    assert report["inventory"]["engines"] == ["mobile-audit", "quaygate-lint"]
    assert report["inventory"]["quaygate"]["input_sha256"] == file_digest(apk)
    assert report["inventory"]["fingerprint"] == file_digest(apk)
    assert report["inventory"]["quaygate"]["complete"] is True
    assert "QG-APP-SIGNATURE" in {f["rule_id"] for f in report["findings"]}
    assert "QG-APP-SIGNATURE" in {f["ruleId"] for f in sarif(report)["runs"][0]["results"]}
    assert assistant_context(report)["engines"] == report["inventory"]["engines"]
    again = refresh_report(store, report["id"])
    assert again["parent_report"] == report["id"]
    assert compare(store, report["id"], again["id"])["added"] == []
    assert store.verify_reports()["state"] == "passed"


def test_debug_configuration_is_deduplicated_in_real_parser(store, tmp_path):
    target = tmp_path / "debug.apk"
    with zipfile.ZipFile(Path(__file__).parent / "fixtures/binary_analysis/unsafe.apk") as source:
        dex = source.read("classes.dex")
    with zipfile.ZipFile(target, "w") as archive:
        archive.writestr(
            "AndroidManifest.xml",
            '<manifest xmlns:android="http://schemas.android.com/apk/res/android" '
            'package="audit.fixture"><uses-sdk android:targetSdkVersion="36"/>'
            '<application android:debuggable="true"/></manifest>',
        )
        archive.writestr("classes.dex", dex)
    report = scan(store, target)
    debug = [f for f in report["findings"] if f["rule_id"] == "ANDROID-DEBUG"]
    assert len(debug) == 1 and debug[0]["severity"] == "high"
    assert debug[0]["supporting_checks"] == ["QG-APP-DEBUGGABLE"]
    assert "QG-APP-DEBUGGABLE" not in {f["rule_id"] for f in report["findings"]}


def test_ipa_extra_hardening_and_profile_checks_are_evidence_candidates(store, tmp_path):
    target = tmp_path / "app.ipa"
    with zipfile.ZipFile(target, "w") as archive:
        archive.writestr(
            "Payload/App.app/Info.plist",
            plistlib.dumps(
                {
                    "CFBundleIdentifier": "integration.ios",
                    "CFBundleExecutable": "Main",
                    "MinimumOSVersion": "16.0",
                    "UIFileSharingEnabled": True,
                }
            ),
        )
        archive.writestr("Payload/App.app/Main", _macho(pie=True))
        archive.writestr(
            "Payload/App.app/embedded.mobileprovision",
            b"CMS"
            + plistlib.dumps(
                {
                    "Entitlements": {"get-task-allow": True},
                }
            ),
        )
    report = scan(store, target)
    assert report["inventory"]["quaygate"]["complete"] is True
    assert report["inventory"]["quaygate"]["input_sha256"] == report["inventory"]["fingerprint"]
    values = {f["rule_id"]: f for f in report["findings"]}
    assert values["QG-IPA-GET-TASK-ALLOW"]["status"] == "candidate"
    assert values["QG-IPA-BINARY-HARDENING"]["status"] == "candidate"
    assert values["QG-IPA-FILE-SHARING"]["status"] == "configuration-confirmed"
    assert all(f["reproduced"] is False for f in values.values() if f.get("origin") == "quaygate-lint")


def test_source_scan_and_both_cli_names_use_common_engine(store, demo, capsys):
    assert main(["--home", str(store.home), "--json", "scan", str(demo)]) == 0
    report = json.loads(capsys.readouterr().out)["data"]
    assert report["inventory"]["engines"] == ["mobile-audit"]
    assert not any(f["rule_id"].startswith("QG-") for f in report["findings"])
    assert main(["rules", "--id", "QG-NATIVE-HARDENING", "--json", "--home", str(store.home)]) == 0
    assert json.loads(capsys.readouterr().out)["data"]["rules"][0]["engine"] == "quaygate-lint"


def test_backend_failure_preserves_other_evidence_and_fails_required_policy(tmp_path, monkeypatch):
    from mobile_audit._parser_worker import analyze

    def failed(_):
        raise ValueError("secret/private error must not be copied")

    monkeypatch.setattr(quaygate_analysis, "_audit", failed)
    target = Path(__file__).parent / "fixtures/binary_analysis/unsafe.apk"
    result = analyze(target, None)
    assert result["inventory"]["partial"] is True
    assert any(f["rule_id"] == "BINARY-WEBVIEW-FILE-ACCESS" for f in result["findings"])
    assert "secret/private" not in json.dumps(result)
    gate = evaluate(
        {**result, "runtime": [], "intel_snapshot": []},
        {
            "schema_version": 1,
            "required_rules": ["QG-NATIVE-HARDENING"],
        },
    )
    assert gate["state"] == "incomplete" and gate["exit_code"] == 3


def test_missing_binary_and_unsigned_profile_never_pass_required_rules(tmp_path):
    target = tmp_path / "empty.ipa"
    with zipfile.ZipFile(target, "w") as archive:
        archive.writestr("Payload/App.app/Info.plist", plistlib.dumps({"CFBundleIdentifier": "empty.ios"}))
    result = quaygate_analysis.analyze(target)
    coverage = {r["rule_id"]: r["state"] for r in result["coverage"]}
    assert coverage["QG-IPA-GET-TASK-ALLOW"] == "not-run"
    assert coverage["QG-BIN-SECRETS"] == "not-run"
    assert coverage["QG-IPA-BINARY-HARDENING"] == "not-run"


def test_no_dex_is_not_a_completed_string_check(tmp_path):
    from tests.helpers import temp_apk

    with temp_apk() as name:
        target = tmp_path / "without-dex.apk"
        with zipfile.ZipFile(name) as source, zipfile.ZipFile(target, "w") as dest:
            for item in source.infolist():
                if not item.filename.endswith(".dex"):
                    dest.writestr(item, source.read(item))
    states = {r["rule_id"]: r["state"] for r in quaygate_analysis.analyze(target)["coverage"]}
    assert states["QG-DEX-SECRETS"] == "not-run"
    assert states["QG-DEX-WEAK-CRYPTO"] == "not-run"


def test_secret_and_string_calls_stay_candidates_and_context_hides_literals(tmp_path, monkeypatch):
    literal = "sk-veryprivate123456789"
    monkeypatch.setattr(
        quaygate_analysis,
        "_audit",
        lambda _: (
            {"dex_entries": 1},
            [
                Finding("dex-secrets", "Secret indicator", "fail", "HIGH", literal),
                Finding("dex-webview", "Call indicator", "warn", "MEDIUM", 'call("private literal")'),
            ],
        ),
    )
    target = tmp_path / "app.apk"
    target.write_bytes(b"fixture")
    result = quaygate_analysis.analyze(target)
    assert all(f["status"] == "candidate" for f in result["findings"])
    assert literal not in json.dumps(result) and "private literal" not in json.dumps(result)


def test_plain_manifest_matches_binary_shape_and_rejects_entity_expansion():
    events = parse_axml(
        b'<manifest xmlns:android="http://schemas.android.com/apk/res/android">'
        b'<application android:debuggable="true"/></manifest>'
    )
    assert ("start", "application", {"debuggable": "true"}) in events
    with pytest.raises(AxmlError):
        parse_axml(b'<!DOCTYPE manifest [<!ENTITY x "expanded">]><manifest>&x;</manifest>')
    with pytest.raises(AxmlError):
        parse_axml(b"<manifest>" + b"<a>" * 129 + b"</a>" * 129 + b"</manifest>")


def test_home_environment_keeps_existing_history(monkeypatch, tmp_path):
    legacy = tmp_path / "old-state"
    monkeypatch.setenv("MOBILE_AUDIT_HOME", str(legacy))
    monkeypatch.delenv("QUAYGATE_HOME", raising=False)
    monkeypatch.delenv("APSA_HOME", raising=False)
    assert default_home() == legacy
    newer = tmp_path / "new-state"
    monkeypatch.setenv("QUAYGATE_HOME", str(newer))
    assert default_home() == newer
    canonical = tmp_path / "apsa-state"
    monkeypatch.setenv("APSA_HOME", str(canonical))
    assert default_home() == canonical


@pytest.mark.asyncio
async def test_background_binary_job_contains_both_engines(store, apk):
    job = jobs.start(store, {"kind": "scan", "target": str(apk)})
    status = job
    try:
        for _ in range(100):
            status = jobs.get(store, job["id"])
            if status["state"] in jobs.TERMINAL:
                break
            await asyncio.sleep(0.05)
        assert status["state"] == "completed", status
        report = store.report(status["report_id"])
        assert report["inventory"]["quaygate"]["complete"] is True
        assert any(f["rule_id"] == "QG-APP-SIGNATURE" for f in report["findings"])
    finally:
        if jobs.get(store, job["id"])["state"] not in jobs.TERMINAL:
            jobs.cancel(store, job["id"])


@pytest.mark.asyncio
@pytest.mark.parametrize("module", ["apsa", "quaygate", "mobile_audit"])
async def test_unified_mcp_binary_scan_root_and_resource_contract(store, apk, tmp_path, module):
    root = tmp_path / "owned"
    root.mkdir()
    target = root / "app.apk"
    shutil.copyfile(apk, target)
    params = StdioServerParameters(
        command=sys.executable,
        args=[
            "-m",
            module,
            "--home",
            str(store.home),
            "mcp",
            "--root",
            str(root),
        ],
    )
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            capabilities = (await session.call_tool("capabilities", {})).structuredContent
            assert capabilities is not None and capabilities["product"] == "apsa"
            assert capabilities["engines"] == ["mobile-audit", "quaygate-lint"]
            reply = await session.call_tool("audit_scan", {"target": str(target)})
            assert not reply.isError
            report = reply.structuredContent
            assert report is not None and report["engines"] == capabilities["engines"]
            assert any(f["rule_id"] == "QG-APP-SIGNATURE" for f in report["findings"])
            assert (await session.call_tool("audit_scan", {"target": str(apk)})).isError
            payloads = []
            for scheme in ("apsa", "quaygate", "mobile-audit"):
                resource = await session.read_resource(AnyUrl(f"{scheme}://reports/{report['report_id']}"))
                assert resource.contents
                payloads.append([item.model_dump(exclude={"uri"}) for item in resource.contents])
            assert payloads[0] == payloads[1] == payloads[2]
            resources = {str(r.uri) for r in (await session.list_resources()).resources}
            assert {"apsa://rules", "quaygate://rules", "mobile-audit://rules"} <= resources
