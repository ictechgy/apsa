"""New synthetic APK sets and option contracts through public scan surfaces."""

import ast
import io
import json
import os
import plistlib
import zipfile
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from mobile_audit._parser_worker import analyze
from mobile_audit.cli import dispatch, parser
from mobile_audit.engine import analyze_target
from mobile_audit.run_options import artifact_options
from tests.apks_fixture import DEFAULT_DEVICE, DEFAULT_PATHS, apk_bytes, split_toc
from tests.test_ipa_trust import chain_fixture as synthetic_chain_fixture

chain_fixture = synthetic_chain_fixture


def apk_set(root: Path, *, malformed_identity=False, risky_split="base-arm64") -> Path:
    root.mkdir(parents=True)
    path = root / "synthetic.apks"
    toc, names = split_toc()
    with zipfile.ZipFile(path, "x", zipfile.ZIP_DEFLATED) as outer:
        outer.writestr("toc.pb", toc)
        for name in names:
            master = name == DEFAULT_PATHS[0]
            split = Path(name).stem
            raw = apk_bytes(config=not master, split_id="" if master else split)
            buffer = io.BytesIO(raw)
            with zipfile.ZipFile(buffer, "a") as child:
                if split == risky_split:
                    child.writestr("assets/bridge.js", "function open() { view.loadUrl(route.params.url); }")
            raw = buffer.getvalue()
            if malformed_identity and split == "base-arm64":
                source = zipfile.ZipFile(io.BytesIO(raw))
                modified = io.BytesIO()
                with source, zipfile.ZipFile(modified, "w") as child:
                    for item in source.infolist():
                        content = source.read(item)
                        if item.filename == "AndroidManifest.xml":
                            content = content.replace(b"org.synthetic.apks", b"org.synthetic.other")
                        child.writestr(item.filename, content)
                raw = modified.getvalue()
            outer.writestr(name, raw)
    return path


def test_apk_set_scan_retains_selected_member_evidence_and_partial_scope(tmp_path):
    target = apk_set(tmp_path / "input")
    result = analyze(target, None, apk_set_device=DEFAULT_DEVICE)
    inv = result["inventory"]
    selected = inv["apk_set"]["selected_apks"]
    paths = {entry["path"] for entry in selected}
    assert paths == {DEFAULT_PATHS[index] for index in (0, 1, 4, 5)}
    assert inv["input_kind"] == "apks" and inv["package"] == "org.synthetic.apks"
    assert inv["partial"] and inv["apk_set"]["installed_split_verified"] is False
    assert inv["apk_set"]["manifest_merge_verified"] is False
    risky = [f for f in result["findings"] if f["rule_id"] == "HYBRID-UNTRUSTED-URL"]
    assert risky and all(f["apk_set_member"] == DEFAULT_PATHS[1] for f in risky)
    assert all(f["origin"] == "source" for f in risky)
    assert all(f["evidence"][0]["path"].startswith(DEFAULT_PATHS[1] + "!/") for f in risky)
    assert not any(check["state"] == "checked" for check in result["coverage"])
    assert "selected-" not in json.dumps(inv)


def test_apk_set_device_changes_selected_analysis(tmp_path):
    target = apk_set(tmp_path / "input")
    x86 = {**DEFAULT_DEVICE, "supportedAbis": ["x86"]}
    result = analyze(target, None, apk_set_device=x86)
    assert DEFAULT_PATHS[1] not in result["inventory"]["apk_set"]["selected_apk_sha256"]
    assert not any(f["rule_id"] == "HYBRID-UNTRUSTED-URL" for f in result["findings"])


def test_apk_set_inconsistent_selected_identity_fails_closed(tmp_path):
    target = apk_set(tmp_path / "input", malformed_identity=True)
    with pytest.raises(ValueError, match="identities disagree"):
        analyze(target, None, apk_set_device=DEFAULT_DEVICE)


def test_apk_set_requires_explicit_selection_and_rejects_other_target_options(tmp_path):
    target = apk_set(tmp_path / "input")
    with pytest.raises(ValueError, match="explicit"):
        analyze(target, None)
    with pytest.raises(ValueError, match="requires an .apks"):
        artifact_options(tmp_path / "source", DEFAULT_DEVICE)
    with pytest.raises(ValueError, match="IPA trust policy requires"):
        artifact_options(target, DEFAULT_DEVICE, {})


def test_apk_set_real_parser_staging_preserves_device_and_archive_identity(tmp_path):
    target = apk_set(tmp_path / "input")
    try:
        result = analyze_target(target, apk_set_device=DEFAULT_DEVICE, report_home=tmp_path / "new-home")
    except ValueError as error:
        if str(error) != "RSS inspection unavailable; resource-limited execution refused":
            raise
        if os.environ.get("GITHUB_ACTIONS") == "true":
            pytest.fail("Disposable CI must measure actual parser staging and RSS")
        pytest.skip("Host privacy guard denies child RSS; actual parser staging remains unmeasured here")
    inv = result["inventory"]
    assert inv["target"] == str(target.resolve())
    assert inv["apk_set"]["device_spec"]["sdkVersion"] == DEFAULT_DEVICE["sdkVersion"]
    assert inv["input_snapshot"]["files"] == 1
    assert any(f["rule_id"] == "HYBRID-UNTRUSTED-URL" for f in result["findings"])


def artifact_case(root, kind, policy):
    if kind == "apks":
        return apk_set(root / "input"), "apk_set_device", "--apk-set-device", DEFAULT_DEVICE
    target = root / "synthetic.ipa"
    with zipfile.ZipFile(target, "x") as archive:
        archive.writestr(
            "Payload/App.app/Info.plist", plistlib.dumps({"CFBundleIdentifier": "synthetic.test"})
        )
    return target, "ipa_trust_policy", "--ipa-trust-policy", artifact_options(target, None, policy)[1]


@pytest.mark.parametrize("kind", ["apks", "ipa"])
def test_cli_foreground_and_background_share_artifact_options(
    tmp_path, store, monkeypatch, chain_fixture, kind
):
    target, key, flag, value = artifact_case(tmp_path, kind, chain_fixture[2])
    spec = tmp_path / "artifact-option.json"
    spec.write_text(json.dumps(value))
    calls = []
    monkeypatch.setattr(
        "mobile_audit.cli.scan",
        lambda *a, **kw: calls.append(kw) or {"findings": [], "coverage": [], "inventory": {}},
    )
    monkeypatch.setattr("mobile_audit.cli.jobs.start", lambda _, p: calls.append(p) or {"id": "new-job"})
    args = ["scan", str(target), flag, str(spec)]
    dispatch(parser().parse_args(args), store)
    dispatch(parser().parse_args(args + ["--background"]), store)
    assert calls[0][key] == calls[1][key] == value


@pytest.mark.parametrize("kind", ["apks", "ipa"])
@pytest.mark.parametrize("tool", ["audit_scan", "audit_start"])
def test_mcp_actual_tool_body_forwards_artifact_options(tmp_path, store, chain_fixture, kind, tool):
    # Executes the actual trusted source tool body; served SDK serialization is separate.
    target, key, _, value = artifact_case(tmp_path, kind, chain_fixture[2])
    module = ast.parse((Path(__file__).parents[1] / "src/mobile_audit/mcp_server.py").read_text())
    node = next(n for n in ast.walk(module) if isinstance(n, ast.FunctionDef) and n.name == tool)
    node.decorator_list = []
    calls = []

    @contextmanager
    def database():
        yield store

    def scan(*args, **kwargs):
        calls.append(kwargs)
        return {"id": "new-report"}

    def start(_, payload):
        calls.append(payload)
        return {"id": "new-report"}

    env = {
        "__name__": "mobile_audit.mcp_server",
        "Any": Any,
        "authorize": lambda value: Path(value),
        "select_source_module": lambda path, module: path,
        "database": database,
        "scan": scan,
        "jobs": SimpleNamespace(start=start),
        "load_specs": lambda _: None,
        "read_json": lambda path, **_: json.loads(path.read_text()),
        "assistant_context": lambda value: value,
        "load_report": lambda *args: {"id": "new-report"},
    }
    exec(compile(ast.Module(body=[node], type_ignores=[]), "trusted-source-tool", "exec"), env)
    assert env[tool](str(target), **{key: value})["id"] == "new-report"
    assert calls[0][key] == value


@pytest.mark.parametrize("kind", ["apks", "ipa"])
def test_actual_job_worker_forwards_serialized_artifact_options(tmp_path, store, monkeypatch, kind):
    from mobile_audit import _job_worker as worker
    from mobile_audit.core import digest, now

    # This is an option serialization test; full generated certificate chains
    # are verified in test_ipa_trust.py. A digest-bound DER sequence is enough
    # for policy schema normalization and never reaches a certificate verifier.
    policy = {"schema_version": 1, "anchors": [{"der_base64": "MAA=", "sha256": digest(b"\x30\x00")}]}
    target, key, _, value = artifact_case(tmp_path, kind, policy)
    payload = {"kind": "scan", "target": str(target), key: value}
    stamp = now()
    worker.jobs.initialize(store)
    with store.db:
        store.db.execute(
            "INSERT INTO jobs VALUES(?,?,?,?,?,?,?, ?,NULL,NULL,NULL,'')",
            ("new-job", "queued", stamp, stamp, str(target), json.dumps(payload), 0, "queued"),
        )
    calls = []

    def scan(active_store, actual_target, **options):
        assert actual_target == target
        assert active_store.db.execute("SELECT state FROM jobs WHERE id='new-job'").fetchone()[0] == "running"
        calls.append(options)
        options["progress"]("synthetic-artifact-options", 50)
        assert active_store.db.execute("SELECT progress FROM jobs WHERE id='new-job'").fetchone()[0] == 50
        return active_store.save_report({"id": "new-report", "created": stamp, "target": str(target)})

    monkeypatch.setattr(worker.signal, "signal", lambda *a: None)
    monkeypatch.setattr(worker, "scan", scan)
    monkeypatch.setattr(worker.sys, "argv", ["new-worker", str(store.home), "new-job"])
    worker.main()
    assert len(calls) == 1 and calls[0][key] == value
    assert calls[0]["expected_target"] == target
    result = worker.jobs.get(store, "new-job")
    assert result["state"] == result["stage"] == "completed" and result["progress"] == 100
    assert result["report_id"] == "new-report"
    assert store.report("new-report")["target"] == str(target)
