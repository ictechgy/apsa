"""CLI selections remain bound through the real engine and job preflight checks."""

import json
import os
import socket
import subprocess
from contextlib import nullcontext
from pathlib import Path
from types import SimpleNamespace

import psutil
import pytest

from mobile_audit import cli, engine, jobs, parser_sandbox
from mobile_audit.store import Store


@pytest.fixture(autouse=True)
def isolated_boundaries(monkeypatch, tmp_path):
    def denied(*args, **kwargs):
        raise AssertionError("Unexpected process, inventory, network, sandbox, or Store access")

    for name in ("run", "Popen", "call", "check_call", "check_output"):
        monkeypatch.setattr(subprocess, name, denied)
    for name in ("system", "fork", "posix_spawn", "posix_spawnp"):
        if hasattr(os, name):
            monkeypatch.setattr(os, name, denied)
    for name in ("Process", "process_iter", "pids", "net_connections"):
        monkeypatch.setattr(psutil, name, denied)
    monkeypatch.setattr(socket, "socket", denied)
    monkeypatch.setattr(Store, "__init__", denied)
    monkeypatch.setattr(engine, "command", denied)
    monkeypatch.setattr(engine, "parser_lease", denied)
    monkeypatch.setattr(parser_sandbox, "backend", denied)
    monkeypatch.setattr(parser_sandbox, "sandbox_command", denied)
    monkeypatch.setattr(parser_sandbox, "activate", denied)
    home = tmp_path / "new-home"
    home.mkdir()
    monkeypatch.setattr(Path, "home", lambda: home)
    expanduser = Path.expanduser
    monkeypatch.setattr(
        Path,
        "expanduser",
        lambda path: home / str(path)[2:] if str(path).startswith("~/") else expanduser(path),
    )
    closed = []
    store = SimpleNamespace(home=home, db=SimpleNamespace(execute=denied), close=lambda: closed.append(True))
    monkeypatch.setattr(cli, "Store", lambda *a, **k: store)
    return store, closed


@pytest.mark.parametrize("background", [False, True])
def test_cli_refuses_module_component_replaced_after_selection(
    tmp_path, monkeypatch, capsys, isolated_boundaries, background
):
    root = tmp_path / "new-root"
    component = root / "modules"
    selected = component / "app"
    selected.mkdir(parents=True)
    (selected / "Selected.java").write_text("class Selected {}")
    outside = tmp_path / "new-outside"
    (outside / "app").mkdir(parents=True)
    (outside / "app/Outside.java").write_text("class Outside {}")
    select = cli.select_source_module

    def replace_component(target, module):
        result = select(target, module)
        component.rename(root / "retained-selected-modules")
        component.symlink_to(outside, target_is_directory=True)
        return result

    monkeypatch.setattr(cli, "select_source_module", replace_component)
    initialized = []
    monkeypatch.setattr(jobs, "initialize", initialized.append)
    staging = []

    def refused_staging(*args, **kwargs):
        staging.append(args)
        pytest.fail("A replaced module must be refused before reading or staging its files")

    monkeypatch.setattr(engine, "stage_input", refused_staging)
    args = ["scan", str(root), "--source-module", "modules/app", "--json"]
    if background:
        args.append("--background")
    assert cli.main(args) == 1
    result = json.loads(capsys.readouterr().out)
    assert result["error"]["type"] == "ValueError"
    expected = (
        "Authorized job input moved or became a symlink"
        if background
        else "Authorized input moved or became a symlink; audit refused"
    )
    assert result["error"]["message"] == expected
    assert result["exit_code"] == 1 and staging == []
    store, closed = isolated_boundaries
    assert initialized == ([store] if background else [])
    assert closed == [True]


@pytest.mark.parametrize("sbom_kind", ["relative", "symlink", "home-relative"])
def test_foreground_binding_preserves_explicit_sbom_selection(
    tmp_path, monkeypatch, capsys, isolated_boundaries, sbom_kind
):
    root = tmp_path / "new-root"
    selected = root / "app"
    selected.mkdir(parents=True)
    (selected / "Selected.java").write_text("class Selected {}")
    root_alias = tmp_path / "selected-root-alias"
    root_alias.symlink_to(root, target_is_directory=True)
    store, closed = isolated_boundaries
    sbom = store.home / "selected-sbom.json"
    sbom.write_text('{"bomFormat": "CycloneDX", "components": []}')
    monkeypatch.chdir(tmp_path)
    if sbom_kind == "relative":
        sbom_argument = "new-home/selected-sbom.json"
    elif sbom_kind == "symlink":
        alias = tmp_path / "selected-sbom-alias.json"
        alias.symlink_to(sbom)
        sbom_argument = str(alias)
    else:
        sbom_argument = "~/selected-sbom.json"
    staged = []
    stage_input = engine.stage_input

    def observed_staging(target, *args, **kwargs):
        staged.append(target)
        return stage_input(target, *args, **kwargs)

    monkeypatch.setattr(engine, "stage_input", observed_staging)
    monkeypatch.setattr(engine, "parser_lease", lambda: nullcontext())
    monkeypatch.setattr(
        parser_sandbox, "sandbox_command", lambda args, *a, **k: (args, {"state": "mock-worker"})
    )
    monkeypatch.setattr(parser_sandbox, "activate", lambda wrapped, args, state, scratch: (wrapped, state))
    monkeypatch.setattr(
        engine,
        "command",
        lambda *a, **k: json.dumps({"inventory": {"warnings": []}, "findings": [], "coverage": []}),
    )

    def scan_boundary(store, target, online, sbom, environment, **options):
        return engine.analyze_target(
            target,
            sbom,
            options["expected_target"],
            options["configuration"],
            report_home=store.home,
        )

    monkeypatch.setattr(cli, "scan", scan_boundary)
    assert (
        cli.main(["scan", str(root_alias), "--source-module", "app", "--sbom", sbom_argument, "--json"]) == 0
    )
    assert json.loads(capsys.readouterr().out)["ok"] is True
    assert staged == [selected.resolve(), sbom.resolve()]
    assert closed == [True]
