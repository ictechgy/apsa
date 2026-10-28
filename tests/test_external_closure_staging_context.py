"""Staging uncertainty must reach dependency provenance before correlation.

The parser call runs the real analyzer in process to bind each snapshot's bytes
without relying on the installed subprocess import path. OS isolation itself is
covered by the separate public CLI reproduction and normal integration suite.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from mobile_audit import _parser_worker, engine, input_snapshot, parser_sandbox


def project(path: Path) -> Path:
    path.mkdir()
    (path / "build.gradle").write_text("ext { releaseVersion = '1.0' }\n")
    leaf = path / "libs/app/build.gradle"
    leaf.parent.mkdir(parents=True)
    leaf.write_text(
        'dependencies { implementation "g:derived:$releaseVersion"\nimplementation "g:literal:3.0" }\n'
    )
    return path


def analyze(path: Path, home: Path, monkeypatch: pytest.MonkeyPatch) -> dict:
    monkeypatch.setenv("APSA_PARSER_LOCK_DIR", str(home / "locks"))

    def sandbox_command(args, *_args, **_kwargs):
        return args, {"state": "unit-boundary", "backend": "in-process-test"}

    def command(args, **_kwargs):
        return json.dumps(_parser_worker.analyze(Path(args[5]), None))

    monkeypatch.setattr(parser_sandbox, "sandbox_command", sandbox_command)
    monkeypatch.setattr(
        parser_sandbox, "activate", lambda wrapped, args, isolation, scratch: (wrapped, isolation)
    )
    monkeypatch.setattr(engine, "command", command)
    return engine.analyze_target(path, report_home=home)


@pytest.mark.parametrize("kind", ["symlink", "directory", "fifo"])
@pytest.mark.parametrize("name", ["build.gradle", "build.gradle.kts", "settings.gradle"])
def test_known_unread_script_withdraws_inferred_version_before_correlation(tmp_path, monkeypatch, kind, name):
    source = project(tmp_path / "source")
    omitted = source / "libs" / name
    if kind == "symlink":
        target = tmp_path / "synthetic-link-target.gradle"
        target.write_text("ext { releaseVersion = '2.0' }\n")
        omitted.symlink_to(target)
    elif kind == "directory":
        omitted.mkdir()
        (omitted / "nested.kt").write_text("class NestedSource\n")
    else:
        os.mkfifo(omitted)

    result = analyze(source, tmp_path / "home", monkeypatch)
    inventory = result["inventory"]
    deps = {item["name"]: item for item in inventory["dependencies"]}
    derived = deps["g:derived"]
    assert derived["version"] == "$releaseVersion"
    assert derived["confidence"] == "unknown"
    assert "version_source" not in derived
    assert "resolution" not in derived
    assert deps["g:literal"]["version"] == "3.0"
    assert deps["g:literal"]["confidence"] == "declared"
    assert inventory["partial"] is True
    assert inventory["fingerprint_complete"] is False
    assert inventory["input_snapshot"]["app_scope_complete"] is False
    assert inventory["credential_text"]["partial"] is True
    assert inventory["credential_text"]["staging_incomplete"] is True


@pytest.mark.parametrize("ancestor", ["absent", "regular-conflict"])
def test_complete_input_retains_existing_literal_context_contract(tmp_path, monkeypatch, ancestor):
    source = project(tmp_path / "source")
    if ancestor == "regular-conflict":
        (source / "libs/build.gradle").write_text("ext { releaseVersion = '2.0' }\n")
    result = analyze(source, tmp_path / "home", monkeypatch)
    inventory = result["inventory"]
    deps = {item["name"]: item for item in inventory["dependencies"]}
    if ancestor == "absent":
        assert deps["g:derived"]["version"] == "1.0"
        assert deps["g:derived"]["confidence"] == "declared"
        assert deps["g:derived"]["version_source"]["path"] == "build.gradle"
    else:
        assert deps["g:derived"]["version"] == "$releaseVersion"
        assert deps["g:derived"]["confidence"] == "unknown"
    assert deps["g:literal"]["version"] == "3.0"
    assert inventory["fingerprint_complete"] is True
    assert inventory["input_snapshot"]["app_scope_complete"] is True
    assert inventory["credential_text"]["partial"] is False
    assert not inventory["credential_text"].get("staging_incomplete", False)


def test_nonregular_script_directory_preserves_independent_nested_source(tmp_path):
    source = project(tmp_path / "source")
    nested = source / "libs/build.gradle/nested.kt"
    nested.parent.mkdir()
    nested.write_text("class IndependentlyReadable\n")
    staged = tmp_path / "staged"
    snapshot = input_snapshot.stage_input(source, staged)
    assert (staged / "libs/build.gradle/nested.kt").read_text() == nested.read_text()
    assert snapshot["app_scope_complete"] is False
    assert any("non-regular Gradle" in warning for warning in snapshot["warnings"])


def test_unread_scope_does_not_withdraw_direct_lockfile_evidence(tmp_path, monkeypatch):
    source = project(tmp_path / "source")
    (source / "unused-link.kt").symlink_to(tmp_path / "never-read-target.kt")
    (source / "gradle.lockfile").write_text("g:locked:4.0=runtimeClasspath\n")
    result = analyze(source, tmp_path / "home", monkeypatch)
    locked = next(item for item in result["inventory"]["dependencies"] if item["name"] == "g:locked")
    assert locked["version"] == "4.0"
    assert str(locked["version_source"]).startswith("gradle-lockfile")
    assert result["inventory"]["fingerprint_complete"] is False
