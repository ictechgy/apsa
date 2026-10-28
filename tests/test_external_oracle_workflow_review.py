"""Fresh-job CI trust controls; in-memory HTTPS double and synthetic ZIP data only."""

from __future__ import annotations

import hashlib
import io
import json
import re
import struct
import subprocess
import urllib.request
import zipfile
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/dependency-oracle.yml"
CASES = {"owncloud", "nextcloud", "home-assistant", "signal", "amaze"}


def workflow():
    return yaml.safe_load(WORKFLOW.read_text())


def record_code():
    steps = workflow()["jobs"]["record"]["steps"]
    command = next(s["run"] for s in steps if s.get("name", "").startswith("Verify manifest-commit"))
    assert command.startswith("python3 -I - <<'PY'\n") and command.endswith("\nPY\n")
    return command.split("\n", 1)[1].rsplit("\nPY\n", 1)[0]


def test_untrusted_build_and_trusted_recorder_are_distinct_fresh_jobs():
    jobs = workflow()["jobs"]
    assert set(jobs) == {"build", "record"}
    assert jobs["record"]["needs"] == "build"
    for job in jobs.values():
        assert job["runs-on"] == "ubuntu-24.04"
        assert job["strategy"]["fail-fast"] is False
        assert {entry["case"] for entry in job["strategy"]["matrix"]["include"]} == CASES
        checkout = job["steps"][0]
        assert checkout["uses"].startswith("actions/checkout@")
        assert checkout["with"] == {"persist-credentials": False, "path": "apsa"}
    build_commands = "\n".join(s.get("run", "") for s in jobs["build"]["steps"])
    record_commands = "\n".join(s.get("run", "") for s in jobs["record"]["steps"])
    assert "./gradlew" in build_commands
    assert "./gradlew" not in record_commands
    assert '"record"' in record_commands
    assert 'recorder["case"](identifier)' in record_commands
    assert 'recorder["fetch"](spec, archive_path)' in record_commands
    assert "steps.fetch.outputs" not in record_commands


def test_raw_and_final_artifacts_are_distinct_and_downstream_names_preserved():
    jobs = workflow()["jobs"]
    raw = jobs["build"]["steps"][-1]["with"]
    final = jobs["record"]["steps"][-1]["with"]
    assert raw["name"] == "untrusted-gradle-output-${{ matrix.case }}"
    assert raw["path"] == "${{ runner.temp }}/raw-oracle-output/"
    assert final["name"] == "dependency-oracle-${{ matrix.case }}"
    assert "trusted-oracle/*.zip" in final["path"]
    assert "/source/" not in final["path"] and "**" not in final["path"]
    assert "raw-oracle-output" not in final["path"]
    assert final["retention-days"] == raw["retention-days"] == 90
    for job in jobs.values():
        for step in job["steps"]:
            if "uses" in step:
                assert re.search(r"@[a-f0-9]{40}$", step["uses"])


def source_archive():
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(
            "fresh-public-source/gradle/libs.versions.toml",
            '[libraries]\nprobe = { module = "g:a", version = "1.0" }\n',
        )
        archive.writestr("fresh-public-source/owncloudApp/.keep", "synthetic only")
        archive.writestr("fresh-public-source/gradlew", "NEVER EXECUTE THIS SYNTHETIC SOURCE")
    return stream.getvalue()


@pytest.fixture
def boundary(tmp_path, monkeypatch):
    raw = tmp_path / "untrusted-gradle-output"
    raw.mkdir()
    expected = source_archive()
    (raw / "owncloud.zip").write_bytes(expected)
    (raw / "owncloud.lockfile").write_text("g:a:1.0=releaseRuntimeClasspath\n")
    (raw / "owncloud.dependencies.txt").write_text("synthetic untrusted resolver text\n")
    (raw / "owncloud.java.txt").write_text("synthetic compiler metadata\n")
    urls = []

    def https(url, *, timeout):
        assert timeout == 120
        urls.append(url)
        assert (
            url == "https://codeload.github.com/owncloud/android/zip/0d6c955f9d06776bce425d88b55f608c8bd6fe89"
        )
        return io.BytesIO(expected)

    monkeypatch.setattr(urllib.request, "urlopen", https)
    monkeypatch.setenv("RUNNER_TEMP", str(tmp_path))
    monkeypatch.setenv("ORACLE_CASE", "owncloud")
    monkeypatch.chdir(ROOT)
    return {"root": tmp_path, "raw": raw, "expected": expected, "urls": urls}


def execute():
    exec(compile(record_code(), "dependency-oracle-record-step", "exec"), {})


def test_fresh_trusted_source_and_actual_recorder_keep_untrusted_scope(boundary, monkeypatch):
    commands = []
    original = subprocess.run

    def run(argv, **kwargs):
        commands.append(argv)
        return original(argv, **kwargs)

    monkeypatch.setattr(subprocess, "run", run)
    execute()
    assert len(boundary["urls"]) == 1
    assert len(commands) == 1 and commands[0][1:4] == ["-I", "benchmarks/dependency_oracle.py", "record"]
    assert commands[0][-1] == hashlib.sha256(boundary["expected"]).hexdigest()
    work = boundary["root"] / "trusted-oracle"
    result = json.loads((work / "owncloud.oracle.json").read_text())
    assert result["shipped_coordinates"] == [{"module": "g:a", "versions": ["1.0"]}]
    provenance = result["recording_provenance"]
    assert provenance["recorder"] == "fresh-trusted-checkout-job"
    assert provenance["reviewed_truth"] is False
    assert provenance["upstream_build_executed_in_recording_job"] is False
    assert provenance["resolved_outputs"] == "untrusted-upstream-Gradle-build-observations"
    assert provenance["expected_archive_sha256"] == result["archive"]["sha256"]
    assert "fresh-HTTPS" in provenance["source_identity"]
    assert (work / "source/fresh-public-source/gradlew").read_text() == "NEVER EXECUTE THIS SYNTHETIC SOURCE"


def test_modified_uploaded_archive_rejected_before_extraction_or_recorder(boundary, monkeypatch):
    (boundary["raw"] / "owncloud.zip").write_bytes(b"attacker-modified source")
    run = []
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: run.append(a))
    with pytest.raises(ValueError, match="differs from fresh trusted"):
        execute()
    assert boundary["urls"]
    assert not run
    assert not (boundary["root"] / "trusted-oracle/source").exists()


def test_uploaded_manifest_is_not_a_trusted_pin(boundary):
    (boundary["raw"] / "owncloud.archive.json").write_text(json.dumps({"sha256": "0" * 64}))
    with pytest.raises(ValueError, match="four bounded raw"):
        execute()
    assert boundary["urls"] == []


def test_symbolic_link_build_output_rejected_without_reading_target(boundary):
    path = boundary["raw"] / "owncloud.lockfile"
    path.unlink()
    target = boundary["root"] / "fresh-synthetic-target"
    target.write_text("synthetic test value only")
    path.symlink_to(target)
    with pytest.raises(OSError):
        execute()
    assert boundary["urls"] == []


@pytest.mark.parametrize(
    "suffix,size", [("zip", 512 * 1024 * 1024), ("lockfile", 8 * 1024 * 1024), ("java.txt", 1024 * 1024)]
)
def test_declared_raw_byte_budgets_checked_before_buffering(boundary, suffix, size):
    with (boundary["raw"] / ("owncloud." + suffix)).open("wb") as handle:
        handle.truncate(size + 1)  # Sparse fixture; do not allocate/read these bytes.
    with pytest.raises(ValueError, match="byte budget"):
        execute()
    assert boundary["urls"] == []


def test_fresh_source_extraction_is_bounded_before_extract(boundary, monkeypatch):
    forged = bytearray(boundary["expected"])
    central = forged.index(b"PK\x01\x02")
    struct.pack_into("<I", forged, central + 24, 64 * 1024 * 1024 + 1)
    value = bytes(forged)
    (boundary["raw"] / "owncloud.zip").write_bytes(value)
    monkeypatch.setattr(urllib.request, "urlopen", lambda *a, **k: io.BytesIO(value))
    with pytest.raises(ValueError, match="member exceeds the extraction budget"):
        execute()
    assert not (boundary["root"] / "trusted-oracle/source").exists()


def test_failed_recorder_does_not_create_oracle_success(boundary, monkeypatch):
    def fail(argv, **kwargs):
        raise subprocess.CalledProcessError(2, argv)

    monkeypatch.setattr(subprocess, "run", fail)
    with pytest.raises(subprocess.CalledProcessError):
        execute()
    assert not (boundary["root"] / "trusted-oracle/owncloud.oracle.json").exists()
