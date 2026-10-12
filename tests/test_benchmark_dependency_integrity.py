"""Workflow guards prevent unpinned benchmark execution and accidental broad mounts."""

import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest
import yaml


@pytest.fixture
def benchmark_job():
    root = Path(__file__).resolve().parents[1]
    workflow = yaml.load(
        (root / ".github/workflows/competitive-benchmark.yml").read_text(), Loader=yaml.BaseLoader
    )
    return workflow["jobs"]["compare"]


def _step(job, name):
    return next(step["run"] for step in job["steps"] if name in step.get("name", ""))


def _python_blocks(run):
    blocks = re.findall(r"(?ms)^(?:uv run --locked )?python - <<'PY'\n(.*?)^PY$", run)
    assert blocks, "Expected actual workflow inline Python, not a reconstructed guard"
    return blocks


def _execute(block):
    # Only the actual JSON/identity Python blocks execute; no workflow shell,
    # Docker command, compiler, download, or fixture binary is invoked.
    exec(compile(block, "<synthetic-workflow-integrity-contract>", "exec"), {})


@pytest.fixture
def image_inspection(benchmark_job, tmp_path, monkeypatch):
    blocks = _python_blocks(_step(benchmark_job, "Prepare pinned Semgrep"))
    assert len(blocks) == 2
    monkeypatch.setenv("RUNNER_TEMP", str(tmp_path))
    declared = benchmark_job["env"]["SEMGREP_BENCHMARK_IMAGE"]
    monkeypatch.setenv("SEMGREP_BENCHMARK_IMAGE", declared)
    image_id = "sha256:" + "d" * 64

    def inspect(observed, observed_id=image_id):
        (tmp_path / "semgrep-image-digests.json").write_text(json.dumps(observed))
        (tmp_path / "semgrep-image-id.json").write_text(json.dumps(observed_id))
        _execute(blocks[1])

    return declared, image_id, inspect


@pytest.fixture
def terminal_execution(benchmark_job, tmp_path, monkeypatch):
    blocks = _python_blocks(_step(benchmark_job, "Measure limited Semgrep"))
    assert len(blocks) == 1
    declared = benchmark_job["env"]["SEMGREP_BENCHMARK_IMAGE"]
    image_id = "sha256:" + "d" * 64
    container_id = "c" * 64
    run_id, head_sha = "123456", "e" * 40
    for key, value in {
        "RUNNER_TEMP": str(tmp_path),
        "SEMGREP_BENCHMARK_IMAGE": declared,
        "GITHUB_RUN_ID": run_id,
        "GITHUB_SHA": head_sha,
    }.items():
        monkeypatch.setenv(key, value)
    (tmp_path / "semgrep-image-id.json").write_text(json.dumps(image_id))
    provenance = tmp_path / "semgrep-container-provenance"
    provenance.mkdir()
    results = tmp_path / "semgrep-results"
    results.mkdir()
    (results / "result.json").write_text(
        json.dumps(
            {
                "scope": "new synthetic measurement only",
                "cases": [
                    {
                        "id": "synthetic-case",
                        "tools": {
                            "semgrep": {
                                "state": "matched",
                                "seconds": 0.125,
                                "rss": None,
                                "rss_state": "unavailable-container",
                                "rss_bytes": None,
                            }
                        },
                    }
                ],
            }
        )
    )
    baseline = {
        "container_id": container_id,
        "image_id": image_id,
        "declared": declared,
        "run_id": run_id,
        "head_sha": head_sha,
        "running": False,
        "exit_code": 0,
    }

    use_baseline = object()

    def verify(record=use_baseline, journal=None):
        owned = [container_id] if journal is None else journal
        (tmp_path / "semgrep-owned-container-ids.txt").write_text("\n".join(owned) + ("\n" if owned else ""))
        (provenance / (container_id + ".json")).write_text(
            json.dumps(baseline if record is use_baseline else record)
        )
        _execute(blocks[0])

    return baseline, verify


def test_competitive_tools_require_predeclared_pins_before_use():
    path = Path(__file__).resolve().parents[1] / ".github/workflows/competitive-benchmark.yml"
    workflow = yaml.load(path.read_text(), Loader=yaml.BaseLoader)
    job = workflow["jobs"]["compare"]
    semgrep = next(step["run"] for step in job["steps"] if "Prepare pinned Semgrep" in step.get("name", ""))
    assert "uv pip install" not in semgrep
    assert semgrep.index("re.fullmatch") < semgrep.index("docker pull")
    assert 'docker pull --platform linux/amd64 "$SEMGREP_BENCHMARK_IMAGE"' in semgrep
    assert "--entrypoint semgrep" in semgrep
    assert "--network none --read-only" in semgrep
    assert "source=$RUNNER_TEMP,target=$RUNNER_TEMP" not in semgrep
    assert "source=$RUNNER_TEMP/competitive-fixtures" in semgrep
    assert "source=$RUNNER_TEMP/semgrep-rules" in semgrep
    assert "source=$RUNNER_TEMP/semgrep-results,target=$RUNNER_TEMP/semgrep-results,readonly" in semgrep
    assert semgrep.index('container_id="$(docker create') < semgrep.index("semgrep-owned-container-ids.txt")
    assert semgrep.index("semgrep-owned-container-ids.txt") < semgrep.index("docker start --attach")
    assert "State.ExitCode" in semgrep
    run = next(step["run"] for step in job["steps"] if "Measure limited Semgrep" in step.get("name", ""))
    assert "--semgrep-runtime container" in run
    assert '--semgrep-image "$SEMGREP_BENCHMARK_IMAGE"' in run
    jadx = next(step["run"] for step in job["steps"] if "Prepare MobSF" in step.get("name", ""))
    assert jadx.index("scripts/verify_dependency.py") < jadx.index("unzip -q")
    assert jadx.index("APSA_JADX_MUTATION=") < jadx.index("unzip -q")
    assert '--expected-sha256 "$JADX_BENCHMARK_SHA256"' in jadx
    cleanup = next(
        step["run"] for step in job["steps"] if "Remove benchmark-only service" in step.get("name", "")
    )
    assert "semgrep-owned-container-ids.txt" in cleanup
    assert cleanup.index('test "$owner" = "$GITHUB_RUN_ID/$GITHUB_SHA"') < cleanup.index(
        'docker rm -f "$container_id"'
    )
    assert "docker system prune" not in cleanup


def test_workflow_source_pins_exactly_match_reviewed_acquisition_and_precede_mutations(benchmark_job):
    root = Path(__file__).resolve().parents[1]
    documentation = json.loads((root / "docs/benchmark-integrity.json").read_text())
    pins = documentation["accepted_pins"]
    declared = benchmark_job["env"]["SEMGREP_BENCHMARK_IMAGE"]
    assert declared == pins["semgrep_execution_reference"]
    assert "docker.io/" + declared == pins["semgrep_acquired_repo_digest"]
    assert pins["semgrep_acquired_repo_digest"] == documentation["acquisition"]["semgrep"]["repo_digest"]
    jadx = benchmark_job["env"]["JADX_BENCHMARK_SHA256"]
    assert jadx == pins["jadx_zip_sha256"]
    assert re.fullmatch(r"[a-f0-9]{64}", jadx)
    assert {item["sha256"] for item in documentation["acquisition"]["jadx"]["acquisitions"]} == {jadx}
    semgrep_run = _step(benchmark_job, "Prepare pinned Semgrep")
    # The pin comes from job source, never from the just-pulled image inspection.
    assert "SEMGREP_BENCHMARK_IMAGE=" not in semgrep_run
    assert semgrep_run.index("reviewed source-predeclared OCI digest") < semgrep_run.index("docker pull")
    jadx_run = _step(benchmark_job, "Prepare MobSF")
    assert "JADX_BENCHMARK_SHA256=" not in jadx_run
    assert jadx_run.index("scripts/verify_dependency.py") < jadx_run.index("artifact.write")
    assert jadx_run.index("APSA_JADX_MUTATION=") < jadx_run.index("unzip -q")


@pytest.mark.parametrize(
    "declared",
    [
        "",
        "semgrep/semgrep:1.179.0",
        "other/semgrep@sha256:" + "a" * 64,
        "semgrep/semgrep@sha256:" + "a" * 63,
        "docker.io.evil/semgrep/semgrep@sha256:" + "a" * 64,
    ],
)
def test_actual_pre_pull_guard_rejects_missing_malformed_and_other_origin_pin(
    benchmark_job, monkeypatch, declared
):
    monkeypatch.setenv("SEMGREP_BENCHMARK_IMAGE", declared)
    block = _python_blocks(_step(benchmark_job, "Prepare pinned Semgrep"))[0]
    with pytest.raises(ValueError, match="source-predeclared OCI digest"):
        _execute(block)


@pytest.mark.parametrize("docker_prefix", ["", "docker.io/"])
def test_actual_image_inspection_accepts_only_official_alias_of_identical_pin(
    image_inspection, capsys, docker_prefix
):
    declared, image_id, inspect = image_inspection
    inspect([docker_prefix + declared])
    observation = json.loads(capsys.readouterr().out.removeprefix("APSA_SEMGREP_IMAGE="))
    assert observation["canonical_declared"] == declared
    assert observation["image_id"] == image_id


@pytest.mark.parametrize(
    "observed",
    [None, {}, "declared", [], [None], [123], ["other/project@sha256:" + "a" * 64]],
)
def test_actual_image_inspection_rejects_malformed_or_other_repository(image_inspection, observed):
    _, _, inspect = image_inspection
    with pytest.raises(ValueError, match="declared pin"):
        inspect(observed)


@pytest.mark.parametrize(
    "mutation", ["lookalike-registry", "other-repository", "wrong-hash", "mixed-malformed", "too-many"]
)
def test_actual_image_inspection_rejects_wrong_origin_hash_and_mixed_metadata(image_inspection, mutation):
    declared, _, inspect = image_inspection
    if mutation == "lookalike-registry":
        observed = ["docker.io.evil/" + declared]
    elif mutation == "other-repository":
        observed = [declared.replace("semgrep/semgrep", "other/semgrep")]
    elif mutation == "wrong-hash":
        observed = ["semgrep/semgrep@sha256:" + "a" * 64]
    elif mutation == "mixed-malformed":
        observed = [declared, None]
    else:
        observed = [declared] * 17
    with pytest.raises(ValueError, match="declared pin"):
        inspect(observed)


@pytest.mark.parametrize("image_id", [None, {}, 1, "", "sha256:" + "a" * 63, "sha256:" + "g" * 64])
def test_actual_image_inspection_rejects_malformed_image_id(image_inspection, image_id):
    declared, _, inspect = image_inspection
    with pytest.raises(ValueError, match="image ID is malformed"):
        inspect([declared], image_id)


def test_actual_terminal_gate_accepts_owned_successful_pinned_container(terminal_execution, capsys):
    baseline, verify = terminal_execution
    verify()
    lines = capsys.readouterr().out.splitlines()
    execution = json.loads(lines[0].removeprefix("APSA_SEMGREP_CONTAINER_EXECUTION="))
    assert execution["container_execution_verified"] is True
    assert execution["containers"] == [baseline]
    assert "APSA_SEMGREP_MEASUREMENT_BEGIN" in lines and "APSA_SEMGREP_MEASUREMENT_END" in lines


@pytest.mark.parametrize("record", [[], None, "synthetic", 0])
def test_actual_terminal_gate_rejects_nonobject_record(terminal_execution, record):
    _, verify = terminal_execution
    with pytest.raises(ValueError, match="identity or successful completion"):
        verify(record)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("container_id", "b" * 64),
        ("image_id", "sha256:" + "b" * 64),
        ("image_id", "malformed"),
        ("declared", "other/semgrep@sha256:" + "a" * 64),
        ("run_id", "different-run"),
        ("head_sha", "f" * 40),
        ("running", True),
        ("running", None),
        ("running", "false"),
        ("running", 0),
        ("exit_code", 1),
        ("exit_code", None),
        ("exit_code", "0"),
        ("exit_code", False),
    ],
)
def test_actual_terminal_gate_rejects_identity_owner_incomplete_or_unsuccessful_record(
    terminal_execution, field, value
):
    baseline, verify = terminal_execution
    record = {**baseline, field: value}
    with pytest.raises(ValueError, match="identity or successful completion"):
        verify(record)


@pytest.mark.parametrize(
    "field", ["container_id", "image_id", "declared", "run_id", "head_sha", "running", "exit_code"]
)
def test_actual_terminal_gate_rejects_missing_required_record_field(terminal_execution, field):
    baseline, verify = terminal_execution
    record = dict(baseline)
    record.pop(field)
    with pytest.raises(ValueError, match="identity or successful completion"):
        verify(record)


@pytest.mark.parametrize("kind", ["empty", "duplicate", "oversized", "malformed", "path-traversal"])
def test_actual_terminal_gate_rejects_ambiguous_or_unsafe_owned_journal(terminal_execution, kind):
    baseline, verify = terminal_execution
    journal = {
        "empty": [],
        "duplicate": [baseline["container_id"]] * 2,
        "oversized": [f"{index:064x}" for index in range(17)],
        "malformed": ["g" * 64],
        "path-traversal": ["../synthetic-record"],
    }[kind]
    with pytest.raises(ValueError, match="journal"):
        verify(journal=journal)


@pytest.fixture
def version_failure_diagnostic(benchmark_job, tmp_path, monkeypatch):
    block = _python_blocks(_step(benchmark_job, "Report bounded public Semgrep version failure provenance"))
    assert len(block) == 1
    run_id, head_sha = "123456", "e" * 40
    monkeypatch.setenv("RUNNER_TEMP", str(tmp_path))
    monkeypatch.setenv("GITHUB_RUN_ID", run_id)
    monkeypatch.setenv("GITHUB_SHA", head_sha)
    input_path = tmp_path / "semgrep-results/semgrep-version.json"
    input_path.parent.mkdir()

    def diagnose():
        _execute(block[0])
        return json.loads((tmp_path / "semgrep-failure-probe.json").read_text())

    return input_path, diagnose, run_id, head_sha


def test_actual_version_diagnostic_missing_file_stays_unmeasured(version_failure_diagnostic, capsys):
    path, diagnose, run_id, head_sha = version_failure_diagnostic
    assert not path.exists()
    report = diagnose()
    emitted = json.loads(capsys.readouterr().out.removeprefix("APSA_SEMGREP_VERSION_FAILURE="))
    assert emitted == report
    assert report == {
        "source_revision": head_sha,
        "run_id": run_id,
        "state": "unmeasured",
        "reason": "version-probe-not-created",
        "target_rss_bytes": None,
        "client_rss_excluded": True,
    }


@pytest.mark.parametrize("stdout_size,stderr_size", [(0, 0), (2048, 4096), (2049, 4097)])
def test_actual_version_diagnostic_preserves_failure_hash_and_bounded_streams(
    version_failure_diagnostic, capsys, stdout_size, stderr_size
):
    path, diagnose, run_id, head_sha = version_failure_diagnostic
    observation = {
        "status": 124,
        "incomplete": True,
        "seconds": 30.125,
        "stdout": "é" * stdout_size,
        "stderr": "z" * stderr_size,
        "rss": 12345678,
        "rss_bytes": 12345678,
        "target_rss_bytes": 12345678,
        "client_rss_excluded": False,
        "rss_state": "measured-client-only",
    }
    raw = (json.dumps(observation, ensure_ascii=False) + "\n").encode("utf-8")
    path.write_bytes(raw)
    report = diagnose()
    emitted = json.loads(capsys.readouterr().out.removeprefix("APSA_SEMGREP_VERSION_FAILURE="))
    assert emitted == report
    assert report["source_revision"] == head_sha and report["run_id"] == run_id
    assert report["state"] == "observed" and report["reason"] == "version-contract-failure"
    assert report["status"] == 124 and report["incomplete"] is True and report["seconds"] == 30.125
    assert report["evidence_sha256"] == hashlib.sha256(raw).hexdigest()
    assert report["stdout"] == observation["stdout"][:2048]
    assert report["stderr"] == observation["stderr"][:4096]
    assert report["stdout_truncated"] is (stdout_size > 2048)
    assert report["stderr_truncated"] is (stderr_size > 4096)
    assert report["target_rss_bytes"] is None and report["client_rss_excluded"] is True
    assert "rss" not in report and "rss_bytes" not in report and "rss_state" not in report


@pytest.mark.parametrize("kind", ["oversized", "symlink"])
def test_actual_version_diagnostic_rejects_oversized_or_symlink_input(
    version_failure_diagnostic, tmp_path, kind, capsys
):
    path, diagnose, _, _ = version_failure_diagnostic
    if kind == "oversized":
        with path.open("wb") as stream:
            stream.seek(3 * 1024 * 1024)
            stream.write(b"x")
        assert path.stat().st_size == 3 * 1024 * 1024 + 1
    else:
        target = tmp_path / "new-synthetic-version-record.json"
        target.write_text(
            json.dumps({"status": 1, "incomplete": False, "seconds": 1, "stdout": "", "stderr": ""})
        )
        path.symlink_to(target)
    with pytest.raises(ValueError, match="unsafe or oversized"):
        diagnose()
    assert not (tmp_path / "semgrep-failure-probe.json").exists()
    assert capsys.readouterr().out == ""


@pytest.mark.parametrize("field", ["stdout", "stderr"])
def test_actual_version_diagnostic_rejects_malformed_stream(version_failure_diagnostic, field):
    path, diagnose, _, _ = version_failure_diagnostic
    observation = {"status": 1, "incomplete": False, "seconds": 1, "stdout": "", "stderr": ""}
    observation[field] = None
    path.write_text(json.dumps(observation))
    with pytest.raises(ValueError, match="stream is malformed"):
        diagnose()


def test_version_failure_diagnostic_does_not_accept_pins_versions_or_extend_deadline(benchmark_job):
    step = next(
        step
        for step in benchmark_job["steps"]
        if step.get("name") == "Report bounded public Semgrep version failure provenance"
    )
    assert step["if"] == "failure()"
    block = _python_blocks(step["run"])[0]
    assert "subprocess" not in block and "docker" not in block
    assert "SEMGREP_BENCHMARK_IMAGE" not in block and "JADX_BENCHMARK_SHA256" not in block
    measure = next(
        step for step in benchmark_job["steps"] if "Measure limited Semgrep" in step.get("name", "")
    )
    assert "continue-on-error" not in measure
    source = (Path(__file__).resolve().parents[1] / "benchmarks/semgrep_compare.py").read_text()
    assert 'VERSION = "1.179.0"' in source
    assert 'version_call = capture([executable, "--version"], output, environment, timeout=30)' in source
    assert 'if version_call["status"] or version_call["incomplete"] or version != VERSION:' in source
    assert 'raise ValueError("Semgrep executable must report the pinned version " + VERSION)' in source


@pytest.fixture
def synthetic_wrapper(benchmark_job, tmp_path):
    """Run only a source wrapper and newly written fake CLI; never real Docker."""
    prepare = _step(benchmark_job, "Prepare pinned Semgrep")
    match = re.search(r"(?ms)^cat > \"\$RUNNER_TEMP/semgrep-wrapper\" <<'SH'\n(.*?)^SH$", prepare)
    assert match is not None, "Extract the actual workflow shell wrapper"
    wrapper = tmp_path / "synthetic-semgrep-wrapper"
    wrapper.write_text(match.group(1))
    fake_bin = tmp_path / "synthetic-bin"
    fake_bin.mkdir()
    fake_docker = fake_bin / "docker"
    fake_docker.write_text(
        f"#!{sys.executable}\n"
        + """# Unit fixture only: records arguments and synthesizes Docker replies.
import json
import os
import sys
from pathlib import Path
argv = sys.argv[1:]
calls = Path(os.environ["APSA_SYNTHETIC_DOCKER_CALLS"])
state_path = Path(os.environ["APSA_SYNTHETIC_DOCKER_STATE"])
with calls.open("a") as stream:
    stream.write(json.dumps(argv) + "\\n")
container_id = os.environ["APSA_SYNTHETIC_CONTAINER_ID"]
if argv[0] == "create":
    labels = dict(argv[index + 1].split("=", 1) for index, value in enumerate(argv) if value == "--label")
    image = argv[argv.index("--entrypoint") + 2]
    state = {"container_id": container_id, "image_id": "sha256:" + "b" * 64,
             "declared": image, "run_id": labels["apsa.run-id"], "head_sha": labels["apsa.head-sha"],
             "running": False, "exit_code": 0}
    state_path.write_text(json.dumps(state))
    print(container_id)
elif argv[0] == "inspect":
    assert argv[1] == container_id and argv[2] == "--format"
    state = json.loads(state_path.read_text())
    format_string = argv[3]
    if format_string == "{{.State.Running}}":
        print("true" if state["running"] else "false")
    elif format_string == "{{.State.ExitCode}}":
        print(state["exit_code"])
    else:
        assert format_string.startswith('{"container_id":')
        print(json.dumps(state))
elif argv[0] == "start":
    assert argv == ["start", "--attach", container_id]
    state = json.loads(state_path.read_text())
    state["exit_code"] = int(os.environ["APSA_SYNTHETIC_EXIT_CODE"])
    state_path.write_text(json.dumps(state))
    print("1.179.0")
    raise SystemExit(state["exit_code"])
elif argv[0] == "rm":
    assert argv == ["rm", container_id]
    print(container_id)
else:
    raise AssertionError("Unexpected fake Docker command")
"""
    )
    fake_docker.chmod(0o700)
    for name in ("semgrep-container-provenance", "competitive-fixtures", "semgrep-rules", "semgrep-results"):
        (tmp_path / name).mkdir()
    image = "semgrep/semgrep@sha256:" + "f" * 64
    calls = tmp_path / "synthetic-docker-calls.jsonl"
    state = tmp_path / "synthetic-docker-state.json"
    environment = {
        "PATH": os.pathsep.join((str(fake_bin), str(Path(sys.executable).parent), "/usr/bin", "/bin")),
        "PYTHONDONTWRITEBYTECODE": "1",
        "RUNNER_TEMP": str(tmp_path),
        "GITHUB_RUN_ID": "synthetic-run",
        "GITHUB_SHA": "a" * 40,
        "SEMGREP_BENCHMARK_IMAGE": image,
        "APSA_SYNTHETIC_DOCKER_CALLS": str(calls),
        "APSA_SYNTHETIC_DOCKER_STATE": str(state),
    }

    def run(*, container_id="c" * 64, exit_code=0):
        result = subprocess.run(
            ["/bin/sh", str(wrapper), "--version"],
            cwd=tmp_path,
            env={
                **environment,
                "APSA_SYNTHETIC_CONTAINER_ID": container_id,
                "APSA_SYNTHETIC_EXIT_CODE": str(exit_code),
            },
            capture_output=True,
            text=True,
            check=False,
            timeout=10,
        )
        actual_calls = [json.loads(line) for line in calls.read_text().splitlines()]
        return result, actual_calls

    return tmp_path, image, run


def test_actual_wrapper_forwards_bounded_tmp_runtime_paths_and_owned_terminal_provenance(synthetic_wrapper):
    root, image, run = synthetic_wrapper
    result, calls = run()
    assert result.returncode == 0, result.stderr
    assert result.stdout == "1.179.0\n" and result.stderr == ""
    create = calls[0]
    assert create[0] == "create"
    flags = {
        name: create[create.index(name) + 1]
        for name in (
            "--platform",
            "--network",
            "--security-opt",
            "--cap-drop",
            "--memory",
            "--cpus",
            "--workdir",
            "--tmpfs",
            "--entrypoint",
        )
    }
    assert flags == {
        "--platform": "linux/amd64",
        "--network": "none",
        "--security-opt": "no-new-privileges",
        "--cap-drop": "ALL",
        "--memory": "2g",
        "--cpus": "2",
        "--workdir": "/tmp",
        "--tmpfs": "/tmp:rw,nosuid,size=536870912",
        "--entrypoint": "semgrep",
    }
    assert "--read-only" in create
    forwarded = dict(
        create[index + 1].split("=", 1) for index, value in enumerate(create) if value == "--env"
    )
    assert forwarded["SEMGREP_LOG_FILE"] == "/tmp/semgrep.log"
    assert forwarded["SEMGREP_VERSION_CACHE_PATH"] == "/tmp/semgrep-version"
    assert forwarded["SEMGREP_SETTINGS_FILE"] == "/tmp/semgrep-settings.yml"
    assert forwarded["SEMGREP_CACHE_DIR"] == "/tmp/semgrep-cache"
    assert forwarded["SEMGREP_ENABLE_VERSION_CHECK"] == "0" and forwarded["SEMGREP_SEND_METRICS"] == "off"
    assert "HOME" not in forwarded
    assert all(
        Path(forwarded[key]).is_relative_to("/tmp")
        for key in (
            "SEMGREP_LOG_FILE",
            "SEMGREP_VERSION_CACHE_PATH",
            "SEMGREP_SETTINGS_FILE",
            "SEMGREP_CACHE_DIR",
        )
    )
    mounts = [create[index + 1] for index, value in enumerate(create) if value == "--mount"]
    assert set(mounts) == {
        f"type=bind,source={root / name},target={root / name},readonly"
        for name in ("competitive-fixtures", "semgrep-rules", "semgrep-results")
    }
    assert create[-2:] == [image, "--version"]
    container_id = "c" * 64
    assert (root / "semgrep-owned-container-ids.txt").read_text().splitlines() == [container_id]
    terminal = json.loads((root / "semgrep-container-provenance" / (container_id + ".json")).read_text())
    assert terminal == {
        "container_id": container_id,
        "image_id": "sha256:" + "b" * 64,
        "declared": image,
        "run_id": "synthetic-run",
        "head_sha": "a" * 40,
        "running": False,
        "exit_code": 0,
    }
    assert type(terminal["running"]) is bool and type(terminal["exit_code"]) is int
    assert calls[-1] == ["rm", container_id]


def test_actual_wrapper_propagates_nonzero_owned_exit_code_after_terminal_record_and_removal(
    synthetic_wrapper,
):
    root, _, run = synthetic_wrapper
    result, calls = run(exit_code=7)
    assert result.returncode == 7
    assert result.stdout == "1.179.0\n" and result.stderr == ""
    container_id = "c" * 64
    terminal = json.loads((root / "semgrep-container-provenance" / (container_id + ".json")).read_text())
    assert terminal["exit_code"] == 7 and terminal["running"] is False
    assert calls[-1] == ["rm", container_id]


@pytest.mark.parametrize("container_id", ["", "c" * 63, "g" * 64, "c" * 64 + "\nmalformed", "-" + "c" * 63])
def test_actual_wrapper_rejects_malformed_created_id_before_journal_start_or_removal(
    synthetic_wrapper, container_id
):
    root, _, run = synthetic_wrapper
    result, calls = run(container_id=container_id)
    assert result.returncode != 0
    assert len(calls) == 1 and calls[0][0] == "create"
    assert not (root / "semgrep-owned-container-ids.txt").exists()
    assert list((root / "semgrep-container-provenance").iterdir()) == []
