"""Workflow guards prevent unpinned benchmark execution and accidental broad mounts."""

import json
import re
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
