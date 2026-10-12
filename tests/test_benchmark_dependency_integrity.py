"""Workflow guards prevent unpinned benchmark execution and accidental broad mounts."""

from pathlib import Path

import yaml


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
