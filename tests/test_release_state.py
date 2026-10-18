"""Release graph gates preserve tag identity and avoid duplicate publication."""

from __future__ import annotations

import ast
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]


def workflow(name):
    return yaml.safe_load((ROOT / ".github/workflows" / name).read_text())


def condition(expression, *, ref_type, created):
    """Evaluate the narrow boolean syntax of the two release-context gates."""
    expression = (
        expression.replace("github.ref_type", repr(ref_type))
        .replace("needs.tag.outputs.created", repr(created))
        .replace("&&", " and ")
        .replace("||", " or ")
    )
    tree = ast.parse(expression, mode="eval")
    assert all(
        isinstance(
            node, (ast.Expression, ast.BoolOp, ast.And, ast.Or, ast.Compare, ast.Eq, ast.NotEq, ast.Constant)
        )
        for node in ast.walk(tree)
    )
    return eval(compile(tree, "<release-condition>", "eval"), {"__builtins__": {}})


def ancestors(jobs, name):
    needs = jobs[name].get("needs", [])
    if isinstance(needs, str):
        needs = [needs]
    return set(needs).union(*(ancestors(jobs, parent) for parent in needs))


@pytest.mark.parametrize(
    "ref_type,created,dispatch,publish",
    [
        ("branch", "true", True, False),
        ("branch", "false", False, False),
        ("tag", "true", False, True),
        ("tag", "false", False, True),
    ],
)
def test_new_tag_dispatch_and_existing_tag_resume_are_distinct(ref_type, created, dispatch, publish):
    jobs = workflow("release.yml")["jobs"]
    assert condition(jobs["dispatch-tag"]["if"], ref_type=ref_type, created=created) is dispatch
    assert condition(jobs["publish"]["if"], ref_type=ref_type, created=created) is publish
    assert jobs["tag"]["outputs"]["created"] == "${{ steps.bind_tag.outputs.created }}"
    binding = next(step for step in jobs["tag"]["steps"] if step.get("id") == "bind_tag")["run"]
    # Both states must be explicit; the existing identity check precedes either output.
    assert binding.index('ref["sha"] != os.environ["GITHUB_SHA"]') < binding.index("created=false")
    assert binding.index("created=false") < binding.index("git/refs") < binding.index("created=true")


def test_registry_and_public_verification_require_all_prior_gates():
    config = workflow("release.yml")
    jobs = config["jobs"]
    assert {"validate", "verify", "build", "tag"} <= ancestors(jobs, "publish")
    assert "publish" in ancestors(jobs, "mcp-registry")
    assert {"publish", "mcp-registry", "github-release"} <= ancestors(jobs, "verify-publication")
    assert jobs["verify-publication"]["with"]["source-sha"] == "${{ github.sha }}"
    assert config["permissions"] == {"contents": "read"}
    action_writers = [
        name for name, job in jobs.items() if job.get("permissions", {}).get("actions") == "write"
    ]
    assert action_writers == ["dispatch-tag"]
    assert jobs["publish"]["environment"]["name"] == "pypi"
    assert "environment" not in jobs["mcp-registry"]


def test_release_build_provisions_same_compiler_and_android_tools_as_ci():
    jobs = workflow("release.yml")["jobs"]
    build_steps = jobs["build"]["steps"]
    ci_steps = workflow("ci.yml")["jobs"]["verify"]["steps"]
    for prefix in ["actions/setup-java@", "android-actions/setup-android@"]:
        build = next(step for step in build_steps if step.get("uses", "").startswith(prefix))
        ci = next(step for step in ci_steps if step.get("uses", "").startswith(prefix))
        assert build["uses"] == ci["uses"]
        assert build["with"] == ci["with"]
    install = next(
        i for i, step in enumerate(build_steps) if step.get("name") == "Install the locked build environment"
    )
    assert all(
        next(i for i, step in enumerate(build_steps) if step.get("uses", "").startswith(prefix)) < install
        for prefix in ["actions/setup-java@", "android-actions/setup-android@"]
    )


def test_post_publication_upload_excludes_cold_cache_and_home():
    job = workflow("published-check.yml")["jobs"]["verify-publication"]
    assert set(job["strategy"]["matrix"]["os"]) == {"ubuntu-24.04", "macos-15"}
    upload = next(
        step for step in job["steps"] if step.get("uses", "").startswith("actions/upload-artifact@")
    )
    paths = upload["with"]["path"].splitlines()
    assert all("cache" not in path and "/home" not in path for path in paths)
    assert any("attempt-*/stderr" in path for path in paths)
