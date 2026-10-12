"""Fresh-source measurement failures must never become clean competitor scores."""

from __future__ import annotations

import json
import sys

import pytest

from benchmarks.competitive_cases import generate
from benchmarks.semgrep_compare import VERSION, blob_hash, capture, main, observation, run, summarize


def test_missing_competitor_is_unmeasured_with_no_accuracy_or_rss_claim(tmp_path):
    fixtures = tmp_path / "new-cases"
    generate(fixtures)
    result = run(fixtures, tmp_path / "measurement", None, None)
    assert result["summary"]["semgrep"] == {
        "tp": 0,
        "fp": 0,
        "fn": 0,
        "tn": 0,
        "partial": 0,
        "failed": 0,
        "unmeasured": 4,
        "unsupported": 36,
        "scored_cases": 0,
        "precision": None,
        "recall": None,
    }
    assert result["summary"]["apsa"]["partial"] == 4
    assert result["summary"]["apsa"]["scored_cases"] == 0
    assert sum(row["tools"]["apsa"].get("matched", False) for row in result["cases"]) == 2
    assert all(row["tools"]["semgrep"].get("rss_bytes") is None for row in result["cases"])


@pytest.mark.parametrize("problem", ["error", "omitted", "skipped"])
def test_semgrep_no_alert_requires_complete_actual_target_scan(tmp_path, problem):
    target = tmp_path / "Fresh.java"
    report = {"results": [], "errors": [], "paths": {"scanned": [str(target)]}}
    if problem == "error":
        report["errors"] = [{"type": "ParseError"}]
    elif problem == "omitted":
        report["paths"]["scanned"] = []
    else:
        report["paths"]["skipped"] = [{"path": str(target)}]
    observed = observation(report, "use-of-md5", target)
    assert observed["state"] == "partial"
    counts = summarize([{"risky": True, "tools": {"semgrep": observed}}], "semgrep")
    assert counts["partial"] == 1 and counts["fn"] == counts["tn"] == 0


def test_rule_mapping_is_exact_and_malformed_json_is_not_a_clean_scan(tmp_path):
    target = tmp_path / "New.java"
    report = {
        "results": [{"check_id": "unrelated.use-of-md5"}],
        "errors": [],
        "paths": {"scanned": [str(target)]},
    }
    assert not observation(report, "use-of-md5", target)["matched"]
    with pytest.raises(ValueError, match="results/errors"):
        observation({}, "use-of-md5", target)


def test_actual_capture_preserves_failure_and_bounds_output(tmp_path):
    failed = capture(
        [sys.executable, "-c", "import sys; print('fresh error',file=sys.stderr);sys.exit(7)"], tmp_path, {}
    )
    assert failed["status"] == 7 and failed["stderr"] == "fresh error\n"
    oversized = capture([sys.executable, "-c", "print('x'*2000000)"], tmp_path, {})
    assert oversized["incomplete"] and len(oversized["stdout"]) <= 1024 * 1024


def test_changed_source_truth_is_rejected_before_tool_execution(tmp_path):
    fixtures = tmp_path / "new-cases"
    manifest = generate(fixtures)
    manifest["cases"][0]["risky"] = not manifest["cases"][0]["risky"]
    (fixtures / "manifest.json").write_text(json.dumps(manifest))
    with pytest.raises(ValueError, match="ground truth"):
        run(fixtures, tmp_path / "measurement", None, "/missing/executable")


IMAGE = "semgrep/semgrep@sha256:" + "a" * 64


@pytest.mark.parametrize(
    "image",
    [
        None,
        "semgrep/semgrep:1.179.0",
        "semgrep/semgrep@sha256:" + "a" * 63,
        "semgrep/semgrep@sha256:" + "A" * 64,
        "other/semgrep@sha256:" + "a" * 64,
        IMAGE + "\n",
    ],
)
def test_container_requires_exact_immutable_image_before_any_process_or_input_read(
    tmp_path, monkeypatch, image
):
    monkeypatch.setattr(
        "benchmarks.semgrep_compare.capture", lambda *a, **kw: pytest.fail("process forbidden")
    )
    monkeypatch.setattr(
        "benchmarks.semgrep_compare.read_manifest", lambda *a: pytest.fail("input read forbidden")
    )
    output = tmp_path / "never-created"
    with pytest.raises(ValueError, match="immutable"):
        run(
            tmp_path / "never-read",
            output,
            tmp_path / "new-rules",
            "/new/wrapper",
            runtime="container",
            image=image,
        )
    assert not output.exists()


@pytest.mark.parametrize("executable,rules", [(None, True), ("semgrep", True), ("/new/wrapper", False)])
def test_container_requires_explicit_wrapper_and_rules_without_local_fallback(
    tmp_path, monkeypatch, executable, rules
):
    monkeypatch.setattr(
        "benchmarks.semgrep_compare.capture", lambda *a, **kw: pytest.fail("process forbidden")
    )
    output = tmp_path / "never-created"
    with pytest.raises(ValueError, match="wrapper path and pinned local rules"):
        run(
            tmp_path / "never-read",
            output,
            tmp_path / "new-rules" if rules else None,
            executable,
            runtime="container",
            image=IMAGE,
        )
    assert not output.exists()


def test_local_cli_cannot_acquire_fake_container_provenance(tmp_path, monkeypatch):
    monkeypatch.setattr(
        "benchmarks.semgrep_compare.capture", lambda *a, **kw: pytest.fail("process forbidden")
    )
    with pytest.raises(ValueError, match="explicit container runtime"):
        run(tmp_path / "never-read", tmp_path / "never-created", None, "/new/cli", image=IMAGE)


@pytest.fixture
def measured_source_double(tmp_path, monkeypatch):
    fixtures = tmp_path / "new-source-cases"
    generate(fixtures)
    rules = tmp_path / "new-rules"
    rules.mkdir()
    specs = {}
    for category, name in (("ecb", "use-of-aes-ecb"), ("md5", "use-of-md5")):
        raw = ("NEW synthetic rule double: " + name).encode()
        (rules / (name + ".yaml")).write_bytes(raw)
        specs[category] = {"id": name, "blob": blob_hash(raw)}
    monkeypatch.setattr("benchmarks.semgrep_compare.RULES", specs)
    calls = []
    rss = {"state": "sampled", "sampled_max_rss_bytes": 88446611, "sample_count": 9}

    def fake_capture(argv, location, environment, **kwargs):
        assert "SEMGREP_APP_TOKEN" not in environment
        calls.append(argv)
        stdout = (
            VERSION
            if argv[-1] == "--version"
            else json.dumps(
                {
                    "results": [],
                    "errors": [],
                    "paths": {"scanned": [argv[-1]]},
                }
            )
        )
        return {"stdout": stdout, "status": 0, "incomplete": False, "seconds": 1.25, "rss": rss}

    monkeypatch.setattr("benchmarks.semgrep_compare.capture", fake_capture)
    return fixtures, rules, calls, rss


@pytest.mark.parametrize("runtime", ["cli", "container"])
def test_runtime_provenance_and_rss_respect_container_boundary(tmp_path, measured_source_double, runtime):
    fixtures, rules, calls, rss = measured_source_double
    output = tmp_path / "new-measurement"
    result = run(
        fixtures,
        output,
        rules,
        "/new/wrapper",
        runtime=runtime,
        image=IMAGE if runtime == "container" else None,
    )
    assert len(calls) == 5 and all(argv[0] == "/new/wrapper" for argv in calls)
    assert result["semgrep_version"] == VERSION and result["semgrep_runtime"] == runtime
    assert result["summary"]["semgrep"]["scored_cases"] == 4
    assert result["summary"]["semgrep"]["unsupported"] == 36
    assert result["summary"]["semgrep"]["fn"] == result["summary"]["semgrep"]["tn"] == 2
    observed = [row for row in result["cases"] if row["tools"]["semgrep"]["state"] == "completed"]
    for row in observed:
        metric = row["tools"]["semgrep"]
        assert metric["seconds"] == 1.25
        invocation = json.loads((output / row["id"] / "invocation.json").read_text())
        if runtime == "container":
            assert metric["rss"] is None and metric["rss_bytes"] is None
            assert metric["rss_state"] == "unmeasured-container-boundary"
            assert metric["client_rss_excluded"] is True
            assert metric["latency_scope"] == "container-start-and-scan"
            assert invocation["rss"] == {
                "state": "unmeasured-container-boundary",
                "sampled_max_rss_bytes": None,
                "client_rss_excluded": True,
            }
        else:
            assert metric["rss"] == rss and metric["rss_bytes"] == rss["sampled_max_rss_bytes"]
            assert metric["rss_state"] == "sampled" and invocation["rss"] == rss
            assert "latency_scope" not in metric
    version = json.loads((output / "semgrep-version.json").read_text())
    if runtime == "container":
        assert version["rss"]["sampled_max_rss_bytes"] is None
        assert result["semgrep_image"] == IMAGE and result["semgrep_image_digest"] == "sha256:" + "a" * 64
        assert result["semgrep_execution_provenance"]["state"] == "declared-immutable-wrapper-contract"
        assert result["semgrep_execution_provenance"]["container_execution_verified"] is False
        assert "88446611" not in json.dumps(result) + json.dumps(version)
        assert "Docker-client RSS excluded" in result["scope"]
    else:
        assert version["rss"] == rss and result["semgrep_image"] is None
        assert result["semgrep_execution_provenance"]["state"] == "local-cli"


def test_container_scan_failure_never_falls_back_or_promotes_client_rss(
    tmp_path, monkeypatch, measured_source_double
):
    fixtures, rules, calls, rss = measured_source_double

    def failure(argv, location, environment, **kwargs):
        calls.append(argv)
        if argv[-1] == "--version":
            return {"stdout": VERSION, "status": 0, "incomplete": False, "seconds": 1, "rss": rss}
        raise OSError("NEW synthetic wrapper failure")

    monkeypatch.setattr("benchmarks.semgrep_compare.capture", failure)
    result = run(
        fixtures, tmp_path / "new-failed-measurement", rules, "/new/wrapper", runtime="container", image=IMAGE
    )
    assert len(calls) == 5 and all(argv[0] == "/new/wrapper" for argv in calls)
    assert result["summary"]["semgrep"]["failed"] == 4 and result["summary"]["semgrep"]["scored_cases"] == 0
    for row in result["cases"]:
        metric = row["tools"]["semgrep"]
        if metric["state"] == "failed":
            assert metric["rss"] is None and metric["rss_bytes"] is None
            assert metric["rss_state"] == "unmeasured-container-boundary" and metric["client_rss_excluded"]


def test_container_cli_never_uses_implicit_local_executable(tmp_path, monkeypatch):
    monkeypatch.setattr(
        "benchmarks.semgrep_compare.shutil.which", lambda *a: pytest.fail("local fallback forbidden")
    )
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "compare",
            "run",
            "--fixtures",
            str(tmp_path / "never-read"),
            "--out",
            str(tmp_path / "never-created"),
            "--rules",
            str(tmp_path / "rules"),
            "--semgrep-runtime",
            "container",
            "--semgrep-image",
            IMAGE,
        ],
    )
    with pytest.raises(ValueError, match="wrapper path"):
        main()
