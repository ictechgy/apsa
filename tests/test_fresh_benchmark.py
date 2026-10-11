"""Fresh benchmark staging refuses retained inputs and preserves incomplete evidence."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from benchmarks import fresh


def test_freeze_drops_retained_binary_without_reading_it(tmp_path, monkeypatch):
    public = tmp_path / "public"
    (public / "cases").mkdir(parents=True)
    (public / "cases/control.java").write_text("class Synthetic {}")
    compiled = tmp_path / "new-compiled"
    compiled.mkdir()
    for variant in ("safe", "unsafe"):
        (compiled / (variant + ".apk")).write_bytes(b"NEW synthetic test bytes " + variant.encode())
    labels = public / "labels.json"
    cases = [
        {"id": "source", "kind": "source", "path": "cases/control.java"},
        {"id": "dex-safe", "kind": "binary", "path": "RETAINED/safe.apk"},
        {"id": "dex-unsafe", "kind": "binary", "path": "RETAINED/unsafe.apk"},
        {"id": "dex-upstream-irrelevant", "kind": "binary", "path": "RETAINED/upstream.apk"},
    ]
    labels.write_text(json.dumps({"cases": cases}))
    original = Path.open

    def source_or_new_only(path, *args, **kwargs):
        assert "RETAINED" not in path.parts
        return original(path, *args, **kwargs)

    monkeypatch.setattr(Path, "open", source_or_new_only)
    frozen = fresh.freeze_corpus(tmp_path / "frozen", compiled, labels)
    manifest = json.loads(frozen.read_text())
    assert [case["id"] for case in manifest["cases"]] == ["source", "dex-safe", "dex-unsafe"]
    assert all(len(case["sha256"]) == 64 for case in manifest["cases"])
    assert manifest["published_baseline_approved"] is False
    assert manifest["omitted_cases"][0]["id"] == "dex-upstream-irrelevant"


def test_freeze_rejects_source_path_escape_and_existing_output(tmp_path):
    labels = tmp_path / "labels.json"
    labels.write_text(json.dumps({"cases": [{"id": "escape", "kind": "source", "path": "../private.java"}]}))
    with pytest.raises(ValueError, match="relative cases"):
        fresh.freeze_corpus(tmp_path / "new", tmp_path / "compiled", labels)
    with pytest.raises(FileExistsError):
        fresh.freeze_corpus(tmp_path / "new", tmp_path / "compiled", labels)


def test_known_partial_contract_never_approves_accuracy_and_rejects_new_partial():
    result = {
        "passed": False,
        "summary": {"fp": 0, "fn": 0},
        "cases": [
            {
                "id": "java-cross-function-irrelevant",
                "warnings": ["unsupported receiver"],
                "incomplete_rules": [],
                "error": None,
            }
        ],
        "disagreements": [{"case_id": "java-cross-function-irrelevant"}],
    }
    assert fresh.regression_contract(result)
    assert result["passed"] is False
    result["cases"].append({"id": "new-partial", "warnings": [], "incomplete_rules": ["rule"], "error": None})
    assert not fresh.regression_contract(result)
    result["cases"].pop()
    result["summary"]["fn"] = 1
    assert not fresh.regression_contract(result)


def test_real_fresh_controls_preserve_partial_and_hash_lock(compiled_apks, tmp_path):
    from benchmarks.run import run

    frozen = fresh.freeze_corpus(tmp_path / "fresh-corpus", compiled_apks)
    first, second = run(frozen), run(frozen)
    assert first == second
    assert first["summary"]["cases"] == 30
    assert first["passed"] is False
    assert fresh.regression_contract(first)
    assert first["summary"]["fp"] == first["summary"]["fn"] == 0
    assert {case["id"] for case in first["cases"] if case["kind"] == "binary"} == {"dex-safe", "dex-unsafe"}
