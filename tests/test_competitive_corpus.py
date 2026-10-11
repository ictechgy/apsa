"""Validate corpus labels/hashes without making scanner accuracy assertions."""

import hashlib
import json

import pytest

from tests.competitive_corpus import cases, evaluate, freeze


def test_independent_labels_are_bounded_and_paired():
    corpus = cases()
    assert len({case["id"] for case in corpus}) == len(corpus)
    assert all(case["label"] in {"vulnerable", "safe", "uncertain"} for case in corpus)
    assert all(case["rationale"] and case["files"] and case["rule"] for case in corpus)
    families = {case["family"] for case in corpus}
    for family in families - {"native-uncertainty"}:
        assert {case["label"] for case in corpus if case["family"] == family} == {"vulnerable", "safe"}
    assert all(case["expected_partial"] for case in corpus if case["label"] == "uncertain")


def test_freeze_sources_and_labels_before_run(tmp_path):
    root = tmp_path / "new-corpus"
    freeze(root)
    raw = (root / "labels.json").read_bytes()
    assert (root / "labels.sha256").read_text().strip() == hashlib.sha256(raw).hexdigest()
    manifest = json.loads(raw)
    for case in manifest["cases"]:
        for entry in case["files"]:
            source = (root / "inputs" / case["id"] / entry["path"]).read_bytes()
            assert hashlib.sha256(source).hexdigest() == entry["sha256"]
    with pytest.raises(FileExistsError):
        freeze(root)


def test_objc_extension_is_separate_and_bounded():
    initial = cases()
    extended = cases(include_objc=True)
    assert extended[: len(initial)] == initial
    objective_c = extended[len(initial) :]
    assert len(objective_c) == 4
    assert all(case["expected_partial"] for case in objective_c)
    assert {case["label"] for case in objective_c} == {"safe", "vulnerable"}


@pytest.mark.parametrize("tamper", ["labels", "source"])
def test_evaluation_rejects_changed_frozen_inputs(tmp_path, tamper):
    root = tmp_path / "tampered-corpus"
    manifest = freeze(root)
    if tamper == "labels":
        destination = root / "labels.json"
    else:
        first = manifest["cases"][0]
        destination = root / "inputs" / first["id"] / first["files"][0]["path"]
    destination.write_bytes(destination.read_bytes() + b"\n")
    with pytest.raises(ValueError, match="hash changed"):
        evaluate(root)
    assert not (root / "results.json").exists()
