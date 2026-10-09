"""MASTG demo benchmark parsing and staging on synthetic demo folders."""

from __future__ import annotations

from benchmarks.mastg_demos import demos, label, stage

DEMO = """---
platform: android
title: Synthetic
id: MASTG-DEMO-9001
code: [kotlin]
test: MASTG-TEST-9001
---

## Evaluation

The test fails because the sample logs the token.
"""

TEST = """---
platform: android
id: MASTG-TEST-9001
type: [static, code]
weakness: MASWE-0001
---
"""


def test_labels_prefer_kind_then_unambiguous_evaluation():
    assert label({"kind": "pass"}, "## Evaluation\nThe test fails") == "pass"
    assert label({}, "## Evaluation\nThe test fails because of X") == "fail"
    assert label({}, "## Evaluation\nThe test passes because of Y") == "pass"
    assert label({}, "## Evaluation\nThe test fails for A. The test passes for B.") is None
    assert label({"kind": "attack"}, "No evaluation") is None


def test_demo_discovery_translates_beta_weakness_and_stages_original_sources(tmp_path):
    source = tmp_path / "mastg"
    demo = source / "demos/android/MASVS-STORAGE/MASTG-DEMO-9001"
    demo.mkdir(parents=True)
    (demo / "MASTG-DEMO-9001.md").write_text(DEMO)
    (demo / "MastgTest.kt").write_text("class MastgTest")
    (demo / "MastgTest_reversed.java").write_text("class MastgTest {}")
    (demo / "run.sh").write_text("echo")
    tests = source / "tests-beta/android/MASVS-STORAGE"
    tests.mkdir(parents=True)
    (tests / "MASTG-TEST-9001.md").write_text(TEST)
    [entry] = demos(source)
    assert entry["label"] == "fail" and entry["weakness_beta"] == "MASWE-0001"
    assert stage(entry["directory"], tmp_path / "target") == ["MastgTest.kt"]
