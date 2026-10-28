"""A Gradle lexer abstention stays local without proving unknown ancestry safe."""

import copy

import pytest

from mobile_audit import inputs
from mobile_audit.inputs import inspect_target
from mobile_audit.source_context import resolve_gradle


def dependency(path):
    return {
        "ecosystem": "Maven",
        "name": "synthetic:library",
        "path": path,
        "version": "$releaseVersion",
        "version_expression": "$releaseVersion",
        "version_interpolation": True,
    }


GOOD = "ext { releaseVersion = '1.2.3' }"


@pytest.mark.parametrize("broken", ["def pattern = ~/don't/", "/* never closed", "ext {", "'never closed"])
@pytest.mark.parametrize("reverse", [False, True])
def test_independent_gradle_context_survives_bad_sibling(broken, reverse):
    dependencies = [dependency("good/build.gradle"), dependency("bad/build.gradle")]
    sources = [("bad/build.gradle", broken), ("good/build.gradle", GOOD)]
    if reverse:
        sources.reverse()
    warnings = resolve_gradle(dependencies, sources)
    assert dependencies[0]["version"] == "1.2.3"
    assert dependencies[0]["confidence"] == "declared"
    assert dependencies[1]["version"] == "$releaseVersion"
    assert "version_source" not in dependencies[1]
    assert len(warnings) == 1 and "bad/build.gradle" in warnings[0]


@pytest.mark.parametrize("via", ["ancestor", "import"])
def test_unread_context_still_blocks_its_dependents(via):
    dependencies = [dependency("app/build.gradle")]
    sources = [("app/build.gradle", GOOD), ("broken.gradle", "/* never closed")]
    if via == "ancestor":
        sources[1] = ("build.gradle", "/* never closed")
    else:
        sources[0] = ("app/build.gradle", "apply from: '../broken.gradle'\n" + GOOD)
    warnings = resolve_gradle(dependencies, sources)
    assert dependencies[0]["version"] == "$releaseVersion"
    assert "version_source" not in dependencies[0]
    assert len(warnings) == 1


def test_healthy_context_keeps_same_declared_evidence_and_no_warning():
    dependencies = [dependency("good/build.gradle")]
    assert not resolve_gradle(dependencies, [("good/build.gradle", GOOD)])
    assert dependencies[0]["version"] == "1.2.3"
    assert dependencies[0]["version_source"]["path"] == "good/build.gradle"


def test_inventory_keeps_partial_warning_and_independent_resolved_version(tmp_path):
    good = tmp_path / "good/build.gradle"
    bad = tmp_path / "bad/build.gradle"
    good.parent.mkdir()
    bad.parent.mkdir()
    good.write_text(GOOD + '\ndependencies { implementation "synthetic:library:$releaseVersion" }')
    bad.write_text("def pattern = ~/don't/")
    inventory, _ = inspect_target(tmp_path)
    found = next(row for row in inventory["dependencies"] if row["name"] == "synthetic:library")
    assert found["version"] == "1.2.3"
    assert found["confidence"] == "declared"
    assert inventory["partial"] is True
    assert any(
        "Gradle declaration context unavailable: bad/build.gradle" in note for note in inventory["warnings"]
    )


def test_opaque_file_does_not_mutate_input_sources():
    sources = [("bad/build.gradle", "'never closed"), ("good/build.gradle", GOOD)]
    before = copy.deepcopy(sources)
    resolve_gradle([dependency("good/build.gradle")], sources)
    assert sources == before


def test_omitted_source_still_prevents_context_resolution(tmp_path, monkeypatch):
    good_text = GOOD + '\ndependencies { implementation "synthetic:library:$releaseVersion" }'
    cap = len(good_text.encode()) + 1
    monkeypatch.setattr(inputs, "MAX_FILE", cap)
    (tmp_path / "build.gradle").write_text(good_text)
    (tmp_path / "omitted.gradle").write_text("x" * (cap + 1))
    inventory, _ = inspect_target(tmp_path)
    found = next(row for row in inventory["dependencies"] if row["name"] == "synthetic:library")
    assert found["version"] == "$releaseVersion"
    assert "version_source" not in found
    assert inventory["partial"] is True
    assert inventory["fingerprint_complete"] is False
