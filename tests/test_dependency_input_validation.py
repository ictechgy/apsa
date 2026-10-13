"""Malformed untrusted dependency coordinates must leave source analysis partial."""

import json

import pytest

from mobile_audit.inputs import inspect_target, parse_dependencies


@pytest.mark.parametrize("version", [["1.0"], {"release": "1.0"}, 123, True])
@pytest.mark.parametrize("format_name", ["npm-packages", "npm-dependencies", "swift-pins"])
def test_invalid_dependency_versions_mark_source_partial(tmp_path, version, format_name):
    source = tmp_path / "source"
    source.mkdir()
    (source / "Main.java").write_text("class Main {}")
    if format_name == "swift-pins":
        name = "Package.resolved"
        value = {"pins": [{"location": "https://example.com/synthetic.git", "state": {"version": version}}]}
    elif format_name == "npm-packages":
        name = "package-lock.json"
        value = {"packages": {"node_modules/synthetic": {"version": version}}}
    else:
        name = "package-lock.json"
        value = {"dependencies": {"synthetic": {"version": version}}}
    (source / name).write_text(json.dumps(value))
    inventory, sources = inspect_target(source.resolve(), authorized=True)
    assert inventory["partial"] is True
    assert inventory["dependencies"] == []
    assert f"Could not parse {name}: ValueError" in inventory["warnings"]
    assert any(path == "Main.java" for path, _ in sources)


def test_invalid_catalog_module_marks_source_partial(tmp_path):
    (tmp_path / "Main.java").write_text("class Main {}")
    (tmp_path / "libs.versions.toml").write_text(
        '[libraries]\nexample = {module = ["example:lib"], version = "1.0"}\n'
    )
    inventory, _ = inspect_target(tmp_path.resolve(), authorized=True)
    assert inventory["partial"] is True
    assert inventory["dependencies"] == []
    assert "Could not parse libs.versions.toml: ValueError" in inventory["warnings"]


def test_string_dependency_coordinates_keep_existing_evidence():
    npm = parse_dependencies(
        "package-lock.json", json.dumps({"packages": {"node_modules/synthetic": {"version": "1.0"}}}).encode()
    )
    assert [(item["name"], item["version"], item["confidence"]) for item in npm] == [
        ("synthetic", "1.0", "exact")
    ]
    swift = parse_dependencies(
        "Package.resolved",
        json.dumps({"pins": [{"location": "https://example.com/synthetic.git", "state": {}}]}).encode(),
    )
    assert [(item["name"], item["version"], item["confidence"]) for item in swift] == [
        ("https://example.com/synthetic", "", "unknown")
    ]
