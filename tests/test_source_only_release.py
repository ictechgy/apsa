"""Release staging never descends into retained inputs or generated caches."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import zipfile
from pathlib import Path

import pytest

from scripts import release


def test_release_source_smoke_keeps_candidate_and_checked_rule():
    from mobile_audit.source_analysis import analyze_sources

    result = analyze_sources([("Main.java", release.SOURCE_SMOKE_JAVA)])
    findings = [item for item in result["findings"] if item["rule_id"] == "AST-WEBVIEW-UNTRUSTED-URL"]
    assert findings and all(item["status"] == "candidate" for item in findings)
    assert any(
        item["rule_id"] == "AST-WEBVIEW-UNTRUSTED-URL" and item["state"] == "checked"
        for item in result["coverage"]
    )


def test_original_inherited_release_smoke_retains_partial_uncertainty():
    from mobile_audit.source_analysis import analyze_sources

    original = (
        "import android.app.Activity; import android.webkit.WebView;\n"
        "class Main extends Activity { void open(WebView web) { web.loadUrl(getIntent().getDataString()); } }\n"
    )
    result = analyze_sources([("Main.java", original)])
    assert result["metadata"]["native_flow"]["state"] == "partial"
    assert any(
        item["rule_id"] == "AST-WEBVIEW-UNTRUSTED-URL" and item["status"] == "candidate"
        for item in result["findings"]
    )


def minimal_source(root: Path) -> None:
    for name in ("pyproject.toml", "uv.lock", "requirements-release.txt", "src/mobile_audit/__init__.py"):
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("# new synthetic source\n")


def test_staging_prunes_private_directories_before_stat_or_list_or_read(tmp_path, monkeypatch):
    root = tmp_path / "new-source"
    minimal_source(root)
    public = root / "tests/fixtures/binary_analysis/unsafe/Calls.java"
    public.parent.mkdir(parents=True)
    public.write_text("class Calls {}\n")
    forbidden = []
    for name in ("uploads", "retained", "cache", "prompts", "history", "__pycache__", "outputs"):
        directory = root / "tests" / name
        directory.mkdir()
        (directory / "private.py").write_text("NEW SENTINEL - must not read\n")
        forbidden.append(directory)
    archive = public.parent / "retained.apk"
    archive.write_bytes(b"NEW SYNTHETIC SENTINEL")
    arbitrary_data = public.parent / "retained.json"
    arbitrary_data.write_text('{"new_sentinel": true}')
    demo = root / "src/mobile_audit/data/demo"
    demo.mkdir(parents=True)
    (demo / "Demo.swift").write_text("// NEW public demo source\n")
    retained_demo = demo / "private.apk"
    retained_demo.write_bytes(b"NEW SYNTHETIC SENTINEL")
    denied = [*forbidden, archive, arbitrary_data, retained_demo]
    unlisted = [root / "tests/fixtures", root / "tests/fixtures/binary_analysis", demo]

    def check(path):
        current = Path(path)
        assert not any(current == private or private in current.parents for private in denied)

    original_scandir = release.os.scandir
    original_stat = Path.stat
    original_open = Path.open

    def guarded_scandir(path):
        assert Path(path) not in unlisted
        check(path)
        return original_scandir(path)

    def guarded_stat(path, *args, **kwargs):
        check(path)
        return original_stat(path, *args, **kwargs)

    def guarded_open(path, *args, **kwargs):
        check(path)
        return original_open(path, *args, **kwargs)

    monkeypatch.setattr(release, "ROOT", root)
    monkeypatch.setattr(release.os, "scandir", guarded_scandir)
    monkeypatch.setattr(Path, "stat", guarded_stat)
    monkeypatch.setattr(Path, "open", guarded_open)
    inputs = release.stage_sources(tmp_path / "new-stage")
    assert "tests/fixtures/binary_analysis/unsafe/Calls.java" in inputs
    assert "src/mobile_audit/data/demo/Demo.swift" in inputs
    assert len(inputs) == 6


def test_staging_copies_only_declared_public_data_and_contracts(tmp_path, monkeypatch):
    root = tmp_path / "new-source"
    minimal_source(root)
    names = (
        "src/mobile_audit/data/rules.json",
        "tests/contracts/synthetic.json",
        "action.yml",
        "server.json",
        ".claude-plugin/marketplace.json",
        ".claude-plugin/plugin.json",
        "plugins/apsa/.claude-plugin/plugin.json",
        "plugins/apsa/.mcp.json",
        "benchmarks/corpus.json",
    )
    for name in names:
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("{}\n")
    monkeypatch.setattr(release, "ROOT", root)
    inputs = release.stage_sources(tmp_path / "new-stage")
    assert all(name in inputs for name in names)


def test_staging_generates_plugin_alias_from_public_package_source_without_reading_original(
    tmp_path, monkeypatch
):
    root = tmp_path / "new-source"
    minimal_source(root)
    source = "src/mobile_audit/data/skills/apsa/SKILL.md"
    packaged = root / source
    packaged.parent.mkdir(parents=True)
    packaged.write_text("# Newly generated public synthetic skill source\n")
    alias = "plugins/apsa/skills/apsa/SKILL.md"
    original = root / alias
    original.parent.mkdir(parents=True)
    sentinel = tmp_path / "new-private-sentinel.md"
    sentinel.write_text("NEW SENTINEL: original alias target must remain unread\n")
    original.symlink_to(sentinel)
    forbidden = (root / "plugins/apsa/skills", sentinel)
    original_stat, original_open, original_scandir = Path.stat, Path.open, release.os.scandir

    def check(path):
        assert not any(Path(path) == denied or denied in Path(path).parents for denied in forbidden)

    def checked_stat(path, *args, **kwargs):
        check(path)
        return original_stat(path, *args, **kwargs)

    def checked_open(path, *args, **kwargs):
        check(path)
        return original_open(path, *args, **kwargs)

    def checked_scandir(path):
        check(path)
        return original_scandir(path)

    monkeypatch.setattr(release, "ROOT", root)
    monkeypatch.setattr(Path, "stat", checked_stat)
    monkeypatch.setattr(Path, "open", checked_open)
    monkeypatch.setattr(release.os, "scandir", checked_scandir)
    destination = tmp_path / "new-stage"
    inputs = release.stage_sources(destination)
    staged_alias = destination / alias
    assert staged_alias.is_file() and not staged_alias.is_symlink()
    assert staged_alias.read_bytes() == (destination / source).read_bytes()
    assert inputs[alias] == inputs[source] == release.digest(staged_alias)


def test_staging_refuses_source_symlinks_and_checkout_destination(tmp_path, monkeypatch):
    root = tmp_path / "new-source"
    minimal_source(root)
    monkeypatch.setattr(release, "ROOT", root)
    with pytest.raises(ValueError, match="outside"):
        release.stage_sources(root / "stage")
    (root / "tests").mkdir()
    (root / "tests/escape.py").symlink_to(root / "pyproject.toml")
    with pytest.raises(ValueError, match="symlink"):
        release.stage_sources(tmp_path / "new-stage")


def test_fixture_builder_refuses_existing_output_before_input_access(tmp_path):
    builder_path = Path(__file__).parent / "fixtures/binary_analysis/build.py"
    spec = importlib.util.spec_from_file_location("fresh_release_fixtures", builder_path)
    assert spec is not None and spec.loader is not None
    builder = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(builder)
    output = tmp_path / "existing-output"
    output.mkdir()
    sentinel = output / "new-sentinel.txt"
    sentinel.write_text("preserve")
    with pytest.raises(ValueError, match="overwrite"):
        builder.build_fixtures(sdk=tmp_path / "absent-sdk", output_dir=output)
    assert sentinel.read_text() == "preserve"


def test_fresh_compiled_manifest_uses_real_binary_xml_and_parser(compiled_apks):
    from mobile_audit.inputs import inspect_target

    provenance = json.loads((compiled_apks / "fixture-provenance.json").read_text())
    assert provenance["manifest"]["format"] == "android-binary-xml"
    links = [record for record in provenance["commands"] if record["argv"][1:2] == ["link"]]
    assert len(links) == 1 and links[0]["status"] == 0
    for variant in ("safe", "unsafe"):
        path = compiled_apks / f"{variant}.apk"
        with zipfile.ZipFile(path) as archive:
            raw = archive.read("AndroidManifest.xml")
        assert raw.startswith(b"\x03\x00\x08\x00")
        assert hashlib.sha256(raw).hexdigest() == provenance["manifest"]["compiled_sha256"]
        inventory, _ = inspect_target(path)
        assert inventory["package"] == "audit.fixture"
        assert inventory["android_sdk"]["min"] == "23" and inventory["android_sdk"]["target"] == "36"
        assert inventory["android_config"][0]["debuggable"] == "false"
