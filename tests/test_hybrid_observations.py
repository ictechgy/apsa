"""New synthetic name-only staging and parser-boundary observations."""

import json
from contextlib import nullcontext
from pathlib import Path

import pytest

from mobile_audit._parser_worker import analyze
from mobile_audit.hybrid_analysis import compiled_hybrid_input
from mobile_audit.hybrid_observations import MAX_BYTES, NOTE_NAME, merge, read, validate, write
from mobile_audit.input_snapshot import stage_input


def document(path="lib/arm64-v8a/libapp.so", complete=True):
    return {"version": 1, "inputs": [compiled_hybrid_input(path)], "inventory_complete": complete}


def test_presence_survives_staging_without_compiled_bytes(tmp_path):
    source = tmp_path / "new-source"
    source.mkdir()
    (source / "main.dart").write_text('void main() { print("synthetic"); }')
    compiled = source / "lib" / "arm64-v8a" / "libapp.so"
    compiled.parent.mkdir(parents=True)
    compiled.write_bytes(b"fresh-synthetic-compiled-content-never-copied")
    staged = tmp_path / "new-stage"
    snapshot = stage_input(source, staged)
    assert not (staged / compiled.relative_to(source)).exists()
    scratch = tmp_path / "new-scratch"
    scratch.mkdir()
    write(scratch, snapshot)
    notes = read(scratch)
    assert "fresh-synthetic-compiled-content" not in (scratch / NOTE_NAME).read_text()
    result = analyze(staged, None, hybrid_observations=notes)
    hybrid = result["inventory"]["hybrid_analysis"]
    row = next(item for item in hybrid["files"] if item["path"] == "lib/arm64-v8a/libapp.so")
    assert row["analysis_state"] == "skipped" and row["representation"] == "aot-candidate"
    assert not hybrid["complete"]
    assert all(
        item["state"] == "partial" for item in result["coverage"] if item["rule_id"].startswith("HYBRID-")
    )


def test_loader_observations_take_precedence_and_order_is_stable():
    compiled = compiled_hybrid_input("fresh.hbc")
    assert compiled is not None
    record = {**compiled, "basis": "loader-synthetic"}
    inventory = {"hybrid_inputs": [record]}
    notes = document("fresh.hbc")
    merge(inventory, notes)
    assert inventory["hybrid_inputs"] == [record]
    assert inventory["hybrid_input_inventory_complete"]


def test_incomplete_presence_inventory_never_becomes_not_applicable(tmp_path):
    source = tmp_path / "fresh"
    source.mkdir()
    (source / "fresh.java").write_text("class Fresh {}")
    result = analyze(
        source, None, hybrid_observations={"version": 1, "inputs": [], "inventory_complete": False}
    )
    assert result["inventory"]["hybrid_inputs_truncated"]
    assert not result["inventory"]["hybrid_analysis"]["complete"]
    assert all(
        item["state"] == "partial" for item in result["coverage"] if item["rule_id"].startswith("HYBRID-")
    )


@pytest.mark.parametrize(
    "path",
    [
        "/libapp.so",
        "../libapp.so",
        "a/../libapp.so",
        "a//libapp.so",
        "./libapp.so",
        "a\\libapp.so",
        "a\nlibapp.so",
        "a" * 4097 + "/libapp.so",
        "fake.js",
    ],
)
def test_invalid_presence_paths_fail_closed(path):
    with pytest.raises(ValueError):
        validate(document(path))


@pytest.mark.parametrize(
    "mutate",
    [
        lambda d: d.update(version=True),
        lambda d: d.update(inventory_complete="true"),
        lambda d: d.update(extra="metadata"),
        lambda d: d["inputs"].append(d["inputs"][0]),
        lambda d: d["inputs"][0].update(state="source-available"),
        lambda d: d["inputs"][0].update(reason="analyzed"),
        lambda d: d.update(inputs=[compiled_hybrid_input(f"{i}/libapp.so") for i in range(257)]),
    ],
)
def test_invalid_schema_cannot_promote_presence(mutate):
    notes = document()
    mutate(notes)
    with pytest.raises(ValueError):
        validate(notes)


def test_duplicate_json_and_byte_limit_fail_closed(tmp_path):
    path = tmp_path / NOTE_NAME
    path.write_text('{"version":1,"version":1,"inputs":[],"inventory_complete":true}')
    with pytest.raises(ValueError, match="Duplicate"):
        read(tmp_path)
    path.write_bytes(b" " * (MAX_BYTES + 1))
    with pytest.raises(ValueError, match="byte budget"):
        read(tmp_path)


def test_note_file_refuses_symlinks(tmp_path):
    outside = tmp_path / "fresh-note.json"
    outside.write_text(json.dumps(document()))
    (tmp_path / NOTE_NAME).symlink_to(outside)
    with pytest.raises((OSError, ValueError)):
        read(tmp_path)


def test_merge_bounds_union_without_losing_incomplete_marker():
    inventory = {"hybrid_inputs": [compiled_hybrid_input(f"b/{i:03}/libapp.so") for i in range(256)]}
    notes = {
        "version": 1,
        "inputs": [compiled_hybrid_input(f"a/{i:03}/libapp.so") for i in range(256)],
        "inventory_complete": True,
    }
    merge(inventory, notes)
    assert len(inventory["hybrid_inputs"]) == 256
    for item in inventory["hybrid_inputs"]:
        assert item is not None and item["path"].startswith("a/")
    assert inventory["hybrid_inputs_truncated"]


def test_engine_sends_bounded_owned_note_to_worker(monkeypatch, tmp_path):
    from mobile_audit import engine, parser_sandbox
    from mobile_audit.hybrid_observations import PROTOCOL

    source = tmp_path / "new-source"
    source.mkdir()
    (source / "New.java").write_text("class New {}")
    (source / "fresh.hbc").write_bytes(b"fresh-compiled-content")
    observed = []

    def worker_boundary(argv, **kwargs):
        assert len(argv) == 15 and argv[-1] == PROTOCOL
        scratch, staged = Path(argv[8]), Path(argv[5])
        assert kwargs["cwd"] == scratch
        notes = read(scratch)
        assert notes == document("fresh.hbc")
        assert not (staged / "fresh.hbc").exists()
        observed.append(notes)
        return json.dumps(analyze(staged, None, hybrid_observations=notes))

    monkeypatch.setattr(engine, "parser_lease", lambda: nullcontext())
    monkeypatch.setattr(engine, "command", worker_boundary)
    monkeypatch.setattr(
        parser_sandbox, "sandbox_command", lambda args, *a, **k: (args, {"state": "unit-boundary-only"})
    )
    monkeypatch.setattr(
        parser_sandbox, "activate", lambda wrapped, args, isolation, scratch: (wrapped, isolation)
    )
    result = engine.analyze_target(source, report_home=tmp_path / "new-report-home")
    assert len(observed) == 1
    assert result["inventory"]["input_snapshot"]["hybrid_input_inventory_complete"]
    files = result["inventory"]["hybrid_analysis"]["files"]
    assert next(item for item in files if item["path"] == "fresh.hbc")["analysis_state"] == "skipped"
