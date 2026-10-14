"""Staging must retain copied bytes and report every unread app-scope boundary."""

from __future__ import annotations

import errno
import os
from pathlib import Path

import pytest

from mobile_audit import input_snapshot


def test_exclusive_copy_does_not_remove_an_existing_destination(tmp_path):
    source = tmp_path / "new-source.kt"
    source.write_bytes(b"new source bytes")
    destination = tmp_path / "new-output.kt"
    destination.write_bytes(b"previously staged bytes")

    with pytest.raises(FileExistsError):
        input_snapshot.stage_input(source, destination)

    assert destination.read_bytes() == b"previously staged bytes"
    assert source.read_bytes() == b"new source bytes"


def test_destination_name_collision_preserves_first_copy_and_inventory(tmp_path, monkeypatch):
    source = tmp_path / "source"
    source.mkdir()
    (source / "A.kt").write_bytes(b"class First")
    (source / "B.kt").write_bytes(b"class Second")
    output = tmp_path / "output"
    first = output / "A.kt"
    second = output / "B.kt"
    original_open = Path.open
    original_unlink = Path.unlink

    # A source volume can distinguish names that the destination volume aliases.
    # Model the destination's lookup for both exclusive creation and deletion.
    def colliding_open(path, mode="r", *args, **kwargs):
        return original_open(first if path == second and mode == "xb" else path, mode, *args, **kwargs)

    def colliding_unlink(path, *args, **kwargs):
        return original_unlink(first if path == second else path, *args, **kwargs)

    monkeypatch.setattr(Path, "open", colliding_open)
    monkeypatch.setattr(Path, "unlink", colliding_unlink)
    snapshot = input_snapshot.stage_input(source, output)

    assert first.read_bytes() == b"class First"
    assert not second.exists()
    assert snapshot["files"] == len(list(output.iterdir())) == 1
    assert snapshot["bytes"] == first.stat().st_size == len(b"class First")
    assert snapshot["omitted"] == {"code_and_config": {"files": 1, "bytes": len(b"class Second")}}
    assert snapshot["app_scope_complete"] is False
    assert any("B.kt: FileExistsError" in warning for warning in snapshot["warnings"])


def test_partially_created_copy_is_removed_after_read_failure(tmp_path, monkeypatch):
    source = tmp_path / "source"
    source.mkdir()
    (source / "A.kt").write_bytes(b"class First")
    (source / "B.kt").write_bytes(b"class Second")
    output = tmp_path / "output"
    original_read = os.read
    first_descriptor = None
    reads = 0

    def failing_read(descriptor, limit):
        nonlocal first_descriptor, reads
        if first_descriptor is None:
            first_descriptor = descriptor
        if descriptor == first_descriptor and reads < 2:
            reads += 1
            if reads == 2:
                raise OSError(errno.EIO, "synthetic interrupted read")
            return original_read(descriptor, min(limit, 3))
        return original_read(descriptor, limit)

    monkeypatch.setattr(os, "read", failing_read)
    snapshot = input_snapshot.stage_input(source, output)

    assert not (output / "A.kt").exists()
    assert (output / "B.kt").read_bytes() == b"class Second"
    assert snapshot["files"] == 1 and snapshot["bytes"] == len(b"class Second")
    assert snapshot["omitted"] == {"code_and_config": {"files": 1, "bytes": len(b"class First")}}
    assert snapshot["app_scope_complete"] is False
    assert any("A.kt: OSError" in warning for warning in snapshot["warnings"])


def test_growing_copy_removes_only_its_new_destination(tmp_path, monkeypatch):
    source = tmp_path / "source.kt"
    source.write_bytes(b"four")
    output = tmp_path / "output.kt"
    original_read = os.read

    def growing_read(descriptor, limit):
        raw = original_read(descriptor, limit)
        return raw + b"!" if raw else raw

    monkeypatch.setattr(input_snapshot, "MAX_ARCHIVE_TOTAL", 4)
    monkeypatch.setattr(os, "read", growing_read)
    with pytest.raises(ValueError, match="grew beyond staging byte limit"):
        input_snapshot.stage_input(source, output)

    assert not output.exists()
    assert source.read_bytes() == b"four"


def test_changed_input_removes_its_new_destination(tmp_path, monkeypatch):
    source = tmp_path / "source.kt"
    source.write_bytes(b"class Original")
    original_mtime = source.stat().st_mtime_ns
    output = tmp_path / "output.kt"
    original_read = os.read

    def changing_read(descriptor, limit):
        raw = original_read(descriptor, limit)
        if not raw:
            os.utime(source, ns=(original_mtime, original_mtime + 1_000_000_000))
        return raw

    monkeypatch.setattr(os, "read", changing_read)
    with pytest.raises(ValueError, match="changed during staging"):
        input_snapshot.stage_input(source, output)

    assert not output.exists()
    assert source.read_bytes() == b"class Original"


@pytest.mark.parametrize("link_name", ["src", "build.gradle", "images.png"])
def test_symlink_targets_stay_unread_and_make_app_scope_unknown(tmp_path, monkeypatch, link_name):
    source = tmp_path / "source"
    source.mkdir()
    (source / "Main.kt").write_bytes(b"class Main")
    outside = tmp_path / "new-outside"
    outside.mkdir()
    (outside / "Hidden.kt").write_bytes(b"class Hidden")
    (source / link_name).symlink_to(outside, target_is_directory=True)
    output = tmp_path / "output"
    original_open = os.open
    original_path_open = Path.open

    def deny_link_open(path, *args, **kwargs):
        assert path != link_name and path != outside
        return original_open(path, *args, **kwargs)

    def deny_outside_read(path, *args, **kwargs):
        assert not path.is_relative_to(outside)
        return original_path_open(path, *args, **kwargs)

    monkeypatch.setattr(os, "open", deny_link_open)
    monkeypatch.setattr(Path, "open", deny_outside_read)
    snapshot = input_snapshot.stage_input(source, output)

    assert (output / "Main.kt").read_bytes() == b"class Main"
    assert not (output / link_name).exists()
    assert snapshot["files"] == 1 and snapshot["bytes"] == len(b"class Main")
    assert snapshot["app_scope_complete"] is False
    assert snapshot["hybrid_input_inventory_complete"] is False
    assert snapshot["warnings"] == [
        f"Source staging skipped 1 symbolic link(s) without reading their targets "
        f"(first: {link_name}); app scope unknown; coverage partial"
    ]


def test_policy_skipped_directory_links_do_not_penalize_app_scope(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    (source / "Main.kt").write_bytes(b"class Main")
    outside = tmp_path / "new-build"
    outside.mkdir()
    (outside / "Synthetic.kt").write_bytes(b"class Synthetic")
    (source / "build").symlink_to(outside, target_is_directory=True)

    snapshot = input_snapshot.stage_input(source, tmp_path / "output")

    assert snapshot["files"] == 1
    assert snapshot["warnings"] == []
    assert snapshot["app_scope_complete"] is True


def test_many_symlinks_share_one_warning(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    (source / "Main.kt").write_bytes(b"class Main")
    for index in range(200):
        (source / f"link{index:03}").symlink_to(tmp_path / "new-missing")

    snapshot = input_snapshot.stage_input(source, tmp_path / "output")

    assert snapshot["files"] == 1
    assert snapshot["app_scope_complete"] is False
    assert len(snapshot["warnings"]) == 1
    assert snapshot["warnings"][0].startswith("Source staging skipped 200 symbolic link(s)")


def test_hidden_store_case_alias_is_excluded_without_reading_contents(tmp_path, monkeypatch):
    source = tmp_path / "source"
    source.mkdir()
    (source / "Main.kt").write_bytes(b"class Main")
    store = source / "reports"
    store.mkdir()
    (store / "synthetic.json").write_bytes(b'{"fresh":true}')
    alias = source / "REPORTS"
    original_stat = os.stat
    original_scandir = os.scandir
    original_path_open = Path.open
    store_identity = (store.stat().st_dev, store.stat().st_ino)

    # Preserve the real metadata/descriptor walk while simulating case-insensitive
    # lookup on runners whose source and temporary filesystems are case-sensitive.
    def alias_stat(path, *args, **kwargs):
        if path == "REPORTS" and kwargs.get("dir_fd") is not None:
            assert kwargs.get("follow_symlinks") is False
            path = "reports"
        return original_stat(path, *args, **kwargs)

    def deny_store_listing(path):
        if isinstance(path, int):
            metadata = os.fstat(path)
            assert (metadata.st_dev, metadata.st_ino) != store_identity
        return original_scandir(path)

    def deny_store_read(path, *args, **kwargs):
        assert not path.is_relative_to(store)
        return original_path_open(path, *args, **kwargs)

    monkeypatch.setattr(os, "stat", alias_stat)
    monkeypatch.setattr(os, "scandir", deny_store_listing)
    monkeypatch.setattr(Path, "open", deny_store_read)
    output = tmp_path / "output"
    snapshot = input_snapshot.stage_input(source, output, hidden=(alias,))

    assert (output / "Main.kt").read_bytes() == b"class Main"
    assert not (output / "reports").exists()
    assert snapshot["files"] == 1 and snapshot["bytes"] == len(b"class Main")
    assert snapshot["warnings"] == ["Report store excluded from staged input: reports"]


def test_hidden_parent_store_is_never_inspected_for_a_selected_subtree(tmp_path, monkeypatch):
    store = tmp_path / "new-store"
    source = store / "new-demo"
    source.mkdir(parents=True)
    (source / "Main.kt").write_bytes(b"class Main")
    original_open = os.open
    original_stat = os.stat

    def deny_parent_open(path, *args, **kwargs):
        assert path != store
        return original_open(path, *args, **kwargs)

    def deny_parent_stat(path, *args, **kwargs):
        assert path != store
        return original_stat(path, *args, **kwargs)

    monkeypatch.setattr(os, "open", deny_parent_open)
    monkeypatch.setattr(os, "stat", deny_parent_stat)
    snapshot = input_snapshot.stage_input(source, tmp_path / "output", hidden=(store,))

    assert snapshot["files"] == 1
    assert snapshot["warnings"] == []
    assert snapshot["app_scope_complete"] is True


def test_noncanonical_hidden_path_cannot_open_a_parent_directory(tmp_path, monkeypatch):
    source = tmp_path / "source"
    source.mkdir()
    (source / "Main.kt").write_bytes(b"class Main")
    original_open = os.open

    def deny_parent_open(path, *args, **kwargs):
        assert path != ".."
        return original_open(path, *args, **kwargs)

    monkeypatch.setattr(os, "open", deny_parent_open)
    snapshot = input_snapshot.stage_input(
        source, tmp_path / "output", hidden=(source / ".." / "new-sibling-store",)
    )

    assert snapshot["files"] == 1
    assert snapshot["warnings"] == []
    assert snapshot["app_scope_complete"] is True
