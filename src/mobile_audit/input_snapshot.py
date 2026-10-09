"""Stage bounded inputs through stable descriptors before granting parser permissions."""

from __future__ import annotations

import os
import stat
import time
from pathlib import Path

from .core import MAX_ARCHIVE_TOTAL, MAX_FILE, MAX_FILES, MAX_SOURCE_TOTAL, open_directory, open_file


def identity(path: Path) -> tuple[int, int]:
    metadata = path.lstat()
    if stat.S_ISLNK(metadata.st_mode):
        raise ValueError("Authorized input moved or became a symlink; audit refused")
    return metadata.st_dev, metadata.st_ino


def stage_input(target: Path, output: Path, *, source: bool = True, hidden: tuple[Path, ...] = ()) -> dict:
    from .inputs import SKIP_DIRS, TEXT_SUFFIXES

    started = time.monotonic()
    warnings = []
    counts = {"files": 0, "bytes": 0, "entries": 0}

    def omitted(message):
        warnings.append(message)
        if len(warnings) > 128:
            raise ValueError("Input staging error budget exceeded; audit refused")

    def deadline():
        if time.monotonic() - started > 90:
            raise ValueError("Input staging time budget exceeded; audit refused")

    def copy_file(fd: int, destination: Path, limit: int):
        deadline()
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_size > limit:
            raise ValueError("Input staging requires a regular file within byte limits")
        destination.parent.mkdir(parents=True, exist_ok=True)
        try:
            with destination.open("xb") as stream:
                destination.chmod(0o600)
                size = 0
                while raw := os.read(fd, min(1024 * 1024, limit + 1 - size)):
                    deadline()
                    size += len(raw)
                    if size > limit:
                        raise ValueError("Input grew beyond staging byte limit")
                    stream.write(raw)
            after = os.fstat(fd)
            if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
                raise ValueError("Input changed during staging; audit refused")
        except BaseException:
            destination.unlink(missing_ok=True)
            raise
        counts["bytes"] += size
        counts["files"] += 1

    original_identity = identity(target)
    metadata = target.lstat()
    if not stat.S_ISDIR(metadata.st_mode):
        fd = open_file(target)
        try:
            if (os.fstat(fd).st_dev, os.fstat(fd).st_ino) != original_identity:
                raise ValueError("Authorized input moved during staging; audit refused")
            copy_file(fd, output, MAX_ARCHIVE_TOTAL if source else MAX_FILE)
        finally:
            os.close(fd)
    else:
        if not source:
            raise ValueError("SBOM must be a regular file")
        root = open_directory(target)
        try:
            if (os.fstat(root).st_dev, os.fstat(root).st_ino) != original_identity:
                raise ValueError("Authorized input moved during staging; audit refused")
            output.mkdir(parents=True)

            def visit(fd: int, relative: Path, depth: int):
                if depth > 64:
                    raise ValueError("Input staging directory depth budget exceeded; audit refused")
                with os.scandir(fd) as entries:
                    for entry in entries:
                        deadline()
                        counts["entries"] += 1
                        if counts["entries"] > 100_000:
                            raise ValueError("Input staging entry budget exceeded; audit refused")
                        child = relative / entry.name
                        if any((target / child).is_relative_to(path) for path in hidden):
                            omitted("Report store excluded from staged input: " + str(child))
                            continue
                        try:
                            mode = entry.stat(follow_symlinks=False).st_mode
                            if stat.S_ISDIR(mode):
                                if entry.name in SKIP_DIRS:
                                    continue
                                nested = os.open(
                                    entry.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd
                                )
                                try:
                                    visit(nested, child, depth + 1)
                                finally:
                                    os.close(nested)
                            elif stat.S_ISREG(mode) and (
                                child.suffix in TEXT_SUFFIXES
                                or child.name in {"Podfile.lock", "Package.resolved"}
                            ):
                                if counts["files"] >= MAX_FILES:
                                    raise ValueError("Input staging file budget exceeded; audit refused")
                                opened = os.open(
                                    entry.name, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW, dir_fd=fd
                                )
                                try:
                                    size = os.fstat(opened).st_size
                                    if size > MAX_FILE:
                                        omitted("Oversized source omitted during staging: " + str(child))
                                        continue
                                    if counts["bytes"] + size > MAX_SOURCE_TOTAL:
                                        raise ValueError(
                                            "Input staging total byte budget exceeded; audit refused"
                                        )
                                    copy_file(
                                        opened,
                                        output / child,
                                        min(MAX_FILE, MAX_SOURCE_TOTAL - counts["bytes"]),
                                    )
                                finally:
                                    os.close(opened)
                        except OSError as error:
                            omitted("Source staging omitted: " + str(child) + ": " + type(error).__name__)

            visit(root, Path(), 0)
        finally:
            os.close(root)
    if identity(target) != original_identity:
        raise ValueError("Authorized input moved during staging; audit refused")
    return {
        "identity": original_identity,
        "warnings": warnings,
        "files": counts["files"],
        "bytes": counts["bytes"],
    }
