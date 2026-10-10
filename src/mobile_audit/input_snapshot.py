"""Stage bounded inputs through stable descriptors before granting parser permissions."""

from __future__ import annotations

import os
import re
import stat
import time
from pathlib import Path

from .core import MAX_ARCHIVE_TOTAL, MAX_FILE, MAX_FILES, MAX_SOURCE_TOTAL, open_directory, open_file

# When a source tree exceeds the staging budgets, files are staged in this order and the rest
# are omitted (the audit becomes partial) instead of the whole audit being refused.
MAX_ENTRIES = 100_000
MAX_DEPTH = 64
STAGING_KINDS = (
    "app code and configuration",
    "test code and other text resources",
    "localized or qualified Android values",
)
CODE_AND_CONFIG = {
    ".kt",
    ".java",
    ".swift",
    ".m",
    ".mm",
    ".h",
    ".gradle",
    ".kts",
    ".toml",
    ".lock",
    ".lockfile",
    ".resolved",
    ".pbxproj",
    ".plist",
    ".xcprivacy",
}
TEST_SOURCES = re.compile(
    r"(?:^|/)src/(?:test(?:[A-Z0-9]\w*)?|androidTest\w*|[a-z]\w*Test(?:[A-Z]\w*)?)/|(?:^|/)\w*Tests/"
)


def staging_tier(relative: Path) -> int:
    """0: app code and configuration; 1: tests and other text; 2: localized/qualified Android values."""
    path = relative.as_posix()
    if re.search(r"(?:^|/)res/values-[^/]+/", path):
        return 2
    if TEST_SOURCES.search(path):
        return 1
    if (
        relative.suffix in CODE_AND_CONFIG
        or relative.name in {"AndroidManifest.xml", "Podfile.lock", "Package.resolved"}
        or re.search(r"(?:^|/)res/xml/", path)
    ):
        return 0
    return 1


def open_relative(root: int, relative: Path) -> int:
    """Open a regular-file candidate again through directory descriptors, never following symlinks."""
    current, opened = root, []
    try:
        for part in relative.parts[:-1]:
            current = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=current)
            opened.append(current)
        return os.open(relative.parts[-1], os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW, dir_fd=current)
    finally:
        for fd in opened:
            os.close(fd)


def identity(path: Path) -> tuple[int, int]:
    metadata = path.lstat()
    if stat.S_ISLNK(metadata.st_mode):
        raise ValueError("Authorized input moved or became a symlink; audit refused")
    return metadata.st_dev, metadata.st_ino


def stage_input(target: Path, output: Path, *, source: bool = True, hidden: tuple[Path, ...] = ()) -> dict:
    from .inputs import SKIP_DIRS, TEXT_SUFFIXES

    started = time.monotonic()
    # An explicitly selected source subtree (including generated demo inputs) does
    # not grant sibling report access. Exclude report stores contained in the input.
    hidden = tuple(path for path in hidden if path.is_relative_to(target))
    warnings = []
    counts = {"files": 0, "bytes": 0, "entries": 0}
    omitted_by_kind = {kind: {"files": 0, "bytes": 0} for kind in STAGING_KINDS}
    too_deep: list[Path] = []

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
            candidates: list[tuple[int, str, Path, int]] = []

            def visit(fd: int, relative: Path, depth: int):
                if depth > MAX_DEPTH:
                    too_deep.append(relative)
                    return
                with os.scandir(fd) as entries:
                    for entry in entries:
                        deadline()
                        if counts["entries"] >= MAX_ENTRIES:
                            # Entries include images and other files that are never staged.
                            if not counts.get("entry_budget"):
                                counts["entry_budget"] = 1
                                omitted(
                                    f"Input staging entry budget reached ({MAX_ENTRIES} entries); "
                                    "remaining directories were not read; coverage partial"
                                )
                            return
                        counts["entries"] += 1
                        child = relative / entry.name
                        if any((target / child).is_relative_to(path) for path in hidden):
                            omitted("Report store excluded from staged input: " + str(child))
                            continue
                        try:
                            metadata = entry.stat(follow_symlinks=False)
                            if stat.S_ISDIR(metadata.st_mode):
                                if entry.name in SKIP_DIRS:
                                    continue
                                nested = os.open(
                                    entry.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd
                                )
                                try:
                                    visit(nested, child, depth + 1)
                                finally:
                                    os.close(nested)
                            elif stat.S_ISREG(metadata.st_mode) and (
                                child.suffix in TEXT_SUFFIXES
                                or child.name in {"Podfile.lock", "Package.resolved"}
                            ):
                                candidates.append(
                                    (staging_tier(child), child.as_posix(), child, metadata.st_size)
                                )
                        except OSError as error:
                            omitted("Source staging omitted: " + str(child) + ": " + type(error).__name__)

            # Collect first, then stage the most useful files within the budgets.
            visit(root, Path(), 0)
            if too_deep:
                # One warning however many directories, so deep trees stay partial rather than refused.
                omitted(
                    f"{len(too_deep)} director{'y' if len(too_deep) == 1 else 'ies'} deeper than {MAX_DEPTH} "
                    f"levels not staged (first: {too_deep[0]}); coverage partial"
                )
            for tier, _, child, listed in sorted(candidates):
                deadline()
                kind = STAGING_KINDS[tier]
                if counts["files"] >= MAX_FILES:
                    omitted_by_kind[kind]["files"] += 1
                    omitted_by_kind[kind]["bytes"] += listed
                    continue
                try:
                    opened = open_relative(root, child)
                except OSError as error:
                    omitted("Source staging omitted: " + str(child) + ": " + type(error).__name__)
                    continue
                try:
                    size = os.fstat(opened).st_size
                    if size > MAX_FILE:
                        omitted("Oversized source omitted during staging: " + str(child))
                        continue
                    if counts["bytes"] + size > MAX_SOURCE_TOTAL:
                        omitted_by_kind[kind]["files"] += 1
                        omitted_by_kind[kind]["bytes"] += size
                        continue
                    copy_file(opened, output / child, min(MAX_FILE, MAX_SOURCE_TOTAL - counts["bytes"]))
                finally:
                    os.close(opened)
            for kind, omission in omitted_by_kind.items():
                if omission["files"]:
                    omitted(
                        f"Input staging budget reached: {omission['files']} file(s) of {kind} "
                        f"({omission['bytes'] / 1024 / 1024:.1f} MiB) omitted; coverage partial"
                    )
        finally:
            os.close(root)
    if identity(target) != original_identity:
        raise ValueError("Authorized input moved during staging; audit refused")
    return {
        "identity": original_identity,
        "warnings": warnings,
        "files": counts["files"],
        "bytes": counts["bytes"],
        "omitted": {kind: omission for kind, omission in omitted_by_kind.items() if omission["files"]},
    }
