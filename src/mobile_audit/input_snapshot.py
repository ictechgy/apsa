"""Stage bounded inputs through stable descriptors before granting parser permissions."""

from __future__ import annotations

import itertools
import math
import os
import re
import stat
import time
from pathlib import Path

from .core import MAX_ARCHIVE_TOTAL, MAX_FILE, MAX_FILES, MAX_SOURCE_TOTAL, open_directory, open_file

# When a source tree exceeds the staging budgets, files are staged kind by kind in this order
# and the rest are omitted (the audit becomes partial) instead of the whole audit being refused.
# Keys are stable report fields (inventory.input_snapshot.omitted); values are warning labels.
MAX_ENTRIES = 100_000
MAX_DEPTH = 64
STAGING_KINDS = {
    "code_and_config": "app code and configuration",
    "other_text": "other shipped text resources",
    "localized_values": "localized or qualified Android values",
    "tests": "test code and resources",
}
TIERS = tuple(STAGING_KINDS)
# Omitting these kinds can hide a whole platform or module, so even not-applicable coverage is unknown.
SCOPE_KINDS = {"code_and_config", "other_text"}
NATIVE = {".kt", ".java", ".swift", ".m", ".mm"}
CODE = NATIVE | {".h", ".dart", ".js", ".ts"}
CONFIG = {".gradle", ".kts", ".toml", ".lock", ".lockfile", ".resolved", ".pbxproj", ".plist", ".xcprivacy"}
CONFIG_NAMES = {
    "AndroidManifest.xml",
    "Podfile.lock",
    "Package.resolved",
    "package.json",
    "package-lock.json",
    "pubspec.yaml",
    "google-services.json",
    "sbom.json",
}
# Third-party code checked into the tree, and web assets, go after the app's own code
# (directory names compared in lower case).
VENDORED = {
    ".build",
    ".dart_tool",
    "assets",
    "carthage",
    "external",
    "frameworks",
    "third_party",
    "thirdparty",
    "vendor",
}
TEST_SOURCES = re.compile(
    r"(?:^|/)src/(?:test(?:[A-Z0-9]\w*)?|androidTest\w*|[a-z]\w*Test(?:[A-Z]\w*)?)/"
    r"|^(?:test(?:[A-Z0-9]\w*)?|androidTest\w*)/"
    r"|(?:^|/)(?:[\w-]*Tests|__tests__)/"
    r"|\.(?:test|spec)\.[jt]s$|_test\.dart$|(?:^|/)integration_test/"
)


def staging_rank(relative: Path) -> tuple[int, int]:
    """(tier, rank): the index into TIERS, then configuration, native code, JS/TS/Dart, then the rest."""
    path = relative.as_posix()
    if TEST_SOURCES.search(path):
        return 3, 0
    if re.search(r"(?:^|/)res/values-[^/]+/", path):
        return 2, 0
    vendored = any(part.lower() in VENDORED for part in relative.parts[:-1])
    if relative.suffix in CODE:
        return 0, 3 if vendored or relative.suffix == ".h" else 1 if relative.suffix in NATIVE else 2
    if (
        relative.suffix in CONFIG
        or relative.name in CONFIG_NAMES
        or relative.name.endswith(".cdx.json")
        or re.search(r"(?:^|/)res/xml[^/]*/", path)
    ):
        return 0, 3 if vendored else 0
    return 1, 0


def staging_tier(relative: Path) -> int:
    """Index into TIERS: app code and configuration, other text, localized values, then tests."""
    return staging_rank(relative)[0]


def open_parent(root: int, directory: Path) -> int:
    """Open a staged directory again through directory descriptors, never following symlinks."""
    current = os.dup(root)
    try:
        for part in directory.parts:
            nested = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=current)
            os.close(current)
            current = nested
    except BaseException:
        os.close(current)
        raise
    return current


def size_label(size: int) -> str:
    return f"{size / 1024 / 1024:.1f} MiB" if size >= 1024 * 1024 else f"{math.ceil(size / 1024)} KiB"


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
    oversized: list[Path] = []
    unreadable: list[str] = []
    # False once a file that could change which rules apply (code, configuration, shipped text) is
    # left out, or directories were not read at all.
    scope = {"complete": True}

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
            candidates: list[tuple[tuple[int, int], str, int, tuple[int, int]]] = []

            def visit(fd: int, relative: Path, depth: int):
                if depth > MAX_DEPTH:
                    too_deep.append(relative)
                    return
                with os.scandir(fd) as listing:
                    # Name order makes the entry budget cut the same files on every filesystem, except
                    # within the directory where it runs out (that slice is read in listing order).
                    entries = sorted(
                        itertools.islice(listing, MAX_ENTRIES - counts["entries"] + 1), key=lambda e: e.name
                    )
                for entry in entries:
                    deadline()
                    if counts["entries"] >= MAX_ENTRIES:
                        # Entries include images and other files that are never staged.
                        if not counts.get("entry_budget"):
                            counts["entry_budget"] = 1
                            scope["complete"] = False
                            omitted(
                                f"Input staging entry budget reached ({MAX_ENTRIES} entries, in path order); "
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
                                (
                                    staging_rank(child),
                                    child.as_posix(),
                                    metadata.st_size,
                                    (metadata.st_dev, metadata.st_ino),
                                )
                            )
                    except OSError as error:
                        # An unread entry may be (or hold) app code, so the app scope is unknown.
                        scope["complete"] = False
                        unreadable.append(f"{child}: {type(error).__name__}")

            def omit(kind: str, size: int):
                omitted_by_kind[kind]["files"] += 1
                omitted_by_kind[kind]["bytes"] += size
                if kind in SCOPE_KINDS:
                    scope["complete"] = False

            # Collect first, then stage the most useful files within the budgets.
            visit(root, Path(), 0)
            # Sorted candidates arrive directory by directory; reuse the last parent descriptor.
            parent: dict = {"path": None, "fd": None}
            try:
                for (tier, _), posix, listed, listed_identity in sorted(candidates):
                    deadline()
                    kind, child = TIERS[tier], Path(posix)
                    if counts["files"] >= MAX_FILES:
                        omit(kind, listed)
                        continue
                    try:
                        if parent["path"] != child.parent:
                            if parent["fd"] is not None:
                                os.close(parent["fd"])
                            parent.update(path=None, fd=None)
                            parent.update(path=child.parent, fd=open_parent(root, child.parent))
                        opened = os.open(
                            child.name, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW, dir_fd=parent["fd"]
                        )
                    except OSError as error:
                        omit(kind, listed)
                        unreadable.append(f"{child}: {type(error).__name__}")
                        continue
                    try:
                        metadata = os.fstat(opened)
                        # Files are reopened by name after the walk; a different file (for example
                        # an editor's save, or a swapped-in report store) is left out, never read.
                        if (metadata.st_dev, metadata.st_ino) != listed_identity:
                            omit(kind, listed)
                            unreadable.append(f"{child}: replaced during staging")
                            continue
                        size = metadata.st_size
                        if size > MAX_FILE:
                            oversized.append(child)
                            omit(kind, size)
                            continue
                        if counts["bytes"] + size > MAX_SOURCE_TOTAL:
                            omit(kind, size)
                            continue
                        copy_file(opened, output / child, min(MAX_FILE, MAX_SOURCE_TOTAL - counts["bytes"]))
                    except OSError as error:
                        # A failed read or destination write (for example a name too long for the
                        # staging directory) leaves this file out, as in 1.5.0, not the audit.
                        omit(kind, listed)
                        unreadable.append(f"{child}: {type(error).__name__}")
                    finally:
                        os.close(opened)
            finally:
                if parent["fd"] is not None:
                    os.close(parent["fd"])
            # One warning per cause, however many files, so large trees stay partial rather than refused.
            if too_deep:
                scope["complete"] = False
                omitted(
                    f"{len(too_deep)} director{'y' if len(too_deep) == 1 else 'ies'} deeper than {MAX_DEPTH} "
                    f"levels not staged (first: {too_deep[0]}); coverage partial"
                )
            if unreadable:
                omitted(
                    f"Source staging could not read or stage {len(unreadable)} entr"
                    f"{'y' if len(unreadable) == 1 else 'ies'} (first: {unreadable[0]}); coverage partial"
                )
            if oversized:
                omitted(
                    f"{len(oversized)} file(s) over the {size_label(MAX_FILE)} file limit not staged "
                    f"(first: {oversized[0]}); coverage partial"
                )
            for kind, omission in omitted_by_kind.items():
                if omission["files"]:
                    omitted(
                        f"Input staging omitted {omission['files']} file(s) of {STAGING_KINDS[kind]} "
                        f"({size_label(omission['bytes'])}); coverage partial"
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
        "app_scope_complete": scope["complete"],
    }
