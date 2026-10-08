"""Explicit source scopes; does not resolve or merge Gradle/Xcode variants."""

from pathlib import Path, PurePosixPath


def relative_source_path(value: str) -> str:
    path = PurePosixPath(value)
    if not value or path.is_absolute() or ".." in path.parts or "\\" in value or value != path.as_posix():
        raise ValueError("Source selection must be a normalized relative path without traversal")
    return value


def select_source_module(target: Path, module: str | None = None) -> Path:
    if not module:
        return target
    if not target.is_dir() or target.suffix.lower() == ".app":
        raise ValueError("Source module selection requires a source directory")
    module = relative_source_path(module)
    path = target
    for part in PurePosixPath(module).parts:
        path = path / part
        if path.is_symlink():
            raise ValueError("Source module selection cannot cross symlinks")
    if not path.is_dir():
        raise ValueError("Selected source module is not a directory")
    return path
