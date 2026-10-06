"""Install the same reusable instructions shipped in the wheel and source tree."""

from __future__ import annotations

import hashlib
import os
from importlib.resources import files
from pathlib import Path

from .core import read_bounded

KNOWN_RELEASE_HASHES = {
    "apsa": {
        "a7aae332969ba98ac8da4831b05a21092b342578e2b4b2c6c8bd270c9c93e81b",
    },
    "quaygate": {
        "61c5a4df34781542525177f3fc868e29bcf0ffe7f2757f39c1ef225f8b86b305",
        "f12331750c1ee915179e7956f4856cbc7ec824f8ba48a6146e1ce5a1537a4c09",
        "7b483602f91a9fd9bbc48893247e7edd3ae3b7e52059f51c7426357f2555ccd4",
        "2710bb3466bca1f95c15d0287c58b073e3c219eb532f1d7cf9bd84b6dd723dd2",
    },
    "mobile-audit": {
        "5bdd02b82f6e71e189130851d7b851aa134d727791e596da775545728c87936b",
        "a0f2df02d2c642b61e5dbb4e74f158b20b480b3dd8cdef8ce15503f4b4a60098",
        "31414a783b5e5011d72d6593d70d0d8b06a4c2c675f36297e3826d555d2d7cc6",
        "7c8835465139fc02bd8855a094f5a315c93148b888702c738de62df259ccdeaa",
    },
}


def skill_status(name: str, destination: Path | None = None) -> str:
    path = (destination or Path.home() / ".codex" / "skills" / name).expanduser() / "SKILL.md"
    if path.is_symlink():
        return "modified"
    if not path.exists():
        return "missing"
    try:
        raw = read_bounded(path.parent.resolve() / path.name)
    except (OSError, ValueError):
        return "modified"
    current = files("mobile_audit").joinpath("data", "skills", name, "SKILL.md").read_bytes()
    if raw == current:
        return "current"
    return "outdated" if hashlib.sha256(raw).hexdigest() in KNOWN_RELEASE_HASHES[name] else "modified"


def install_skill(name: str, destination: Path | None = None, force=False) -> dict:
    if name not in {"apsa", "quaygate", "mobile-audit"}:
        raise ValueError("Unknown packaged skill")
    raw = files("mobile_audit").joinpath("data", "skills", name, "SKILL.md").read_bytes()
    if not raw.startswith(f"---\nname: {name}\n".encode()):
        raise ValueError("Packaged skill has invalid frontmatter")
    directory = (destination or Path.home() / ".codex" / "skills" / name).expanduser()
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / "SKILL.md"
    if path.is_symlink():
        raise ValueError("Skill destination must not be a symlink")
    status = skill_status(name, directory)
    if status == "current":
        return {"name": name, "path": str(path.resolve()), "status": "unchanged"}
    mode = os.O_WRONLY | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
    mode |= os.O_TRUNC if force or status == "outdated" else os.O_EXCL
    with os.fdopen(os.open(path, mode, 0o644), "wb") as handle:
        handle.write(raw)
    return {"name": name, "path": str(path.resolve()), "status": "installed"}
