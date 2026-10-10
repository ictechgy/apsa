"""Install the same reusable instructions shipped in the wheel and source tree."""

from __future__ import annotations

import hashlib
import os
from importlib.resources import files
from pathlib import Path

from .core import read_bounded

KNOWN_RELEASE_HASHES = {
    "apsa": {
        "ca319e50888e6f6353e5a0e41e6c10208f829765e6149f3b90ecfc05331a19d1",
        "a7aae332969ba98ac8da4831b05a21092b342578e2b4b2c6c8bd270c9c93e81b",
        "248652d8cec8653d3ef265cac24cf9c59df9a9668753a781d8852fa616c6ddd5",
        "ebcfff30de22c7e84bc99bcc31b5208fd2d35f870aa45ea1cf3218c1500e6678",
        "afc9ae9c7ed89937bcf9a1d8d46d47b4557c1ecf20ca9c4ac14f9e6d0dc45819",
        "9bc6d3605d6cb303ab7ed462af4b0fcd1d3085fa74cdaffbd20bb7afec14b127",
    },
    "quaygate": {
        "b6016f299e2207f85db9a2850e5a837c4fb78bbc0cdee18e37bf19102b6c8c60",
        "61c5a4df34781542525177f3fc868e29bcf0ffe7f2757f39c1ef225f8b86b305",
        "f12331750c1ee915179e7956f4856cbc7ec824f8ba48a6146e1ce5a1537a4c09",
        "7b483602f91a9fd9bbc48893247e7edd3ae3b7e52059f51c7426357f2555ccd4",
        "2710bb3466bca1f95c15d0287c58b073e3c219eb532f1d7cf9bd84b6dd723dd2",
        "1cac4b413c8853c30cc158f388fc7bfeb2d10c42796eec0fac7bca6a2ca2e62a",
        "b96c322d0b31ddc1a55372e64c7afdf49bc4b5d2f3a25380527f53da89a7b9a3",
        "67c224315933d0e023c3fa345035cf7a737d462ec1b83d218f37ac56192583ed",
        "58af5c5c0c3f606fa00672ee5e15c052fc5f34075d7bfefca0c834e399acc966",
    },
    "mobile-audit": {
        "5bcb6a468221e51f3c6e786a44b135ff7761652a5fa663a4514372f3ade73280",
        "5bdd02b82f6e71e189130851d7b851aa134d727791e596da775545728c87936b",
        "a0f2df02d2c642b61e5dbb4e74f158b20b480b3dd8cdef8ce15503f4b4a60098",
        "31414a783b5e5011d72d6593d70d0d8b06a4c2c675f36297e3826d555d2d7cc6",
        "7c8835465139fc02bd8855a094f5a315c93148b888702c738de62df259ccdeaa",
        "42252e36cd0b3d9f4b3d4ca3ecbb1d71c474a2661689b9f3a58f47ea51848d63",
        "1425ed115ec263b0d47442c93aa43eef1676ba36b86d8303137cd1e8f214f103",
        "b839f8026c4d2c050c0710e40ac08f94991845da44a84f0ec6185a98929e7498",
        "69c38bfac093cec3c30a27905eeef83c5686d0c225d44ad12ebaf8288dfe1ec9",
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
