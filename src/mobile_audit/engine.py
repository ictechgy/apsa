from __future__ import annotations

import json
import os
import sys
import tempfile
from contextlib import contextmanager
from pathlib import Path

from .processes import command

PARSER_TIMEOUT = 90
MAX_RESULT = 32 * 1024 * 1024


@contextmanager
def parser_lease(directory: Path | None = None):
    if os.name != "posix":
        raise ValueError("Bounded parser execution currently supports macOS and Linux hosts")
    import fcntl

    directory = directory or Path.home() / ".cache/mobile-audit/parser-locks"
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor = None
    for index in range(2):
        candidate = os.open(directory / f"{index}.lock", os.O_CREAT | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
        try:
            fcntl.flock(candidate, fcntl.LOCK_EX | fcntl.LOCK_NB)
            descriptor = candidate
            break
        except BlockingIOError:
            os.close(candidate)
    if descriptor is None:
        raise ValueError("Two parsers are already active; wait for another audit to finish")
    try:
        yield
    finally:
        os.close(descriptor)


def analyze_target(target: Path, sbom: Path | None = None, expected_target: Path | None = None) -> dict:
    caller_bound = expected_target is not None
    resolved = target.expanduser().resolve()
    expected_target = expected_target or resolved
    if resolved != expected_target:
        raise ValueError("Authorized input moved or became a symlink; audit refused")
    args = [
        sys.executable,
        "-I",
        "-m",
        "mobile_audit._parser_worker",
        str(resolved),
        str(sbom if caller_bound else sbom.expanduser().resolve()) if sbom else "",
        str(expected_target),
    ]
    with parser_lease(), tempfile.TemporaryDirectory(prefix="mobile-audit-work-") as directory:
        args.append(str(Path(directory).resolve()))
        raw = command(
            args,
            timeout=PARSER_TIMEOUT,
            max_bytes=MAX_RESULT,
            max_rss=1024 * 1024 * 1024,
            cwd=Path(directory).resolve(),
        )
    try:
        result = json.loads(raw)
    except (ValueError, UnicodeError):
        raise ValueError("Parser worker returned invalid output; audit incomplete") from None
    if result.get("error"):
        raise ValueError(result["error"])
    if not isinstance(result.get("inventory"), dict) or not isinstance(result.get("findings"), list):
        raise ValueError("Parser worker returned an invalid schema; audit incomplete")
    return result
