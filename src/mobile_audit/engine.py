from __future__ import annotations

import json
import os
import sys
import tempfile
from contextlib import contextmanager
from pathlib import Path

from .input_snapshot import identity, stage_input
from .processes import command

PARSER_TIMEOUT = 90
MAX_RESULT = 32 * 1024 * 1024


@contextmanager
def parser_lease(directory: Path | None = None):
    if os.name != "posix":
        raise ValueError("Bounded parser execution currently supports macOS and Linux hosts")
    import fcntl

    directory = directory or (
        Path(os.environ["APSA_PARSER_LOCK_DIR"])
        if os.environ.get("APSA_PARSER_LOCK_DIR")
        else Path.home() / ".cache/mobile-audit/parser-locks"
    )
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


def analyze_target(
    target: Path,
    sbom: Path | None = None,
    expected_target: Path | None = None,
    configuration: str | None = None,
    *,
    report_home: Path | None = None,
    specs: dict | None = None,
) -> dict:
    caller_bound = expected_target is not None
    resolved = target.expanduser().resolve()
    expected_target = expected_target or resolved
    if resolved != expected_target:
        raise ValueError("Authorized input moved or became a symlink; audit refused")
    if not resolved.exists():
        raise ValueError(f"Input not found: {resolved}")
    sbom = (sbom if caller_bound else sbom.expanduser().resolve()) if sbom else None
    with parser_lease(), tempfile.TemporaryDirectory(prefix="mobile-audit-work-") as directory:
        root = Path(directory).resolve()
        scratch = root / "work"
        scratch.mkdir()
        staged = root / "input" / resolved.name
        hidden = (Path.home() / ".local/share/mobile-audit",) + (
            (report_home.resolve(),) if report_home else ()
        )
        snapshot = stage_input(resolved, staged, hidden=hidden)
        staged_sbom = root / "sbom" / "sbom.json" if sbom else None
        if sbom and staged_sbom:
            stage_input(sbom, staged_sbom, source=False)
        args = [
            sys.executable,
            "-I",
            "-B",
            "-m",
            "mobile_audit._parser_worker",
            str(staged),
            str(staged_sbom) if staged_sbom else "",
            str(staged),
            str(scratch),
            configuration or "",
            # Notes are for people; the parser needs only names, kinds and the file hash.
            json.dumps(
                {
                    **specs,
                    "source": [{k: v for k, v in e.items() if k != "note"} for e in specs["source"]],
                    "sink": [{k: v for k, v in e.items() if k != "note"} for e in specs["sink"]],
                },
                sort_keys=True,
            )
            if specs
            else "",
        ]
        from .parser_sandbox import activate, sandbox_command

        wrapped, isolation = sandbox_command(args, staged, staged_sbom, scratch, report_home=report_home)
        wrapped, isolation = activate(wrapped, args, isolation, scratch)
        try:
            raw = command(
                wrapped,
                timeout=PARSER_TIMEOUT,
                max_bytes=MAX_RESULT,
                max_rss=1024 * 1024 * 1024,
                cwd=scratch,
                env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "TMPDIR": str(scratch)},
            )
        except ValueError as error:
            if isolation["state"] == "enforced" and str(error).startswith("Command failed"):
                raise ValueError(
                    f"Sandboxed parser failed under {isolation['backend']}; the audit was not retried "
                    f"without OS isolation. {error} If the backend is incompatible with this host, "
                    "APSA_PARSER_SANDBOX=off runs with resource limits only."
                ) from None
            raise
        if resolved.resolve() != expected_target or identity(resolved) != snapshot["identity"]:
            raise ValueError("Authorized input moved or became a symlink; audit refused")
    try:
        result = json.loads(raw)
    except (ValueError, UnicodeError):
        raise ValueError("Parser worker returned invalid output; audit incomplete") from None
    if result.get("error"):
        raise ValueError(result["error"])
    if not isinstance(result.get("inventory"), dict) or not isinstance(result.get("findings"), list):
        raise ValueError("Parser worker returned an invalid schema; audit incomplete")
    result["inventory"]["parser_isolation"] = isolation
    if isolation.get("activation_probe") == "failed":
        result["inventory"]["warnings"].append(
            f"Parser OS isolation unavailable; parsed with resource limits only: {isolation['unavailable_reason']}"
        )
    result["inventory"]["target"] = str(resolved)
    result["inventory"]["input_snapshot"] = {
        "kind": "parent-staged-descriptor-safe",
        "files": snapshot["files"],
        "bytes": snapshot["bytes"],
        "partial": bool(snapshot["warnings"]),
    }
    if snapshot["warnings"]:
        result["inventory"]["warnings"].extend(snapshot["warnings"])
        result["inventory"]["partial"] = True
        result["inventory"]["fingerprint_complete"] = False
        for check in result.get("coverage", []):
            if check["state"] == "checked":
                check["state"] = "partial"
    return result
