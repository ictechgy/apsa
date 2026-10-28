#!/usr/bin/env python3
"""Capture official local artifact checks for explicitly NEW synthetic fixtures.

Use only newly compiled fixtures in a fresh temporary directory. This driver does
not enumerate devices, profiles, keychains, installed applications or user data.
It records hashes and actual stdout/stderr; records remain caller-attested.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import selectors
import signal
import subprocess
import tempfile
import time
from pathlib import Path

from mobile_audit.artifact_oracle import MAX_OUTPUT_BYTES, record_digest, validate_artifact_observation


def sha(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def _wait_unreaped(process: subprocess.Popen, deadline: float) -> bool:
    """Observe only this owned child's exit without releasing its PID custody."""
    while True:
        waitid = getattr(os, "waitid", None)
        if waitid is not None:
            event = waitid(os.P_PID, process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
            exited = event is not None
        else:
            # Darwin has no os.waitid; status() does not reap the owned child.
            import psutil

            try:
                exited = psutil.Process(process.pid).status() == psutil.STATUS_ZOMBIE
            except psutil.NoSuchProcess:
                raise ChildProcessError("Owned child custody unavailable") from None
        if exited:
            return True
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return False
        time.sleep(min(0.01, remaining))


def capture(argv: list[str], cwd: Path, *, java_home: Path | None = None) -> dict:
    """Retain bounded raw streams and status, terminating a hung process group."""
    streams = {"stdout": bytearray(), "stderr": bytearray()}
    timed_out = truncated = False
    environment = {"PATH": "/usr/bin:/bin", "TMPDIR": str(cwd)}
    if java_home is not None:
        environment["JAVA_HOME"] = str(java_home.resolve(strict=True))
    process = subprocess.Popen(
        argv,
        cwd=cwd,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
        env=environment,
    )
    assert process.stdout is not None and process.stderr is not None
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ, "stdout")
    selector.register(process.stderr, selectors.EVENT_READ, "stderr")
    deadline = time.monotonic() + 45
    custody_held = True
    exited_observed = False
    group_cleanup = "unconfirmed"
    try:
        while selector.get_map():
            if time.monotonic() >= deadline:
                timed_out = True
                break
            for key, _ in selector.select(0.05):
                chunk = os.read(key.fd, 65536)
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                target = streams[key.data]
                remaining = MAX_OUTPUT_BYTES - len(target)
                target.extend(chunk[:remaining])
                if len(chunk) > remaining:
                    truncated = True
                    break
            if truncated:
                break
        if not timed_out and not truncated:
            exited_observed = _wait_unreaped(process, deadline)
            timed_out = not exited_observed
    except ChildProcessError:
        custody_held = False
        raise
    finally:
        if custody_held:
            try:
                os.killpg(process.pid, signal.SIGKILL)
                group_cleanup = "signal-sent"
            except ProcessLookupError:
                group_cleanup = "absent"
            except PermissionError:
                # Darwin can deny killpg for an unreaped zombie leader. Only
                # this observed exit permits reaping without another signal.
                if not exited_observed:
                    raise
        process.wait()
        selector.close()
        process.stdout.close()
        process.stderr.close()
    return {
        "argv": argv,
        "environment": environment,
        "returncode": process.returncode,
        "timed_out": timed_out,
        "output_truncated": truncated,
        "process_group_cleanup": group_cleanup,
        **{f"{name}_base64": base64.b64encode(raw).decode() for name, raw in streams.items()},
        **{f"{name}_sha256": hashlib.sha256(raw).hexdigest() for name, raw in streams.items()},
    }


def snapshot(paths: list[Path], root: Path) -> dict[str, str]:
    result = {}
    for path in paths:
        resolved = path.resolve(strict=True)
        if not resolved.is_relative_to(root) or path.is_symlink() or not resolved.is_file():
            raise ValueError("Every fixture input must be a regular file within the NEW fixture root")
        result[str(resolved.relative_to(root))] = sha(resolved)
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--new-root", type=Path, required=True)
    parser.add_argument("--artifact", type=Path, required=True)
    parser.add_argument("--source", type=Path, action="append", required=True)
    parser.add_argument("--compiler", type=Path, action="append", required=True)
    parser.add_argument("--oracle", choices=("codesign_integrity", "apksigner_signature"), required=True)
    parser.add_argument("--tool", type=Path, required=True)
    parser.add_argument("--record", type=Path, required=True)
    parser.add_argument("--java-home", type=Path)
    args = parser.parse_args()
    root = args.new_root.resolve(strict=True)
    temporary_roots = {Path(tempfile.gettempdir()).resolve(), Path("/tmp").resolve()}
    if (
        root in temporary_roots
        or not root.is_dir()
        or not any(root.is_relative_to(parent) for parent in temporary_roots)
    ):
        raise ValueError(
            "NEW fixture root must be an explicitly created subdirectory of a system temp directory"
        )
    if args.artifact.is_symlink():
        raise ValueError("NEW artifact must not be a symlink")
    artifact = args.artifact.resolve(strict=True)
    record_path = args.record.resolve()
    if (
        not artifact.is_relative_to(root)
        or not record_path.is_relative_to(root)
        or record_path.exists()
        or artifact.is_symlink()
    ):
        raise ValueError("Artifact and new record must remain within the NEW root")
    if args.oracle == "codesign_integrity":
        if not artifact.is_dir() or artifact.suffix != ".app":
            raise ValueError("codesign oracle requires a NEW app bundle")
        files = list(artifact.rglob("*"))
        if any(path.is_symlink() for path in files) or len(files) > 256:
            raise ValueError("NEW bundle has unsupported links or too many files")
        files = [path for path in files if path.is_file()]
        argv = [str(args.tool), "--verify", "--deep", "--strict", "--verbose=4", str(artifact)]
    else:
        if not artifact.is_file() or artifact.suffix != ".apk":
            raise ValueError("apksigner oracle requires a NEW APK")
        files = [artifact]
        argv = [str(args.tool), "verify", "--verbose", "--print-certs", str(artifact)]
    inputs = snapshot(files, root)
    sources = snapshot(args.source, root)
    compilers = {str(path.resolve(strict=True)): sha(path.resolve(strict=True)) for path in args.compiler}
    tool_hash = sha(args.tool.resolve(strict=True))
    captured = capture(argv, root, java_home=args.java_home)
    capture_diagnostics = {"process_group_cleanup": captured.pop("process_group_cleanup")}
    result = {
        "schema_version": 1,
        "oracle": args.oracle,
        "tool_sha256": tool_hash,
        "input_sha256": inputs,
        "source_sha256": sources,
        "compiler_sha256": compilers,
        **captured,
    }
    current_files = [artifact]
    if artifact.is_dir():
        current_files = list(artifact.rglob("*"))
        if any(path.is_symlink() for path in current_files) or len(current_files) > 256:
            raise ValueError("NEW bundle changed during verification")
        current_files = [path for path in current_files if path.is_file()]
    current_compilers = {
        str(path.resolve(strict=True)): sha(path.resolve(strict=True)) for path in args.compiler
    }
    if (
        inputs != snapshot(current_files, root)
        or sources != snapshot(args.source, root)
        or compilers != current_compilers
        or tool_hash != sha(args.tool.resolve(strict=True))
    ):
        raise ValueError("Artifact/tool changed during verification; discard observation")
    result["record_sha256"] = record_digest(result)
    summary = validate_artifact_observation(
        result,
        expected_inputs=inputs,
        expected_argv=argv,
        expected_tool_sha256=tool_hash,
        expected_environment=result["environment"],
    )
    with record_path.open("x") as stream:
        json.dump(
            {"observation": result, "summary": summary, "capture_diagnostics": capture_diagnostics},
            stream,
            indent=2,
            sort_keys=True,
        )
        stream.write("\n")
    print(json.dumps({"record": str(record_path), "state": summary["state"]}, sort_keys=True))


if __name__ == "__main__":
    main()
