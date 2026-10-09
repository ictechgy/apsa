from __future__ import annotations

import os
import selectors
import signal
import subprocess
import time
from pathlib import Path

import psutil


def command(
    args: list[str],
    timeout: float = 30,
    max_bytes: int = 64 * 1024 * 1024,
    max_rss: int | None = None,
    *,
    cwd: Path | None = None,
    env: dict[str, str] | None = None,
) -> bytes:
    """Capture a command with finite output and wall time, including its descendants."""
    if timeout <= 0 or max_bytes <= 0:
        raise ValueError("Command limits must be positive")
    try:
        process = subprocess.Popen(
            args,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=os.name == "posix",
            cwd=cwd,
            env=env,
        )
    except FileNotFoundError:
        raise ValueError(f"Required tool missing: {args[0]}. Run apsa doctor.") from None
    output = bytearray()
    error_bytes = 0
    deadline = time.monotonic() + timeout
    monitored = psutil.Process(process.pid) if max_rss else None
    selector = selectors.DefaultSelector()
    assert process.stdout is not None and process.stderr is not None
    selector.register(process.stdout, selectors.EVENT_READ, "stdout")
    selector.register(process.stderr, selectors.EVENT_READ, "stderr")
    try:
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ValueError(f"Command timed out: {args[0]}")
            if monitored:
                try:
                    rss = monitored.memory_info().rss + sum(
                        child.memory_info().rss for child in monitored.children(recursive=True)
                    )
                    if max_rss and rss > max_rss:
                        raise ValueError("Parser memory exceeds limit; audit incomplete")
                except psutil.NoSuchProcess:
                    pass
            for key, _ in selector.select(min(remaining, 0.1)):
                chunk = os.read(key.fd, 65536)
                if not chunk:
                    selector.unregister(key.fileobj)
                elif key.data == "stdout":
                    if len(output) + len(chunk) > max_bytes:
                        raise ValueError("Command output exceeds size limit; capture incomplete")
                    output.extend(chunk)
                else:
                    error_bytes += len(chunk)
                    if error_bytes > min(max_bytes, 256 * 1024):
                        raise ValueError("Command error output exceeds size limit; capture incomplete")
        try:
            returncode = process.wait(timeout=max(0.001, deadline - time.monotonic()))
        except subprocess.TimeoutExpired:
            raise ValueError(f"Command timed out: {args[0]}") from None
        if returncode:
            raise ValueError(
                f"Command failed ({args[0]}, exit {returncode}); check input, device authorization and test-build permissions."
            )
        return bytes(output)
    finally:
        if os.name == "posix":
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        elif process.poll() is None:
            process.kill()
        process.wait()
        selector.close()
        process.stdout.close()
        process.stderr.close()
