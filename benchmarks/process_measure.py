"""Bounded execution and sampled RSS of explicitly owned synthetic processes."""

from __future__ import annotations

import os
import selectors
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path

import psutil


class RssSampler:
    """Sample only an explicitly supplied process tree; never enumerate the host."""

    def __init__(self, pid: int):
        self.pid = pid
        self.root: psutil.Process | None = None
        self.identity: float | None = None
        self.samples = 0
        self.maximum = 0
        self.denied = False
        if not sys.platform.startswith("linux"):
            self.denied = True
            return
        try:
            self.root = psutil.Process(pid)
            self.identity = self.root.create_time()
        except (psutil.Error, OSError):
            self.denied = True

    def sample(self) -> None:
        if self.root is None or self.identity is None or self.denied:
            return
        try:
            if self.root.create_time() != self.identity:
                self.denied = True
                return
            # Read child IDs from this owned Linux tree only. psutil.children()
            # may build a host-wide process map, which this probe avoids.
            processes = [self.root]
            parents = [self.root]
            seen = {self.pid}
            while parents:
                parent = parents.pop()
                try:
                    child_ids = Path(f"/proc/{parent.pid}/task/{parent.pid}/children").read_text().split()
                except FileNotFoundError:
                    continue
                for raw_pid in child_ids:
                    pid = int(raw_pid)
                    if pid in seen:
                        continue
                    try:
                        child = psutil.Process(pid)
                        if child.ppid() != parent.pid or child.create_time() < self.identity:
                            self.denied = True
                            return
                    except (psutil.NoSuchProcess, psutil.ZombieProcess):
                        continue
                    seen.add(pid)
                    processes.append(child)
                    parents.append(child)
            total = 0
            for process in processes:
                try:
                    total += process.memory_info().rss
                except (psutil.NoSuchProcess, psutil.ZombieProcess):
                    continue
            self.samples += 1
            self.maximum = max(self.maximum, total)
        except (psutil.NoSuchProcess, psutil.ZombieProcess):
            return
        except (psutil.Error, OSError):
            self.denied = True

    def result(self) -> dict:
        measured = bool(self.samples) and not self.denied
        return {
            "state": "measured" if measured else "unmeasured",
            "sampled_max_rss_bytes": self.maximum if measured else None,
            "samples": self.samples,
            "interval_seconds": 0.05,
            "scope": "sum of resident bytes in explicitly owned process tree; shared pages may be counted more than once; sampled maximum is a lower bound on peak",
        }


class ServiceRss:
    """Sample the new benchmark service PID supplied by its fresh container."""

    def __init__(self, pid: int | None):
        self.sampler = RssSampler(pid) if pid is not None else None
        self.stop = threading.Event()
        self.thread: threading.Thread | None = None

    def __enter__(self):
        def sample():
            assert self.sampler is not None
            while not self.stop.is_set():
                self.sampler.sample()
                self.stop.wait(0.05)

        if self.sampler is not None:
            self.sampler.sample()
            self.thread = threading.Thread(target=sample, daemon=True)
            self.thread.start()
        return self

    def __exit__(self, *_):
        self.stop.set()
        if self.thread is not None:
            self.thread.join(timeout=1)

    def result(self) -> dict:
        if self.sampler is None:
            return {"state": "unmeasured", "sampled_max_rss_bytes": None, "samples": 0}
        return self.sampler.result() | {
            "service_scope": "entire warm MobSF container process tree during upload and forced rescan, including idle resident memory; API caller excluded",
        }


def capture(argv: list[str], cwd: Path, environment: dict[str, str], timeout: int = 120) -> dict:
    """Bound streams, sample owned descendants, and terminate the new process group."""
    streams = {"stdout": bytearray(), "stderr": bytearray()}
    process = subprocess.Popen(
        argv,
        cwd=cwd,
        env=environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
    )
    sampler = RssSampler(process.pid)
    selector = selectors.DefaultSelector()
    assert process.stdout is not None and process.stderr is not None
    selector.register(process.stdout, selectors.EVENT_READ, "stdout")
    selector.register(process.stderr, selectors.EVENT_READ, "stderr")
    started = time.monotonic()
    incomplete = False
    try:
        while selector.get_map():
            sampler.sample()
            if time.monotonic() - started >= timeout:
                incomplete = True
                break
            for key, _ in selector.select(0.05):
                raw = os.read(key.fd, 65536)
                if not raw:
                    selector.unregister(key.fileobj)
                else:
                    stream = streams[key.data]
                    remaining = 1024 * 1024 - len(stream)
                    stream.extend(raw[:remaining])
                    if len(raw) > remaining:
                        incomplete = True
                        break
            if incomplete:
                break
        if not incomplete:
            try:
                process.wait(timeout=max(0.001, timeout - (time.monotonic() - started)))
            except subprocess.TimeoutExpired:
                incomplete = True
    finally:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait()
        selector.close()
        process.stdout.close()
        process.stderr.close()
    return {
        "argv": argv,
        "status": process.returncode,
        "incomplete": incomplete,
        "seconds": time.monotonic() - started,
        "rss": sampler.result(),
        **{name: raw.decode("utf-8", errors="replace") for name, raw in streams.items()},
    }
