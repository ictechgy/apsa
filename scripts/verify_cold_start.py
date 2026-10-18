"""Record bounded cold PyPI resolution attempts on a fresh hosted runner."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import time
from pathlib import Path


def verify(version: str, output: Path, *, attempts: int = 10, delay: int = 30) -> dict:
    if (
        not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version)
        or not 1 <= attempts <= 10
        or not 0 <= delay <= 30
    ):
        raise ValueError("Invalid cold-resolution version or retry bounds")
    output.mkdir(parents=True, exist_ok=False)
    records = []
    report = {
        "version": version,
        "passed": False,
        "attempts": records,
        "scope": "Fresh uvx resolution and exact CLI version only",
    }
    for number in range(1, attempts + 1):
        directory = output / f"attempt-{number:02d}"
        directory.mkdir()
        cache, app_home = directory / "cache", directory / "home"
        argv = ["uvx", "--python", "3.12.13", f"apsa@{version}", "--version"]
        environment = dict(os.environ, UV_CACHE_DIR=str(cache), APSA_HOME=str(app_home), UV_NO_CONFIG="1")
        timed_out = False
        try:
            result = subprocess.run(argv, env=environment, capture_output=True, timeout=90, check=False)
            code, stdout, stderr = result.returncode, result.stdout, result.stderr
        except subprocess.TimeoutExpired as error:
            code, stdout, stderr, timed_out = None, error.stdout or b"", error.stderr or b"", True
        (directory / "stdout").write_bytes(stdout)
        (directory / "stderr").write_bytes(stderr)
        exact_version = code == 0 and stdout.strip() == version.encode("ascii")
        outcome = (
            "passed"
            if exact_version
            else "version-mismatch"
            if code == 0
            else "timeout"
            if timed_out
            else "resolution-failed"
        )
        record = {
            "number": number,
            "argv": argv,
            "cache": str(cache),
            "app_home": str(app_home),
            "exit_code": code,
            "timed_out": timed_out,
            "outcome": outcome,
            "stdout_sha256": hashlib.sha256(stdout).hexdigest(),
            "stderr_sha256": hashlib.sha256(stderr).hexdigest(),
        }
        records.append(record)
        (directory / "result.json").write_text(json.dumps(record, indent=2) + "\n")
        report["passed"] = exact_version
        (output / "result.json").write_text(json.dumps(report, indent=2) + "\n")
        if exact_version or code == 0:
            break
        if number < attempts:
            time.sleep(delay)
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    if os.environ.get("GITHUB_ACTIONS") != "true" or not args.out.resolve().is_relative_to(
        Path(os.environ["RUNNER_TEMP"]).resolve()
    ):
        raise ValueError("Cold startup execution requires a fresh hosted runner temporary directory")
    report = verify(args.version, args.out)
    print(json.dumps(report, indent=2))
    if not report["passed"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
