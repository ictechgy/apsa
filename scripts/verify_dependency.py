#!/usr/bin/env python3
"""Compare dependency bytes to a predeclared SHA256; never unpack or execute."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
from pathlib import Path

DEFAULT_MAX_BYTES = 256 * 1024 * 1024
CHUNK_BYTES = 1024 * 1024


def _result(status, reason, digest=None, filesize=None):
    return {
        "status": status,
        "reason": reason,
        "sha256": digest,
        "filesize": filesize,
        "provenance": "predeclared-sha256-pin" if status == "verified" else "unverified",
    }


def _identity(info):
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def verify(path: str | Path, expected: str, *, max_bytes: int = DEFAULT_MAX_BYTES) -> dict:
    """Return a fixed-shape result; only a matching, stable regular file passes.

    The caller must obtain `expected` from a reviewed pin declared before this
    acquisition, and check `status` before unpacking or executing the artifact.
    No download, extraction, process execution, or expected-digest update occurs.
    """
    if not isinstance(expected, str) or re.fullmatch(r"[0-9a-fA-F]{64}", expected) is None:
        return _result("failed", "invalid_expected_sha256")
    if isinstance(max_bytes, bool) or not isinstance(max_bytes, int) or max_bytes <= 0:
        return _result("failed", "invalid_size_limit")
    if not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_NONBLOCK"):
        return _result("failed", "unsupported_platform")

    descriptor = None
    total = 0
    try:
        # NONBLOCK prevents a named pipe from stalling before the regular-file
        # check; NOFOLLOW rejects symlinks at the artifact path.
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            return _result("failed", "not_regular_file")
        if before.st_size <= 0:
            return _result("failed", "empty_artifact", filesize=before.st_size)
        if before.st_size > max_bytes:
            return _result("failed", "size_limit_exceeded", filesize=before.st_size)
        hasher = hashlib.sha256()
        while True:
            # Read at most max_bytes + 1 even if a file grows during hashing.
            chunk = os.read(descriptor, min(CHUNK_BYTES, max_bytes - total + 1))
            if not chunk:
                break
            total += len(chunk)
            if total > max_bytes:
                return _result("failed", "size_limit_exceeded", filesize=total)
            hasher.update(chunk)
        after = os.fstat(descriptor)
        named_after = os.stat(path, follow_symlinks=False)
        if (
            _identity(before) != _identity(after)
            or _identity(before) != _identity(named_after)
            or total != before.st_size
        ):
            return _result("failed", "artifact_changed", filesize=total)
        digest = hasher.hexdigest()
        if digest != expected.lower():
            return _result("failed", "sha256_mismatch", digest, total)
        return _result("verified", "sha256_match", digest, total)
    except (OSError, TypeError, ValueError):
        # Avoid leaking a path, file contents, or raw system error into CI logs.
        return _result("failed", "artifact_unreadable")
    finally:
        if descriptor is not None:
            os.close(descriptor)


class _SafeParser(argparse.ArgumentParser):
    def error(self, message):
        raise ValueError("invalid_arguments")


def main(argv=None):
    parser = _SafeParser(description=__doc__)
    parser.add_argument("artifact")
    parser.add_argument("--expected-sha256", required=True)
    parser.add_argument("--max-bytes", type=int, default=DEFAULT_MAX_BYTES)
    try:
        args = parser.parse_args(argv)
    except ValueError:
        result = _result("failed", "invalid_arguments")
    else:
        result = verify(args.artifact, args.expected_sha256, max_bytes=args.max_bytes)
    print(json.dumps(result, sort_keys=True))
    return 0 if result["status"] == "verified" else 1


if __name__ == "__main__":
    raise SystemExit(main())
