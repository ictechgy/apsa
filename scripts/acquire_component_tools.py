"""Acquire pinned public tools in a NEW hosted-CI directory before execution."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import tarfile
import urllib.request
from pathlib import Path
from typing import TypedDict
from urllib.parse import urlsplit

from .verify_dependency import verify


class ToolPin(TypedDict):
    version: str
    url: str
    checksums: str
    sha256: str
    bytes: int
    member: str | None


PINS: dict[str, ToolPin] = {
    "gitleaks": {
        "version": "8.30.1",
        "url": "https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/gitleaks_8.30.1_linux_x64.tar.gz",
        "checksums": "https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/gitleaks_8.30.1_checksums.txt",
        "sha256": "551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb",
        "bytes": 8_230_402,
        "member": "gitleaks",
    },
    "osv-scanner": {
        "version": "2.7.0",
        "url": "https://github.com/google/osv-scanner/releases/download/v2.7.0/osv-scanner_linux_amd64",
        "checksums": "https://github.com/google/osv-scanner/releases/download/v2.7.0/osv-scanner_SHA256SUMS",
        "sha256": "160c6253e2922e9e0a6a9771c5c4c40a4b3c6090b34a3cdd5e80c96cc2e4218b",
        "bytes": 57_725_088,
        "member": None,
    },
}
MARKER = "APSA_COMPONENT_ACQUISITION="
MAX_EXECUTABLE_BYTES = 128 * 1024 * 1024


class AcquisitionError(ValueError):
    """Fixed reasons never include signed redirect URLs or raw HTTP errors."""


def permitted_url(url: str) -> bool:
    try:
        parsed = urlsplit(url)
        if (
            parsed.scheme != "https"
            or parsed.username
            or parsed.password
            or parsed.port not in (None, 443)
            or parsed.fragment
        ):
            return False
        if parsed.hostname == "github.com":
            return url in {value for p in PINS.values() for value in (p["url"], p["checksums"])}
        return parsed.hostname in {
            "release-assets.githubusercontent.com",
            "objects.githubusercontent.com",
        } and parsed.path.startswith("/github-production-release-asset")
    except (ValueError, TypeError):
        return False


class PublicRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not permitted_url(newurl):
            raise AcquisitionError("unexpected_public_redirect")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def download(opener, url: str, destination: Path, limit: int) -> str:
    if not permitted_url(url):
        raise AcquisitionError("unexpected_public_source")
    request = urllib.request.Request(url, headers={"User-Agent": "APSA-component-benchmark"})
    total = 0
    checksum = hashlib.sha256()
    try:
        with opener.open(request, timeout=90) as response:
            if response.status != 200 or not permitted_url(response.geturl()):
                raise AcquisitionError("unexpected_public_response")
            with destination.open("xb") as target:
                while chunk := response.read(min(1024 * 1024, limit + 1 - total)):
                    total += len(chunk)
                    if total > limit:
                        raise AcquisitionError("download_size_limit")
                    target.write(chunk)
                    checksum.update(chunk)
    except AcquisitionError:
        raise
    except OSError as exc:
        raise AcquisitionError("download_unavailable") from exc
    if not total:
        raise AcquisitionError("empty_download")
    return checksum.hexdigest()


def published_checksum(text: str, filename: str, expected: str) -> None:
    matches = []
    for line in text.splitlines():
        match = re.fullmatch(r"([0-9a-fA-F]{64})\s+\*?([^\s]+)", line.strip())
        if match and match[2] == filename:
            matches.append(match[1].lower())
    if matches != [expected]:
        raise AcquisitionError("published_checksum_disagrees")


def extract_executable(archive: Path, destination: Path, member: str) -> str:
    """Copy only one exact regular member, never extract/extractall."""
    with tarfile.open(archive, "r:gz") as container:
        selected = []
        for count, entry in enumerate(container, 1):
            if count > 64:
                raise AcquisitionError("archive_member_limit")
            if entry.name == member:
                selected.append(entry)
        if len(selected) != 1 or not selected[0].isfile() or not 0 < selected[0].size <= MAX_EXECUTABLE_BYTES:
            raise AcquisitionError("invalid_executable_member")
        stream = container.extractfile(selected[0])
        if stream is None:
            raise AcquisitionError("missing_executable_member")
        total = 0
        checksum = hashlib.sha256()
        with stream, destination.open("xb") as target:
            while chunk := stream.read(1024 * 1024):
                total += len(chunk)
                if total > selected[0].size:
                    raise AcquisitionError("executable_size_mismatch")
                target.write(chunk)
                checksum.update(chunk)
        if total != selected[0].size:
            raise AcquisitionError("executable_size_mismatch")
    return checksum.hexdigest()


def mutation_control(artifact: Path, expected: str) -> dict:
    mutation = artifact.with_name(artifact.name + ".mutated")
    with artifact.open("rb") as source, mutation.open("xb") as target:
        first = source.read(1)
        if not first:
            raise AcquisitionError("empty_mutation_source")
        target.write(bytes([first[0] ^ 1]))
        shutil.copyfileobj(source, target)
    try:
        result = verify(mutation, expected)
        if result["reason"] != "sha256_mismatch":
            raise AcquisitionError("mutation_control_failed")
        return result
    finally:
        mutation.unlink()


def acquire(destination: Path, opener, head: str) -> dict:
    if re.fullmatch(r"[a-f0-9]{40}", head) is None:
        raise AcquisitionError("missing_source_revision")
    destination.mkdir(parents=False, exist_ok=False)
    tools = {}
    for name, pin in PINS.items():
        checksums = destination / (name + "-SHA256SUMS")
        download(opener, pin["checksums"], checksums, 128 * 1024)
        published_checksum(checksums.read_text(), pin["url"].rsplit("/", 1)[1], pin["sha256"])
        artifact = destination / (name + ".download")
        observed = download(opener, pin["url"], artifact, pin["bytes"])
        verification = verify(artifact, pin["sha256"], max_bytes=pin["bytes"])
        if (
            observed != pin["sha256"]
            or verification["status"] != "verified"
            or verification["filesize"] != pin["bytes"]
        ):
            raise AcquisitionError("pinned_artifact_mismatch")
        mutation = mutation_control(artifact, pin["sha256"])
        executable = destination / name
        if pin["member"] is not None:
            executable_hash = extract_executable(artifact, executable, pin["member"])
        else:
            artifact.rename(executable)
            executable_hash = pin["sha256"]
        with executable.open("rb") as stream:
            if stream.read(4) != b"\x7fELF":
                raise AcquisitionError("unexpected_binary_format")
        executable.chmod(0o755)
        tools[name] = {
            "path": str(executable),
            "version": pin["version"],
            "sha256": executable_hash,
            "archive_sha256": pin["sha256"],
            "acquisition": {
                "url": pin["url"],
                "sha256": observed,
                "bytes": verification["filesize"],
                "verification": verification,
                "mutation_rejected": mutation,
                "published_checksum_matched": True,
                "vendor_signature_verified": False,
            },
        }
    root = Path(__file__).resolve().parents[1]
    result = {
        "schema_version": 1,
        "source_commit": head,
        "source_sha256": {
            p: hashlib.sha256((root / p).read_bytes()).hexdigest()
            for p in ("scripts/acquire_component_tools.py", "scripts/verify_dependency.py")
        },
        "tools": tools,
    }
    (destination / "manifest.json").write_text(json.dumps(result, indent=2) + "\n")
    return result


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if os.environ.get("GITHUB_ACTIONS") != "true":
            raise AcquisitionError("hosted_ci_only")
        runner = Path(os.environ["RUNNER_TEMP"]).resolve()
        out = args.out.absolute()
        if out.parent.resolve() != runner or out.exists() or out.is_symlink():
            raise AcquisitionError("new_runner_directory_required")
        result = acquire(
            out,
            urllib.request.build_opener(PublicRedirects()),
            os.environ.get("GITHUB_SHA", ""),
        )
    except (AcquisitionError, OSError, KeyError, UnicodeError, tarfile.TarError) as exc:
        reason = str(exc) if isinstance(exc, AcquisitionError) else "acquisition_failed"
        print(MARKER + json.dumps({"state": "failed", "reason": reason}))
        return 1
    print(MARKER + json.dumps({"state": "verified", **result}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
