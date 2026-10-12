#!/usr/bin/env python3
"""Public remote-CI acquisition only: no image run, ZIP extraction, or tool run."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

JADX_URL = "https://github.com/skylot/jadx/releases/download/v1.5.0/jadx-1.5.0.zip"
JADX_METADATA_URL = "https://api.github.com/repos/skylot/jadx/releases/tags/v1.5.0"
JADX_BYTES = 104_967_983
JADX_LIMIT = 128 * 1024 * 1024
SEMGREP_IMAGE = "docker.io/semgrep/semgrep:1.179.0"
PLATFORM = "linux/amd64"
MARKER = "APSA_BENCHMARK_DEPENDENCY_ACQUISITION="


class AcquisitionError(ValueError):
    """Fixed public reason only; never include URLs with signed query tokens."""


def permitted_url(url: str) -> bool:
    try:
        parts = urlsplit(url)
        if parts.scheme != "https" or parts.username or parts.password or parts.port not in (None, 443):
            return False
        if parts.fragment:
            return False
        if parts.hostname == "github.com":
            return not parts.query and parts.path in {
                urlsplit(JADX_URL).path + suffix for suffix in ("", ".sha256", ".sha512", ".sha1")
            }
        if parts.hostname == "api.github.com":
            return not parts.query and parts.path == urlsplit(JADX_METADATA_URL).path
        return parts.hostname in {
            "release-assets.githubusercontent.com",
            "objects.githubusercontent.com",
        } and parts.path.startswith("/github-production-release-asset")
    except ValueError:
        return False


class PublicRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not permitted_url(newurl):
            raise AcquisitionError("unexpected_public_redirect")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def small_response(opener, url: str, limit: int) -> tuple[dict, bytes | None]:
    if not permitted_url(url):
        raise AcquisitionError("unexpected_public_source")
    try:
        request = urllib.request.Request(url, headers={"User-Agent": "APSA-public-dependency-acquisition"})
        with opener.open(request, timeout=30) as response:
            if not permitted_url(response.geturl()):
                raise AcquisitionError("unexpected_public_redirect")
            record = {"source_url": url, "http_status": response.status}
            if response.status != 200:
                return record, None
            raw = response.read(limit + 1)
        if len(raw) > limit:
            raise AcquisitionError("public_metadata_exceeds_bound")
        return record, raw
    except urllib.error.HTTPError as error:
        return {"source_url": url, "http_status": error.code}, None
    except urllib.error.URLError:
        return {"source_url": url, "http_status": None, "transport_status": "unavailable"}, None


def checksum_metadata(opener) -> dict:
    result = {"sidecars": {}, "release_metadata": {}, "published_checksums": {}}
    for algorithm, length in (("sha256", 64), ("sha512", 128), ("sha1", 40)):
        observation, raw = small_response(opener, JADX_URL + "." + algorithm, 4096)
        if raw is not None:
            try:
                match = re.fullmatch(
                    rf"([0-9a-fA-F]{{{length}}})(?:[ \t]+\*?jadx-1\.5\.0\.zip)?\s*", raw.decode("ascii")
                )
            except UnicodeDecodeError as error:
                raise AcquisitionError("malformed_published_checksum") from error
            if match is None:
                raise AcquisitionError("malformed_published_checksum")
            observation["digest"] = match.group(1).lower()
            result["published_checksums"][algorithm] = observation["digest"]
        result["sidecars"][algorithm] = observation
    observation, raw = small_response(opener, JADX_METADATA_URL, 1024 * 1024)
    if raw is not None:
        try:
            metadata = json.loads(raw)
            if metadata.get("tag_name") != "v1.5.0":
                raise AcquisitionError("unexpected_release_metadata")
            assets = [asset for asset in metadata["assets"] if asset.get("name") == "jadx-1.5.0.zip"]
            if len(assets) != 1 or assets[0].get("browser_download_url") != JADX_URL:
                raise AcquisitionError("unexpected_release_asset_metadata")
            if assets[0].get("size") != JADX_BYTES:
                raise AcquisitionError("unexpected_release_asset_size")
            digest = assets[0].get("digest")
            observation["asset_bytes"] = JADX_BYTES
            observation["digest_status"] = "not_published" if digest is None else "published"
            if digest is not None:
                if not isinstance(digest, str) or re.fullmatch(r"sha256:[a-fA-F0-9]{64}", digest) is None:
                    raise AcquisitionError("malformed_release_asset_digest")
                value = digest.split(":", 1)[1].lower()
                if result["published_checksums"].get("sha256", value) != value:
                    raise AcquisitionError("published_checksum_sources_disagree")
                result["published_checksums"]["sha256"] = value
                observation["sha256"] = value
        except (KeyError, TypeError, AttributeError, json.JSONDecodeError) as error:
            raise AcquisitionError("malformed_release_metadata") from error
    result["release_metadata"] = observation
    return result


def acquire_jadx(opener, metadata: dict) -> list[dict]:
    acquisitions = []
    for attempt in (1, 2):
        hashes = {algorithm: hashlib.new(algorithm) for algorithm in ("sha256", "sha512", "sha1")}
        total = 0
        with opener.open(JADX_URL, timeout=90) as response:
            if response.status != 200 or not permitted_url(response.geturl()):
                raise AcquisitionError("unexpected_artifact_response")
            final_host = urlsplit(response.geturl()).hostname
            while chunk := response.read(min(1024 * 1024, JADX_LIMIT - total + 1)):
                total += len(chunk)
                if total > JADX_LIMIT:
                    raise AcquisitionError("artifact_exceeds_bound")
                for digest in hashes.values():
                    digest.update(chunk)
        if total != JADX_BYTES:
            raise AcquisitionError("unexpected_artifact_size")
        observation = {
            "attempt": attempt,
            "bytes": total,
            "final_host": final_host,
            **{algorithm: digest.hexdigest() for algorithm, digest in hashes.items()},
        }
        for algorithm, expected in metadata["published_checksums"].items():
            if observation[algorithm] != expected:
                raise AcquisitionError("published_checksum_mismatch")
        acquisitions.append(observation)
    if acquisitions[0]["sha256"] != acquisitions[1]["sha256"]:
        raise AcquisitionError("independent_acquisitions_disagree")
    return acquisitions


def acquire_semgrep(work: Path) -> dict:
    docker_config = work / "empty-docker-config"
    docker_config.mkdir()
    (docker_config / "config.json").write_text('{"auths": {}}\n')
    environment = dict(os.environ)
    environment["DOCKER_CONFIG"] = str(docker_config)
    # No login or credential helper. Native Docker pulls verify registry content
    # addresses; acquired image contents are never run by this workflow.
    subprocess.run(
        ["docker", "pull", "--platform", PLATFORM, SEMGREP_IMAGE],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=600,
        env=environment,
    )
    observed = subprocess.run(
        ["docker", "image", "inspect", "--format", "{{json .RepoDigests}}", SEMGREP_IMAGE],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        timeout=30,
        env=environment,
    ).stdout
    if len(observed) > 65536:
        raise AcquisitionError("image_metadata_exceeds_bound")
    try:
        digests = json.loads(observed)
    except (ValueError, UnicodeDecodeError) as error:
        raise AcquisitionError("malformed_image_digest_metadata") from error
    if not isinstance(digests, list) or not 1 <= len(digests) <= 16:
        raise AcquisitionError("malformed_image_digest_metadata")
    values = set()
    for digest in digests:
        if not isinstance(digest, str):
            raise AcquisitionError("malformed_image_digest_metadata")
        match = re.fullmatch(r"(?:docker\.io/)?semgrep/semgrep@sha256:([a-f0-9]{64})", digest)
        if match:
            values.add("docker.io/semgrep/semgrep@sha256:" + match.group(1))
    if len(values) != 1:
        raise AcquisitionError("missing_or_ambiguous_image_repo_digest")
    platform = subprocess.run(
        ["docker", "image", "inspect", "--format", "{{.Os}}/{{.Architecture}}", SEMGREP_IMAGE],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        timeout=30,
        env=environment,
    ).stdout
    if platform.strip() != PLATFORM.encode("ascii"):
        raise AcquisitionError("unexpected_image_platform")
    return {
        "source_image": SEMGREP_IMAGE,
        "source_url": "https://hub.docker.com/r/semgrep/semgrep",
        "requested_platform": PLATFORM,
        "observed_platform": PLATFORM,
        "repo_digest": next(iter(values)),
        "digest_scope": "registry-OCI-manifest-or-index-content-address-not-ZIP-file-SHA256",
        "tool_execution": False,
        "vendor_signature_verified": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--work", type=Path, required=True)
    args = parser.parse_args()
    # Network work is restricted to explicitly new hosted CI runs, never local.
    if os.environ.get("GITHUB_ACTIONS") != "true" or os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted":
        print(MARKER + json.dumps({"schema": 1, "status": "failed", "reason": "hosted_ci_required"}))
        return 1
    runner_temp = Path(os.environ["RUNNER_TEMP"]).resolve()
    work = args.work.resolve()
    if work == runner_temp or not work.is_relative_to(runner_temp):
        raise AcquisitionError("new_runner_temp_child_required")
    work.mkdir(parents=True, exist_ok=False)
    record = {
        "schema": 1,
        "head_sha": os.environ["GITHUB_SHA"],
        "run_id": os.environ["GITHUB_RUN_ID"],
        "run_url": f"https://github.com/{os.environ['GITHUB_REPOSITORY']}/actions/runs/{os.environ['GITHUB_RUN_ID']}",
        "acquired_at_utc": datetime.now(timezone.utc).isoformat(),
        "mode": "acquisition-only-no-extraction-no-container-or-tool-execution",
        "vendor_signature_verified": False,
        "status": "started",
        "jadx": {"source_url": JADX_URL, "version": "1.5.0", "expected_bytes": JADX_BYTES},
        "semgrep": {"source_image": SEMGREP_IMAGE},
    }
    exit_code = 1
    try:
        opener = urllib.request.build_opener(PublicRedirects())
        record["jadx"].update(checksum_metadata(opener))
        record["jadx"]["acquisitions"] = acquire_jadx(opener, record["jadx"])
        record["jadx"]["pin_basis"] = (
            "upstream-published-sha256"
            if "sha256" in record["jadx"]["published_checksums"]
            else "reviewed-HTTPS-acquisition-TOFU-candidate"
        )
        record["semgrep"] = acquire_semgrep(work)
        record["status"] = "acquired-for-review-not-yet-repository-pins"
        exit_code = 0
    except Exception as error:
        record["status"] = "failed"
        record["error_type"] = type(error).__name__
        if isinstance(error, AcquisitionError):
            record["reason"] = str(error)
    finally:
        (work / "acquisition.json").write_text(json.dumps(record, sort_keys=True, indent=2) + "\n")
        print(MARKER + json.dumps(record, sort_keys=True))
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
