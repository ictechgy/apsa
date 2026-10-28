"""Verify public release bytes and identities on a fresh hosted CI runner."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import time
from http.client import HTTPException
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

REPOSITORY = "ictechgy/apsa"
SERVER_NAME = "io.github.ictechgy/apsa"
OFFICIAL_META = "io.modelcontextprotocol.registry/official"


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def validate_identity(version: str, source_sha: str, pypi: dict, release: dict, tag: dict, registry: dict):
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version) or not re.fullmatch(r"[a-f0-9]{40}", source_sha):
        raise ValueError("Invalid release version or source SHA")
    if pypi["info"]["name"] != "apsa" or pypi["info"]["version"] != version:
        raise ValueError("PyPI identity differs")
    if release["tag_name"] != "v" + version or release["draft"] or release["prerelease"]:
        raise ValueError("GitHub release identity differs")
    if (
        tag["ref"] != "refs/tags/v" + version
        or tag["object"]["type"] != "commit"
        or tag["object"]["sha"] != source_sha
    ):
        raise ValueError("Release tag is not bound to the expected source commit")
    server = registry["server"]
    if server["name"] != SERVER_NAME or server["version"] != version:
        raise ValueError("MCP Registry identity differs")
    if registry["_meta"][OFFICIAL_META]["status"] != "active":
        raise ValueError("MCP Registry entry is not active")
    packages = server["packages"]
    if not any(
        p.get("registryType") == "pypi" and p.get("identifier") == "apsa" and p.get("version") == version
        for p in packages
    ):
        raise ValueError("MCP Registry package version differs")


def validate_artifacts(
    version: str, pypi: dict, release: dict, sums: bytes, downloads: dict[str, bytes]
) -> dict:
    expected = {f"apsa-{version}-py3-none-any.whl", f"apsa-{version}.tar.gz"}
    records = {}
    for line in sums.decode("ascii").splitlines():
        match = re.fullmatch(r"([a-f0-9]{64})  (?:\./)?([A-Za-z0-9_.-]+)", line)
        if not match or match[2] in records:
            raise ValueError("Malformed or duplicate release checksum entry")
        records[match[2]] = match[1]
    allowed = expected | {f"apsa-{version}-verified-bundle.tar.gz", "release-manifest.json"}
    if set(records) != allowed:
        raise ValueError("Release checksum file set differs")
    assets = {item["name"]: item for item in release["assets"]}
    if len(assets) != len(release["assets"]) or set(assets) != allowed | {"SHA256SUMS"}:
        raise ValueError("Release asset file set differs")
    if assets["SHA256SUMS"].get("digest") != "sha256:" + sha256(sums):
        raise ValueError("Release checksum asset digest differs")
    for name, digest in records.items():
        if assets[name].get("digest") != "sha256:" + digest:
            raise ValueError("Release asset digest differs: " + name)
    urls = {item["filename"]: item for item in pypi["urls"]}
    if len(urls) != len(pypi["urls"]) or set(urls) != expected or set(downloads) != expected:
        raise ValueError("PyPI file set differs")
    for name in expected:
        item = urls[name]
        if (
            item.get("yanked")
            or item["digests"]["sha256"] != records[name]
            or sha256(downloads[name]) != records[name]
        ):
            raise ValueError("Published package digest differs: " + name)
    return {name: records[name] for name in sorted(expected)}


PUBLIC_HOSTS = {
    "pypi.org",
    "files.pythonhosted.org",
    "api.github.com",
    "github.com",
    "registry.modelcontextprotocol.io",
    "release-assets.githubusercontent.com",
    "objects.githubusercontent.com",
}


def public_origin(url: str):
    parsed = urlsplit(url)
    if (
        parsed.scheme != "https"
        or parsed.hostname not in PUBLIC_HOSTS
        or parsed.username
        or parsed.password
        or parsed.port not in {None, 443}
    ):
        raise ValueError("Unexpected public metadata/download origin")
    return parsed


class PublicRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        target = public_origin(newurl)
        redirected = super().redirect_request(req, fp, code, msg, headers, newurl)
        if redirected is not None and target.hostname != urlsplit(req.full_url).hostname:
            redirected.remove_header("Authorization")
        return redirected


def fetch(url: str, limit: int = 4 * 1024 * 1024) -> bytes:
    parsed = public_origin(url)
    headers = {"User-Agent": "apsa-publication-verification"}
    if parsed.hostname == "api.github.com" and os.environ.get("GH_TOKEN"):
        headers["Authorization"] = "Bearer " + os.environ["GH_TOKEN"]
    with build_opener(PublicRedirect()).open(Request(url, headers=headers), timeout=45) as response:
        data = response.read(limit + 1)
    if len(data) > limit:
        raise ValueError("Public response exceeds verification budget")
    return data


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", required=True)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    # Network execution belongs only to a newly provisioned hosted runner.
    if os.environ.get("GITHUB_ACTIONS") != "true" or not args.out.resolve().is_relative_to(
        Path(os.environ["RUNNER_TEMP"]).resolve()
    ):
        raise ValueError("Publication verification requires a fresh hosted runner temporary directory")
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", args.version) or not re.fullmatch(
        r"[a-f0-9]{40}", args.source_sha
    ):
        raise ValueError("Invalid version/source identity")
    args.out.mkdir(parents=True, exist_ok=False)
    endpoints = {
        "pypi": f"https://pypi.org/pypi/apsa/{args.version}/json",
        "release": f"https://api.github.com/repos/{REPOSITORY}/releases/tags/v{args.version}",
        "tag": f"https://api.github.com/repos/{REPOSITORY}/git/ref/tags/v{args.version}",
        "registry": f"https://registry.modelcontextprotocol.io/v0.1/servers/io.github.ictechgy%2Fapsa/versions/{args.version}",
    }
    observations = {}
    for name, url in endpoints.items():
        for attempt in range(1, 11):
            try:
                raw = fetch(url)
                observations[name] = json.loads(raw)
                (args.out / (name + ".json")).write_bytes(raw)
                break
            except (HTTPError, URLError, OSError, HTTPException, json.JSONDecodeError) as error:
                (args.out / f"{name}-attempt-{attempt}.json").write_text(
                    json.dumps(
                        {"error_type": type(error).__name__, "http_status": getattr(error, "code", None)}
                    )
                    + "\n"
                )
                if attempt == 10:
                    raise
                time.sleep(20)
    validate_identity(args.version, args.source_sha, **observations)
    assets = observations["release"]["assets"]
    checksums = next(item for item in assets if item["name"] == "SHA256SUMS")
    sums = fetch(checksums["browser_download_url"])
    (args.out / "SHA256SUMS").write_bytes(sums)
    downloads = {}
    for item in observations["pypi"]["urls"]:
        name = item["filename"]
        if name not in {f"apsa-{args.version}-py3-none-any.whl", f"apsa-{args.version}.tar.gz"}:
            raise ValueError("Unexpected PyPI filename")
        if urlsplit(item["url"]).hostname != "files.pythonhosted.org":
            raise ValueError("Unexpected PyPI file origin")
        downloads[name] = fetch(item["url"], 64 * 1024 * 1024)
    digests = validate_artifacts(args.version, observations["pypi"], observations["release"], sums, downloads)
    for name, data in downloads.items():
        (args.out / name).write_bytes(data)
    result = {
        "version": args.version,
        "source_sha": args.source_sha,
        "packages": digests,
        "public_identity_and_bytes_verified": True,
    }
    (args.out / "verification.json").write_text(json.dumps(result, sort_keys=True, indent=2) + "\n")
    print("APSA_PUBLICATION=" + json.dumps(result, sort_keys=True), flush=True)


if __name__ == "__main__":
    main()
