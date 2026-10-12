"""Public dependency acquisition contract tested without HTTP or Docker access."""

from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import subprocess
import sys
import urllib.error
from email.message import Message
from pathlib import Path

import pytest

SYNTHETIC_BYTES = b"synthetic"
SYNTHETIC_DIGEST = "a" * 64


@pytest.fixture
def acquisition(monkeypatch):
    source = Path(__file__).parents[1] / "scripts/acquire_benchmark_dependencies.py"
    spec = importlib.util.spec_from_file_location("synthetic_benchmark_acquisition", source)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    monkeypatch.setattr(module, "JADX_BYTES", len(SYNTHETIC_BYTES))
    # Fail immediately if a test accidentally reaches either real transport.
    monkeypatch.setattr(
        module.urllib.request, "build_opener", lambda *_args, **_kwargs: pytest.fail("unexpected real HTTP")
    )
    monkeypatch.setattr(
        module.subprocess, "run", lambda *_args, **_kwargs: pytest.fail("unexpected real Docker")
    )
    return module


class SyntheticResponse(io.BytesIO):
    status = 200

    def __init__(self, data: bytes, url: str):
        super().__init__(data)
        self.url = url

    def geturl(self) -> str:
        return self.url


class SyntheticOpener:
    def __init__(self, acquisition, *, payloads=None, sidecar=None, metadata=None):
        self.acquisition = acquisition
        self.payloads = iter(payloads if payloads is not None else [SYNTHETIC_BYTES] * 2)
        self.sidecar = sidecar
        self.metadata = metadata

    def open(self, request, timeout):
        assert timeout > 0
        url = request if isinstance(request, str) else request.full_url
        if url == self.acquisition.JADX_URL:
            return SyntheticResponse(
                next(self.payloads),
                "https://release-assets.githubusercontent.com/github-production-release-asset/"
                "synthetic?token=synthetic-secret",
            )
        if url == self.acquisition.JADX_METADATA_URL and self.metadata is not None:
            return SyntheticResponse(json.dumps(self.metadata).encode(), url)
        if self.sidecar is not None and url.endswith(".sha256"):
            return SyntheticResponse(self.sidecar, url)
        raise urllib.error.HTTPError(url, 404, "synthetic absent", Message(), None)


def test_redirect_origin_allowlist(acquisition):
    assert acquisition.permitted_url(acquisition.JADX_URL)
    assert acquisition.permitted_url(acquisition.JADX_METADATA_URL)
    assert acquisition.permitted_url(
        "https://release-assets.githubusercontent.com/github-production-release-asset/synthetic?token=synthetic"
    )
    for url in (
        "http://github.com/x",
        "https://github.com.evil/x",
        "https://user@github.com/x",
        "https://github.com:444/skylot/jadx/releases/download/v1.5.0/jadx-1.5.0.zip",
        acquisition.JADX_URL + "?token=synthetic",
        "https://github.com/other/project/releases/download/v1.5.0/jadx-1.5.0.zip",
        "https://release-assets.githubusercontent.com/other",
        "https://release-assets.githubusercontent.com.evil/github-production-release-asset/synthetic",
        "https://objects.githubusercontent.com/github-production-release-asset/synthetic#fragment",
    ):
        assert not acquisition.permitted_url(url), url
    with pytest.raises(acquisition.AcquisitionError, match="unexpected_public_redirect"):
        acquisition.PublicRedirects().redirect_request(None, None, 302, None, {}, "https://evil.test/x")


def test_two_equal_bounded_streams_produce_exact_byte_digests_without_signed_tokens(acquisition):
    expected = hashlib.sha256(SYNTHETIC_BYTES).hexdigest()
    result = acquisition.acquire_jadx(
        SyntheticOpener(acquisition), {"published_checksums": {"sha256": expected}}
    )
    assert len(result) == 2
    assert all(item["bytes"] == len(SYNTHETIC_BYTES) for item in result)
    assert all(item["sha256"] == expected for item in result)
    assert "synthetic-secret" not in json.dumps(result)
    assert all(item["final_host"] == "release-assets.githubusercontent.com" for item in result)


@pytest.mark.parametrize(
    ("payloads", "limit", "reason"),
    [
        ([SYNTHETIC_BYTES, b"different"], 128, "independent_acquisitions_disagree"),
        ([b"syntheti", SYNTHETIC_BYTES], 128, "unexpected_artifact_size"),
        ([SYNTHETIC_BYTES + b"extra", SYNTHETIC_BYTES], 128, "unexpected_artifact_size"),
        ([SYNTHETIC_BYTES, SYNTHETIC_BYTES], 8, "artifact_exceeds_bound"),
    ],
)
def test_mismatch_truncation_and_bound_fail(acquisition, monkeypatch, payloads, limit, reason):
    monkeypatch.setattr(acquisition, "JADX_LIMIT", limit)
    with pytest.raises(acquisition.AcquisitionError, match=reason):
        acquisition.acquire_jadx(SyntheticOpener(acquisition, payloads=payloads), {"published_checksums": {}})


def test_published_checksum_mismatch_fails(acquisition):
    with pytest.raises(acquisition.AcquisitionError, match="published_checksum_mismatch"):
        acquisition.acquire_jadx(
            SyntheticOpener(acquisition), {"published_checksums": {"sha256": SYNTHETIC_DIGEST}}
        )


def test_null_release_digest_and_missing_sidecars_never_invent_published_hash(acquisition):
    metadata = {
        "tag_name": "v1.5.0",
        "assets": [
            {
                "name": "jadx-1.5.0.zip",
                "browser_download_url": acquisition.JADX_URL,
                "size": len(SYNTHETIC_BYTES),
                "digest": None,
            }
        ],
    }
    result = acquisition.checksum_metadata(SyntheticOpener(acquisition, metadata=metadata))
    assert result["published_checksums"] == {}
    assert result["release_metadata"]["digest_status"] == "not_published"
    assert all(item["http_status"] == 404 for item in result["sidecars"].values())


@pytest.mark.parametrize("sidecar", [b"not a checksum", b"a" * 65, b"\xff"])
def test_malformed_published_sidecar_rejected(acquisition, sidecar):
    with pytest.raises(acquisition.AcquisitionError, match="malformed_published_checksum"):
        acquisition.checksum_metadata(SyntheticOpener(acquisition, sidecar=sidecar))


@pytest.mark.parametrize("kind", ["matching", "wrong-repository", "ambiguous-digest", "wrong-platform"])
def test_docker_pull_inspect_digest_platform_and_no_container_execution(
    acquisition, tmp_path, monkeypatch, kind
):
    calls = []
    expected_digest = "semgrep/semgrep@sha256:" + SYNTHETIC_DIGEST
    digests = [expected_digest]
    if kind == "wrong-repository":
        digests = ["other/project@sha256:" + SYNTHETIC_DIGEST]
    elif kind == "ambiguous-digest":
        digests.append("semgrep/semgrep@sha256:" + "b" * 64)

    def fake_run(argv, **kwargs):
        calls.append(argv)
        config = Path(kwargs["env"]["DOCKER_CONFIG"], "config.json")
        assert config.is_relative_to(tmp_path)
        assert json.loads(config.read_text()) == {"auths": {}}
        assert kwargs["check"] is True and kwargs["timeout"] > 0
        if argv[1] == "pull":
            assert argv == ["docker", "pull", "--platform", "linux/amd64", acquisition.SEMGREP_IMAGE]
            stdout = b""
        else:
            assert argv[:4] == ["docker", "image", "inspect", "--format"]
            if argv[4] == "{{json .RepoDigests}}":
                stdout = json.dumps(digests).encode()
            else:
                assert argv[4] == "{{.Os}}/{{.Architecture}}"
                stdout = b"linux/arm64\n" if kind == "wrong-platform" else b"linux/amd64\n"
        return subprocess.CompletedProcess(argv, 0, stdout=stdout)

    monkeypatch.setattr(acquisition.subprocess, "run", fake_run)
    if kind == "matching":
        result = acquisition.acquire_semgrep(tmp_path)
        assert result["repo_digest"] == "docker.io/" + expected_digest
        assert result["observed_platform"] == "linux/amd64"
        assert result["tool_execution"] is False and result["vendor_signature_verified"] is False
        assert "not-ZIP-file-SHA256" in result["digest_scope"]
    else:
        with pytest.raises(acquisition.AcquisitionError):
            acquisition.acquire_semgrep(tmp_path)
    assert calls and all(argv[1] in ("pull", "image") for argv in calls)
    assert all("run" not in argv and "login" not in argv for argv in calls)


def test_local_main_refuses_before_any_http_or_docker(acquisition, tmp_path, monkeypatch, capsys):
    work = tmp_path / "unused"
    monkeypatch.setenv("GITHUB_ACTIONS", "false")
    monkeypatch.setenv("RUNNER_ENVIRONMENT", "local")
    monkeypatch.setattr(sys, "argv", ["acquisition", "--work", str(work)])
    assert acquisition.main() == 1
    result = json.loads(capsys.readouterr().out.removeprefix(acquisition.MARKER))
    assert result["status"] == "failed" and result["reason"] == "hosted_ci_required"
    assert not work.exists()
