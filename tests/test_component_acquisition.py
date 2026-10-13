"""Acquisition controls use fresh synthetic bytes and mocked public responses."""

import hashlib
import io
import tarfile
from http.client import HTTPMessage
from urllib.request import Request

import pytest

from scripts import acquire_component_tools as acquisition


def archive(path, *, name="gitleaks", kind=tarfile.REGTYPE, duplicate=False):
    with tarfile.open(path, "w:gz") as output:
        for _ in range(2 if duplicate else 1):
            member = tarfile.TarInfo(name)
            member.type = kind
            member.size = 5 if kind == tarfile.REGTYPE else 0
            member.linkname = "/outside"
            output.addfile(member, io.BytesIO(b"\x7fELFx") if member.size else None)


@pytest.mark.parametrize(
    "url",
    [
        "http://github.com/gitleaks/gitleaks/releases/download/v8.30.1/file",
        "https://github.com/other/other/releases/download/file",
        "https://192.0.2.1/",
        "https://evil.example/",
        "https://user@release-assets.githubusercontent.com/github-production-release-asset-x",
        "https://release-assets.githubusercontent.com:444/github-production-release-asset-x",
    ],
)
def test_rejects_nonpublic_or_unexpected_sources(url):
    assert not acquisition.permitted_url(url)


def test_exact_public_sources_and_bounded_redirects():
    assert all(
        acquisition.permitted_url(p[k]) for p in acquisition.PINS.values() for k in ("url", "checksums")
    )
    assert acquisition.permitted_url(
        "https://release-assets.githubusercontent.com/github-production-release-asset-x?signature=public"
    )
    with pytest.raises(acquisition.AcquisitionError, match="unexpected_public_redirect"):
        acquisition.PublicRedirects().redirect_request(
            Request(acquisition.PINS["gitleaks"]["url"]),
            io.BytesIO(),
            302,
            "redirect",
            HTTPMessage(),
            "https://192.0.2.1/",
        )


@pytest.mark.parametrize("text", ["", "wrong file", "a" * 64 + "  other", ("a" * 64 + "  target\n") * 2])
def test_checksum_requires_one_exact_record(text):
    with pytest.raises(acquisition.AcquisitionError):
        acquisition.published_checksum(text, "target", "a" * 64)


def test_checksum_and_regular_extraction(tmp_path):
    acquisition.published_checksum("a" * 64 + " *target\n", "target", "a" * 64)
    source, target = tmp_path / "source.tgz", tmp_path / "new-tool"
    archive(source)
    result = acquisition.extract_executable(source, target, "gitleaks")
    assert target.read_bytes() == b"\x7fELFx"
    assert result == hashlib.sha256(target.read_bytes()).hexdigest()


@pytest.mark.parametrize(
    "options",
    [
        {"name": "../gitleaks"},
        {"kind": tarfile.SYMTYPE},
        {"kind": tarfile.LNKTYPE},
        {"duplicate": True},
    ],
)
def test_only_one_exact_regular_archive_member(tmp_path, options):
    source, target = tmp_path / "source.tgz", tmp_path / "new-tool"
    archive(source, **options)
    with pytest.raises(acquisition.AcquisitionError, match="invalid_executable_member"):
        acquisition.extract_executable(source, target, "gitleaks")
    assert not target.exists()


def test_real_byte_mutation_rejected_without_execution(tmp_path):
    source = tmp_path / "synthetic.download"
    source.write_bytes(b"new-synthetic-pinned-bytes")
    expected = hashlib.sha256(source.read_bytes()).hexdigest()
    result = acquisition.mutation_control(source, expected)
    assert result["reason"] == "sha256_mismatch"
    assert source.read_bytes() == b"new-synthetic-pinned-bytes"
    assert not source.with_name(source.name + ".mutated").exists()


class Response(io.BytesIO):
    status = 200

    def geturl(self):
        return acquisition.PINS["gitleaks"]["url"]


class Opener:
    def open(self, request, timeout):
        return Response(b"123456")


def test_download_limit_and_no_overwrite(tmp_path):
    url = acquisition.PINS["gitleaks"]["url"]
    with pytest.raises(acquisition.AcquisitionError, match="download_size_limit"):
        acquisition.download(Opener(), url, tmp_path / "bounded", 5)
    existing = tmp_path / "owned"
    existing.write_bytes(b"original")
    with pytest.raises(acquisition.AcquisitionError):
        acquisition.download(Opener(), url, existing, 10)
    assert existing.read_bytes() == b"original"


def test_local_main_refuses_network(monkeypatch, tmp_path, capsys):
    monkeypatch.delenv("GITHUB_ACTIONS", raising=False)
    assert acquisition.main(["--out", str(tmp_path / "new")]) == 1
    assert "hosted_ci_only" in capsys.readouterr().out
    assert not (tmp_path / "new").exists()


@pytest.mark.parametrize("mode", ["mutated", "wrong-size"])
def test_acquisition_never_extracts_unverified_bytes(monkeypatch, tmp_path, mode):
    expected_bytes = b"new-ELF-control"
    digest = hashlib.sha256(expected_bytes).hexdigest()
    pin = {
        **acquisition.PINS["gitleaks"],
        "sha256": digest,
        "bytes": len(expected_bytes) + (mode == "wrong-size"),
    }
    monkeypatch.setattr(acquisition, "PINS", {"gitleaks": pin})

    def fake_download(opener, url, destination, limit):
        if url == pin["checksums"]:
            content = (digest + "  " + pin["url"].rsplit("/", 1)[1] + "\n").encode()
        else:
            content = b"X" + expected_bytes[1:] if mode == "mutated" else expected_bytes
        destination.write_bytes(content)
        return hashlib.sha256(content).hexdigest()

    def forbidden_extract(*args):
        pytest.fail("unverified bytes reached extraction")

    monkeypatch.setattr(acquisition, "download", fake_download)
    monkeypatch.setattr(acquisition, "extract_executable", forbidden_extract)
    with pytest.raises(acquisition.AcquisitionError, match="pinned_artifact_mismatch"):
        acquisition.acquire(tmp_path / "new", object(), "a" * 40)
    assert not (tmp_path / "new/gitleaks").exists()
