from __future__ import annotations

import hashlib
import json
import zipfile

import httpx
import pytest

from benchmarks.real_world import (
    OSVTransport,
    config_result,
    cve_score,
    dependency_result,
    download,
    load_spec,
    path_matches,
    sha,
    source_archive,
)


def public_archive(tmp_path, path="repo/app/Info.plist", raw=b"public synthetic source"):
    archive = tmp_path / "upstream.zip"
    with zipfile.ZipFile(archive, "w") as value:
        value.writestr(path, raw)
        value.writestr("repo/image.png", b"new synthetic non-source bytes")
    blob = hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()
    return archive, {"config_label": {"path": "app/Info.plist", "git_blob": blob}, "dependencies": []}


def test_source_archive_preserves_source_and_discards_non_source(tmp_path):
    upstream, app = public_archive(tmp_path)
    output = tmp_path / "source.zip"
    result = source_archive(upstream, output, app)
    with zipfile.ZipFile(output) as archive:
        assert archive.namelist() == ["app/Info.plist"]
        assert archive.read("app/Info.plist") == b"public synthetic source"
    assert result["sha256"] == sha(output.read_bytes())
    assert result["source_entries"] == 1


@pytest.mark.parametrize("path", ["repo/../Info.plist", "/repo/Info.plist", "repo\\Info.plist"])
def test_source_archive_rejects_unsafe_paths(tmp_path, path):
    upstream, app = public_archive(tmp_path, path)
    with pytest.raises(ValueError):
        source_archive(upstream, tmp_path / "source.zip", app)


def test_source_archive_rejects_changed_primary_anchor(tmp_path):
    upstream, app = public_archive(tmp_path)
    app["config_label"]["git_blob"] = "0" * 40
    with pytest.raises(ValueError, match="anchors"):
        source_archive(upstream, tmp_path / "source.zip", app)


def test_source_archive_symlink_cannot_substitute_primary_configuration(tmp_path):
    upstream, app = public_archive(tmp_path)
    with zipfile.ZipFile(upstream, "w") as archive:
        entry = zipfile.ZipInfo("repo/app/Info.plist")
        entry.external_attr = 0o120777 << 16
        archive.writestr(entry, b"/private/example")
    with pytest.raises(ValueError, match="anchors"):
        source_archive(upstream, tmp_path / "source.zip", app)


@pytest.mark.parametrize("url", ["http://github.com/repo", "https://127.0.0.1/", "https://example.org/"])
def test_public_download_rejects_unapproved_origins_without_request(tmp_path, url):
    def handler(request):
        pytest.fail("Unapproved origin was requested")

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        with pytest.raises(ValueError, match="origin"):
            download(client, url, tmp_path / "download", 20)


def test_public_download_rejects_redirect_to_local_service(tmp_path):
    def handler(request):
        assert request.url.host == "github.com"
        return httpx.Response(302, headers={"Location": "http://localhost:8000/"})

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        with pytest.raises(ValueError, match="origin"):
            download(client, "https://github.com/source", tmp_path / "download", 20)


def test_public_download_byte_budget_and_digest(tmp_path):
    with httpx.Client(
        transport=httpx.MockTransport(lambda r: httpx.Response(200, content=b"12345"))
    ) as client:
        with pytest.raises(ValueError, match="limit"):
            download(client, "https://github.com/source", tmp_path / "too-large", 4)
        result = download(client, "https://github.com/source", tmp_path / "source", 5)
    assert result["sha256"] == sha(b"12345")


def case(expected="affected"):
    return {
        "id": "new-synthetic",
        "cve": "CVE-2022-25647",
        "expected": expected,
        "dependency": {
            "name": "com.google.code.gson:gson",
            "version": "2.8.8",
            "ecosystem": "Maven",
            "confidence": "exact",
            "path": "new-synthetic/SBOM",
        },
    }


def make_capture(tmp_path, response):
    capture = OSVTransport(tmp_path / "capture", True)
    assert capture.network is not None
    capture.network.close()
    capture.network = httpx.Client(
        transport=httpx.MockTransport(lambda r: httpx.Response(200, json=response))
    )
    return capture


def test_actual_intelligence_functions_replay_frozen_response_and_retain_scope(tmp_path):
    vuln = {
        "id": "GHSA-4jrv-ppp4-jm57",
        "aliases": ["CVE-2022-25647"],
        "summary": "public record",
        "affected": [],
        "references": [],
    }
    capture = make_capture(tmp_path, {"vulns": [vuln]})
    first = dependency_result(case(), capture, tmp_path / "first")
    capture.close()
    replay = OSVTransport(tmp_path / "capture", False)
    try:
        second = dependency_result(case(), replay, tmp_path / "second")
    finally:
        replay.close()
    assert first == second
    assert first["matched"] is True
    assert first["statuses"] == ["version-affected"]
    assert first["reachability"] == ["unknown"]


def test_withdrawn_cve_is_not_a_matching_finding(tmp_path):
    capture = make_capture(
        tmp_path,
        {
            "vulns": [
                {"id": "GHSA-public", "aliases": ["CVE-2022-25647"], "withdrawn": "2025-01-01T00:00:00Z"}
            ]
        },
    )
    try:
        assert not dependency_result(case(), capture, tmp_path / "state")["matched"]
    finally:
        capture.close()


def test_unknown_dependency_abstains_without_network(tmp_path):
    capture = make_capture(tmp_path, {})
    item = case("unknown")
    item["dependency"]["confidence"] = "unknown"
    try:
        result = dependency_result(item, capture, tmp_path / "state")
        assert result["state"] == "abstained" and not result["matched"]
        assert not capture.records
    finally:
        capture.close()


def test_tampered_osv_bytes_are_a_failure_not_a_clean_negative(tmp_path):
    capture = make_capture(tmp_path, {})
    dependency_result(case(), capture, tmp_path / "first")
    capture.close()
    manifest = json.loads((tmp_path / "capture/manifest.json").read_text())
    key = manifest["responses"][0]["key"]
    (tmp_path / "capture" / f"{key}.json").write_text('{"vulns":[]}')
    replay = OSVTransport(tmp_path / "capture", False)
    try:
        result = dependency_result(case(), replay, tmp_path / "second")
    finally:
        replay.close()
    assert result["state"] == "failed"


def test_missing_osv_request_is_a_failure(tmp_path):
    capture = make_capture(tmp_path, {})
    capture.close()
    replay = OSVTransport(tmp_path / "capture", False)
    try:
        result = dependency_result(case(), replay, tmp_path / "state")
    finally:
        replay.close()
    assert result["state"] == "failed"


def test_cve_scoring_does_not_turn_failures_or_unknowns_into_true_negatives():
    rows = [
        {"expected": "affected", "result": {"state": "completed", "matched": True}},
        {"expected": "affected", "result": {"state": "failed", "matched": False}},
        {"expected": "unaffected", "result": {"state": "failed", "matched": False}},
        {"expected": "unknown", "result": {"state": "abstained", "matched": False}},
    ]
    score = cve_score(rows)
    assert score["tp"] == 1 and score["tn"] == 0
    assert score["end_to_end_recall"] == 0.5
    assert score["completed_recall"] == 1
    assert score["unknown"] == score["correct_abstentions"] == 1
    assert cve_score([])["precision"] is None


def test_selected_configuration_must_be_covered_even_when_no_alert():
    report = {"inventory": {"ios_config": []}, "findings": []}
    result = config_result(report, {"path": "app/Info.plist", "rule": "IOS-ATS", "expected": False})
    assert not result["covered"] and not result["correct"]


def test_path_suffix_does_not_mix_different_modules():
    assert path_matches("prefix/app/Info.plist", "app/Info.plist")
    assert not path_matches("otherapp/Info.plist", "app/Info.plist")


def test_frozen_spec_keeps_positive_negative_and_unknown_groups_separate():
    spec = load_spec()
    assert len(spec["apps"]) == 6
    assert sum(c["expected"] == "affected" for c in spec["dependency_cases"]) == 8
    assert sum(c["expected"] == "unaffected" for c in spec["dependency_cases"]) == 19
    assert sum(c["expected"] == "unknown" for c in spec["dependency_cases"]) == 5
