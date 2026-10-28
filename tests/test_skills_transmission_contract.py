"""Release disclosures follow callable budgets; all IO uses fresh synthetic stores."""

from __future__ import annotations

import hashlib
import inspect
import json
import re
from pathlib import Path

import httpx
import pytest

from mobile_audit.cli import UsageError, parser
from mobile_audit.intel import query_dependencies
from mobile_audit.skills import install_skill, skill_status
from mobile_audit.store import Store

ROOT = Path(__file__).parents[1]
PRIOR_DISCLOSURE = "CLI analysis runs locally and does not upload app source or builds. Online OSV queries send dependency names and versions, including Gradle catalog aliases used in shipped configurations and release-runtime lockfile coordinates from any module (private group IDs too). One online run queries at most 100 packages: those without a recent OSV result first, declared packages and non-Gradle manifests before transitive Gradle lockfile coordinates. The rest without such a result stay not-run and the audit incomplete; repeated runs advance through them. MCP context sends finding metadata to the invoking client, which may forward it to a hosted model. Follow the user's model/data policy; local analysis is separate from whether the product is open source."
PRIOR_HASHES = {
    "apsa": "49cf257c114fa2f65fbf09bcbdec93e702799295e8d1cf7bae2fb5e2e7a138ca",
    "mobile-audit": "ae4b28774e41b6ca9c022627e803ff54490d2384b66fb7fc72222d8f85190e8f",
    "quaygate": "97b87a571070eaf12782573d46a46588e29cb1b58dcd2e7e4b8b3a47fce210c2",
}


@pytest.mark.parametrize(
    "relative",
    ["README.md", "README.ko.md", *[f".agents/skills/{name}/SKILL.md" for name in PRIOR_HASHES]],
)
def test_disclosed_default_query_budgets_match_callable_contract(relative):
    text = " ".join((ROOT / relative).read_text().split())
    pattern = (
        r"기본 온라인 한도는 패키지 (\d+)개, 배치당 (\d+)개, OSV 요청 (\d+)회"
        if relative.endswith(".ko.md")
        else r"Default online budgets are (\d+) packages, (\d+) packages per batch and (\d+) OSV requests"
    )
    match = re.search(pattern, text)
    assert match is not None, relative
    parameters = inspect.signature(query_dependencies).parameters
    assert tuple(map(int, match.groups())) == tuple(
        parameters[key].default for key in ("max_packages", "batch_size", "max_requests")
    )
    assert parameters["query_mode"].default == parser().parse_args(["scan", "synthetic"]).osv_query_mode
    assert f"`{parameters['query_mode'].default}`" in text


def test_documented_auto_switch_matches_actual_transmission_routes(tmp_path):
    text = " ".join((ROOT / "README.md").read_text().split())
    match = re.search(r"at most (\d+) eligible unique package-version coordinates", text)
    assert match is not None
    threshold = int(match.group(1))
    assert 1 <= threshold <= 1000
    for count, endpoint in ((threshold, "/v1/query"), (threshold + 1, "/v1/querybatch")):
        paths = []

        def handler(request, paths=paths):
            paths.append(request.url.path)
            body = json.loads(request.content)
            return httpx.Response(
                200, json={"results": [{} for _ in body["queries"]]} if "queries" in body else {}
            )

        deps = [
            {
                "ecosystem": "Maven",
                "name": f"synthetic.public:lib{index}",
                "version": "1",
                "confidence": "exact",
            }
            for index in range(count)
        ]
        store = Store(tmp_path / str(count))
        try:
            with httpx.Client(transport=httpx.MockTransport(handler)) as client:
                _, errors = query_dependencies(store, deps, client)
            assert errors == []
            assert paths and set(paths) == {endpoint}
        finally:
            store.close()


def test_documented_scan_controls_parse_and_are_not_claimed_for_watch():
    for relative in ("README.md", "README.ko.md"):
        text = (ROOT / relative).read_text()
        for line in text.splitlines():
            if line.startswith("apsa scan ") and "--osv-" in line:
                import shlex

                args = parser().parse_args(shlex.split(line)[1:])
                assert args.command == "scan" and args.online is True
    args = parser().parse_args(
        [
            "scan",
            "synthetic",
            "--online",
            "--osv-query-mode",
            "batch",
            "--osv-exclude-ecosystem",
            "npm",
            "--osv-exclude-name",
            "private-*",
            "--osv-exclude-coordinate",
            "Maven:com.private:*",
        ]
    )
    assert args.osv_query_mode == "batch"
    assert (args.osv_exclude_ecosystem, args.osv_exclude_name, args.osv_exclude_coordinate) == (
        ["npm"],
        ["private-*"],
        ["Maven:com.private:*"],
    )
    for option, value in (("--osv-query-mode", "legacy"), ("--osv-exclude-name", "private-*")):
        with pytest.raises(UsageError):
            parser().parse_args(["intel", "watch", "--online", option, value])


@pytest.mark.parametrize("name", list(PRIOR_HASHES))
def test_captured_prior_skill_upgrades_without_overwriting_customizations(name, tmp_path):
    current = (ROOT / "src/mobile_audit/data/skills" / name / "SKILL.md").read_text()
    prior = (ROOT / "tests/fixtures/skills" / f"{name}-1.5.1.md").read_bytes()
    assert hashlib.sha256(prior).hexdigest() == PRIOR_HASHES[name]
    destination = tmp_path / name
    destination.mkdir()
    path = destination / "SKILL.md"
    path.write_bytes(prior)
    assert skill_status(name, destination) == "outdated"
    assert install_skill(name, destination)["status"] == "installed"
    assert path.read_text() == current
    path.write_bytes(prior + b"\nSynthetic user customization\n")
    with pytest.raises(FileExistsError):
        install_skill(name, destination)
    assert path.read_bytes().endswith(b"Synthetic user customization\n")
