"""Publication verification rejects mismatched synthetic public metadata."""

import copy

import pytest

from scripts.verify_publication import OFFICIAL_META, sha256, validate_artifacts, validate_identity


def public_fixture():
    version, source = "1.6.0", "a" * 40
    names = [f"apsa-{version}-py3-none-any.whl", f"apsa-{version}.tar.gz"]
    downloads = {name: ("NEW synthetic bytes: " + name).encode() for name in names}
    sums = "".join(sha256(data) + "  ./" + name + "\n" for name, data in downloads.items())
    for name in (f"apsa-{version}-verified-bundle.tar.gz", "release-manifest.json"):
        sums += "b" * 64 + "  " + name + "\n"
    pypi = {
        "info": {"name": "apsa", "version": version},
        "urls": [
            {"filename": name, "digests": {"sha256": sha256(data)}, "yanked": False}
            for name, data in downloads.items()
        ],
    }
    assets = [
        {"name": line.split("  ")[1].removeprefix("./"), "digest": "sha256:" + line.split("  ")[0]}
        for line in sums.splitlines()
    ]
    assets.append({"name": "SHA256SUMS", "digest": "sha256:" + sha256(sums.encode())})
    release = {"tag_name": "v" + version, "draft": False, "prerelease": False, "assets": assets}
    tag = {
        "ref": "refs/tags/v" + version,
        "object": {"type": "commit", "sha": source, "url": "https://example.invalid/new"},
    }
    registry = {
        "server": {
            "name": "io.github.ictechgy/apsa",
            "version": version,
            "packages": [{"registryType": "pypi", "identifier": "apsa", "version": version}],
        },
        "_meta": {OFFICIAL_META: {"status": "active"}},
    }
    return version, source, pypi, release, tag, registry, sums.encode(), downloads


def test_publication_binds_version_source_all_public_package_bytes():
    version, source, pypi, release, tag, registry, sums, downloads = public_fixture()
    validate_identity(version, source, pypi, release, tag, registry)
    assert validate_artifacts(version, pypi, release, sums, downloads) == {
        name: sha256(data) for name, data in downloads.items()
    }


@pytest.mark.parametrize("mutation", ["version", "source", "draft", "registry", "package", "inactive"])
def test_publication_rejects_mismatched_identity(mutation):
    version, source, pypi, release, tag, registry, _, _ = public_fixture()
    if mutation == "version":
        pypi["info"]["version"] = "1.5.1"
    elif mutation == "source":
        tag["object"]["sha"] = "c" * 40
    elif mutation == "draft":
        release["draft"] = True
    elif mutation == "registry":
        registry["server"]["version"] = "1.5.1"
    elif mutation == "package":
        registry["server"]["packages"][0]["version"] = "1.5.1"
    else:
        registry["_meta"][OFFICIAL_META]["status"] = "deprecated"
    with pytest.raises(ValueError):
        validate_identity(version, source, pypi, release, tag, registry)


@pytest.mark.parametrize(
    "mutation",
    ["bytes", "pypi-hash", "asset-hash", "sums-hash", "duplicate", "extra", "missing", "yanked", "traversal"],
)
def test_publication_rejects_missing_conflicting_or_changed_bytes(mutation):
    version, _, pypi, release, _, _, sums, downloads = public_fixture()
    if mutation == "bytes":
        downloads[next(iter(downloads))] += b"changed"
    elif mutation == "pypi-hash":
        pypi["urls"][0]["digests"]["sha256"] = "c" * 64
    elif mutation == "asset-hash":
        release["assets"][0]["digest"] = "sha256:" + "c" * 64
    elif mutation == "sums-hash":
        release["assets"][-1]["digest"] = "sha256:" + "c" * 64
    elif mutation == "duplicate":
        release["assets"].append(copy.deepcopy(release["assets"][0]))
    elif mutation == "extra":
        pypi["urls"].append({"filename": "foreign.whl"})
    elif mutation == "missing":
        del downloads[next(iter(downloads))]
    elif mutation == "yanked":
        pypi["urls"][0]["yanked"] = True
    else:
        sums = sums.replace(b"./apsa-", b"../apsa-", 1)
    with pytest.raises(ValueError):
        validate_artifacts(version, pypi, release, sums, downloads)
