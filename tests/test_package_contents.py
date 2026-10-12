"""Verify new synthetic distributions without opening retained archives or private source."""

from __future__ import annotations

import base64
import csv
import hashlib
import io
import tarfile
import zipfile

import pytest

from scripts import release

NAMESPACE = "synthetic_release-1.0"
SOURCE_FILES = {
    "pyproject.toml": b"""[project]\nname="synthetic-release"\nversion="1.0"\n[project.scripts]\nsynthetic="synthetic_pkg:main"\n[tool.hatch.build.targets.wheel]\npackages=["src/synthetic_pkg"]\n[tool.hatch.build.targets.sdist]\ninclude=["/src", "/tests", "/pyproject.toml", "/LICENSE"]\nexclude=["**/__pycache__", "**/*.pyc"]\n""",
    "src/synthetic_pkg/__init__.py": b"def main(): pass\n",
    "src/synthetic_pkg/acquisition.py": b"def acquire(source): return source\n",
    "src/synthetic_pkg/data/canary.json": b'{"public_canary": true}\n',
    "src/synthetic_pkg/data/canary.svg": b'<svg xmlns="http://www.w3.org/2000/svg"/>\n',
    "tests/support/runtime_compiled.py": b"# New source-only test helper, excluded from wheel\n",
    "LICENSE": b"New synthetic public license\n",
}


@pytest.fixture
def clean_package(tmp_path, monkeypatch):
    stage = tmp_path / "new-clean-stage"
    for name, raw in SOURCE_FILES.items():
        path = stage / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
    monkeypatch.setattr(
        release,
        "PUBLIC_RESOURCES",
        frozenset(
            {
                "src/synthetic_pkg/data/canary.json",
                "src/synthetic_pkg/data/canary.svg",
            }
        ),
    )
    inputs = {name: hashlib.sha256(raw).hexdigest() for name, raw in SOURCE_FILES.items()}
    return stage, inputs


def wheel_payload():
    payload = {
        name.removeprefix("src/"): raw
        for name, raw in SOURCE_FILES.items()
        if name.startswith("src/synthetic_pkg/")
    }
    payload.update(
        {
            NAMESPACE
            + ".dist-info/METADATA": b"Metadata-Version: 2.4\nName: synthetic-release\nVersion: 1.0\n",
            NAMESPACE + ".dist-info/WHEEL": b"Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: py3-none-any\n",
            NAMESPACE + ".dist-info/entry_points.txt": b"[console_scripts]\nsynthetic = synthetic_pkg:main\n",
            NAMESPACE + ".dist-info/licenses/LICENSE": SOURCE_FILES["LICENSE"],
        }
    )
    return payload


def write_wheel(path, payload=None, *, edit_record=None, duplicate=None, symlink=None):
    payload = wheel_payload() if payload is None else payload
    record = NAMESPACE + ".dist-info/RECORD"
    rows = [
        [
            name,
            "sha256=" + base64.urlsafe_b64encode(hashlib.sha256(raw).digest()).decode().rstrip("="),
            str(len(raw)),
        ]
        for name, raw in sorted(payload.items())
    ]
    rows.append([record, "", ""])
    if edit_record:
        edit_record(rows)
    output = io.StringIO()
    csv.writer(output, lineterminator="\n").writerows(rows)
    with zipfile.ZipFile(path, "x", zipfile.ZIP_DEFLATED) as archive:
        for name, raw in payload.items():
            if name == symlink:
                info = zipfile.ZipInfo(name)
                info.create_system = 3
                info.external_attr = 0o120777 << 16
                archive.writestr(info, raw)
            else:
                archive.writestr(name, raw)
        archive.writestr(record, output.getvalue())
        if duplicate:
            with pytest.warns(UserWarning, match="Duplicate name"):
                archive.writestr(duplicate, payload[duplicate])
    return path


def write_sdist(path, payload=None, *, symlink=False):
    payload = (
        {**SOURCE_FILES, "PKG-INFO": b"Name: synthetic-release\nVersion: 1.0\n"}
        if payload is None
        else payload
    )
    with tarfile.open(path, "x:gz") as archive:
        for name, raw in payload.items():
            item = tarfile.TarInfo(NAMESPACE + "/" + name)
            item.size = len(raw)
            archive.addfile(item, io.BytesIO(raw))
        if symlink:
            item = tarfile.TarInfo(NAMESPACE + "/linked-source")
            item.type = tarfile.SYMTYPE
            item.linkname = "/new-synthetic-outside"
            archive.addfile(item)
    return path


@pytest.mark.parametrize("kind", ["wheel", "sdist"])
def test_new_distribution_matches_explicit_stage_and_declarations(tmp_path, clean_package, kind):
    stage, inputs = clean_package
    artifact = write_wheel(tmp_path / "new.whl") if kind == "wheel" else write_sdist(tmp_path / "new.tar.gz")
    result = release.verify_package_contents(artifact, stage, inputs)
    assert result["state"] == "verified" and result["kind"] == kind
    assert result["record_verified"] is (kind == "wheel")
    assert result["artifact_sha256"] == release.digest(artifact)


@pytest.mark.parametrize(
    "member",
    ["synthetic_pkg/acquisition.py", "synthetic_pkg/data/canary.json", "synthetic_pkg/data/canary.svg"],
)
def test_missing_known_package_module_or_resource_fails(tmp_path, clean_package, member):
    stage, inputs = clean_package
    payload = wheel_payload()
    del payload[member]
    with pytest.raises(ValueError, match="membership mismatch"):
        release.verify_package_contents(write_wheel(tmp_path / "new.whl", payload), stage, inputs)


def test_declared_public_resource_absent_from_stage_manifest_fails(tmp_path, clean_package):
    stage, inputs = clean_package
    del inputs["src/synthetic_pkg/data/canary.svg"]
    with pytest.raises(ValueError, match="resource is absent"):
        release.verify_package_contents(write_wheel(tmp_path / "new.whl"), stage, inputs)


@pytest.mark.parametrize(
    "extra",
    [
        "synthetic_pkg/runtime_compiled.py",
        "synthetic_pkg/runtime_synthetic.py",
        "synthetic_pkg/runtime_transport.py",
        "tests/support/runtime_compiled.py",
        NAMESPACE + ".dist-info/arbitrary-private-data.json",
        "synthetic_pkg/unexpected.py",
    ],
)
def test_extra_test_harness_or_undeclared_file_fails(tmp_path, clean_package, extra):
    stage, inputs = clean_package
    payload = wheel_payload()
    payload[extra] = b"# NEW synthetic unexpected content\n"
    with pytest.raises(ValueError, match="membership mismatch"):
        release.verify_package_contents(write_wheel(tmp_path / "new.whl", payload), stage, inputs)


def test_manifest_cannot_authorize_public_runtime_test_harness(tmp_path, clean_package):
    stage, inputs = clean_package
    inputs["src/synthetic_pkg/runtime_compiled.py"] = hashlib.sha256(b"new source").hexdigest()
    with pytest.raises(ValueError, match="Test acquisition harness"):
        release.verify_package_contents(write_wheel(tmp_path / "new.whl"), stage, inputs)


@pytest.mark.parametrize(
    "name",
    ["../escape.py", "/absolute.py", "C:/developer/escape.py", "a\\escape.py", "synthetic_pkg/./escape.py"],
)
def test_unsafe_new_archive_member_paths_fail(tmp_path, clean_package, name):
    stage, inputs = clean_package
    payload = wheel_payload()
    payload[name] = b"# new synthetic payload\n"
    with pytest.raises(ValueError, match="unsafe or noncanonical"):
        release.verify_package_contents(write_wheel(tmp_path / "new.whl", payload), stage, inputs)


def test_duplicate_wheel_member_and_symlink_fail(tmp_path, clean_package):
    stage, inputs = clean_package
    duplicate = write_wheel(tmp_path / "new-duplicate.whl", duplicate="synthetic_pkg/__init__.py")
    with pytest.raises(ValueError, match="duplicate members"):
        release.verify_package_contents(duplicate, stage, inputs)
    link = write_wheel(tmp_path / "new-linked.whl", symlink="synthetic_pkg/acquisition.py")
    with pytest.raises(ValueError, match="symlinks"):
        release.verify_package_contents(link, stage, inputs)


@pytest.mark.parametrize("failure", ["digest", "size", "missing", "duplicate", "own_digest", "unknown"])
def test_wheel_record_membership_and_integrity_failures(tmp_path, clean_package, failure):
    stage, inputs = clean_package

    def edit(rows):
        if failure == "digest":
            rows[0][1] = "sha256=corrupted"
        elif failure == "size":
            rows[0][2] = "999999"
        elif failure == "missing":
            rows.pop(0)
        elif failure == "duplicate":
            rows.append(rows[0])
        elif failure == "own_digest":
            rows[-1][1] = "sha256=forbidden"
        else:
            rows.append(["not-in-archive.py", "", ""])

    with pytest.raises(ValueError, match="Wheel RECORD"):
        release.verify_package_contents(write_wheel(tmp_path / "new.whl", edit_record=edit), stage, inputs)


def test_record_cannot_hide_changed_expected_source_bytes(tmp_path, clean_package):
    stage, inputs = clean_package
    payload = wheel_payload()
    payload["synthetic_pkg/acquisition.py"] += b"# NEW unauthorized change\n"
    with pytest.raises(ValueError, match="differs from the staged source manifest"):
        release.verify_package_contents(write_wheel(tmp_path / "new.whl", payload), stage, inputs)


@pytest.mark.parametrize(
    "home",
    [
        "/Users/synthetic_developer/SDK",
        "/home/synthetic_developer/sdk",
        r"C:\Users\synthetic_developer\SDK",
        "/Users/synthetic_developer",
        "/home/synthetic_developer",
        r"C:\Users\synthetic_developer",
    ],
)
def test_packaged_acquisition_code_cannot_contain_developer_home(tmp_path, clean_package, home):
    stage, inputs = clean_package
    payload = wheel_payload()
    raw = f"SDK = {home!r}\n".encode()
    payload["synthetic_pkg/acquisition.py"] = raw
    inputs["src/synthetic_pkg/acquisition.py"] = hashlib.sha256(raw).hexdigest()
    with pytest.raises(ValueError, match="absolute developer-home"):
        release.verify_package_contents(write_wheel(tmp_path / "new.whl", payload), stage, inputs)


def test_sdist_missing_source_extra_source_and_links_fail(tmp_path, clean_package):
    stage, inputs = clean_package
    payload = {**SOURCE_FILES, "PKG-INFO": b"Name: synthetic-release\nVersion: 1.0\n"}
    del payload["src/synthetic_pkg/acquisition.py"]
    with pytest.raises(ValueError, match="membership mismatch"):
        release.verify_package_contents(write_sdist(tmp_path / "new-missing.tar.gz", payload), stage, inputs)
    payload["src/synthetic_pkg/acquisition.py"] = SOURCE_FILES["src/synthetic_pkg/acquisition.py"]
    payload["undeclared.py"] = b"# new unexpected source\n"
    with pytest.raises(ValueError, match="membership mismatch"):
        release.verify_package_contents(write_sdist(tmp_path / "new-extra.tar.gz", payload), stage, inputs)
    with pytest.raises(ValueError, match="links and special files"):
        release.verify_package_contents(
            write_sdist(tmp_path / "new-link.tar.gz", symlink=True), stage, inputs
        )


def test_archive_expanded_byte_and_member_budgets(tmp_path, clean_package, monkeypatch):
    stage, inputs = clean_package
    artifact = write_wheel(tmp_path / "new.whl")
    monkeypatch.setattr(release, "MAX_PACKAGE_MEMBERS", 1)
    with pytest.raises(ValueError, match="member budget"):
        release.verify_package_contents(artifact, stage, inputs)
    monkeypatch.setattr(release, "MAX_PACKAGE_MEMBERS", 20000)
    monkeypatch.setattr(release, "MAX_PACKAGE_MEMBER_BYTES", 1)
    with pytest.raises(ValueError, match="expanded-byte budget"):
        release.verify_package_contents(artifact, stage, inputs)


def test_manifest_cannot_authorize_private_paths_before_archive_is_opened(
    tmp_path, clean_package, monkeypatch
):
    stage, inputs = clean_package
    inputs["tests/private/new-canary.py"] = hashlib.sha256(b"new private sentinel").hexdigest()

    def refuse_archive(*args, **kwargs):
        pytest.fail("Archive must remain unopened when the source manifest has a private path")

    monkeypatch.setattr(release, "_archive_payload", refuse_archive)
    with pytest.raises(ValueError, match="protected directory"):
        release.verify_package_contents(tmp_path / "new-absent.whl", stage, inputs)
