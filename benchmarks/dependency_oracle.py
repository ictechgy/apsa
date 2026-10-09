"""Capture Gradle's own resolution of pinned public apps; APSA is never imported here."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import stat
import tomllib
import urllib.request
import zipfile
from pathlib import Path, PurePosixPath

HERE = Path(__file__).resolve().parent
CASES = HERE / "dependency_cases.json"
MAX_ARCHIVE = 512 * 1024 * 1024
LINE = re.compile(r"([^:=\s]+):([^:=\s]+):([^:=\s]+)=([^=\s]*)")


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def case(identifier: str) -> dict:
    return next(c for c in json.loads(CASES.read_text())["cases"] if c["id"] == identifier)


def shipped(configuration: str) -> bool:
    # Defined by the evaluation, independently of the scanner's implementation:
    # release build-type runtime classpaths of any flavor. Benchmark and
    # non-minified baseline-profile variants are measurement builds, not shipped.
    return bool(
        re.fullmatch(r"(?:[a-z][A-Za-z0-9]*)?[Rr]eleaseRuntimeClasspath|runtimeClasspath", configuration)
        and not re.search(r"[Bb]enchmark|[Nn]onMinified", configuration)
    )


def fetch(spec: dict, out: Path) -> dict:
    url = f"https://codeload.github.com/{spec['repository']}/zip/{spec['commit']}"
    with urllib.request.urlopen(url, timeout=120) as response:
        raw = response.read(MAX_ARCHIVE + 1)
    if len(raw) > MAX_ARCHIVE:
        raise ValueError("Source archive exceeds the evaluation budget")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(raw)
    return {"url": url, "sha256": sha(raw), "bytes": len(raw)}


def extract(archive: Path, destination: Path) -> Path:
    """Extract regular members only; symlinks are skipped and listed, never followed."""
    with zipfile.ZipFile(archive) as bundle:
        roots = set()
        regular = []
        skipped = []
        for item in bundle.infolist():
            path = PurePosixPath(item.filename)
            if path.is_absolute() or ".." in path.parts:
                raise ValueError(f"Unsafe archive member: {item.filename}")
            roots.add(path.parts[0])
            if stat.S_ISLNK(item.external_attr >> 16):
                skipped.append(item.filename)
            else:
                regular.append(item)
        if len(roots) != 1:
            raise ValueError("Expected one top-level source directory")
        bundle.extractall(destination, members=regular)
    root = destination / roots.pop()
    (destination / "skipped-symlinks.json").write_text(json.dumps(sorted(skipped), indent=2) + "\n")
    gradlew = root / "gradlew"
    if gradlew.is_file():
        gradlew.chmod(0o755)
    return root


def oracle(spec: dict, source: Path, lockfile: Path, archive: dict) -> dict:
    raw = lockfile.read_bytes()
    resolved: dict[str, dict[str, list[str]]] = {}
    for line in raw.decode().splitlines():
        if not line or line.startswith("#") or line.startswith("empty="):
            continue
        match = LINE.fullmatch(line.strip())
        if not match:
            raise ValueError(f"Unexpected Gradle lockfile line: {line[:120]}")
        group, artifact, version, configurations = match.groups()
        names = [c for c in configurations.split(",") if c]
        resolved.setdefault(f"{group}:{artifact}", {})[version] = names
    shipped_versions = {
        module: sorted(v for v, names in versions.items() if any(shipped(n) for n in names))
        for module, versions in resolved.items()
    }
    shipped_versions = {k: v for k, v in shipped_versions.items() if v}
    catalog = tomllib.loads((source / "gradle/libs.versions.toml").read_text())
    entries = []
    for alias, entry in sorted(catalog.get("libraries", {}).items()):
        if isinstance(entry, str):
            parts = entry.split(":")
            entry = {key: part for key, part in zip(("group", "name", "version"), parts, strict=False)}
        module = entry.get("module") or f"{entry.get('group', '')}:{entry.get('name', '')}"
        version = entry.get("version", "")
        if isinstance(version, dict):
            version = catalog.get("versions", {}).get(version.get("ref"), version)
        entries.append(
            {
                "alias": alias,
                "module": module,
                "catalog_version": version if isinstance(version, str) else None,
                "shipped": module in shipped_versions,
                "shipped_versions": shipped_versions.get(module, []),
                "in_any_app_configuration": module in resolved,
            }
        )
    configurations = sorted(
        {n for versions in resolved.values() for names in versions.values() for n in names}
    )
    return {
        "id": spec["id"],
        "repository": spec["repository"],
        "commit": spec["commit"],
        "module": spec["module"],
        "archive": archive,
        "lockfile_sha256": sha(raw),
        "release_runtime_configurations": [c for c in configurations if shipped(c)],
        "shipped_coordinates": [
            {"module": module, "versions": versions} for module, versions in sorted(shipped_versions.items())
        ],
        "catalog_libraries": entries,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)
    prepare = commands.add_parser("prepare")
    prepare.add_argument("--case", required=True)
    prepare.add_argument("--work", type=Path, required=True)
    record = commands.add_parser("record")
    record.add_argument("--case", required=True)
    record.add_argument("--work", type=Path, required=True)
    args = parser.parse_args()
    spec = case(args.case)
    archive_path = args.work / f"{spec['id']}.zip"
    if args.command == "prepare":
        archive = fetch(spec, archive_path)
        (args.work / f"{spec['id']}.archive.json").write_text(json.dumps(archive, indent=2) + "\n")
        print(extract(archive_path, args.work / "source"))
        return
    archive = json.loads((args.work / f"{spec['id']}.archive.json").read_text())
    if sha(archive_path.read_bytes()) != archive["sha256"]:
        raise ValueError("Source archive changed after capture")
    source = next(p for p in (args.work / "source").iterdir() if p.is_dir())
    module_dir = source / spec["module"].strip(":").replace(":", "/")
    result = oracle(spec, source, module_dir / "gradle.lockfile", archive)
    (args.work / f"{spec['id']}.lockfile").write_bytes((module_dir / "gradle.lockfile").read_bytes())
    (args.work / f"{spec['id']}.oracle.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    shipped_aliases = sum(e["shipped"] for e in result["catalog_libraries"])
    print(
        json.dumps(
            {
                "id": spec["id"],
                "catalog_libraries": len(result["catalog_libraries"]),
                "shipped_catalog_libraries": shipped_aliases,
                "shipped_coordinates": len(result["shipped_coordinates"]),
                "release_runtime_configurations": result["release_runtime_configurations"],
            }
        )
    )


if __name__ == "__main__":
    main()
