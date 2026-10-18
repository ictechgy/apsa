"""Build and smoke-test a local, hashed release bundle; never publish it."""

from __future__ import annotations

import argparse
import base64
import csv
import fnmatch
import hashlib
import importlib.util
import io
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import tomllib
import zipfile
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[1]
UV_VERSION = "0.12.1"
SOURCE_DATE_EPOCH = "315532800"
SOURCE_SMOKE_JAVA = (
    "import android.content.Intent; import android.webkit.WebView;\n"
    "class Main { void open(Intent incoming, WebView web) { web.loadUrl(incoming.getDataString()); } }\n"
)
# Exact wheel hashes from each distribution's official PyPI JSON file records.
BUILD_REQUIREMENTS = """hatchling==1.32.4 --hash=sha256:08ecf7548fb48205e7f213d70c71e67b8271b7242093dc3f1da578b42c734a2c
editables==0.6 --hash=sha256:d70e4698078a1d033e7786d9c64e5be070d058a67c21417024d38a58ac20aa43
packaging==26.3 --hash=sha256:d7193f7c8e4e93f444fde0262bf90af30e16fa0ad0ad44cb553c87339b23cd1c
pathspec==1.1.1 --hash=sha256:a00ce642f577bf7f473932318056212bc4f8bfdf53128c78bbd5af0b9b20b189
pluggy==1.6.0 --hash=sha256:e920276dd6813095e9377c0bc5566d94c932c33b27a3e3945d8389c374dd4746
tomlkit==0.15.1 --hash=sha256:177a05aece5a8ca5266fd3c448abb47b8d352f09d477d3ca8332db4d89b24304
trove-classifiers==2026.9.21.13 --hash=sha256:8b1ff4f9c191b1040b71c37f1e445ab99732911e3cd91de52838453a854d7a17
"""
STAGE_PATHS = (
    "apsa",
    ".agents/skills/apsa",
    "quaygate",
    "src",
    "tests",
    "benchmarks",
    "scripts",
    "docs",
    ".agents/skills/quaygate",
    ".agents/skills/mobile-audit",
    ".github/workflows",
    "pyproject.toml",
    "uv.lock",
    "requirements-release.txt",
    ".gitignore",
    ".gitattributes",
    "README.md",
    "README.ko.md",
    "NAMING.md",
    "DESIGN.md",
    "VERIFICATION.md",
    "RELEASE_READINESS.md",
    "PRODUCT_REQUIREMENTS.md",
    "Makefile",
    "THIRD_PARTY_NOTICES.md",
    "LICENSE",
    "examples",
    "action.yml",
    "server.json",
    ".claude-plugin/marketplace.json",
    ".claude-plugin/plugin.json",
    "plugins/apsa/.claude-plugin/plugin.json",
    "plugins/apsa/.mcp.json",
)


def digest(path: Path) -> str:
    checksum = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            checksum.update(block)
    return checksum.hexdigest()


def run(arguments: list[str], cwd: Path, environment: dict[str, str], timeout: int = 900) -> str:
    result = subprocess.run(
        arguments, cwd=cwd, env=environment, capture_output=True, text=True, timeout=timeout, check=False
    )
    if result.returncode:
        raise RuntimeError(
            f"Command failed ({result.returncode}): {arguments[0]} {arguments[1:4]}\n"
            f"{result.stdout[-12000:]}{result.stderr[-12000:]}"
        )
    return result.stdout


# Prune names before stat, descent, or copy. Retained binary inputs are never
# needed to assemble a source-only release snapshot.
PRIVATE_DIRECTORIES = frozenset(
    {
        "__pycache__",
        ".pytest_cache",
        ".ruff_cache",
        ".mypy_cache",
        ".git",
        ".venv",
        "venv",
        "node_modules",
        "cache",
        "caches",
        "uploads",
        "upload",
        "outputs",
        "output",
        "history",
        "jobs",
        "prompts",
        "input",
        "inputs",
        "private",
        "retained",
        "logs",
        "preferences",
        ".cache",
        "raw_logs",
        "fixtures",
        "corpus",
        "corpora",
        "artifacts",
        "builds",
    }
)
SOURCE_SUFFIXES = frozenset(
    {
        ".py",
        ".pyi",
        ".java",
        ".kt",
        ".kts",
        ".swift",
        ".m",
        ".h",
        ".c",
        ".cpp",
        ".xml",
        ".plist",
        ".gradle",
        ".pbxproj",
        ".sh",
        ".md",
        ".rst",
        ".toml",
        ".yml",
        ".yaml",
    }
)
PUBLIC_FIXTURE_SOURCES = (
    "tests/fixtures/native_context_legacy/java-vulnerable.java",
    "tests/fixtures/native_context_legacy/java-fixed.java",
    "tests/fixtures/native_context_legacy/kotlin-vulnerable.kt",
    "tests/fixtures/native_context_legacy/kotlin-fixed.kt",
    "tests/fixtures/native_context_legacy/swift-vulnerable.swift",
    "tests/fixtures/native_context_legacy/swift-fixed.swift",
    "tests/fixtures/binary_analysis/build.py",
    "tests/fixtures/binary_analysis/unsafe/Calls.java",
    "tests/fixtures/binary_analysis/safe/Calls.java",
    "tests/fixtures/runtime/build.py",
    "tests/fixtures/runtime/build_evidence.py",
    "tests/fixtures/runtime/acquire_compiled.py",
    "tests/fixtures/runtime/verify.py",
    "tests/fixtures/runtime/android/MainActivity.java",
    "tests/fixtures/runtime/android/AndroidManifest.xml",
    "tests/fixtures/runtime/ios/Main.swift",
    "tests/fixtures/runtime/ios/Instrumented.swift",
    "tests/fixtures/runtime/transport/TransportActivity.java",
    "tests/fixtures/runtime/transport/Transport.swift",
    "tests/fixtures/runtime/transport/UrlDispatcher.swift",
    "tests/fixtures/runtime/README.md",
    "tests/fixtures/runtime/COMPILED.md",
    "tests/fixtures/mcp_tool_manifest.json",
) + tuple(
    f"tests/fixtures/skills/{name}-{version}.md"
    for version in ("1.0.1", "1.0.2", "1.0.3", "1.0.6", "1.1.0")
    for name in (
        ("quaygate", "mobile-audit")
        if version in {"1.0.1", "1.0.2"}
        else ("apsa", "quaygate", "mobile-audit")
    )
)
PUBLIC_DEMO_SOURCES = tuple(
    f"src/mobile_audit/data/demo/{name}"
    for name in ("AndroidManifest.xml", "MainActivity.kt", "build.gradle.kts", "Info.plist", "Demo.swift")
)
PUBLIC_RESOURCES = frozenset(
    {
        "src/mobile_audit/data/rules.json",
        "src/mobile_audit/data/structural-rules.json",
        "src/mobile_audit/data/maswe.json",
        "action.yml",
        "server.json",
        ".claude-plugin/marketplace.json",
        ".claude-plugin/plugin.json",
        "plugins/apsa/.claude-plugin/plugin.json",
        "plugins/apsa/.mcp.json",
        "tests/fixtures/mcp_tool_manifest.json",
        "benchmarks/corpus.json",
        "docs/aapt2-integrity.json",
        "docs/benchmark-integrity.json",
        "scripts/sarif-validator/package.json",
        "scripts/sarif-validator/package-lock.json",
    }
)
# Generate this alias only from the staged public package source. The checkout's
# plugin alias may be a symlink and is never opened, inspected, or traversed.
GENERATED_SOURCE_ALIASES = {
    "plugins/apsa/skills/apsa/SKILL.md": "src/mobile_audit/data/skills/apsa/SKILL.md",
}


def source_file_allowed(relative: Path) -> bool:
    """Declare source formats and specific public data/contracts, not archives."""
    name = relative.as_posix()
    return (
        name in STAGE_PATHS
        or name in PUBLIC_RESOURCES
        or relative.suffix in SOURCE_SUFFIXES
        or (name.startswith("tests/contracts/") and relative.suffix == ".json")
    )


def stage_sources(destination: Path, *, source_only: bool = True) -> dict[str, str]:
    if destination.resolve().is_relative_to(ROOT.resolve()):
        raise ValueError("Source staging destination must be outside the checkout")
    destination.mkdir()
    inputs = {}

    def visit(origin: Path) -> None:
        relative = origin.relative_to(ROOT)
        # Do not even stat a protected directory or a disallowed input file.
        if relative.as_posix() == "src/mobile_audit/data/demo":
            for name in PUBLIC_DEMO_SOURCES:
                visit(ROOT / name)
            return
        if relative.as_posix() == "tests/fixtures":
            # This tree retains old binaries. Select trusted source paths without
            # enumerating either the fixture root or binary_analysis directory.
            for name in PUBLIC_FIXTURE_SOURCES:
                visit(ROOT / name)
            return
        if any(part.casefold() in PRIVATE_DIRECTORIES for part in relative.parts):
            if relative.as_posix() not in PUBLIC_FIXTURE_SOURCES:
                return
        if origin.suffix and not source_file_allowed(relative) and source_only:
            return
        if origin.name == ".DS_Store" or origin.suffix == ".pyc":
            return
        for parent in origin.parents:
            if parent == ROOT:
                break
            if parent.is_symlink():
                raise ValueError(f"Release source symlink is unsupported: {parent.relative_to(ROOT)}")
        if origin.is_symlink():
            raise ValueError(f"Release source symlink is unsupported: {relative}")
        if origin.is_dir():
            with os.scandir(origin) as entries:
                children = sorted((entry.name for entry in entries))
            for name in children:
                visit(origin / name)
            return
        if not origin.is_file() or (source_only and not source_file_allowed(relative)):
            return
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(origin, target)
        target.chmod(0o755 if os.access(origin, os.X_OK) else 0o644)
        inputs[relative.as_posix()] = digest(target)

    for relative in STAGE_PATHS:
        visit(ROOT / relative)
    for alias, source in GENERATED_SOURCE_ALIASES.items():
        if source not in inputs:
            continue
        target = destination / alias
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(destination / source, target)
        target.chmod(0o644)
        inputs[alias] = digest(target)
    for required in ("pyproject.toml", "uv.lock", "requirements-release.txt", "src/mobile_audit/__init__.py"):
        if required not in inputs:
            raise ValueError(f"Release source is missing {required}")
    return inputs


MAX_PACKAGE_MEMBERS = 20_000
MAX_PACKAGE_MEMBER_BYTES = 16 * 1024 * 1024
MAX_PACKAGE_TOTAL_BYTES = 256 * 1024 * 1024
TEST_HARNESS_MODULES = frozenset({"runtime_compiled.py", "runtime_synthetic.py", "runtime_transport.py"})
_DEVELOPER_HOME = re.compile(
    rb"/(?:Users|home)/[^/\s\"'\\]+(?:/|(?=[\s\"']|$))"
    rb"|[A-Za-z]:[\\/]+Users[\\/]+[^\\/\s\"']+(?:[\\/]+|(?=[\s\"']|$))"
)


def _package_path(name: str) -> PurePosixPath:
    path = PurePosixPath(name)
    if (
        not name
        or "\\" in name
        or path.is_absolute()
        or path.as_posix() != name
        or ".." in path.parts
        or re.match(r"^[A-Za-z]:", name)
        or any(ord(char) < 32 or ord(char) == 127 for char in name)
    ):
        raise ValueError("Package archive contains an unsafe or noncanonical member path")
    return path


def _package_manifest(stage: Path, inputs: dict[str, str]) -> tuple[dict, dict[str, str], dict[str, str]]:
    """Derive expectations only from declared roots and the already clean stage manifest."""
    if "pyproject.toml" not in inputs:
        raise ValueError("Package verification requires a staged pyproject manifest entry")
    for name, checksum in inputs.items():
        path = _package_path(name)
        if (
            any(part.casefold() in PRIVATE_DIRECTORIES for part in path.parts)
            and name not in PUBLIC_FIXTURE_SOURCES
        ):
            raise ValueError(
                "Source manifest contains a protected directory outside explicit public fixture sources"
            )
        if not re.fullmatch(r"[0-9a-f]{64}", checksum):
            raise ValueError("Package verification requires SHA-256 stage manifest entries")
    if digest(stage / "pyproject.toml") != inputs["pyproject.toml"]:
        raise ValueError("Staged pyproject changed after the source manifest was created")
    project = tomllib.loads((stage / "pyproject.toml").read_text())
    targets = project["tool"]["hatch"]["build"]["targets"]
    packages = targets["wheel"]["packages"]
    if not isinstance(packages, list) or not packages or any(not isinstance(p, str) for p in packages):
        raise ValueError("Wheel verification requires explicit package root declarations")
    wheel: dict[str, str] = {}
    public_roots = [_package_path(package) for package in packages]
    for package in public_roots:
        if (package / "__init__.py").as_posix() not in inputs:
            raise ValueError("Declared public package entry point is absent from the clean stage")
        for name in sorted(inputs):
            path = PurePosixPath(name)
            if path.is_relative_to(package):
                member = (PurePosixPath(package.name) / path.relative_to(package)).as_posix()
                if member in wheel:
                    raise ValueError("Declared wheel package roots produce colliding member paths")
                if path.name in TEST_HARNESS_MODULES or "tests" in path.relative_to(package).parts:
                    raise ValueError(
                        "Test acquisition harness modules must not be packaged as public runtime code"
                    )
                wheel[member] = name
    # A staged whitelist must not silently drop declared package data formats.
    for name in sorted(PUBLIC_RESOURCES | frozenset(PUBLIC_DEMO_SOURCES)):
        if (
            any(PurePosixPath(name).is_relative_to(package) for package in public_roots)
            and name not in inputs
        ):
            raise ValueError(f"Declared public package resource is absent from the clean stage: {name}")
    sdist_config = targets["sdist"]
    included = sdist_config.get("include")
    excluded = sdist_config.get("exclude", [])
    if not isinstance(included, list) or not included or not all(isinstance(p, str) for p in included):
        raise ValueError("Sdist verification requires explicit include declarations")
    if not isinstance(excluded, list) or not all(isinstance(p, str) for p in excluded):
        raise ValueError("Sdist exclude declarations must be arrays of strings")

    def matches(name: str, pattern: str) -> bool:
        normalized = pattern.lstrip("/").rstrip("/")
        return (
            name == normalized or name.startswith(normalized + "/") or fnmatch.fnmatchcase(name, normalized)
        )

    sdist = {
        name: name
        for name in sorted(inputs)
        if any(matches(name, pattern) for pattern in included)
        and not any(matches(name, pattern) for pattern in excluded)
    }
    if not set(wheel.values()) <= set(sdist):
        raise ValueError("Sdist declarations omit expected public wheel package sources")
    return project, wheel, sdist


def _archive_payload(artifact: Path, *, wheel: bool, prefix: str) -> dict[str, bytes]:
    """Inspect a newly built archive in memory; never extract or follow archive links."""
    contents: dict[str, bytes] = {}
    total = 0

    def put(name: str, size: int, stream) -> None:
        nonlocal total
        _package_path(name)
        if name in contents or len(contents) >= MAX_PACKAGE_MEMBERS:
            raise ValueError("Package archive has duplicate members or exceeds its member budget")
        total += size
        if not 0 <= size <= MAX_PACKAGE_MEMBER_BYTES or total > MAX_PACKAGE_TOTAL_BYTES:
            raise ValueError("Package archive exceeds its expanded-byte budget")
        raw = stream.read(MAX_PACKAGE_MEMBER_BYTES + 1)
        if len(raw) != size:
            raise ValueError("Package archive member size is inconsistent")
        contents[name] = raw

    if artifact.stat().st_size > MAX_PACKAGE_TOTAL_BYTES:
        raise ValueError("Package artifact exceeds its byte budget")
    if wheel:
        with zipfile.ZipFile(artifact) as archive:
            if len(archive.infolist()) > MAX_PACKAGE_MEMBERS:
                raise ValueError("Package archive exceeds its member budget")
            for item in archive.infolist():
                if item.is_dir():
                    _package_path(item.filename.rstrip("/"))
                    continue
                if item.flag_bits & 1 or (item.external_attr >> 16) & 0o170000 == 0o120000:
                    raise ValueError("Package archive encrypted entries and symlinks are unsupported")
                with archive.open(item) as stream:
                    put(item.filename, item.file_size, stream)
    else:
        with tarfile.open(artifact, "r:gz") as archive:
            count = 0
            for item in archive:
                count += 1
                if count > MAX_PACKAGE_MEMBERS:
                    raise ValueError("Package archive exceeds its member budget")
                path = _package_path(item.name.rstrip("/") if item.isdir() else item.name)
                if not path.is_relative_to(prefix):
                    raise ValueError("Sdist member is outside its declared distribution prefix")
                if item.isdir():
                    continue
                if not item.isfile():
                    raise ValueError("Sdist links and special files are unsupported")
                stream = archive.extractfile(item)
                if stream is None:
                    raise ValueError("Sdist member cannot be read")
                with stream:
                    put(path.relative_to(prefix).as_posix(), item.size, stream)
    return contents


def _wheel_record(contents: dict[str, bytes], record: str) -> None:
    try:
        rows = list(csv.reader(io.StringIO(contents[record].decode("utf-8", errors="strict"))))
    except (UnicodeError, csv.Error):
        raise ValueError("Wheel RECORD is malformed") from None
    observed: set[str] = set()
    for row in rows:
        if len(row) != 3 or row[0] in observed or row[0] not in contents:
            raise ValueError("Wheel RECORD has invalid, duplicate, or absent member entries")
        name, checksum, size = row
        observed.add(name)
        if name == record:
            if checksum or size:
                raise ValueError("Wheel RECORD must omit its own digest and size")
            continue
        raw = contents[name]
        expected = "sha256=" + base64.urlsafe_b64encode(hashlib.sha256(raw).digest()).decode().rstrip("=")
        if checksum != expected or size != str(len(raw)):
            raise ValueError("Wheel RECORD member digest or size disagrees with archive content")
    if observed != set(contents):
        raise ValueError("Wheel RECORD membership disagrees with archive content")


def verify_package_contents(artifact: Path, stage: Path, inputs: dict[str, str]) -> dict:
    """Verify only NEW wheel/sdist artifacts against the explicit clean source manifest."""
    project, wheel_expected, sdist_expected = _package_manifest(stage, inputs)
    distribution = re.sub(r"[-_.]+", "_", project["project"]["name"]).lower()
    version = project["project"]["version"]
    if not re.fullmatch(r"[a-z0-9_]+", distribution) or not re.fullmatch(r"[A-Za-z0-9.!+_-]+", version):
        raise ValueError("Package metadata has an unsupported distribution name or version")
    wheel = artifact.suffix == ".whl"
    if not wheel and not artifact.name.endswith(".tar.gz"):
        raise ValueError("Package verifier accepts only wheel and sdist artifacts")
    namespace = f"{distribution}-{version}"
    contents = _archive_payload(artifact, wheel=wheel, prefix=namespace)
    expected = wheel_expected if wheel else sdist_expected
    generated = {"PKG-INFO"}
    if wheel:
        metadata = namespace + ".dist-info/"
        generated = {metadata + name for name in ("METADATA", "WHEEL", "RECORD")}
        if project["project"].get("scripts"):
            generated.add(metadata + "entry_points.txt")
        # Hatch's generated license destination remains bound to staged bytes.
        for name in sorted(inputs):
            if "/" not in name and name.startswith(("LICENSE", "NOTICE", "AUTHORS", "COPYING")):
                expected[metadata + "licenses/" + name] = name
    missing = (set(expected) | generated) - set(contents)
    extra = set(contents) - set(expected) - generated
    if missing or extra:
        raise ValueError(
            f"Package content membership mismatch; missing={sorted(missing)}, extra={sorted(extra)}"
        )
    for member, source in expected.items():
        if hashlib.sha256(contents[member]).hexdigest() != inputs[source]:
            raise ValueError(f"Package content differs from the staged source manifest: {member}")
        if (
            wheel
            and source in wheel_expected.values()
            and source.endswith(".py")
            and _DEVELOPER_HOME.search(contents[member])
        ):
            raise ValueError("Packaged public Python source contains an absolute developer-home path")
    if wheel:
        _wheel_record(contents, namespace + ".dist-info/RECORD")
    return {
        "state": "verified",
        "artifact": artifact.name,
        "kind": "wheel" if wheel else "sdist",
        "expected_source_members": len(expected),
        "generated_metadata_members": len(generated),
        "record_verified": wheel,
        "source_manifest_basis": "explicit-clean-stage-and-pyproject-declarations",
        "artifact_sha256": digest(artifact),
    }


def fresh_binary_fixture(stage: Path, destination: Path, environment: dict[str, str]) -> Path:
    """Compile trusted staged Java into a new synthetic smoke input."""
    sdk_name = environment.get("ANDROID_SDK_ROOT") or environment.get("ANDROID_HOME")
    if not sdk_name:
        raise ValueError("Binary release smoke requires ANDROID_SDK_ROOT or ANDROID_HOME")
    specification = importlib.util.spec_from_file_location(
        "release_fixture_builder", stage / "tests/fixtures/binary_analysis/build.py"
    )
    if specification is None or specification.loader is None:
        raise ValueError("Release fixture builder is unavailable")
    builder = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(builder)
    javac = environment.get("APSA_FIXTURE_JAVAC") or shutil.which("javac", path=environment.get("PATH"))
    result = builder.build_fixtures(
        sdk=Path(sdk_name),
        output_dir=destination,
        source_dir=stage / "tests/fixtures/binary_analysis",
        javac=javac,
        environment=environment,
        compile_manifest=True,
        platform=environment.get("APSA_TEST_ANDROID_PLATFORM", "android-36"),
        build_tools=environment.get("APSA_TEST_ANDROID_BUILD_TOOLS", "36.0.0"),
    )
    return Path(result["artifacts"]["unsafe"]["path"])


def smoke(python: Path, directory: Path, environment: dict[str, str], version: str, stage: Path) -> dict:
    cli = python.parent / "apsa"
    home = directory / "audit-home"
    source = directory / "smoke-source"
    source.mkdir()
    (source / "AndroidManifest.xml").write_text(
        '<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="release.smoke">'
        '<application android:debuggable="false"/></manifest>'
    )
    (source / "Main.java").write_text(SOURCE_SMOKE_JAVA)
    installed_path = Path(
        run(
            [str(python), "-c", "import mobile_audit; print(mobile_audit.__file__)"], directory, environment
        ).strip()
    ).resolve()
    if not installed_path.is_relative_to(python.parent.parent.resolve()):
        raise RuntimeError("Smoke import resolved outside the clean release virtual environment")
    if "scan" not in run([str(cli), "--help"], directory, environment):
        raise RuntimeError("Installed CLI help is incomplete")
    for alias in ("apsa", "quaygate", "mobile-audit"):
        if run([str(python.parent / alias), "--version"], directory, environment).strip() != version:
            raise RuntimeError("Installed CLI version disagrees with the release metadata")
    for module in ("apsa", "quaygate", "mobile_audit"):
        if run([str(python), "-m", module, "--version"], directory, environment).strip() != version:
            raise RuntimeError("Installed Python entry point disagrees with the release metadata")
    for name in ("apsa", "quaygate", "mobile-audit"):
        destination = directory / "installed-skills" / name
        installed = json.loads(
            run(
                [
                    str(cli),
                    "--json",
                    "--home",
                    str(home),
                    "skill",
                    "install",
                    "--name",
                    name,
                    "--dest",
                    str(destination),
                ],
                directory,
                environment,
            )
        )
        if (
            installed["data"]["status"] != "installed"
            or (destination / "SKILL.md").read_bytes()
            != (stage / ".agents/skills" / name / "SKILL.md").read_bytes()
        ):
            raise RuntimeError("Clean wheel skill installation differs from canonical source")
    doctor = json.loads(run([str(cli), "doctor", "--home", str(home), "--json"], directory, environment))
    if not doctor["data"]["offline_ready"]:
        raise RuntimeError("Clean release installation is not ready for offline scanning")
    scanned = json.loads(
        run([str(cli), "scan", str(source), "--home", str(home), "--json"], directory, environment, 180)
    )["data"]
    findings = [item for item in scanned["findings"] if item["rule_id"] == "AST-WEBVIEW-UNTRUSTED-URL"]
    if not findings or any(item["status"] != "candidate" for item in findings):
        raise RuntimeError("Clean release offline AST scan did not produce the expected candidate evidence")
    if not any(
        item["rule_id"] == "AST-WEBVIEW-UNTRUSTED-URL" and item["state"] == "checked"
        for item in scanned["coverage"]
    ):
        raise RuntimeError("Clean release offline AST rule was not checked")
    verified = json.loads(
        run([str(cli), "reports", "verify", "--home", str(home), "--json"], directory, environment)
    )
    binary = fresh_binary_fixture(stage, directory / "synthetic-binary", environment)
    binary_report = json.loads(
        run([str(cli), "scan", str(binary), "--home", str(home), "--json"], directory, environment, 180)
    )["data"]
    if binary_report["inventory"]["engines"] != ["mobile-audit", "quaygate-lint"]:
        raise RuntimeError("Clean installation did not run both binary engines")
    if binary_report["inventory"]["quaygate"].get("input_sha256") != digest(binary):
        raise RuntimeError("Quaygate did not inspect the exact scanned build")
    if not any(item["rule_id"] == "QG-APP-SIGNATURE" for item in binary_report["findings"]):
        raise RuntimeError("Quaygate binary findings are missing from the common report")
    protocol_smoke = """import asyncio, sys
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
async def check():
    params = StdioServerParameters(command=sys.argv[1], args=["--home", sys.argv[2], "mcp", "--root", sys.argv[3]])
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            result = await session.call_tool("capabilities", {})
            assert not result.isError and result.structuredContent["product"] == "apsa"
            result = await session.call_tool("audit_scan", {"target": sys.argv[4]})
            assert not result.isError
            assert any(item["rule_id"] == "QG-APP-SIGNATURE" for item in result.structuredContent["findings"])
asyncio.run(check())
"""
    run(
        [str(python), "-c", protocol_smoke, str(cli), str(home), str(directory), str(binary)],
        directory,
        environment,
        180,
    )
    return {
        "help": "passed",
        "version": version,
        "console_aliases": ["apsa", "quaygate", "mobile-audit"],
        "module_entrypoints": ["apsa", "quaygate", "mobile_audit"],
        "doctor_offline_ready": True,
        "import_from_clean_venv": True,
        "offline_source_scan": "passed",
        "expected_candidate_rule": "AST-WEBVIEW-UNTRUSTED-URL",
        "reports_verify": verified["data"],
        "offline_binary_engines": ["mobile-audit", "quaygate-lint"],
        "binary_input_hash_matches": True,
        "mcp_stdio_binary_scan": "passed",
        "packaged_skill_install": ["apsa", "quaygate", "mobile-audit"],
        "intel_network_requested": False,
    }


def release(output: Path, offline: bool) -> dict:
    if (
        sys.platform not in {"darwin", "linux"}
        or sys.implementation.name != "cpython"
        or sys.version_info[:2] not in {(3, 11), (3, 12)}
    ):
        raise ValueError("Release verification supports macOS/Linux with CPython 3.11 or 3.12")
    if output.exists() and any(output.iterdir()):
        raise ValueError("Release output must be absent or empty; an existing bundle will not be overwritten")
    uv = shutil.which("uv")
    if not uv:
        raise ValueError(f"Install uv {UV_VERSION} before building; this script does not install tools")
    environment = {
        **os.environ,
        "PYTHONPATH": "",
        "PYTHONNOUSERSITE": "1",
        "UV_PYTHON_DOWNLOADS": "never",
        "SOURCE_DATE_EPOCH": SOURCE_DATE_EPOCH,
    }
    if run([uv, "--version"], ROOT, environment).split()[:2] != ["uv", UV_VERSION]:
        raise ValueError(f"Release toolchain requires uv {UV_VERSION}")
    uv_args = [uv, *(["--offline"] if offline else [])]
    with tempfile.TemporaryDirectory(prefix="apsa-release-") as name:
        temporary = Path(name).resolve()
        if temporary.is_relative_to(ROOT):
            raise ValueError(
                "Release build and clean-install temporary directory must be outside the checkout"
            )
        stage = temporary / "source"
        inputs = stage_sources(stage)
        version = tomllib.loads((stage / "pyproject.toml").read_text())["project"]["version"]
        exported = temporary / "requirements-export.txt"
        run(
            [
                *uv_args,
                "export",
                "--locked",
                "--no-dev",
                "--no-emit-project",
                "--no-header",
                "--quiet",
                "--output-file",
                str(exported),
            ],
            stage,
            environment,
        )
        if exported.read_bytes() != (stage / "requirements-release.txt").read_bytes():
            raise ValueError("requirements-release.txt is stale; regenerate it from uv.lock before release")
        bundle = temporary / "bundle"
        bundle.mkdir()
        shutil.copyfile(exported, bundle / "requirements-release.txt")
        build_requirements = bundle / "requirements-build.txt"
        build_requirements.write_text(BUILD_REQUIREMENTS)
        builder = temporary / "build-venv"
        run([*uv_args, "venv", "--python", sys.executable, str(builder)], temporary, environment)
        build_python = builder / "bin/python"
        run(
            [
                *uv_args,
                "pip",
                "install",
                "--python",
                str(build_python),
                "--require-hashes",
                "--only-binary",
                ":all:",
                "-r",
                str(build_requirements),
            ],
            temporary,
            environment,
        )
        artifacts = []
        repeated = temporary / "repeat"
        for target in (bundle, repeated):
            run(
                [
                    *uv_args,
                    "build",
                    "--python",
                    str(build_python),
                    "--no-build-isolation",
                    "--out-dir",
                    str(target),
                    str(stage),
                ],
                temporary,
                environment,
            )
        first = {
            item.name: digest(item)
            for item in bundle.iterdir()
            if item.suffix == ".whl" or item.name.endswith(".tar.gz")
        }
        second = {
            item.name: digest(item)
            for item in repeated.iterdir()
            if item.suffix == ".whl" or item.name.endswith(".tar.gz")
        }
        (bundle / ".gitignore").unlink(missing_ok=True)
        if len(first) != 2 or first != second:
            raise RuntimeError(f"Repeated wheel/sdist builds disagree: {first} / {second}")
        package_contents = {
            filename: {
                "primary": verify_package_contents(bundle / filename, stage, inputs),
                "repeated": verify_package_contents(repeated / filename, stage, inputs),
            }
            for filename in sorted(first)
        }
        for filename, sha256 in sorted(first.items()):
            artifacts.append({"file": filename, "sha256": sha256})
        wheel = next(bundle.glob("*.whl"))
        installed = temporary / "install-venv"
        run([*uv_args, "venv", "--python", sys.executable, str(installed)], temporary, environment)
        installed_python = installed / "bin/python"
        run(
            [
                *uv_args,
                "pip",
                "install",
                "--python",
                str(installed_python),
                "--require-hashes",
                "--only-binary",
                ":all:",
                "-r",
                str(exported),
            ],
            temporary,
            environment,
        )
        own_requirement = temporary / "own-wheel.txt"
        own_requirement.write_text(f"apsa @ {wheel.as_uri()} --hash=sha256:{digest(wheel)}\n")
        run(
            [
                *uv_args,
                "pip",
                "install",
                "--python",
                str(installed_python),
                "--no-deps",
                "--require-hashes",
                "-r",
                str(own_requirement),
            ],
            temporary,
            environment,
        )
        run([*uv_args, "pip", "check", "--python", str(installed_python)], temporary, environment)
        working = temporary / "unrelated-working-directory"
        working.mkdir()
        smoke_result = smoke(installed_python, working, environment, version, stage)
        shutil.copyfile(
            working / "synthetic-binary/fixture-provenance.json", bundle / "fixture-provenance.json"
        )
        served_hashes = json.loads(
            run(
                [
                    str(installed_python),
                    str(stage / "scripts/served_mcp_manifest.py"),
                    "--out",
                    str(bundle / "served-mcp"),
                    "--contract",
                    str(stage / "tests/contracts/mcp_tool_manifest_pending.json"),
                ],
                working,
                environment,
                120,
            )
        )
        smoke_result["clean_install_served_mcp"] = {
            "transport": "actual-sdk-stdio-initialize-and-tools/list",
            "scope_sha256": served_hashes,
            "responses": "served-mcp",
            "published_baseline_approved": False,
        }
        licenses = json.loads(
            run(
                [
                    str(installed_python),
                    str(stage / "scripts/licenses.py"),
                    "--requirements",
                    str(exported),
                    "--out",
                    str(bundle),
                ],
                working,
                environment,
            )
        )
        manifest = {
            "schema_version": 1,
            "product": "apsa",
            "version": version,
            "python": platform.python_version(),
            "host": {
                "system": platform.system(),
                "release": platform.release(),
                "machine": platform.machine(),
            },
            "toolchain": {
                "uv": UV_VERSION,
                "uv_binary_sha256": digest(Path(uv)),
                "build_requirements_sha256": digest(build_requirements),
                "source_date_epoch": SOURCE_DATE_EPOCH,
            },
            "runtime_requirements_sha256": digest(exported),
            "source_files_sha256": inputs,
            "generated_source_aliases": {
                alias: source for alias, source in GENERATED_SOURCE_ALIASES.items() if alias in inputs
            },
            "artifacts": artifacts,
            "package_content_verification": package_contents,
            "repeated_builds_identical": True,
            "reproducibility_scope": "Two builds of one staged input with the same host/interpreter/toolchain; no cross-platform or whole-bundle byte identity claim.",
            "smoke": smoke_result,
            "attribution": licenses,
            "offline_install_requested": offline,
            "published": False,
        }
        (bundle / "release-manifest.json").write_text(
            json.dumps(manifest, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
        )
        checksums = [
            f"{digest(item)}  {item.relative_to(bundle).as_posix()}"
            for item in sorted(bundle.rglob("*"))
            if item.is_file()
        ]
        (bundle / "SHA256SUMS").write_text("\n".join(checksums) + "\n")
        output.parent.mkdir(parents=True, exist_ok=True)
        shutil.copytree(bundle, output, dirs_exist_ok=True)
    return {
        "version": version,
        "output": str(output),
        "artifacts": artifacts,
        "package_content_verification": package_contents,
        "smoke": smoke_result,
        "attribution": licenses,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True, help="New or empty local bundle directory")
    parser.add_argument(
        "--offline", action="store_true", help="Require all uv/PyPI artifacts in the existing local cache"
    )
    parser.add_argument(
        "--stage-only",
        action="store_true",
        help="Create a source-only snapshot without building or installing",
    )
    args = parser.parse_args()
    try:
        output = args.out.expanduser().resolve()
        if args.stage_only:
            inputs = stage_sources(output)
            result = {
                "schema_version": 1,
                "output": str(output),
                "source_files_sha256": inputs,
                "generated_source_aliases": {
                    alias: source for alias, source in GENERATED_SOURCE_ALIASES.items() if alias in inputs
                },
                "source_only": True,
                "build": "not-run",
                "clean_install": "not-run",
                "served_mcp": "not-run",
                "published": False,
            }
        else:
            result = release(output, args.offline)
        print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired) as error:
        print(str(error), file=sys.stderr)
        raise SystemExit(1) from error


if __name__ == "__main__":
    main()
