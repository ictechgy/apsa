from __future__ import annotations

import hashlib
import json
import os
import plistlib
import re
import stat
import tomllib
import zipfile
import zlib
from pathlib import Path
from urllib.parse import unquote

from defusedxml import ElementTree as ET

from .core import (
    MAX_ARCHIVE_TOTAL,
    MAX_FILE,
    MAX_FILES,
    MAX_SOURCE_TOTAL,
    digest,
    file_digest,
    read_bounded,
    read_under,
)

ANDROID_NS = "{http://schemas.android.com/apk/res/android}"
SKIP_DIRS = {
    ".git",
    ".venv",
    "node_modules",
    "Pods",
    "build",
    ".gradle",
    ".idea",
    "DerivedData",
    "__pycache__",
    ".mobile-audit",
}
TEXT_SUFFIXES = {
    ".kt",
    ".java",
    ".swift",
    ".m",
    ".mm",
    ".h",
    ".xml",
    ".plist",
    ".json",
    ".gradle",
    ".kts",
    ".toml",
    ".lock",
    ".lockfile",
    ".yaml",
    ".yml",
    ".js",
    ".ts",
    ".dart",
    ".xcprivacy",
    ".resolved",
    ".pbxproj",
}


def dependency(name: str, version: str, ecosystem: str, path: str, confidence="exact") -> dict:
    return {"name": name, "version": version, "ecosystem": ecosystem, "path": path, "confidence": confidence}


def shipped_runtime_configuration(name: str) -> bool:
    lowered = name.lower()
    return lowered.endswith("runtimeclasspath") and not any(
        word in lowered
        for word in ("test", "debug", "benchmark", "lint", "kapt", "ksp", "annotationprocessor")
    )


def parse_dependencies(path: str, raw: bytes) -> list[dict]:
    text = raw.decode("utf-8", errors="replace")
    name = Path(path).name
    found = []
    if name.endswith((".gradle", ".gradle.kts")):
        from .source_context import tokens

        # Only real string declarations; comments are not dependency evidence.
        stream = tokens(text)
        for index, (kind, word, _) in enumerate(stream):
            if kind != "code" or word not in {"implementation", "api", "compileOnly", "runtimeOnly"}:
                continue
            index += 1
            parenthesized = index < len(stream) and stream[index][1] == "("
            if parenthesized:
                index += 1
            if index >= len(stream) or stream[index][0] != "string":
                continue
            match = re.fullmatch(r"""(["'])([^"':\s]+:[^"':\s]+):([^"'\s]+)\1""", stream[index][1])
            if not match:
                continue
            quote, package, version = match.groups()
            end = index + 1
            standalone = True
            if parenthesized:
                standalone = end < len(stream) and stream[end][1] == ")"
                if standalone:
                    end += 1
            if end < len(stream):
                following = stream[end]
                standalone &= following[1] in {";", "}"} or (
                    following[0] == "code"
                    and following[1] not in {"as", "in", "instanceof"}
                    and bool(re.fullmatch(r"[A-Za-z_]\w*", following[1]))
                    and following[2] > stream[end - 1][2]
                )
            exact = (
                standalone
                and not any(c in version for c in "$+[](),")
                and version.lower() != "latest.release"
            )
            entry = dependency(package, version, "Maven", path, "declared" if exact else "unknown")
            if "$" in version:
                entry.update(version_expression=version, version_interpolation=standalone and quote == '"')
            found.append(entry)
    elif name.endswith(".versions.toml"):
        value = tomllib.loads(text)
        bundles = value.get("bundles", {})
        for alias, entry in value.get("libraries", {}).items():
            if isinstance(entry, str):
                # "group:name:version"; a version-less entry is resolved by a platform/BOM.
                parts = entry.split(":")
                entry = (
                    {key: part for key, part in zip(("group", "name", "version"), parts, strict=False)}
                    if len(parts) in {2, 3}
                    else {}
                )
            if not isinstance(entry, dict):
                continue
            package = entry.get("module") or f"{entry.get('group', '')}:{entry.get('name', '')}"
            version = entry.get("version", "")
            if isinstance(version, dict):
                version = value.get("versions", {}).get(version.get("ref"), "")
            if isinstance(version, str) and version:
                catalog = dependency(package, version, "Maven", path, "unknown")
                catalog["version_source"] = "catalog-declared-unresolved-usage"
                catalog["catalog_alias"] = alias
                member = sorted(
                    bundle
                    for bundle, aliases in bundles.items()
                    if isinstance(aliases, list) and alias in aliases
                )
                if member:
                    catalog["catalog_bundles"] = member[:16]
                found.append(catalog)
    elif name == "gradle.lockfile" or (
        name.endswith(".lockfile") and Path(path).parent.as_posix().endswith("gradle/dependency-locks")
    ):
        # Gradle writes resolved coordinates per configuration. Only release runtime
        # classpaths describe shipped code; build tooling and test/debug graphs are omitted.
        legacy = None if name == "gradle.lockfile" else name.removesuffix(".lockfile")
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("empty="):
                continue
            match = re.fullmatch(r"([^:=\s]+):([^:=\s]+):([^:=\s]+)(?:=([^=\s]*))?", line)
            if not match:
                raise ValueError("Unsupported Gradle lockfile entry")
            group, artifact, version, configurations = match.groups()
            names = [legacy] if legacy else (configurations or "").split(",")
            shipped = sorted(c for c in names if c and shipped_runtime_configuration(c))
            if shipped:
                entry = dependency(f"{group}:{artifact}", version, "Maven", path)
                entry["version_source"] = "gradle-lockfile-resolved"
                entry["resolved_configurations"] = shipped[:16]
                found.append(entry)
    elif name == "Package.resolved":
        value = json.loads(text)
        pins = value.get("pins", value.get("object", {}).get("pins", []))
        for pin in pins:
            state = pin.get("state", {})
            found.append(
                dependency(
                    pin.get("location", pin.get("repositoryURL", pin.get("identity", ""))).removesuffix(
                        ".git"
                    ),
                    state.get("version", ""),
                    "SwiftURL",
                    path,
                    "exact" if state.get("version") else "unknown",
                )
            )
    elif name == "Podfile.lock":
        pods = text.split("PODS:", 1)[-1].split("DEPENDENCIES:", 1)[0]
        for package, version in re.findall(r"^  - ([\w.+/-]+) \(([^)]+)\)", pods, re.M):
            found.append(dependency(package.split("/")[0], version, "CocoaPods", path))
    elif name == "package-lock.json":
        value = json.loads(text)
        for location, entry in value.get("packages", {}).items():
            if "node_modules/" in location and entry.get("version"):
                package = location.rsplit("node_modules/", 1)[-1]
                found.append(dependency(package, entry["version"], "npm", path))
        for package, entry in value.get("dependencies", {}).items():
            if entry.get("version"):
                found.append(dependency(package, entry["version"], "npm", path))
    elif name.endswith(".cdx.json") or name == "sbom.json":
        value = json.loads(text)
        for entry in value.get("components", []):
            purl = entry.get("purl", "")
            match = re.match(r"pkg:(maven|npm|pypi|golang|pub|swift)/(.+?)@([^?]+)", purl)
            if match:
                kind, package, version = match.groups()
                package = unquote(package)
                if kind == "maven":
                    package = package.replace("/", ":")
                ecosystem = {
                    "maven": "Maven",
                    "npm": "npm",
                    "pypi": "PyPI",
                    "golang": "Go",
                    "pub": "Pub",
                    "swift": "SwiftURL",
                }[kind]
                found.append(dependency(package, unquote(version), ecosystem, path))
    return found


def android_manifest(raw: bytes, origin: str, inventory: dict) -> None:
    if raw.lstrip().startswith(b"<"):
        root = ET.fromstring(raw)
    else:
        from loguru import logger

        logger.disable("androguard")
        from androguard.core.axml import AXMLPrinter

        printer = AXMLPrinter(raw)
        if not printer.is_valid():
            raise ValueError("Invalid binary AndroidManifest.xml")
        root = printer.get_xml_obj()
        if root is None:
            raise ValueError("Unable to decode binary Android manifest")
    inventory["platforms"].append("android")
    inventory["package"] = root.get("package", inventory.get("package", ""))
    if root.get("package"):
        inventory.setdefault("apps", []).append(
            {"platform": "android", "package": root.get("package"), "path": origin, "basis": "manifest"}
        )
    sdk = root.find("uses-sdk")
    if sdk is not None:
        inventory["android_sdk"] = {
            "min": sdk.get(ANDROID_NS + "minSdkVersion", ""),
            "target": sdk.get(ANDROID_NS + "targetSdkVersion", ""),
        }
    app = root.find("application")
    if app is None:
        return
    inventory["android_config"].append(
        {
            "path": origin,
            "debuggable": app.get(ANDROID_NS + "debuggable", "false"),
            "cleartext": app.get(ANDROID_NS + "usesCleartextTraffic", "unspecified"),
            "network_security_config": app.get(ANDROID_NS + "networkSecurityConfig", ""),
            "allow_backup": app.get(ANDROID_NS + "allowBackup", "unspecified"),
        }
    )
    for component in app:
        component_name = component.get(ANDROID_NS + "name", "")
        exported = component.get(ANDROID_NS + "exported", "unspecified")
        filters = component.findall("intent-filter")
        inventory["components"].append(
            {
                "name": component_name,
                "type": component.tag,
                "exported": exported,
                "permission": component.get(ANDROID_NS + "permission", ""),
                "path": origin,
            }
        )
        for filter_ in filters:
            actions = {a.get(ANDROID_NS + "name") for a in filter_.findall("action")}
            if "android.intent.action.VIEW" not in actions:
                continue
            # Android combines <data> declarations within the same filter.
            # Separate scheme/host elements and cross-pairs must not be lost.
            from itertools import islice, product

            data_elements = filter_.findall("data")
            schemes = list(dict.fromkeys(d.get(ANDROID_NS + "scheme") for d in data_elements))
            schemes = [s for s in schemes if s]
            authorities = list(
                dict.fromkeys(
                    (d.get(ANDROID_NS + "host", ""), d.get(ANDROID_NS + "port", ""))
                    for d in data_elements
                    if d.get(ANDROID_NS + "host")
                )
            )
            paths = list(
                dict.fromkeys(
                    (kind, d.get(ANDROID_NS + kind, ""))
                    for d in data_elements
                    for kind in ("path", "pathPrefix", "pathPattern", "pathSuffix", "pathAdvancedPattern")
                    if d.get(ANDROID_NS + kind)
                )
            )
            if not authorities:
                paths = []  # Android ignores paths when the filter has no host.
            authorities = authorities or [("", "")]
            paths = paths or [("", "")]
            if len(schemes) * len(authorities) * len(paths) > 200:
                inventory["warnings"].append(f"Deep-link combinations limited to 200 for {origin}")
            if filter_.find("uri-relative-filter-group") is not None:
                inventory["warnings"].append(f"URI relative filter groups require manual review: {origin}")
            for scheme, (host, port), (kind, path) in islice(product(schemes, authorities, paths), 200):
                inventory["deep_links"].append(
                    {
                        "scheme": scheme,
                        "host": host,
                        "port": port,
                        "path": path,
                        "path_kind": kind,
                        "component": component_name,
                        "auto_verify": filter_.get(ANDROID_NS + "autoVerify", "false"),
                        "origin": origin,
                        "platform": "android",
                    }
                )


def ios_plist(raw: bytes, origin: str, inventory: dict, *, primary=True) -> None:
    value = plistlib.loads(raw)
    if not isinstance(value, dict):
        raise ValueError("Info.plist must be a dictionary")
    inventory["platforms"].append("ios")
    if primary:
        inventory["package"] = value.get("CFBundleIdentifier", inventory.get("package", ""))
    if primary and value.get("CFBundleIdentifier"):
        inventory.setdefault("apps", []).append(
            {
                "platform": "ios",
                "package": value["CFBundleIdentifier"],
                "path": origin,
                "basis": "plist",
                "version": value.get("CFBundleShortVersionString", ""),
            }
        )
    inventory["ios_config"].append(
        {
            "path": origin,
            "ats": value.get("NSAppTransportSecurity", {}),
            "minimum_os": value.get("MinimumOSVersion", ""),
            "version": value.get("CFBundleShortVersionString", ""),
            "bundle_role": "main" if primary else "embedded",
        }
    )
    for entry in value.get("CFBundleURLTypes", []):
        for scheme in entry.get("CFBundleURLSchemes", []):
            inventory["deep_links"].append(
                {
                    "scheme": scheme,
                    "host": "",
                    "path": "",
                    "origin": origin,
                    "platform": "ios",
                    "bundle_role": "main" if primary else "embedded",
                }
            )


class SourceBudgetExceeded(ValueError):
    pass


def _outer_app_index(parts: tuple[str, ...]) -> int | None:
    for index, part in enumerate(parts):
        if part.lower().endswith((".framework", ".appex", ".bundle")):
            return None
        if part.lower().endswith(".app"):
            return index
    return None


def inspect_target(
    target: Path, sbom: Path | None = None, *, authorized: bool = False, configuration: str | None = None
) -> tuple[dict, list[tuple[str, str]]]:
    target = target if authorized else target.expanduser().resolve()
    if not target.exists():
        raise ValueError(f"Input not found: {target}")
    inventory = {
        "target": str(target),
        "input_kind": "source" if target.is_dir() else target.suffix.lstrip("."),
        "platforms": [],
        "package": "",
        "apps": [],
        "deep_links": [],
        "components": [],
        "dependencies": [],
        "features": [],
        "android_config": [],
        "ios_config": [],
        "warnings": [],
        "files_scanned": 0,
        "fingerprint": "",
        "fingerprint_complete": True,
        "bytes_scanned": 0,
        "partial": False,
    }
    sources = []
    source_plists = {}
    main_plists = set()
    app_archive = False
    source_input = target.is_dir() and target.suffix.lower() != ".app"
    if configuration:
        from .selection import relative_source_path

        configuration = relative_source_path(configuration)
        if not source_input or not (
            Path(configuration).name == "AndroidManifest.xml" or Path(configuration).suffix == ".plist"
        ):
            raise ValueError(
                "Configuration selection requires a source directory and a manifest or .plist file"
            )
    inventory["source_selection"] = {
        "configuration": configuration,
        "configuration_semantics": "declared source file; no build-system merge",
    }
    hasher = hashlib.sha256()

    def primary_android(name: str) -> bool:
        return (
            (
                source_input
                and name.endswith("AndroidManifest.xml")
                and (not configuration or name == configuration)
            )
            or (target.suffix.lower() == ".apk" and name == "AndroidManifest.xml")
            or (target.suffix.lower() == ".aab" and name == "base/manifest/AndroidManifest.xml")
        )

    def consume(name: str, raw: bytes):
        if inventory["bytes_scanned"] + len(raw) > MAX_SOURCE_TOTAL:
            inventory["fingerprint_complete"] = False
            raise SourceBudgetExceeded("Source/configuration total byte limit reached; coverage incomplete")
        inventory["bytes_scanned"] += len(raw)
        hasher.update(name.encode() + b"\0" + raw)
        inventory["files_scanned"] += 1
        if source_input and name.endswith(".plist"):
            source_plists[name] = raw
        if name.endswith((".gradle", ".gradle.kts")) and source_input and not configuration:
            text = raw.decode("utf-8", errors="replace")
            package_ids = re.findall(r"applicationId\s*(?:=|\()?\s*[\"']([A-Za-z0-9_.]+)[\"']", text)
            suffixes = re.findall(r"applicationIdSuffix\s*(?:=|\()?\s*[\"'](\.[A-Za-z0-9_.]+)[\"']", text)
            for package in package_ids:
                for suffix in ["", *suffixes]:
                    inventory["apps"].append(
                        {
                            "platform": "android",
                            "package": package + suffix,
                            "path": name,
                            "basis": "declared-gradle",
                        }
                    )
                    inventory["platforms"].append("android")
        try:
            if primary_android(name):
                if target.suffix.lower() == ".aab" and not raw.lstrip().startswith(b"<"):
                    from .aab_manifest import decode_manifest

                    raw, notes = decode_manifest(raw)
                    inventory["warnings"].extend(notes)
                    inventory["partial"] |= bool(notes)
                    inventory["aab_manifest"] = {
                        "path": name,
                        "basis": "aapt2-protobuf",
                        "resource_resolution": False,
                        "unresolved_attributes": bool(notes),
                    }
                android_manifest(raw, name, inventory)
            elif (
                (name.endswith("Info.plist") or (source_input and name == configuration))
                and (not configuration or name == configuration)
                and (target.is_dir() or target.suffix.lower() in {".ipa", ".zip"})
                and (
                    source_input
                    or target.is_dir()
                    or any(name.startswith(Path(main).parent.as_posix() + "/") for main in main_plists)
                )
            ):
                main_plist = (
                    name == "Info.plist"
                    if target.is_dir() and target.suffix.lower() == ".app"
                    else target.is_dir() or name in main_plists
                )
                if main_plist:
                    ios_plist(raw, name, inventory)
                else:
                    ios_plist(raw, name, inventory, primary=False)
                    value = plistlib.loads(raw)
                    if isinstance(value, dict) and value.get("CFBundleIdentifier"):
                        inventory.setdefault("embedded_bundles", []).append(
                            {"package": value["CFBundleIdentifier"], "path": name}
                        )
            inventory["dependencies"].extend(parse_dependencies(name, raw))
        except (
            ValueError,
            KeyError,
            TypeError,
            AttributeError,
            ET.ParseError,
            plistlib.InvalidFileException,
            RecursionError,
        ) as error:
            inventory["warnings"].append(f"Could not parse {name}: {type(error).__name__}")
            inventory["partial"] = True
        if Path(name).suffix in TEXT_SUFFIXES and not raw.startswith(b"bplist"):
            sources.append((name, raw.decode("utf-8", errors="replace")))

    if target.is_dir():

        def source_error(
            error: OSError, action: str = "enumerate source directory", relative: Path | None = None
        ) -> None:
            try:
                if relative is not None:
                    location = str(relative)
                else:
                    location = str(Path(error.filename).relative_to(target)) if error.filename else "."
            except (TypeError, ValueError):
                location = "."
            inventory["warnings"].append(f"Could not {action}: {location} ({type(error).__name__})")
            inventory["partial"] = True
            inventory["fingerprint_complete"] = False

        source_paths = []
        for directory, dirs, names in os.walk(target, followlinks=False, onerror=source_error):
            kept = []
            for name in sorted(dirs):
                if name in SKIP_DIRS:
                    continue
                child = Path(directory) / name
                try:
                    if not child.is_symlink():
                        kept.append(name)
                except OSError as error:
                    source_error(error, "inspect source directory", child.relative_to(target))
            dirs[:] = kept
            for name in sorted(names):
                path = Path(directory) / name
                if path.suffix in TEXT_SUFFIXES or path.name in {"Podfile.lock", "Package.resolved"}:
                    source_paths.append(path)
                if len(source_paths) > MAX_FILES:
                    break
            if len(source_paths) > MAX_FILES:
                break
        if len(source_paths) > MAX_FILES:
            inventory["warnings"].append("Source enumeration limit reached; coverage incomplete")
            inventory["partial"] = True
            inventory["fingerprint_complete"] = False
        if target.suffix.lower() == ".app":
            main = target / "Info.plist"
            if main.is_file() and main not in source_paths:
                source_paths.append(main)
            source_paths.sort(key=lambda path: path != main)
        for path in source_paths:
            relative = path.relative_to(target)
            if any(part in SKIP_DIRS for part in relative.parts):
                continue
            try:
                metadata = path.lstat()
            except OSError as error:
                source_error(error, "inspect source entry", relative)
                continue
            if (
                stat.S_ISLNK(metadata.st_mode)
                or not stat.S_ISREG(metadata.st_mode)
                or (
                    path.suffix not in TEXT_SUFFIXES and path.name not in {"Podfile.lock", "Package.resolved"}
                )
            ):
                continue
            if inventory["files_scanned"] >= MAX_FILES:
                inventory["warnings"].append("Source file limit reached; coverage incomplete")
                inventory["partial"] = True
                inventory["fingerprint_complete"] = False
                break
            if metadata.st_size > MAX_FILE:
                inventory["warnings"].append(f"Oversized source omitted: {relative}")
                inventory["partial"] = True
                inventory["fingerprint_complete"] = False
                continue
            try:
                consume(str(relative), read_under(target, relative))
            except OSError as error:
                source_error(error, "read source file", relative)
                continue
            except ValueError as error:
                inventory["warnings"].append(str(error))
                inventory["partial"] = True
                inventory["fingerprint_complete"] = False
                break
    elif target.suffix.lower() in {".apk", ".ipa", ".zip", ".aab"}:
        inventory["fingerprint"] = file_digest(target)
        with zipfile.ZipFile(target) as archive:
            items = archive.infolist()
            if len(items) > MAX_FILES or sum(i.file_size for i in items) > MAX_ARCHIVE_TOTAL:
                raise ValueError("Archive exceeds safe size/file-count limit")
            # AppleDouble files contain filesystem metadata, not app configuration.
            items = [
                item
                for item in items
                if "__MACOSX" not in Path(item.filename).parts
                and not Path(item.filename).name.startswith("._")
            ]
            app_archive = any(_outer_app_index(Path(item.filename).parts[:-1]) is not None for item in items)
            source_input = target.suffix.lower() == ".zip" and not app_archive
            if target.suffix.lower() == ".zip":
                inventory["archive_role"] = "ios-app-build" if app_archive else "source-zip"
            for item in items:
                parts = Path(item.filename).parts
                if (
                    target.suffix.lower() in {".ipa", ".zip"}
                    and len(parts) >= 2
                    and parts[-1] == "Info.plist"
                    and parts[-2].lower().endswith(".app")
                    and _outer_app_index(parts[:-1]) == len(parts) - 2
                    and sum(part.lower().endswith(".app") for part in parts[:-1]) == 1
                    and (
                        target.suffix.lower() != ".ipa"
                        or re.fullmatch(r"Payload/[^/]+\.app/Info\.plist", item.filename)
                    )
                ):
                    main_plists.add(item.filename)
            if not main_plists and target.suffix.lower() == ".zip" and not app_archive:
                candidates = {
                    item.filename
                    for item in items
                    if item.filename.endswith("Info.plist")
                    and not any(
                        part.lower().endswith((".framework", ".appex", ".bundle"))
                        for part in Path(item.filename).parts[:-1]
                    )
                }
                if len(candidates) == 1:
                    main_plists = candidates
            if len(main_plists) > 1:
                raise ValueError("Archive contains multiple main apps; provide a single owned app build")
            if target.suffix.lower() == ".ipa" and not main_plists:
                raise ValueError("IPA has no main iOS Info.plist")
            # Establish main identity before optional resources consume the byte budget.
            items.sort(
                key=lambda item: (
                    0 if item.filename in main_plists else (1 if primary_android(item.filename) else 2)
                )
            )
            for item in items:
                name = item.filename
                if item.is_dir():
                    continue
                # Read in place. Never extract untrusted archive paths.
                if name.startswith("/") or ".." in Path(name).parts:
                    raise ValueError("Unsafe archive member path")
                if item.file_size > MAX_FILE:
                    inventory["warnings"].append(f"Oversized archive member omitted: {name}")
                    inventory["partial"] = True
                    continue
                if (
                    name.endswith("AndroidManifest.xml")
                    or re.match(r"Payload/[^/]+\.app/Info\.plist$", name)
                    or Path(name).suffix in TEXT_SUFFIXES
                ):
                    try:
                        consume(name, archive.read(item))
                    except SourceBudgetExceeded as error:
                        inventory["warnings"].append(str(error))
                        inventory["partial"] = True
                        break
                    except (
                        ValueError,
                        OSError,
                        zipfile.BadZipFile,
                        RuntimeError,
                        NotImplementedError,
                        EOFError,
                        zlib.error,
                    ) as error:
                        inventory["warnings"].append(
                            f"Archive member unreadable: {name}: {type(error).__name__}"
                        )
                        inventory["partial"] = True
                        inventory["fingerprint_complete"] = False
                elif re.match(r"classes\d*\.dex$", name):
                    inventory["files_scanned"] += 1
                    # DEX parsing and feature discovery belong to the bounded binary pass.
            if target.suffix.lower() == ".aab":
                inventory["partial"] = True
                inventory["archive_role"] = "android-app-bundle"
                inventory["android_modules"] = sorted(
                    {
                        item.filename.split("/")[0]
                        for item in items
                        if re.fullmatch(r"[^/]+/manifest/AndroidManifest.xml", item.filename)
                    }
                )
                inventory["warnings"].append(
                    "AAB base manifest and declared module DEX are inspected; resource/device split merging and installed feature reachability are not established."
                )
        if target.suffix.lower() == ".ipa":
            inventory["warnings"].append(
                "IPA code paths and library versions may be unavailable for encrypted/stripped binaries; supply source or SBOM for dependency coverage."
            )
    else:
        raise ValueError(
            "Use a source folder, APK, IPA, simulator .app folder, or ZIP containing a supported app"
        )
    if source_input:
        from .source_context import plist_references, resolve_catalog_usage, resolve_gradle, supersede

        if not inventory["partial"]:
            try:
                resolve_gradle(inventory["dependencies"], sources)
            except ValueError as error:
                inventory["warnings"].append(str(error))
                inventory["partial"] = True
        # Positive usage evidence is valid even when other files were omitted;
        # a missing reference never becomes evidence that a library is unused.
        inventory["warnings"].extend(resolve_catalog_usage(inventory["dependencies"], sources))
        try:
            supersede(inventory["dependencies"], sources)
        except ValueError as error:
            inventory["warnings"].append(f"Gradle module roles not resolved: {error}")
            supersede(inventory["dependencies"])
        references, warnings = plist_references(sources)
        inventory["warnings"].extend(warnings)
        inventory["partial"] |= bool(warnings)
        inventory["configuration_references"] = []
        for name, origins in references.items():
            if configuration and name != configuration:
                continue
            existing = next((c for c in inventory["ios_config"] if c["path"] == name), None)
            if existing is None:
                try:
                    if name not in source_plists:
                        raise ValueError("Referenced plist was not read within source bounds")
                    ios_plist(source_plists[name], name, inventory)
                    existing = inventory["ios_config"][-1]
                except (ValueError, TypeError, plistlib.InvalidFileException, RecursionError):
                    inventory["warnings"].append(f"Referenced source plist unavailable or invalid: {name}")
                    inventory["partial"] = True
            if existing is not None:
                existing["xcode_references"] = origins
            inventory["configuration_references"].append(
                {
                    "path": name,
                    "origins": origins,
                    "state": "observed" if existing is not None else "unavailable",
                }
            )
    if not target.is_dir() and not inventory["platforms"]:
        raise ValueError("Archive has no readable Android manifest or main iOS Info.plist")
    if (
        (target.is_dir() and target.suffix.lower() == ".app")
        or target.suffix.lower() == ".ipa"
        or (target.suffix.lower() == ".zip" and app_archive)
    ) and not any(a["platform"] == "ios" for a in inventory["apps"]):
        raise ValueError("iOS app build has no readable main Info.plist with an app identifier")
    if not inventory["fingerprint"]:
        inventory["fingerprint"] = hasher.hexdigest()
    if sbom:
        if sbom.stat().st_size > MAX_FILE:
            raise ValueError("SBOM exceeds size limit")
        raw = read_bounded(sbom)
        inventory["dependencies"].extend(parse_dependencies("sbom.json", raw))
        inventory["sbom_hash"] = digest(raw)
    for name, text in sources:
        if "WebView" in text or "WKWebView" in text:
            inventory["features"].append("webview")
        if "addJavascriptInterface" in text or "WKScriptMessageHandler" in text:
            inventory["features"].append("javascript_bridge")
        if Path(name).suffix == ".swift" and source_input:
            inventory["platforms"].append("ios")
        if Path(name).suffix in {".kt", ".java"} and source_input:
            inventory["platforms"].append("android")
    for key in ("platforms", "features"):
        inventory[key] = sorted(set(inventory[key]))
    unique = {(d["ecosystem"], d["name"], d["version"], d["path"]): d for d in inventory["dependencies"]}
    inventory["dependencies"] = list(unique.values())
    configurations = inventory["android_config"] + inventory["ios_config"]
    if configuration and not any(c["path"] == configuration for c in configurations):
        raise ValueError("Selected source configuration was absent, unreadable, excluded or invalid")
    multiple_apps = any(
        len({app["package"] for app in inventory["apps"] if app["platform"] == platform}) > 1
        for platform in inventory["platforms"]
    )
    multiple_configurations = any(len(inventory[key]) > 1 for key in ("android_config", "ios_config"))
    if source_input and not configuration and (multiple_configurations or multiple_apps):
        inventory["configuration_ambiguous"] = True
        inventory["partial"] = True
        inventory["package"] = ""
        inventory["warnings"].append(
            "Multiple source configurations were observed; select one configuration for an app/variant audit. No build-system merge was performed."
        )
    if not inventory["files_scanned"]:
        if inventory["partial"]:
            raise ValueError(
                "No supported source or configuration files found; inspection incomplete: "
                + inventory["warnings"][0]
            )
        raise ValueError("No supported source or configuration files found")
    return inventory, sources
