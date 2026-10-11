"""Compile fresh fixture APKs with javac and Android SDK d8; never install them."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import zipfile
from pathlib import Path

MANIFEST = b'<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="audit.fixture"><uses-sdk android:minSdkVersion="23" android:targetSdkVersion="36"/><application android:debuggable="false"/></manifest>'


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def build_fixtures(
    *,
    sdk: Path,
    output_dir: Path,
    source_dir: Path | None = None,
    platform: str = "android-36",
    build_tools: str = "36.0.0",
    javac: str | None = None,
    overwrite: bool = False,
    compile_manifest: bool = False,
    environment: dict[str, str] | None = None,
) -> dict:
    """Read only Java source and compiler inputs; write new APKs and provenance.

    The explicit output seam permits privacy-safe tests/release smoke outside the
    checkout. Existing output is refused before any build unless requested by a
    user rebuilding their public fixture set.
    """
    output_dir = output_dir.expanduser().resolve()
    if output_dir.exists() and not overwrite:
        raise ValueError("Fixture output directory already exists; refusing to overwrite it")
    source_dir = (source_dir or Path(__file__).parent).expanduser().resolve()
    sdk = sdk.expanduser().resolve()
    javac = javac or shutil.which("javac")
    if javac is None:
        raise ValueError("javac is required to rebuild these fixtures")
    javac_path = Path(shutil.which(javac) or javac).resolve()
    android_jar = sdk / "platforms" / platform / "android.jar"
    d8 = sdk / "build-tools" / build_tools / "d8"
    output_dir.mkdir(parents=True, exist_ok=overwrite)
    evidence = {
        "schema_version": 1,
        "synthetic": True,
        "installed_or_run": False,
        "compiler_inputs": {
            str(javac_path): sha256(javac_path),
            str(d8): sha256(d8),
            str(android_jar): sha256(android_jar),
        },
        "commands": [],
        "sources": {},
        "artifacts": {},
    }
    d8_jar = d8.parent / "lib" / "d8.jar"
    if d8_jar.is_file():
        evidence["compiler_inputs"][str(d8_jar)] = sha256(d8_jar)
    proof = output_dir / "fixture-provenance.json"

    def save() -> None:
        proof.write_text(json.dumps(evidence, sort_keys=True, indent=2) + "\n")

    def invoke(arguments: list[str], cwd: Path) -> None:
        record = {"argv": arguments, "cwd": str(cwd)}
        try:
            result = subprocess.run(
                arguments,
                cwd=cwd,
                env=environment,
                capture_output=True,
                text=True,
                timeout=60,
                check=False,
            )
            record.update(status=result.returncode, stdout=result.stdout, stderr=result.stderr)
        except (OSError, subprocess.TimeoutExpired) as error:
            record.update(status=None, stdout="", stderr=str(error))
            evidence["commands"].append(record)
            save()
            raise
        evidence["commands"].append(record)
        save()
        if result.returncode:
            raise RuntimeError(f"Synthetic fixture compiler failed: {arguments[0]} ({result.returncode})")

    invoke([str(javac_path), "-version"], output_dir)
    invoke([str(d8), "--version"], output_dir)
    manifest = MANIFEST
    evidence["manifest"] = {
        "format": "plaintext",
        "source_utf8": MANIFEST.decode(),
        "source_sha256": hashlib.sha256(MANIFEST).hexdigest(),
    }
    if compile_manifest:
        aapt2 = sdk / "build-tools" / build_tools / "aapt2"
        evidence["compiler_inputs"][str(aapt2)] = sha256(aapt2)
        invoke([str(aapt2), "version"], output_dir)
        with tempfile.TemporaryDirectory(prefix="manifest-", dir=output_dir) as temporary:
            root = Path(temporary)
            source_manifest = root / "AndroidManifest.xml"
            source_manifest.write_bytes(MANIFEST)
            compiled_manifest = root / "manifest.apk"
            invoke(
                [
                    str(aapt2),
                    "link",
                    "-I",
                    str(android_jar),
                    "--manifest",
                    str(source_manifest),
                    "-o",
                    str(compiled_manifest),
                ],
                root,
            )
            with zipfile.ZipFile(compiled_manifest) as archive:
                manifest = archive.read("AndroidManifest.xml")
            evidence["manifest"].update(
                format="android-binary-xml",
                compiled_sha256=hashlib.sha256(manifest).hexdigest(),
                compiler_output_sha256=sha256(compiled_manifest),
            )
        save()
    for variant in ("unsafe", "safe"):
        source = source_dir / variant / "Calls.java"
        evidence["sources"][variant] = {"path": str(source), "sha256": sha256(source)}
        # Build intermediates are also new and outside the source fixture tree.
        with tempfile.TemporaryDirectory(prefix="compile-", dir=output_dir) as temporary:
            root = Path(temporary)
            classes, dex = root / "classes", root / "dex"
            classes.mkdir()
            dex.mkdir()
            invoke(
                [
                    str(javac_path),
                    "--release",
                    "8",
                    "-classpath",
                    str(android_jar),
                    "-d",
                    str(classes),
                    str(source),
                ],
                root,
            )
            invoke(
                [
                    str(d8),
                    "--lib",
                    str(android_jar),
                    "--min-api",
                    "23",
                    "--output",
                    str(dex),
                    str(classes / "audit/fixture/Calls.class"),
                ],
                root,
            )
            compiled_class = classes / "audit/fixture/Calls.class"
            compiled_dex = dex / "classes.dex"
            evidence["sources"][variant]["compiled_class_sha256"] = sha256(compiled_class)
            evidence["sources"][variant]["compiled_dex_sha256"] = sha256(compiled_dex)
            artifact = output_dir / f"{variant}.apk"
            with zipfile.ZipFile(
                artifact,
                "w" if overwrite else "x",
                compression=zipfile.ZIP_DEFLATED,
            ) as archive:
                for name, raw in (
                    ("AndroidManifest.xml", manifest),
                    ("classes.dex", (dex / "classes.dex").read_bytes()),
                ):
                    entry = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
                    entry.compress_type = zipfile.ZIP_DEFLATED
                    archive.writestr(entry, raw)
            evidence["artifacts"][variant] = {"path": str(artifact), "sha256": sha256(artifact)}
            save()
    return evidence


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--sdk", type=Path, required=True)
    parser.add_argument("--platform", default="android-36")
    parser.add_argument("--build-tools", default="36.0.0")
    parser.add_argument("--javac", help="Explicit javac executable, independent of PATH")
    parser.add_argument(
        "--output-dir",
        type=Path,
        help="New output directory; omission retains the public fixture rebuild command",
    )
    parser.add_argument(
        "--overwrite", action="store_true", help="Explicitly rebuild existing public fixtures"
    )
    parser.add_argument(
        "--compiled-manifest", action="store_true", help="Compile a real binary manifest with aapt2"
    )
    args = parser.parse_args()
    print(
        json.dumps(
            build_fixtures(
                sdk=args.sdk,
                output_dir=args.output_dir or Path(__file__).parent,
                platform=args.platform,
                build_tools=args.build_tools,
                javac=args.javac,
                overwrite=args.overwrite or args.output_dir is None,
                compile_manifest=args.compiled_manifest,
                environment=dict(os.environ),
            ),
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
