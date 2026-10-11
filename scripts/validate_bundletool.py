#!/usr/bin/env python3
"""Official bundletool oracle on freshly compiled base/config resources only.

No corpus, existing devices, APK input, TOC fabrication, or local downloads.
The optional device is explicitly owned by this disposable GitHub CI job.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import selectors
import signal
import struct
import subprocess
import time
import zipfile
import zlib
from pathlib import Path

from mobile_audit.apks_selection import ApkSetSelectionError, select_apks

BUNDLETOOL_VERSION = "1.18.3"
BUNDLETOOL_SHA256 = "a099cfa1543f55593bc2ed16a70a7c67fe54b1747bb7301f37fdfd6d91028e29"
PACKAGE = "audit.fresh.bundletool"
REFERENCES = [
    "https://github.com/google/bundletool/releases/expanded_assets/1.18.3",
    "https://developer.android.com/tools/bundletool",
    "https://developer.android.com/build/building-cmdline#bundletool-build",
    "https://github.com/google/bundletool/blob/1.18.3/src/main/proto/commands.proto",
]


def sha(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def png(red: int, blue: int) -> bytes:
    """New one-pixel resource fixture, generated without existing image inputs."""

    def chunk(kind: bytes, data: bytes) -> bytes:
        return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data))

    return (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0))
        + chunk(b"IDAT", zlib.compress(bytes([0, red, 0, blue])))
        + chunk(b"IEND", b"")
    )


def write_sources(root: Path) -> list[Path]:
    sources = {
        "BundleConfig.json": json.dumps({"optimizations": {"storeArchive": {"enabled": False}}}),
        "AndroidManifest.xml": (
            '<manifest xmlns:android="http://schemas.android.com/apk/res/android" '
            f'package="{PACKAGE}" android:versionCode="1" android:versionName="1">'
            '<uses-sdk android:minSdkVersion="21" android:targetSdkVersion="36"/>'
            '<application android:debuggable="true" android:label="@string/probe" '
            'android:hasCode="true"/>'
            f'<instrumentation android:name="{PACKAGE}.Probe" android:targetPackage="{PACKAGE}"/>'
            "</manifest>"
        ),
        "res/values/strings.xml": '<resources><string name="probe">hello-new-fixture</string></resources>',
        "res/values-fr/strings.xml": '<resources><string name="probe">bonjour-new-fixture</string></resources>',
        "Probe.java": f'''package {PACKAGE};
import android.app.Instrumentation;
import android.content.res.Configuration;
import android.content.res.Resources;
import android.os.Bundle;
import java.util.Locale;
public final class Probe extends Instrumentation {{
  public void onCreate(Bundle args) {{ super.onCreate(args); start(); }}
  public void onStart() {{
    Bundle result = new Bundle();
    try {{
      Configuration config = new Configuration(getTargetContext().getResources().getConfiguration());
      config.setLocale(Locale.FRENCH);
      Resources resources = getTargetContext().createConfigurationContext(config).getResources();
      int id = resources.getIdentifier("probe", "string", "{PACKAGE}");
      String value = resources.getString(id);
      result.putString("apsa_resource_value", value);
      result.putString("apsa_resource_package", getTargetContext().getPackageName());
      finish(value.equals("bonjour-new-fixture") ? -1 : 0, result);
    }} catch (Throwable error) {{
      result.putString("apsa_resource_error", error.getClass().getName());
      finish(0, result);
    }}
  }}
}}
''',
    }
    for name, value in sources.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(value)
    for density, red, blue in (("hdpi", 255, 0), ("xhdpi", 0, 255)):
        path = root / "res" / f"drawable-{density}" / "probe.png"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(png(red, blue))
        sources[str(path.relative_to(root))] = ""
    return [root / name for name in sources]


def redact_argv(argv: list[str]) -> list[str]:
    """Keep replayable nonsecret arguments; never persist signing passwords."""
    result = []
    password_next = False
    for argument in argv:
        if password_next:
            result.append("[REDACTED]")
            password_next = False
        elif argument in {"-storepass", "-keypass", "--ks-pass", "--key-pass"}:
            result.append(argument)
            password_next = True
        elif argument.startswith(("--ks-pass=", "--key-pass=")):
            result.append(argument.split("=", 1)[0] + "=[REDACTED]")
        else:
            result.append(argument)
    return result


class Commands:
    def __init__(self, root: Path):
        self.root = root
        self.records: list[dict] = []

    def run(self, argv: list[str], *, timeout: int = 120) -> str:
        started = time.monotonic()
        process = subprocess.Popen(
            argv,
            cwd=self.root,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
        assert process.stdout is not None and process.stderr is not None
        selector = selectors.DefaultSelector()
        selector.register(process.stdout, selectors.EVENT_READ, "stdout")
        selector.register(process.stderr, selectors.EVENT_READ, "stderr")
        streams = {"stdout": bytearray(), "stderr": bytearray()}
        timed_out = truncated = False
        try:
            while selector.get_map():
                if time.monotonic() - started >= timeout:
                    timed_out = True
                    break
                for key, _ in selector.select(0.05):
                    raw = os.read(key.fd, 65536)
                    if not raw:
                        selector.unregister(key.fileobj)
                        continue
                    stream = streams[key.data]
                    remaining = 1_048_576 - len(stream)
                    stream.extend(raw[:remaining])
                    if len(raw) > remaining:
                        truncated = True
                        break
                if truncated:
                    break
            if not timed_out and not truncated:
                try:
                    process.wait(timeout=max(0.001, timeout - (time.monotonic() - started)))
                except subprocess.TimeoutExpired:
                    timed_out = True
        finally:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait()
            selector.close()
            process.stdout.close()
            process.stderr.close()
        stdout, stderr = bytes(streams["stdout"]), bytes(streams["stderr"])
        self.records.append(
            {
                "argv": redact_argv(argv),
                "returncode": process.returncode,
                "timed_out": timed_out,
                "output_truncated": truncated,
                "elapsed_seconds": time.monotonic() - started,
                "stdout_bytes": len(stdout),
                "stderr_bytes": len(stderr),
                "stream_hash_scope": "captured-bytes-before-redaction",
                "stdout_sha256": hashlib.sha256(stdout).hexdigest(),
                "stderr_sha256": hashlib.sha256(stderr).hexdigest(),
            }
        )
        if process.returncode != 0 or timed_out or truncated:
            raise RuntimeError(f"Fresh fixture command failed: {argv[0]} ({process.returncode})")
        return stdout.decode("utf-8", errors="replace")


def failure_diagnostic(result: dict, records: list[dict]) -> dict:
    """Expose owned terminal metadata without password arguments or raw streams."""
    failures = [
        item for item in records if item["returncode"] != 0 or item["timed_out"] or item["output_truncated"]
    ]
    record = failures[-1] if failures else records[-1] if records else None
    metadata = None
    if record is not None:
        metadata = {
            key: record[key]
            for key in (
                "returncode",
                "timed_out",
                "output_truncated",
                "elapsed_seconds",
                "stdout_bytes",
                "stderr_bytes",
                "stream_hash_scope",
                "stdout_sha256",
                "stderr_sha256",
            )
        }
        metadata["argv"] = redact_argv(record["argv"])

    def selection_metadata(case: dict) -> dict:
        # Parser messages contain bounded schema labels, never APK contents.
        return {
            "state": case["state"],
            "reason": case.get("reason"),
            "message": case.get("message", "")[:256],
            "toc_sha256": case.get("toc_sha256"),
        }

    return {
        "stage": result["stage"],
        "error_type": result.get("error", {}).get("type"),
        "owned_command": metadata,
        "case_states": [selection_metadata(case) for case in result.get("cases", [])],
        "installed_state": result.get("installed", {}).get("state"),
        "installed_selection": (
            selection_metadata(result["installed"]["selection"])
            if "selection" in result.get("installed", {})
            else None
        ),
    }


def compile_module(args: argparse.Namespace, root: Path, commands: Commands) -> Path:
    write_sources(root)
    resources = root / "compiled-res.zip"
    commands.run([str(args.aapt2), "compile", "--dir", str(root / "res"), "-o", str(resources)])
    linked = root / "base-proto.apk"
    commands.run(
        [
            str(args.aapt2),
            "link",
            "--proto-format",
            "-I",
            str(args.android),
            "--manifest",
            str(root / "AndroidManifest.xml"),
            "-o",
            str(linked),
            "-R",
            str(resources),
            "--auto-add-overlay",
        ]
    )
    classes, dex = root / "classes", root / "dex"
    classes.mkdir()
    dex.mkdir()
    commands.run(
        [
            str(args.javac),
            "--release",
            "8",
            "-classpath",
            str(args.android),
            "-d",
            str(classes),
            str(root / "Probe.java"),
        ]
    )
    commands.run(
        [
            str(args.d8),
            "--lib",
            str(args.android),
            "--min-api",
            "21",
            "--output",
            str(dex),
            str(classes / "audit/fresh/bundletool/Probe.class"),
        ]
    )
    module = root / "base.zip"
    with zipfile.ZipFile(linked) as apk, zipfile.ZipFile(module, "x") as target:
        for name in apk.namelist():
            destination = "manifest/AndroidManifest.xml" if name == "AndroidManifest.xml" else name
            target.writestr(destination, apk.read(name))
        target.write(dex / "classes.dex", "dex/classes.dex")
    return module


def compare_extracted(apks: Path, extracted: Path, device: dict) -> dict:
    """Compare immutable byte hashes; bundletool controls names in extraction."""
    official_files = sorted(extracted.rglob("*.apk"))
    if not official_files or len(official_files) > 64:
        raise ValueError("Official extraction must contain a bounded nonempty APK set")
    official = {str(path.relative_to(extracted)): sha(path) for path in official_files}
    with zipfile.ZipFile(apks) as archive:
        raw_toc = archive.read("toc.pb")
        try:
            selection = select_apks(raw_toc, device, archive.namelist())
        except ApkSetSelectionError as error:
            return {
                "state": "partial",
                "reason": error.code,
                "message": str(error),
                "official_extracted_sha256": official,
                "device_spec": device,
                "toc_sha256": hashlib.sha256(raw_toc).hexdigest(),
            }
        observed = {
            item.path: hashlib.sha256(archive.read(item.path)).hexdigest() for item in selection.selected_apks
        }
    # Distinct paths with duplicate bytes are not accepted as a set comparison.
    matches = sorted(observed.values()) == sorted(official.values())
    return {
        "state": "matched" if matches else "mismatch",
        "device_spec": device,
        "apsa_selection": selection.as_dict(),
        "apsa_selected_sha256": observed,
        "official_extracted_sha256": official,
    }


def install_probe(
    args: argparse.Namespace, root: Path, commands: Commands, bundle: list[str], apks: Path
) -> dict:
    if os.environ.get("GITHUB_ACTIONS") != "true" or not args.serial.startswith("emulator-"):
        raise ValueError("Device operations require the explicitly fresh remote CI emulator")
    adb = [str(args.adb), "-P", str(args.adb_port), "-s", args.serial]
    spec_path = root / "device-acquired.json"
    commands.run(
        bundle
        + [
            "get-device-spec",
            f"--adb={args.adb}",
            f"--device-id={args.serial}",
            f"--output={spec_path}",
        ]
    )
    actual = json.loads(spec_path.read_text())
    # Explicit synthetic locale override; device-derived hardware dimensions are retained.
    device = {
        key: actual[key] for key in ("supportedAbis", "screenDensity", "sdkVersion", "supportedLocales")
    }
    device["supportedLocales"] = ["en-US", "fr-FR"]
    probe_spec = root / "device-resource-probe.json"
    probe_spec.write_text(json.dumps(device))
    extracted = root / "installed-selected"
    commands.run(
        bundle
        + ["extract-apks", f"--apks={apks}", f"--device-spec={probe_spec}", f"--output-dir={extracted}"]
    )
    comparison = compare_extracted(apks, extracted, device)
    if comparison["state"] != "matched":
        return {"state": "partial", "selection": comparison, "resource_merge_verified": False}
    selected = sorted(extracted.rglob("*.apk"))
    commands.run(adb + ["install-multiple", *map(str, selected)])
    try:
        installed_paths = commands.run(adb + ["shell", "pm", "path", PACKAGE]).splitlines()
        installed = root / "installed-acquired"
        installed.mkdir()
        acquired = {}
        for index, line in enumerate(installed_paths):
            if not line.startswith("package:/data/app/") or not line.endswith(".apk"):
                raise ValueError("Unexpected new package acquisition path")
            destination = installed / f"{index}.apk"
            commands.run(adb + ["pull", line.removeprefix("package:"), str(destination)])
            acquired[destination.name] = sha(destination)
        hashes_match = sorted(acquired.values()) == sorted(sha(path) for path in selected)
        output = commands.run(adb + ["shell", "am", "instrument", "-w", f"{PACKAGE}/.Probe"])
        merged = (
            "INSTRUMENTATION_RESULT: apsa_resource_value=bonjour-new-fixture" in output
            and f"INSTRUMENTATION_RESULT: apsa_resource_package={PACKAGE}" in output
            and "INSTRUMENTATION_CODE: -1" in output
        )
        return {
            "state": "verified" if merged and hashes_match else "mismatch",
            "acquired_device_spec": actual,
            "explicit_locale_override": device["supportedLocales"],
            "selection": comparison,
            "installed_sha256": acquired,
            "installed_split_set_verified": hashes_match,
            "resource_merge_verified": merged,
            "scope": "fresh base plus language/density config only; no feature, ABI, or physical-device claim",
        }
    finally:
        commands.run(adb + ["uninstall", PACKAGE])


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("work", "aapt2", "android", "javac", "java", "keytool", "d8"):
        parser.add_argument(f"--{name}", type=Path, required=True)
    parser.add_argument("--bundletool", type=Path)
    parser.add_argument("--compile-only", action="store_true")
    parser.add_argument("--serial")
    parser.add_argument("--adb", type=Path)
    parser.add_argument("--adb-port", type=int, default=5038)
    args = parser.parse_args()
    # The caller creates only this fresh child; existing work data is never accepted.
    root = args.work.resolve()
    if not any(
        root.is_relative_to(Path(prefix))
        for prefix in ("/private/tmp", "/tmp", os.environ.get("RUNNER_TEMP", "/tmp"))
    ):
        raise ValueError("Fresh fixtures must stay outside protected project/runtime locations")
    root.mkdir(parents=True, exist_ok=False)
    commands = Commands(root)
    result = {
        "schema_version": 1,
        "fixture": "new-aapt2-d8-base-config-only",
        "references": REFERENCES,
        "resource_merge_verified": False,
        "installed_split_set_verified": False,
        "state": "started",
        "stage": "tool-input-hashes",
    }
    exit_code = 1
    try:
        tool_paths = [
            args.aapt2,
            args.android,
            args.javac,
            args.java,
            args.keytool,
            args.d8,
            args.d8.parent / "lib/d8.jar",
        ]
        result["tool_sha256"] = {str(path): sha(path) for path in tool_paths}
        if (args.aapt2.parent / "aapt2.jar").is_file():
            result["tool_sha256"][str(args.aapt2.parent / "aapt2.jar")] = sha(args.aapt2.parent / "aapt2.jar")
        result["stage"] = "compiler-version-probes"
        commands.run([str(args.aapt2), "version"])
        commands.run([str(args.javac), "-version"])
        commands.run([str(args.d8), "--version"])
        result["stage"] = "fresh-module-compilation"
        module = compile_module(args, root, commands)
        result["source_sha256"] = {
            str(path.relative_to(root)): sha(path)
            for path in [
                root / "Probe.java",
                root / "AndroidManifest.xml",
                root / "BundleConfig.json",
                *sorted((root / "res").rglob("*")),
            ]
            if path.is_file()
        }
        result["module_sha256"] = sha(module)
        if args.compile_only:
            result["state"] = "compiled-only-official-bundletool-not-executed"
            exit_code = 0
        else:
            result["stage"] = "official-bundletool-pin-check"
            if args.bundletool is None or sha(args.bundletool) != BUNDLETOOL_SHA256:
                raise ValueError("Official bundletool artifact must match the pinned release checksum")
            bundle = [str(args.java), "-jar", str(args.bundletool)]
            version = commands.run(bundle + ["version"]).strip()
            if version != BUNDLETOOL_VERSION:
                raise ValueError("Official bundletool executable version mismatch")
            result["bundletool_version"] = version
            result["tool_sha256"][str(args.bundletool)] = sha(args.bundletool)
            aab, apks = root / "fresh.aab", root / "fresh.apks"
            result["stage"] = "official-build-bundle"
            commands.run(
                bundle
                + [
                    "build-bundle",
                    f"--modules={module}",
                    f"--output={aab}",
                    f"--config={root / 'BundleConfig.json'}",
                ]
            )
            result["stage"] = "official-validate-bundle"
            commands.run(bundle + ["validate", f"--bundle={aab}"])
            keystore = root / "fresh-test-key.jks"
            result["stage"] = "fresh-synthetic-signing-key"
            commands.run(
                [
                    str(args.keytool),
                    "-genkeypair",
                    "-keystore",
                    str(keystore),
                    "-storepass",
                    "synthetic-only",
                    "-keypass",
                    "synthetic-only",
                    "-alias",
                    "fresh",
                    "-keyalg",
                    "RSA",
                    "-dname",
                    "CN=Fresh Synthetic",
                    "-validity",
                    "1",
                ]
            )
            result["stage"] = "official-build-apks"
            commands.run(
                bundle
                + [
                    "build-apks",
                    f"--bundle={aab}",
                    f"--output={apks}",
                    f"--aapt2={args.aapt2}",
                    f"--ks={keystore}",
                    "--ks-pass=pass:synthetic-only",
                    "--ks-key-alias=fresh",
                    "--key-pass=pass:synthetic-only",
                ],
                timeout=300,
            )
            cases = []
            for index, (density, locales) in enumerate(
                ((240, ["en-US"]), (320, ["fr-FR"]), (213, ["en-US", "fr-FR"]))
            ):
                result["stage"] = f"official-extract-and-compare-{index}"
                device = {
                    "sdkVersion": 36,
                    "supportedAbis": ["x86_64", "x86"],
                    "screenDensity": density,
                    "supportedLocales": locales,
                }
                spec = root / f"spec-{index}.json"
                spec.write_text(json.dumps(device))
                extracted = root / f"selected-{index}"
                commands.run(
                    bundle
                    + ["extract-apks", f"--apks={apks}", f"--device-spec={spec}", f"--output-dir={extracted}"]
                )
                cases.append(compare_extracted(apks, extracted, device))
            result["cases"] = cases
            result["artifact_sha256"] = {aab.name: sha(aab), apks.name: sha(apks)}
            result["state"] = "matched" if all(case["state"] == "matched" for case in cases) else "partial"
            if any(case["state"] == "mismatch" for case in cases):
                result["state"] = "mismatch"
            if args.serial:
                if not args.adb:
                    raise ValueError("Explicit adb required for a fresh device")
                result["stage"] = "fresh-installed-config-resource-probe"
                result["installed"] = install_probe(args, root, commands, bundle, apks)
                result["resource_merge_verified"] = result["installed"].get("resource_merge_verified", False)
                result["installed_split_set_verified"] = result["installed"].get(
                    "installed_split_set_verified", False
                )
            exit_code = (
                0
                if result["state"] == "matched"
                and (not args.serial or result["installed"]["state"] == "verified")
                else 1
            )
    except Exception as error:
        result["state"] = "execution-failed"
        result["error"] = {"type": type(error).__name__, "message": str(error)}
    finally:
        result["commands"] = commands.records
        evidence = root / "evidence"
        evidence.mkdir()
        (evidence / "summary.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
        output = {"state": result["state"], "evidence": str(evidence / "summary.json")}
        if exit_code:
            output["failure"] = failure_diagnostic(result, commands.records)
        print(json.dumps(output))
    raise SystemExit(exit_code)


if __name__ == "__main__":
    main()
