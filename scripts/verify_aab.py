"""Compile only a fresh synthetic protobuf manifest; compare with AAPT2's dump."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import zipfile
from pathlib import Path

from mobile_audit.aab_manifest import decode_manifest
from mobile_audit.inputs import inspect_target


def command(args: list[str]) -> str:
    return subprocess.check_output(args, timeout=60, stderr=subprocess.STDOUT).decode()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--aapt2", type=Path, required=True)
    parser.add_argument("--android", type=Path, required=True)
    parser.add_argument("--work", type=Path, required=True)
    args = parser.parse_args()
    args.work.mkdir(parents=True, exist_ok=False)
    manifest = args.work / "AndroidManifest.xml"
    manifest.write_text(
        '<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="audit.generated">'
        '<uses-sdk android:minSdkVersion="21" android:targetSdkVersion="35"/>'
        '<application android:debuggable="true" android:usesCleartextTraffic="false"/>'
        "</manifest>"
    )
    apk = args.work / "base.apk"
    command(
        [
            str(args.aapt2),
            "link",
            "--proto-format",
            "-I",
            str(args.android),
            "--manifest",
            str(manifest),
            "-o",
            str(apk),
        ]
    )
    dump = command([str(args.aapt2), "dump", "xmltree", str(apk), "--file", "AndroidManifest.xml"])
    (args.work / "aapt2-dump.txt").write_text(dump)
    with zipfile.ZipFile(apk) as archive:
        raw = archive.read("AndroidManifest.xml")
    decoded, warnings = decode_manifest(raw)
    if warnings or b"audit.generated" not in decoded or "audit.generated" not in dump:
        raise ValueError("Generated base manifest differs from the independent AAPT2 observation")
    bundle = args.work / "Generated.aab"
    with zipfile.ZipFile(bundle, "x") as archive:
        archive.writestr("base/manifest/AndroidManifest.xml", raw)
    inventory, _ = inspect_target(bundle)
    configuration = inventory["android_config"][0]
    if not (
        inventory["package"] == "audit.generated"
        and configuration["debuggable"] == "true"
        and configuration["cleartext"] == "false"
        and inventory["android_sdk"] == {"min": "21", "target": "35"}
        and "debuggable" in dump
        and "usesCleartextTraffic" in dump
    ):
        raise ValueError("Generated bundle declaration verification failed")
    result = {
        "fixture": "fresh-synthetic-only-no-upstream-app",
        "aapt2_version": command([str(args.aapt2), "version"]).strip(),
        "aapt2_sha256": hashlib.sha256(args.aapt2.read_bytes()).hexdigest(),
        "android_jar_sha256": hashlib.sha256(args.android.read_bytes()).hexdigest(),
        "manifest_sha256": hashlib.sha256(raw).hexdigest(),
        "independent_dump": dump,
        "observed_configuration": configuration,
        "module_inventory": inventory["android_modules"],
        "resource_merge_verified": False,
        "installed_split_set_verified": False,
    }
    (args.work / "summary.json").write_text(json.dumps(result, indent=2) + "\n")
    print("APSA_GENERATED_AAB_BEGIN")
    print(json.dumps(result))
    print("APSA_GENERATED_AAB_END")


if __name__ == "__main__":
    main()
