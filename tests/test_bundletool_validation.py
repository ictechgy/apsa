"""Validation driver checks use only new synthetic source and compiler outputs."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import os
import shutil
import sys
import zipfile
from pathlib import Path

import pytest
from defusedxml import ElementTree

from mobile_audit.aab_manifest import decode_manifest
from mobile_audit.aab_resources import ResourceResolver


@pytest.fixture
def driver():
    source = Path(__file__).parents[1] / "scripts/validate_bundletool.py"
    spec = importlib.util.spec_from_file_location("fresh_bundletool_driver", source)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_module_compiles_real_manifest_resources_and_dex(driver, tmp_path):
    sdk_value = os.environ.get("APSA_TEST_ANDROID_SDK")
    javac_value = os.environ.get("APSA_TEST_JAVAC") or shutil.which("javac")
    if not sdk_value or not javac_value:
        pytest.skip("Requires designated public SDK/JDK tools; no retained binary fixtures")
    sdk = Path(sdk_value)
    tools = sdk / "build-tools" / os.environ.get("APSA_TEST_ANDROID_BUILD_TOOLS", "36.0.0")
    android = sdk / "platforms" / os.environ.get("APSA_TEST_ANDROID_PLATFORM", "android-36") / "android.jar"
    args = argparse.Namespace(
        aapt2=tools / "aapt2", d8=tools / "d8", android=android, javac=Path(javac_value)
    )
    root = tmp_path / "fresh-module"
    root.mkdir()
    module = driver.compile_module(args, root, driver.Commands(root))
    with zipfile.ZipFile(module) as archive:
        assert archive.read("dex/classes.dex").startswith(b"dex\n")
        manifest, warnings = decode_manifest(archive.read("manifest/AndroidManifest.xml"))
        assert warnings == ["AAB manifest compiled resource attribute remains unresolved: label"]
        assert b"audit.fresh.bundletool" in manifest
        tree = ElementTree.fromstring(manifest)
        uses_sdk = tree.find("uses-sdk")
        assert uses_sdk is not None
        assert uses_sdk.attrib["{http://schemas.android.com/apk/res/android}targetSdkVersion"] == "36"
        resources = ResourceResolver()
        resources.add("base", archive.read("resources.pb"))
        candidates = resources.by_name["audit.fresh.bundletool:string/probe"]
        assert len(candidates) == 2
        assert {candidate.qualified for candidate in candidates} == {False, True}
        # Both genuine density resources survive AAPT2 into the bundle module.
        assert any("hdpi" in name for name in archive.namelist())
        assert any("xhdpi" in name for name in archive.namelist())


def test_new_fixture_failure_keeps_actual_terminal_status(driver, tmp_path):
    commands = driver.Commands(tmp_path)
    with pytest.raises(RuntimeError):
        commands.run(["/usr/bin/false"])
    assert len(commands.records) == 1
    assert commands.records[0]["returncode"] != 0
    assert commands.records[0]["timed_out"] is False
    assert commands.records[0]["output_truncated"] is False


def test_oversized_owned_process_output_is_stopped_at_capture_bound(driver, tmp_path):
    commands = driver.Commands(tmp_path)
    with pytest.raises(RuntimeError):
        commands.run([sys.executable, "-c", "import sys; sys.stdout.buffer.write(b'x' * 2097152)"])
    record = commands.records[0]
    assert record["output_truncated"] is True
    assert record["stdout_bytes"] == 1_048_576
    assert record["stdout_sha256"] == hashlib.sha256(b"x" * 1_048_576).hexdigest()
    assert "stdout_base64" not in record


def test_failure_diagnostic_preserves_status_without_passwords_or_raw_output(driver, tmp_path):
    commands = driver.Commands(tmp_path)
    with pytest.raises(RuntimeError):
        commands.run(["/usr/bin/false"])
    commands.records[0]["argv"] += [
        "--ks-pass=pass:synthetic-only",
        "--key-pass=pass:synthetic-only",
        "-storepass",
        "synthetic-only",
        "-keypass",
        "synthetic-only",
    ]
    observed = driver.failure_diagnostic({"stage": "new-test-failure"}, commands.records)
    assert observed["stage"] == "new-test-failure"
    assert observed["owned_command"]["returncode"] != 0
    serialized = driver.json.dumps(observed)
    assert "synthetic-only" not in serialized
    assert "stdout_base64" not in serialized
    assert "stderr_base64" not in serialized
    assert "stdout_sha256" in serialized


def test_public_command_records_redact_passwords_and_keep_original_stream_hashes(driver, tmp_path):
    commands = driver.Commands(tmp_path)
    argv = [
        sys.executable,
        "-c",
        "import sys; sys.stdout.write(sys.argv[2]); sys.stderr.write(sys.argv[4])",
        "--ks-pass",
        "fresh-secret",
        "--key-pass",
        "fresh-key-secret",
        "--ks-pass=pass:fresh-inline",
        "--key-pass=pass:fresh-key-inline",
        "-storepass",
        "fresh-store-secret",
        "-keypass",
        "fresh-keytool-secret",
        "--ordinary=value",
    ]
    assert commands.run(argv) == "fresh-secret"
    record = commands.records[0]
    assert record["stdout_sha256"] == hashlib.sha256(b"fresh-secret").hexdigest()
    assert record["stderr_sha256"] == hashlib.sha256(b"fresh-key-secret").hexdigest()
    assert record["stdout_bytes"] == len(b"fresh-secret")
    assert record["stderr_bytes"] == len(b"fresh-key-secret")
    assert record["argv"][:3] == argv[:3]
    assert record["argv"][-1] == argv[-1]
    serialized = driver.json.dumps({"commands": commands.records})
    assert all(secret not in serialized for secret in argv[4:] if secret.startswith("fresh-"))
    assert "pass:fresh-inline" not in serialized and "pass:fresh-key-inline" not in serialized
    assert "stdout_base64" not in serialized and "stderr_base64" not in serialized


def test_failure_diagnostic_exposes_bounded_parser_reason_for_cases_and_install(driver):
    selection = {
        "state": "partial",
        "reason": "unsupported_toc",
        "message": "m" * 1000,
        "toc_sha256": "a" * 64,
    }
    observed = driver.failure_diagnostic(
        {
            "stage": "fresh-installed-config-resource-probe",
            "cases": [selection],
            "installed": {"state": "partial", "selection": selection},
        },
        [],
    )
    assert observed["case_states"][0]["message"] == "m" * 256
    assert observed["installed_selection"] == observed["case_states"][0]
    assert observed["case_states"][0]["toc_sha256"] == "a" * 64
