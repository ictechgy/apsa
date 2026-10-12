"""Validation driver checks use only new synthetic source and compiler outputs."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import os
import shutil
import stat
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
    aapt2_jar = os.environ.get("APSA_TEST_AAPT2_JAR")
    aapt2_jar_sha256 = os.environ.get("APSA_TEST_AAPT2_JAR_SHA256")
    javac_value = os.environ.get("APSA_TEST_JAVAC") or shutil.which("javac")
    if not sdk_value or not javac_value or not aapt2_jar or not aapt2_jar_sha256:
        pytest.skip("Requires designated public SDK/JDK and pinned AAPT2 JAR; no retained binary fixtures")
    sdk = Path(sdk_value)
    tools = sdk / "build-tools" / os.environ.get("APSA_TEST_ANDROID_BUILD_TOOLS", "36.0.0")
    android = sdk / "platforms" / os.environ.get("APSA_TEST_ANDROID_PLATFORM", "android-36") / "android.jar"
    args = argparse.Namespace(
        aapt2=tools / "aapt2",
        aapt2_jar=Path(aapt2_jar),
        aapt2_jar_sha256=aapt2_jar_sha256,
        d8=tools / "d8",
        android=android,
        javac=Path(javac_value),
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


def test_console_evidence_exposes_only_bounded_hashes_and_controls(driver):
    comparison = {
        "state": "matched",
        "toc_sha256": "a" * 64,
        "apsa_selected_sha256": {"splits/base.apk": "b" * 64},
        "official_extracted_sha256": {"base.apk": "b" * 64},
        "raw_output": "synthetic-secret",
    }
    result = {
        "source": {"head_sha": "c" * 40, "driver_sha256": "d" * 64, "raw_output": "synthetic-secret"},
        "bundletool_version": "1.18.3",
        "artifact_sha256": {"fresh.aab": "e" * 64, "fresh.apks": "f" * 64},
        "cases": [comparison] * 3,
        "commands": [{"argv": ["-keypass", "synthetic-secret"], "stdout_base64": "opaque"}],
        "installed": {
            "state": "verified",
            "selection": comparison,
            "installed_sha256": {"0.apk": "b" * 64},
            "installed_split_set_verified": True,
            "resource_merge_verified": True,
            "resource_probe": {
                "expected_value_sha256": "a" * 64,
                "observed_value_sha256": "a" * 64,
                "value_equal": True,
                "raw_output": "synthetic-secret",
            },
            "package_uninstall_returncode": 0,
        },
    }
    evidence = driver.console_evidence(result)
    assert len(evidence["cases"]) == 3
    assert evidence["cases"][0]["apsa_selected_sha256"] == comparison["apsa_selected_sha256"]
    assert evidence["installed"]["installed_sha256"] == {"0.apk": "b" * 64}
    assert evidence["installed"]["package_uninstall_returncode"] == 0
    assert "synthetic-secret" not in driver.json.dumps(evidence)
    assert "stdout_base64" not in driver.json.dumps(evidence)


@pytest.mark.parametrize(
    "result",
    [
        {"cases": [{"state": "matched"}] * 4},
        {"artifact_sha256": {f"{i}.apk": "a" * 64 for i in range(65)}},
        {"artifact_sha256": {"a" * 257: "a" * 64}},
        {"artifact_sha256": {"fresh.apk": "invalid"}},
    ],
)
def test_console_evidence_rejects_contract_overflow(driver, result):
    with pytest.raises(ValueError):
        driver.console_evidence(result)


def test_resource_probe_evidence_requires_exact_french_value_package_and_code(driver):
    output = (
        "INSTRUMENTATION_RESULT: apsa_resource_value=bonjour-new-fixture\n"
        f"INSTRUMENTATION_RESULT: apsa_resource_package={driver.PACKAGE}\n"
        "INSTRUMENTATION_CODE: -1\n"
    )
    probe = driver.resource_probe_evidence(output, 0)
    assert probe["value_equal"] and probe["package_equal"] and probe["instrumentation_success_code_observed"]
    assert probe["expected_value_sha256"] == probe["observed_value_sha256"]
    assert "bonjour-new-fixture" not in driver.json.dumps(probe)
    assert (
        driver.resource_probe_evidence(output.replace("-1", "-10"), 0)[
            "instrumentation_success_code_observed"
        ]
        is False
    )
    assert (
        driver.resource_probe_evidence(output.replace(driver.PACKAGE, driver.PACKAGE + ".other"), 0)[
            "package_equal"
        ]
        is False
    )
    assert (
        driver.resource_probe_evidence(output.replace("bonjour-new-fixture", "bonjour-new-fixture-other"), 0)[
            "value_equal"
        ]
        is False
    )
    assert driver.resource_probe_evidence(output + output, 0)["value_equal"] is False
    assert (
        driver.resource_probe_evidence(output.replace("bonjour-new-fixture", "x" * 257), 0)[
            "observed_value_sha256"
        ]
        is None
    )


def synthetic_aapt2(tmp_path, entries=None, executable=b"synthetic executable bytes; never run\n"):
    jar = tmp_path / "synthetic-aapt2.jar"
    with zipfile.ZipFile(jar, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, data in entries or [("aapt2", executable), ("META-INF/MANIFEST.MF", b"synthetic\n")]:
            archive.writestr(name, data)
    binary = tmp_path / "synthetic-aapt2"
    binary.write_bytes(executable)
    binary.chmod(0o700)
    return argparse.Namespace(
        aapt2=binary,
        aapt2_jar=jar,
        aapt2_jar_sha256=hashlib.sha256(jar.read_bytes()).hexdigest(),
    )


def test_aapt2_integrity_matches_executable_to_unique_pinned_jar_entry(driver, tmp_path, monkeypatch):
    args = synthetic_aapt2(tmp_path)
    monkeypatch.setattr(driver.Commands, "run", lambda *_args, **_kwargs: pytest.fail("must not execute"))
    evidence = driver.verify_aapt2(args)
    assert evidence["status"] == "verified"
    assert evidence["provenance"] == "predeclared-jar-sha256-and-entry-byte-match"
    assert evidence["jar"]["sha256"] == args.aapt2_jar_sha256
    assert evidence["entry_sha256"] == evidence["executable"]["sha256"]
    assert str(tmp_path) not in driver.json.dumps(evidence)


@pytest.mark.parametrize("mutate", ["jar", "executable", "truncated-jar", "truncated-executable"])
def test_aapt2_mutation_or_truncation_fails_before_compile_execution(driver, tmp_path, monkeypatch, mutate):
    args = synthetic_aapt2(tmp_path)
    path = args.aapt2_jar if "jar" in mutate else args.aapt2
    original = path.read_bytes()
    if mutate.startswith("truncated"):
        path.write_bytes(original[:-1])
    else:
        changed = bytearray(original)
        changed[len(changed) // 2] ^= 1
        path.write_bytes(changed)
    monkeypatch.setattr(driver.Commands, "run", lambda *_args, **_kwargs: pytest.fail("must not execute"))
    with pytest.raises(driver.Aapt2IntegrityError) as caught:
        driver.compile_module(args, tmp_path, driver.Commands(tmp_path))
    assert caught.value.evidence["status"] == "failed"
    assert not (tmp_path / "AndroidManifest.xml").exists()


@pytest.mark.parametrize("pin", [None, "", "a" * 63, "a" * 65, "g" * 64, "a" * 64 + "\n"])
def test_aapt2_missing_or_bad_pin_fails_before_input_read_or_execution(driver, tmp_path, monkeypatch, pin):
    args = synthetic_aapt2(tmp_path)
    args.aapt2_jar_sha256 = pin
    monkeypatch.setattr(driver.os, "open", lambda *_args, **_kwargs: pytest.fail("must not open"))
    monkeypatch.setattr(driver.Commands, "run", lambda *_args, **_kwargs: pytest.fail("must not execute"))
    with pytest.raises(driver.Aapt2IntegrityError) as caught:
        driver.compile_module(args, tmp_path, driver.Commands(tmp_path))
    assert caught.value.evidence["jar"]["reason"] == "invalid_expected_sha256"


@pytest.mark.parametrize("name", ["../aapt2", "/aapt2", "bin/aapt2", "./aapt2", "bin\\aapt2"])
def test_aapt2_path_entries_are_rejected_even_when_jar_is_pinned(driver, tmp_path, name):
    args = synthetic_aapt2(
        tmp_path, entries=[("aapt2", b"synthetic"), (name, b"synthetic")], executable=b"synthetic"
    )
    with pytest.raises(driver.Aapt2IntegrityError, match="aapt2_jar_unsafe_entry_path"):
        driver.verify_aapt2(args)


def test_aapt2_duplicate_entries_are_rejected_even_when_jar_is_pinned(driver, tmp_path):
    with pytest.warns(UserWarning, match="Duplicate name"):
        args = synthetic_aapt2(tmp_path, entries=[("aapt2", b"synthetic"), ("aapt2", b"different")])
    with pytest.raises(driver.Aapt2IntegrityError, match="aapt2_jar_duplicate_entry"):
        driver.verify_aapt2(args)


def test_aapt2_symlink_entry_is_rejected_even_when_jar_is_pinned(driver, tmp_path):
    link = zipfile.ZipInfo("aapt2")
    link.create_system = 3
    link.external_attr = (stat.S_IFLNK | 0o777) << 16
    args = synthetic_aapt2(tmp_path, entries=[(link, b"synthetic-link-target")])
    with pytest.raises(driver.Aapt2IntegrityError, match="aapt2_jar_symlink_entry"):
        driver.verify_aapt2(args)


@pytest.mark.parametrize("kind", ["missing-entry", "empty-entry", "oversized-entry", "invalid-zip"])
def test_aapt2_invalid_jar_structure_is_rejected(driver, tmp_path, monkeypatch, kind):
    entries = [("other-tool", b"synthetic")] if kind == "missing-entry" else [("aapt2", b"")]
    if kind == "oversized-entry":
        entries = [("aapt2", b"x" * 300)]
        monkeypatch.setattr(driver, "AAPT2_MAX_BYTES", 200)
    args = synthetic_aapt2(tmp_path, entries=entries)
    if kind == "invalid-zip":
        args.aapt2_jar.write_bytes(b"new synthetic non-ZIP bytes")
        args.aapt2_jar_sha256 = hashlib.sha256(args.aapt2_jar.read_bytes()).hexdigest()
    with pytest.raises(driver.Aapt2IntegrityError):
        driver.verify_aapt2(args)


@pytest.mark.parametrize("kind", ["symlink", "empty", "not-executable"])
def test_aapt2_unsafe_executable_is_rejected(driver, tmp_path, kind):
    args = synthetic_aapt2(tmp_path)
    if kind == "symlink":
        target = tmp_path / "synthetic-target"
        args.aapt2.rename(target)
        args.aapt2.symlink_to(target)
    elif kind == "empty":
        args.aapt2.write_bytes(b"")
    else:
        args.aapt2.chmod(0o600)
    with pytest.raises(driver.Aapt2IntegrityError):
        driver.verify_aapt2(args)


@pytest.mark.parametrize("compile_only", [False, True])
def test_main_aapt2_guard_precedes_all_tool_execution_and_records_failure(
    driver, tmp_path, monkeypatch, capsys, compile_only
):
    args = synthetic_aapt2(tmp_path)
    args.aapt2.write_bytes(b"new synthetic mutation")
    work = tmp_path / "fresh-driver-work"
    argv = [
        "validate_bundletool.py",
        "--work",
        str(work),
        "--aapt2",
        str(args.aapt2),
        "--aapt2-jar",
        str(args.aapt2_jar),
        "--aapt2-jar-sha256",
        args.aapt2_jar_sha256,
    ]
    for name in ("android", "javac", "java", "keytool", "d8"):
        argv += [f"--{name}", str(tmp_path / f"unused-{name}")]
    if compile_only:
        argv.append("--compile-only")
    monkeypatch.setenv("RUNNER_TEMP", str(tmp_path.resolve()))
    monkeypatch.setattr(sys, "argv", argv)
    monkeypatch.setattr(driver.Commands, "run", lambda *_args, **_kwargs: pytest.fail("must not execute"))
    with pytest.raises(SystemExit) as caught:
        driver.main()
    assert caught.value.code == 1
    output = driver.json.loads(capsys.readouterr().out)
    assert output["failure"]["stage"] == "aapt2-integrity"
    assert output["failure"]["owned_command"] is None
    assert output["validation"]["aapt2_integrity"]["status"] == "failed"
    summary = driver.json.loads((work / "evidence/summary.json").read_text())
    assert summary["commands"] == []
