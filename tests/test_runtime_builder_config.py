"""Explicit mobile fixture build configuration with fresh mock SDK/JDK files only."""

from __future__ import annotations

import importlib.util
import json
import plistlib
import shutil
import subprocess
import zipfile
from pathlib import Path

import pytest


@pytest.fixture
def builder():
    source = Path(__file__).parent / "fixtures/runtime/build_evidence.py"
    spec = importlib.util.spec_from_file_location("new_runtime_fixture_builder", source)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def config(tmp_path):
    jdk = tmp_path / "new-jdk" / "bin"
    sdk = tmp_path / "new-sdk"
    host = tmp_path / "new-host-bin"
    tools = [jdk / name for name in ("java", "javac", "keytool")]
    tools += [sdk / "build-tools" / "35.0.1" / name for name in ("aapt2", "d8", "zipalign", "apksigner")]
    tools += [host / name for name in ("xcrun", "codesign")]
    for path in tools:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("# NEW inert synthetic tool; never execute\n")
        path.chmod(0o755)
    jar = sdk / "platforms/android-35/android.jar"
    jar.parent.mkdir(parents=True)
    jar.write_bytes(b"NEW inert synthetic jar; never execute")
    return {
        "jdk_bin": jdk,
        "sdk": sdk,
        "android_platform": "android-35",
        "build_tools": "35.0.1",
        "ios_sdk": "iphonesimulator27.0",
        "ios_runtime": "com.apple.CoreSimulator.SimRuntime.iOS-18-2",
        "ios_target": "x86_64-apple-ios18.1-simulator",
        "environment": {"PATH": str(host)},
    }


def test_explicit_config_and_known_environment_fallbacks(builder, config):
    expected = builder.resolve_build_config(**config)
    assert expected.android_platform == "android-35" and expected.ios_minimum == "18.1"
    for jdk_variable in ("APSA_TEST_JAVA_HOME", "JAVA_HOME"):
        for sdk_variable in ("APSA_TEST_ANDROID_SDK_ROOT", "ANDROID_SDK_ROOT", "ANDROID_HOME"):
            fallback = {**config, "jdk_bin": None, "sdk": None}
            fallback["environment"] = {
                **config["environment"],
                jdk_variable: str(config["jdk_bin"].parent),
                sdk_variable: str(config["sdk"]),
            }
            assert builder.resolve_build_config(**fallback) == expected
    fallback = {**config, "jdk_bin": None}
    fallback["environment"] = {"PATH": str(config["jdk_bin"]) + ":" + config["environment"]["PATH"]}
    assert builder.resolve_build_config(**fallback) == expected


@pytest.mark.parametrize(
    "change",
    [
        {"android_platform": "../android-35"},
        {"android_platform": "android-0"},
        {"android_platform": True},
        {"build_tools": "../35.0.1"},
        {"build_tools": "35.0"},
        {"android_platform": "android-25"},
        {"sdk": "new-incorrect-path-type"},
        {"jdk_bin": "new-incorrect-path-type"},
        {"environment": {"PATH": None}},
        {"ios_sdk": "iphoneos"},
        {"ios_sdk": "../iphonesimulator"},
        {"ios_sdk": "iphonesimulator18.0"},
        {"ios_runtime": "default"},
        {"ios_runtime": "booted"},
        {"ios_runtime": None},
        {"ios_target": "arm64-apple-ios18.3-simulator"},
        {"ios_target": "default"},
        {"ios_target": "arm64-apple-ios18.0"},
        {"ios_target": None},
    ],
)
def test_invalid_components_fail_before_filesystem_or_process_operations(
    builder, config, tmp_path, monkeypatch, change
):
    def denied(*args, **kwargs):
        pytest.fail("No filesystem/source/SDK/process operation is allowed before component validation")

    monkeypatch.setattr(Path, "stat", denied)
    monkeypatch.setattr(Path, "mkdir", denied)
    monkeypatch.setattr(builder.shutil, "copyfile", denied)
    monkeypatch.setattr(builder.subprocess, "run", denied)
    with pytest.raises(ValueError):
        builder.build_new(tmp_path / "new-never-created", **{**config, **change})


def test_missing_configuration_tools_and_platform_fail_before_output_creation(
    builder, config, tmp_path, monkeypatch
):
    monkeypatch.setattr(builder.subprocess, "run", lambda *args, **kwargs: pytest.fail("No tool may run"))
    output = tmp_path / "new-never-created"
    cases = (
        {**config, "sdk": None},
        {**config, "jdk_bin": None},
        {**config, "environment": {}},
        {**config, "sdk": tmp_path / "new-absent-sdk"},
        {**config, "jdk_bin": tmp_path / "new-absent-jdk"},
        {**config, "android_platform": "android-34"},
    )
    for arguments in cases:
        with pytest.raises(ValueError):
            builder.build_new(output, **arguments)
        assert not output.exists()


def fake_mobile_commands(config, calls):
    def run(argv, **kwargs):
        calls.append((argv, kwargs))
        executable = Path(argv[0]).name
        stdout = b"NEW RAW STDOUT SENTINEL"
        stderr = b"NEW RAW STDERR SENTINEL"
        if executable == "javac" and "-d" in argv:
            path = Path(argv[argv.index("-d") + 1]) / "audit/fixture/runtime/MainActivity.class"
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b"NEW SYNTHETIC CLASS")
        elif executable == "d8":
            (Path(argv[argv.index("--output") + 1]) / "classes.dex").write_bytes(b"NEW SYNTHETIC DEX")
        elif executable == "aapt2" and "link" in argv:
            with zipfile.ZipFile(argv[argv.index("-o") + 1], "x"):
                pass
        elif executable == "zipalign":
            shutil.copyfile(argv[-2], argv[-1])
        elif executable == "keytool":
            Path(argv[argv.index("-keystore") + 1]).write_bytes(b"NEW SYNTHETIC TEST KEY")
        elif executable == "apksigner":
            shutil.copyfile(argv[-1], argv[argv.index("--out") + 1])
        elif executable == "xcrun" and "--show-sdk-path" in argv:
            stdout = str(config["sdk"] / "new-ios-sdk").encode()
        elif executable == "xcrun" and "swiftc" in argv and "-o" in argv:
            Path(argv[argv.index("-o") + 1]).write_bytes(b"NEW SYNTHETIC MACHO")
        elif executable == "codesign":
            info = plistlib.loads((Path(argv[-1]) / "Info.plist").read_bytes())
            assert info["MinimumOSVersion"] == "18.1"
        return subprocess.CompletedProcess(argv, 0, stdout, stderr)

    return run


def test_mock_build_rewrites_explicit_toolchain_and_preserves_only_hashed_journals(
    builder, config, tmp_path, monkeypatch
):
    calls = []
    monkeypatch.setattr(builder.subprocess, "run", fake_mobile_commands(config, calls))
    output = tmp_path / "new-build"
    result = builder.build_new(output, **config)
    assert result["compiled"] is True and result["installed"] is False
    assert result["android_target"] == "android-35/min-api-26"
    assert result["ios_target"] == config["ios_target"] and result["ios_sdk_selector"] == config["ios_sdk"]
    assert result["planned_ios_runtime"] == config["ios_runtime"] and result["ios_runtime_verified"] is False
    assert len(calls) > 5
    for argv, kwargs in calls:
        assert "android-36" not in " ".join(argv) and "build-tools/36.0.0" not in " ".join(argv)
        if "--sdk" in argv:
            assert argv[argv.index("--sdk") + 1] == config["ios_sdk"]
        if "-target" in argv:
            assert argv[argv.index("-target") + 1] == config["ios_target"]
        if Path(argv[0]).name in {"java", "javac", "keytool"}:
            assert Path(argv[0]).parent == config["jdk_bin"]
        assert kwargs["env"]["JAVA_HOME"] == str(config["jdk_bin"].parent)
    journal = (output / "commands.json").read_text()
    assert "NEW RAW" not in journal and str(tmp_path) not in journal
    assert all(
        set(record)
        == {"argv_sha256", "status", "stdout_sha256", "stdout_bytes", "stderr_sha256", "stderr_bytes"}
        for record in result["commands"]
    )
    assert json.loads(journal) == result["commands"]
    assert Path(result["apk"]).is_file() and Path(result["app"]).is_dir()


@pytest.mark.parametrize("failure", ["exit", "timeout", "unavailable", "invalid_utf8"])
def test_mock_tool_failures_are_generic_and_journal_has_only_hashes(
    builder, config, tmp_path, monkeypatch, failure
):
    secret = b"NEW PRIVATE-LIKE SENTINEL: raw output must remain in memory"

    def run(argv, **kwargs):
        if failure == "timeout":
            raise subprocess.TimeoutExpired(argv, 120, output=secret, stderr=secret)
        if failure == "unavailable":
            raise OSError(secret.decode())
        return subprocess.CompletedProcess(
            argv, 7 if failure == "exit" else 0, secret if failure == "exit" else b"\xff", secret
        )

    monkeypatch.setattr(builder.subprocess, "run", run)
    output = tmp_path / "new-failed-build"
    with pytest.raises(ValueError) as error:
        builder.build_new(output, **config)
    assert "SENTINEL" not in str(error.value) and str(tmp_path) not in str(error.value)
    assert error.value.__suppress_context__ or failure == "exit"
    journal = (output / "commands.json").read_text()
    assert "SENTINEL" not in journal and str(tmp_path) not in journal
    record = json.loads(journal)[0]
    assert (
        record["status"]
        == {"exit": 7, "timeout": "timeout", "unavailable": "unavailable", "invalid_utf8": 0}[failure]
    )
    assert not (output / "manifest.json").exists()


def test_cli_requires_explicit_platform_and_simulator_components(builder, config, tmp_path):
    with pytest.raises(SystemExit):
        builder.parser().parse_args(["--out", str(tmp_path / "new-output")])
    args = builder.parser().parse_args(
        [
            "--out",
            str(tmp_path / "new-output"),
            "--jdk-bin",
            str(config["jdk_bin"]),
            "--sdk",
            str(config["sdk"]),
            "--android-platform",
            config["android_platform"],
            "--build-tools",
            config["build_tools"],
            "--ios-sdk",
            config["ios_sdk"],
            "--ios-runtime",
            config["ios_runtime"],
            "--ios-target",
            config["ios_target"],
        ]
    )
    assert args.ios_target == config["ios_target"] and args.sdk == config["sdk"]
