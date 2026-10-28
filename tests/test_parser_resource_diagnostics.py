"""Parser resource failures retain evidence and never trigger an unisolated retry."""

import os
import signal
import sys
from contextlib import nullcontext

import pytest

from mobile_audit import engine, parser_sandbox
from mobile_audit.processes import CommandFailure, command


@pytest.mark.skipif(os.name != "posix" or not hasattr(signal, "SIGXCPU"), reason="POSIX signal exit")
def test_command_preserves_actual_sigxcpu_exit_without_a_core_dump():
    child = (
        "import os, resource, signal; "
        "resource.setrlimit(resource.RLIMIT_CORE, (0, 0)); "
        "os.kill(os.getpid(), signal.SIGXCPU)"
    )
    with pytest.raises(CommandFailure) as caught:
        command([sys.executable, "-I", "-B", "-c", child], timeout=10)
    assert isinstance(caught.value, ValueError)
    assert caught.value.returncode == -signal.SIGXCPU
    assert str(caught.value) == (
        f"Command failed ({sys.executable}, exit {-signal.SIGXCPU}); "
        "check input, device authorization and test-build permissions."
    )


def test_ordinary_command_exit_remains_value_error_compatible():
    with pytest.raises(ValueError) as caught:
        command([sys.executable, "-I", "-B", "-c", "raise SystemExit(7)"], timeout=10)
    assert isinstance(caught.value, CommandFailure)
    assert caught.value.returncode == 7
    assert str(caught.value) == (
        f"Command failed ({sys.executable}, exit 7); "
        "check input, device authorization and test-build permissions."
    )


@pytest.fixture
def parser_boundary(tmp_path, monkeypatch):
    source = tmp_path / "new-source"
    source.mkdir()
    (source / "New.java").write_text("class New {}")
    isolation = {"state": "enforced", "backend": "synthetic-isolation"}
    monkeypatch.setattr(engine, "parser_lease", lambda: nullcontext())
    monkeypatch.setattr(parser_sandbox, "sandbox_command", lambda args, *a, **k: (args, isolation))
    monkeypatch.setattr(parser_sandbox, "activate", lambda wrapped, args, state, scratch: (wrapped, state))
    calls = []

    def install_failure(error):
        def failed(args, **kwargs):
            calls.append((args, kwargs))
            raise error

        monkeypatch.setattr(engine, "command", failed)

    return source, isolation, calls, install_failure


@pytest.mark.skipif(not hasattr(signal, "SIGXCPU"), reason="POSIX CPU limit signal")
@pytest.mark.parametrize("isolation_state", ["enforced", "unavailable", "disabled"])
def test_cpu_limit_is_not_misdiagnosed_as_sandbox_failure(parser_boundary, isolation_state):
    source, isolation, calls, install_failure = parser_boundary
    isolation["state"] = isolation_state
    install_failure(CommandFailure(sys.executable, -signal.SIGXCPU))
    with pytest.raises(ValueError) as caught:
        engine.analyze_target(source)
    message = str(caught.value)
    assert "CPU time limit (SIGXCPU); audit incomplete" in message
    assert "not retried" in message
    assert "incompatible" not in message
    assert "APSA_PARSER_SANDBOX=off" not in message
    assert len(calls) == 1
    assert calls[0][1]["timeout"] == engine.PARSER_TIMEOUT
    assert calls[0][1]["max_rss"] == 1024 * 1024 * 1024


@pytest.mark.parametrize("returncode", [1, -signal.SIGKILL])
def test_other_exits_keep_existing_sandbox_diagnostic_without_retry(parser_boundary, returncode):
    source, _, calls, install_failure = parser_boundary
    install_failure(CommandFailure(sys.executable, returncode))
    with pytest.raises(ValueError) as caught:
        engine.analyze_target(source)
    message = str(caught.value)
    assert "Sandboxed parser failed under synthetic-isolation" in message
    assert "not retried without OS isolation" in message
    assert f"exit {returncode}" in message
    assert "CPU time limit" not in message
    assert len(calls) == 1


def test_non_command_resource_error_remains_unchanged(parser_boundary):
    source, _, calls, install_failure = parser_boundary
    original = ValueError("Parser memory exceeds limit; audit incomplete")
    install_failure(original)
    with pytest.raises(ValueError) as caught:
        engine.analyze_target(source)
    assert caught.value is original
    assert len(calls) == 1


@pytest.mark.skipif(not hasattr(signal, "SIGXCPU"), reason="POSIX CPU limit signal")
def test_error_text_alone_is_not_cpu_limit_evidence(parser_boundary):
    source, _, calls, install_failure = parser_boundary
    install_failure(ValueError(f"Command failed (synthetic, exit {-signal.SIGXCPU}); check input"))
    with pytest.raises(ValueError) as caught:
        engine.analyze_target(source)
    assert "CPU time limit" not in str(caught.value)
    assert "Sandboxed parser failed" in str(caught.value)
    assert len(calls) == 1
