import logging
import subprocess

import pytest
import requests

from empire.server.core.config.data_manager import CompilerSyncError
from empire.server.core.dotnet import DotnetCompiler
from empire.server.core.exceptions import ModuleExecutionException


@pytest.fixture
def compiler(tmp_path, monkeypatch):
    """A DotnetCompiler that doesn't actually try to sync EmpireCompiler.

    `__init__` calls `sync_empire_compiler` which would fetch the binary;
    short-circuit it for unit tests by stubbing the function.
    """

    def fake_sync(*_args, **_kwargs):
        return tmp_path

    monkeypatch.setattr("empire.server.core.dotnet.sync_empire_compiler", fake_sync)
    return DotnetCompiler(install_path=tmp_path)


@pytest.fixture
def unavailable_compiler(tmp_path, monkeypatch):
    """A DotnetCompiler whose sync failed (e.g. GitHub API rate-limit).

    `sync_empire_compiler` returns None on failure; __init__ must degrade
    gracefully rather than raising `TypeError: None / "EmpireCompiler"`.
    """
    monkeypatch.setattr(
        "empire.server.core.dotnet.sync_empire_compiler",
        lambda *_a, **_k: None,
    )
    return DotnetCompiler(install_path=tmp_path)


def test_init_does_not_crash_when_sync_returns_none(unavailable_compiler):
    # Regression: a bare `None / "EmpireCompiler"` used to raise TypeError at
    # construction and take down the whole server / test suite.
    assert unavailable_compiler.compiler_dir is None


def test_compile_task_raises_clear_error_when_compiler_unavailable(
    unavailable_compiler,
):
    with pytest.raises(ModuleExecutionException, match="not available"):
        unavailable_compiler.compile_task(compiler_yaml="dummy: yaml", task_name="task")


def test_compile_stager_raises_clear_error_when_compiler_unavailable(
    unavailable_compiler,
):
    with pytest.raises(ModuleExecutionException, match="not available"):
        unavailable_compiler.compile_stager(
            compiler_yaml="dummy: yaml", task_name="stager"
        )


@pytest.mark.parametrize(
    ("returncode", "stdout", "stderr", "expected_substrings"),
    [
        (-9, "", "", ["rc=-9", "no output", "likely killed by signal"]),
        (1, "", "compiler error: foo", ["rc=1", "compiler error: foo"]),
        (2, "diagnostic on stdout", "", ["rc=2", "diagnostic on stdout"]),
    ],
    ids=["signal_kill_empty_streams", "stderr_has_error", "stdout_fallback"],
)
def test_compile_task_includes_diagnostics_when_empire_compiler_fails(
    compiler, monkeypatch, returncode, stdout, stderr, expected_substrings
):
    """Symmetric to the go.py fix: rc != 0 with empty stderr previously
    rendered as `EmpireCompiler execution failed with error: ` (no info).
    New message must include returncode + stdout fallback."""

    def fake_run(*_args, **_kwargs):
        return subprocess.CompletedProcess(
            args=["./EmpireCompiler"],
            returncode=returncode,
            stdout=stdout,
            stderr=stderr,
        )

    monkeypatch.setattr("empire.server.core.dotnet.subprocess.run", fake_run)

    with pytest.raises(ModuleExecutionException) as excinfo:
        compiler.compile_task(compiler_yaml="dummy: yaml", task_name="task")

    message = str(excinfo.value)
    for substring in expected_substrings:
        assert substring in message, (
            f"expected {substring!r} in error message, got: {message!r}"
        )


@pytest.mark.parametrize(
    ("returncode", "stdout", "stderr", "expected_substrings"),
    [
        (-9, "", "", ["rc=-9", "no output", "likely killed by signal"]),
        (1, "", "compiler error: bar", ["rc=1", "compiler error: bar"]),
        (2, "diagnostic on stdout", "", ["rc=2", "diagnostic on stdout"]),
    ],
    ids=["signal_kill_empty_streams", "stderr_has_error", "stdout_fallback"],
)
def test_compile_stager_includes_diagnostics_when_empire_compiler_fails(
    compiler, monkeypatch, returncode, stdout, stderr, expected_substrings
):
    """Same shape as compile_task — pin the diagnostic for the stager path."""

    def fake_run(*_args, **_kwargs):
        return subprocess.CompletedProcess(
            args=["./EmpireCompiler"],
            returncode=returncode,
            stdout=stdout,
            stderr=stderr,
        )

    monkeypatch.setattr("empire.server.core.dotnet.subprocess.run", fake_run)

    with pytest.raises(ModuleExecutionException) as excinfo:
        compiler.compile_stager(compiler_yaml="dummy: yaml", task_name="stager")

    message = str(excinfo.value)
    for substring in expected_substrings:
        assert substring in message, (
            f"expected {substring!r} in error message, got: {message!r}"
        )


# ---------- startup resilience (#1319) ----------


def test_init_survives_sync_failure(tmp_path, monkeypatch, caplog):
    """A cold cache on an offline or throttled host must degrade C# compilation,
    not abort MainMenu and with it the whole server."""

    def failing_sync(*_a, **_k):
        raise CompilerSyncError(
            "network error fetching the release (Remote end closed connection)"
        ) from requests.ConnectionError("Remote end closed connection")

    monkeypatch.setattr("empire.server.core.dotnet.sync_empire_compiler", failing_sync)

    with caplog.at_level(logging.ERROR, logger="empire.server.core.dotnet"):
        compiler = DotnetCompiler(install_path=tmp_path)

    assert compiler.compiler_dir is None
    assert "not available" in caplog.text
    assert "Remote end closed connection" in caplog.text


def test_init_propagates_non_sync_errors(tmp_path, monkeypatch):
    """Only sync failures degrade; anything else must still abort startup."""

    def broken(*_a, **_k):
        raise RuntimeError("config attribute typo")

    monkeypatch.setattr("empire.server.core.dotnet.sync_empire_compiler", broken)

    with pytest.raises(RuntimeError, match="typo"):
        DotnetCompiler(install_path=tmp_path)


def test_require_available_is_a_no_op_when_compiler_present(compiler):
    compiler.require_available()


def test_require_available_raises_clear_error_when_unavailable(unavailable_compiler):
    with pytest.raises(ModuleExecutionException, match="not available"):
        unavailable_compiler.require_available()


def test_embedded_resources_dir_raises_clear_error_when_unavailable(
    unavailable_compiler,
):
    with pytest.raises(ModuleExecutionException, match="not available"):
        unavailable_compiler.embedded_resources_dir()
