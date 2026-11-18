"""Run gopire's Go unit tests and a Windows type-check of the agent package.

The comms package builds on Linux; the agent package is Windows-only, so it is
vetted with GOOS=windows (a type check: the Run loop's wiring is only
exercised by a live agent). Locally the tests skip when no Go toolchain is on
PATH; in CI a missing toolchain is a failure.
"""

import functools
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from empire.server.core.go import _resolve_go_binary

GOPIRE = Path(__file__).resolve().parents[1] / "server" / "data" / "agent" / "gopire"


@functools.cache
def _go_binary():
    # _resolve_go_binary never fails: it returns the bare name "go" when the
    # goenv shim cannot be resolved, so PATH decides whether Go exists at all.
    return shutil.which(_resolve_go_binary())


pytestmark = [
    pytest.mark.slow,
    pytest.mark.skipif(
        not os.environ.get("CI") and _go_binary() is None, reason="needs a Go toolchain"
    ),
]


def _run(*args, **env_overrides):
    go = _go_binary()
    if go is None:
        pytest.fail("no Go toolchain on PATH; CI must install Go for the gopire tests")
    env = {**os.environ, "GOTOOLCHAIN": "local", **env_overrides}
    try:
        result = subprocess.run(
            [go, *args],
            cwd=GOPIRE,
            capture_output=True,
            text=True,
            env=env,
            timeout=900,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        pytest.fail(f"go {' '.join(args)} timed out:\n{exc.stdout}\n{exc.stderr}")
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.parametrize(
    "args",
    [("test", "./comms/"), ("test", "-tags", "malleable", "./comms/")],
    ids=["comms", "comms-malleable"],
)
def test_gopire_comms_unit_tests(args):
    _run(*args)


def test_gopire_type_checks_for_windows():
    _run("vet", "./...", GOOS="windows", GOARCH="amd64")
