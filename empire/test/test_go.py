import os
import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from empire.server.core.config.config_manager import empire_config
from empire.server.core.exceptions import ModuleExecutionException
from empire.server.core.go import GoCompiler, _resolve_go_binary
from empire.server.core.stager_service import StagerService

_MIN_GO_BUILD_ARGS = 2


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def _make_compiler(tmp_path):
    """Return a GoCompiler backed by a minimal fake gopire tree under tmp_path."""
    gopire_dir = tmp_path / "data" / "agent" / "gopire"
    gopire_dir.mkdir(parents=True)
    (gopire_dir / "main.template").write_text("")
    return GoCompiler(install_path=tmp_path)


def _patch_compile_stager_subprocess(monkeypatch, returncode=0, stdout="", stderr=""):
    """Patch subprocess.run for compile_stager and return the list of captured calls."""
    calls = []

    def fake_run(args, **kwargs):
        calls.append({"args": args, "kwargs": kwargs})
        return subprocess.CompletedProcess(
            args=args, returncode=returncode, stdout=stdout, stderr=stderr
        )

    monkeypatch.setattr("empire.server.core.go.subprocess.run", fake_run)
    monkeypatch.setattr(
        "empire.server.core.go.shutil.copytree",
        lambda src, dst, **k: Path(dst).mkdir(parents=True, exist_ok=True),
    )
    monkeypatch.setattr("empire.server.core.go.shutil.move", lambda *a, **k: None)
    return calls


# ---------------------------------------------------------------------------
# GoCompiler construction
# ---------------------------------------------------------------------------


def test_go_compiler_jinja_env_path(tmp_path):
    """GoCompiler constructs the jinja_env loader path correctly."""
    compiler = _make_compiler(tmp_path)
    assert compiler.install_path == tmp_path
    assert str(tmp_path / "data/agent/gopire") in compiler.jinja_env.loader.searchpath


def test_go_compiler_accepts_path_object():
    """GoCompiler works with a Path object as install_path."""
    install = Path("/fake/install/path")
    with patch("empire.server.core.go._resolve_go_binary", return_value="go"):
        compiler = GoCompiler(install_path=install)
    assert str(install / "data/agent/gopire") in compiler.jinja_env.loader.searchpath


def test_go_compiler_jinja_autoescape_disabled(tmp_path):
    """autoescape must be False so Go template vars containing & < > are not
    HTML-escaped into invalid Go source (e.g. profile URIs with query strings)."""
    compiler = _make_compiler(tmp_path)
    assert not compiler.jinja_env.autoescape, (
        "autoescape=True would corrupt Go source: '&' in profile URIs becomes '&amp;'"
    )


# ---------------------------------------------------------------------------
# _resolve_go_binary
# ---------------------------------------------------------------------------


def test_resolve_go_binary_returns_real_path(tmp_path):
    """When go env GOROOT returns a valid directory the real binary is used."""
    fake_go = tmp_path / "bin" / "go"
    fake_go.parent.mkdir(parents=True)
    fake_go.touch()

    fake_result = subprocess.CompletedProcess(
        args=["go", "env", "GOROOT"],
        returncode=0,
        stdout=str(tmp_path) + "\n",
        stderr="",
    )
    with patch("empire.server.core.go.subprocess.run", return_value=fake_result):
        binary = _resolve_go_binary()

    assert binary == str(fake_go)


def test_resolve_go_binary_falls_back_when_goroot_missing(tmp_path):
    """Falls back to 'go' when the GOROOT bin/go path does not exist."""
    fake_result = subprocess.CompletedProcess(
        args=["go", "env", "GOROOT"],
        returncode=0,
        stdout=str(tmp_path / "nonexistent") + "\n",
        stderr="",
    )
    with patch("empire.server.core.go.subprocess.run", return_value=fake_result):
        assert _resolve_go_binary() == "go"


def test_resolve_go_binary_falls_back_on_nonzero_returncode():
    """Falls back to 'go' when go env itself fails (rc != 0)."""
    fake_result = subprocess.CompletedProcess(
        args=["go", "env", "GOROOT"], returncode=1, stdout="", stderr="go not found"
    )
    with patch("empire.server.core.go.subprocess.run", return_value=fake_result):
        assert _resolve_go_binary() == "go"


def test_resolve_go_binary_falls_back_on_timeout():
    """Falls back to 'go' when go env times out (e.g. hung NFS home dir)."""
    with patch(
        "empire.server.core.go.subprocess.run",
        side_effect=subprocess.TimeoutExpired(cmd="go", timeout=10),
    ):
        assert _resolve_go_binary() == "go"


def test_resolve_go_binary_uses_minimal_env():
    """_resolve_go_binary passes only PATH and HOME so the subprocess environment
    is small enough to avoid E2BIG when the parent carries a large environment
    (e.g. sudo -E uvicorn worker preserving the operator's full shell state)."""
    captured = {}

    def capture_run(args, **kwargs):
        captured["env"] = kwargs.get("env", {})
        return subprocess.CompletedProcess(
            args=args, returncode=1, stdout="", stderr=""
        )

    with (
        patch.dict(
            os.environ, {"PATH": "/usr/bin", "HOME": "/home/x", "EXTRA": "bloat"}
        ),
        patch("empire.server.core.go.subprocess.run", side_effect=capture_run),
    ):
        _resolve_go_binary()

    assert set(captured["env"].keys()) <= {"PATH", "HOME"}, (
        "Only PATH and HOME should be passed; large envs cause E2BIG in goenv shims"
    )


# ---------------------------------------------------------------------------
# compile_stager — subprocess invocation contract
# ---------------------------------------------------------------------------


def test_compile_stager_uses_resolved_binary_not_literal_go(tmp_path, monkeypatch):
    """compile_stager must call self._go_binary (the absolute path resolved at
    init time), not the bare string 'go'.  Using 'go' routes through the
    version-manager shim which fails with E2BIG in large environments."""
    compiler = _make_compiler(tmp_path)
    compiler._go_binary = "/fake/go/bin/go"

    calls = _patch_compile_stager_subprocess(monkeypatch)

    compiler.compile_stager({}, "stager", goos="windows", goarch="amd64")

    build_calls = [
        c
        for c in calls
        if len(c["args"]) >= _MIN_GO_BUILD_ARGS and c["args"][1] == "build"
    ]
    assert build_calls, "no go build subprocess call was made"
    assert build_calls[0]["args"][0] == "/fake/go/bin/go", (
        "compile_stager must use self._go_binary, not the string 'go'"
    )


def test_compile_stager_env_has_required_go_vars(tmp_path, monkeypatch):
    """GOTOOLCHAIN=local, a stable GOCACHE under the configured cache dir
    (DirectoriesConfig.cache), and GONOSUMDB=* must all be present in every go
    build invocation.

    Missing GOTOOLCHAIN caused Go to auto-download a nonexistent toolchain.
    Wrong GOCACHE (e.g. ``Path.home()/.cache/...``) meant the server running as
    root always got a cold cache — the cache must anchor on the configured
    platform cache path, not the runtime user's home.
    """
    compiler = _make_compiler(tmp_path)
    calls = _patch_compile_stager_subprocess(monkeypatch)

    compiler.compile_stager({}, "stager", goos="windows", goarch="amd64")

    build_calls = [
        c
        for c in calls
        if len(c["args"]) >= _MIN_GO_BUILD_ARGS and c["args"][1] == "build"
    ]
    assert build_calls, "no go build subprocess call was made"
    env = build_calls[0]["kwargs"].get("env", {})

    assert env.get("GOTOOLCHAIN") == "local", (
        "GOTOOLCHAIN=local must be set to prevent phantom toolchain downloads"
    )
    gocache = env.get("GOCACHE", "")
    assert gocache.endswith("/go-build"), (
        f"GOCACHE must end in /go-build (the configured cache subdir), got: {gocache!r}"
    )
    cache_dir = str(empire_config.directories.cache)
    assert gocache.startswith(cache_dir), (
        "GOCACHE must live under DirectoriesConfig.cache (the platform cache dir, "
        f"e.g. ~/.cache/empire on Linux), not install_path or Path.home(); "
        f"got: {gocache!r}, cache dir: {cache_dir!r}"
    )
    assert env.get("GONOSUMDB") == "*", (
        "GONOSUMDB=* must be set to avoid sum-database network calls"
    )


def test_compile_stager_function_args_override_operator_env(tmp_path, monkeypatch):
    """Function-argument goos/goarch must win over any operator-set GOOS/GOARCH
    in the environment — previously the merge was reversed so a shell export
    would silently override the cross-compile target."""
    compiler = _make_compiler(tmp_path)
    calls = _patch_compile_stager_subprocess(monkeypatch)

    with monkeypatch.context() as m:
        m.setenv("GOOS", "linux")
        m.setenv("GOARCH", "arm64")
        compiler.compile_stager({}, "stager", goos="windows", goarch="amd64")

    build_calls = [
        c
        for c in calls
        if len(c["args"]) >= _MIN_GO_BUILD_ARGS and c["args"][1] == "build"
    ]
    assert build_calls, "no go build subprocess call was made"
    env = build_calls[0]["kwargs"].get("env", {})

    assert env.get("GOOS") == "windows", (
        "GOOS from function arg must win over operator GOOS=linux in env"
    )
    assert env.get("GOARCH") == "amd64", (
        "GOARCH from function arg must win over operator GOARCH=arm64 in env"
    )


# ---------------------------------------------------------------------------
# compile_stager — error message chain
# ---------------------------------------------------------------------------


def test_compile_stager_error_uses_stderr(tmp_path, monkeypatch):
    """When stderr is non-empty it is the primary error source."""
    compiler = _make_compiler(tmp_path)
    _patch_compile_stager_subprocess(
        monkeypatch, returncode=1, stderr="undefined: SomeFunc", stdout=""
    )

    with pytest.raises(ModuleExecutionException) as exc_info:
        compiler.compile_stager({}, "stager", goos="windows", goarch="amd64")

    assert "undefined: SomeFunc" in str(exc_info.value)


def test_compile_stager_error_falls_back_to_stdout(tmp_path, monkeypatch):
    """When stderr is empty, stdout is used.  Some Go toolchain errors go to
    stdout (e.g. 'go: finding module ...' lines from an older Go release)."""
    compiler = _make_compiler(tmp_path)
    _patch_compile_stager_subprocess(
        monkeypatch, returncode=1, stderr="", stdout="internal compiler error"
    )

    with pytest.raises(ModuleExecutionException) as exc_info:
        compiler.compile_stager({}, "stager", goos="windows", goarch="amd64")

    assert "internal compiler error" in str(exc_info.value)


def test_compile_stager_error_signal_hint_when_no_output(tmp_path, monkeypatch):
    """When both stderr and stdout are empty (process killed by signal), a
    diagnostic hint must appear so operators don't chase a phantom build error.
    rc=-9 is SIGKILL; rc=-2 is SIGINT (Ctrl-C)."""
    compiler = _make_compiler(tmp_path)
    _patch_compile_stager_subprocess(monkeypatch, returncode=-9, stderr="", stdout="")

    with pytest.raises(ModuleExecutionException) as exc_info:
        compiler.compile_stager({}, "stager", goos="windows", goarch="amd64")

    msg = str(exc_info.value)
    assert "killed by signal" in msg, (
        "empty-output failures must hint at signal kill so operators check OOM/AV"
    )


def test_compile_stager_error_includes_returncode(tmp_path, monkeypatch):
    """The return code must appear in the exception message so operators can
    look up the exit status without reading server logs."""
    compiler = _make_compiler(tmp_path)
    _patch_compile_stager_subprocess(monkeypatch, returncode=126, stderr="some error")

    with pytest.raises(ModuleExecutionException) as exc_info:
        compiler.compile_stager({}, "stager", goos="windows", goarch="amd64")

    assert "rc=126" in str(exc_info.value), (
        "return code must be embedded in the exception message"
    )


def test_compile_stager_raises_on_binary_not_found(tmp_path, monkeypatch):
    """FileNotFoundError when launching go build must become a
    ModuleExecutionException so the API returns 400 rather than an unhandled
    500.  This covers the case where the Go installation is removed or moved
    after the server starts."""
    compiler = _make_compiler(tmp_path)
    monkeypatch.setattr(
        "empire.server.core.go.shutil.copytree",
        lambda src, dst, **k: Path(dst).mkdir(parents=True, exist_ok=True),
    )

    def raise_not_found(*args, **kwargs):
        raise FileNotFoundError(2, "No such file or directory")

    monkeypatch.setattr("empire.server.core.go.subprocess.run", raise_not_found)

    with pytest.raises(ModuleExecutionException, match="binary not found"):
        compiler.compile_stager({}, "stager", goos="windows", goarch="amd64")


# ---------------------------------------------------------------------------
# generate_main_go — template rendering
# ---------------------------------------------------------------------------


def test_generate_main_go_preserves_ampersand_in_profile(tmp_path):
    """autoescape=False: & in a profile URI must survive template rendering
    unchanged.  With autoescape=True it became &amp; which broke Go compilation
    when operators used malleable profiles with query-string parameters."""
    gopire_dir = tmp_path / "data" / "agent" / "gopire"
    gopire_dir.mkdir(parents=True)
    (gopire_dir / "main.template").write_text('profile := "{{ PROFILE }}"')

    compiler = GoCompiler(install_path=tmp_path)
    out = tmp_path / "main.go"
    compiler.generate_main_go("main.template", str(out), {"PROFILE": "/path?a=1&b=2"})

    rendered = out.read_text()
    assert "&amp;" not in rendered, "& must not be HTML-escaped in Go source"
    assert "/path?a=1&b=2" in rendered, "profile value must appear verbatim"


# ---------------------------------------------------------------------------
# stager_service — exception propagation
# ---------------------------------------------------------------------------


def test_generate_stager_returns_error_tuple_on_compile_failure():
    """generate_stager must catch ModuleExecutionException and return (None, msg)
    so the API layer surfaces a 400 instead of propagating a 500."""
    service = StagerService.__new__(StagerService)
    template = MagicMock()
    template.__class__.__name__ = "FakeStager"
    template.generate.side_effect = ModuleExecutionException(
        "Go build failed (rc=1): some compiler error"
    )

    result, err = service.generate_stager(template)

    assert result is None
    assert "Go build failed" in err
    assert "some compiler error" in err


def test_generate_stager_does_not_swallow_other_exceptions():
    """Only ModuleExecutionException is caught.  Other exceptions (e.g.
    AttributeError in a stager template bug) must still propagate so they
    are not silently converted into opaque 500s with no traceback."""
    service = StagerService.__new__(StagerService)
    template = MagicMock()
    template.generate.side_effect = AttributeError("stager template bug")

    with pytest.raises(AttributeError, match="stager template bug"):
        service.generate_stager(template)


@pytest.mark.parametrize("malleable", [False, True], ids=["http", "malleable"])
def test_generate_main_go_wires_session_cookie_and_default_page(tmp_path, malleable):
    """The sender gets the listener's cookie name and decoded default page from
    the template. No Go tool sees the Jinja wiring, so pin it on both branches."""
    compiler = GoCompiler(install_path=Path(__file__).resolve().parents[1] / "server")
    out = tmp_path / "main.go"
    compiler.generate_main_go(
        "main.template",
        str(out),
        {"SESSION_COOKIE": "PHPSESSID", "MALLEABLE": malleable},
    )
    rendered = out.read_text()
    assert 'sessionCookie := "PHPSESSID"' in rendered
    assert ", sessionCookie, defaultPage)" in rendered
