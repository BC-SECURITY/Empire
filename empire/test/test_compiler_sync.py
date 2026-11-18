import io
import tarfile
import time
from pathlib import Path, PurePosixPath
from unittest.mock import patch

import pytest
import requests
import urllib3
import yaml

from empire.server.core.config import data_manager, paths
from empire.server.core.config.config_manager import EmpireCompilerConfig
from empire.server.core.config.data_manager import (
    CompilerArchiveError,
    CompilerSyncError,
    _configure_compiler,
    _github_session,
    _resolve_compiler_download_url,
    _resolve_compiler_platform,
    sync_empire_compiler,
)

STAGERS_DIR = Path(__file__).resolve().parent.parent / "server" / "stagers"
LAUNCHER_RESOURCE_RELATIVE_PATH = "common/launcher.txt"


@patch("empire.server.core.config.data_manager.platform")
def test_resolve_platform_linux_x86_64(mock_platform):
    mock_platform.system.return_value = "Linux"
    mock_platform.machine.return_value = "x86_64"
    assert _resolve_compiler_platform() == ("linux", "x64")


@patch("empire.server.core.config.data_manager.platform")
def test_resolve_platform_darwin_arm64(mock_platform):
    mock_platform.system.return_value = "Darwin"
    mock_platform.machine.return_value = "arm64"
    assert _resolve_compiler_platform() == ("osx", "arm64")


@patch("empire.server.core.config.data_manager.platform")
def test_resolve_platform_darwin_aarch64(mock_platform):
    mock_platform.system.return_value = "Darwin"
    mock_platform.machine.return_value = "aarch64"
    assert _resolve_compiler_platform() == ("osx", "arm64")


@patch("empire.server.core.config.data_manager.platform")
def test_resolve_platform_linux_arm64(mock_platform):
    mock_platform.system.return_value = "Linux"
    mock_platform.machine.return_value = "arm64"
    assert _resolve_compiler_platform() == ("linux", "arm64")


def test_download_url_missing_repo_and_ref():
    config = EmpireCompilerConfig()
    assert _resolve_compiler_download_url(config, "linux-x64") is None


def test_download_url_missing_ref():
    config = EmpireCompilerConfig(repo="BC-SECURITY/Empire-Compiler")
    assert _resolve_compiler_download_url(config, "linux-x64") is None


class _FakeResponse:
    def __init__(self, *, status=200, body: bytes = b"", raw=None, json=None):
        self.status_code = status
        self.ok = status < 400  # noqa: PLR2004
        self.text = f"status {status}"
        self.raw = raw if raw is not None else io.BytesIO(body)
        self._json = json

    def json(self):
        return self._json

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class _FakeSession:
    """Serves `responses` in order; an Exception instance is raised instead."""

    def __init__(self, responses):
        self._responses = list(responses)
        self.calls = []

    def get(self, url, **kwargs):
        self.calls.append((url, kwargs))
        if not self._responses:
            pytest.fail(f"unexpected extra GET {url}")
        nxt = self._responses.pop(0)
        if isinstance(nxt, Exception):
            raise nxt
        return nxt

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def test_download_url_repo_ref_finds_asset():
    session = _FakeSession(
        [
            _FakeResponse(
                json={
                    "assets": [
                        {
                            "name": "EmpireCompiler-linux-x64-v1.1.0-a.7.tgz",
                            "browser_download_url": "https://github.com/downloads/EmpireCompiler-linux-x64-v1.1.0-a.7.tgz",
                        },
                        {
                            "name": "EmpireCompiler-osx-arm64-v1.1.0-a.7.tgz",
                            "browser_download_url": "https://github.com/downloads/EmpireCompiler-osx-arm64-v1.1.0-a.7.tgz",
                        },
                    ]
                }
            )
        ]
    )

    config = EmpireCompilerConfig(repo="BC-SECURITY/Empire-Compiler", ref="v1.1.0-a.7")
    url = _resolve_compiler_download_url(config, "linux-x64", session)
    assert url == "https://github.com/downloads/EmpireCompiler-linux-x64-v1.1.0-a.7.tgz"

    assert session.calls == [
        (
            "https://api.github.com/repos/BC-SECURITY/Empire-Compiler/releases/tags/v1.1.0-a.7",
            {"timeout": 30, "headers": {"Accept": "application/vnd.github+json"}},
        )
    ]


def test_download_url_repo_ref_no_matching_asset():
    session = _FakeSession(
        [
            _FakeResponse(
                json={
                    "assets": [
                        {
                            "name": "EmpireCompiler-osx-arm64-v1.1.0-a.7.tgz",
                            "browser_download_url": "https://example.com/osx.tgz",
                        },
                    ]
                }
            )
        ]
    )

    config = EmpireCompilerConfig(repo="BC-SECURITY/Empire-Compiler", ref="v1.1.0-a.7")
    assert _resolve_compiler_download_url(config, "linux-x64", session) is None


def test_download_url_repo_ref_api_failure():
    session = _FakeSession([_FakeResponse(status=404)])

    config = EmpireCompilerConfig(repo="BC-SECURITY/Empire-Compiler", ref="v99.0.0")
    assert _resolve_compiler_download_url(config, "linux-x64", session) is None


def _find_launcher_locations(entries):
    """Recursively find launcher.txt Location values in YAML task entries."""
    locations = []
    if not entries:
        return locations
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        for res in entry.get("EmbeddedResources", []) or []:
            if isinstance(res, dict) and res.get("Name") == "launcher.txt":
                locations.append(res["Location"])
        for lib in entry.get("ReferenceSourceLibraries", []) or []:
            if isinstance(lib, dict):
                for res in lib.get("EmbeddedResources", []) or []:
                    if isinstance(res, dict) and res.get("Name") == "launcher.txt":
                        locations.append(res["Location"])
    return locations


@pytest.mark.parametrize("stager_file", ["CSharpPS.yaml", "CSharpPy.yaml"])
def test_stager_yaml_launcher_path_matches_service(stager_file):
    """Verify that stager YAML EmbeddedResources Location for launcher.txt
    is ``common/launcher.txt`` — the base path that StagerGenerationService
    patches in-memory to a unique subdirectory per compilation.
    """
    stager_data = yaml.safe_load(
        (STAGERS_DIR / stager_file).read_text(encoding="utf-8")
    )
    entries = stager_data if isinstance(stager_data, list) else [stager_data]

    launcher_locations = _find_launcher_locations(entries)

    assert launcher_locations, (
        f"No launcher.txt EmbeddedResource found in {stager_file}"
    )
    for loc in launcher_locations:
        normalised = str(PurePosixPath(loc.replace("\\", "/")))
        assert normalised == LAUNCHER_RESOURCE_RELATIVE_PATH, (
            f"{stager_file}: EmbeddedResources Location '{loc}' does not match "
            f"expected '{LAUNCHER_RESOURCE_RELATIVE_PATH}'"
        )


def test_configure_compiler_resolves_confuser_proj_off_the_package(
    monkeypatch, tmp_path
):
    """A relative `confuser_proj` must resolve against the installed package.

    Resolving it against the CWD meant a server started from anywhere but the
    repo root died inside MainMenu.__init__.
    """
    package_root = tmp_path / "install-root"
    template_path = package_root / "empire" / "server" / "data" / "confuser.crproj"
    template_path.parent.mkdir(parents=True)
    template_path.write_text("<project base='{confuser_base_dir}' />")
    monkeypatch.setattr(paths, "REPO_ROOT", package_root)

    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    monkeypatch.chdir(elsewhere)

    extracted = tmp_path / "extracted"
    (extracted / "EmpireCompiler").mkdir(parents=True)
    config = EmpireCompilerConfig(confuser_proj="empire/server/data/confuser.crproj")

    _configure_compiler(config, extracted)

    written = extracted / "EmpireCompiler" / "Data" / "Temp" / "empire.crproj"
    assert written.exists()
    assert "confuser_base_dir" not in written.read_text()


def test_configure_compiler_honours_an_absolute_confuser_proj(tmp_path):
    """Operators who set an absolute path must keep getting that exact file."""
    template_path = tmp_path / "custom.crproj"
    template_path.write_text("<project base='{confuser_base_dir}' />")

    extracted = tmp_path / "extracted"
    (extracted / "EmpireCompiler").mkdir(parents=True)
    config = EmpireCompilerConfig(confuser_proj=str(template_path))

    _configure_compiler(config, extracted)

    assert (extracted / "EmpireCompiler" / "Data" / "Temp" / "empire.crproj").exists()


# ---------- sync_empire_compiler: download resilience (#1606) ----------
#
# These drive the whole sync through a fake GitHub session so no bytes leave
# the machine: the first GET is the release lookup, every later GET is the
# asset download. The tarball is built in memory with the real layout
# (`<name>/EmpireCompiler/EmpireCompiler`).

_REF = "v9.9.9"
_NAME = f"EmpireCompiler-linux-x64-{_REF}"
_DOWNLOAD_URL = f"https://github.com/BC-SECURITY/Empire-Compiler/releases/download/{_REF}/{_NAME}.tgz"


def _make_tgz(member: str = f"{_NAME}/EmpireCompiler/EmpireCompiler") -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        payload = b"#!/bin/sh\necho EmpireCompiler\n"
        info = tarfile.TarInfo(member)
        info.size = len(payload)
        info.mode = 0o755
        tar.addfile(info, io.BytesIO(payload))
    return buf.getvalue()


class _HookedStream(io.BytesIO):
    """A response body that runs `on_read` before every read.

    `resp.raw` is a urllib3 HTTPResponse, so a mid-body drop surfaces as a
    urllib3 ProtocolError -- not a requests exception -- from `.read()`; the
    hook can raise that, or simulate a peer process acting mid-stream.
    """

    def __init__(self, data: bytes, on_read):
        super().__init__(data)
        self._on_read = on_read

    def read(self, size=-1):
        self._on_read()
        return super().read(size)


def _dropped_connection():
    raise urllib3.exceptions.ProtocolError("Connection broken: IncompleteRead")


def _broken_response() -> _FakeResponse:
    return _FakeResponse(raw=_HookedStream(_make_tgz(), _dropped_connection))


def _release_response():
    return _FakeResponse(
        json={
            "assets": [{"name": f"{_NAME}.tgz", "browser_download_url": _DOWNLOAD_URL}]
        }
    )


@pytest.fixture
def compiler_cache(tmp_path, monkeypatch):
    """Point the compiler cache at tmp, pin the platform to linux-x64, and
    disable the backoff sleep."""
    monkeypatch.setattr(data_manager.config_manager, "DATA_DIR", tmp_path)
    monkeypatch.setattr(
        data_manager, "_resolve_compiler_platform", lambda: ("linux", "x64")
    )
    monkeypatch.setattr(time, "sleep", lambda _s: None)
    return tmp_path / "empire-compiler"


def _install_session(monkeypatch, responses) -> _FakeSession:
    session = _FakeSession(responses)
    monkeypatch.setattr(data_manager, "_github_session", lambda: session)
    return session


def _cfg() -> EmpireCompilerConfig:
    return EmpireCompilerConfig(
        repo="BC-SECURITY/Empire-Compiler",
        ref=_REF,
        confuser_proj="empire/server/data/confuser.crproj",
    )


def _install_cached(compiler_cache: Path, name: str) -> Path:
    binary = compiler_cache / name / "EmpireCompiler" / "EmpireCompiler"
    binary.parent.mkdir(parents=True)
    binary.write_bytes(b"#!/bin/sh\n")
    return compiler_cache / name


def _visible_dirs(compiler_cache: Path) -> list[str]:
    return sorted(
        d.name
        for d in compiler_cache.iterdir()
        if d.is_dir() and not d.name.startswith(".")
    )


def _scratch_leftovers(compiler_cache: Path) -> list[Path]:
    return list((compiler_cache / ".partial").glob("*"))


def test_sync_retries_download_after_mid_stream_failure(compiler_cache, monkeypatch):
    session = _install_session(
        monkeypatch,
        [_release_response(), _broken_response(), _FakeResponse(body=_make_tgz())],
    )

    result = sync_empire_compiler(_cfg())

    assert result == compiler_cache / _NAME
    assert (result / "EmpireCompiler" / "EmpireCompiler").is_file()
    assert len(session.calls) == 3  # noqa: PLR2004
    assert _visible_dirs(compiler_cache) == [_NAME]
    assert _scratch_leftovers(compiler_cache) == []


def test_sync_gives_up_after_repeated_mid_stream_failures(compiler_cache, monkeypatch):
    _install_cached(compiler_cache, "EmpireCompiler-linux-x64-v1.0.0")
    _install_cached(compiler_cache, "EmpireCompiler-osx-arm64-v1.0.0")
    session = _install_session(
        monkeypatch, [_release_response()] + [_broken_response() for _ in range(3)]
    )

    with pytest.raises(CompilerSyncError) as excinfo:
        sync_empire_compiler(_cfg())

    assert isinstance(excinfo.value.__cause__, urllib3.exceptions.ProtocolError)
    assert len(session.calls) == 1 + 3
    assert _visible_dirs(compiler_cache) == [
        "EmpireCompiler-linux-x64-v1.0.0",
        "EmpireCompiler-osx-arm64-v1.0.0",
    ]
    assert _scratch_leftovers(compiler_cache) == []
    # No silent fallback: the operator is told which refs for *this* platform
    # are usable, as refs (not directory names, which the cache scan would
    # never match), and that the cause was the network.
    message = str(excinfo.value)
    assert "set empire_compiler.ref to one of: v1.0.0" in message
    assert "EmpireCompiler-linux-x64-v1.0.0" not in message
    assert "osx" not in message
    assert "GitHub is reachable" in message


def test_sync_does_not_retry_download_on_404(compiler_cache, monkeypatch):
    session = _install_session(
        monkeypatch, [_release_response(), _FakeResponse(status=404)]
    )

    assert sync_empire_compiler(_cfg()) is None
    assert len(session.calls) == 2  # noqa: PLR2004
    assert not compiler_cache.exists()


def test_sync_corrupt_tarball_is_cleaned_up(compiler_cache, monkeypatch):
    garbage = b"this is not a gzip stream" * 64
    session = _install_session(
        monkeypatch,
        [_release_response()] + [_FakeResponse(body=garbage) for _ in range(3)],
    )

    with pytest.raises(CompilerSyncError, match="corrupt or truncated") as excinfo:
        sync_empire_compiler(_cfg())

    assert isinstance(excinfo.value.__cause__, tarfile.ReadError)
    assert len(session.calls) == 1 + 3
    assert _visible_dirs(compiler_cache) == []
    assert _scratch_leftovers(compiler_cache) == []


def test_sync_rejects_archive_without_binary_on_first_attempt(
    compiler_cache, monkeypatch
):
    """A well-formed archive with the wrong layout is a bad release asset, not
    a transient failure: it must not be renamed into place and must not cost
    three downloads."""
    session = _install_session(
        monkeypatch,
        [
            _release_response(),
            _FakeResponse(body=_make_tgz(member=f"{_NAME}/EmpireCompiler/README.md")),
        ],
    )

    with pytest.raises(CompilerArchiveError, match="EmpireCompiler/EmpireCompiler"):
        sync_empire_compiler(_cfg())

    assert len(session.calls) == 2  # noqa: PLR2004
    assert _visible_dirs(compiler_cache) == []
    assert _scratch_leftovers(compiler_cache) == []


def test_sync_does_not_retry_disk_errors(compiler_cache, monkeypatch):
    """A full or unwritable disk is not fixed by downloading the archive again."""
    session = _install_session(
        monkeypatch, [_release_response(), _FakeResponse(body=_make_tgz())]
    )

    def no_space(*_a, **_k):
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(data_manager, "_extract_compiler_stream", no_space)

    with pytest.raises(CompilerSyncError, match="No space left") as excinfo:
        sync_empire_compiler(_cfg())

    message = str(excinfo.value)
    assert "check permissions and free space" in message
    assert "GitHub is reachable" not in message
    assert len(session.calls) == 2  # noqa: PLR2004
    assert _scratch_leftovers(compiler_cache) == []


def test_sync_keeps_peer_install_that_completed_mid_download(
    compiler_cache, monkeypatch
):
    target = compiler_cache / _NAME

    def peer_installs():
        if not target.exists():
            binary = target / "EmpireCompiler" / "EmpireCompiler"
            binary.parent.mkdir(parents=True)
            binary.write_bytes(b"peer")

    session = _install_session(
        monkeypatch,
        [
            _release_response(),
            _FakeResponse(raw=_HookedStream(_make_tgz(), peer_installs)),
        ],
    )

    result = sync_empire_compiler(_cfg())

    assert result == target
    assert (target / "EmpireCompiler" / "EmpireCompiler").read_bytes() == b"peer"
    assert len(session.calls) == 2  # noqa: PLR2004
    assert _scratch_leftovers(compiler_cache) == []


def test_sync_surfaces_failed_removal_of_incomplete_install(
    compiler_cache, monkeypatch
):
    """If the leftover cannot be removed, say so and stop: silently keeping it
    would let a later "peer won" check hand back a directory with no binary."""
    (compiler_cache / _NAME / "EmpireCompiler").mkdir(parents=True)
    session = _install_session(
        monkeypatch, [_release_response(), _FakeResponse(body=_make_tgz())]
    )

    def refuse(*_a, **_k):
        raise PermissionError(13, "Permission denied")

    monkeypatch.setattr(data_manager.shutil, "rmtree", refuse)

    with pytest.raises(CompilerSyncError, match="Permission denied") as excinfo:
        sync_empire_compiler(_cfg())

    assert isinstance(excinfo.value.__cause__, PermissionError)
    assert session.calls == []


def test_sync_download_attempts_are_bounded_when_connection_refused(
    compiler_cache, monkeypatch
):
    """Connect-level failures are already retried inside the session, so the
    whole-download loop must not multiply them: one raise, one give-up."""
    session = _install_session(
        monkeypatch,
        [_release_response(), requests.ConnectionError("connection refused")],
    )

    with pytest.raises(CompilerSyncError, match="connection refused"):
        sync_empire_compiler(_cfg())

    assert len(session.calls) == 2  # noqa: PLR2004


def test_sync_redownloads_when_cached_dir_lacks_binary(compiler_cache, monkeypatch):
    """A partially extracted dir from an interrupted older install must not be
    served as a cache hit; it is removed and fetched again."""
    stale = compiler_cache / _NAME
    (stale / "EmpireCompiler").mkdir(parents=True)
    (stale / "EmpireCompiler" / "Confuser.Core.dll").write_bytes(b"")
    session = _install_session(
        monkeypatch, [_release_response(), _FakeResponse(body=_make_tgz())]
    )

    result = sync_empire_compiler(_cfg())

    assert result == compiler_cache / _NAME
    assert (result / "EmpireCompiler" / "EmpireCompiler").is_file()
    assert len(session.calls) == 2  # noqa: PLR2004


def test_sync_uses_complete_cached_dir_without_network(compiler_cache, monkeypatch):
    cached = _install_cached(compiler_cache, _NAME)
    session = _install_session(monkeypatch, [])

    assert sync_empire_compiler(_cfg()) == cached
    assert session.calls == []


# ---------- _github_session: headers + retry policy ----------


def test_github_session_sets_user_agent_and_bearer_token(monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "tok_abc123")
    monkeypatch.delenv("GH_TOKEN", raising=False)

    session = _github_session()

    assert session.headers["User-Agent"].startswith("Empire")
    assert session.headers["Authorization"] == "Bearer tok_abc123"


def test_github_session_falls_back_to_gh_token(monkeypatch):
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    monkeypatch.setenv("GH_TOKEN", "tok_gh")

    assert _github_session().headers["Authorization"] == "Bearer tok_gh"


def test_github_session_unauthenticated_when_no_token(monkeypatch):
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    monkeypatch.delenv("GH_TOKEN", raising=False)

    assert "Authorization" not in _github_session().headers


def test_github_session_retries_transient_statuses_only(monkeypatch):
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    monkeypatch.delenv("GH_TOKEN", raising=False)

    retry = _github_session().get_adapter("https://github.com/").max_retries

    assert retry.total == 4  # noqa: PLR2004
    assert retry.backoff_factor >= 1
    assert retry.respect_retry_after_header
    # A GitHub secondary-limit Retry-After can be minutes; never let it hold
    # server startup for that long.
    assert retry.retry_after_max <= 120  # noqa: PLR2004
    assert {429, 500, 502, 503, 504} <= set(retry.status_forcelist)
    assert not {400, 401, 403, 404} & set(retry.status_forcelist)
    # A retried GET must hand back the final response rather than raising, so
    # the existing `resp.ok` handling keeps reporting the status.
    assert not retry.raise_on_status
