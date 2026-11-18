"""Unit tests for the helpers and orchestration added by `./ps-empire update` (PR #1276).

Covers `overwrite_base_config`, `_detect_release_channel`, `update_empire_source`
branch detection, `_git_fast_forward` per-step error reporting, `_confirm`,
`update_starkiller` / `update_empire_compiler` / `update_plugin_registry`,
the `check_no_foreign_ownership` pre-flight, `run_update`'s aggregation
+ EmpireConfig reload, and `run_setup`'s install-time sync orchestration.
"""

import logging
import os
import stat
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from empire.server.core.config import data_manager
from empire.server.utils.git_util import GitOperationException


@pytest.fixture(autouse=True)
def _restore_empire_config():
    """Undo `run_update`'s rebinding of the process-global `empire_config`.

    `run_update` reloads config by rebinding
    `config_manager.empire_config` to a fresh `EmpireConfig`
    (data_manager.py:881). Modules that did `from ... import empire_config`
    before that point keep the old object while anything imported afterwards
    -- notably the Empire modules that `ModuleService` imports lazily -- gets
    the new one, so a later test monkeypatching the config it holds a
    reference to silently fails to affect the code under test.
    """
    config_manager = data_manager.config_manager
    original = config_manager.empire_config
    yield
    config_manager.empire_config = original


@pytest.fixture
def fake_repo_root(tmp_path):
    """Lay out a minimal repo tree: `.git/` + `setup/checkout-latest-tag.sh`.

    No shipped `config.yaml` — `overwrite_base_config` reads
    `config_manager.DEFAULT_CONFIG`, not anything under this root.
    """
    (tmp_path / ".git").mkdir()
    setup_dir = tmp_path / "setup"
    setup_dir.mkdir()
    script = setup_dir / "checkout-latest-tag.sh"
    script.write_text("#!/bin/bash\nexit 0\n")
    return tmp_path


# ---------- overwrite_base_config ----------


@pytest.fixture
def shipped_config(tmp_path, monkeypatch):
    """Point `DEFAULT_CONFIG` at a template this test owns."""
    src = tmp_path / "shipped-config.yaml"
    src.write_text("starkiller:\n  ref: 4.0-dev\n")
    monkeypatch.setattr(data_manager.config_manager, "DEFAULT_CONFIG", src)
    return src


def test_overwrite_base_config_copies_template(tmp_path, shipped_config, monkeypatch):
    dst = tmp_path / "active-config.yaml"
    dst.write_text("starkiller:\n  ref: stale\n")
    monkeypatch.setattr(data_manager.config_manager, "CONFIG_PATH", dst)

    assert data_manager.overwrite_base_config() is True
    assert dst.read_text() == "starkiller:\n  ref: 4.0-dev\n"


def test_overwrite_base_config_missing_src_returns_false(tmp_path, monkeypatch):
    dst = tmp_path / "active.yaml"
    monkeypatch.setattr(
        data_manager.config_manager, "DEFAULT_CONFIG", tmp_path / "never-shipped.yaml"
    )
    monkeypatch.setattr(data_manager.config_manager, "CONFIG_PATH", dst)

    assert data_manager.overwrite_base_config() is False
    assert not dst.exists()


def test_overwrite_base_config_same_path_skips_copy(shipped_config, monkeypatch):
    monkeypatch.setattr(data_manager.config_manager, "CONFIG_PATH", shipped_config)

    # Should detect that src and dst resolve to the same file and skip the
    # copy without raising shutil.SameFileError.
    assert data_manager.overwrite_base_config() is True


def test_overwrite_base_config_returns_false_on_oserror(
    tmp_path, shipped_config, monkeypatch
):
    dst = tmp_path / "active.yaml"
    monkeypatch.setattr(data_manager.config_manager, "CONFIG_PATH", dst)

    def boom(*_args, **_kwargs):
        raise PermissionError("dst is root-owned")

    monkeypatch.setattr(data_manager.config_manager, "seed_config", boom)

    assert data_manager.overwrite_base_config() is False


# ---------- _detect_release_channel ----------


@pytest.mark.parametrize(
    ("remote_url", "expected"),
    [
        ("git@github.com:BC-SECURITY/Empire-Sponsors.git", "sponsors"),
        ("https://github.com/BC-SECURITY/Empire-Sponsors", "sponsors"),
        ("git@github.com:BC-SECURITY/Empire-Kali.git", "kali"),
        ("https://github.com/BC-SECURITY/Empire.git", None),
    ],
)
def test_detect_release_channel_from_remote_url(
    tmp_path, monkeypatch, remote_url, expected
):
    monkeypatch.setattr(data_manager, "run_as_user", lambda *_a, **_kw: remote_url)
    assert data_manager._detect_release_channel(tmp_path) == expected


def test_detect_release_channel_subprocess_failure_warns_and_returns_none(
    tmp_path, monkeypatch, capsys
):
    """Silent None on subprocess failure would downgrade a sponsors/kali
    install to mainline tags with no greppable breadcrumb — warn loudly."""

    def fail(*_a, **_kw):
        raise subprocess.CalledProcessError(128, ["git", "remote", "get-url", "origin"])

    monkeypatch.setattr(data_manager, "run_as_user", fail)
    assert data_manager._detect_release_channel(tmp_path) is None
    out = capsys.readouterr().out
    assert "could not read 'origin' remote" in out
    assert "treating as mainline" in out


def test_detect_release_channel_empty_stdout_warns_and_returns_none(
    tmp_path, monkeypatch, capsys
):
    monkeypatch.setattr(data_manager, "run_as_user", lambda *_a, **_kw: "")
    assert data_manager._detect_release_channel(tmp_path) is None
    out = capsys.readouterr().out
    assert "empty URL" in out
    assert "treating as mainline" in out


# ---------- update_empire_source ----------


def test_update_empire_source_non_git_skips(tmp_path):
    # No .git directory — should banner and return True without subprocess work.
    assert data_manager.update_empire_source(tmp_path) is True


def test_update_empire_source_on_branch_skips_with_warning(fake_repo_root, monkeypatch):
    calls = []

    def fake(cmd, **kwargs):
        calls.append(cmd)
        if cmd[:2] == ["git", "fetch"]:
            return None
        if cmd[:3] == ["git", "branch", "--show-current"]:
            return "sponsors-main"  # non-empty → on a branch
        pytest.fail(f"unexpected call: {cmd}")
        return None

    monkeypatch.setattr(data_manager, "run_as_user", fake)
    assert data_manager.update_empire_source(fake_repo_root) is True
    # The bash script must NOT be invoked when on a branch.
    assert not any("checkout-latest-tag.sh" in " ".join(c) for c in calls)


def test_update_empire_source_detached_runs_checkout_script(
    fake_repo_root, monkeypatch
):
    calls = []

    def fake(cmd, **kwargs):
        calls.append(cmd)
        if cmd[:2] == ["git", "fetch"]:
            return None
        if cmd[:3] == ["git", "branch", "--show-current"]:
            return ""  # empty → detached HEAD
        if cmd[:3] == ["git", "remote", "get-url"]:
            return "git@github.com:BC-SECURITY/Empire-Sponsors.git"
        if cmd[0] == "bash" and "checkout-latest-tag.sh" in cmd[1]:
            assert cmd[-1] == "sponsors", "channel arg should be 'sponsors'"
            return None
        pytest.fail(f"unexpected call: {cmd}")
        return None

    monkeypatch.setattr(data_manager, "run_as_user", fake)
    assert data_manager.update_empire_source(fake_repo_root) is True
    assert any("checkout-latest-tag.sh" in " ".join(c) for c in calls)


def test_update_empire_source_fetch_failure_returns_false(fake_repo_root, monkeypatch):
    def fake(cmd, **kwargs):
        if cmd[:2] == ["git", "fetch"]:
            raise subprocess.CalledProcessError(128, cmd)
        pytest.fail(f"unexpected call: {cmd}")

    monkeypatch.setattr(data_manager, "run_as_user", fake)
    assert data_manager.update_empire_source(fake_repo_root) is False


def test_update_empire_source_missing_script_returns_false(tmp_path, monkeypatch):
    (tmp_path / ".git").mkdir()  # is a git checkout
    # No setup/checkout-latest-tag.sh

    def fake(cmd, **kwargs):
        if cmd[:2] == ["git", "fetch"]:
            return None
        if cmd[:3] == ["git", "branch", "--show-current"]:
            return ""  # detached
        pytest.fail(f"unexpected call: {cmd}")
        return None

    monkeypatch.setattr(data_manager, "run_as_user", fake)
    assert data_manager.update_empire_source(tmp_path) is False


# ---------- _git_fast_forward per-step error reporting ----------


def test_git_fast_forward_happy_path(tmp_path, monkeypatch):
    target = tmp_path / "starkiller"
    target.mkdir()

    def fake(cmd, **kwargs):
        # `branch --show-current` runs with capture_output=True; everything
        # else (fetch/checkout/pull) runs without.
        if kwargs.get("capture_output"):
            return "main\n"
        return None

    monkeypatch.setattr(data_manager, "run_as_user", fake)
    assert data_manager._git_fast_forward(target, "main", "Starkiller") is True


@pytest.mark.parametrize(
    ("failing_step", "expected_label"),
    [
        ("fetch", "git fetch failed"),
        ("checkout", "git checkout failed"),
        ("pull", "git pull failed"),
    ],
)
def test_git_fast_forward_names_failing_step(
    tmp_path, monkeypatch, capsys, failing_step, expected_label
):
    target = tmp_path / "starkiller"
    target.mkdir()

    def fake(cmd, **kwargs):
        # `branch --show-current` (capture_output=True) reports a branch so
        # the pull step is reached.
        if kwargs.get("capture_output"):
            return "main\n"
        # cmd[1] is the git verb (fetch/checkout/pull) — fail the parametrized one.
        if cmd[1] == failing_step:
            raise subprocess.CalledProcessError(1, cmd)
        return None

    monkeypatch.setattr(data_manager, "run_as_user", fake)
    assert data_manager._git_fast_forward(target, "main", "Starkiller") is False

    captured = capsys.readouterr()
    assert expected_label in captured.out
    assert "Starkiller" in captured.out


def test_git_fast_forward_skips_pull_on_detached_head(tmp_path, monkeypatch, capsys):
    """`ref` may be a tag/SHA — after checkout we land on detached HEAD,
    where `git pull --ff-only` errors out. Skip the pull cleanly."""
    target = tmp_path / "starkiller"
    target.mkdir()
    invoked = []

    def fake(cmd, **kwargs):
        invoked.append(tuple(cmd))
        if kwargs.get("capture_output"):
            # Empty stdout = detached HEAD.
            return ""
        return None

    monkeypatch.setattr(data_manager, "run_as_user", fake)
    assert data_manager._git_fast_forward(target, "v6.5.0", "Starkiller") is True
    assert ("git", "pull", "--ff-only") not in invoked
    assert "detached HEAD" in capsys.readouterr().out


# ---------- _confirm ----------


def test_confirm_assume_yes_returns_true_without_prompting(monkeypatch):
    def boom(*_a, **_kw):
        pytest.fail("input() should not be called when assume_yes=True")

    monkeypatch.setattr("builtins.input", boom)
    assert data_manager._confirm("Migrate?", assume_yes=True) is True


def test_confirm_eof_exits_non_zero(monkeypatch, capsys):
    """Non-TTY without -y must be a hard error, not a silent "no" — otherwise
    CI runs without -y skip migrations and the aggregator exits 0."""

    def raise_eof(_prompt):
        raise EOFError

    monkeypatch.setattr("builtins.input", raise_eof)
    with pytest.raises(SystemExit) as excinfo:
        data_manager._confirm("Migrate?", assume_yes=False)
    assert excinfo.value.code == 2  # noqa: PLR2004 — Unix "misuse of args" convention
    assert "No interactive TTY" in capsys.readouterr().out


@pytest.mark.parametrize(
    ("answer", "expected"),
    [("y", True), ("Y", True), ("yes", True), ("Yes", True), ("n", False), ("", False)],
)
def test_confirm_parses_answer(monkeypatch, answer, expected):
    monkeypatch.setattr("builtins.input", lambda _p: answer)
    assert data_manager._confirm("Migrate?", assume_yes=False) is expected


# ---------- update_starkiller / update_empire_compiler / update_plugin_registry ----------


def test_update_starkiller_existing_checkout_fast_forwards(tmp_path, monkeypatch):
    starkiller_root = tmp_path / "starkiller"
    target = starkiller_root / "4.0-dev"
    (target / ".git").mkdir(parents=True)
    monkeypatch.setattr(data_manager.config_manager, "DATA_DIR", tmp_path)
    # `_git_fast_forward` invokes `branch --show-current` with
    # `capture_output=True`; return a branch so the pull step runs.
    monkeypatch.setattr(
        data_manager,
        "run_as_user",
        lambda *_a, **kw: "4.0-dev\n" if kw.get("capture_output") else None,
    )

    cfg = data_manager.StarkillerConfig(ref="4.0-dev")
    assert data_manager.update_starkiller(cfg, assume_yes=True) is True


def test_update_starkiller_first_run_clones(tmp_path, monkeypatch):
    monkeypatch.setattr(data_manager.config_manager, "DATA_DIR", tmp_path)
    cloned = []

    def fake_sync(cfg):
        cloned.append(cfg.ref)

    monkeypatch.setattr(data_manager, "sync_starkiller", fake_sync)
    cfg = data_manager.StarkillerConfig(ref="4.0-dev")
    assert data_manager.update_starkiller(cfg, assume_yes=True) is True
    assert cloned == ["4.0-dev"]


def test_update_starkiller_cached_other_ref_declined_skips(
    tmp_path, monkeypatch, capsys
):
    starkiller_root = tmp_path / "starkiller"
    (starkiller_root / "sponsors-main").mkdir(parents=True)
    monkeypatch.setattr(data_manager.config_manager, "DATA_DIR", tmp_path)
    monkeypatch.setattr("builtins.input", lambda _p: "n")

    def fake_sync(_cfg):
        pytest.fail("sync_starkiller should not be called when prompt declined")

    monkeypatch.setattr(data_manager, "sync_starkiller", fake_sync)

    cfg = data_manager.StarkillerConfig(ref="4.0-dev")
    assert data_manager.update_starkiller(cfg, assume_yes=False) is True
    assert "migration skipped" in capsys.readouterr().out


# ---------- sync_starkiller directory override ----------


def test_sync_starkiller_directory_override_skips_clone(tmp_path, monkeypatch):
    """A configured `directory` must be used as-is with no network access.

    This is the whole point of the override: an air-gapped or distro install
    has no way to reach GitHub, so reaching `clone_git_repo` at all is a
    failure regardless of what the function returns.
    """
    build_dir = tmp_path / "starkiller-build"
    build_dir.mkdir()

    def boom(*_a, **_kw):
        pytest.fail("clone_git_repo must not run when `directory` is set")

    monkeypatch.setattr(data_manager, "clone_git_repo", boom)
    cfg = data_manager.StarkillerConfig(directory=str(build_dir))

    assert data_manager.sync_starkiller(cfg) == build_dir


def test_sync_starkiller_directory_override_missing_does_not_fall_back(
    tmp_path, monkeypatch, caplog
):
    """A typo'd `directory` must NOT fall back to cloning.

    Falling back would turn a config typo into an unexpected GitHub fetch on
    a machine meant to be offline, and would silently serve upstream
    Starkiller in place of the operator's vetted build. The compiler's
    override does fall back; this one deliberately does not.
    """
    missing = tmp_path / "does-not-exist"

    def boom(*_a, **_kw):
        pytest.fail("a missing `directory` must not fall back to a clone")

    monkeypatch.setattr(data_manager, "clone_git_repo", boom)
    cfg = data_manager.StarkillerConfig(directory=str(missing))

    with caplog.at_level(logging.ERROR):
        assert data_manager.sync_starkiller(cfg) == missing

    assert "does not exist" in caplog.text
    assert str(missing) in caplog.text


def test_sync_starkiller_directory_override_expands_user(tmp_path, monkeypatch):
    """`~/starkiller` is a natural operator value.

    Without expansion, `Path("~/starkiller")` is CWD-relative, and with no
    fallback the operator gets no UI and no clue why.
    """
    monkeypatch.setenv("HOME", str(tmp_path))
    build_dir = tmp_path / "starkiller-build"
    build_dir.mkdir()

    monkeypatch.setattr(
        data_manager,
        "clone_git_repo",
        lambda *_a, **_kw: pytest.fail("clone must not run"),
    )
    cfg = data_manager.StarkillerConfig(directory="~/starkiller-build")

    assert data_manager.sync_starkiller(cfg) == build_dir


def test_unresolvable_tilde_user_is_diagnosed_not_raised(capsys):
    """`Path.expanduser()` raises `RuntimeError` for a `~user` whose home can't
    be resolved -- a typo'd username, or an unmapped uid in the very containers
    this override exists to serve. Both entry points are asserted because both
    would surface it as a traceback: `run_setup` catches only
    `GitOperationException` around `sync_starkiller`, and `update`'s override
    branch has no handler at all.
    """
    cfg = data_manager.StarkillerConfig(directory="~nosuchuser12345/starkiller")

    assert data_manager.sync_starkiller(cfg) == Path("~nosuchuser12345/starkiller")
    assert data_manager.update_starkiller(cfg, assume_yes=True) is False

    out = capsys.readouterr().out
    assert "no resolvable home directory" in out
    # The unexpanded value is not absolute, so the relative-path warning would
    # otherwise fire and blame the working directory -- advice that leads
    # nowhere, since moving the config or the process changes nothing here.
    assert "is relative" not in out
    assert "is not a directory" not in out


def test_sync_starkiller_without_directory_still_clones(tmp_path, monkeypatch):
    """The negative case: unset `directory` must behave exactly as before.

    Guards against the override short-circuit swallowing the default path.
    """
    monkeypatch.setattr(data_manager.config_manager, "DATA_DIR", tmp_path)
    calls = []
    monkeypatch.setattr(
        data_manager, "clone_git_repo", lambda *a, **_kw: calls.append(a)
    )
    cfg = data_manager.StarkillerConfig(ref="sponsors-main")

    result = data_manager.sync_starkiller(cfg)

    assert result == tmp_path / "starkiller" / "sponsors-main"
    assert len(calls) == 1


def test_update_empire_compiler_directory_override_short_circuits(monkeypatch):
    cfg = data_manager.EmpireCompilerConfig(directory="/tmp/local-compiler")
    # Should not call sync_empire_compiler or _resolve_compiler_platform
    monkeypatch.setattr(
        data_manager,
        "_resolve_compiler_platform",
        lambda: pytest.fail("should not resolve when directory override is set"),
    )
    assert data_manager.update_empire_compiler(cfg, assume_yes=True) is True


def test_update_starkiller_directory_override_short_circuits(
    tmp_path, monkeypatch, capsys
):
    """`update` must not touch an externally managed Starkiller directory.

    Fast-forwarding a read-only store path or a distro-owned directory fails,
    and "update" has no meaning for an install the operator manages elsewhere.
    """
    monkeypatch.setattr(data_manager, "_git_fast_forward", boom_no_git)
    monkeypatch.setattr(data_manager, "sync_starkiller", boom_no_git)
    cfg = data_manager.StarkillerConfig(directory=str(_layout(tmp_path, dist=True)))

    assert data_manager.update_starkiller(cfg, assume_yes=True) is True
    assert "nothing to update" in capsys.readouterr().out


def test_update_starkiller_directory_override_fails_on_a_bad_path(monkeypatch, capsys):
    """`update` is what operators run after editing config. Reporting success
    for an override `setup` would reject hands them a green "Update complete"
    over a server that will boot with no UI.
    """
    monkeypatch.setattr(data_manager, "_git_fast_forward", boom_no_git)
    monkeypatch.setattr(data_manager, "sync_starkiller", boom_no_git)
    cfg = data_manager.StarkillerConfig(directory="/nonexistent/starkiller")

    assert data_manager.update_starkiller(cfg, assume_yes=True) is False
    assert "is not a directory" in capsys.readouterr().out


def test_update_empire_compiler_already_on_ref_returns_true(tmp_path, monkeypatch):
    compiler_dir = tmp_path / "empire-compiler"
    compiler_dir.mkdir()
    # Match the platform-arch-ref naming scheme produced by sync_empire_compiler.
    monkeypatch.setattr(
        data_manager, "_resolve_compiler_platform", lambda: ("linux", "x64")
    )
    binary = (
        compiler_dir
        / "EmpireCompiler-linux-x64-v1.2.3"
        / "EmpireCompiler"
        / "EmpireCompiler"
    )
    binary.parent.mkdir(parents=True)
    binary.write_bytes(b"#!/bin/sh\n")
    monkeypatch.setattr(data_manager.config_manager, "DATA_DIR", tmp_path)

    def fake_sync(_cfg):
        pytest.fail("sync_empire_compiler should not run on cache hit")

    monkeypatch.setattr(data_manager, "sync_empire_compiler", fake_sync)

    cfg = data_manager.EmpireCompilerConfig(repo="r", ref="v1.2.3")
    assert data_manager.update_empire_compiler(cfg, assume_yes=True) is True


def test_update_empire_compiler_redownloads_dir_without_binary(
    tmp_path, monkeypatch, capsys
):
    """`update` is the tool operators are told to run to repair the cache, so
    it must agree with the server about what counts as installed: a directory
    on the right ref but without the binary is an interrupted extract, not
    "up to date"."""
    compiler_dir = tmp_path / "empire-compiler"
    (compiler_dir / "EmpireCompiler-linux-x64-v1.2.3" / "EmpireCompiler").mkdir(
        parents=True
    )
    monkeypatch.setattr(
        data_manager, "_resolve_compiler_platform", lambda: ("linux", "x64")
    )
    monkeypatch.setattr(data_manager.config_manager, "DATA_DIR", tmp_path)
    synced = []
    monkeypatch.setattr(
        data_manager, "sync_empire_compiler", lambda cfg: synced.append(cfg) or object()
    )
    monkeypatch.setattr(
        data_manager, "_confirm", lambda *_a, **_k: pytest.fail("no migration prompt")
    )

    cfg = data_manager.EmpireCompilerConfig(repo="r", ref="v1.2.3")
    assert data_manager.update_empire_compiler(cfg, assume_yes=True) is True

    assert synced == [cfg]
    assert "up to date" not in capsys.readouterr().out


def test_update_plugin_registry_no_git_url_returns_true(tmp_path):
    cfg = data_manager.PluginRegistryConfig(
        name="local", location=tmp_path / "registry.yaml"
    )
    assert data_manager.update_plugin_registry(cfg, assume_yes=True) is True


def test_update_plugin_registry_existing_checkout_fast_forwards(tmp_path, monkeypatch):
    base = tmp_path / "plugin-registries" / "marketplace"
    target = base / "main"
    (target / ".git").mkdir(parents=True)
    monkeypatch.setattr(data_manager.config_manager, "DATA_DIR", tmp_path)
    monkeypatch.setattr(
        data_manager,
        "run_as_user",
        lambda *_a, **kw: "main\n" if kw.get("capture_output") else None,
    )

    cfg = data_manager.PluginRegistryConfig(
        name="marketplace", git_url="git://example.com/r.git", ref="main"
    )
    assert data_manager.update_plugin_registry(cfg, assume_yes=True) is True


def test_update_starkiller_clone_failure_returns_false(tmp_path, monkeypatch, capsys):
    """`GitOperationException` from `sync_starkiller` must surface via the
    `[x]` banner and return False — otherwise it propagates past `run_update`
    as a raw traceback, bypassing the aggregator."""
    monkeypatch.setattr(data_manager.config_manager, "DATA_DIR", tmp_path)

    def fail(_cfg):
        raise GitOperationException("clone failed: bad ref")

    monkeypatch.setattr(data_manager, "sync_starkiller", fail)

    cfg = data_manager.StarkillerConfig(ref="4.0-dev")
    assert data_manager.update_starkiller(cfg, assume_yes=True) is False
    out = capsys.readouterr().out
    assert "Starkiller: clone failed" in out
    assert "bad ref" in out


def test_update_empire_compiler_sync_returns_none_is_failure(
    tmp_path, monkeypatch, capsys
):
    """`sync_empire_compiler` returns None (no exception) on unsupported
    arch / missing asset / GitHub API failure. The wrapper must treat that
    as failure — discarding the return value reports "[*] Update complete."
    while the user hits the actual error several layers later."""
    monkeypatch.setattr(data_manager.config_manager, "DATA_DIR", tmp_path)
    monkeypatch.setattr(
        data_manager, "_resolve_compiler_platform", lambda: ("linux", "x64")
    )
    monkeypatch.setattr(data_manager, "sync_empire_compiler", lambda _cfg: None)

    cfg = data_manager.EmpireCompilerConfig(repo="r", ref="v1.2.3")
    assert data_manager.update_empire_compiler(cfg, assume_yes=True) is False
    out = capsys.readouterr().out
    assert "Empire Compiler: sync returned no path" in out


def test_update_empire_compiler_request_failure_returns_false(
    tmp_path, monkeypatch, capsys
):
    """A sync failure (DNS failure, timeout, connection reset, disk) must be
    caught and its operator-facing message reported via `[x]`, not propagate."""
    monkeypatch.setattr(data_manager.config_manager, "DATA_DIR", tmp_path)
    monkeypatch.setattr(
        data_manager, "_resolve_compiler_platform", lambda: ("linux", "x64")
    )

    def boom(_cfg):
        raise data_manager.CompilerSyncError(
            "network error fetching the release (simulated DNS failure); "
            "re-run './ps-empire setup' once GitHub is reachable"
        )

    monkeypatch.setattr(data_manager, "sync_empire_compiler", boom)

    cfg = data_manager.EmpireCompilerConfig(repo="r", ref="v1.2.3")
    assert data_manager.update_empire_compiler(cfg, assume_yes=True) is False
    out = capsys.readouterr().out
    assert "[x] Empire Compiler: network error" in out
    assert "simulated DNS failure" in out
    assert "once GitHub is reachable" in out


def test_update_plugin_registry_clone_failure_returns_false(
    tmp_path, monkeypatch, capsys
):
    monkeypatch.setattr(data_manager.config_manager, "DATA_DIR", tmp_path)

    def fail(_cfg):
        raise GitOperationException("bad git url")

    monkeypatch.setattr(data_manager, "sync_plugin_registry", fail)

    cfg = data_manager.PluginRegistryConfig(
        name="marketplace", git_url="git://example.com/bad.git", ref="main"
    )
    assert data_manager.update_plugin_registry(cfg, assume_yes=True) is False
    out = capsys.readouterr().out
    assert "Plugin Registry 'marketplace': clone failed" in out
    assert "bad git url" in out


# ---------- pre-flight ownership check ----------


def test_check_no_foreign_ownership_passes_when_user_owned(tmp_path, monkeypatch):
    config_dir = tmp_path / "config"
    config_dir.mkdir()
    config_path = config_dir / "config.yaml"
    config_path.write_text("starkiller:\n  ref: x\n")
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    monkeypatch.setattr(data_manager.config_manager, "CONFIG_DIR", config_dir)
    monkeypatch.setattr(data_manager.config_manager, "CONFIG_PATH", config_path)
    monkeypatch.setattr(data_manager.config_manager, "DATA_DIR", data_dir)

    assert data_manager.check_no_foreign_ownership() is True


def test_check_no_foreign_ownership_blocks_when_root_owned(
    tmp_path, monkeypatch, capsys
):
    config_dir = tmp_path / "config"
    config_dir.mkdir()
    config_path = config_dir / "config.yaml"
    config_path.write_text("x")
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    monkeypatch.setattr(data_manager.config_manager, "CONFIG_DIR", config_dir)
    monkeypatch.setattr(data_manager.config_manager, "CONFIG_PATH", config_path)
    monkeypatch.setattr(data_manager.config_manager, "DATA_DIR", data_dir)

    # Pretend the current user is uid 99999 — none of the tmp paths match.
    monkeypatch.setattr(data_manager.os, "getuid", lambda: 99999)
    monkeypatch.setenv("USER", "kali")

    assert data_manager.check_no_foreign_ownership() is False
    out = capsys.readouterr().out
    assert "owned by another user" in out
    assert "sudo chown -R kali" in out
    assert str(config_dir) in out
    assert str(data_dir) in out


def test_run_update_aborts_on_foreign_ownership(tmp_path, monkeypatch):
    monkeypatch.setattr(data_manager, "check_no_foreign_ownership", lambda: False)

    def boom(*_a, **_kw):
        pytest.fail("downstream helpers should not run when ownership check fails")

    monkeypatch.setattr(data_manager, "update_empire_source", boom)
    monkeypatch.setattr(data_manager, "overwrite_base_config", boom)

    args = type("Args", (), {"yes": True})()
    # Should return False (caller maps to non-zero exit) without invoking
    # downstream helpers.
    assert data_manager.run_update(args, repo_root=tmp_path) is False


def test_check_no_foreign_ownership_warns_on_unstat_able(tmp_path, monkeypatch, capsys):
    """A path that exists but can't be stat'd must surface a warning, not
    silently pass — otherwise the pre-flight gives false reassurance."""
    config_dir = tmp_path / "config"
    config_dir.mkdir()
    config_path = config_dir / "config.yaml"
    config_path.write_text("x")
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    monkeypatch.setattr(data_manager.config_manager, "CONFIG_DIR", config_dir)
    monkeypatch.setattr(data_manager.config_manager, "CONFIG_PATH", config_path)
    monkeypatch.setattr(data_manager.config_manager, "DATA_DIR", data_dir)

    real_stat = data_manager.Path.stat

    def stat_raises_for_config(self, *args, **kwargs):
        if self == config_path:
            raise PermissionError("simulated EACCES on stat")
        return real_stat(self, *args, **kwargs)

    monkeypatch.setattr(data_manager.Path, "stat", stat_raises_for_config)

    # Other two paths are user-owned → no foreign-owned, but config_path
    # couldn't be stat'd — we expect True (no foreign found) AND a warning.
    assert data_manager.check_no_foreign_ownership() is True
    assert "Could not stat" in capsys.readouterr().out


def test_check_no_foreign_ownership_falls_back_when_pwd_lookup_fails(
    tmp_path, monkeypatch, capsys
):
    """A uid not present in the passwd database (slim containers, deleted
    accounts) must not crash the pre-flight; fall back to the numeric uid
    in the chown hint."""
    config_dir = tmp_path / "config"
    config_dir.mkdir()
    monkeypatch.setattr(data_manager.config_manager, "CONFIG_DIR", config_dir)
    monkeypatch.setattr(
        data_manager.config_manager, "CONFIG_PATH", config_dir / "config.yaml"
    )
    monkeypatch.setattr(data_manager.config_manager, "DATA_DIR", tmp_path / "data")
    (tmp_path / "data").mkdir()
    monkeypatch.setattr(data_manager.os, "getuid", lambda: 99999)
    monkeypatch.delenv("USER", raising=False)

    def raise_keyerror(_uid):
        raise KeyError(99999)

    monkeypatch.setattr(data_manager.pwd, "getpwuid", raise_keyerror)

    assert data_manager.check_no_foreign_ownership() is False
    out = capsys.readouterr().out
    # Numeric uid fallback rather than a crash.
    assert "sudo chown -R 99999" in out


def test_check_no_foreign_ownership_detects_root_owned_starkiller_clone(
    tmp_path, monkeypatch, capsys
):
    """Real-world failure mode: DATA_DIR itself user-owned but a Starkiller
    clone underneath is root-owned — git's dubious-ownership check trips
    later. The pre-flight must catch this."""
    data_dir = tmp_path / "data"
    starkiller_root = data_dir / "starkiller"
    starkiller_clone = starkiller_root / "4.0-dev"
    (starkiller_clone / ".git").mkdir(parents=True)
    monkeypatch.setattr(data_manager.config_manager, "CONFIG_DIR", tmp_path / "config")
    (tmp_path / "config").mkdir()
    monkeypatch.setattr(
        data_manager.config_manager, "CONFIG_PATH", tmp_path / "config" / "config.yaml"
    )
    monkeypatch.setattr(data_manager.config_manager, "DATA_DIR", data_dir)

    real_stat = data_manager.Path.stat

    def stat_with_root_starkiller(self, *args, **kwargs):
        if self == starkiller_clone:
            # Pretend this child is owned by *another* user; everything else
            # delegates to the real stat (= current user's uid). Derived from
            # the current uid rather than hardcoded to 0, because the check is
            # `st_uid != os.getuid()` — so a literal 0 is not foreign when the
            # suite runs as root, which is what happens inside the Docker
            # image. `st_mode` carries the directory bit because
            # `_ownership_check_paths` routes children through `is_dir()`
            # before adding them, and on 3.13 `is_dir` reads
            # `S_ISDIR(st_mode)` via the patched `stat`.
            class FakeStat:
                st_mode = stat.S_IFDIR | 0o755
                st_uid = os.getuid() + 1

            return FakeStat()
        return real_stat(self, *args, **kwargs)

    monkeypatch.setattr(data_manager.Path, "stat", stat_with_root_starkiller)

    assert data_manager.check_no_foreign_ownership() is False
    out = capsys.readouterr().out
    assert str(starkiller_clone) in out


# ---------- update_database ----------


@pytest.fixture
def fake_db_base(monkeypatch):
    """Stub out empire.server.core.db.base so update_database can be tested
    without standing up a real database. Tests override individual attrs
    (`pending_migrations`, `backup_db`, `stamp_and_migrate`) as needed.
    """
    from empire.server.core.db import base as base_mod

    # Defaults: already-at-head, never called.
    monkeypatch.setattr(base_mod, "pending_migrations", lambda: ("0003", "0003"))
    monkeypatch.setattr(
        base_mod,
        "backup_db",
        lambda: pytest.fail("backup_db should not be called in this test"),
    )
    monkeypatch.setattr(
        base_mod,
        "stamp_and_migrate",
        lambda: pytest.fail("stamp_and_migrate should not be called in this test"),
    )
    return base_mod


def test_update_database_noop_when_at_head(fake_db_base, capsys):
    """No migration needed — no prompt, no backup, no migrate, success."""
    assert data_manager.update_database(assume_yes=False) is True
    out = capsys.readouterr().out
    assert "schema up to date" in out


def test_update_database_applies_pending_migrations(
    fake_db_base, monkeypatch, capsys, tmp_path
):
    """Pending migrations — backup runs, stamp_and_migrate runs, success."""
    monkeypatch.setattr(fake_db_base, "pending_migrations", lambda: ("0002", "0003"))

    backup_called = []
    migrate_called = []
    backup_path = tmp_path / "empire.db.20260515_120000"

    monkeypatch.setattr(
        fake_db_base, "backup_db", lambda: backup_called.append(True) or backup_path
    )
    monkeypatch.setattr(
        fake_db_base, "stamp_and_migrate", lambda: migrate_called.append(True)
    )

    assert data_manager.update_database(assume_yes=True) is True
    assert backup_called == [True]
    assert migrate_called == [True]
    out = capsys.readouterr().out
    assert "pending migrations" in out
    assert str(backup_path) in out
    assert "migrations complete" in out


def test_update_database_user_declines(fake_db_base, monkeypatch, capsys):
    """User answers 'n' to the prompt — no backup, no migrate, returns False."""
    monkeypatch.setattr(fake_db_base, "pending_migrations", lambda: ("0002", "0003"))
    monkeypatch.setattr("builtins.input", lambda _prompt: "n")

    assert data_manager.update_database(assume_yes=False) is False
    out = capsys.readouterr().out
    assert "skipping migrations" in out


def test_update_database_backup_failure_does_not_block_migration(
    fake_db_base, monkeypatch, capsys
):
    """backup_db returning None should warn but proceed with migration."""
    monkeypatch.setattr(fake_db_base, "pending_migrations", lambda: ("0002", "0003"))
    monkeypatch.setattr(fake_db_base, "backup_db", lambda: None)

    migrate_called = []
    monkeypatch.setattr(
        fake_db_base, "stamp_and_migrate", lambda: migrate_called.append(True)
    )

    assert data_manager.update_database(assume_yes=True) is True
    assert migrate_called == [True]
    out = capsys.readouterr().out
    assert "backup did not produce a file" in out
    assert "migrations complete" in out


def test_update_database_migration_failure_returns_false(
    fake_db_base, monkeypatch, capsys, tmp_path
):
    """stamp_and_migrate raising surfaces an error referencing the backup path."""
    monkeypatch.setattr(fake_db_base, "pending_migrations", lambda: ("0002", "0003"))
    backup_path = tmp_path / "empire.db.20260515_120000"
    monkeypatch.setattr(fake_db_base, "backup_db", lambda: backup_path)

    def boom():
        raise RuntimeError("migration boom")

    monkeypatch.setattr(fake_db_base, "stamp_and_migrate", boom)

    assert data_manager.update_database(assume_yes=True) is False
    out = capsys.readouterr().out
    assert "migration failed" in out
    assert str(backup_path) in out


def test_update_database_revision_check_failure_returns_false(
    fake_db_base, monkeypatch, capsys
):
    """pending_migrations raising should be reported and abort the step."""

    def boom():
        raise RuntimeError("alembic boom")

    monkeypatch.setattr(fake_db_base, "pending_migrations", boom)

    assert data_manager.update_database(assume_yes=True) is False
    out = capsys.readouterr().out
    assert "failed to read Alembic revision state" in out


def test_update_database_untracked_db_labels_correctly(
    fake_db_base, monkeypatch, capsys
):
    """Pre-Alembic DB (current=None) gets an 'untracked → head' label."""
    monkeypatch.setattr(fake_db_base, "pending_migrations", lambda: (None, "0003"))
    monkeypatch.setattr(fake_db_base, "backup_db", lambda: None)
    monkeypatch.setattr(fake_db_base, "stamp_and_migrate", lambda: None)

    assert data_manager.update_database(assume_yes=True) is True
    out = capsys.readouterr().out
    assert "untracked → '0003'" in out


# ---------- run_update orchestration ----------


def test_run_update_aggregates_failures_and_continues_after_source_fail(
    tmp_path, fake_repo_root, monkeypatch, capsys
):
    """Source failure must NOT short-circuit downstream steps; the result
    aggregator must list each failed label."""
    dst = tmp_path / "active.yaml"
    monkeypatch.setattr(data_manager.config_manager, "CONFIG_PATH", dst)

    # Force update_empire_source to return False without doing real git work.
    monkeypatch.setattr(data_manager, "update_empire_source", lambda _root: False)
    # Stub out the downstream helpers so we exercise just the aggregation path.
    monkeypatch.setattr(data_manager, "update_database", lambda *, assume_yes: True)
    monkeypatch.setattr(
        data_manager, "update_starkiller", lambda _cfg, *, assume_yes: True
    )
    monkeypatch.setattr(
        data_manager, "update_empire_compiler", lambda _cfg, *, assume_yes: True
    )
    monkeypatch.setattr(
        data_manager, "update_plugin_registry", lambda _cfg, *, assume_yes: True
    )

    args = type("Args", (), {"yes": True})()
    data_manager.run_update(args, repo_root=fake_repo_root)

    out = capsys.readouterr().out
    assert "Update finished with 1 failure" in out
    assert "Empire source" in out


def test_run_update_reloads_empire_config_after_overwrite(
    tmp_path, fake_repo_root, monkeypatch
):
    """Overwriting the base config must trigger an EmpireConfig reload so
    update_starkiller/update_empire_compiler see the new refs."""
    dst = tmp_path / "active.yaml"
    monkeypatch.setattr(data_manager.config_manager, "CONFIG_PATH", dst)
    monkeypatch.setattr(data_manager, "update_empire_source", lambda _root: True)
    monkeypatch.setattr(data_manager, "update_database", lambda *, assume_yes: True)
    monkeypatch.setattr(
        data_manager, "update_starkiller", lambda _cfg, *, assume_yes: True
    )
    monkeypatch.setattr(
        data_manager, "update_empire_compiler", lambda _cfg, *, assume_yes: True
    )
    monkeypatch.setattr(
        data_manager, "update_plugin_registry", lambda _cfg, *, assume_yes: True
    )

    reloaded = []
    real_cls = data_manager.config_manager.EmpireConfig

    class TrackingEmpireConfig(real_cls):
        def __init__(self, *a, **kw):
            reloaded.append(True)
            super().__init__(*a, **kw)

    monkeypatch.setattr(
        data_manager.config_manager, "EmpireConfig", TrackingEmpireConfig
    )

    args = type("Args", (), {"yes": True})()
    data_manager.run_update(args, repo_root=fake_repo_root)

    assert reloaded, "EmpireConfig was not reloaded after config overwrite"


# ---------- run_setup orchestration ----------


@pytest.fixture
def fake_setup_config(monkeypatch):
    """Minimal `config_manager.empire_config` shape for run_setup.

    Each sync function only reads attributes off the config it's handed,
    so a SimpleNamespace with the right field names is enough — we never
    let the real syncs run (the per-test monkeypatches replace them).
    """
    fake = SimpleNamespace(
        starkiller=SimpleNamespace(ref="v1.0", directory=None, enabled=True),
        empire_compiler=SimpleNamespace(),
        plugin_marketplace=SimpleNamespace(
            registries=[SimpleNamespace(name="marketplace")]
        ),
    )
    monkeypatch.setattr(data_manager.config_manager, "empire_config", fake)
    monkeypatch.setattr(data_manager, "check_no_foreign_ownership", lambda: True)
    return fake


def test_run_setup_aborts_on_foreign_ownership(monkeypatch):
    """Pre-flight failure must short-circuit and return None so the caller
    exits non-zero without invoking any sync."""
    monkeypatch.setattr(data_manager, "check_no_foreign_ownership", lambda: False)

    def boom(*_a, **_kw):
        pytest.fail("syncs must not run when ownership pre-flight fails")

    monkeypatch.setattr(data_manager, "sync_starkiller", boom)
    monkeypatch.setattr(data_manager, "sync_empire_compiler", boom)
    monkeypatch.setattr(data_manager, "sync_plugin_registry", boom)

    args = type("Args", (), {})()
    assert data_manager.run_setup(args) is None


def test_run_setup_starkiller_failure_marked_in_results(
    fake_setup_config, monkeypatch, capsys
):
    """A `GitOperationException` from `sync_starkiller` must surface via
    the `[x]` banner and land in the results dict as False — without it,
    `setup` would print nothing about the failure and the next server
    boot would crash trying to mount a missing Starkiller dir."""

    def fail(_cfg):
        raise GitOperationException("clone failed: no SSH key")

    monkeypatch.setattr(data_manager, "sync_starkiller", fail)
    monkeypatch.setattr(data_manager, "sync_empire_compiler", lambda _cfg: object())
    monkeypatch.setattr(data_manager, "sync_plugin_registry", lambda _cfg: object())

    args = type("Args", (), {})()
    results = data_manager.run_setup(args)

    assert results == {
        "Starkiller": False,
        "Empire Compiler": True,
        "Plugin Registry 'marketplace'": True,
    }
    out = capsys.readouterr().out
    assert "Starkiller: clone failed" in out
    assert "no SSH key" in out
    # Failure summary should fire once with the failing label.
    assert "Setup finished with 1 failure" in out
    assert "Starkiller" in out


def test_run_setup_compiler_returns_none_marks_failure(
    fake_setup_config, monkeypatch, capsys
):
    """`sync_empire_compiler` returns None on unsupported arch / missing
    asset / GitHub API failure. Without explicit None handling, setup
    would silently report success and the cold-cache server boot would
    crash with a confusing TypeError in `DotnetCompiler.__init__`."""
    monkeypatch.setattr(data_manager, "sync_starkiller", lambda _cfg: object())
    monkeypatch.setattr(data_manager, "sync_empire_compiler", lambda _cfg: None)
    monkeypatch.setattr(data_manager, "sync_plugin_registry", lambda _cfg: object())

    args = type("Args", (), {})()
    results = data_manager.run_setup(args)

    assert results["Empire Compiler"] is False
    out = capsys.readouterr().out
    assert "Empire Compiler: sync returned no path" in out


def test_run_setup_compiler_request_exception_marks_failure(
    fake_setup_config, monkeypatch, capsys
):
    """`requests.RequestException` mid-download (DNS failure, timeout,
    connection reset) must be caught and reported via `[x]`, not
    propagate as a raw traceback — the install-time analog of the
    update-path fix."""

    def boom(_cfg):
        raise data_manager.CompilerSyncError(
            "network error fetching the release (simulated DNS failure); "
            "re-run './ps-empire setup' once GitHub is reachable"
        )

    monkeypatch.setattr(data_manager, "sync_starkiller", lambda _cfg: object())
    monkeypatch.setattr(data_manager, "sync_empire_compiler", boom)
    monkeypatch.setattr(data_manager, "sync_plugin_registry", lambda _cfg: object())

    args = type("Args", (), {})()
    results = data_manager.run_setup(args)

    assert results["Empire Compiler"] is False
    out = capsys.readouterr().out
    assert "[x] Empire Compiler: network error" in out
    assert "simulated DNS failure" in out


def test_run_setup_plugin_registry_failure_marked_per_registry(
    fake_setup_config, monkeypatch, capsys
):
    """Per-registry result keying lets the caller (empire.py) gate
    `_auto_install_plugins` on every configured registry succeeding."""
    fake_setup_config.plugin_marketplace.registries = [
        SimpleNamespace(name="marketplace"),
        SimpleNamespace(name="sponsors"),
    ]

    def fail_for_sponsors(cfg):
        if cfg.name == "sponsors":
            raise GitOperationException("private repo, no SSH key")

    monkeypatch.setattr(data_manager, "sync_starkiller", lambda _cfg: object())
    monkeypatch.setattr(data_manager, "sync_empire_compiler", lambda _cfg: object())
    monkeypatch.setattr(data_manager, "sync_plugin_registry", fail_for_sponsors)

    args = type("Args", (), {})()
    results = data_manager.run_setup(args)

    assert results["Plugin Registry 'marketplace'"] is True
    assert results["Plugin Registry 'sponsors'"] is False
    # Caller-side gating: the dict shape must support a "all registries
    # succeeded?" filter without parsing labels by hand beyond the prefix.
    registries_ok = all(
        ok for label, ok in results.items() if label.startswith("Plugin Registry")
    )
    assert registries_ok is False

    out = capsys.readouterr().out
    assert "Plugin Registry 'sponsors': clone failed" in out
    assert "private repo, no SSH key" in out


def test_run_setup_aggregates_all_failures_in_summary(
    fake_setup_config, monkeypatch, capsys
):
    """Aggregate-then-exit: every sync runs even after earlier failures,
    and the summary lists each failed label so a fresh-install operator
    sees the full picture in one pass."""
    monkeypatch.setattr(
        data_manager,
        "sync_starkiller",
        lambda _cfg: (_ for _ in ()).throw(GitOperationException("starkiller down")),
    )
    monkeypatch.setattr(data_manager, "sync_empire_compiler", lambda _cfg: None)
    monkeypatch.setattr(
        data_manager,
        "sync_plugin_registry",
        lambda _cfg: (_ for _ in ()).throw(GitOperationException("registry down")),
    )

    args = type("Args", (), {})()
    results = data_manager.run_setup(args)

    assert all(ok is False for ok in results.values())
    out = capsys.readouterr().out
    assert "Setup finished with 3 failure(s)" in out
    assert "Starkiller" in out
    assert "Empire Compiler" in out
    assert "Plugin Registry 'marketplace'" in out


def test_run_setup_all_succeed_no_warning_summary(
    fake_setup_config, monkeypatch, capsys
):
    """Happy path: every sync succeeds, results all True, no failure
    summary banner is printed (operators shouldn't see a warning when
    nothing went wrong)."""
    monkeypatch.setattr(data_manager, "sync_starkiller", lambda _cfg: object())
    monkeypatch.setattr(data_manager, "sync_empire_compiler", lambda _cfg: object())
    monkeypatch.setattr(data_manager, "sync_plugin_registry", lambda _cfg: object())

    args = type("Args", (), {})()
    results = data_manager.run_setup(args)

    assert all(results.values())
    out = capsys.readouterr().out
    assert "Setup finished with" not in out


def test_run_setup_missing_directory_override_marks_failure(
    fake_setup_config, monkeypatch, capsys
):
    """`setup` must fail loudly on a typo'd `starkiller.directory`.

    `sync_starkiller` returns a configured directory unvalidated (it never
    falls back to a clone), so without an explicit check here `setup` prints
    its success banner and exits 0 on a misconfiguration -- and `setup` is
    the install-time path for exactly the air-gapped and distro deployments
    this override exists to serve.

    `log.error` cannot carry this: `setup_logging` is only called from
    server.py, and `empire/main.py` dispatches `setup` without it.
    """
    missing = "/nonexistent/starkiller"
    fake_setup_config.starkiller.directory = missing

    monkeypatch.setattr(data_manager, "sync_starkiller", lambda _cfg: Path(missing))
    monkeypatch.setattr(data_manager, "sync_empire_compiler", lambda _cfg: object())
    monkeypatch.setattr(data_manager, "sync_plugin_registry", lambda _cfg: object())

    args = type("Args", (), {})()
    results = data_manager.run_setup(args)

    assert results["Starkiller"] is False
    out = capsys.readouterr().out
    assert "starkiller.directory" in out
    assert missing in out
    assert "Setup finished with 1 failure" in out


def test_run_setup_present_directory_override_succeeds(
    fake_setup_config, monkeypatch, tmp_path
):
    """The positive case: a valid override (directory + dist/) records success.

    Pins that the new check keys on the path being absent, not on the
    override merely being set.
    """
    build_dir = tmp_path / "starkiller-build"
    (build_dir / "dist").mkdir(parents=True)
    (build_dir / "dist" / "index.html").write_text('<script src="/assets/i.js">')
    fake_setup_config.starkiller.directory = str(build_dir)

    monkeypatch.setattr(data_manager, "sync_starkiller", lambda _cfg: build_dir)
    monkeypatch.setattr(data_manager, "sync_empire_compiler", lambda _cfg: object())
    monkeypatch.setattr(data_manager, "sync_plugin_registry", lambda _cfg: object())

    args = type("Args", (), {})()

    assert data_manager.run_setup(args)["Starkiller"] is True


def test_run_setup_relative_directory_override_warns(
    fake_setup_config, monkeypatch, capsys, tmp_path
):
    """A relative override resolves against the process CWD, so `setup` (run
    from the repo root) and the server (launched by a systemd unit, console
    script, or container from somewhere else) can disagree about which
    directory is being served -- and `setup`'s green banner would then mean
    nothing for the boot that follows.
    """
    monkeypatch.chdir(tmp_path)
    (tmp_path / "starkiller-build" / "dist").mkdir(parents=True)
    (tmp_path / "starkiller-build" / "dist" / "index.html").write_text("<html>")
    fake_setup_config.starkiller.directory = "starkiller-build"

    monkeypatch.setattr(
        data_manager, "sync_starkiller", lambda _cfg: Path("starkiller-build")
    )
    monkeypatch.setattr(data_manager, "sync_empire_compiler", lambda _cfg: object())
    monkeypatch.setattr(data_manager, "sync_plugin_registry", lambda _cfg: object())

    args = type("Args", (), {})()
    results = data_manager.run_setup(args)

    # Relative is legal, so the step still passes -- but it must not pass silently.
    assert results["Starkiller"] is True
    out = capsys.readouterr().out
    assert "is relative" in out
    assert str(tmp_path) in out


def _run_setup_against(fake_setup_config, monkeypatch, build_dir):
    fake_setup_config.starkiller.directory = str(build_dir)
    monkeypatch.setattr(data_manager, "sync_starkiller", lambda _cfg: build_dir)
    monkeypatch.setattr(data_manager, "sync_empire_compiler", lambda _cfg: object())
    monkeypatch.setattr(data_manager, "sync_plugin_registry", lambda _cfg: object())
    return data_manager.run_setup(type("Args", (), {})())


def test_run_setup_flattened_build_succeeds(
    fake_setup_config, monkeypatch, tmp_path, capsys
):
    """The nixpkgs derivation does `cp -r dist/** $out`, so its files land
    directly at `$out/` with no `dist/` level -- and the level above `$out` is
    `/nix/store`, so there is no other value the packager could supply.
    Requiring `dist/` would leave that package unusable, which is the case
    this override exists to serve.
    """
    build_dir = tmp_path / "starkiller-out"
    build_dir.mkdir()
    (build_dir / "index.html").write_text('<script src="/assets/index-abc.js">')

    results = _run_setup_against(fake_setup_config, monkeypatch, build_dir)

    assert results["Starkiller"] is True
    assert "Setup finished with" not in capsys.readouterr().out


def test_run_setup_unbuilt_checkout_marks_failure(
    fake_setup_config, monkeypatch, tmp_path, capsys
):
    """A source checkout carries Vite's entry template at its root, so
    index.html alone is not proof of a build -- serving it would render a
    blank page. The `package.json` beside it marks it as source, and `setup`
    must say so rather than pass.
    """
    checkout = tmp_path / "starkiller"
    checkout.mkdir()
    (checkout / "index.html").write_text('<script src="/src/main.js">')
    (checkout / "package.json").write_text("{}")

    results = _run_setup_against(fake_setup_config, monkeypatch, checkout)

    assert results["Starkiller"] is False
    out = capsys.readouterr().out
    assert "has not been built" in out
    assert str(checkout) in out


def test_run_setup_disabled_starkiller_ignores_a_bad_override(
    fake_setup_config, monkeypatch, tmp_path
):
    """`app.py` only loads Starkiller when `enabled`, so a stale override for a
    switched-off UI must not fail the whole install. Reachable in practice: a
    packaged `directory` outlives the package, and turning the UI off is the
    obvious thing to do once it's broken.
    """
    fake_setup_config.starkiller.enabled = False

    results = _run_setup_against(fake_setup_config, monkeypatch, tmp_path / "gone")

    assert results["Starkiller"] is True


def test_run_setup_directory_without_a_build_marks_failure(
    fake_setup_config, monkeypatch, tmp_path, capsys
):
    """A directory that exists but matches neither layout must fail `setup`,
    not report success. Checking only `starkiller_dir.is_dir()` would print a
    green banner over a broken install.
    """
    build_dir = tmp_path / "starkiller-build"
    build_dir.mkdir()

    results = _run_setup_against(fake_setup_config, monkeypatch, build_dir)

    assert results["Starkiller"] is False
    out = capsys.readouterr().out
    assert "contains no Starkiller build" in out
    assert str(build_dir) in out


def boom_no_git(*_a, **_kw):
    pytest.fail("no git or sync work may run under a directory override")


def _layout(tmp_path, *, dist=False, dist_index=True, index=False, package=False):
    """`dist` builds a *populated* dist/ by default -- an empty one is not a
    build, so it would be the wrong baseline for the accept-path tests. Pass
    `dist_index=False` for the interrupted-build case.
    """
    root = tmp_path / "starkiller"
    root.mkdir()
    if dist:
        (root / "dist").mkdir()
        if dist_index:
            (root / "dist" / "index.html").write_text('<script src="/assets/i.js">')
    if index:
        (root / "index.html").write_text("<html></html>")
    if package:
        (root / "package.json").write_text("{}")
    return root


@pytest.mark.parametrize(
    ("layout", "expected"),
    [
        ({"dist": True}, "dist"),
        ({"index": True}, "root"),
        ({"dist": True, "index": True, "package": True}, "dist"),
        ({"dist": True, "index": True}, "dist"),
        ({"index": True, "package": True}, None),
        ({}, None),
        ({"dist": True, "dist_index": False}, None),
    ],
    ids=[
        "dist-subdirectory",
        "flattened-build",
        "built-checkout-serves-dist-not-the-template",
        "both-rules-match-dist-wins",
        "unbuilt-checkout-rejected-by-package-json",
        "neither",
        "bare-dist-without-an-index",
    ],
)
def test_resolve_starkiller_dist(tmp_path, layout, expected):
    """The whole rule as the table it is. Three rows carry the reasoning:

    `both-rules-match-dist-wins` is the only row that pins rule *order* -- a
    built checkout is caught by the package.json guard whichever rule runs
    first, so it cannot. `unbuilt-checkout` is why package.json discriminates at
    all: a checkout root carries Vite's entry template, so an index.html is not
    proof of a build and serving one renders blank. `bare-dist-without-an-index`
    is why both branches key on index.html rather than on `dist/` existing -- an
    interrupted `npm run build` leaves an empty one, and so does any unrelated
    project's dist/ of wheels.
    """
    root = _layout(tmp_path, **layout)

    assert (
        data_manager.resolve_starkiller_dist(root)
        == {
            "dist": root / "dist",
            "root": root,
            None: None,
        }[expected]
    )


def test_a_real_directory_named_like_a_tilde_path_is_still_served(
    tmp_path, monkeypatch
):
    """Ordering, isolated: the unexpanded-`~` diagnosis sits after `is_dir()`.

    Absurd input, but it is the only one that reaches both branches and so the
    only one that can pin which runs first. Checking the `~` first would reject
    a build that resolves perfectly well.
    """
    monkeypatch.chdir(tmp_path)
    _layout(tmp_path, dist=True).rename(tmp_path / "~nosuchuser12345")

    assert data_manager.starkiller_directory_problem(Path("~nosuchuser12345")) is None


def test_dist_without_a_build_hint_does_not_send_operator_back_to_dist(tmp_path):
    """They already pointed at a directory containing dist/; repeating that
    advice is a dead end. The incomplete dist/ is the actionable fact.
    """
    root = _layout(tmp_path, dist=True, dist_index=False)

    hint = data_manager._starkiller_layout_hint(root)

    assert "build is incomplete" in hint
    assert "directory containing dist/" not in hint


def test_starkiller_directory_problem_reports_a_path_that_is_not_a_directory(tmp_path):
    """A `directory` pointing at a file (or a dangling symlink) exists, so
    reporting it as "does not exist" sends the operator to `ls` it, see it
    there, and conclude Empire is broken.
    """
    not_a_dir = tmp_path / "starkiller.tar.gz"
    not_a_dir.write_text("x")

    problem = data_manager.starkiller_directory_problem(not_a_dir)

    assert "is not a directory" in problem
    assert str(not_a_dir) in problem


def test_starkiller_directory_problem_none_for_a_real_build(tmp_path):
    root = _layout(tmp_path, dist=True)

    assert data_manager.starkiller_directory_problem(root) is None
