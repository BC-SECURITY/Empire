"""Unit tests for empire.server.utils.file_util.

``ensure_user_ownership`` (root-only recursive chown) and ``run_as_user``
(sudo-preserving subprocess wrapper) were largely uncovered. These exercise
their branches with monkeypatched os/pwd/subprocess so no privileges are
needed. ``safe_filename``, ``is_path_within`` and ``resolve_under_root`` are the
path-traversal guards for operator- and client-supplied paths.
"""

import os
import subprocess
from types import SimpleNamespace

import pytest

from empire.server.utils import file_util
from empire.server.utils.file_util import (
    is_path_within,
    resolve_under_root,
    safe_filename,
)


# --------------------------------------------------------------------------- #
# ensure_user_ownership
# --------------------------------------------------------------------------- #
def _no_chown(monkeypatch):
    """Install an os.chown that fails the test if it is ever called."""
    calls = []

    def fake_chown(*a, **k):
        calls.append((a, k))

    monkeypatch.setattr(os, "chown", fake_chown)
    return calls


def test_ensure_ownership_noop_when_not_root(monkeypatch, tmp_path):
    monkeypatch.setattr(os, "geteuid", lambda: 1000)
    calls = _no_chown(monkeypatch)

    file_util.ensure_user_ownership(tmp_path, user="someone")

    assert calls == []


def test_ensure_ownership_noop_for_root_target(monkeypatch, tmp_path):
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    calls = _no_chown(monkeypatch)

    file_util.ensure_user_ownership(tmp_path, user="root")

    assert calls == []


def test_ensure_ownership_noop_when_no_sudo_user(monkeypatch, tmp_path):
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    monkeypatch.delenv("SUDO_USER", raising=False)
    calls = _no_chown(monkeypatch)

    file_util.ensure_user_ownership(tmp_path)

    assert calls == []


def test_ensure_ownership_unknown_user_skips(monkeypatch, tmp_path):
    monkeypatch.setattr(os, "geteuid", lambda: 0)

    def raise_keyerror(_name):
        raise KeyError

    monkeypatch.setattr(file_util.pwd, "getpwnam", raise_keyerror)
    calls = _no_chown(monkeypatch)

    file_util.ensure_user_ownership(tmp_path, user="ghost")

    assert calls == []


def test_ensure_ownership_already_correct_is_noop(monkeypatch, tmp_path):
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    st = tmp_path.stat()
    monkeypatch.setattr(
        file_util.pwd,
        "getpwnam",
        lambda _n: SimpleNamespace(pw_uid=st.st_uid, pw_gid=st.st_gid),
    )
    calls = _no_chown(monkeypatch)

    file_util.ensure_user_ownership(tmp_path, user="me")

    assert calls == []


def test_ensure_ownership_chowns_tree(monkeypatch, tmp_path):
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "f.txt").write_text("x")

    monkeypatch.setattr(os, "geteuid", lambda: 0)
    monkeypatch.setattr(
        file_util.pwd,
        "getpwnam",
        lambda _n: SimpleNamespace(pw_uid=424242, pw_gid=424242),
    )
    chowned = []
    monkeypatch.setattr(os, "chown", lambda p, *a, **k: chowned.append(str(p)))

    file_util.ensure_user_ownership(tmp_path, user="target")

    # Root path plus every walked entry got chowned.
    assert str(tmp_path) in chowned
    assert str(tmp_path / "sub") in chowned
    assert str(tmp_path / "sub" / "f.txt") in chowned


def test_ensure_ownership_missing_path_returns(monkeypatch, tmp_path):
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    monkeypatch.setattr(
        file_util.pwd,
        "getpwnam",
        lambda _n: SimpleNamespace(pw_uid=424242, pw_gid=424242),
    )
    calls = _no_chown(monkeypatch)

    # stat() on a non-existent path raises FileNotFoundError -> early return.
    file_util.ensure_user_ownership(tmp_path / "does-not-exist", user="target")

    assert calls == []


def test_ensure_ownership_skips_vanished_entry(monkeypatch, tmp_path):
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "f.txt").write_text("x")

    monkeypatch.setattr(os, "geteuid", lambda: 0)
    monkeypatch.setattr(
        file_util.pwd,
        "getpwnam",
        lambda _n: SimpleNamespace(pw_uid=424242, pw_gid=424242),
    )

    def chown(p, *a, **k):
        # Top-level succeeds; entries look like they vanished mid-walk.
        if str(p) != str(tmp_path):
            raise FileNotFoundError

    monkeypatch.setattr(os, "chown", chown)

    file_util.ensure_user_ownership(tmp_path, user="target")


def test_ensure_ownership_reraises_on_root_chown_failure(monkeypatch, tmp_path):
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    monkeypatch.setattr(
        file_util.pwd,
        "getpwnam",
        lambda _n: SimpleNamespace(pw_uid=424242, pw_gid=424242),
    )

    def deny(*a, **k):
        raise PermissionError("nope")

    monkeypatch.setattr(os, "chown", deny)

    with pytest.raises(PermissionError):
        file_util.ensure_user_ownership(tmp_path, user="target")


def test_ensure_ownership_continues_past_entry_failure(monkeypatch, tmp_path):
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "f.txt").write_text("x")

    monkeypatch.setattr(os, "geteuid", lambda: 0)
    monkeypatch.setattr(
        file_util.pwd,
        "getpwnam",
        lambda _n: SimpleNamespace(pw_uid=424242, pw_gid=424242),
    )

    def chown(p, *a, **k):
        # Top-level chown succeeds; per-entry chowns raise but must not abort.
        if str(p) != str(tmp_path):
            raise OSError("entry busy")

    monkeypatch.setattr(os, "chown", chown)

    # Should complete without raising despite the per-entry failures.
    file_util.ensure_user_ownership(tmp_path, user="target")


# --------------------------------------------------------------------------- #
# run_as_user
# --------------------------------------------------------------------------- #
def _fake_run(monkeypatch, stdout="output", exc=None):
    recorded = {}

    def fake_run(cmd, **kwargs):
        recorded["cmd"] = cmd
        recorded["kwargs"] = kwargs
        if exc is not None:
            raise exc
        return SimpleNamespace(stdout=stdout)

    monkeypatch.setattr(subprocess, "run", fake_run)
    return recorded


def test_run_as_user_root_skips_sudo(monkeypatch):
    recorded = _fake_run(monkeypatch)

    file_util.run_as_user(["echo", "hi"], user="root")

    assert recorded["cmd"] == ["echo", "hi"]


def test_run_as_user_named_user_prepends_sudo(monkeypatch):
    recorded = _fake_run(monkeypatch)

    file_util.run_as_user(["git", "status"], user="alice")

    assert recorded["cmd"] == ["sudo", "-E", "-u", "alice", "git", "status"]


def test_run_as_user_defaults_to_sudo_user_env(monkeypatch):
    monkeypatch.setenv("SUDO_USER", "bob")
    recorded = _fake_run(monkeypatch)

    file_util.run_as_user(["whoami"])

    assert recorded["cmd"] == ["sudo", "-E", "-u", "bob", "whoami"]


def test_run_as_user_no_sudo_user_runs_plain(monkeypatch):
    monkeypatch.delenv("SUDO_USER", raising=False)
    recorded = _fake_run(monkeypatch)

    file_util.run_as_user(["whoami"])

    assert recorded["cmd"] == ["whoami"]


def test_run_as_user_capture_output_returns_stripped_stdout(monkeypatch):
    _fake_run(monkeypatch, stdout="  hello \n")

    result = file_util.run_as_user(["echo"], user="root", capture_output=True)

    assert result == "hello"


def test_run_as_user_without_capture_returns_none(monkeypatch):
    _fake_run(monkeypatch)

    result = file_util.run_as_user(["echo"], user="root")

    assert result is None


def test_run_as_user_reraises_called_process_error(monkeypatch):
    err = subprocess.CalledProcessError(
        1, ["boom"], output="out-data", stderr="err-data"
    )
    _fake_run(monkeypatch, exc=err)

    with pytest.raises(subprocess.CalledProcessError):
        file_util.run_as_user(["boom"], user="root")


# --------------------------------------------------------------------------- #
# safe_filename / is_path_within
# --------------------------------------------------------------------------- #
class TestSafeFilename:
    @pytest.mark.parametrize("filename", ["report.yaml", "avatar.png", "a.b.c.txt"])
    def test_plain_names_pass_through(self, filename):
        assert safe_filename(filename) == filename

    @pytest.mark.parametrize(
        "filename",
        [
            "",
            None,
            ".",
            "..",
            "/",
            "/etc/passwd",
            "../etc/passwd",
            "../../../../etc/shadow",
            "../../../../../../../../root/.ssh/authorized_keys",  # issue #824 PoC
            "foo/bar.txt",
            "..\\..\\windows\\evil.dll",
            "dir\\file.txt",
            "foo\x00bar.txt",
        ],
    )
    def test_unsafe_names_return_none(self, filename):
        assert safe_filename(filename) is None


class TestIsPathWithin:
    def test_contained_path_is_within(self, tmp_path):
        assert is_path_within(tmp_path / "a" / "b.txt", tmp_path) is True

    @pytest.mark.parametrize(
        "relative",
        ["../evil.txt", "a/../../evil.txt", "../../../../etc/passwd"],
    )
    def test_traversal_is_not_within(self, tmp_path, relative):
        assert is_path_within(tmp_path / relative, tmp_path) is False

    def test_sibling_prefix_is_not_within(self, tmp_path):
        base = tmp_path / "downloads"
        base.mkdir()
        assert is_path_within(tmp_path / "downloads-evil" / "x", base) is False


class TestResolveUnderRoot:
    def test_relative_value_resolves_under_root(self, tmp_path):
        assert resolve_under_root(tmp_path, "out.ps1") == (tmp_path / "out.ps1")

    def test_nested_relative_value_is_preserved(self, tmp_path):
        assert resolve_under_root(tmp_path, "a/b/c.ps1") == (tmp_path / "a/b/c.ps1")

    @pytest.mark.parametrize(
        "operator_path",
        ["../escape", "a/../../escape", "../../../../etc/cron.d/x"],
    )
    def test_traversal_returns_none(self, tmp_path, operator_path):
        root = tmp_path / "root"
        root.mkdir()
        assert resolve_under_root(root, operator_path) is None

    def test_absolute_path_outside_root_returns_none(self, tmp_path):
        root = tmp_path / "root"
        root.mkdir()
        assert resolve_under_root(root, "/etc/cron.d/x") is None
        assert resolve_under_root(root, str(tmp_path / "sibling" / "x")) is None

    def test_absolute_path_inside_root_is_accepted(self, tmp_path):
        root = tmp_path / "root"
        root.mkdir()
        inside = root / "a" / "b.ps1"
        assert resolve_under_root(root, str(inside)) == inside.resolve()

    def test_sibling_prefix_of_root_returns_none(self, tmp_path):
        root = tmp_path / "http_hop"
        root.mkdir()
        assert resolve_under_root(root, str(tmp_path / "http_hop-evil" / "x")) is None

    def test_null_byte_returns_none_and_does_not_raise(self, tmp_path):
        # Path("a\x00b") constructs fine but .resolve() raises ValueError, which
        # no caller on the four fixed paths catches -- so the byte is rejected
        # before any Path is built. Assert the return value, not the absence of
        # an exception: pytest.raises(ValueError) would pass without the guard.
        assert resolve_under_root(tmp_path, "a\x00b") is None

    def test_empty_value_resolves_to_the_root(self, tmp_path):
        # Path("") is Path("."), which joins to the root. Benign at every call
        # site; pinned so tightening it later has to be deliberate.
        assert resolve_under_root(tmp_path, "") == tmp_path.resolve()

    def test_returned_path_is_resolved(self, tmp_path):
        # Call sites mkdir/write whatever comes back, and containment was
        # decided about the resolved form -- returning the raw candidate would
        # let the checked path and the written path disagree.
        real = tmp_path / "real"
        real.mkdir()
        link = tmp_path / "link"
        link.symlink_to(real)
        assert resolve_under_root(link, "a/../b.ps1") == (real / "b.ps1")
