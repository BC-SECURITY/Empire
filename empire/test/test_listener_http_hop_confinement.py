"""Regression tests for the ``OutFolder`` path-confinement fix (audit H-4, S1).

``http_hop.Listener.start()`` took the operator's ``OutFolder`` option and
joined it with URIs pulled from a *second* listener's stored ``DefaultProfile``,
then ran ``save_path.parent.mkdir(parents=True, exist_ok=True)`` +
``save_path.write_text(hopCode)``. Any authenticated non-admin operator could
therefore write PHP, with partially operator-chosen content, to any path the
Empire process could reach -- creating directory trees on the way and silently
truncating whatever was already there.

Three escapes were reproduced against the unfixed code and each has a case
below:

1. ``..`` inside the URI, with a perfectly benign ``OutFolder``. ``lstrip("/")``
   defeats a bare absolute URI and nothing else, so a check on ``OutFolder``
   alone leaves the hole open -- the fix must confine the *composed* path.
2. An absolute ``OutFolder``. ``root / "/abs"`` evaluates to ``/abs`` in
   pathlib, so a hand-rolled join silently discards the root.
3. Arbitrary filename and suffix, from the URI. Nothing forces ``.php``.

Two structural rules make these tests non-tautological, both load-bearing:

- **The cwd is pinned to a sibling of the confinement root.** Unfixed code joins
  no root, so a relative ``OutFolder`` is interpreted against the test process's
  cwd -- which ``empire/test/conftest.py`` chdirs to the repo root at import.
  Without pinning it, the traversal assertions would name paths the unfixed code
  never writes to and would pass for free. The cwd must also never *be* the
  root, or the happy-path assertion would be satisfied by the unfixed write.
- **Escaping profiles are set on the redirect listener, not the hop listener.**
  ``start()`` overwrites ``self.options["DefaultProfile"]`` from the redirect
  listener's stored options *before* splitting it into URIs, so a test that
  poisons the hop listener's own profile tests nothing at all.
"""

from pathlib import Path
from typing import NamedTuple
from unittest.mock import Mock

import pytest

from empire.server.core.config import config_manager
from empire.server.core.exceptions import ListenerValidationException
from empire.server.utils import data_util
from empire.test.conftest import build_test_listener

BENIGN_PROFILE = "/news.php|Mozilla/5.0|"


@pytest.fixture
def main_menu_mock(install_path):
    """``start()`` reads ``install_path / "data/misc/hop.php"`` off this."""
    main_menu = Mock()
    main_menu.install_path = Path(install_path)
    return main_menu


@pytest.fixture
def hop(main_menu_mock):
    """The real shipped http_hop listener, built *before* any chdir.

    ``build_test_listener`` reads ``Path("empire/server/listeners")/<name>`` --
    a relative path -- so constructing it after ``monkeypatch.chdir`` would fail
    to load the YAML. ``confined`` depends on this fixture (and on
    ``victim_hop``, for the same reason) to pin that order.
    """
    return build_test_listener("http_hop", main_menu_mock)


@pytest.fixture
def victim_hop(main_menu_mock):
    """A second hop listener on shipped defaults, for the cross-operator case.

    Built here rather than in the test body for the same reason as ``hop``:
    ``build_test_listener`` resolves its YAML against a relative path, so it
    cannot run after ``confined`` chdirs. ``confined`` depends on this fixture
    to pin that order -- signature order in the one test that uses it would
    work today and break silently the moment someone reorders the arguments.
    """
    return build_test_listener("http_hop", main_menu_mock)


class Confined(NamedTuple):
    tmp_path: Path
    cwd: Path
    root: Path


@pytest.fixture
def confined(hop, victim_hop, tmp_path, monkeypatch) -> Confined:
    """Pin the confinement root and the cwd to two *distinct* directories.

    ``downloads`` is the only patchable handle: the fix computes
    ``downloads / "http_hop"`` inside the call, so the confinement root is one
    level deeper than what is patched here. Patching a handle named ``root`` and
    asserting files directly under it would have the *fixed* code failing its
    own happy-path assertion.

    ``cwd`` is where the unfixed code's relative writes land, and it
    deliberately differs from the root so neither direction of test can be
    satisfied by the other's write. Every escape target asserted below sits
    directly under ``tmp_path``, i.e. outside both.

    The root is patched through ``config_manager.empire_config`` resolved
    *now*, never through a module-level ``from ... import empire_config``:
    ``config/data_manager.py`` rebinds that name to a fresh ``EmpireConfig()``
    after rewriting the base config, so patching a stale object would leave
    these tests reading the real install's downloads directory.
    """
    downloads = tmp_path / "downloads"
    cwd = tmp_path / "cwd"
    downloads.mkdir()
    cwd.mkdir()
    monkeypatch.setattr(
        config_manager.empire_config.directories, "downloads", downloads
    )
    monkeypatch.chdir(cwd)
    return Confined(tmp_path=tmp_path, cwd=cwd, root=downloads / "http_hop")


@pytest.fixture
def redirect_listener(monkeypatch):
    """Stub all three of ``start()``'s external dependencies.

    Getting any one of them wrong produces a failure *before* the sink, which
    would satisfy the rejection assertions for entirely the wrong reason:

    - ``get_listener_options`` returning falsy makes ``start()`` log "not a
      valid listener" and return ``False`` without writing anything.
    - ``get_host_address`` opens a real DB session and swallows every failure
      into ``None``; ``hopCode.replace("REPLACE_SERVER", None)`` then raises
      ``TypeError`` before the sink is reached.
    - ``main_menu.install_path`` is handled by ``main_menu_mock`` above.

    Returns a setter so each test can choose the redirect listener's
    ``DefaultProfile`` -- the option the URIs actually come from.
    """
    options = {
        "StagingKey": {"Value": "0" * 32},
        "DefaultProfile": {"Value": BENIGN_PROFILE},
    }
    stub = Mock()
    stub.options = options
    monkeypatch.setattr(data_util, "get_listener_options", lambda name: stub)
    monkeypatch.setattr(
        data_util, "get_host_address", lambda name: "http://192.168.0.1:80"
    )

    def set_profile(profile: str) -> None:
        options["DefaultProfile"]["Value"] = profile

    return set_profile


def test_traversing_uri_cannot_escape_a_benign_out_folder(
    hop, confined, redirect_listener
):
    """``..`` in the URI must not escape, even when ``OutFolder`` is innocent.

    This is the case a root-only check passes while leaving the finding open:
    the URIs come from the *redirect* listener's row, which is mutable after
    this listener was validated, so the composed path is the only thing that
    can be confined.

    Red without the fix: the unfixed write resolves ``cwd/ok/../../ESCAPED_VIA_URI``
    to ``tmp_path/ESCAPED_VIA_URI``, creates it, drops ``escaped.php`` inside,
    and ``start()`` returns ``True`` -- so both assertions fail. Asserting on
    the directory covers the ``mkdir`` and the ``write_text`` at once, since the
    escaping file lands inside it.

    ``start()``'s return value is captured rather than asserted inline so that
    the filesystem assertion -- the one that actually proves confinement -- is
    what reports first. The ``is False`` half still has to be here: it catches a
    fix that rejects the path but carries on to the next URI.
    """
    redirect_listener("/../../ESCAPED_VIA_URI/escaped.php|Mozilla/5.0|")
    hop.options["OutFolder"]["Value"] = "ok"

    started = hop.start()
    assert not (confined.tmp_path / "ESCAPED_VIA_URI").exists()
    # Two spellings deliberately. The line above is where the UNFIXED code
    # lands; this one is where a check-AFTER-mkdir regression lands. Without
    # it that regression creates a directory outside the root from operator
    # input and every test in this file still passes.
    assert not (confined.root.parent / "ESCAPED_VIA_URI").exists()
    assert started is False


def test_absolute_out_folder_outside_root_is_refused(hop, confined, redirect_listener):
    """An absolute ``OutFolder`` must be rejected, not joined.

    ``root / "/abs"`` discards the root entirely in pathlib, so this is the
    escape a hand-rolled join lets through without the URI's help at all.

    Red without the fix: ``mkdir(parents=True)`` has created the directory and
    ``start()`` returns ``True``.
    """
    escaped = confined.tmp_path / "escaped_dir"
    hop.options["OutFolder"]["Value"] = str(escaped)

    started = hop.start()
    assert not escaped.exists()
    assert not (confined.root.parent / "escaped_dir").exists()
    assert started is False


def test_start_does_not_raise_for_a_rejected_out_folder(
    hop, confined, redirect_listener
):
    """The sink's contract, stated as such: rejection is ``False``, never a raise.

    This passes trivially against unfixed code, so it is a guard against the
    *wrong* fix rather than a proof of the bug -- and it is kept deliberately.
    Two of the three routes into ``start()`` do not wrap it:
    ``start_existing_listener`` (a bare 500) and ``start_existing_listeners``,
    which the server runs for every enabled listener at every boot. Turning
    this ``return False`` into a ``raise`` would make a persisted poisoned
    ``OutFolder`` a plantable startup abort.
    """
    hop.options["OutFolder"]["Value"] = str(confined.tmp_path / "escaped_dir")

    hop.start()  # plain call: an escaping exception fails this test as an error


def test_confined_out_folder_keeps_its_directory_structure(
    hop, confined, redirect_listener
):
    """The happy path: relative ``OutFolder`` and nested URIs land under the root.

    Confinement is not basename reduction. Hop URIs are served at their URI on
    the redirector and two of them can share a basename, so ``admin/`` has to
    survive.

    Red without the fix: the write lands under ``cwd``, not the root, so both
    ``exists()`` assertions fail. This is why ``cwd`` must never equal the root.
    """
    redirect_listener("/news.php,/admin/index.asp|Mozilla/5.0|")
    hop.options["OutFolder"]["Value"] = "redirectors"

    assert hop.start() is True

    written = confined.root / "redirectors"
    assert "<?php" in (written / "news.php").read_text()
    assert "<?php" in (written / "admin" / "index.asp").read_text()
    # Nothing left behind where the unfixed code would have put it.
    assert not (confined.cwd / "redirectors").exists()


def test_unwritable_confined_target_returns_false_rather_than_raising(
    hop, confined, redirect_listener
):
    """A confined-but-unwritable target must not escape ``start()``.

    ``mkdir(parents=True, exist_ok=True)`` excuses an existing *directory*, not
    an existing regular file, so a name already taken raises ``FileExistsError``
    -- an ``OSError`` on the boot path, where nothing catches it.

    The blocker is planted in *both* the root and the cwd on purpose: with it
    only inside the root, the unfixed code -- which resolves against the cwd and
    never looks inside the root -- writes happily and returns ``True``, making
    this case green against the very code it must catch.

    Red without the fix: the unfixed ``mkdir`` trips over ``cwd/redirectors``
    and the ``FileExistsError`` escapes ``start()``, failing this test as an
    error rather than an assertion.
    """
    confined.root.mkdir(parents=True)
    (confined.root / "redirectors").write_text("x")
    (confined.cwd / "redirectors").write_text("x")
    hop.options["OutFolder"]["Value"] = "redirectors"

    assert hop.start() is False


@pytest.mark.parametrize(
    "out_folder",
    ["../escape", "escaped_dir_abs", "a\x00b"],
    ids=["traversal", "absolute", "nul-byte"],
)
def test_validate_options_rejects_an_escaping_out_folder(hop, confined, out_folder):
    """The pre-check keeps a poisoned ``OutFolder`` out of the DB entirely.

    ``validate_options()`` runs on create *and* on every persisted row at every
    boot (``start_existing_listener`` -> ``_validate_existing`` ->
    ``_validate_listener_options``), which catches only
    ``ListenerValidationException`` and turns it into a clean 400 carrying this
    message. Any other exception type escapes to a bare 500 on the enable route
    and aborts server startup on the boot route.

    The NUL parameter is exactly that regression: ``Path("a\\x00b")``
    constructs fine and ``.resolve()`` then raises ``ValueError``, so a
    pre-check that reached ``resolve()`` unguarded would be strictly worse than
    no pre-check at all. ``"\\x00"`` is legal in a JSON string and
    ``option_util.validate_options`` does not sanitise string options, so it is
    operator-reachable over the API.

    Red without the fix: ``validate_options()`` is a bare ``pass`` and raises
    nothing.
    """
    if out_folder == "escaped_dir_abs":
        out_folder = str(confined.tmp_path / "escaped_dir")
    hop.options["OutFolder"]["Value"] = out_folder

    with pytest.raises(ListenerValidationException) as exc:
        hop.validate_options()

    assert str(confined.root) in str(exc.value)


def test_uri_resolving_to_the_folder_itself_is_refused(
    confined, hop, redirect_listener
):
    """A URI that names no file must not turn the folder into a regular file.

    A DefaultProfile URI of ``/`` strips to ``""``, which resolves back onto
    ``save_folder`` itself; ``write_text`` would then create that directory as
    a regular file and every later URI under it would fail its ``mkdir``.

    ``OutFolder`` is a real sub-directory on purpose. Spelling it ``"."`` --
    which also collapses -- would have this rejected one guard earlier, at the
    ``OutFolder`` resolve, and the URI clause would go untested. The
    ``OutFolder`` collapse has its own case below.
    """
    hop.options["OutFolder"]["Value"] = "redirectors"
    redirect_listener("/|Mozilla/5.0|")

    assert hop.start() is False
    assert not (confined.root / "redirectors").is_file()


@pytest.mark.parametrize("out_folder", [".", "./", "a/.."], ids=["dot", "slash", "up"])
def test_out_folder_collapsing_onto_the_root_is_refused(
    confined, hop, redirect_listener, out_folder
):
    """``OutFolder`` must be a sub-directory, never the shared root itself.

    These spellings are perfectly contained, so a containment-only check hands
    back the root and the URI then names a file one level down -- exactly the
    level every *other* hop listener's ``OutFolder`` lives at. See the
    cross-operator case below for what that buys the attacker.

    Rejected at ``validate_options`` too, so it never reaches the stored row.
    """
    hop.options["OutFolder"]["Value"] = out_folder
    redirect_listener("/redirectors|Mozilla/5.0|")

    with pytest.raises(ListenerValidationException):
        hop.validate_options()

    assert hop.start() is False
    assert not (confined.root / "redirectors").exists()


def test_one_operator_cannot_wedge_another_operators_default_out_folder(
    confined, hop, victim_hop, redirect_listener
):
    """The reason the collapse guard is a security fix and not a tidy-up.

    ``OutFolder`` is confined to a root *shared by every hop listener*, so a
    write the attacker is allowed to make can still land on top of another
    operator's directory. With ``OutFolder`` collapsed onto the root, a
    redirect profile of ``/redirectors`` plants a regular file at precisely the
    shipped default ``OutFolder`` -- no guessing required. Every other
    operator's listener then fails ``save_path.parent.mkdir(exist_ok=True)``
    with ``FileExistsError`` (``exist_ok`` excuses an existing *directory*,
    not a file), at create and again at every boot, until someone removes the
    file by hand.

    Verified against the un-guarded code: the attacker's ``start()`` returned
    ``True``, ``redirectors`` was a regular file, and the victim's ``start()``
    returned ``False``. All three assertions below flip together.
    """
    hop.options["Name"]["Value"] = "attacker-hop"
    hop.options["OutFolder"]["Value"] = "."
    redirect_listener("/redirectors|Mozilla/5.0|")

    assert hop.start() is False
    assert not (confined.root / "redirectors").is_file()

    # A second operator, shipped defaults, nothing unusual.
    victim_hop.options["Name"]["Value"] = "victim-hop"
    assert victim_hop.options["OutFolder"]["Value"] == "redirectors"
    redirect_listener(BENIGN_PROFILE)

    assert victim_hop.start() is True


def test_a_rejected_uri_leaves_no_partial_redirectors(hop, confined, redirect_listener):
    """One escaping URI must not leave the earlier ones written to disk.

    ``start()`` reports failure for the whole listener, so a redirector it
    wrote before hitting the bad URI is an artifact of a listener that never
    started -- carrying a ``REPLACE_SERVER`` the operator may still go and
    deploy. Resolving every URI before writing any of them is what keeps the
    rejection all-or-nothing.

    The benign URI is deliberately first: with the write interleaved into the
    resolve loop, ``news.php`` is already on disk by the time the second URI is
    rejected, so this assertion is what goes red.
    """
    redirect_listener("/news.php,/../ESCAPED_VIA_URI/evil.php|Mozilla/5.0|")
    hop.options["OutFolder"]["Value"] = "redirectors"

    started = hop.start()
    assert not (confined.root / "redirectors" / "news.php").exists()
    assert not (confined.tmp_path / "ESCAPED_VIA_URI").exists()
    assert started is False


def test_missing_redirect_host_returns_false_rather_than_raising(
    hop, confined, redirect_listener, monkeypatch
):
    """A redirect listener with no host address must not take down the boot loop.

    ``models.Listener.host_address`` is nullable and ``get_host_address()``
    swallows every DB failure into ``None``, so this is reachable from a
    transient error rather than only from a malformed row.
    ``hopCode.replace("REPLACE_SERVER", None)`` is a ``TypeError``, and
    ``start_existing_listeners`` does not wrap ``start()`` -- so one such
    listener would stop every later listener from starting.

    A plain call, not ``pytest.raises``: an escaping exception fails this test
    as an error, which is the outcome under test.
    """
    monkeypatch.setattr(data_util, "get_host_address", lambda name: None)

    assert hop.start() is False


def test_unreadable_hop_template_returns_false_rather_than_raising(
    hop, confined, redirect_listener, main_menu_mock
):
    """A missing ``data/misc/hop.php`` must not take down the boot loop either.

    Same contract as the missing-host case, different source: the template is
    read off ``install_path``, so a failed mount, a bad umask under
    ``sudo -E``, or an incomplete install is enough. The read sits *above*
    every confinement guard, so without this ``try`` the whole rejection path
    below it is unreachable -- ``start_existing_listeners`` takes the
    ``FileNotFoundError`` and stops starting listeners.

    A plain call, not ``pytest.raises``: an escaping exception fails this test
    as an error, which is the outcome under test.
    """
    main_menu_mock.install_path = confined.tmp_path / "no-such-install"

    assert hop.start() is False
