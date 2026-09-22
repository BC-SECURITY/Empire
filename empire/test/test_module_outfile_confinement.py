"""Regression tests for the ``OutFile`` path-confinement fix (audit H-4).

Three powerbreach modules -- ``eventlog`` (S2), ``deaduser`` (S3) and
``resolver`` (S4) -- took the operator's ``OutFile`` option verbatim into
``Path(out_file).parent.mkdir(parents=True, exist_ok=True)`` +
``write_text(script)``. Any authenticated non-admin operator could therefore
write a file, with an operator-authored trailing block, to any path the Empire
process can reach -- creating directory trees on the way and silently
truncating whatever was already there.

The fix routes all three through ``module_util.write_module_outfile``, which
resolves ``OutFile`` under ``<downloads>/generated-modules`` *before* the
``mkdir`` (the mkdir is itself a filesystem side effect on operator input), and
converts a failed write into the module layer's clean-4xx channel.

One parametrised file rather than three: the three sinks take the identical
fix, so a single table of (module id, short name, script marker) keeps them
from drifting apart in review.

Three things make these tests non-tautological, and all are load-bearing:

1. **The cwd is pinned to a sibling of the confinement root.** Unfixed code
   joins no root, so a relative ``OutFile`` is interpreted against the test
   process's cwd -- which ``empire/test/conftest.py`` chdirs to the repo root at
   import. Without pinning it, the traversal assertions would name a path the
   unfixed code never writes to and would pass for free. The cwd must also
   never *be* the root, or the happy-path assertion would be satisfied by the
   unfixed write instead.
2. **Every rejection case asserts ``"[+]"`` is absent.** A *successful* write is
   also reported by raising ``ModuleValidationException``
   (``"[+] PowerBreach ... written to ..."``), so rejection and success share an
   exception type and an HTTP status. Asserting the type alone passes against
   unfixed code and proves nothing.
3. **One rejection case names a parent that does not exist yet.** The rest use
   an ``OutFile`` whose parent is already there, so none of them can tell a
   check-before-``mkdir`` from a check-after-``mkdir``. Without that case, a
   sink that built the tree first would keep the whole file green while leaving
   the arbitrary-directory-creation half of H-4 wide open.
"""

from pathlib import Path
from typing import NamedTuple
from unittest.mock import Mock

import pytest

from empire.server.core.config import config_manager
from empire.server.core.exceptions import ModuleValidationException
from empire.server.core.module_service import ModuleService


class Site(NamedTuple):
    module_id: str
    short_name: str
    script_marker: str


SITES = [
    Site(
        "powershell_persistence_powerbreach_eventlog",
        "eventlog",
        "Invoke-EventLogBackdoor",
    ),
    Site(
        "powershell_persistence_powerbreach_deaduser",
        "deaduser",
        "Invoke-DeadUserBackdoor",
    ),
    Site(
        "powershell_persistence_powerbreach_resolver",
        "resolver",
        "Invoke-ResolverBackdoor",
    ),
]

sites = pytest.mark.parametrize("site", SITES, ids=lambda s: s.short_name)


@pytest.fixture(scope="module")
def main_menu_mock(install_path):
    """Stub everything the three modules touch *before* the OutFile block.

    Each stub below is load-bearing on the OutFile path, and getting one wrong
    produces a false green rather than a loud failure:

    - ``get_active_listener_by_name`` falsy raises
      ``ModuleValidationException("Invalid listener: ...")`` before the sink
      ever runs. That carries no ``"[+]"`` and writes no file, so it satisfies
      every rejection assertion below for entirely the wrong reason.
    - The launcher must be a real ``str``. A bare ``Mock`` is not ``""``, so it
      clears the guard and then raises ``TypeError`` in ``script.replace()``.
    - ``eventlog`` gets its launcher from ``stagergenv2.generate_launcher``
      while ``deaduser`` and ``resolver`` use
      ``stagertemplatesv2.new_instance("multi_launcher").generate()``. Both are
      stubbed here; the unused one costs nothing.
    """
    main_menu = Mock()
    main_menu.install_path = Path(install_path)
    main_menu.listenersv2.get_active_listener_by_name = Mock(return_value=Mock())
    main_menu.stagergenv2.generate_launcher = Mock(return_value="LAUNCHER_CODE")
    stager = Mock()
    stager.options = {"Listener": {"Value": ""}, "Base64": {"Value": True}}
    stager.generate = Mock(return_value="LAUNCHER_CODE")
    main_menu.stagertemplatesv2.new_instance = Mock(return_value=stager)

    return main_menu


@pytest.fixture(scope="module")
def module_service(main_menu_mock):
    module_service = ModuleService(main_menu=main_menu_mock)
    # custom_generate modules reach finalize_module / get_module_source via this.
    main_menu_mock.modulesv2 = module_service
    return module_service


@pytest.fixture
def obf_disabled(models):
    return models.ObfuscationConfig(language="powershell", command="", enabled=False)


class Confined(NamedTuple):
    tmp_path: Path
    cwd: Path
    root: Path


@pytest.fixture
def confined(module_service, tmp_path, monkeypatch) -> Confined:
    """Pin the confinement root and the cwd to two *distinct* directories.

    ``downloads`` is the only patchable handle: the fix computes
    ``downloads / "generated-modules"`` inside the call, so the confinement root
    is one level deeper than what is patched here. Patching a handle named
    ``root`` and asserting files directly under it would have the *fixed* code
    failing its own happy-path assertion.

    ``cwd`` is where the unfixed code's relative writes land, and it
    deliberately differs from the root so neither direction of test can be
    satisfied by the other's write. Every escape target asserted below sits
    directly under ``tmp_path``, i.e. outside both.

    ``module_service`` is requested first on purpose: it loads every shipped
    module YAML off relative paths, so it has to be built before the chdir.

    The root is patched through ``config_manager.empire_config`` resolved
    *now*, never through a module-level ``from ... import empire_config``:
    ``config/data_manager.py`` rebinds that name to a fresh ``EmpireConfig()``
    after rewriting the base config, and ``test_data_manager_update.py``
    exercises the rebind without restoring it. Patching a stale object instead
    would have these tests reading the real ``~/.../empire-test/downloads``.
    """
    downloads = tmp_path / "downloads"
    cwd = tmp_path / "cwd"
    downloads.mkdir()
    cwd.mkdir()
    monkeypatch.setattr(
        config_manager.empire_config.directories, "downloads", downloads
    )
    monkeypatch.chdir(cwd)
    return Confined(tmp_path=tmp_path, cwd=cwd, root=downloads / "generated-modules")


def _generate(module_service, obf_disabled, site: Site, out_file: str):
    """Drive the real shipped module through the real ModuleService entry point.

    Going through ``_generate_script`` rather than calling ``Module.generate``
    directly is what makes the exception-type assertions meaningful: it
    re-raises ``ModuleValidationException`` untouched but swallows everything
    else into ``ModuleExecutionException`` (a 500 at the API layer), which is
    precisely the outcome the fix has to avoid.
    """
    params = {"Agent": "ABC", "Listener": "http", "OutFile": out_file}
    module = module_service.modules[site.module_id]
    return module_service._generate_script(
        None, module, params, "powershell", obf_disabled
    )


@sites
def test_traversal_outfile_is_rejected(module_service, obf_disabled, confined, site):
    """``..`` must not escape the root.

    Red without the fix: the unfixed sink resolves ``../escaped.ps1`` against
    the cwd, creating ``tmp_path/escaped.ps1``, and then raises the *success*
    exception -- so both the ``"[+]"`` and the ``exists()`` assertions fail.
    """
    with pytest.raises(ModuleValidationException) as exc:
        _generate(module_service, obf_disabled, site, "../escaped.ps1")

    assert "[+]" not in str(exc.value)
    assert not (confined.tmp_path / "escaped.ps1").exists()


@sites
def test_traversal_outfile_creates_no_directory_outside_root(
    module_service, obf_disabled, confined, site
):
    """The rejection must land before the ``mkdir``, not merely before the write.

    Every other rejection case names an ``OutFile`` whose parent directory
    already exists, so none of them can observe the *other* half of H-4:
    ``mkdir(parents=True)`` on operator input is itself an arbitrary filesystem
    write, and a sink that created the tree first and only then checked
    containment would satisfy all of them while still letting an operator
    scatter directories anywhere the Empire process can reach.

    ``../pwned/`` exists nowhere beforehand, so its presence afterwards can only
    have come from this call. Both plausible spellings of the escape are
    asserted: the unfixed sink joins nothing and lands under the cwd, while a
    check-after-mkdir regression joins the root and lands beside it.
    """
    cwd_relative = confined.cwd.parent / "pwned"
    root_relative = confined.root.parent / "pwned"
    assert not cwd_relative.exists()
    assert not root_relative.exists()

    with pytest.raises(ModuleValidationException) as exc:
        _generate(module_service, obf_disabled, site, "../pwned/x.ps1")

    assert "[+]" not in str(exc.value)
    assert not cwd_relative.exists()
    assert not root_relative.exists()


@sites
def test_absolute_outfile_outside_root_is_rejected(
    module_service, obf_disabled, confined, site
):
    """An absolute path outside the root must be rejected, not joined.

    ``root / "/abs"`` evaluates to ``/abs`` in pathlib, discarding the root
    entirely, so this is the case a hand-rolled join silently lets through.

    Red without the fix: the file is created at the absolute path and the
    success exception is raised.
    """
    escaped = confined.tmp_path / "abs_escape.ps1"

    with pytest.raises(ModuleValidationException) as exc:
        _generate(module_service, obf_disabled, site, str(escaped))

    assert "[+]" not in str(exc.value)
    assert not escaped.exists()


@sites
def test_nul_byte_outfile_is_rejected(module_service, obf_disabled, confined, site):
    """A NUL byte is operator-reachable over the API and must stay a 4xx.

    ``"\\x00"`` is legal in a JSON string and ``option_util.validate_options``
    does no sanitisation of string options, so this reaches the sink.

    Red without the fix: ``Path("a\\x00b").parent`` is ``Path(".")``, so the
    unfixed ``mkdir`` succeeds and ``write_text`` raises ``ValueError: embedded
    null byte``, which ``_generate_script`` converts into a
    ``ModuleExecutionException`` -- a 500. The ``pytest.raises`` line is what
    goes red here, not the ``"[+]"`` assertion.
    """
    with pytest.raises(ModuleValidationException) as exc:
        _generate(module_service, obf_disabled, site, "a\x00b")

    assert "[+]" not in str(exc.value)


@sites
def test_relative_outfile_lands_under_root(
    module_service, obf_disabled, confined, site
):
    """A relative ``OutFile`` keeps its directory structure, under the root.

    Confinement is not basename reduction: ``campaign-a/`` survives. The success
    notice reports the *resolved* path and names its own module, since after
    confinement it is the operator's only pointer to where the file went.

    Red without the fix: the write lands at ``cwd/campaign-a/backdoor.ps1``, so
    ``read_text()`` raises ``FileNotFoundError``; for eventlog and resolver the
    short-name assertion also fails, since both notices said "deaduser".
    """
    with pytest.raises(ModuleValidationException) as exc:
        _generate(module_service, obf_disabled, site, "campaign-a/backdoor.ps1")

    message = str(exc.value)
    assert message.startswith("[+]")
    assert site.short_name in message

    written = confined.root / "campaign-a" / "backdoor.ps1"
    assert site.script_marker in written.read_text()
    # Nothing left behind where the unfixed code would have put it.
    assert not (confined.cwd / "campaign-a").exists()


@sites
def test_unwritable_confined_path_is_a_validation_error(
    module_service, obf_disabled, confined, site
):
    """A confined-but-unwritable path is a 4xx, not an opaque 500.

    Confinement funnels every module write into one shared tree, so one
    operator's ``OutFile = "blocker"`` leaving a regular file where another's
    perfectly legal ``OutFile = "blocker/x.ps1"`` needs a directory is routine
    rather than accidental. ``mkdir(parents=True, exist_ok=True)`` then raises
    ``FileExistsError`` on a request that violates nothing.

    The blocker is planted in *both* the root and the cwd on purpose: with it
    only in the root, the unfixed code -- which resolves against the cwd and
    never looks inside the root -- writes happily and raises the success
    exception, making this case green against the very code it must catch.

    Red without the fix: the unfixed ``mkdir`` trips over ``cwd/blocker`` and
    the ``FileExistsError`` escapes ``generate()`` as a
    ``ModuleExecutionException``, failing the ``pytest.raises`` line.
    """
    confined.root.mkdir(parents=True)
    (confined.root / "blocker").write_text("x")
    (confined.cwd / "blocker").write_text("x")

    with pytest.raises(ModuleValidationException) as exc:
        _generate(module_service, obf_disabled, site, "blocker/x.ps1")

    assert "[+]" not in str(exc.value)
