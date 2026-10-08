import base64
import importlib.util
import json
import shutil
import subprocess
from pathlib import Path
from unittest.mock import Mock, patch

import pytest

from empire.server.core.config.config_manager import empire_config
from empire.server.core.exceptions import (
    ModuleExecutionException,
    ModuleValidationException,
)
from empire.server.core.module_models import EmpireModule, LanguageEnum
from empire.server.core.module_service import ModuleService
from empire.server.core.obfuscation_service import ObfuscationService
from empire.server.stagers.windows.launcher_bat import Stager as LauncherBat
from empire.server.utils.dotnet_version_util import parse_agent_dotnet_versions


@pytest.fixture(scope="module")
def main_menu_mock(models, install_path):
    main_menu = Mock()
    main_menu.install_path = Path(install_path)
    main_menu.listeners.activeListeners = {}
    main_menu.listeners.listeners = {}
    main_menu.obfuscationv2 = Mock()
    main_menu.obfuscationv2.get_obfuscation_config = Mock(
        return_value=models.ObfuscationConfig(
            language="python", command="", enabled=False
        )
    )
    main_menu.obfuscationv2.obfuscate_keywords = Mock(side_effect=lambda x: x)

    return main_menu


@pytest.fixture(scope="module")
def module_service(main_menu_mock):
    module_service = ModuleService(main_menu=main_menu_mock)

    module_service.dotnet_compiler.compile_task = Mock(
        return_value=Path("/tmp/compiled_task.exe")
    )

    # Wire up so custom_generate modules can access modulesv2 via main_menu
    main_menu_mock.modulesv2 = module_service

    return module_service


@pytest.fixture
def agent_mock():
    agent_mock = Mock()
    agent_mock.session_id = "ABC123"
    agent_mock.process_id = None
    return agent_mock


@pytest.fixture
def downloads_root(monkeypatch, tmp_path):
    """Point the downloads directory at a scratch root for path-confinement tests."""
    root = tmp_path / "downloads"
    root.mkdir()
    monkeypatch.setattr(empire_config.directories, "downloads", root)
    return root


# Every module whose ExtFile option feeds a read_text() sink, with the extra
# required options each one needs. Shared by the ExtFile encoding test and the
# confinement tests so the two lists cannot drift apart.
EXTFILE_MODULES = [
    ("powershell_persistence_userland_registry", {}),
    ("powershell_persistence_userland_schtasks", {}),
    (
        "powershell_persistence_userland_backdoor_lnk",
        {"Listener": "http", "LNKPath": "C:\\Users\\test\\test.lnk"},
    ),
    ("powershell_persistence_elevated_registry", {}),
    ("powershell_persistence_elevated_schtasks", {}),
    ("powershell_persistence_elevated_wmi", {"Listener": "http"}),
    ("powershell_persistence_elevated_wmi_updater", {}),
]


def test_execute_module_with_script_in_yaml_modified_python_agent(
    module_service, agent_mock
):
    agent_mock.language = "python"
    params = {
        "Agent": agent_mock.session_id,
        "Text": "Hello World",
    }
    module_id = "python_trollsploit_osx_say"
    res, err = module_service.execute_module(
        None, agent_mock, module_id, params, True, True, "Modified Script: {{ Text }}"
    )

    assert err is None
    script = res.data

    assert script == "Modified Script: Hello World"


def test_execute_module_with_script_in_path_powershell_agent(
    module_service, agent_mock
):
    agent_mock.language = "powershell"
    params = {
        "Agent": agent_mock.session_id,
        "BooSource": "Hello World",
    }
    module_id = "powershell_code_execution_invoke_boolang"
    res, err = module_service.execute_module(
        None, agent_mock, module_id, params, True, True, None
    )

    assert err is None
    script = res.data

    assert script.startswith("function Invoke-Boolang")


def test_execute_module_with_script_in_path_modified_powershell(
    module_service, agent_mock
):
    agent_mock.language = "powershell"
    params = {
        "Agent": agent_mock.session_id,
        "BooSource": "Hello World",
    }
    module_id = "powershell_code_execution_invoke_boolang"
    res, err = module_service.execute_module(
        None, agent_mock, module_id, params, True, True, "Modified Script: "
    )

    assert err is None
    script = res.data

    assert script.startswith(
        'Modified Script:  Invoke-Boolang -BooSource "Hello World"'
    )


def test_execute_module_custom_generate_no_obfuscation_config_powershell_agent(
    main_menu_mock, module_service, agent_mock
):
    agent_mock.language = "python"
    params = {"Agent": agent_mock.session_id}
    module_id = "python_collection_osx_search_email"

    main_menu_mock.obfuscationv2.get_obfuscation_config = Mock(
        side_effect=lambda x, y: None
    )
    res, err = module_service.execute_module(
        None, agent_mock, module_id, params, True, True, None
    )

    assert err is None
    script = res.data

    assert script == 'cmd = "find /Users/ -name *.emlx 2>/dev/null"\nrun_command(cmd)'


def test_execute_module_custom_generate_native_bool_gates_branch(
    module_service, agent_mock
):
    """Boolean options must reach a custom_generate module as native bools so an
    ``if params["X"]:`` gate fires only when the option is truthy.

    Regression guard for the removed ``normalize_legacy_params`` shim, which
    re-stringified ``False`` -> ``"False"`` (truthy) before dispatch and so
    silently triggered bool-gated branches (e.g. ThreadlessInject's always-on
    launcher obfuscation). ``computerdetails`` emits ``Get-ComputerDetails
    -Limit 100`` only from its all-false fallthrough, so that string's
    presence/absence proves whether any ``if params["X"]:`` gate fired.
    """
    agent_mock.language = "powershell"
    module_id = "powershell_situational_awareness_host_computerdetails"
    base = {"Agent": agent_mock.session_id}

    # All switches false (defaults) -> no gate fires -> fallthrough invocation.
    res, err = module_service.execute_module(
        None, agent_mock, module_id, base, True, True, None
    )
    assert err is None
    assert "Get-ComputerDetails -Limit 100" in res.data

    # Explicit string "False" (the API/coerced_dict wire form) must stay falsy.
    res, err = module_service.execute_module(
        None, agent_mock, module_id, {**base, "4624": "False"}, True, True, None
    )
    assert err is None
    assert "Get-ComputerDetails -Limit 100" in res.data

    # A truthy switch fires its branch and returns early, skipping the fallthrough.
    res, err = module_service.execute_module(
        None, agent_mock, module_id, {**base, "4624": "True"}, True, True, None
    )
    assert err is None
    assert "Get-ComputerDetails -Limit 100" not in res.data


@pytest.mark.parametrize(("module_id", "extra_params"), EXTFILE_MODULES)
def test_execute_persistence_module_extfile_mode(
    module_service, agent_mock, downloads_root, module_id, extra_params
):
    """ExtFile mode must base64-encode the external payload into the script.

    ``helpers.enc_powershell`` returns ``bytes``. The registry/schtasks/wmi
    modules concatenate ``enc_script`` into a ``str`` PowerShell script, so
    without decoding they raise ``TypeError`` — which ``execute_module`` re-raises
    as ``ModuleExecutionException("Error generating script.")``. ``backdoor_lnk``
    instead f-string-interpolates it, silently embedding the ``b'...'`` bytes-repr;
    the negative assertion below catches that corruption, while ``err is None`` and
    the positive assertion catch the crash. ``main_menu`` is a truthy ``Mock``, so
    the listener checks pass and the test isolates the ExtFile encoding path.

    The payload lives under ``downloads_root`` because ExtFile is confined to the
    downloads directory; this doubles as the permissive-side pin for all seven
    guards -- a guard that rejects too much takes every case here red.
    """
    agent_mock.language = "powershell"
    payload = downloads_root / "payload.ps1"
    payload_content = "Write-Host 'persist-check'"
    payload.write_text(payload_content)
    expected_b64 = base64.b64encode(payload_content.encode("UTF-16LE")).decode("UTF-8")

    params = {
        "Agent": agent_mock.session_id,
        "ExtFile": str(payload),
        **extra_params,
    }
    res, err = module_service.execute_module(
        None, agent_mock, module_id, params, True, True, None
    )

    assert err is None
    # The decoded base64 string is present...
    assert expected_b64 in res.data
    # ...and not as a Python bytes repr (the backdoor_lnk silent-corruption form).
    assert f"b'{expected_b64}'" not in res.data


@pytest.mark.parametrize(("module_id", "extra_params"), EXTFILE_MODULES)
def test_execute_persistence_module_extfile_outside_downloads_is_blocked(
    module_service, agent_mock, tmp_path, downloads_root, module_id, extra_params
):
    """ExtFile outside the downloads root is rejected, and the rejection is
    identical whether or not the target exists.

    The existing-target case is the disclosure proof: unfixed code reads the
    decoy and returns its base64 in the script, so it never raises. The decoy
    must really exist -- against unfixed code a missing target raises
    ``ModuleValidationException`` too, which would make the assertion vacuous.

    The missing-target case pins the file-existence oracle shut: unfixed code
    answers ``"File does not exist: <path>"`` for a missing file and hands back a
    script for an existing one, so the two are distinguishable. After the fix the
    messages must be byte-identical.
    """
    agent_mock.language = "powershell"
    outside = tmp_path / "outside"
    outside.mkdir()
    decoy = outside / "decoy.txt"
    decoy.write_text("H5-LEAK-MARKER")
    params = {"Agent": agent_mock.session_id, "ExtFile": str(decoy), **extra_params}

    with pytest.raises(ModuleValidationException) as exists_exc:
        module_service.execute_module(
            None, agent_mock, module_id, params, True, True, None
        )

    decoy.unlink()
    with pytest.raises(ModuleValidationException) as missing_exc:
        module_service.execute_module(
            None, agent_mock, module_id, params, True, True, None
        )

    assert str(downloads_root) in str(exists_exc.value)
    assert "H5-LEAK-MARKER" not in str(exists_exc.value)
    assert str(missing_exc.value) == str(exists_exc.value)


@pytest.mark.parametrize(("module_id", "extra_params"), EXTFILE_MODULES)
def test_execute_persistence_module_extfile_traversal_back_inside_is_allowed(
    module_service, agent_mock, downloads_root, module_id, extra_params
):
    """A path containing ``..`` that resolves back inside the root is allowed.

    Permissive-side pin, and the proof that the guard resolves rather than
    string-matching on ``".."``.
    """
    agent_mock.language = "powershell"
    payload_dir = downloads_root / "uploads" / "op"
    payload_dir.mkdir(parents=True)
    payload_content = "Write-Host 'traversal-check'"
    (payload_dir / "payload.ps1").write_text(payload_content)
    ext_file = downloads_root / "uploads" / ".." / "uploads" / "op" / "payload.ps1"
    expected_b64 = base64.b64encode(payload_content.encode("UTF-16LE")).decode("UTF-8")

    params = {"Agent": agent_mock.session_id, "ExtFile": str(ext_file), **extra_params}
    res, err = module_service.execute_module(
        None, agent_mock, module_id, params, True, True, None
    )

    assert err is None
    assert expected_b64 in res.data


@pytest.mark.parametrize(("module_id", "extra_params"), EXTFILE_MODULES)
def test_execute_persistence_module_extfile_nul_byte_is_a_validation_error(
    module_service, agent_mock, downloads_root, module_id, extra_params
):
    """An embedded NUL in ExtFile stays a clean 400, not a 500.

    Green against unfixed code on purpose: ``Path("a\\x00b").exists()`` is False,
    so unfixed code raises ``ModuleValidationException``. What this pins is the
    *wrong* fix -- ``Path.resolve()`` raises ``ValueError`` on an embedded null,
    which ``_generate_script`` turns into ``ModuleExecutionException`` (a 500). A
    confinement check without an explicit NUL clause takes this red.
    """
    agent_mock.language = "powershell"
    params = {"Agent": agent_mock.session_id, "ExtFile": "a\x00b", **extra_params}

    with pytest.raises(ModuleValidationException):
        module_service.execute_module(
            None, agent_mock, module_id, params, True, True, None
        )


def test_execute_module_reflectivepeinjection_file_outside_downloads_is_blocked(
    module_service, agent_mock, tmp_path, downloads_root
):
    """invoke_reflectivepeinjection's ``File`` option is confined to downloads.

    The decoy is binary: this sink uses ``read_bytes()``, so unlike the ExtFile
    sites it is not bounded by ``read_text()``'s text constraint. Unfixed code
    base64s the bytes into ``script_end`` and returns a script, so it never
    raises.

    The rejection also has to be raised *outside* the module's own ``try``: the
    bare ``except Exception`` in there only prints, so a guard placed inside it
    would be swallowed and the operator would get a 201 with no ``-PEBytes``.
    """
    agent_mock.language = "powershell"
    outside = tmp_path / "outside"
    outside.mkdir()
    decoy = outside / "payload.dll"
    decoy.write_bytes(b"\x00\x01\x02R8-BINARY-MARKER\xff\xfe\x00")

    params = {"Agent": agent_mock.session_id, "File": str(decoy)}
    with pytest.raises(ModuleValidationException) as exc_info:
        module_service.execute_module(
            None,
            agent_mock,
            "powershell_code_execution_invoke_reflectivepeinjection",
            params,
            True,
            True,
            None,
        )

    assert str(downloads_root) in str(exc_info.value)


# Escape shapes that discriminate a resolving confinement check from a weakened
# one. The blocked-case decoys above sit in a plain sibling directory, which
# even a naive ``str.startswith`` rejects -- so on their own they leave the
# resolution behaviour untested. Each shape here defeats a different plausible
# weakening: ``dot_segment`` a lexical prefix comparison, ``sibling_prefix`` a
# string-prefix comparison that ignores path components, and ``symlink`` any
# check that normalises without resolving.
ESCAPE_SHAPES = ["dot_segment", "sibling_prefix", "symlink"]


def _escape_path(shape, downloads_root, tmp_path, write_decoy):
    """Return (path_to_pass, decoy) for ``shape``; ``write_decoy`` fills the file."""
    outside = tmp_path / "outside"
    outside.mkdir(exist_ok=True)

    if shape == "dot_segment":
        decoy = outside / "decoy.bin"
        write_decoy(decoy)
        # Lexically prefixed by the root, resolves outside it.
        return downloads_root / ".." / "outside" / "decoy.bin", decoy

    if shape == "sibling_prefix":
        sibling = tmp_path / f"{downloads_root.name}_evil"
        sibling.mkdir(exist_ok=True)
        decoy = sibling / "decoy.bin"
        write_decoy(decoy)
        # str(decoy).startswith(str(downloads_root)) is True; it is not inside.
        return decoy, decoy

    decoy = outside / "decoy.bin"
    write_decoy(decoy)
    link = downloads_root / "escape_link"
    if not link.is_symlink():
        link.symlink_to(outside, target_is_directory=True)
    # Every component lexically inside the root; the symlink leaves it.
    return link / "decoy.bin", decoy


@pytest.mark.parametrize("shape", ESCAPE_SHAPES)
@pytest.mark.parametrize(("module_id", "extra_params"), EXTFILE_MODULES)
def test_execute_persistence_module_extfile_escape_shapes_are_blocked(
    module_service,
    agent_mock,
    tmp_path,
    downloads_root,
    module_id,
    extra_params,
    shape,
):
    """Each escape shape is rejected as a confinement failure at every site.

    The decoy exists in all three shapes, so a guard that compares strings
    instead of resolving returns a script with the marker in it rather than
    raising -- which is what makes these red where the sibling-decoy case is
    green. Asserting the root appears in the message also separates a
    confinement rejection from the unrelated "File does not exist" one.
    """
    agent_mock.language = "powershell"
    ext_file, _ = _escape_path(
        shape, downloads_root, tmp_path, lambda d: d.write_text("H5-LEAK-MARKER")
    )
    params = {"Agent": agent_mock.session_id, "ExtFile": str(ext_file), **extra_params}

    with pytest.raises(ModuleValidationException) as exc_info:
        module_service.execute_module(
            None, agent_mock, module_id, params, True, True, None
        )

    assert str(downloads_root) in str(exc_info.value)
    assert "H5-LEAK-MARKER" not in str(exc_info.value)


@pytest.mark.parametrize("shape", ESCAPE_SHAPES)
def test_execute_module_reflectivepeinjection_escape_shapes_are_blocked(
    module_service, agent_mock, tmp_path, downloads_root, shape
):
    """Same shapes against the ``read_bytes()`` sink, which discloses binary."""
    agent_mock.language = "powershell"
    marker = b"\x00\x01\x02R8-BINARY-MARKER\xff\xfe\x00"
    file_path, _ = _escape_path(
        shape, downloads_root, tmp_path, lambda d: d.write_bytes(marker)
    )

    params = {"Agent": agent_mock.session_id, "File": str(file_path)}
    with pytest.raises(ModuleValidationException) as exc_info:
        module_service.execute_module(
            None,
            agent_mock,
            "powershell_code_execution_invoke_reflectivepeinjection",
            params,
            True,
            True,
            None,
        )

    assert str(downloads_root) in str(exc_info.value)


def test_execute_module_reflectivepeinjection_file_inside_downloads_is_allowed(
    module_service, agent_mock, downloads_root
):
    """Permissive-side pin for the ``File`` guard."""
    agent_mock.language = "powershell"
    payload = downloads_root / "payload.dll"
    payload_bytes = b"\x00\x01\x02R8-BINARY-MARKER\xff\xfe\x00"
    payload.write_bytes(payload_bytes)

    params = {"Agent": agent_mock.session_id, "File": str(payload)}
    res, err = module_service.execute_module(
        None,
        agent_mock,
        "powershell_code_execution_invoke_reflectivepeinjection",
        params,
        True,
        True,
        None,
    )

    assert err is None
    assert base64.b64encode(payload_bytes).decode("UTF-8") in res.data


@pytest.mark.parametrize(
    ("module_id", "language", "extra_params"),
    [
        (
            "powershell_code_execution_invoke_reflectivepeinjection",
            "powershell",
            {"File": "a\x00b"},
        ),
        (
            "python_management_osx_shellcodeinject64",
            "python",
            {"PID": "1234", "Shellcode": "a\x00b"},
        ),
    ],
)
def test_execute_module_nul_byte_in_path_option_is_a_validation_error(
    module_service, agent_mock, downloads_root, module_id, language, extra_params
):
    """An embedded NUL in a confined path option stays a clean 400, not a 500.

    Same trap as the ExtFile case: ``Path.resolve()`` raises ``ValueError`` on an
    embedded null, which ``_generate_script`` turns into
    ``ModuleExecutionException``. A confinement check without the explicit NUL
    clause takes this red.
    """
    agent_mock.language = language
    params = {"Agent": agent_mock.session_id, **extra_params}

    with pytest.raises(ModuleValidationException):
        module_service.execute_module(
            None, agent_mock, module_id, params, True, True, None
        )


def test_execute_module_shellcodeinject64_outside_downloads_is_blocked(
    module_service, agent_mock, tmp_path, downloads_root
):
    """shellcodeinject64's ``Shellcode`` option is confined to downloads.

    Unfixed code reads the file and then dies at the pre-existing ``TypeError``
    in ``script.replace("[SC]", shellcode)``, which surfaces as
    ``ModuleExecutionException`` -- a different exception class, so this goes red.
    """
    agent_mock.language = "python"
    outside = tmp_path / "outside"
    outside.mkdir()
    decoy = outside / "sc.bin"
    decoy.write_bytes(b"\x90\x90R9-MARKER")

    params = {"Agent": agent_mock.session_id, "PID": "1234", "Shellcode": str(decoy)}
    with pytest.raises(ModuleValidationException) as exc_info:
        module_service.execute_module(
            None,
            agent_mock,
            "python_management_osx_shellcodeinject64",
            params,
            True,
            True,
            None,
        )

    assert str(downloads_root) in str(exc_info.value)


@pytest.mark.parametrize("shape", ESCAPE_SHAPES)
def test_execute_module_shellcodeinject64_escape_shapes_are_blocked(
    module_service, agent_mock, tmp_path, downloads_root, shape
):
    """Same shapes against the ``Shellcode`` guard.

    The plain-sibling decoy above is rejected even by a ``str.startswith``
    rewrite, so without these the third guard's resolution behaviour is the one
    of the three left untested. ``ModuleValidationException`` is the
    discriminator: a weakened guard lets the path through to the pre-existing
    ``TypeError`` at ``script.replace("[SC]", shellcode)``, which surfaces as
    ``ModuleExecutionException`` instead.
    """
    agent_mock.language = "python"
    shellcode_path, _ = _escape_path(
        shape, downloads_root, tmp_path, lambda d: d.write_bytes(b"\x90\x90R9-MARKER")
    )

    params = {
        "Agent": agent_mock.session_id,
        "PID": "1234",
        "Shellcode": str(shellcode_path),
    }
    with pytest.raises(ModuleValidationException) as exc_info:
        module_service.execute_module(
            None,
            agent_mock,
            "python_management_osx_shellcodeinject64",
            params,
            True,
            True,
            None,
        )

    assert str(downloads_root) in str(exc_info.value)


def test_execute_module_shellcodeinject64_inside_downloads_generates(
    module_service, agent_mock, downloads_root
):
    """Permissive-side pin for the ``Shellcode`` guard: a path inside the downloads
    root is accepted and its bytes reach the generated script.

    Do not delete this, or the guard loses its only permissive-side test and can be
    inverted unnoticed.
    """
    agent_mock.language = "python"
    payload = downloads_root / "sc.bin"
    payload.write_bytes(b"\x90\x90R9-MARKER")

    params = {"Agent": agent_mock.session_id, "PID": "1234", "Shellcode": str(payload)}
    res, err = module_service.execute_module(
        None,
        agent_mock,
        "python_management_osx_shellcodeinject64",
        params,
        True,
        True,
        None,
    )

    assert err is None
    assert base64.b64encode(b"\x90\x90R9-MARKER").decode() in res.data


def test_execute_module_dcsync_hashdump_native_bool_toggles(module_service, agent_mock):
    """dcsync_hashdump gates ``-DumpForest``/``-GetComputers``/``-OnlyActive:$false``
    on native-bool options.

    Regression guard for the pre-existing ``!= ""`` / ``== ""`` comparisons
    against bool options: a native bool is never ``== ""``, so
    ``-DumpForest`` and ``-GetComputers`` were appended unconditionally and
    ``-OnlyActive:$false`` never was -- the toggles were dead. ``Active`` defaults
    to true (only-active), matching its description and the ``$OnlyActive = $true``
    default in Invoke-DCSync.ps1.
    """
    agent_mock.language = "powershell"
    module_id = "powershell_credentials_mimikatz_dcsync_hashdump"
    base = {"Agent": agent_mock.session_id}

    # Defaults: Forest/Computers false, Active true -> no extra switches.
    res, err = module_service.execute_module(
        None, agent_mock, module_id, base, True, True, None
    )
    assert err is None
    assert "-DumpForest" not in res.data
    assert "-GetComputers" not in res.data
    assert "-OnlyActive:$false" not in res.data

    # Forest + Computers on -> both switches appended.
    res, err = module_service.execute_module(
        None,
        agent_mock,
        module_id,
        {**base, "Forest": "True", "Computers": "True"},
        True,
        True,
        None,
    )
    assert err is None
    assert "-DumpForest" in res.data
    assert "-GetComputers" in res.data

    # Active off -> only-active restriction lifted.
    res, err = module_service.execute_module(
        None, agent_mock, module_id, {**base, "Active": "False"}, True, True, None
    )
    assert err is None
    assert "-OnlyActive:$false" in res.data


def test_execute_module_osx_prompt_native_bool_branches(module_service, agent_mock):
    """osx/prompt selects its script branch from the ``ListApps``/``SandboxMode``
    bools.

    Regression guard for the pre-existing ``!= ""`` comparisons: a native
    bool is always ``!= ""`` so the ``ListApps`` branch was always taken and the
    sandbox / AppName-prompt branches were dead.
    """
    agent_mock.language = "python"
    module_id = "python_collection_osx_prompt"
    base = {"Agent": agent_mock.session_id, "AppName": "App Store"}

    # Defaults: both false -> AppName prompt branch (the else fallthrough).
    res, err = module_service.execute_module(
        None, agent_mock, module_id, base, True, True, None
    )
    assert err is None
    assert "App Store" in res.data
    assert "Available applications" not in res.data

    # ListApps on -> application-listing branch.
    res, err = module_service.execute_module(
        None, agent_mock, module_id, {**base, "ListApps": "True"}, True, True, None
    )
    assert err is None
    assert "Available applications" in res.data

    # SandboxMode on (ListApps off) -> sandbox prompt branch.
    res, err = module_service.execute_module(
        None,
        agent_mock,
        module_id,
        {**base, "SandboxMode": "True"},
        True,
        True,
        None,
    )
    assert err is None
    assert "Software Update requires" in res.data
    assert "Available applications" not in res.data


def test_execute_module_invoke_sqloscmd_obfuscate_options_present(
    module_service, agent_mock
):
    """invoke_sqloscmd reads ``params["Obfuscate"]`` / ``params["ObfuscateCommand"]``
    unconditionally.

    Regression guard for the pre-existing KeyError: those options were
    missing from the module YAML, so ``validate_options`` dropped them and the
    read raised ``KeyError`` on every invocation. A ``Command`` is supplied to
    skip the listener/launcher path so the test needs no active listener.
    """
    agent_mock.language = "powershell"
    module_id = "powershell_lateral_movement_invoke_sqloscmd"
    params = {
        "Agent": agent_mock.session_id,
        "Instance": "SQL01",
        "Command": "whoami",
    }
    res, err = module_service.execute_module(
        None, agent_mock, module_id, params, True, True, None
    )
    assert err is None
    assert 'Invoke-SQLOSCmd -Instance "SQL01" -Command "whoami"' in res.data


def test_windowlist_all_flag_reads_correct_option_key():
    """windowlist packs its BOF ``All`` flag from the ``All`` option.

    Regression guard for the pre-existing key mismatch: the module read
    ``params.get("all")`` (lowercase) which never matched the ``All`` option, so
    the flag was hard-wired to ``"0"`` regardless of the toggle. Exercised
    directly (the BOF path otherwise needs the .NET compiler) by capturing the
    params handed to ``generate_script_bof``.
    """
    spec = importlib.util.spec_from_file_location(
        "windowlist_mod",
        Path(__file__).parents[1]
        / "server/modules/bof/situational_awareness/windowlist.py",
    )
    windowlist = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(windowlist)

    captured = {}
    main_menu = Mock()
    main_menu.modulesv2.generate_script_bof = Mock(
        side_effect=lambda module, params, obfuscate: captured.update(params)
    )

    windowlist.Module.generate(main_menu, Mock(), {"Architecture": "x64", "All": True})
    assert captured["All"] == "1"

    captured.clear()
    windowlist.Module.generate(main_menu, Mock(), {"Architecture": "x64", "All": False})
    assert captured["All"] == "0"


def test_execute_module_credential_injection_winlogon_guard_fires(
    module_service, agent_mock
):
    """credential_injection requires ``NewWinLogon`` or ``ExistingWinLogon`` to be
    set.

    Regression guard for the pre-existing ``== ""`` comparison on bool options:
    a native bool is never ``== ""`` so the guard never raised and the
    module proceeded with neither WinLogon option selected.
    """
    agent_mock.language = "powershell"
    module_id = "powershell_credentials_credential_injection"
    base = {"Agent": agent_mock.session_id}

    # Neither WinLogon option set (both default false) -> validation must fire.
    with pytest.raises(
        ModuleValidationException, match="NewWinLogon or ExistingWinLogon"
    ):
        module_service.execute_module(
            None, agent_mock, module_id, base, True, True, None
        )


def test_execute_module_credential_injection_omits_unset_winlogon_switch(
    module_service, agent_mock
):
    """credential_injection emits the set ``[Switch]`` flag but not the unset one,
    and never drops a value option.

    Regression guard for the bespoke option loop: it emitted every option
    as ``-Name Value``, so a normal ``NewWinLogon`` run still appended the unset
    ``-ExistingWinLogon False``. Because the two are ``[Switch]`` parameters in
    mutually-exclusive parameter sets, that command fails to bind on the agent.
    The loop now keys on the option's native type: boolean switches emit a bare
    flag only when set; value options pass through unchanged -- including a
    literal ``"False"`` (e.g. a password), which must not be dropped as if it
    were an unset switch.
    """
    agent_mock.language = "powershell"
    module_id = "powershell_credentials_credential_injection"
    params = {
        "Agent": agent_mock.session_id,
        "NewWinLogon": "True",
        "DomainName": "demo",
        "UserName": "administrator",
        "Password": "Password1",
    }
    res, err = module_service.execute_module(
        None, agent_mock, module_id, params, True, True, None
    )
    assert err is None
    assert "Invoke-CredentialInjection -NewWinLogon" in res.data
    assert "-ExistingWinLogon False" not in res.data

    # A value option whose literal text is "False" must be passed through, not
    # skipped as if it were an unset switch.
    res, err = module_service.execute_module(
        None,
        agent_mock,
        module_id,
        {**params, "Password": "False"},
        True,
        True,
        None,
    )
    assert err is None
    assert "-Password False" in res.data


def test_execute_module_packet_capture_persistent_native_bool(
    module_service, agent_mock
):
    """packet_capture appends ``persistent=yes`` only when the ``Persistent``
    bool is set.

    Regression guard for the pre-existing ``!= ""`` comparison: a native
    bool is always ``!= ""`` so persistence was always enabled regardless of the
    toggle.
    """
    agent_mock.language = "powershell"
    module_id = "powershell_situational_awareness_host_packet_capture"
    base = {"Agent": agent_mock.session_id}

    # Persistent false (default), StopTrace false -> start capture, no persistence.
    res, err = module_service.execute_module(
        None, agent_mock, module_id, base, True, True, None
    )
    assert err is None
    assert "netsh trace start" in res.data
    assert "persistent=yes" not in res.data

    # Persistent on -> persistence flag appended.
    res, err = module_service.execute_module(
        None, agent_mock, module_id, {**base, "Persistent": "True"}, True, True, None
    )
    assert err is None
    assert "persistent=yes" in res.data


def test_execute_module_fodhelper_custom_command_without_listener(
    module_service, agent_mock
):
    """bypassuac_fodhelper supports a custom ``Command`` instead of a Listener.

    Regression guard for the missing ``Command`` option: the YAML never
    declared it (so ``params.get("Command", "")`` was always empty) and
    ``Listener`` was ``required: true``, so the custom-command branch was
    unreachable. ``Command`` is now declared and ``Listener`` is optional.
    """
    agent_mock.language = "powershell"
    module_id = "powershell_privesc_bypassuac_fodhelper"
    params = {
        "Agent": agent_mock.session_id,
        "Command": "powershell -enc ABC123",
    }
    res, err = module_service.execute_module(
        None, agent_mock, module_id, params, True, True, None
    )
    assert err is None
    assert "Invoke-FodHelperBypass" in res.data
    assert "ABC123" in res.data


def test_execute_module_schtasks_onlogon_native_bool_selects_trigger(
    module_service, agent_mock, downloads_root
):
    """schtasks selects the ONLOGON trigger only when the ``OnLogon`` bool is set.

    Regression guard for the pre-existing ``!= ""`` comparison: a native
    bool is always ``!= ""`` so ``ONLOGON`` was always chosen and BOTH the idle
    and daily trigger branches were unreachable. ``ExtFile`` supplies the payload
    so the test needs no active listener; ``enc_powershell`` is patched to return
    bytes, matching its real return type (the module base64-decodes the result).
    """
    agent_mock.language = "powershell"
    module_id = "powershell_persistence_elevated_schtasks"
    ext_file = downloads_root / "payload.ps1"
    ext_file.write_text("Write-Output hi")
    base = {"Agent": agent_mock.session_id, "ExtFile": str(ext_file)}

    with patch(
        "empire.server.common.helpers.enc_powershell", return_value=b"ENCPAYLOAD"
    ):
        # OnLogon false (default) -> daily trigger, not ONLOGON.
        res, err = module_service.execute_module(
            None, agent_mock, module_id, base, True, True, None
        )
        assert err is None
        assert "/SC DAILY" in res.data
        assert "/SC ONLOGON" not in res.data

        # IdleTime set (OnLogon still off) -> idle trigger, the formerly-dead branch.
        res, err = module_service.execute_module(
            None, agent_mock, module_id, {**base, "IdleTime": "5"}, True, True, None
        )
        assert err is None
        assert "/SC ONIDLE" in res.data
        assert "/SC ONLOGON" not in res.data

        # OnLogon on -> ONLOGON trigger selected.
        res, err = module_service.execute_module(
            None, agent_mock, module_id, {**base, "OnLogon": "True"}, True, True, None
        )
        assert err is None
        assert "/SC ONLOGON" in res.data


def test_execute_module_service_stager_no_proxy_options_on_launcher_bat(
    module_service, main_menu_mock, agent_mock
):
    """service_stager only sets options that ``windows_launcher_bat`` defines.

    Regression guard for the pre-existing KeyError: the module set
    ``UserAgent`` / ``Proxy`` / ``ProxyCreds`` on the ``windows_launcher_bat``
    template, which does not define them, so the assignment raised ``KeyError``
    before ``generate()`` was reached -- the module crashed on every invocation.
    A real ``windows_launcher_bat`` instance supplies the faithful option surface;
    its ``generate()`` is stubbed so the test needs no active listener.
    """
    agent_mock.language = "powershell"
    module_id = "powershell_privesc_powerup_service_stager"

    launcher = LauncherBat(main_menu_mock)
    launcher.generate = Mock(return_value="@echo off\nstart /B powershell -enc ABC123")
    main_menu_mock.stagertemplatesv2.new_instance = Mock(return_value=launcher)

    params = {
        "Agent": agent_mock.session_id,
        "ServiceName": "VulnSvc",
        "Listener": "http",
    }
    res, err = module_service.execute_module(
        None, agent_mock, module_id, params, True, True, None
    )
    assert err is None
    assert 'Invoke-ServiceAbuse -ServiceName "VulnSvc"' in res.data
    assert "start /B powershell -enc ABC123" in res.data


def test_execute_module_service_exe_stager_no_proxy_options_on_launcher_bat(
    module_service, main_menu_mock, agent_mock
):
    """service_exe_stager only sets options that ``windows_launcher_bat`` defines.

    Regression guard for the same pre-existing KeyError: the module
    set ``UserAgent`` / ``Proxy`` / ``ProxyCreds`` on ``windows_launcher_bat``
    (which lacks them), crashing before ``generate()``. Its remaining option
    assignments (``Obfuscate`` / ``ObfuscateCommand`` / ``Bypasses`` / ``Delete``)
    are all defined by the template and pass through as native types.
    """
    agent_mock.language = "powershell"
    module_id = "powershell_privesc_powerup_service_exe_stager"

    launcher = LauncherBat(main_menu_mock)
    launcher.generate = Mock(return_value="@echo off\nstart /B powershell -enc XYZ789")
    main_menu_mock.stagertemplatesv2.new_instance = Mock(return_value=launcher)

    params = {
        "Agent": agent_mock.session_id,
        "ServiceName": "VulnSvc",
        "Listener": "http",
    }
    res, err = module_service.execute_module(
        None, agent_mock, module_id, params, True, True, None
    )
    assert err is None
    assert 'Install-ServiceBinary -ServiceName "VulnSvc"' in res.data
    assert "start /B powershell -enc XYZ789" in res.data


def test_execute_module_task_command_python_agent(module_service, agent_mock):
    agent_mock.language = "python"
    params = {
        "Agent": agent_mock.session_id,
        "Text": "Hello World",
    }
    module_id = "python_trollsploit_osx_say"
    res, err = module_service.execute_module(
        None, agent_mock, module_id, params, True, True, None
    )

    assert err is None

    script = res.data
    assert script == "run_command('say -v alex Hello World')"

    task_command = res.command
    assert task_command == "TASK_PYTHON_CMD_WAIT"


def test_execute_module_task_command_ironpython_agent(module_service, agent_mock):
    agent_mock.language = "ironpython"
    params = {
        "Agent": agent_mock.session_id,
        "Text": "Hello World",
    }
    module_id = "python_trollsploit_osx_say"
    res, err = module_service.execute_module(
        None, agent_mock, module_id, params, True, True, None
    )

    assert err is None
    task_command = res.command
    assert task_command == "TASK_PYTHON_CMD_WAIT"


def test_execute_module_task_command_csharp_agent_with_missing_csharp_module(
    module_service, agent_mock
):
    agent_mock.language = "csharp"
    params = {
        "Agent": agent_mock.session_id,
        "Text": "Hello World",
    }
    module_id = "csharp_execution_some_module"
    _res, err = module_service.execute_module(
        None, agent_mock, module_id, params, True, True, None
    )

    assert err == "Module not found for id csharp_execution_some_module"


def test_execute_module_task_command_csharp_agent_with_csharp_module(
    module_service, agent_mock
):
    agent_mock.language = "csharp"
    params = {
        "Agent": agent_mock.session_id,
        "Command": "triage",
    }
    module_id = "csharp_credentials_rubeus"
    res, err = module_service.execute_module(
        None, agent_mock, module_id, params, True, True, None
    )

    assert err is None
    task_command = res.command
    assert task_command == "TASK_CSHARP_CMD_JOB"


@pytest.mark.parametrize(
    ("background_override", "expected_command"),
    [
        (False, "TASK_CSHARP_CMD_WAIT"),
        (True, "TASK_CSHARP_CMD_JOB"),
        (None, "TASK_CSHARP_CMD_JOB"),
    ],
)
def test_execute_module_background_override(
    module_service, agent_mock, background_override, expected_command
):
    """Test that background_override overrides the module's YAML background setting."""
    agent_mock.language = "csharp"
    module_id = "csharp_credentials_rubeus"

    module = module_service.get_by_id(module_id)
    assert module.background is True, "Rubeus should have background=true in YAML"

    params = {
        "Agent": agent_mock.session_id,
        "Command": "triage",
    }
    res, err = module_service.execute_module(
        None,
        agent_mock,
        module_id,
        params,
        True,
        True,
        None,
        background_override=background_override,
    )

    assert err is None
    assert res.command == expected_command


@pytest.mark.parametrize(
    ("background_override", "expected_command"),
    [
        (True, "TASK_CSHARP_CMD_JOB"),
        (False, "TASK_CSHARP_CMD_WAIT"),
        (None, "TASK_CSHARP_CMD_WAIT"),
    ],
)
def test_execute_module_background_override_default_false(
    module_service, agent_mock, background_override, expected_command
):
    """Test background_override on a module whose YAML background defaults to false."""
    agent_mock.language = "csharp"
    module_id = "csharp_management_patchetw"

    module = module_service.get_by_id(module_id)
    assert module.background is False, "PatchETW should have background=false in YAML"

    params = {
        "Agent": agent_mock.session_id,
        "Method": "patch",
    }
    res, err = module_service.execute_module(
        None,
        agent_mock,
        module_id,
        params,
        True,
        True,
        None,
        background_override=background_override,
    )

    assert err is None
    assert res.command == expected_command


def test_execute_module_bof_custom_generate(module_service, agent_mock):
    agent_mock.language = "csharp"
    params = {
        "Agent": agent_mock.session_id,
        "Architecture": "x64",
        "Domain": ".",
    }
    module_id = "bof_situational_awareness_adcs_enum"
    res, err = module_service.execute_module(
        None, agent_mock, module_id, params, True, True, None
    )

    assert err is None
    task_command = res.command
    assert task_command == "TASK_CSHARP_CMD_WAIT"


def test_execute_module_bof(module_service, agent_mock):
    agent_mock.language = "csharp"
    params = {
        "Agent": agent_mock.session_id,
        "Architecture": "x64",
        "Server": ".",
    }
    module_id = "bof_situational_awareness_tasklist"
    res, err = module_service.execute_module(
        None, agent_mock, module_id, params, True, True, None
    )

    assert err is None
    task_command = res.command
    assert task_command == "TASK_CSHARP_CMD_WAIT"


def test_execute_bof_module_missing_architecture(module_service, agent_mock):
    agent_mock.language = "csharp"
    params = {
        "Agent": agent_mock.session_id,
        "Architecture": "",
        "Server": ".",
    }
    module_id = "bof_situational_awareness_tasklist"

    with pytest.raises(ModuleValidationException) as excinfo:
        module_service.execute_module(
            None, agent_mock, module_id, params, True, True, None
        )

    assert "required option missing: Architecture" in str(excinfo.value)


def test_execute_csharp_module(module_service, agent_mock):
    agent_mock.language = "csharp"
    params = {
        "Agent": agent_mock.session_id,
        "Password": "password",
        "Port": "5900",
        "Username": "Empire",
    }
    module_id = "csharp_management_vnc"

    res, err = module_service.execute_module(
        None, agent_mock, module_id, params, True, True, None
    )

    assert err is None
    task_command = res.command
    assert task_command == "TASK_CSHARP_CMD_JOB"


def test_execute_bof_module_missing_option(module_service, agent_mock):
    agent_mock.language = "csharp"
    params = {
        "Agent": agent_mock.session_id,
        "Password": "password",
        "Port": "",
        "Username": "Empire",
    }
    module_id = "csharp_management_vnc"

    with pytest.raises(ModuleValidationException) as excinfo:
        module_service.execute_module(
            None, agent_mock, module_id, params, True, True, None
        )

    assert "required option missing: Port" in str(excinfo.value)


def test_execute_module_inveigh_array_option_quoted_elements(
    module_service, agent_mock
):
    """Regression: a PowerShell ``[Array]`` option with a ``{{ VALUE_ARRAY }}``
    format_string must render each element double-quoted so the value binds as a
    string array.

    ``-NBNSTypes "00,20"`` binds as the single element ``"00,20"`` (fails the
    ValidateSet) and unquoted ``-NBNSTypes 00,20`` parses ``00`` as the number
    ``0`` (also fails); only ``-NBNSTypes "00","20"`` yields ``@("00","20")``.

    mDNSTypes covers the same path for an option that also carries
    ``suggested_values``: it must not be ``strict``, or validation rejects a
    multi-type value before the format string ever renders.

    The NBNSTypes value is written the way an operator actually types a list —
    with a space after the comma and a trailing comma — so the element
    ``strip()`` and blank-drop are pinned. Without them PowerShell receives
    ``" 20"`` and ``""``, which fail the same ``ValidateSet`` this fix exists
    to satisfy.

    All six of the module's ``[Array]`` options are rendered here, not just the
    two with a ``ValidateSet``: the four Spoofer lists default to empty, so
    without an explicit value the ``and value`` guard skips them and a typo in
    any of their format strings would never surface.

    A scalar option must stay a single quoted token — asserted with a
    comma-bearing value, so an over-broad array expansion would visibly split
    it.

    Note this also covers default-value validation for every option left
    unset — it is currently the only test that fails if ``Proxy`` regresses to
    ``strict: true``.
    """
    agent_mock.language = "powershell"
    module_id = "powershell_situational_awareness_host_inveigh"
    scalar = "Access denied, please authenticate"
    params = {
        "Agent": agent_mock.session_id,
        "NBNSTypes": "00, 20,",
        "mDNSTypes": "QU,QM",
        "SpooferHostsIgnore": "host1,host2",
        "SpooferHostsReply": "host3,host4",
        "SpooferIPsIgnore": "10.0.0.1,10.0.0.2",
        "SpooferIPsReply": "10.0.0.3,10.0.0.4",
        "HTTPResponse": scalar,
    }
    res, err = module_service.execute_module(
        None, agent_mock, module_id, params, True, True, None
    )
    assert err is None
    assert '-NBNSTypes "00","20"' in res.data
    assert '-NBNSTypes "00,20"' not in res.data
    # Bare-substring "not in" checks would collide with the Invoke-Inveigh
    # source, which declares [Array] params as = "" — assert the exact tokens.
    assert '-NBNSTypes "00"," 20"' not in res.data
    assert '-NBNSTypes "00","20",""' not in res.data
    assert '-mDNSTypes "QU","QM"' in res.data
    assert '-SpooferHostsIgnore "host1","host2"' in res.data
    assert '-SpooferHostsReply "host3","host4"' in res.data
    assert '-SpooferIPsIgnore "10.0.0.1","10.0.0.2"' in res.data
    assert '-SpooferIPsReply "10.0.0.3","10.0.0.4"' in res.data
    # module-wide format string still quotes scalar options as a single token
    assert f'-HTTPResponse "{scalar}"' in res.data


def test_execute_module_task_command_powershell_agent(module_service, agent_mock):
    agent_mock.language = "powershell"
    params = {
        "Agent": agent_mock.session_id,
        "BooSource": "Hello World",
    }
    module_id = "powershell_code_execution_invoke_boolang"
    res, err = module_service.execute_module(
        None, agent_mock, module_id, params, True, True, None
    )

    assert err is None
    task_command = res.command
    assert task_command == "TASK_POWERSHELL_CMD_JOB"


def test_execute_module_task_command_unsupported_agent_language(
    module_service, agent_mock
):
    agent_mock.language = "unsupported_language"
    params = {
        "Agent": agent_mock.session_id,
        "BooSource": "Hello World",
    }
    module_id = "powershell_code_execution_invoke_boolang"

    with pytest.raises(ModuleValidationException) as excinfo:
        module_service.execute_module(
            None, agent_mock, module_id, params, True, True, None
        )

    assert "Unsupported agent language 'unsupported_language'" in str(excinfo.value)


def test_execute_module_with_non_ascii_characters(module_service, agent_mock):
    agent_mock.language = "python"
    params = {
        "Agent": agent_mock.session_id,
        "Text": "こんにちは世界",
    }
    module_id = "python_trollsploit_osx_say"

    res, err = module_service.execute_module(
        None, agent_mock, module_id, params, True, True, None
    )

    assert err is None
    assert res.data


def test_execute_disabled_module(module_service, agent_mock):
    agent_mock.language = "python"
    params = {
        "Agent": agent_mock.session_id,
        "Text": "Hello World",
    }
    module_id = "python_trollsploit_osx_say"

    module = module_service.get_by_id(module_id)
    module.enabled = False

    res, err = module_service.execute_module(
        None, agent_mock, module_id, params, True, True, None
    )

    module.enabled = True

    assert res is None
    assert err == "Cannot execute disabled module"


def test_execute_module_validation_error(module_service, agent_mock):
    agent_mock.language = "python"
    params = {
        "InvalidParam": "invalid_value",
    }
    module_id = "python_trollsploit_osx_say"

    with pytest.raises(ModuleValidationException) as excinfo:
        module_service.execute_module(
            None, agent_mock, module_id, params, True, True, None
        )

    assert "required option missing: Agent" in str(excinfo.value)


def test_execute_module_with_empty_params(module_service, agent_mock):
    agent_mock.language = "python"
    params = {}
    module_id = "python_trollsploit_osx_say"

    with pytest.raises(ModuleValidationException) as excinfo:
        module_service.execute_module(
            None, agent_mock, module_id, params, True, True, None
        )

    assert "required option missing: Agent" in str(excinfo.value)


def test_handle_save_file_command_with_extension(module_service):
    """Test _handle_save_file_command extracts basename from path-like module name."""
    command, data = module_service._handle_save_file_command(
        "TASK_PYTHON", "python/trollsploit/osx/say", ".txt ", "data_here"
    )
    assert command == "TASK_PYTHON_CMD_WAIT_SAVE"
    # The prefix should be the basename "say" right-justified to 15 chars
    assert data.startswith("say".rjust(15))
    assert ".txt " in data
    assert data.endswith("data_here")


def test_handle_save_file_command_without_extension(module_service):
    """Test _handle_save_file_command with empty extension returns CMD_WAIT."""
    command, data = module_service._handle_save_file_command(
        "TASK_POWERSHELL", "powershell/collection/screenshot", "", "script_data"
    )
    assert command == "TASK_POWERSHELL_CMD_WAIT"
    assert data == "script_data"


@pytest.mark.parametrize(
    ("agent_language", "module_language", "should_raise"),
    [
        # Valid combinations
        ("go", "bof", False),
        ("go", "powershell", False),
        ("go", "csharp", False),
        ("ironpython", "bof", False),
        ("ironpython", "powershell", False),
        ("ironpython", "csharp", False),
        ("ironpython", "python", False),
        ("powershell", "bof", False),
        ("powershell", "powershell", False),
        ("powershell", "csharp", False),
        ("csharp", "bof", False),
        ("csharp", "powershell", False),
        ("csharp", "csharp", False),
        ("python", "python", False),
        # Invalid combinations
        ("go", "python", True),
        ("go", "ironpython", True),
        ("powershell", "python", True),
        ("powershell", "ironpython", True),
        ("csharp", "python", True),
        ("csharp", "ironpython", True),
        ("python", "powershell", True),
        ("python", "csharp", True),
        ("python", "bof", True),
    ],
)
def test_validate_agent_module_language_compatibility(
    module_service, agent_mock, agent_language, module_language, should_raise
):
    agent_mock.language = agent_language
    agent_mock.language_version = "5.1"

    module_mock = Mock()
    module_mock.language = module_language
    module_mock.min_language_version = "5.0"
    module_mock.needs_admin = False
    module_mock.options = {}

    params = {"Agent": agent_mock.session_id}

    if should_raise:
        with pytest.raises(ModuleValidationException) as excinfo:
            module_service._validate_module_params(
                None, module_mock, agent_mock, params
            )
        assert (
            f"agent language '{agent_language}' cannot run module language '{module_language}'"
            in str(excinfo.value)
        )
    else:
        options, err = module_service._validate_module_params(
            None, module_mock, agent_mock, params
        )
        assert err is None
        assert options is not None


@pytest.mark.parametrize(
    ("needs_admin", "high_integrity", "ignore_admin_check", "should_raise"),
    [
        (
            True,
            False,
            False,
            True,
        ),  # Needs admin, no high integrity, no ignore -> should raise
        (
            True,
            False,
            True,
            False,
        ),  # Needs admin, no high integrity, but ignored -> should not raise
        (
            True,
            True,
            False,
            False,
        ),  # Needs admin, has high integrity -> should not raise
        (False, False, False, False),  # Does not need admin -> should not raise
    ],
)
def test_validate_module_admin_check(
    module_service,
    agent_mock,
    needs_admin,
    high_integrity,
    ignore_admin_check,
    should_raise,
):
    agent_mock.language = "powershell"
    agent_mock.language_version = "5.1"
    agent_mock.high_integrity = high_integrity

    module_mock = Mock()
    module_mock.language = "powershell"
    module_mock.min_language_version = "5.0"
    module_mock.needs_admin = needs_admin
    module_mock.options = {}

    params = {"Agent": agent_mock.session_id}

    if needs_admin and not high_integrity and not ignore_admin_check:
        with pytest.raises(ModuleValidationException) as excinfo:
            module_service._validate_module_params(
                None,
                module_mock,
                agent_mock,
                params,
                ignore_admin_check=ignore_admin_check,
            )
        assert "module needs to run in an elevated context" in str(excinfo.value)
    else:
        options, err = module_service._validate_module_params(
            None, module_mock, agent_mock, params, ignore_admin_check=ignore_admin_check
        )
        assert err is None
        assert options is not None


@pytest.mark.parametrize(
    (
        "agent_language",
        "module_language",
        "agent_version",
        "module_version",
        "ignore_version_check",
        "should_raise",
    ),
    [
        ("powershell", "powershell", "4.0", "5.0", False, True),  # Version too low
        ("powershell", "powershell", "5.0", "5.0", False, False),  # Matching versions
        (
            "powershell",
            "powershell",
            "6.0",
            "5.0",
            False,
            False,
        ),  # Agent version higher than required
        (
            "powershell",
            "powershell",
            "4.0",
            "5.0",
            True,
            False,
        ),  # Ignoring version check
        ("csharp", "csharp", "3.0", "3.5", False, True),  # C# version too low
        ("csharp", "csharp", "3.5", "3.5", False, False),  # C# version matches
        ("csharp", "csharp", "4.0", "3.5", False, False),  # C# agent version higher
    ],
)
def test_validate_module_version_check(
    module_service,
    agent_mock,
    agent_language,
    module_language,
    agent_version,
    module_version,
    ignore_version_check,
    should_raise,
):
    agent_mock.language = agent_language
    agent_mock.language_version = agent_version

    module_mock = Mock()
    module_mock.language = module_language
    module_mock.min_language_version = module_version
    module_mock.needs_admin = False
    module_mock.options = {}

    params = {"Agent": agent_mock.session_id}

    if should_raise:
        with pytest.raises(ModuleValidationException) as excinfo:
            module_service._validate_module_params(
                None,
                module_mock,
                agent_mock,
                params,
                ignore_language_version_check=ignore_version_check,
            )
        assert (
            f"module requires language version {module_version} but agent running language version {agent_version}"
            in str(excinfo.value)
        )
    else:
        options, err = module_service._validate_module_params(
            None,
            module_mock,
            agent_mock,
            params,
            ignore_language_version_check=ignore_version_check,
        )
        assert err is None
        assert options is not None


def test_format_bof_output_go_agent(module_service):
    """Test format_bof_output returns base64 JSON with File and HexData for Go agents."""
    result = module_service.format_bof_output(
        bof_data_b64="dGVzdA==",
        hex_data="AAAA",
        agent_language="go",
    )

    decoded = json.loads(base64.b64decode(result))
    assert decoded == {"File": "dGVzdA==", "HexData": "AAAA"}
    assert "Entrypoint" not in decoded


def test_format_bof_output_dotnet_agent(module_service):
    """Test format_bof_output returns file|,json format with Entrypoint for .NET agents."""
    result = module_service.format_bof_output(
        bof_data_b64="dGVzdA==",
        hex_data="AAAA",
        agent_language="csharp",
        obfuscate=False,
    )

    assert "|," in result.data
    script_file, b64_json = result.data.split("|,", 1)
    assert script_file  # non-empty file path
    assert len(result.files) == 1

    decoded = json.loads(base64.b64decode(b64_json))
    assert decoded["Entrypoint"] == "go"
    assert decoded["File"] == "dGVzdA=="
    assert decoded["HexData"] == "AAAA"


def test_format_bof_output_custom_entry_point(module_service):
    """Test format_bof_output respects custom entry_point parameter."""
    result = module_service.format_bof_output(
        bof_data_b64="dGVzdA==",
        hex_data="AAAA",
        agent_language="csharp",
        entry_point="main",
    )

    _, b64_json = result.data.split("|,", 1)
    decoded = json.loads(base64.b64decode(b64_json))
    assert decoded["Entrypoint"] == "main"


def test_execute_module_bof_go_agent(module_service, agent_mock):
    """Test standard BOF module execution with Go agent produces correct format."""
    agent_mock.language = "go"
    params = {
        "Agent": agent_mock.session_id,
        "Architecture": "x64",
        "Server": ".",
    }
    module_id = "bof_situational_awareness_tasklist"
    res, err = module_service.execute_module(
        None, agent_mock, module_id, params, True, True, None
    )

    assert err is None
    assert res.command == "TASK_BOF_CMD_WAIT"

    # Go format: base64 JSON with File + HexData, no Entrypoint
    decoded = json.loads(base64.b64decode(res.data))
    assert "File" in decoded
    assert "HexData" in decoded
    assert "Entrypoint" not in decoded


def test_execute_module_bof_custom_generate_go_agent(module_service, agent_mock):
    """Test custom-generate BOF module with Go agent returns Go format, not .NET format."""
    agent_mock.language = "go"
    params = {
        "Agent": agent_mock.session_id,
    }
    module_id = "bof_situational_awareness_clipboard_window_inject_list"
    res, err = module_service.execute_module(
        None, agent_mock, module_id, params, True, True, None
    )

    assert err is None
    assert res.command == "TASK_BOF_CMD_WAIT"

    # Must be valid base64 JSON, not the .NET file|,json format
    assert "|," not in res.data
    decoded = json.loads(base64.b64decode(res.data))
    assert "File" in decoded
    assert "HexData" in decoded
    assert "Entrypoint" not in decoded


def test_generate_script_powershell_obfuscates_source_and_script_end_separately(
    module_service, models
):
    """Verify that _generate_script_powershell does NOT double-obfuscate.

    When obfuscation is enabled, the module source is already obfuscated by
    get_module_source(obfuscate=True).  finalize_module() only obfuscates
    script_end (the invoke command), not the already-obfuscated source.
    """
    module = module_service.get_by_id("powershell_code_execution_invoke_boolang")

    obfuscation_config = Mock()
    obfuscation_config.enabled = True
    obfuscation_config.command = "Token\\All\\1"

    fake_source = "function Invoke-Boolang { <# original source #> }"
    obfuscated_source = f"OBFUSCATED({fake_source})"

    obfuscate_calls = []

    def mock_obfuscate(script, command, timeout=300):
        obfuscate_calls.append(script)
        return f"OBFUSCATED({script})"

    with (
        patch.object(
            module_service,
            "get_module_source",
            return_value=(obfuscated_source, None),
        ) as mock_get_source,
        patch.object(
            module_service.obfuscation_service,
            "obfuscate",
            side_effect=mock_obfuscate,
        ),
        patch.object(
            module_service.obfuscation_service,
            "obfuscate_keywords",
            side_effect=lambda x: x,
        ),
    ):
        params = {"Agent": "ABC123", "BooSource": "test"}
        result = module_service._generate_script_powershell(
            module, params, obfuscation_config
        )

        # get_module_source should have been called with obfuscate=True
        mock_get_source.assert_called_once_with(
            module_name=module.script_path,
            obfuscate=True,
            obfuscate_command="Token\\All\\1",
        )

        # obfuscate() should have been called exactly ONCE inside
        # _generate_script_powershell — for script_end only.
        # (get_module_source handles its own obfuscation internally.)
        assert len(obfuscate_calls) == 1, (
            f"Expected obfuscate() to be called once (for script_end), "
            f"but it was called {len(obfuscate_calls)} time(s). "
            f"Calls: {obfuscate_calls}"
        )

        # The single obfuscate call should be for the script_end, not for
        # the combined script+script_end (which would indicate double-obfuscation).
        assert not obfuscate_calls[0].startswith("OBFUSCATED("), (
            "obfuscate() was called on already-obfuscated content, "
            "indicating double-obfuscation"
        )

        # The result should contain the obfuscated source (from get_module_source)
        # and the separately obfuscated script_end.
        assert "OBFUSCATED(" in result
        assert obfuscated_source in result


def test_generate_script_powershell_no_obfuscation_skips_obfuscate(
    module_service, models
):
    """When obfuscation is disabled, obfuscate() should not be called at all."""
    module = module_service.get_by_id("powershell_code_execution_invoke_boolang")

    obfuscation_config = Mock()
    obfuscation_config.enabled = False
    obfuscation_config.command = ""

    fake_source = "function Invoke-Boolang { <# original source #> }"

    with (
        patch.object(
            module_service,
            "get_module_source",
            return_value=(fake_source, None),
        ),
        patch.object(
            module_service.obfuscation_service,
            "obfuscate",
        ) as mock_obfuscate,
        patch.object(
            module_service.obfuscation_service,
            "obfuscate_keywords",
            side_effect=lambda x: x,
        ),
    ):
        params = {"Agent": "ABC123", "BooSource": "test"}
        result = module_service._generate_script_powershell(
            module, params, obfuscation_config
        )

        mock_obfuscate.assert_not_called()
        assert fake_source in result


# ---------------------------------------------------------------------------
# finalize_module — direct tests for both script_already_obfuscated paths
# ---------------------------------------------------------------------------


def test_finalize_module_obfuscates_full_script_when_not_preobfuscated(module_service):
    """When script_already_obfuscated=False (default), finalize_module should
    obfuscate the combined script+script_end as a single unit.  This is the
    path used by custom_generate modules (ask.py, logoff.py, etc.)."""
    raw_script = "function Invoke-Something { Write-Output 'hello' }"
    script_end = " Invoke-Something -Param 'value'"

    obfuscate_calls = []

    def mock_obfuscate(script, command, timeout=300):
        obfuscate_calls.append(script)
        return f"OBFUSCATED({script})"

    with (
        patch.object(
            module_service.obfuscation_service, "obfuscate", side_effect=mock_obfuscate
        ),
        patch.object(
            module_service.obfuscation_service,
            "obfuscate_keywords",
            side_effect=lambda x: x,
        ),
    ):
        result = module_service.finalize_module(
            script=raw_script,
            script_end=script_end,
            obfuscate=True,
            obfuscation_command="Token\\All\\1",
            script_already_obfuscated=False,
        )

    # Should obfuscate the COMBINED script, not just script_end
    assert len(obfuscate_calls) == 1
    assert obfuscate_calls[0] == raw_script + script_end
    assert result == f"OBFUSCATED({raw_script}{script_end})"


def test_finalize_module_obfuscates_only_script_end_when_preobfuscated(module_service):
    """When script_already_obfuscated=True, finalize_module should only
    obfuscate script_end, leaving the pre-obfuscated source intact."""
    pre_obfuscated = "ALREADY_OBFUSCATED_SOURCE"
    script_end = " Invoke-Something -Param 'value'"

    obfuscate_calls = []

    def mock_obfuscate(script, command, timeout=300):
        obfuscate_calls.append(script)
        return f"OBFUSCATED({script})"

    with (
        patch.object(
            module_service.obfuscation_service, "obfuscate", side_effect=mock_obfuscate
        ),
        patch.object(
            module_service.obfuscation_service,
            "obfuscate_keywords",
            side_effect=lambda x: x,
        ),
    ):
        result = module_service.finalize_module(
            script=pre_obfuscated,
            script_end=script_end,
            obfuscate=True,
            obfuscation_command="Token\\All\\1",
            script_already_obfuscated=True,
        )

    # Should only obfuscate script_end, not the pre-obfuscated source
    assert len(obfuscate_calls) == 1
    assert obfuscate_calls[0] == script_end
    assert pre_obfuscated in result


# ---------------------------------------------------------------------------
# obfuscate() fallback paths — non-zero returncode and empty output
# ---------------------------------------------------------------------------


def test_obfuscate_nonzero_returncode_returns_keyword_obfuscated_script(main_menu_mock):
    """When subprocess exits with non-zero code, obfuscate() should return
    the keyword-obfuscated script (graceful degradation)."""
    obfuscation_service = ObfuscationService(main_menu=main_menu_mock)

    raw_script = "Write-Host 'hello'"
    keyword_result = "Write-Host 'KEYWORD_REPLACED'"

    mock_completed = Mock()
    mock_completed.returncode = 1
    mock_completed.stderr = b"some error"

    with (
        patch(
            "empire.server.core.obfuscation_service.data_util.is_powershell_installed",
            return_value=True,
        ),
        patch.object(
            obfuscation_service, "obfuscate_keywords", return_value=keyword_result
        ),
        patch(
            "empire.server.core.obfuscation_service.subprocess.run",
            return_value=mock_completed,
        ),
    ):
        result = obfuscation_service.obfuscate(raw_script, "Token\\All\\1")

    assert result == keyword_result


def test_obfuscate_empty_output_returns_keyword_obfuscated_script(main_menu_mock):
    """When subprocess succeeds but produces empty output, obfuscate() should
    return the keyword-obfuscated script."""
    obfuscation_service = ObfuscationService(main_menu=main_menu_mock)

    raw_script = "Write-Host 'hello'"
    keyword_result = "Write-Host 'KEYWORD_REPLACED'"

    mock_completed = Mock()
    mock_completed.returncode = 0

    with (
        patch(
            "empire.server.core.obfuscation_service.data_util.is_powershell_installed",
            return_value=True,
        ),
        patch.object(
            obfuscation_service, "obfuscate_keywords", return_value=keyword_result
        ),
        patch(
            "empire.server.core.obfuscation_service.subprocess.run",
            return_value=mock_completed,
        ),
    ):
        result = obfuscation_service.obfuscate(raw_script, "Token\\All\\1")

    # The obfuscated file will be empty (NamedTemporaryFile with no writes from subprocess)
    # so obfuscate() should detect empty output and return the keyword-obfuscated script
    assert result == keyword_result


# ---------------------------------------------------------------------------
# preobfuscate_module_by_id
# ---------------------------------------------------------------------------


def test_preobfuscate_module_by_id_not_found(module_service):
    with patch.object(module_service, "get_by_id", return_value=None):
        result = module_service.preobfuscate_module_by_id("nonexistent")
    assert "not found" in result


def test_preobfuscate_module_by_id_no_script_path(module_service):
    mock_module = Mock(script_path=None)
    with patch.object(module_service, "get_by_id", return_value=mock_module):
        result = module_service.preobfuscate_module_by_id("inline_only")
    assert "no script_path" in result


def test_preobfuscate_module_by_id_happy_path(module_service):
    mock_module = Mock(script_path="test/test.ps1", language="powershell")
    mock_config = Mock(command="Token\\All\\1")

    with (
        patch.object(module_service, "get_by_id", return_value=mock_module),
        patch("empire.server.core.module_service.SessionLocal") as mock_sl,
        patch.object(
            module_service.obfuscation_service,
            "get_obfuscation_config",
            return_value=mock_config,
        ),
        patch.object(module_service, "obfuscate_module") as mock_obfuscate,
    ):
        mock_db = Mock()
        mock_sl.begin.return_value.__enter__ = Mock(return_value=mock_db)
        mock_sl.begin.return_value.__exit__ = Mock(return_value=False)

        result = module_service.preobfuscate_module_by_id("test_module")

    assert result is None
    mock_obfuscate.assert_called_once()


def test_preobfuscate_module_by_id_config_survives_session_close(module_service):
    """config.command must be readable after the SessionLocal context exits.

    The real get_obfuscation_config returns a session-bound ORM object.
    With expire_on_commit=True (the default), accessing attributes after
    the session closes raises DetachedInstanceError — crashing the ASGI
    background task and preventing all pre-obfuscation.
    """
    mock_module = Mock(script_path="test/test.ps1", language="powershell")

    # Replace the mock get_obfuscation_config with the real static method
    # so it returns a session-bound ORM object (not a transient Mock).
    original_get_config = module_service.obfuscation_service.get_obfuscation_config
    module_service.obfuscation_service.get_obfuscation_config = (
        ObfuscationService.get_obfuscation_config
    )

    try:
        with (
            patch.object(module_service, "get_by_id", return_value=mock_module),
            patch.object(module_service, "obfuscate_module") as mock_obfuscate,
        ):
            # Should NOT raise DetachedInstanceError
            result = module_service.preobfuscate_module_by_id("test_module")

        assert result is None
        mock_obfuscate.assert_called_once()
    finally:
        module_service.obfuscation_service.get_obfuscation_config = original_get_config


# ---------------------------------------------------------------------------
# obfuscate() timeout fallback
# ---------------------------------------------------------------------------


def test_obfuscate_timeout_returns_keyword_obfuscated_script(main_menu_mock):
    """When subprocess.run raises TimeoutExpired, obfuscate() should return
    the keyword-obfuscated (but not Invoke-Obfuscation-processed) script."""
    obfuscation_service = ObfuscationService(main_menu=main_menu_mock)

    raw_script = "Write-Host 'hello world'"
    keyword_obfuscated = "Write-Host 'KEYWORD_OBFUSCATED'"

    with (
        patch(
            "empire.server.core.obfuscation_service.data_util.is_powershell_installed",
            return_value=True,
        ),
        patch.object(
            obfuscation_service,
            "obfuscate_keywords",
            return_value=keyword_obfuscated,
        ),
        patch(
            "empire.server.core.obfuscation_service.subprocess.run",
            side_effect=subprocess.TimeoutExpired(cmd="pwsh", timeout=300),
        ),
    ):
        result = obfuscation_service.obfuscate(raw_script, "Token\\All\\1", timeout=300)

    # Should get back the keyword-obfuscated version, not empty string
    assert result == keyword_obfuscated


# ---------------------------------------------------------------------------
# _generate_script_powershell — inline script (no script_path) with obfuscation
# ---------------------------------------------------------------------------


def test_generate_script_powershell_inline_script_obfuscation(module_service, models):
    """Verify _generate_script_powershell obfuscates inline module.script and
    script_end separately when there is no script_path.  finalize_module
    only obfuscates script_end, not the already-obfuscated inline source."""
    module = module_service.get_by_id("powershell_code_execution_invoke_boolang")

    # Create a copy-like mock that has no script_path but has an inline script
    inline_module = Mock()
    inline_module.script_path = None
    inline_module.script = "function Invoke-Inline { <# inline source #> }"
    inline_module.script_end = module.script_end
    inline_module.advanced = module.advanced
    inline_module.options = module.options

    obfuscation_config = Mock()
    obfuscation_config.enabled = True
    obfuscation_config.command = "Token\\All\\1"

    obfuscate_calls = []

    def mock_obfuscate(script, command, timeout=300):
        obfuscate_calls.append(script)
        return f"OBFUSCATED({script})"

    with (
        patch.object(
            module_service.obfuscation_service,
            "obfuscate",
            side_effect=mock_obfuscate,
        ),
        patch.object(
            module_service.obfuscation_service,
            "obfuscate_keywords",
            side_effect=lambda x: x,
        ),
        patch.object(
            module_service,
            "finalize_module",
            wraps=module_service.finalize_module,
        ) as mock_finalize,
    ):
        params = {"Agent": "ABC123", "BooSource": "test"}
        result = module_service._generate_script_powershell(
            inline_module, params, obfuscation_config
        )

        # obfuscate() should be called twice: once for the inline script,
        # once for script_end
        expected_obfuscate_call_count = 2
        assert len(obfuscate_calls) == expected_obfuscate_call_count, (
            f"Expected obfuscate() called {expected_obfuscate_call_count} times "
            f"(inline script + script_end), "
            f"got {len(obfuscate_calls)}: {obfuscate_calls}"
        )

        # First call should be for the inline script
        assert obfuscate_calls[0] == inline_module.script

        # Second call should be for script_end (not the already-obfuscated inline script)
        assert not obfuscate_calls[1].startswith("OBFUSCATED("), (
            "script_end obfuscation was called on already-obfuscated content"
        )

        # finalize_module is called with obfuscate=True and
        # script_already_obfuscated=True, so it only obfuscates script_end.
        mock_finalize.assert_called_once()
        _, kwargs = mock_finalize.call_args
        assert kwargs.get("obfuscate") is True
        assert kwargs.get("script_already_obfuscated") is True

        # The result should contain both obfuscated parts
        assert "OBFUSCATED(" in result


# ---------------------------------------------------------------------------
# Integration tests — real Invoke-Obfuscation output verification
# ---------------------------------------------------------------------------

requires_powershell = pytest.mark.skipif(
    not shutil.which("powershell") and not shutil.which("pwsh"),
    reason="PowerShell (powershell or pwsh) is not available on this system",
)


@pytest.mark.slow
@requires_powershell
def test_obfuscate_produces_transformed_output(install_path):
    """Verify Invoke-Obfuscation actually transforms the script content.

    Calls the real obfuscation subprocess and checks that:
    - The output is non-empty
    - The output differs from the input
    - Original identifiers are no longer present in plaintext
    """
    main_menu = Mock()
    main_menu.install_path = Path(install_path)
    obfuscation_service = ObfuscationService(main_menu=main_menu)

    original_script = (
        "function Invoke-PerfTestMarker {\n"
        "    $PerfTestVariable = 'HelloFromPerfTest'\n"
        "    Write-Output $PerfTestVariable\n"
        "}\n"
    )

    result = obfuscation_service.obfuscate(
        original_script, "Token\\All\\1", timeout=120
    )

    assert result, "Obfuscation returned empty output"
    assert result != original_script, (
        "Obfuscation returned the script unchanged — Invoke-Obfuscation may not be running"
    )
    # The original function name and variable should be obfuscated away
    assert "Invoke-PerfTestMarker" not in result, (
        f"Original function name 'Invoke-PerfTestMarker' still present in obfuscated output:\n{result[:500]}"
    )
    assert "PerfTestVariable" not in result, (
        f"Original variable name 'PerfTestVariable' still present in obfuscated output:\n{result[:500]}"
    )
    assert "HelloFromPerfTest" not in result, (
        f"Original string literal 'HelloFromPerfTest' still present in obfuscated output:\n{result[:500]}"
    )


@pytest.mark.slow
@requires_powershell
def test_finalize_module_obfuscates_script_end_not_source(install_path):
    """End-to-end verification that finalize_module obfuscates script_end
    while leaving the already-obfuscated source intact.

    Uses real Invoke-Obfuscation to verify the output contains both
    the pre-obfuscated source and a transformed script_end.
    """
    main_menu = Mock()
    main_menu.install_path = Path(install_path)
    obfuscation_service = ObfuscationService(main_menu=main_menu)

    # Simulate a pre-obfuscated module source (already processed)
    pre_obfuscated_source = (
        "# This simulates pre-obfuscated source\n"
        "Set-Variable -Name xQ3k -Value 'already_obfuscated_content'\n"
    )
    # A recognizable script_end that should get obfuscated
    script_end = " Invoke-OriginalCommand -TargetParam 'SensitiveValue' | Out-String"

    module_service_mock = Mock()
    module_service_mock.obfuscation_service = obfuscation_service

    # Call finalize_module directly via the real class method
    result = ModuleService.finalize_module(
        module_service_mock,
        script=pre_obfuscated_source,
        script_end=script_end,
        obfuscate=True,
        obfuscation_command="Token\\All\\1",
        script_already_obfuscated=True,
    )

    assert result, "finalize_module returned empty output"

    # The pre-obfuscated source should still be present (not re-obfuscated)
    assert "already_obfuscated_content" in result, (
        "Pre-obfuscated source was modified — finalize_module should not re-obfuscate it"
    )

    # The original script_end identifiers should be obfuscated away.
    # Note: Token\All\1 obfuscates command names and string literals
    # but not parameter names (e.g., -TargetParam survives).
    assert "Invoke-OriginalCommand" not in result, (
        f"script_end function name 'Invoke-OriginalCommand' was not obfuscated:\n{result[:500]}"
    )
    assert "SensitiveValue" not in result, (
        f"script_end string 'SensitiveValue' was not obfuscated:\n{result[:500]}"
    )


# ---------------------------------------------------------------------------
# .NET version auto-selection tests
# ---------------------------------------------------------------------------


def _make_csharp_module(module_service, compatible_versions: list[str]):
    """Return a real C# module patched with specific CompatibleDotNetVersions."""
    module = module_service.get_by_id("csharp_persistence_sharpsploit_persistwmi")
    assert module is not None, "PersistWMI module must be loaded"
    # Patch CompatibleDotNetVersions for this test
    module.csharp.CompatibleDotNetVersions = compatible_versions
    # Ensure DotNetVersion option reflects new values
    if "DotNetVersion" in module.options:
        module.options["DotNetVersion"].value = compatible_versions[0]
        module.options["DotNetVersion"].suggested_values = compatible_versions
    return module


@pytest.mark.parametrize(
    ("agent_dotnet", "user_dotnet", "expected"),
    [
        # no agent info → fallback to highest compatible version
        (None, None, "net40"),
        # agent exact match → picks highest compatible ≤ agent (CLR4)
        ("net40", None, "net40"),
        # agent CLR4 only (net48) → picks highest CLR4 compatible (net40), not net35
        ("net48", None, "net40"),
        # case-variant stored value normalised correctly
        ("Net40", None, "net40"),
        # agent CLR2 only → picks net35 (CLR4 not available)
        ("net35", None, "net35"),
        # explicit user choice honoured
        (None, "Net35", "net35"),
        # user choice takes precedence over agent version
        ("net40", "Net35", "net35"),
        # agent has both CLRs → picks highest compatible (net40 over net35)
        ("net48,net35", None, "net40"),
    ],
)
def test_dotnet_version_autoselect(
    module_service, agent_mock, agent_dotnet, user_dotnet, expected
):
    """_validate_module_params selects the correct DotNetVersion for C# modules."""
    module = _make_csharp_module(module_service, ["Net35", "Net40"])

    agent_mock.language = "powershell"
    agent_mock.language_version = "5"
    agent_mock.high_integrity = True
    agent_mock.dotnet_version = agent_dotnet

    params = {"Agent": agent_mock.session_id}
    if user_dotnet:
        params["DotNetVersion"] = user_dotnet

    options, err = module_service._validate_module_params(
        None, module, agent_mock, params, ignore_admin_check=True
    )

    assert err is None
    assert options["DotNetVersion"] == expected


def test_dotnet_version_clr2_only_agent_with_clr2_only_module(
    module_service, agent_mock
):
    """Agent with both CLRs but module only supports net35 → selects net35."""
    module = _make_csharp_module(module_service, ["Net35"])
    agent_mock.language = "powershell"
    agent_mock.language_version = "5"
    agent_mock.high_integrity = True
    agent_mock.dotnet_version = "net48,net35"

    params = {"Agent": agent_mock.session_id}
    options, err = module_service._validate_module_params(
        None, module, agent_mock, params, ignore_admin_check=True
    )

    assert err is None
    assert options["DotNetVersion"] == "net35"


def test_dotnet_version_clr4_only_agent_clr2_only_module_raises(
    module_service, agent_mock
):
    """Agent with CLR4 only but module requires only net35 → raises ModuleValidationException."""
    module = _make_csharp_module(module_service, ["Net35"])
    agent_mock.language = "powershell"
    agent_mock.language_version = "5"
    agent_mock.high_integrity = True
    agent_mock.dotnet_version = "net48"

    params = {"Agent": agent_mock.session_id}

    with pytest.raises(ModuleValidationException):
        module_service._validate_module_params(
            None, module, agent_mock, params, ignore_admin_check=True
        )


def test_dotnet_version_user_invalid_returns_error(module_service, agent_mock):
    """DotNetVersion not in CompatibleDotNetVersions is rejected by option validation."""
    module = _make_csharp_module(module_service, ["Net35", "Net40"])
    agent_mock.language = "powershell"
    agent_mock.language_version = "5"
    agent_mock.high_integrity = True
    agent_mock.dotnet_version = None

    # "net48" fails strict validation because it's not in SuggestedValues ["Net35", "Net40"]
    params = {"Agent": agent_mock.session_id, "DotNetVersion": "net48"}
    options, err = module_service._validate_module_params(
        None, module, agent_mock, params, ignore_admin_check=True
    )

    assert options is None
    assert err is not None
    assert "DotNetVersion" in err


def test_dotnet_version_impossible_downgrade_raises(module_service, agent_mock):
    """Agent CLR4-only (net35) cannot run CLR4 modules (Net45, Net48)."""
    module = _make_csharp_module(module_service, ["Net45", "Net48"])
    agent_mock.language = "powershell"
    agent_mock.language_version = "5"
    agent_mock.high_integrity = True
    agent_mock.dotnet_version = "net35"

    params = {"Agent": agent_mock.session_id}

    with pytest.raises(ModuleValidationException):
        module_service._validate_module_params(
            None, module, agent_mock, params, ignore_admin_check=True
        )


def test_generate_script_csharp_wraps_inner_exception_message(
    module_service, agent_mock
):
    # Pins that C# generate-script errors preserve the inner cause: the except
    # block re-raises `ModuleExecutionException(... {e}) from e` with the inner
    # message and traceback. Guards against a regression back to a static,
    # cause-losing message.
    module = module_service.get_by_id("csharp_persistence_sharpsploit_persistwmi")
    assert module is not None
    # Mock the compiler to raise a deterministic error. Use patch.object so the
    # module-scoped `module_service` fixture's compile_task is restored when the
    # block exits — otherwise the failure leaks into later tests in this file
    # (e.g. the BOF execution tests that also call compile_task).
    with (
        patch.object(
            module_service.dotnet_compiler,
            "compile_task",
            side_effect=RuntimeError("synthetic mcs failure"),
        ),
        pytest.raises(ModuleExecutionException) as exc_info,
    ):
        module_service.generate_script_csharp(
            module, {"DotNetVersion": "net40"}, obfuscation_config=None
        )

    # Inner cause is preserved via `raise ... from e`.
    assert exc_info.value.__cause__ is not None
    assert isinstance(exc_info.value.__cause__, RuntimeError)
    # User-facing message includes the inner reason, not the static label.
    assert "synthetic mcs failure" in str(exc_info.value)


def test_parse_agent_dotnet_versions_helper():
    """parse_agent_dotnet_versions correctly parses stored dotnet_version strings."""
    assert parse_agent_dotnet_versions(None) == frozenset()
    assert parse_agent_dotnet_versions("") == frozenset()
    assert parse_agent_dotnet_versions("net48") == frozenset({"net48"})
    assert parse_agent_dotnet_versions("net35") == frozenset({"net35"})
    assert parse_agent_dotnet_versions("net48,net35") == frozenset({"net48", "net35"})
    assert parse_agent_dotnet_versions("Net48,Net35") == frozenset({"net48", "net35"})


def _make_custom_generate_module(path: Path) -> EmpireModule:
    mod = EmpireModule(
        id="custom_gen_test", name="custom_gen_test", language=LanguageEnum.python
    )
    mod.advanced.custom_generate = True
    mod.advanced.custom_generate_path = str(path)
    return mod


def test_load_custom_generate_class_returns_cached(module_service, tmp_path):
    mod = _make_custom_generate_module(tmp_path / "noop.py")
    sentinel = object()
    mod.advanced.generate_class = sentinel

    assert module_service._load_custom_generate_class(mod) is sentinel


def test_load_custom_generate_class_caches_after_first_call(module_service, tmp_path):
    py = tmp_path / "lazy_load_once.py"
    py.write_text("class Module:\n    pass\n")
    mod = _make_custom_generate_module(py)

    with patch(
        "empire.server.core.module_service.importlib.util.module_from_spec",
        wraps=importlib.util.module_from_spec,
    ) as wrapped:
        first = module_service._load_custom_generate_class(mod)
        second = module_service._load_custom_generate_class(mod)

    assert first is second
    assert wrapped.call_count == 1


def test_load_custom_generate_class_wraps_none_spec(module_service, tmp_path):
    mod = _make_custom_generate_module(tmp_path / "doesnotmatter.py")
    with (
        patch(
            "empire.server.core.module_service.importlib.util.spec_from_file_location",
            return_value=None,
        ),
        pytest.raises(ModuleValidationException, match="cannot build import spec"),
    ):
        module_service._load_custom_generate_class(mod)


def test_load_custom_generate_class_wraps_import_error(module_service, tmp_path):
    py = tmp_path / "broken.py"
    py.write_text("raise RuntimeError('boom')\n")
    mod = _make_custom_generate_module(py)

    with pytest.raises(ModuleValidationException, match="failed to load") as excinfo:
        module_service._load_custom_generate_class(mod)
    assert isinstance(excinfo.value.__cause__, RuntimeError)


def test_execute_module_bof_startwebclient(module_service, agent_mock):
    """StartWebClient BOF: arg-less lateral_movement module triggers WebClient service."""
    agent_mock.language = "csharp"
    params = {
        "Agent": agent_mock.session_id,
        "Architecture": "x64",
    }
    module_id = "bof_management_startwebclient"
    res, err = module_service.execute_module(
        None, agent_mock, module_id, params, True, True, None
    )
    assert err is None
    assert res.command == "TASK_CSHARP_CMD_WAIT"


def test_execute_module_bof_domaininfo(module_service, agent_mock):
    """Domaininfo BOF: arg-less situational_awareness module enumerates domain membership."""
    agent_mock.language = "csharp"
    params = {
        "Agent": agent_mock.session_id,
        "Architecture": "x64",
    }
    module_id = "bof_situational_awareness_domaininfo"
    res, err = module_service.execute_module(
        None, agent_mock, module_id, params, True, True, None
    )
    assert err is None
    assert res.command == "TASK_CSHARP_CMD_WAIT"


def test_execute_module_bof_smbinfo(module_service, agent_mock):
    """Smbinfo BOF: single-arg situational_awareness module queries SMB host info."""
    agent_mock.language = "csharp"
    params = {
        "Agent": agent_mock.session_id,
        "Architecture": "x64",
        "Computername": ".",
    }
    module_id = "bof_situational_awareness_smbinfo"
    res, err = module_service.execute_module(
        None, agent_mock, module_id, params, True, True, None
    )
    assert err is None
    assert res.command == "TASK_CSHARP_CMD_WAIT"


def test_execute_module_bof_lapsdump(module_service, agent_mock):
    """Lapsdump BOF: credentials module reads LAPS passwords from AD via LDAP."""
    agent_mock.language = "csharp"
    params = {
        "Agent": agent_mock.session_id,
        "Architecture": "x64",
        "Computername": "*",
    }
    module_id = "bof_credentials_lapsdump"
    res, err = module_service.execute_module(
        None, agent_mock, module_id, params, True, True, None
    )
    assert err is None
    assert res.command == "TASK_CSHARP_CMD_WAIT"


def test_execute_module_bof_findmodule(module_service, agent_mock):
    """FindModule BOF: enumerates processes with a given DLL loaded."""
    agent_mock.language = "csharp"
    params = {
        "Agent": agent_mock.session_id,
        "Architecture": "x64",
        "ModuleName": "amsi.dll",
    }
    module_id = "bof_situational_awareness_findmodule"
    res, err = module_service.execute_module(
        None, agent_mock, module_id, params, True, True, None
    )
    assert err is None
    assert res.command == "TASK_CSHARP_CMD_WAIT"


def test_execute_module_bof_findprochandle(module_service, agent_mock):
    """FindProcHandle BOF: finds which processes hold a handle to a named object."""
    agent_mock.language = "csharp"
    params = {
        "Agent": agent_mock.session_id,
        "Architecture": "x64",
        "HandleName": "lsass.exe",
    }
    module_id = "bof_situational_awareness_findprochandle"
    res, err = module_service.execute_module(
        None, agent_mock, module_id, params, True, True, None
    )
    assert err is None
    assert res.command == "TASK_CSHARP_CMD_WAIT"


def test_execute_module_bof_reconad(module_service, agent_mock):
    """ReconAD BOF: six-arg ADSI AD enumeration; verifies ZZZiiZ format_string packing."""
    agent_mock.language = "csharp"
    params = {
        "Agent": agent_mock.session_id,
        "Architecture": "x64",
        "Objects": "users",
        "Filter": "*",
        "Attributes": "",
        "MaxResults": "100",
        "UseGC": "0",
        "Server": "",
    }
    module_id = "bof_situational_awareness_reconad"
    res, err = module_service.execute_module(
        None, agent_mock, module_id, params, True, True, None
    )
    assert err is None
    assert res.command == "TASK_CSHARP_CMD_WAIT"


@pytest.mark.parametrize(
    ("module_id", "extra_params"),
    [
        # psx: two modes — standard listing and extended listing
        ("bof_situational_awareness_psx", {"Mode": "standard"}),
        ("bof_situational_awareness_psx", {"Mode": "extended"}),
        # psm: module accepts an optional target PID
        ("bof_situational_awareness_psm", {"Pid": "1234"}),
        # no-arg modules — only need Agent key
        ("bof_situational_awareness_psk", {}),
        ("bof_situational_awareness_psw", {}),
        ("bof_situational_awareness_psc", {}),
        ("bof_situational_awareness_winver", {}),
        ("bof_credentials_wdtoggle", {}),
    ],
)
def test_new_outflank_modules_generate_no_error(
    module_service, agent_mock, module_id, extra_params
):
    """Verify custom_generate path works end-to-end for all new Outflank C2TC modules.

    All 7 modules are x64-only (bof.x86='') with custom_generate: true and NO
    Architecture option exposed to the caller.  This test confirms that executing
    each module via the custom_generate path does not raise an exception and
    returns a valid task command — regression guard for the IsADirectoryError
    crash (adversarial review Critical Finding #1) that would occur if the x86
    path were ever incorrectly invoked.
    """
    agent_mock.language = "csharp"
    params = {"Agent": agent_mock.session_id, **extra_params}
    res, err = module_service.execute_module(
        None, agent_mock, module_id, params, True, True, None
    )
    assert err is None, f"execute_module returned error for {module_id}: {err}"
    assert res.command == "TASK_CSHARP_CMD_WAIT", (
        f"Unexpected task command for {module_id}: {res.command}"
    )
