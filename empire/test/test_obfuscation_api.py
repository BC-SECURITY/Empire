import os
import re
import subprocess
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from starlette import status

from empire.server.core import obfuscation_service
from empire.server.core.obfuscation_service import ObfuscationService


def test_get_keyword_not_found(client, admin_auth_header):
    response = client.get(
        "/api/v2/obfuscation/keywords/9999", headers=admin_auth_header
    )

    assert response.status_code == status.HTTP_404_NOT_FOUND
    assert response.json()["detail"] == "Keyword not found for id 9999"


def test_get_keyword(client, admin_auth_header):
    response = client.get("/api/v2/obfuscation/keywords/1", headers=admin_auth_header)

    assert response.status_code == status.HTTP_200_OK
    assert response.json()["id"] == 1
    assert len(response.json()["replacement"]) > 0


def test_get_keywords(client, admin_auth_header):
    response = client.get("/api/v2/obfuscation/keywords", headers=admin_auth_header)

    assert response.status_code == status.HTTP_200_OK
    assert len(response.json()["records"]) > 0


def test_create_keyword_name_conflict(client, admin_auth_header):
    response = client.post(
        "/api/v2/obfuscation/keywords/",
        headers=admin_auth_header,
        json={"keyword": "Invoke-Mimikatz", "replacement": "Invoke-Hax"},
    )

    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert (
        response.json()["detail"] == "Keyword with name Invoke-Mimikatz already exists."
    )


def test_create_keyword_validate_length(client, admin_auth_header):
    response = client.post(
        "/api/v2/obfuscation/keywords/",
        headers=admin_auth_header,
        json={"keyword": "a", "replacement": "b"},
    )

    assert response.status_code == status.HTTP_422_UNPROCESSABLE_CONTENT
    assert (
        response.json()["detail"][0]["msg"]
        == "String should have at least 3 characters"
    )


def test_create_keyword(client, admin_auth_header):
    response = client.post(
        "/api/v2/obfuscation/keywords/",
        headers=admin_auth_header,
        json={"keyword": "Invoke-Things", "replacement": "Invoke-sgnihT;"},
    )

    assert response.status_code == status.HTTP_201_CREATED
    assert response.json()["keyword"] == "Invoke-Things"
    assert response.json()["replacement"] == "Invoke-sgnihT;"


def test_update_keyword_not_found(client, admin_auth_header):
    response = client.put(
        "/api/v2/obfuscation/keywords/9999",
        headers=admin_auth_header,
        json={"keyword": "thiswontwork", "replacement": "x=0;"},
    )

    assert response.status_code == status.HTTP_404_NOT_FOUND
    assert response.json()["detail"] == "Keyword not found for id 9999"


def test_update_keyword_name_conflict(client, admin_auth_header):
    response = client.put(
        "/api/v2/obfuscation/keywords/1",
        headers=admin_auth_header,
        json={"keyword": "Invoke-Mimikatz", "replacement": "Invoke-Whatever"},
    )

    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert (
        response.json()["detail"] == "Keyword with name Invoke-Mimikatz already exists."
    )


def test_update_keyword(client, admin_auth_header):
    response = client.put(
        "/api/v2/obfuscation/keywords/1",
        headers=admin_auth_header,
        json={"keyword": "Completely-new_name", "replacement": "qwerefdsgaf"},
    )

    assert response.json()["keyword"] == "Completely-new_name"
    assert response.json()["replacement"] == "qwerefdsgaf"


def test_delete_keyword(client, admin_auth_header):
    response = client.delete(
        "/api/v2/obfuscation/keywords/1", headers=admin_auth_header
    )

    assert response.status_code == status.HTTP_204_NO_CONTENT

    response = client.get("/api/v2/obfuscation/keywords/1", headers=admin_auth_header)

    assert response.status_code == status.HTTP_404_NOT_FOUND


def test_get_obfuscation_configs(client, admin_auth_header):
    response = client.get("/api/v2/obfuscation/global", headers=admin_auth_header)

    assert response.status_code == status.HTTP_200_OK
    assert len(response.json()["records"]) > 1

    assert any(x["language"] == "powershell" for x in response.json()["records"])
    assert any(x["language"] == "csharp" for x in response.json()["records"])
    assert any(x["language"] == "python" for x in response.json()["records"])


def test_get_obfuscation_config_not_found(client, admin_auth_header):
    response = client.get(
        "/api/v2/obfuscation/global/madeup", headers=admin_auth_header
    )

    assert response.status_code == status.HTTP_404_NOT_FOUND
    assert (
        response.json()["detail"]
        == "Obfuscation config not found for language madeup. Only powershell is supported."
    )


def test_get_obfuscation_config(client, admin_auth_header):
    response = client.get(
        "/api/v2/obfuscation/global/powershell", headers=admin_auth_header
    )

    assert response.status_code == status.HTTP_200_OK
    assert response.json()["language"] == "powershell"
    assert response.json()["enabled"] is False
    assert response.json()["command"] == r"Token\All\1"
    assert response.json()["module"] == "invoke-obfuscation"


def test_update_obfuscation_config_not_found(client, admin_auth_header):
    response = client.put(
        "/api/v2/obfuscation/global/madeup",
        headers=admin_auth_header,
        json={
            "language": "powershell",
            "command": "x=1;",
            "module": "x=1;",
            "enabled": True,
        },
    )

    assert response.status_code == status.HTTP_404_NOT_FOUND
    assert (
        response.json()["detail"]
        == "Obfuscation config not found for language madeup. Only powershell is supported."
    )


def test_update_obfuscation_config(client, admin_auth_header):
    response = client.put(
        "/api/v2/obfuscation/global/powershell",
        headers=admin_auth_header,
        json={
            "language": "powershell",
            "command": r"Token\All\1",
            "module": "invoke-obfuscation",
            "enabled": True,
        },
    )

    assert response.json()["language"] == "powershell"
    assert response.json()["command"] == r"Token\All\1"
    assert response.json()["module"] == "invoke-obfuscation"
    assert response.json()["enabled"] is True


def test_preobfuscate_post_not_preobfuscatable(
    client, admin_auth_header, empire_config
):
    response = client.post(
        "/api/v2/obfuscation/global/csharp/preobfuscate", headers=admin_auth_header
    )

    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert (
        response.json()["detail"]
        == "Obfuscation language csharp is not preobfuscatable."
    )


@contextmanager
def patch_main_source_path(main, path):
    old_path = main.modulesv2.module_source_path
    main.modulesv2.module_source_path = path
    yield
    main.modulesv2.module_source_path = old_path


@pytest.mark.slow
def test_preobfuscate_post(client, admin_auth_header, empire_config, main):
    module_source_dir = Path("empire/test/data/module_source")
    with patch_main_source_path(main, module_source_dir):
        response = client.post(
            "/api/v2/obfuscation/global/powershell/preobfuscate",
            headers=admin_auth_header,
        )

        # It is run as a background task, but in tests it runs synchronously.
        assert response.status_code == status.HTTP_202_ACCEPTED

        obf_module_dir = main.modulesv2._obfuscated_module_source_path

        count = 0
        for root, _dirs, files in os.walk(module_source_dir):
            for file in files:
                if not file.endswith(".ps1"):
                    continue
                root_rep = root.replace(str(module_source_dir), str(obf_module_dir))
                assert (Path(root_rep) / file).exists()
                count += 1

        assert count > 0


def test_preobfuscate_delete_not_preobfuscatable(
    client, admin_auth_header, empire_config
):
    response = client.delete(
        "/api/v2/obfuscation/global/csharp/preobfuscate", headers=admin_auth_header
    )

    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert (
        response.json()["detail"]
        == "Obfuscation language csharp is not preobfuscatable."
    )


def test_preobfuscate_delete(main, client, admin_auth_header, empire_config):
    response = client.delete(
        "/api/v2/obfuscation/global/powershell/preobfuscate",
        headers=admin_auth_header,
    )

    assert response.status_code == status.HTTP_204_NO_CONTENT

    module_dir = main.modulesv2.module_source_path
    obf_module_dir = main.modulesv2._obfuscated_module_source_path

    for root, _dirs, files in os.walk(module_dir):
        for file in files:
            root_rep = root.replace(str(module_dir), str(obf_module_dir))
            path = Path(root_rep + "/" + file)
            assert not path.exists()


def test_preobfuscate_modules_empty_list(client, admin_auth_header):
    response = client.post(
        "/api/v2/obfuscation/modules/preobfuscate",
        headers=admin_auth_header,
        json=[],
    )

    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert "must not be empty" in response.json()["detail"]


def test_preobfuscate_modules_not_found(client, admin_auth_header):
    response = client.post(
        "/api/v2/obfuscation/modules/preobfuscate",
        headers=admin_auth_header,
        json=["nonexistent_module_id"],
    )

    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert "nonexistent_module_id" in response.json()["detail"]


def test_preobfuscate_modules_deduplicates(client, admin_auth_header, main):
    """Duplicate module IDs should be accepted (deduplicated), not rejected."""
    with patch.object(main.modulesv2, "preobfuscate_module_by_id"):
        response = client.post(
            "/api/v2/obfuscation/modules/preobfuscate",
            headers=admin_auth_header,
            json=[
                "powershell_situational_awareness_network_arpscan",
                "powershell_situational_awareness_network_arpscan",
            ],
        )

    assert response.status_code == status.HTTP_202_ACCEPTED


def test_preobfuscate_modules_valid(client, admin_auth_header, main):
    with patch.object(main.modulesv2, "preobfuscate_module_by_id") as mock_preobfuscate:
        response = client.post(
            "/api/v2/obfuscation/modules/preobfuscate",
            headers=admin_auth_header,
            json=["powershell_situational_awareness_network_arpscan"],
        )

    assert response.status_code == status.HTTP_202_ACCEPTED
    mock_preobfuscate.assert_called_once_with(
        "powershell_situational_awareness_network_arpscan"
    )


def _obfuscation_service():
    """A real ObfuscationService with only the DB-backed keyword pass stubbed out."""
    service = ObfuscationService(main_menu=MagicMock(install_path="/tmp/fake"))
    service.obfuscate_keywords = lambda data: data
    return service


@contextmanager
def _powershell_available():
    with patch("empire.server.core.obfuscation_service.data_util") as mock_util:
        mock_util.is_powershell_installed.return_value = True
        mock_util.get_powershell_name.return_value = "pwsh"
        yield


def test_obfuscate_uses_config_timeout():
    """obfuscate() uses empire_config.obfuscation_timeout as the default timeout."""
    service = _obfuscation_service()

    with (
        patch("empire.server.core.obfuscation_service.empire_config") as mock_config,
        _powershell_available(),
        patch("empire.server.core.obfuscation_service.subprocess") as mock_sub,
    ):
        mock_config.obfuscation.timeout = 999
        mock_sub.TimeoutExpired = subprocess.TimeoutExpired
        mock_sub.run.return_value = MagicMock(returncode=0, stderr=b"")

        service.obfuscate("echo test", "Token\\All\\1")

        _, kwargs = mock_sub.run.call_args
        assert kwargs["timeout"] == 999  # noqa: PLR2004


def test_obfuscate_explicit_timeout_overrides_config():
    """An explicit timeout parameter overrides the config value."""
    service = _obfuscation_service()

    with (
        patch("empire.server.core.obfuscation_service.empire_config") as mock_config,
        _powershell_available(),
        patch("empire.server.core.obfuscation_service.subprocess") as mock_sub,
    ):
        mock_config.obfuscation.timeout = 999
        mock_sub.TimeoutExpired = subprocess.TimeoutExpired
        mock_sub.run.return_value = MagicMock(returncode=0, stderr=b"")

        service.obfuscate("echo test", "Token\\All\\1", timeout=42)

        _, kwargs = mock_sub.run.call_args
        assert kwargs["timeout"] == 42  # noqa: PLR2004


def test_obfuscate_zero_timeout_disables_timeout():
    """A timeout of 0 (from config) passes None to subprocess (no timeout)."""
    service = _obfuscation_service()

    with (
        patch("empire.server.core.obfuscation_service.empire_config") as mock_config,
        _powershell_available(),
        patch("empire.server.core.obfuscation_service.subprocess") as mock_sub,
    ):
        mock_config.obfuscation.timeout = 0
        mock_sub.TimeoutExpired = subprocess.TimeoutExpired
        mock_sub.run.return_value = MagicMock(returncode=0, stderr=b"")

        service.obfuscate("echo test", "Token\\All\\1")

        _, kwargs = mock_sub.run.call_args
        assert kwargs["timeout"] is None


def test_obfuscate_command_does_not_reach_a_shell(tmp_path, monkeypatch):
    """An operator-supplied obfuscation command must never be parsed by /bin/sh.

    ``${IFS}`` is load-bearing: ``_convert_obfuscation_command`` strips *all*
    whitespace, so a payload spelled ``; touch marker`` collapses to
    ``;touchmarker``, executes nothing, and would make this test pass against
    the unfixed sink.

    The grammar is neutered and the sink is spied on, for the same reason the
    cmd_exec twin carries a spy: with the grammar in place this payload is
    rejected before ``subprocess.run`` is ever called, so the marker assertion
    would hold even if ``shell=True`` came back. Only the argv layer is under
    test here -- ``test_obfuscate_rejects_powershell_layer_injection`` covers
    the grammar on its own.
    """
    marker = tmp_path / "H1_PWNED"
    command = f"Token\\All\\1';touch${{IFS}}{marker};'"
    reached = []
    real_run = obfuscation_service.subprocess.run

    def spy(*args, **kwargs):
        reached.append((args, kwargs))
        return real_run(*args, **kwargs)

    monkeypatch.setattr(
        obfuscation_service, "_OBFUSCATION_COMMAND_RE", re.compile(r"[\s\S]+")
    )
    monkeypatch.setattr(obfuscation_service.subprocess, "run", spy)

    with _powershell_available():
        _obfuscation_service().obfuscate("echo test", command, timeout=60)

    assert reached, "obfuscate() never reached the spawn; the assertion is vacuous"
    assert not marker.exists(), "the obfuscation command was executed by a shell"


def test_obfuscate_rejects_powershell_layer_injection():
    """A command that breaks out of the ``-Command "..."`` literal is not spawned at all.

    Argv alone does not stop this one: the value is still interpolated into
    PowerShell source, where ``"``, ``$(...)`` and ``;`` are live.
    """
    script = "echo test"
    command = 'Token\\All\\1";$(touch /tmp/H1_PWNED);"'

    def fail_on_spawn(*args, **kwargs):
        pytest.fail(f"malformed obfuscation command was spawned: {args!r}")

    with (
        _powershell_available(),
        patch("empire.server.core.obfuscation_service.subprocess.run", fail_on_spawn),
    ):
        result = _obfuscation_service().obfuscate(script, command)

    assert result == script


def test_obfuscate_spawns_powershell_as_argv():
    """A legitimate command is passed as an argv list, with no shell involved."""
    captured = {}

    def fake_run(*args, **kwargs):
        captured["args"] = args
        captured["kwargs"] = kwargs
        return MagicMock(returncode=0, stderr=b"")

    with (
        _powershell_available(),
        patch("empire.server.core.obfuscation_service.subprocess.run", fake_run),
    ):
        _obfuscation_service().obfuscate("echo test", "Token\\All\\1")

    argv = captured["args"][0]
    assert isinstance(argv, list)
    assert not captured["kwargs"].get("shell")
    assert argv[0] == "pwsh"
    assert argv[1] == "-C"
    assert '-Command "Token,All,1"' in argv[2]
    # Every path is single-quoted (literal in PowerShell): an install path or
    # TMPDIR with a space in it would otherwise split into two arguments and
    # make obfuscation one more silent no-op.
    assert "Import-Module '/tmp/fake/data/" in argv[2]
    assert "-ScriptPath '" in argv[2]
    assert "-Encoding ASCII '" in argv[2]


@pytest.mark.parametrize(
    ("command", "expected"),
    [
        (r"Token\All\1", "Token,All,1"),
        # "+" is in the grammar's alphabet solely for the LAUNCHER tokens
        # (STDIN++, CLIP+, VAR+, MSHTA++, RUNDLL++); nothing else covers it, so
        # tightening the class to [A-Za-z0-9,] would silently stop obfuscating
        # every launcher config while the suite stayed green.
        (r"Launcher\STDIN++\12467", "Launcher,STDIN++,12467"),
        (r"Launcher\CLIP+\1", "Launcher,CLIP+,1"),
        # A "," in the operator's value is rewritten to ",home," so the next
        # token starts from the top menu -- that rewrite has to survive the check.
        (r"Token\All\1,Ast\All\1", "Token,All,1,home,Ast,All,1"),
    ],
)
def test_obfuscate_accepts_real_invoke_obfuscation_commands(command, expected):
    """The grammar must admit every command shape Invoke-Obfuscation ships."""
    captured = {}

    def fake_run(*args, **kwargs):
        captured["argv"] = args[0]
        return MagicMock(returncode=0, stderr=b"")

    with (
        _powershell_available(),
        patch("empire.server.core.obfuscation_service.subprocess.run", fake_run),
    ):
        _obfuscation_service().obfuscate("echo test", command)

    assert "argv" in captured, f"{command!r} was rejected by the command grammar"
    assert f'-Command "{expected}"' in captured["argv"][2]


def test_obfuscate_rejects_an_empty_command():
    """A blank command is rejected up front rather than spawned.

    ``_convert_obfuscation_command`` strips all whitespace, so a whitespace-only
    config collapses to "". Passing that through as ``-Command ""`` leaves
    Invoke-Obfuscation waiting on its interactive menu until the timeout expires,
    so a non-admin operator could stall an obfuscation worker per call.
    """

    def fail_on_spawn(*args, **kwargs):
        pytest.fail(f"empty obfuscation command was spawned: {args!r}")

    for command in ("", "   "):
        with (
            _powershell_available(),
            patch(
                "empire.server.core.obfuscation_service.subprocess.run", fail_on_spawn
            ),
        ):
            assert _obfuscation_service().obfuscate("echo test", command) == "echo test"


def test_obfuscate_survives_an_unlaunchable_powershell():
    """An un-exec'able PowerShell binary stays a soft failure.

    Under ``shell=True`` this surfaced as exit code 127, which the caller already
    handled. Argv raises OSError instead, and letting that escape would turn a
    broken toolchain into a 500 on every task that obfuscates.
    """
    script = "echo test"

    def raise_oserror(*args, **kwargs):
        raise FileNotFoundError(2, "No such file or directory", "pwsh")

    with (
        _powershell_available(),
        patch("empire.server.core.obfuscation_service.subprocess.run", raise_oserror),
    ):
        assert _obfuscation_service().obfuscate(script, "Token\\All\\1") == script
