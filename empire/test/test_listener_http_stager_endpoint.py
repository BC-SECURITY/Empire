"""The unauthenticated `?stager=` channel on the plain http listener.

Every row here drives `listener.app.test_client()` through the real
`start_server()` closure, reusing the seam established in
`test_listener_generate_launcher.py`: unset TEST_MODE, stub `Flask.run`, call
`start_server` synchronously. No socket is bound.

Rows that reach a compile producer issue their request from a worker thread
(`_get`) so that anything which blocks in that path fails the test rather than
hanging it — a hung test in CI is worse than a red one.
"""

import threading
from pathlib import Path
from unittest.mock import Mock

import flask
import pytest
from fastapi import status

from empire.server.core.exceptions import ModuleExecutionException
from empire.test.conftest import build_test_listener

IIS_404 = "404 - File or directory not found."
IIS_405 = "405 - HTTP verb used to access this page is not allowed."


@pytest.fixture
def main_menu_mock(models):
    main_menu = Mock()
    main_menu.install_path = Path(__file__).resolve().parents[1] / "server"
    main_menu.listeners.activeListeners = {}
    main_menu.listeners.listeners = {}
    return main_menu


@pytest.fixture
def obfuscation_config(main_menu_mock):
    """Only languages with an ObfuscationConfig row return one; the rest None.

    `empire/server/config.yaml` seeds powershell, csharp and python. A bare Mock
    would return a Mock for every language, so `.enabled` would never raise and
    the unknown-language rows below could not go red.
    """
    configured = {"powershell", "python", "csharp"}

    def _get(db, language):
        if language not in configured:
            return None
        return Mock(enabled=False, command="")

    main_menu_mock.obfuscationv2.get_obfuscation_config.side_effect = _get
    return main_menu_mock.obfuscationv2.get_obfuscation_config


@pytest.fixture
def http_listener(monkeypatch, main_menu_mock, obfuscation_config):
    instance = build_test_listener("http", main_menu_mock)
    instance.options["Name"]["Value"] = "stager-endpoint-listener"
    monkeypatch.delenv("TEST_MODE", raising=False)
    monkeypatch.setattr(flask.Flask, "run", lambda *a, **kw: None)
    instance.start_server(instance.options)
    return instance


@pytest.fixture
def stager_client(http_listener):
    return http_listener.app.test_client()


def _get(client, path, **kwargs):
    """Issue a GET from a worker thread and fail (not hang) if it blocks."""
    box = {}

    def _run():
        try:
            box["response"] = client.get(path, **kwargs)
        except BaseException as e:
            box["error"] = e

    thread = threading.Thread(target=_run)
    thread.start()
    thread.join(timeout=5)
    assert not thread.is_alive(), f"GET {path} did not complete within 5s"
    if "error" in box:
        raise box["error"]
    return box["response"]


def _sentinel(tmp_path, name):
    path = tmp_path / name
    path.write_bytes(f"<<{name}>>".encode())
    return path


@pytest.fixture
def stub_compilers(main_menu_mock, tmp_path):
    """Every stager producer returns a per-language sentinel file or string."""

    def _launcher(*args, **kwargs):
        language = kwargs["language"]
        if language in ("powershell", "python"):
            return f"<<{language}>>"
        return str(_sentinel(tmp_path, language))

    main_menu_mock.stagergenv2.generate_launcher.side_effect = _launcher
    main_menu_mock.stagergenv2.generate_python_exe.side_effect = lambda *a, **kw: str(
        _sentinel(tmp_path, "ironpython")
    )
    main_menu_mock.stagergenv2.generate_go_stageless.side_effect = lambda *a, **kw: str(
        _sentinel(tmp_path, "go")
    )
    return main_menu_mock.stagergenv2


@pytest.mark.parametrize("selector", ["0", "6", "bash", "NONE"])
def test_unknown_stager_language_returns_iis_404(stager_client, selector):
    """A selector outside the five known languages must not peel off the cover
    story. `?stager=0` maps to LANGUAGE_IDS[0] == "NONE", which has no
    ObfuscationConfig row, so `.enabled` used to raise into a Werkzeug 500."""
    response = stager_client.get(f"/anything.php?stager={selector}")

    assert response.status_code == status.HTTP_404_NOT_FOUND
    assert IIS_404 in response.get_data(as_text=True)


def test_unknown_stager_language_does_not_touch_the_database(
    stager_client, obfuscation_config
):
    """The allowlist, not the error handler, is what keeps an unauthenticated
    peer from checking out a pooled connection per garbage request."""
    stager_client.get("/anything.php?stager=bash")

    obfuscation_config.assert_not_called()


@pytest.mark.parametrize(
    ("selector", "expected"),
    [
        ("powershell", b"<<powershell>>"),
        ("python", b"<<python>>"),
        ("csharp", b"<<csharp>>"),
        ("ironpython", b"<<ironpython>>"),
        ("go", b"<<go>>"),
        ("1", b"<<powershell>>"),
        ("2", b"<<python>>"),
        ("3", b"<<csharp>>"),
        ("4", b"<<go>>"),
        ("5", b"<<ironpython>>"),
    ],
)
def test_known_stager_languages_still_served(
    stager_client, stub_compilers, selector, expected
):
    """Every member of STAGER_LANGUAGES and every LANGUAGE_IDS id still serves.

    This is the allow side of the allowlist: a typo'd or dropped frozenset
    member, or a lost numeric mapping, silently 404s without it.
    """
    response = _get(stager_client, f"/anything.php?stager={selector}")

    assert response.status_code == status.HTTP_200_OK
    assert response.get_data() == expected


@pytest.mark.parametrize(
    ("selector", "producer"),
    [("csharp", "generate_launcher"), ("go", "generate_go_stageless")],
)
def test_compiler_failure_returns_iis_404(
    stager_client, main_menu_mock, selector, producer
):
    """A box with no EmpireCompiler and no Go toolchain is an ordinary server
    state, not an adversarial one — and no input validation can anticipate it.
    That is why the fix is an app-wide handler rather than a list of guards."""
    getattr(
        main_menu_mock.stagergenv2, producer
    ).side_effect = ModuleExecutionException("EmpireCompiler is not available")

    response = _get(stager_client, f"/anything.php?stager={selector}")

    assert response.status_code == status.HTTP_404_NOT_FOUND
    assert IIS_404 in response.get_data(as_text=True)


def test_unknown_hop_returns_iis_404(stager_client, main_menu_mock):
    """An unresolvable hop reaches `get_by_name(...) is None` -> `.id`."""
    main_menu_mock.stagergenv2.generate_launcher.side_effect = AttributeError(
        "'NoneType' object has no attribute 'id'"
    )

    response = _get(stager_client, "/anything.php?stager=csharp&hop=bogus")

    assert response.status_code == status.HTTP_404_NOT_FOUND
    assert IIS_404 in response.get_data(as_text=True)


def test_go_stager_with_a_hop_is_still_served(
    stager_client, stub_compilers, main_menu_mock
):
    """The go branch passes listenerName and ignores `hop` entirely, so this has
    always returned a local-listener binary. Goes red the moment a hop guard is
    reintroduced ahead of the language dispatch."""
    main_menu_mock.listenersv2.get_active_listener_by_name.return_value = None

    response = _get(stager_client, "/anything.php?stager=go&hop=bogus")

    assert response.status_code == status.HTTP_200_OK
    assert response.get_data() == b"<<go>>"


def test_valid_hop_is_still_dispatched(stager_client, stub_compilers):
    response = stager_client.get("/anything.php?stager=powershell&hop=hop-listener")

    assert response.status_code == status.HTTP_200_OK
    assert response.get_data() == b"<<powershell>>"
    assert (
        stub_compilers.generate_launcher.call_args.kwargs["listener_name"]
        == "hop-listener"
    )


def test_method_not_allowed_still_renders_the_iis_405(stager_client):
    """The app-wide Exception handler must not shadow handle_405.

    Flask's _find_error_handler tries the (code, ...) bucket before the
    (None, ...) one, so this holds today — but it is a framework internal
    guarding a pure-OPSEC property, and the repo has no other 405 coverage.
    """
    response = stager_client.post("/")

    body = response.get_data(as_text=True)
    assert response.status_code == status.HTTP_405_METHOD_NOT_ALLOWED
    assert IIS_405 in body
    assert IIS_404 not in body


def test_compiled_stager_artifact_is_removed(stager_client, main_menu_mock, tmp_path):
    """9.3 MB per request, never reclaimed, is the durable half of the DoS."""
    artifact = tmp_path / "stager_abc123.exe"
    artifact.write_bytes(b"<<compiled>>")
    main_menu_mock.stagergenv2.generate_go_stageless.side_effect = lambda *a, **kw: str(
        artifact
    )

    response = _get(stager_client, "/anything.php?stager=go")

    assert response.get_data() == b"<<compiled>>"
    assert not artifact.exists()


def test_stager_request_is_logged(stager_client, http_listener, stub_compilers):
    """The stager branch returned before any instance_log write, so a compile
    flood left no trace in the listener's own telemetry."""
    http_listener.instance_log = Mock()

    _get(stager_client, "/anything.php?stager=go")

    logged = " ".join(
        call.args[0] for call in http_listener.instance_log.info.call_args_list
    )
    assert "go" in logged
    assert "127.0.0.1" in logged


def test_stager_selector_cannot_forge_a_log_record(stager_client, http_listener):
    """The selector is logged before the allowlist has looked at it, and query
    strings arrive percent-decoded — so an unauthenticated peer would otherwise
    write its own lines into an unrotated log."""
    http_listener.instance_log = Mock()

    stager_client.get("/anything.php?stager=go%0d%0aFORGED+RECORD")

    logged = " ".join(
        call.args[0] for call in http_listener.instance_log.info.call_args_list
    )
    assert "\n" not in logged
    assert "\r" not in logged


def test_stage0_unknown_hop_returns_iis_404(
    stager_client, http_listener, main_menu_mock
):
    """A STAGE0 whose Hop-Name resolves to nothing fails loudly rather than
    handing a hop-routed agent a stager aimed at the direct address."""
    main_menu_mock.agentcommsv2.handle_agent_data.return_value = [
        ("csharp", b"STAGE0", "None")
    ]
    main_menu_mock.listenersv2.get_active_listener_by_name.return_value = None
    main_menu_mock.stagergenv2.generate_launcher.side_effect = AttributeError(
        "'NoneType' object has no attribute 'id'"
    )

    stager_client.set_cookie(http_listener.session_cookie, "QUFBQQ==")

    response = _get(stager_client, "/anything.php", headers={"Hop-Name": "bogus"})

    assert response.status_code == status.HTTP_404_NOT_FOUND
    assert IIS_404 in response.get_data(as_text=True)
    main_menu_mock.stagergenv2.generate_python_exe.assert_not_called()


def test_error_record_uses_the_current_listener_name(
    stager_client, http_listener, main_menu_mock
):
    """A rename must not split the logs between two names.

    The value in scope at `start_server()` is a deep copy of the options taken
    at boot, so a handler that closed over it files every error under the old
    name while the INFO records beside it use the new one -- and log
    correlation breaks exactly when someone is chasing an error.
    """
    main_menu_mock.stagergenv2.generate_launcher.side_effect = RuntimeError("boom")
    http_listener.instance_log = Mock()
    http_listener.options["Name"]["Value"] = "renamed-listener"

    _get(stager_client, "/anything.php?stager=powershell")

    logged = " ".join(
        call.args[0] for call in http_listener.instance_log.error.call_args_list
    )
    assert "renamed-listener" in logged
    assert "stager-endpoint-listener" not in logged
