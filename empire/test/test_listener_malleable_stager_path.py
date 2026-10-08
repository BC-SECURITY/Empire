"""The unauthenticated compile path on the malleable listener.

A GET carrying no routing packet falls through to the `else` branch of
`handle_request`, which builds an IronPython agent — a full EmpireCompiler run
— and returns its bytes. That is the malleable half of the plain listener's
`?stager=` channel: same attacker (any peer that can reach the port, since the
shipped IP allow/deny lists are empty), same cost per request. Rate-limiting
that compile is deliberately out of scope here; what these rows pin is that it
leaves nothing behind and that its failures do not peel off the cover story.

Rows here drive `listener.app.test_client()` through the real `start_server()`
closure, as `test_listener_http_stager_endpoint.py` does.
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


@pytest.fixture
def main_menu_mock(models):
    main_menu = Mock()
    main_menu.install_path = Path(__file__).resolve().parents[1] / "server"
    main_menu.listeners.activeListeners = {}
    main_menu.listeners.listeners = {}
    main_menu.obfuscationv2.get_obfuscation_config.return_value = Mock(
        enabled=False, command=""
    )
    main_menu.listenersv2.validate_listener_address.return_value = (
        "http://localhost:80",
        None,
    )
    return main_menu


@pytest.fixture
def malleable_listener(monkeypatch, main_menu_mock):
    instance = build_test_listener("http_malleable", main_menu_mock)
    instance.options["Name"]["Value"] = "malleable-stager-listener"
    instance.options["Profile"]["Value"] = "amazon.profile"
    instance.options["Host"]["Value"] = "http://localhost"
    instance.options["Port"]["Value"] = "80"
    instance.validate_options()
    monkeypatch.delenv("TEST_MODE", raising=False)
    monkeypatch.setattr(flask.Flask, "run", lambda *a, **kw: None)
    instance.start_server(instance.options)
    return instance


@pytest.fixture
def malleable_client(malleable_listener):
    return malleable_listener.app.test_client()


@pytest.fixture
def stub_compiler(main_menu_mock, tmp_path):
    """generate_python_exe writes an artifact and hands back its path."""
    counter = {"n": 0}

    def _build(*args, **kwargs):
        counter["n"] += 1
        artifact = tmp_path / f"stager_{counter['n']}.exe"
        artifact.write_bytes(b"<<ironpython>>")
        return str(artifact)

    main_menu_mock.stagergenv2.generate_launcher.return_value = "<<launcher>>"
    main_menu_mock.stagergenv2.generate_python_exe.side_effect = _build
    return counter


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


def test_unauthenticated_get_still_serves_the_agent(malleable_client, stub_compiler):
    """The allow side: a peer with no routing packet still gets its agent."""
    response = _get(malleable_client, "/init/")

    assert response.status_code == status.HTTP_200_OK
    assert response.get_data() == b"<<ironpython>>"


def test_compiled_artifact_is_removed(malleable_client, stub_compiler, tmp_path):
    """One ~9 MB build per unauthenticated request, never reclaimed, is the
    durable half of the exhaustion — disk rather than CPU."""
    _get(malleable_client, "/init/")

    assert list(tmp_path.glob("stager_*.exe")) == []


def test_compiler_failure_serves_the_default_response(
    malleable_client, main_menu_mock, stub_compiler
):
    """A box with no EmpireCompiler is an ordinary server state. Without the
    app-wide handler it became a Werkzeug 500, which is the loudest tell a
    listener has: the profile claims one thing and the traceback another.

    404, not 200: default.html is an IIS "file or directory not found" body,
    and a launcher one-liner downloading a stager URI has to see the failure
    rather than Assembly.Load() an HTML page under a success status."""
    main_menu_mock.stagergenv2.generate_python_exe.side_effect = (
        ModuleExecutionException("EmpireCompiler is not available")
    )

    response = _get(malleable_client, "/init/")

    assert response.status_code == status.HTTP_404_NOT_FOUND
    assert IIS_404 in response.get_data(as_text=True)
