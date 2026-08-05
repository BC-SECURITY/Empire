from pathlib import Path
from unittest.mock import MagicMock, Mock

import pytest

from empire.server.listeners.http import Listener as HttpListener
from empire.server.listeners.http import parse_custom_headers
from empire.server.listeners.http_hop import Listener as HttpHopListener
from empire.server.listeners.port_forward_pivot import Listener as PfpListener


@pytest.fixture(scope="module", autouse=True)
def _setup_staging_key(session_local, models):
    with session_local.begin() as db:
        config = db.query(models.Config).first()
        config.staging_key = "@3uiSPNG;mz|{5#1tKCHDZ*dFs87~g,}"


@pytest.fixture
def main_menu_mock(install_path):
    main_menu = Mock()
    main_menu.installPath = ""
    main_menu.install_path = Path(install_path)
    main_menu.listeners.activeListeners = {}
    main_menu.listeners.listeners = {}
    return main_menu


class TestParseCustomHeaders:
    def test_basic_headers(self):
        assert parse_custom_headers(["X-Foo:bar", "X-Baz:qux"]) == {
            "X-Foo": "bar",
            "X-Baz": "qux",
        }

    def test_empty_list(self):
        assert parse_custom_headers([]) == {}

    def test_skips_cookie(self):
        assert parse_custom_headers(["X-Foo:bar", "Cookie:session=abc"]) == {
            "X-Foo": "bar"
        }

    def test_skips_cookie_case_insensitive(self):
        assert parse_custom_headers(["cookie:x"]) == {}
        assert parse_custom_headers(["COOKIE:x"]) == {}

    def test_skips_empty_entries(self):
        assert parse_custom_headers(["", "X-Foo:bar", ""]) == {"X-Foo": "bar"}

    def test_entry_without_colon_becomes_empty_value(self):
        assert parse_custom_headers(["X-Foo"]) == {"X-Foo": ""}

    def test_entry_with_empty_value(self):
        assert parse_custom_headers(["X-Foo:"]) == {"X-Foo": ""}

    def test_skips_empty_key(self):
        assert parse_custom_headers([":value"]) == {}


def _default_profile_with_headers():
    return (
        "/admin/get.php,/news.php|"
        "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko|"
        "X-Foo:bar|X-Baz:qux"
    )


def test_http_generate_stager_powershell_injects_custom_headers(
    monkeypatch, main_menu_mock
):
    http_listener = HttpListener(main_menu_mock)
    http_listener.options["Host"]["Value"] = "http://localhost"
    http_listener.host_address = "http://localhost/"
    http_listener.options["DefaultProfile"]["Value"] = _default_profile_with_headers()

    stager = http_listener.generate_stager(
        listenerOptions=http_listener.options, language="powershell"
    )

    assert "$Script:Headers = @{" in stager
    assert "'X-Foo' = 'bar';" in stager
    assert "'X-Baz' = 'qux';" in stager


def test_http_generate_stager_powershell_no_custom_headers_renders_empty_hashtable(
    monkeypatch, main_menu_mock
):
    http_listener = HttpListener(main_menu_mock)
    http_listener.options["Host"]["Value"] = "http://localhost"
    http_listener.host_address = "http://localhost/"
    http_listener.options["DefaultProfile"]["Value"] = (
        "/admin/get.php,/news.php|Mozilla/5.0"
    )

    stager = http_listener.generate_stager(
        listenerOptions=http_listener.options, language="powershell"
    )

    assert "$Script:Headers = @{" in stager
    # No hashtable entries when profile carries no custom headers.
    headers_block = stager.split("$Script:Headers = @{")[1].split("}")[0]
    assert headers_block.strip() == ""


def test_http_generate_stager_powershell_skips_cookie_from_profile(
    monkeypatch, main_menu_mock
):
    http_listener = HttpListener(main_menu_mock)
    http_listener.options["Host"]["Value"] = "http://localhost"
    http_listener.host_address = "http://localhost/"
    http_listener.options["DefaultProfile"]["Value"] = (
        "/admin/get.php|Mozilla/5.0|Cookie:evil=1|X-Foo:bar"
    )

    stager = http_listener.generate_stager(
        listenerOptions=http_listener.options, language="powershell"
    )

    headers_block = stager.split("$Script:Headers = @{")[1].split("}")[0]
    assert "'X-Foo' = 'bar';" in headers_block
    assert "Cookie" not in headers_block


def test_http_generate_comms_powershell_injects_custom_headers(
    monkeypatch, main_menu_mock
):
    http_listener = HttpListener(main_menu_mock)
    http_listener.options["Host"]["Value"] = "http://localhost"
    http_listener.host_address = "http://localhost/"
    http_listener.options["DefaultProfile"]["Value"] = (
        "/admin/get.php|Mozilla/5.0|X-Foo:bar"
    )

    comms = http_listener.generate_comms(
        listenerOptions=http_listener.options, language="powershell"
    )

    assert "$Script:Headers = @{" in comms
    assert "'X-Foo' = 'bar';" in comms


def test_http_hop_generate_stager_powershell_injects_custom_headers(
    monkeypatch, main_menu_mock
):
    random_mock = MagicMock()
    random_mock.choice.side_effect = lambda x: x[0]
    monkeypatch.setattr("empire.server.listeners.http_hop.random", random_mock)

    # Redirect listener supplies the profile and cert material.
    redirect_listener = HttpListener(main_menu_mock)
    redirect_listener.options["DefaultProfile"]["Value"] = (
        _default_profile_with_headers()
    )

    listenersv2 = MagicMock()
    listenersv2.get_active_listener_by_name.return_value = redirect_listener
    main_menu_mock.listenersv2 = listenersv2

    http_hop_listener = HttpHopListener(main_menu_mock)
    http_hop_listener.options["Host"]["Value"] = "http://localhost"
    http_hop_listener.host_address = "http://localhost/"
    http_hop_listener.options["RedirectListener"]["Value"] = "http1"

    stager = http_hop_listener.generate_stager(
        listenerOptions=http_hop_listener.options, language="powershell"
    )

    assert "$Script:Headers = @{" in stager
    assert "'X-Foo' = 'bar';" in stager
    assert "'X-Baz' = 'qux';" in stager


def test_port_forward_pivot_generate_stager_powershell_injects_custom_headers(
    monkeypatch, main_menu_mock
):
    pfp = PfpListener(main_menu_mock)
    # Port-forward pivot copies options from its parent HTTP listener at start().
    pfp.options.update(HttpListener(main_menu_mock).options)
    pfp.options["Host"] = {"Value": "http://localhost"}
    pfp.options["Port"] = {"Value": "80"}
    pfp.host_address = "http://localhost/"
    pfp.session_cookie = "session"
    pfp.options["DefaultProfile"]["Value"] = _default_profile_with_headers()

    stager = pfp.generate_stager(listenerOptions=pfp.options, language="powershell")

    assert "$Script:Headers = @{" in stager
    assert "'X-Foo' = 'bar';" in stager
    assert "'X-Baz' = 'qux';" in stager
