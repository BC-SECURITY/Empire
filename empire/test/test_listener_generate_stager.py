"""Custom-header handling for the http-family PowerShell stagers and comms.

``DefaultProfile`` is ``uris|user-agent|Header:Value|Header:Value...``. The
tail after the second ``|`` is parsed by ``listener_util.parse_custom_headers``
and rendered into the ``$Script:Headers`` hashtable in ``http/comms.ps1.j2``,
which ``http/http.ps1.j2`` includes.
"""

from pathlib import Path
from unittest.mock import MagicMock, Mock

import pytest

from empire.server.utils.listener_util import parse_custom_headers
from empire.test.conftest import build_test_listener


@pytest.fixture(scope="module", autouse=True)
def _setup_staging_key(session_local, models):
    with session_local.begin() as db:
        config = db.query(models.Config).first()
        config.staging_key = "@3uiSPNG;mz|{5#1tKCHDZ*dFs87~g,}"


@pytest.fixture
def main_menu_mock(models, install_path):
    main_menu = Mock()
    main_menu.install_path = Path(install_path)
    main_menu.listeners.activeListeners = {}
    main_menu.listeners.listeners = {}
    return main_menu


class TestParseCustomHeaders:
    def test_basic_headers(self):
        assert parse_custom_headers("/a|UA|X-Foo:bar|X-Baz:qux") == {
            "X-Foo": "bar",
            "X-Baz": "qux",
        }

    @pytest.mark.parametrize("profile", ["/a|UA", "/a|UA|", "/a"])
    def test_no_header_tail(self, profile):
        assert parse_custom_headers(profile) == {}

    def test_skips_cookie(self):
        assert parse_custom_headers("/a|UA|X-Foo:bar|Cookie:session=abc") == {
            "X-Foo": "bar"
        }

    def test_skips_cookie_case_insensitive(self):
        assert parse_custom_headers("/a|UA|cookie:x") == {}
        assert parse_custom_headers("/a|UA|COOKIE:x") == {}

    def test_skips_empty_entries(self):
        assert parse_custom_headers("/a|UA||X-Foo:bar|") == {"X-Foo": "bar"}

    def test_entry_without_colon_becomes_empty_value(self):
        assert parse_custom_headers("/a|UA|X-Foo") == {"X-Foo": ""}

    def test_entry_with_empty_value(self):
        assert parse_custom_headers("/a|UA|X-Foo:") == {"X-Foo": ""}

    def test_skips_empty_key(self):
        assert parse_custom_headers("/a|UA|:value") == {}

    def test_value_keeps_everything_after_first_colon(self):
        assert parse_custom_headers("/a|UA|X-Time:12:30:00") == {"X-Time": "12:30:00"}

    def test_case_variant_duplicates_collapse_to_last(self):
        assert parse_custom_headers("/a|UA|X-Foo:a|x-foo:b") == {"x-foo": "b"}


def _profile_with_headers():
    return (
        "/admin/get.php,/news.php|"
        "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko|"
        "X-Foo:bar|X-Baz:qux"
    )


def _headers_block(rendered: str) -> str:
    """Return the body of the rendered $Script:Headers hashtable literal."""
    assert "$Script:Headers = @{" in rendered, "no $Script:Headers hashtable"
    return rendered.split("$Script:Headers = @{", 1)[1].split("}", 1)[0]


def _http_listener(main_menu_mock, profile):
    listener = build_test_listener("http", main_menu_mock)
    listener.options["Host"]["Value"] = "http://localhost"
    listener.host_address = "http://localhost/"
    listener.options["DefaultProfile"]["Value"] = profile
    return listener


def _powershell_stager(listener):
    return listener.generate_stager(
        listenerOptions=listener.options, language="powershell"
    )


def test_http_stager_powershell_renders_custom_headers(main_menu_mock):
    listener = _http_listener(main_menu_mock, _profile_with_headers())

    block = _headers_block(_powershell_stager(listener))

    assert "'X-Foo' = 'bar';" in block
    assert "'X-Baz' = 'qux';" in block


@pytest.mark.parametrize(
    "profile", ["/admin/get.php,/news.php|Mozilla/5.0", "/admin/get.php|Mozilla/5.0|"]
)
def test_http_stager_powershell_without_custom_headers_renders_empty_hashtable(
    main_menu_mock, profile
):
    listener = _http_listener(main_menu_mock, profile)

    assert _headers_block(_powershell_stager(listener)).strip() == ""


def test_http_stager_powershell_skips_cookie_header(main_menu_mock):
    listener = _http_listener(
        main_menu_mock, "/admin/get.php|Mozilla/5.0|Cookie:evil=1|X-Foo:bar"
    )

    block = _headers_block(_powershell_stager(listener))

    assert "'X-Foo' = 'bar';" in block
    assert "Cookie" not in block


def test_http_stager_powershell_keeps_colons_in_values(main_menu_mock):
    listener = _http_listener(main_menu_mock, "/admin/get.php|Mozilla/5.0|X-Time:12:30")

    assert "'X-Time' = '12:30';" in _headers_block(_powershell_stager(listener))


def test_http_stager_powershell_escapes_single_quotes(main_menu_mock):
    listener = _http_listener(main_menu_mock, "/admin/get.php|Mozilla/5.0|X-Quote:it's")

    assert "'X-Quote' = 'it''s';" in _headers_block(_powershell_stager(listener))


def test_http_stager_powershell_drops_legacy_custom_headers_variable(main_menu_mock):
    listener = _http_listener(main_menu_mock, _profile_with_headers())

    assert "$customHeaders" not in _powershell_stager(listener)


# Start-Negotiate issues two requests (stage 1 and stage 2); each must apply
# $Script:Headers with the domain-fronting pre-call when the header is Host.
NEGOTIATE_REQUESTS = 2


def test_http_stager_powershell_negotiate_sends_script_headers(main_menu_mock):
    listener = _http_listener(main_menu_mock, _profile_with_headers())

    stager = _powershell_stager(listener)

    assert stager.count("if($_.Name.ToLower() -eq 'host')") == NEGOTIATE_REQUESTS


def test_http_comms_powershell_renders_custom_headers(main_menu_mock):
    listener = _http_listener(main_menu_mock, "/admin/get.php|Mozilla/5.0|X-Foo:bar")

    comms = listener.generate_comms(
        listenerOptions=listener.options, language="powershell"
    )

    assert "'X-Foo' = 'bar';" in _headers_block(comms)


def test_http_foreign_comms_powershell_renders_custom_headers(main_menu_mock):
    """http_foreign renders the same http templates; it must feed them the
    profile headers too rather than rely on a template default."""
    listener = build_test_listener("http_foreign", main_menu_mock)
    listener.host_address = "http://localhost/"
    listener.options["DefaultProfile"]["Value"] = "/admin/get.php|Mozilla/5.0|X-Foo:bar"

    comms = listener.generate_comms(
        listenerOptions=listener.options, language="powershell"
    )

    assert "'X-Foo' = 'bar';" in _headers_block(comms)


def test_http_hop_stager_powershell_renders_custom_headers(main_menu_mock):
    redirect = build_test_listener("http", main_menu_mock)
    redirect.options["DefaultProfile"]["Value"] = _profile_with_headers()
    main_menu_mock.listenersv2 = MagicMock()
    main_menu_mock.listenersv2.get_active_listener_by_name.return_value = redirect

    hop = build_test_listener("http_hop", main_menu_mock)
    hop.options["Host"]["Value"] = "http://localhost"
    hop.host_address = "http://localhost/"
    hop.options["RedirectListener"]["Value"] = "http1"

    block = _headers_block(_powershell_stager(hop))

    assert "'X-Foo' = 'bar';" in block
    assert "'X-Baz' = 'qux';" in block
    assert "$customHeaders" not in _powershell_stager(hop)


def test_port_forward_pivot_stager_powershell_renders_custom_headers(main_menu_mock):
    parent = build_test_listener("http", main_menu_mock)
    pivot = build_test_listener("port_forward_pivot", main_menu_mock)
    # start() copies the parent's options onto the pivot; mirror that here.
    pivot.options.update(parent.options)
    pivot.options["Host"] = {"Value": "http://localhost"}
    pivot.options["Port"] = {"Value": "80"}
    pivot.options["DefaultProfile"]["Value"] = _profile_with_headers()
    pivot.host_address = "http://localhost/"
    pivot.parent_listener_name = "parent_listener"
    main_menu_mock.listenersv2 = MagicMock()
    main_menu_mock.listenersv2.get_active_listener_by_name.side_effect = lambda name: (
        parent if name == "parent_listener" else None
    )

    stager = _powershell_stager(pivot)
    block = _headers_block(stager)

    assert "'X-Foo' = 'bar';" in block
    assert "'X-Baz' = 'qux';" in block
    assert "$customHeaders" not in stager


def test_http_stager_powershell_sets_rather_than_adds_custom_headers(main_menu_mock):
    """Custom headers must be applied with Set, not Add, so a profile header
    that is already present (User-Agent) replaces the value instead of
    producing a combined "UA1,UA2"."""
    listener = _http_listener(main_menu_mock, _profile_with_headers())

    stager = _powershell_stager(listener)

    assert "$wc.Headers.Add($_.Name, $_.Value)" not in stager
    assert stager.count("$wc.Headers.Set($_.Name, $_.Value)") >= NEGOTIATE_REQUESTS


def test_http_stager_powershell_renders_host_header(main_menu_mock):
    """A Host header (domain fronting) reaches the hashtable with its
    original spelling, which is what the case-insensitive pre-call keys on."""
    listener = _http_listener(
        main_menu_mock, "/admin/get.php|Mozilla/5.0|Host:front.example.com"
    )

    assert "'Host' = 'front.example.com';" in _headers_block(
        _powershell_stager(listener)
    )
