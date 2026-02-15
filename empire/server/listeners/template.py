import random
import time

# Empire imports
from empire.server.common import helpers
from empire.server.utils import data_util
from empire.server.utils.module_util import handle_validate_message


class Listener:
    def __init__(self, mainMenu):
        self.info = {
            "Name": "Template",
            "Authors": [
                {
                    "Name": "Will Schroeder",
                    "Handle": "@harmj0y",
                    "Link": "https://twitter.com/harmj0y",
                }
            ],
            "Description": ("Listener template"),
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
                "Value": "http",
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
            "DefaultDelay": {
                "Description": "Agent delay/reach back interval (in seconds).",
                "Required": True,
                "Value": 5,
            },
            "DefaultJitter": {
                "Description": "Jitter in agent reachback interval (0.0-1.0).",
                "Required": True,
                "Value": 0.0,
            },
            "DefaultLostLimit": {
                "Description": "Number of missed checkins before exiting",
                "Required": True,
                "Value": 60,
            },
            "DefaultProfile": {
                "Description": "Default communication profile for the agent.",
                "Required": True,
                "Value": "/admin/get.php,/news.php,/login/process.php|Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko",
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
            "ServerVersion": {
                "Description": "Server header for the control server.",
                "Required": True,
                "Value": "Microsoft-IIS/7.5",
            },
            "StagerURI": {
                "Description": "URI for the stager. Example: stager.php",
                "Required": False,
                "Value": "",
            },
            "UserAgent": {
                "Description": "User-agent string to use for the staging request (default, none, or other).",
                "Required": False,
                "Value": "default",
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
        }

        # required:
        self.mainMenu = mainMenu
        self.thread = None

        # optional/specific for this module

        # set the default staging key to the controller db default
        self.options["StagingKey"]["Value"] = str(
            data_util.get_config("staging_key")[0]
        )

    def default_response(self):
        """
        If there's a default response expected from the server that the client needs to ignore,
        (i.e. a default HTTP page), put the generation here.
        """
        print(
            helpers.color(
                "[!] default_response() not implemented for listeners/template"
            )
        )
        return ""

    def validate_options(self) -> tuple[bool, str | None]:
        """
        Validate all options for this listener.
        """

        for key in self.options:
            if self.options[key]["Required"] and (
                str(self.options[key]["Value"]).strip() == ""
            ):
                return handle_validate_message(f'[!] Option "{key}" is required.')

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
            print(
                helpers.color(
                    "[!] listeners/template generate_launcher(): no language specified!"
                )
            )
            return None

        active_listener = self
        # extract the set options for this instantiated listener
        listenerOptions = active_listener.options

        host = listenerOptions["Host"]["Value"]
        _stagingKey = listenerOptions["StagingKey"]["Value"]
        profile = listenerOptions["DefaultProfile"]["Value"]
        uris = [a.strip("/") for a in profile.split("|")[0].split(",")]
        stage0 = random.choice(uris)
        _launchURI = f"{host}/{stage0}"

        if language.startswith("po"):
            # PowerShell
            return ""

        if language.startswith("py"):
            # Python
            return ""

        print(
            helpers.color(
                "[!] listeners/template generate_launcher(): invalid language specification: only 'powershell' and 'python' are current supported for this module."
            )
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
        print(
            helpers.color(
                "[!] generate_stager() not implemented for listeners/template"
            )
        )
        return ""

    def generate_agent(
        self, listenerOptions, language=None, obfuscate=False, obfuscation_command=""
    ):
        """
        If you want to support staging for the listener module, generate_agent must be
        implemented to return the actual staged agent code.
        """
        print(
            helpers.color("[!] generate_agent() not implemented for listeners/template")
        )
        return ""

    def generate_comms(self, listenerOptions, language=None):
        """
        Generate just the agent communication code block needed for communications with this listener.
        This is so agents can easily be dynamically updated for the new listener.

        This should be implemented for the module.
        """

        if not language:
            print(
                helpers.color(
                    "[!] listeners/template generate_comms(): no language specified!"
                )
            )
            return None

        if language.lower() == "powershell":
            updateServers = """
                $Script:ControlServers = @("{}");
                $Script:ServerIndex = 0;
            """.format(listenerOptions["Host"]["Value"])

            getTask = """
                $script:GetTask = {


                }
            """

            sendMessage = """
                $script:SendMessage = {
                    param($Packets)

                    if($Packets) {

                    }
                }
            """

            return (
                updateServers
                + getTask
                + sendMessage
                + "\n'New agent comms registered!'"
            )

        if language.lower() == "python":
            # send_message()
            return None

        print(
            helpers.color(
                "[!] listeners/template generate_comms(): invalid language specification, only 'powershell' and 'python' are current supported for this module."
            )
        )
        return None

    def start_server(self):
        pass

    def start(self):
        """
        If a server component needs to be started, implement the kick off logic
        here and the actual server code in another function to facilitate threading
        (i.e. start_server() in the http listener).
        """
        listenerOptions = self.options
        self.thread = helpers.KThread(target=self.start_server, args=(listenerOptions,))
        self.thread.daemon = True
        self.thread.start()
        time.sleep(1)
        # returns True if the listener successfully started, false otherwise
        return self.thread.is_alive()

    def shutdown(self):
        """
        If a server component was started, implement the logic that kills the particular
        named listener here.
        """
        pass
