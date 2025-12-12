import logging

log = logging.getLogger(__name__)


class Stager:
    def __init__(self, mainMenu):
        self.info = {
            "Name": "Generate Agent",
            "Authors": [
                {
                    "Name": "Anthony Rose",
                    "Handle": "@Cx01N",
                    "Link": "https://twitter.com/Cx01N_",
                },
            ],
            "Description": "A stageless stager that generates a fully-formed agent for Python, IronPython, and PowerShell by combining stage 0, stage 1, and stage 2 into a single file. Unlike traditional stagers, it performs the key exchange without executing the passed code, making it ideal for debugging or pre-staging agents. This does not apply to C# or Go agents, as they are already compiled and prestaged.",
            "Comments": [],
        }

        self.options = {
            "Language": {
                "Description": "Language of the stager to generate (powershell, csharp).",
                "Required": True,
                "Value": "powershell",
                "SuggestedValues": ["powershell", "python", "ironpython"],
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
                "Description": r"Proxy credentials ([domain\]username:password) to use for request (default, none, or other).",
                "Required": False,
                "Value": "default",
            },
            "OutFile": {
                "Description": "Filename that should be used for the generated output.",
                "Required": True,
                "Value": "agent.txt",
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
            "Staged": {
                "Description": "Allow agent to be staged",
                "Required": True,
                "Value": "False",
                "SuggestedValues": ["True", "False"],
                "Strict": True,
            },
        }

        # save off a copy of the mainMenu object to access external functionality
        #   like listeners/agent handlers/etc.
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
        bypasses = self.options["Bypasses"]["Value"]
        obfuscate = self.options["Obfuscate"]["Value"]
        obfuscate_command = self.options["ObfuscateCommand"]["Value"]

        obfuscate_script = obfuscate.lower() == "true"
        staged = self.options["Staged"]["Value"].lower() == "true"

        if not staged:
            launcher = self.mainMenu.stagergenv2.generate_stageless(self.options)
        else:
            launcher = self.mainMenu.stagergenv2.generate_launcher(
                listener_name,
                language=language,
                encode=False,
                obfuscate=False,
                user_agent=user_agent,
                proxy=proxy,
                proxy_creds=proxy_creds,
                stager_retries=stager_retries,
                bypasses=bypasses,
            )

        if launcher == "":
            log.error("[!] Error in launcher generation.")
            return ""
        if not launcher or launcher.lower() == "failed":
            log.error("[!] Error in launcher command generation.")
            return ""

        if obfuscate_script:
            if language == "powershell":
                launcher = self.mainMenu.obfuscationv2.obfuscate(
                    launcher,
                    obfuscation_command=obfuscate_command,
                )
                launcher = self.mainMenu.obfuscationv2.obfuscate_keywords(launcher)
            elif language in ["python", "ironpython"]:
                launcher = self.mainMenu.obfuscationv2.python_obfuscate(launcher)
                launcher = self.mainMenu.obfuscationv2.obfuscate_keywords(launcher)

        return launcher
