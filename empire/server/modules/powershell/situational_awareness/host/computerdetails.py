from empire.server.common.empire import MainMenu
from empire.server.core.module_models import EmpireModule
from empire.server.core.module_service import auto_finalize, auto_get_source


class Module:
    @staticmethod
    @auto_get_source
    @auto_finalize
    def generate(
        main_menu: MainMenu,
        module: EmpireModule,
        params: dict,
        obfuscate: bool = False,
        obfuscation_command: str = "",
        script: str = "",
    ):
        script_end = ""
        outputf = params.get("OutputFunction", "Out-String")

        if params["4624"].lower() == "true":
            script_end += "$SecurityLog = Get-EventLog -LogName Security; $Filtered4624 = Find-4624Logons $SecurityLog;"
            script_end += 'Write-Output "Event ID 4624 (Logon):`n";'
            script_end += "Write-Output $Filtered4624.Values"
            script_end += f" | {outputf}"
            return script, script_end

        if params["4648"].lower() == "true":
            script_end += "$SecurityLog = Get-EventLog -LogName Security; $Filtered4648 = Find-4648Logons $SecurityLog;"
            script_end += 'Write-Output "Event ID 4648 (Explicit Credential Logon):`n";'
            script_end += "Write-Output $Filtered4648.Values"
            script_end += f" | {outputf}"
            return script, script_end

        if params["AppLocker"].lower() == "true":
            script_end += "$AppLockerLogs = Find-AppLockerLogs;"
            script_end += 'Write-Output "AppLocker Process Starts:`n";'
            script_end += "Write-Output $AppLockerLogs.Values"
            script_end += f" | {outputf}"
            return script, script_end

        if params["PSScripts"].lower() == "true":
            script_end += "$PSLogs = Find-PSScriptsInPSAppLog;"
            script_end += 'Write-Output "PowerShell Script Executions:`n";'
            script_end += "Write-Output $PSLogs.Values"
            script_end += f" | {outputf}"
            return script, script_end

        if params["SavedRDP"].lower() == "true":
            script_end += "$RdpClientData = Find-RDPClientConnections;"
            script_end += 'Write-Output "RDP Client Data:`n";'
            script_end += "Write-Output $RdpClientData.Values"
            script_end += f" | {outputf}"
            return script, script_end

        script_end += "Get-ComputerDetails -Limit " + str(params["Limit"])
        if outputf == "Out-String":
            script_end += (
                " -ToString | "
                + '%{$_ + "`n"};"`n'
                + str(module.name.split("/")[-1])
                + ' completed!"'
            )
        else:
            script_end += (
                f" | {outputf} | "
                + '%{$_ + "`n"};"`n'
                + str(module.name.split("/")[-1])
                + ' completed!"'
            )

        return script, script_end
