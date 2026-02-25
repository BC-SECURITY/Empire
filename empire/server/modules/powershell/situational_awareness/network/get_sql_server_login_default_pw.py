from empire.server.common.empire import MainMenu
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
        username = params["Username"]
        password = params["Password"]
        instance = params["Instance"]
        check_all = params["CheckAll"]

        if check_all:
            # read in the common module source code
            script, err = main_menu.modulesv2.get_module_source(
                module_name="recon/Get-SQLInstanceDomain.ps1",
                obfuscate=obfuscate,
                obfuscate_command=obfuscation_command,
            )

            script_end = " Get-SQLInstanceDomain "
            if username != "":
                script_end += " -Username " + username
            if password != "":
                script_end += " -Password " + password
            script_end += " | Select Instance | "
        script_end += " Get-SQLServerLoginDefaultPw"

        if instance != "" and not check_all:
            # read in the common module source code
            script, err = main_menu.modulesv2.get_module_source(
                module_name="recon/Get-SQLServerLoginDefaultPw.ps1",
                obfuscate=obfuscate,
                obfuscate_command=obfuscation_command,
            )
            script_end += " -Instance " + instance

        return main_menu.modulesv2.finalize_module(
            script=script,
            script_end=script_end,
            obfuscate=obfuscate,
            obfuscation_command=obfuscation_command,
        )
