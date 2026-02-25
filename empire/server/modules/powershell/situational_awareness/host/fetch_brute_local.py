from empire.server.common.empire import MainMenu
from empire.server.core.module_models import EmpireModule
from empire.server.utils.module_util import handle_error_message


class Module:
    @staticmethod
    def generate(
        main_menu: MainMenu,
        module: EmpireModule,
        params: dict,
        obfuscate: bool = False,
        obfuscation_command: str = "",
    ):
        Passlist = params["Passlist"]
        Verbose = params["Verbose"]
        ServerType = params["ServerType"]
        Loginacc = params["Loginacc"]
        Loginpass = params["Loginpass"]

        # read in the common module source code
        script, err = main_menu.modulesv2.get_module_source(
            module_name=module.script_path,
            obfuscate=obfuscate,
            obfuscate_command=obfuscation_command,
        )

        if err:
            return handle_error_message(err)

        script_end = " Fetch-Brute"
        if len(ServerType) >= 1:
            script_end += " -st " + ServerType
        script_end += " -pl " + Passlist
        if len(Verbose) >= 1:
            script_end += " -vbse " + Verbose
        if len(Loginacc) >= 1:
            script_end += " -lacc " + Loginacc
        if len(Loginpass) >= 1:
            script_end += " -lpass " + Loginpass

        return main_menu.modulesv2.finalize_module(
            script=script,
            script_end=script_end,
            obfuscate=obfuscate,
            obfuscation_command=obfuscation_command,
        )
