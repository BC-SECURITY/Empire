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
        Passlist = params["Passlist"]
        Verbose = params["Verbose"]
        ServerType = params["ServerType"]
        Loginacc = params["Loginacc"]
        Loginpass = params["Loginpass"]

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

        return script, script_end
