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
        params_dict = {
            "Architecture": params["Architecture"],
            "ScriptType": "0",
            "Server": params["Server"],
            "AdditionalParam": "",
        }

        return main_menu.modulesv2.generate_script_bof(
            module=module,
            params=params_dict,
            obfuscate=obfuscate,
        )
