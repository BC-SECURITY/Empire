import random

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
        nonce = random.randint(1000, 10000)

        params_dict = {
            "Architecture": params["Architecture"],
            "Nonce": nonce,
            "Domain": params["domain"],
            "SPN": params["SPN"],
        }

        return main_menu.modulesv2.generate_script_bof(
            module=module,
            params=params_dict,
            obfuscate=obfuscate,
        )
