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
        **kwargs,
    ):
        resource = f"\\\\{params['System']}\\{params['Namespace']}"

        # Build the params dictionary with required prefixes
        params_dict = {
            "Architecture": params["Architecture"],
            "System": params["System"],
            "Namespace": params["Namespace"],
            "Query": params["Query"],
            "Resource": resource,
        }

        return main_menu.modulesv2.generate_script_bof(
            module=module,
            params=params_dict,
            obfuscate=obfuscate,
        )
