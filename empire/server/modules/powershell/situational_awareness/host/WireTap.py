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
        script_end = 'Invoke-WireTap -Command "'

        # Add any arguments to the end execution of the script
        for option, values in params.items():
            if option.lower() != "agent" and values and values != "":
                if values.lower() == "true":
                    # if we're just adding a switch
                    script_end += str(option)
                elif option.lower() == "time":
                    # if we're just adding a switch
                    script_end += " " + str(values)
                else:
                    script_end += " " + str(option) + " " + str(values)

        script_end += '"'

        return script, script_end
