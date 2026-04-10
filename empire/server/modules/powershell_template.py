from empire.server.common.empire import MainMenu
from empire.server.core.module_models import EmpireModule
from empire.server.core.module_service import auto_finalize, auto_get_source


class Module:
    """
    STOP. In most cases you will not need this file.
    Take a look at the wiki to see if you truly need this.
    https://bc-security.gitbook.io/empire-wiki/module-development/powershell-modules
    """

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
    ) -> tuple[str | None, str | None]:
        # The @auto_get_source decorator handles loading the module source code
        # from module.script_path (with obfuscation if needed) and passes it as
        # the `script` parameter.

        # If you'd just like to import a subset of the functions from the
        #   module source, use the following:
        #   script = helpers.generate_dynamic_powershell_script(module_code, ["Get-Something", "Set-Something"])

        # Alternative: Use the script from the module's yaml instead of @auto_get_source.
        # script = module.script

        # Parse the module options.
        # The params dict contains the validated options that were sent.
        script_end = ""
        # Add any arguments to the end execution of the script
        for option, values in params.items():
            if option.lower() != "agent" and values and values != "":
                if values.lower() == "true":
                    # if we're just adding a switch
                    script_end += " -" + str(option)
                else:
                    script_end += " -" + str(option) + " " + str(values)

        # The @auto_finalize decorator takes the (script, script_end) tuple returned
        # here and calls finalize_module() to obfuscate script_end (if needed) and
        # append it to the script.
        return script, script_end
