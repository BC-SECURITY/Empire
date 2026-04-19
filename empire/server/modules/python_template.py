from empire.server.common.empire import MainMenu
from empire.server.core.module_models import EmpireModule
from empire.server.core.module_service import auto_get_source


class Module:
    """
    STOP. In most cases you will not need this file.
    Take a look at the wiki to see if you truly need this.
    https://bc-security.gitbook.io/empire-wiki/module-development/python-modules
    """

    @staticmethod
    @auto_get_source
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

        # Alternative: Use the script from the module's yaml instead of @auto_get_source.
        # script = module.script

        # Parse the module options, and insert them into the script.
        # The params dict contains the validated options that were sent.
        for key, value in params.items():
            if key.lower() != "agent" and key.lower() != "computername":
                script = script.replace("{{ " + key + " }}", value).replace(
                    "{{" + key + "}}", value
                )

        # Return the final script directly (no finalize needed for Python modules).
        return script
