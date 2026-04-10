from empire.server.common.empire import MainMenu
from empire.server.core.db.base import SessionLocal
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
        script_end = "\nInvoke-RunAs "

        # if a credential ID is specified, try to parse
        cred_id = params["CredID"]
        if cred_id != "":
            with SessionLocal() as db:
                cred = main_menu.credentialsv2.get_by_id(db, cred_id)

                if not cred:
                    raise ModuleValidationException("CredID is invalid!")

                if cred.credtype != "plaintext":
                    raise ModuleValidationException(
                        "[!] A CredID with a plaintext password must be used!"
                    )

                if cred.domain != "":
                    params["Domain"] = cred.domain
                if cred.username != "":
                    params["UserName"] = cred.username
                if cred.password != "":
                    params["Password"] = "'" + cred.password + "'"

        if (
            params["Domain"] == ""
            or params["UserName"] == ""
            or params["Password"] == ""
        ):
            raise ModuleValidationException(
                "[!] Domain/UserName/Password or CredID required!"
            )

        for option, values in params.items():
            if (
                option.lower() != "agent"
                and option.lower() != "credid"
                and values
                and values != ""
            ):
                if values.lower() == "true":
                    # if we're just adding a switch
                    script_end += " -" + str(option)
                else:
                    script_end += " -" + str(option) + " '" + str(values) + "'"

        return script, script_end
