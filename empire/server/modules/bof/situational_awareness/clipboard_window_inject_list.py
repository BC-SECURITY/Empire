import base64

from empire.server.common.empire import MainMenu
from empire.server.core.module_models import EmpireModule
from empire.server.utils.bof_packer import Packer


class Module:
    @staticmethod
    def generate(
        main_menu: MainMenu,
        module: EmpireModule,
        params: dict,
        obfuscate: bool = False,
        obfuscation_command: str = "",
        **kwargs,
    ):
        agent_language = kwargs.get("agent_language", "")
        script_path = main_menu.modulesv2.module_source_path / module.bof.x64
        bof_data = script_path.read_bytes()
        b64_bof_data = base64.b64encode(bof_data).decode("utf-8")

        packer = Packer()
        packer.addint(0)

        return main_menu.modulesv2.format_bof_output(
            bof_data_b64=b64_bof_data,
            hex_data=packer.getbuffer_data(),
            agent_language=agent_language,
            obfuscate=obfuscate,
        )
