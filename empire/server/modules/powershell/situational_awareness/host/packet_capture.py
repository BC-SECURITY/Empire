from empire.server.common.empire import MainMenu
from empire.server.core.module_models import EmpireModule


class Module:
    @staticmethod
    def generate(
        main_menu: MainMenu,
        module: EmpireModule,
        params: dict,
        obfuscate: bool = False,
        obfuscation_command: str = "",
    ):
        max_size = params["MaxSize"]
        trace_file = params["TraceFile"]
        persistent = params["Persistent"]
        stop_trace = params["StopTrace"]

        if stop_trace.lower() == "true":
            script = "netsh trace stop"

        else:
            script = f"netsh trace start capture=yes traceFile={trace_file}"

            if max_size != "":
                script += f" maxSize={max_size}"

            if persistent != "":
                script += " persistent=yes"

        return main_menu.modulesv2.finalize_module(
            script=script,
            script_end="",
            obfuscate=obfuscate,
            obfuscation_command=obfuscation_command,
        )
