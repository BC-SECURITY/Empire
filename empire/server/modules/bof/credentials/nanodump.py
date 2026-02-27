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
        params_dict = {
            "Architecture": "x64",
            "ProcessID": params.get("pid") if params.get("pid") else "0",
            "DumpPath": params.get("write", "find_me.dmp"),
            "WriteFile": "1" if params.get("write") else "0",
            "ValidSignature": "1" if params.get("valid").lower() == "true" else "0",
            "Fork": "1" if params.get("fork").lower() == "true" else "0",
            "Snapshot": "1" if params.get("snapshot").lower() == "true" else "0",
            "DuplicateHandle": "1" if params.get("duplicate").lower() == "true" else "0",
            "ElevateHandle": "1" if params.get("elevate-handle").lower() == "true" else "0",
            "DuplicateElevate": (
                "1" if params.get("duplicate-elevate").lower() == "true" else "0"
            ),
            "GetPID": "1" if params.get("getpid").lower() == "true" else "0",
            "SecLogonLeakLocal": (
                "1" if params.get("seclogon-leak-local").lower() == "true" else "0"
            ),
            "SecLogonLeakRemote": (
                "1" if params.get("seclogon-leak-remote").lower() == "true" else "0"
            ),
            "SecLogonLeakRemoteBinary": (
                "0" if params.get("seclogon-leak-remote").lower() == "true" else ""
            ),
            "SecLogonDuplicate": (
                "1" if params.get("seclogon-duplicate").lower() == "true" else "0"
            ),
            "SpoofCallstack": "1" if params.get("spoof-callstack").lower() == "true" else "0",
            "SilentProcessExit": "1" if params.get("silent-process-exit").lower() else "0",
            "SilentProcessExitBinary": params.get("silent-process-exit", ""),
            "Shtinkering": "1" if params.get("shtinkering").lower() == "true" else "0",
        }

        return main_menu.modulesv2.generate_script_bof(
            module=module,
            params=params_dict,
            obfuscate=obfuscate,
        )
