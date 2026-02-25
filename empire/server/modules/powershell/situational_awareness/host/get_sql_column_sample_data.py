from empire.server.common import helpers
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
        username = params["Username"]
        password = params["Password"]
        instance = params["Instance"]
        no_defaults = params["NoDefaults"]
        check_all = params["CheckAll"]
        script_end = ""

        # read in the common module source code
        script, err = main_menu.modulesv2.get_module_source(
            module_name="collection/Get-SQLColumnSampleData.ps1",
            obfuscate=obfuscate,
            obfuscate_command=obfuscation_command,
        )

        if check_all:
            aux_module_source = main_menu.modulesv2.get_module_source(
                module_name="situational_awareness/network/Get-SQLInstanceDomain.ps1",
                obfuscate=obfuscate,
                obfuscate_command=obfuscation_command,
            )
            try:
                with open(aux_module_source) as auxSource:
                    aux_script = auxSource.read()
                    script += " " + aux_script
            except Exception:
                print(
                    helpers.color(
                        "[!] Could not read additional module source path at: "
                        + str(aux_module_source)
                    )
                )
            script_end = " Get-SQLInstanceDomain "
            if username != "":
                script_end += " -Username " + username
            if password != "":
                script_end += " -Password " + password
            script_end += " | "
        script_end += " Get-SQLColumnSampleData"
        if username != "":
            script_end += " -Username " + username
        if password != "":
            script_end += " -Password " + password
        if instance != "" and not check_all:
            script_end += " -Instance " + instance
        if no_defaults:
            script_end += " -NoDefaults "

        outputf = params.get("OutputFunction", "Out-String")
        script_end += (
            f" | {outputf} | "
            + '%{$_ + "`n"};"`n'
            + str(module.name.split("/")[-1])
            + ' completed!"'
        )

        return main_menu.modulesv2.finalize_module(
            script=script,
            script_end=script_end,
            obfuscate=obfuscate,
            obfuscation_command=obfuscation_command,
        )
