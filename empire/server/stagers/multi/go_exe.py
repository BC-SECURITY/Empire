from pathlib import Path


class Stager:
    def __init__(self, mainMenu):
        self.info = {
            "Name": "Go Binary Stager",
            "Authors": [
                {
                    "Name": "Anthony Rose",
                    "Handle": "@Cx01N",
                    "Link": "https://twitter.com/Cx01N_",
                },
            ],
            "Description": "Generate a Go binary with embedded stager code.",
            "Comments": ["Based on previous stager implementations"],
        }

        self.options = {
            "Listener": {
                "Description": "Listener to use.",
                "Required": True,
                "Value": "",
            },
            "StagerRetries": {
                "Description": "Times for the stager to retry connecting.",
                "Required": False,
                "Value": "0",
            },
            "OutFile": {
                "Description": "Filename that should be used for the generated output.",
                "Required": True,
                "Value": "Gopire.exe",
            },
            "GOOS": {
                "Description": "Target operating system.",
                "Required": True,
                "Value": "windows",
                "SuggestedValues": ["windows"],
                "Strict": True,
            },
            "GOARCH": {
                "Description": "Target architecture (e.g., amd64, 386, arm).",
                "Required": True,
                "Value": "amd64",
                "SuggestedValues": ["amd64", "386", "arm", "arm64"],
                "Strict": True,
            },
        }

        self.mainMenu = mainMenu

    def generate(self):
        directory = self.mainMenu.stagergenv2.generate_go_stageless(self.options)

        if directory:
            return Path(directory).read_bytes()
        return None
