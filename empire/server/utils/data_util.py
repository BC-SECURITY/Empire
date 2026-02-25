import logging
import socket
import subprocess

from empire.server.core.db import models
from empire.server.core.db.base import SessionLocal

log = logging.getLogger(__name__)


def get_config(fields):
    """
    Helper to pull common database config information outside of the
    normal menu execution.

    Fields should be comma separated.
        i.e. 'version,install_path'
    """
    with SessionLocal.begin() as db:
        results = []
        config = db.query(models.Config).first()

        for field in fields.split(","):
            results.append(config[field.strip()])

        return results


def get_listener_options(listener_name):
    """
    Returns the options for a specified listenername from the database outside
    of the normal menu execution.
    """
    try:
        with SessionLocal() as db:
            return (
                db.query(models.Listener.options)
                .filter(models.Listener.name == listener_name)
                .first()
            )

    except Exception:
        return None


def get_host_address(listener_name):
    try:
        with SessionLocal() as db:
            return (
                db.query(models.Listener.host_address)
                .filter(models.Listener.name == listener_name)
                .first()
            )[0]

    except Exception:
        return None


def is_powershell_installed():
    return get_powershell_name() != ""


def get_powershell_name():
    try:
        subprocess.check_output("which powershell", shell=True)
    except subprocess.CalledProcessError:
        try:
            subprocess.check_output("which pwsh", shell=True)
        except subprocess.CalledProcessError:
            return ""
        return "pwsh"
    return "powershell"


def ps_convert_to_oneliner(psscript):
    """
    Converts a PowerShell script to a one-liner.
    """
    psscript = psscript.replace('"kernel32"', '`"kernel32`"')
    psscript = psscript.replace('"Kernel32.dll"', '`"Kernel32.dll`"')
    psscript = psscript.replace('"RtlMoveMemory"', '`"RtlMoveMemory`"')
    psscript = psscript.replace('"amsi.dll"', '`"amsi.dll`"')
    psscript = psscript.replace('"Amsi"', '`"Amsi`"')
    psscript = psscript.replace('"Scan"', '`"Scan`"')
    psscript = psscript.replace('"Buffer"', '`"Buffer`"')
    psscript = psscript.replace('@"', '"')
    psscript = psscript.replace('"@', '"')
    psscript = psscript.replace("\n", "")
    return psscript.replace("    ", "")


def is_port_in_use(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        return s.connect_ex(("localhost", port)) == 0
