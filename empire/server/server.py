#!/usr/bin/env python3
import logging
import os
import pathlib
import pwd
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path

import urllib3

from empire.server.common import empire
from empire.server.core.config import empire_config
from empire.server.core.db import base
from empire.server.utils import file_util
from empire.server.utils.file_util import run_command
from empire.server.utils.log_util import LOG_FORMAT, SIMPLE_LOG_FORMAT, ColorFormatter

log = logging.getLogger(__name__)
main = None


# Disable http warnings
if empire_config.supress_self_cert_warning:
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def setup_logging(args):
    if args.log_level:
        log_level = logging.getLevelName(args.log_level.upper())
    else:
        log_level = logging.getLevelName(empire_config.logging.level.upper())

    log_dir = empire_config.logging.directory
    log_dir.mkdir(parents=True, exist_ok=True)
    root_log_file = log_dir / "empire_server.log"
    root_logger = logging.getLogger()
    # If this isn't set to DEBUG, then we won't see debug messages from the listeners.
    root_logger.setLevel(logging.DEBUG)

    root_logger_file_handler = logging.FileHandler(root_log_file)
    root_logger_file_handler.setFormatter(logging.Formatter(LOG_FORMAT))
    root_logger.addHandler(root_logger_file_handler)

    simple_console = empire_config.logging.simple_console
    stream_format = SIMPLE_LOG_FORMAT if simple_console else LOG_FORMAT
    root_logger_stream_handler = logging.StreamHandler()
    root_logger_stream_handler.setFormatter(ColorFormatter(stream_format))
    root_logger_stream_handler.setLevel(log_level)
    root_logger.addHandler(root_logger_stream_handler)

    try:
        user = os.getenv("SUDO_USER")
        if user:
            user_info = pwd.getpwnam(user)
            os.chown(root_log_file, user_info.pw_uid, user_info.pw_gid)
            log.debug(f"Log file owner changed to {user}.")
        else:
            log.warning("Log file owner not changed. SUDO_USER not found.")
    except KeyError:
        log.error("User not found. Log file owner not changed.")
    except PermissionError:
        log.error("Permission denied. You need root privileges to change file owner.")


CSHARP_DIR_BASE = os.path.join(os.path.dirname(__file__), "csharp/Covenant")
INVOKE_OBFS_SRC_DIR_BASE = os.path.join(
    os.path.dirname(__file__), "data/Invoke-Obfuscation"
)
INVOKE_OBFS_DST_DIR_BASE = "/usr/local/share/powershell/Modules/Invoke-Obfuscation"


def reset():
    base.reset_db()

    file_util.remove_dir_contents(empire_config.directories.downloads)

    if os.path.exists(f"{CSHARP_DIR_BASE}/bin"):
        shutil.rmtree(f"{CSHARP_DIR_BASE}/bin")

    if os.path.exists(f"{CSHARP_DIR_BASE}/obj"):
        shutil.rmtree(f"{CSHARP_DIR_BASE}/obj")

    file_util.remove_dir_contents(f"{CSHARP_DIR_BASE}/Data/Tasks/CSharp/Compiled/net35")
    file_util.remove_dir_contents(f"{CSHARP_DIR_BASE}/Data/Tasks/CSharp/Compiled/net40")
    file_util.remove_dir_contents(f"{CSHARP_DIR_BASE}/Data/Tasks/CSharp/Compiled/net45")
    file_util.remove_dir_contents(
        f"{CSHARP_DIR_BASE}/Data/Tasks/CSharp/Compiled/netcoreapp3.0"
    )

    if os.path.exists(empire_config.starkiller.directory):
        shutil.rmtree(empire_config.starkiller.directory)

    # invoke obfuscation
    if os.path.exists(f"{INVOKE_OBFS_DST_DIR_BASE}"):
        shutil.rmtree(INVOKE_OBFS_DST_DIR_BASE)
    pathlib.Path(pathlib.Path(INVOKE_OBFS_SRC_DIR_BASE).parent).mkdir(
        parents=True, exist_ok=True
    )
    shutil.copytree(
        INVOKE_OBFS_SRC_DIR_BASE, INVOKE_OBFS_DST_DIR_BASE, dirs_exist_ok=True
    )

    file_util.remove_file("data/sessions.csv")
    file_util.remove_file("data/credentials.csv")
    file_util.remove_file("data/master.log")


def shutdown_handler(signum, frame):
    """
    This is used to gracefully shutdown Empire if uvicorn is not running yet.
    Otherwise, the "shutdown" event in app.py will be used.
    """
    log.info("Shutting down Empire Server...")

    if main:
        log.info("Shutting down MainMenu...")
        main.shutdown()

    sys.exit(0)


signal.signal(signal.SIGINT, shutdown_handler)


def check_submodules():
    log.info("Checking submodules...")
    if not os.path.exists(Path(".git")):
        log.info("No .git directory found. Skipping submodule check.")
        return

    result = subprocess.run(
        ["git", "submodule", "status"], stdout=subprocess.PIPE, text=True, check=False
    )
    for line in result.stdout.splitlines():
        if line[0] == "-":
            log.error(
                "Some git submodules are not initialized. Please run 'git submodule update --init --recursive'"
            )
            sys.exit(1)


def fetch_submodules():
    command = ["git", "submodule", "update", "--init", "--recursive"]
    run_command(command)


def check_recommended_configuration():
    log.info(f"Using {empire_config.database.use} database.")
    if empire_config.database.use == "sqlite":
        log.warning(
            "Using SQLite may result in performance issues and some functions may be disabled."
        )
        log.warning("Consider using MySQL instead.")


def run(args):
    setup_logging(args)

    if empire_config.submodules.auto_update:
        log.info("Submodules auto update enabled. Loading.")
        fetch_submodules()
    else:
        log.info("Submodules auto update disabled. Not fetching.")

    check_submodules()
    check_recommended_configuration()

    if not args.restport:
        args.restport = empire_config.api.port
    else:
        args.restport = int(args.restport[0])

    if not args.restip:
        args.restip = "0.0.0.0"
    else:
        args.restip = args.restip[0]

    if args.version:
        # log to stdout instead of stderr
        print(empire.VERSION)
        sys.exit()

    elif args.reset:
        choice = input(
            "\x1b[1;33m[>] Would you like to reset your Empire Server instance? [y/N]: \x1b[0m"
        )
        if choice.lower() == "y":
            reset()

        sys.exit()

    else:
        base.startup_db()
        global main  # noqa: PLW0603

        # Calling run more than once, such as in the test suite
        # Will generate more instances of MainMenu, which then
        # causes shutdown failure.
        if main is None:
            main = empire.MainMenu(args=args)

        if not (Path(empire_config.api.cert_path) / "empire-chain.pem").exists():
            log.info("Certificate not found. Generating...")
            subprocess.call(["./setup/cert.sh", empire_config.api.cert_path])
            time.sleep(3)

        from empire.server.api import app

        app.initialize(secure=args.secure_api, ip=args.restip, port=args.restport)

    sys.exit()
