#!/usr/bin/env python3
import logging
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path

import urllib3

from empire.server.common import empire
from empire.server.core.config import config_manager
from empire.server.core.config.config_manager import CONFIG_DIR, DATA_DIR, empire_config
from empire.server.core.db import base
from empire.server.utils.file_util import run_as_user
from empire.server.utils.log_util import setup_logging

log = logging.getLogger(__name__)
main = None


# Disable http warnings
if empire_config.supress_self_cert_warning:
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def reset():
    base.reset_db()
    shutil.rmtree(CONFIG_DIR, ignore_errors=True)
    shutil.rmtree(DATA_DIR, ignore_errors=True)


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
    if not Path(".git").exists():
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
    if not Path(".git").exists():
        log.info("No .git directory found. Skipping submodule fetch.")
        return
    command = ["git", "submodule", "update", "--init", "--recursive"]
    run_as_user(command)


def check_recommended_configuration():
    log.info(f"Using {empire_config.database.use} database.")
    if empire_config.database.use == "sqlite":
        log.warning(
            "Using SQLite may result in performance issues and some functions may be disabled."
        )
        log.warning("Consider using MySQL instead.")


def run(args):
    if args.version:
        print(empire.VERSION)
        sys.exit()

    setup_logging(args)

    if empire_config.submodules.auto_update:
        log.info("Submodules auto update enabled. Loading.")
        fetch_submodules()
    else:
        log.info("Submodules auto update disabled. Not fetching.")

    check_submodules()
    check_recommended_configuration()

    if args.reset:
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

        cert_path = config_manager.DATA_DIR / "cert"
        cert_path.mkdir(parents=True, exist_ok=True)
        if not (Path(cert_path) / "empire-chain.pem").exists():
            log.info("Certificate not found. Generating...")
            subprocess.call(["./setup/cert.sh", str(cert_path)])
            time.sleep(3)

        from empire.server.api import app

        app.initialize(cert_path=cert_path)

    sys.exit()


def main():
    """Backward-compatible entry point.

    Left in place for environments still pointing to
    `empire.server.server:main`. It builds a minimal parser for the
    server-only CLI to avoid importing global-parse side effects.
    """
    import argparse

    parser = argparse.ArgumentParser(description="Launch Empire Server")
    general_group = parser.add_argument_group("General Options")
    general_group.add_argument(
        "-l",
        "--log-level",
        dest="log_level",
        type=str.upper,
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        help="Set the logging level",
    )
    general_group.add_argument(
        "-d",
        "--debug",
        help="Set the logging level to DEBUG",
        action="store_const",
        dest="log_level",
        const="DEBUG",
        default=None,
    )
    general_group.add_argument(
        "--reset",
        action="store_true",
        help=(
            "Resets Empire's database and deletes any app data accumulated over previous runs."
        ),
    )
    general_group.add_argument(
        "-v",
        "--version",
        action="store_true",
        help="Display current Empire version.",
    )
    general_group.add_argument(
        "--config",
        type=str,
        nargs=1,
        help=(
            "Specify a config.yaml different from the config.yaml in the empire/server directory."
        ),
    )

    args = parser.parse_args()
    run(args)
