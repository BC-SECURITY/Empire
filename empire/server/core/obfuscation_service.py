import logging
import re
import subprocess
import tempfile
import typing

import python_obfuscator
from python_obfuscator.techniques import one_liner, variable_renamer
from sqlalchemy import select
from sqlalchemy.orm import Session

from empire.server.core.config.config_manager import empire_config
from empire.server.core.db import models
from empire.server.core.db.base import SessionLocal
from empire.server.utils import data_util

if typing.TYPE_CHECKING:
    from empire.server.common.empire import MainMenu

log = logging.getLogger(__name__)

# Invoke-Obfuscation splits -Command on "," and every token on an obfuscation
# path in data/Invoke-Obfuscation/Invoke-Obfuscation.ps1 is alphanumeric plus
# "+" (STDIN++, VAR+, ...); the interactive-only menu words that are not
# (show options, clear-host, quit) are never part of a -Command sequence.
# _convert_obfuscation_command has already removed all whitespace and rewritten
# "\\" as ",", so this alphabet is lossless for every real command and leaves no
# character that is live inside the PowerShell double-quoted string the value is
# interpolated into.
_OBFUSCATION_COMMAND_RE = re.compile(r"[A-Za-z0-9+,]+")


class ObfuscationService:
    def __init__(self, main_menu: "MainMenu"):
        self.main_menu = main_menu

    @staticmethod
    def get_all_keywords(db: Session):
        return db.scalars(select(models.Keyword)).all()

    @staticmethod
    def get_keyword_by_id(db: Session, uid: int):
        return db.scalars(
            select(models.Keyword).where(models.Keyword.id == uid)
        ).first()

    @staticmethod
    def get_by_keyword(db: Session, keyword: str):
        return db.scalars(
            select(models.Keyword).where(models.Keyword.keyword == keyword)
        ).first()

    @staticmethod
    def delete_keyword(db: Session, keyword: models.Keyword):
        db.delete(keyword)

    def create_keyword(self, db: Session, keyword_req):
        if self.get_by_keyword(db, keyword_req.keyword):
            return None, f"Keyword with name {keyword_req.keyword} already exists."

        db_keyword = models.Keyword(
            keyword=keyword_req.keyword, replacement=keyword_req.replacement
        )

        db.add(db_keyword)
        db.flush()

        return db_keyword, None

    def update_keyword(self, db: Session, db_keyword: models.Keyword, keyword_req):
        if keyword_req.keyword != db_keyword.keyword:
            if not self.get_by_keyword(db, keyword_req.keyword):
                db_keyword.keyword = keyword_req.keyword
            else:
                return None, f"Keyword with name {keyword_req.keyword} already exists."

        db_keyword.replacement = keyword_req.replacement

        db.flush()

        return db_keyword, None

    def get_all_obfuscation_configs(self, db: Session):
        return db.scalars(select(models.ObfuscationConfig)).all()

    @staticmethod
    def get_obfuscation_config(db: Session, language: str):
        return db.scalars(
            select(models.ObfuscationConfig).where(
                models.ObfuscationConfig.language == language
            )
        ).first()

    @staticmethod
    def update_obfuscation_config(
        db: Session, db_obf_config: models.ObfuscationConfig, obf_config_req
    ):
        db_obf_config.module = obf_config_req.module
        db_obf_config.command = obf_config_req.command
        db_obf_config.enabled = obf_config_req.enabled

        return db_obf_config, None

    def obfuscate(self, ps_script, obfuscation_command, timeout=None):
        """
        Obfuscate PowerShell scripts using Invoke-Obfuscation.

        :param timeout: Maximum seconds for the obfuscation subprocess.
            Defaults to empire_config.obfuscation.timeout (300s out of the box).
            Set to 0 to disable the timeout entirely.
            On timeout, returns the script with only keyword obfuscation applied.
        """
        if timeout is None:
            timeout = empire_config.obfuscation.timeout
        if timeout == 0:
            timeout = None
        if not data_util.is_powershell_installed():
            log.error(
                "PowerShell is not installed and is required to use obfuscation, please install it first."
            )
            return ps_script

        # run keyword obfuscation before obfuscation
        ps_script = self.obfuscate_keywords(ps_script)

        converted_command = self._convert_obfuscation_command(obfuscation_command)
        if not _OBFUSCATION_COMMAND_RE.fullmatch(converted_command):
            log.error(
                "Obfuscation command %r is not a valid Invoke-Obfuscation command "
                "sequence; skipping obfuscation.",
                obfuscation_command,
            )
            return ps_script

        # When obfuscating large scripts, command line length is too long. Need to save to temp file
        with (
            tempfile.NamedTemporaryFile("r+") as toObfuscateFile,
            tempfile.NamedTemporaryFile("r+") as obfuscatedFile,
        ):
            toObfuscateFile.write(ps_script)

            # Obfuscate using Invoke-Obfuscation w/ PowerShell
            install_path = self.main_menu.install_path
            toObfuscateFile.seek(0)
            # Paths are single-quoted (literal in PowerShell) so an install path
            # or TMPDIR containing a space does not split into two arguments and
            # turn obfuscation into yet another silent no-op.
            ps_command = (
                '$ErrorActionPreference = "SilentlyContinue";'
                f"Import-Module '{install_path}/data/Invoke-Obfuscation/Invoke-Obfuscation.psd1';"
                f"Invoke-Obfuscation -ScriptPath '{toObfuscateFile.name}' "
                f'-Command "{converted_command}" -Quiet '
                f"| Out-File -Encoding ASCII '{obfuscatedFile.name}'"
            )
            result = self._run_invoke_obfuscation(ps_command, timeout)
            if result is None:
                return ps_script

            if result.returncode != 0:
                log.error(
                    "Obfuscation subprocess failed (exit code %d): %s",
                    result.returncode,
                    result.stderr.decode(errors="replace")[:500]
                    if result.stderr
                    else "",
                )
                return ps_script

            # Obfuscation writes a newline character to the end of the file, ignoring that character
            obfuscatedFile.seek(0)
            obfuscated = obfuscatedFile.read()[0:-1]
            if not obfuscated.strip():
                log.error(
                    "Obfuscation produced empty output for command: %s",
                    obfuscation_command,
                )
                return ps_script

            return obfuscated

    def _run_invoke_obfuscation(self, ps_command, timeout):
        """Run Invoke-Obfuscation, returning None on a soft failure.

        Both failures here are environmental rather than caller errors, so they
        degrade to an unobfuscated script rather than propagating.
        """
        try:
            return subprocess.run(
                [data_util.get_powershell_name(), "-C", ps_command],
                timeout=timeout,
                check=False,
                start_new_session=True,
                capture_output=True,
            )
        except subprocess.TimeoutExpired:
            log.exception(
                "Obfuscation subprocess timed out after %ds. "
                "Consider pre-obfuscating modules or increasing the timeout.",
                timeout,
            )
        except OSError:
            # Without a shell to absorb it, an unlaunchable PowerShell binary
            # raises here instead of exiting 127 the way the old shell=True call
            # did, so a broken toolchain would 500 every task that obfuscates.
            log.exception(
                "Could not launch PowerShell for obfuscation; "
                "returning the unobfuscated script."
            )
        return None

    def obfuscate_keywords(self, data):
        if data:
            with SessionLocal.begin() as db:
                keywords = db.scalars(select(models.Keyword)).all()

                for keyword in keywords:
                    data = data.replace(keyword.keyword, keyword.replacement)

        return data

    def _convert_obfuscation_command(self, obfuscate_command):
        return (
            "".join(obfuscate_command.split()).replace(",", ",home,").replace("\\", ",")
        )

    def python_obfuscate(self, module_source):
        """
        Obfuscate Python scripts using python-obfuscator
        """
        obfuscator = python_obfuscator.obfuscator()
        obf_script = obfuscator.obfuscate(module_source, [one_liner, variable_renamer])

        return self.obfuscate_keywords(obf_script)
