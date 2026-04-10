import logging
import subprocess
import tempfile
import typing

import python_obfuscator
from python_obfuscator.techniques import one_liner, variable_renamer
from sqlalchemy.orm import Session

from empire.server.core.db import models
from empire.server.core.db.base import SessionLocal
from empire.server.utils import data_util

if typing.TYPE_CHECKING:
    from empire.server.common.empire import MainMenu

log = logging.getLogger(__name__)


class ObfuscationService:
    def __init__(self, main_menu: "MainMenu"):
        self.main_menu = main_menu

    @staticmethod
    def get_all_keywords(db: Session):
        return db.query(models.Keyword).all()

    @staticmethod
    def get_keyword_by_id(db: Session, uid: int):
        return db.query(models.Keyword).filter(models.Keyword.id == uid).first()

    @staticmethod
    def get_by_keyword(db: Session, keyword: str):
        return (
            db.query(models.Keyword).filter(models.Keyword.keyword == keyword).first()
        )

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
        return db.query(models.ObfuscationConfig).all()

    @staticmethod
    def get_obfuscation_config(db: Session, language: str):
        return (
            db.query(models.ObfuscationConfig)
            .filter(models.ObfuscationConfig.language == language)
            .first()
        )

    @staticmethod
    def update_obfuscation_config(
        db: Session, db_obf_config: models.ObfuscationConfig, obf_config_req
    ):
        db_obf_config.module = obf_config_req.module
        db_obf_config.command = obf_config_req.command
        db_obf_config.enabled = obf_config_req.enabled

        return db_obf_config, None

    def obfuscate(self, ps_script, obfuscation_command):
        """
        Obfuscate PowerShell scripts using Invoke-Obfuscation
        """
        if not data_util.is_powershell_installed():
            log.error(
                "PowerShell is not installed and is required to use obfuscation, please install it first."
            )
            return ""

        # run keyword obfuscation before obfuscation
        ps_script = self.obfuscate_keywords(ps_script)

        # When obfuscating large scripts, command line length is too long. Need to save to temp file
        with (
            tempfile.NamedTemporaryFile("r+") as toObfuscateFile,
            tempfile.NamedTemporaryFile("r+") as obfuscatedFile,
        ):
            toObfuscateFile.write(ps_script)

            # Obfuscate using Invoke-Obfuscation w/ PowerShell
            install_path = self.main_menu.install_path
            toObfuscateFile.seek(0)
            subprocess.call(
                f'{data_util.get_powershell_name()} -C \'$ErrorActionPreference = "SilentlyContinue";Import-Module {install_path}/data/Invoke-Obfuscation/Invoke-Obfuscation.psd1;Invoke-Obfuscation -ScriptPath {toObfuscateFile.name} -Command "{self._convert_obfuscation_command(obfuscation_command)}" -Quiet | Out-File -Encoding ASCII {obfuscatedFile.name}\'',
                shell=True,
            )

            # Obfuscation writes a newline character to the end of the file, ignoring that character
            obfuscatedFile.seek(0)
            return obfuscatedFile.read()[0:-1]

    def obfuscate_keywords(self, data):
        if data:
            with SessionLocal.begin() as db:
                keywords = db.query(models.Keyword).all()

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
