import fnmatch
import logging
import typing
from pathlib import Path

import yaml
from sqlalchemy.orm import Session

from empire.server.core.config.config_manager import empire_config
from empire.server.core.db import models
from empire.server.core.db.base import SessionLocal
from empire.server.utils.data_util import ps_convert_to_oneliner

if typing.TYPE_CHECKING:
    from empire.server.common.empire import MainMenu

log = logging.getLogger(__name__)


class BypassService:
    def __init__(self, main_menu: "MainMenu"):
        self.main_menu = main_menu

        with SessionLocal.begin() as db:
            self.load_bypasses(db)

    def load_bypasses(self, db: Session):
        root_path = Path(self.main_menu.installPath) / "bypasses"
        log.info(f"v2: Loading bypasses from: {root_path}")

        # Get the list of default bypass names from config
        default_bypass_names = empire_config.database.defaults.bypasses

        for file_path in root_path.rglob("*.yaml"):
            filename = file_path.name

            # don't load up any of the templates
            if fnmatch.fnmatch(filename, "*template.yaml"):
                continue

            try:
                yaml2 = yaml.safe_load(file_path.read_text())
                yaml_bypass = {k: v for k, v in yaml2.items() if v is not None}

                # Check if this bypass is marked as default in the config
                is_default = yaml_bypass["name"] in default_bypass_names

                if (
                    db.query(models.Bypass)
                    .filter(models.Bypass.name == yaml_bypass["name"])
                    .first()
                    is None
                ):
                    yaml_bypass["script"] = ps_convert_to_oneliner(
                        yaml_bypass["script"]
                    )
                    my_model = models.Bypass(
                        name=yaml_bypass["name"],
                        authors=yaml_bypass["authors"],
                        code=yaml_bypass["script"],
                        language=yaml_bypass["language"],
                        is_default=is_default,
                    )
                    db.add(my_model)
                else:
                    # Update existing bypass's is_default flag
                    existing = (
                        db.query(models.Bypass)
                        .filter(models.Bypass.name == yaml_bypass["name"])
                        .first()
                    )
                    existing.is_default = is_default
                db.flush()
            except Exception as e:
                log.error(e)

    @staticmethod
    def get_all(db: Session, default: bool | None = None):
        query = db.query(models.Bypass)
        if default:
            query = query.filter(models.Bypass.is_default)

        return query.all()

    @staticmethod
    def get_by_id(db: Session, uid: int):
        return db.query(models.Bypass).filter(models.Bypass.id == uid).first()

    @staticmethod
    def get_by_name(db: Session, name: str):
        return db.query(models.Bypass).filter(models.Bypass.name == name).first()

    @staticmethod
    def delete_bypass(db: Session, bypass: models.Bypass):
        db.delete(bypass)

    def create_bypass(self, db: Session, bypass_req):
        if self.get_by_name(db, bypass_req.name):
            return None, f"Bypass with name {bypass_req.name} already exists."

        bypass = models.Bypass(
            name=bypass_req.name, code=bypass_req.code, language=bypass_req.language
        )

        db.add(bypass)
        db.flush()

        return bypass, None

    def update_bypass(self, db: Session, db_bypass: models.Bypass, bypass_req):
        if bypass_req.name != db_bypass.name:
            if not self.get_by_name(db, bypass_req.name):
                db_bypass.name = bypass_req.name
            else:
                return None, f"Bypass with name {bypass_req.name} already exists."

        db_bypass.code = bypass_req.code
        db_bypass.language = bypass_req.language

        db.flush()

        return db_bypass, None

    def delete_all_bypasses(self, db: Session):
        db.query(models.Bypass).delete()
        db.flush()
