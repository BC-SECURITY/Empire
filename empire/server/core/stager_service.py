import copy
import typing
import uuid
from pathlib import Path
from typing import Any

from sqlalchemy.orm import Session

from empire.server.core.config.config_manager import empire_config
from empire.server.core.db import models
from empire.server.utils.option_util import set_options, validate_options

if typing.TYPE_CHECKING:
    from empire.server.common.empire import MainMenu
    from empire.server.core.download_service import DownloadService
    from empire.server.core.listener_service import ListenerService
    from empire.server.core.stager_template_service import StagerTemplateService


class StagerService:
    def __init__(self, main_menu: "MainMenu"):
        self.main_menu = main_menu

        self.stager_template_service: StagerTemplateService = (
            main_menu.stagertemplatesv2
        )
        self.listener_service: ListenerService = main_menu.listenersv2
        self.download_service: DownloadService = main_menu.downloadsv2

    @staticmethod
    def get_all(db: Session):
        return db.query(models.Stager).all()

    @staticmethod
    def get_by_id(db: Session, uid: int):
        return db.query(models.Stager).filter(models.Stager.id == uid).first()

    @staticmethod
    def get_by_name(db: Session, name: str):
        return db.query(models.Stager).filter(models.Stager.name == name).first()

    def validate_stager_options(
        self, db: Session, template: str, params: dict
    ) -> tuple[Any | None, str | None]:
        """
        Validates the new listener's options. Constructs a new "Listener" object.
        :param template:
        :param params:
        :return: (Stager, error)
        """
        if not self.stager_template_service.get_stager_template(template):
            return None, f"Stager Template {template} not found"

        if params.get("Listener") and not self.listener_service.get_by_name(
            db, params["Listener"]
        ):
            return None, f"Listener {params['Listener']} not found"

        template_instance = self.stager_template_service.new_instance(template)
        cleaned_options, err = validate_options(
            template_instance.options, params, db, self.download_service
        )

        if err:
            return None, err

        revert_options = {}
        for key, value in template_instance.options.items():
            revert_options[key] = template_instance.options[key]["Value"]
            template_instance.options[key]["Value"] = value

        set_options(template_instance, cleaned_options)

        # stager instances don't have a validate method. but they could

        return template_instance, None

    def create_stager(self, db: Session, stager_req, save: bool, user_id: int):
        if save and self.get_by_name(db, stager_req.name):
            return None, f"Stager with name {stager_req.name} already exists."

        template_instance, err = self.validate_stager_options(
            db, stager_req.template, stager_req.options
        )

        if err:
            return None, err

        generated, err = self.generate_stager(template_instance)

        if err:
            return None, err

        stager_options = copy.deepcopy(template_instance.options)
        stager_options = {x[0]: x[1]["Value"] for x in stager_options.items()}

        db_stager = models.Stager(
            name=stager_req.name,
            module=stager_req.template,
            options=stager_options,
            one_liner=not stager_options.get("OutFile", ""),
            user_id=user_id,
        )

        download = models.Download(
            location=str(generated),
            filename=generated.name,
            size=generated.stat().st_size,
        )
        db.add(download)
        db.flush()
        db_stager.downloads.append(download)

        if save:
            db.add(db_stager)
            db.flush()
        else:
            db_stager.id = 0

        return db_stager, None

    def update_stager(self, db: Session, db_stager: models.Stager, stager_req):
        if stager_req.name != db_stager.name:
            if not self.get_by_name(db, stager_req.name):
                db_stager.name = stager_req.name
            else:
                return None, f"Stager with name {stager_req.name} already exists."

        template_instance, err = self.validate_stager_options(
            db, db_stager.module, stager_req.options
        )

        if err:
            return None, err

        generated, err = self.generate_stager(template_instance)

        if err:
            return None, err

        stager_options = copy.deepcopy(template_instance.options)
        stager_options = {x[0]: x[1]["Value"] for x in stager_options.items()}
        db_stager.options = stager_options

        download = models.Download(
            location=str(generated),
            filename=generated.name,
            size=generated.stat().st_size,
        )
        db.add(download)
        db.flush()
        db_stager.downloads.append(download)

        return db_stager, None

    def generate_stager(self, template_instance):
        resp = template_instance.generate()

        # todo generate should return error response much like listener validate
        #  options should.
        if not resp:
            return None, "Error generating"

        out_file = template_instance.options.get("OutFile", {}).get("Value")
        file_name = Path(out_file).name if out_file else f"{uuid.uuid4()}.txt"

        file_name = (
            empire_config.directories.downloads / "generated-stagers" / file_name
        )
        file_name.parent.mkdir(parents=True, exist_ok=True)
        mode = "w" if isinstance(resp, str) else "wb"
        with file_name.open(mode) as f:
            f.write(resp)

        return file_name, None

    @staticmethod
    def delete_stager(db: Session, stager: models.Stager):
        db.delete(stager)
