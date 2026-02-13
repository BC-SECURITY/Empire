import copy
import hashlib
import logging
import re
import typing
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from empire.server.core import protocol_constants as proto
from empire.server.core.db import models
from empire.server.core.db.base import SessionLocal
from empire.server.core.hooks import hooks
from empire.server.utils.option_util import set_options, validate_options

log = logging.getLogger(__name__)

if typing.TYPE_CHECKING:
    from empire.server.common.empire import MainMenu
    from empire.server.core.download_service import DownloadService
    from empire.server.core.listener_template_service import ListenerTemplateService


class ListenerService:
    def __init__(self, main_menu: "MainMenu"):
        self.main_menu = main_menu

        self.listener_template_service: ListenerTemplateService = (
            main_menu.listenertemplatesv2
        )
        self.download_service: DownloadService = main_menu.downloadsv2

        # All running listeners. This is the object instances, NOT the database models.
        # When updating options for a listener, we'll go to the db as the source of truth.
        # We can construct a new instance to validate the options, then save those options back to the db.
        # In essence, turning a listener off and on always constructs a new object.
        self._active_listeners = {}

    @staticmethod
    def get_all(db: Session) -> list[models.Listener]:
        return db.scalars(select(models.Listener)).all()

    @staticmethod
    def get_by_id(db: Session, uid: int) -> models.Listener | None:
        return db.scalars(
            select(models.Listener).where(models.Listener.id == uid)
        ).first()

    @staticmethod
    def get_by_name(db: Session, name: str) -> models.Listener | None:
        return db.scalars(
            select(models.Listener).where(models.Listener.name == name)
        ).first()

    def get_active_listeners(self):
        return self._active_listeners

    def get_active_listener(self, id: int):
        """
        Get an active listener by id.
        Note that this is the object instance, NOT the db model.
        :param id: listener id
        :return: listener object
        """
        return self._active_listeners[id]

    def get_active_listener_by_name(self, name: str):
        """
        Get an active listener by name.
        Note that this is the object instance, NOT the database model.
        :param name: listener name
        :return: listener object
        """
        for listener in self._active_listeners.values():
            if listener.options["Name"]["Value"] == name:
                return listener
        return None

    def update_listener(self, db: Session, db_listener: models.Listener, listener_req):
        if listener_req.name != db_listener.name:
            if not self.get_by_name(db, listener_req.name):
                db_listener.name = listener_req.name
            else:
                return None, f"Listener with name {listener_req.name} already exists."

        listener_req.options["Name"] = listener_req.name
        db_listener.name = listener_req.name
        db_listener.enabled = listener_req.enabled
        template_instance, err = self._validate_listener_options(
            db, db_listener.module, listener_req.options
        )

        if err:
            return None, err

        db_listener.options = copy.deepcopy(template_instance.options)

        return db_listener, None

    def _finalize_created_listener(self, db, template_instance, db_listener):
        """Post-start hook for newly created listeners."""
        template_instance.host_address = db_listener.host_address
        hooks.run_hooks(hooks.AFTER_LISTENER_CREATED_HOOK, db, db_listener)
        return db_listener, None

    def _persist_new_listener(self, db, template_instance, template_name, success):
        """Create Listener DB record after a successful start."""
        name = template_instance.options["Name"]["Value"]
        if not success:
            msg = f"Failed to start listener '{name}'"
            log.error(msg)
            return None, msg

        category = template_instance.info["Category"]
        listener_options = copy.deepcopy(template_instance.options)

        host_address, err = self.validate_listener_address(listener_options)
        if err:
            log.error(err)
            return None, err

        db_listener = models.Listener(
            name=name,
            module=template_name,
            listener_category=category,
            enabled=True,
            options=listener_options,
            host_address=host_address,
        )

        db.add(db_listener)
        db.flush()

        log.info(f'Listener "{name}" successfully started')
        self._active_listeners[db_listener.id] = template_instance

        return db_listener, None

    def _finalize_existing_listener(self, db, listener, template_instance, success):
        """Finalize an existing listener after start attempt."""
        db.flush()
        if success:
            self._active_listeners[listener.id] = template_instance
            log.info(f'Listener "{listener.name}" successfully started')
            return listener, None
        return None, f'Listener "{listener.name}" failed to start'

    def _validate_create(self, db, listener_req):
        """Shared validation preamble for create_listener."""
        if self.get_by_name(db, listener_req.name):
            return None, f"Listener with name {listener_req.name} already exists."

        listener_req.options["Name"] = listener_req.name
        return self._validate_listener_options(
            db, listener_req.template, listener_req.options
        )

    def _finish_create(self, db, template_instance, template_name, success):
        """Persist + finalize after a successful (or failed) listener start."""
        db_listener, err = self._persist_new_listener(
            db, template_instance, template_name, success
        )
        if err:
            return None, err
        return self._finalize_created_listener(db, template_instance, db_listener)

    def create_listener(self, db: Session, listener_req):
        template_instance, err = self._validate_create(db, listener_req)
        if err:
            return None, err

        name = template_instance.options["Name"]["Value"]
        try:
            log.info(f"v2: Starting listener '{name}'")
            success = template_instance.start()
        except Exception as e:
            msg = f"Failed to start listener '{name}': {e}"
            log.exception(msg)
            return None, msg

        return self._finish_create(
            db, template_instance, listener_req.template, success
        )

    def stop_listener(self, db_listener: models.Listener):
        if self._active_listeners.get(db_listener.id):
            self._active_listeners[db_listener.id].shutdown()
            del self._active_listeners[db_listener.id]

    def delete_listener(self, db: Session, db_listener: models.Listener):
        self.stop_listener(db_listener)
        db.delete(db_listener)

    def shutdown_listeners(self):
        for listener in self._active_listeners.values():
            listener.shutdown()

    def _validate_existing(self, db, listener):
        """Shared validation for start_existing_listener."""
        listener.enabled = True
        options = {key: meta["Value"] for key, meta in listener.options.items()}
        template_instance, err = self._validate_listener_options(
            db, listener.module, options
        )
        if err:
            log.error(err)
        return template_instance, err

    def start_existing_listener(self, db: Session, listener: models.Listener):
        template_instance, err = self._validate_existing(db, listener)
        if err:
            return None, err

        success = template_instance.start()
        return self._finalize_existing_listener(
            db, listener, template_instance, success
        )

    def start_existing_listeners(self):
        with SessionLocal.begin() as db:
            listeners = db.scalars(
                select(models.Listener).where(models.Listener.enabled.is_(True))
            ).all()
            for listener in listeners:
                self.start_existing_listener(db, listener)

    @staticmethod
    def validate_listener_address(listener_options):
        """
        Take host and port and generate a host address string
        """
        host_rexp = r"^(https?)?:?/?/?([^:]+):?(\d+)?$"
        matches = re.match(host_rexp, listener_options["Host"]["Value"])

        try:
            protocol, host, port = matches.groups()
            if not protocol:
                if (
                    "CertPath" in listener_options
                    and listener_options["CertPath"]["Value"] != ""
                ):
                    protocol = "https"
                else:
                    protocol = "http"
            if not port:
                port = listener_options["Port"]["Value"]

            if (port == "443" and protocol == "https") or (
                port == "80" and protocol == "http"
            ):
                host_address = f"{protocol}://{host}/"
            else:
                host_address = f"{protocol}://{host}:{port}/"
        except AttributeError:
            return None, "Hostname error in parsing"

        return host_address, None

    def _validate_listener_options(
        self, db: Session, template: str, params: dict
    ) -> tuple[Any | None, str | None]:
        """
        Validates the new listener's options. Constructs a new "Listener" object.
        :param template:
        :param params:
        :return: (Listener, error)
        """
        if not self.listener_template_service.get_listener_template(template):
            return None, f"Listener Template {template} not found"

        template_instance = self.listener_template_service.new_instance(template)
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

        # todo We should update the validate_options method to also return a string error
        self._normalize_listener_options(template_instance)
        validated, err = template_instance.validate_options()
        if not validated:
            for key, value in revert_options.items():
                template_instance.options[key]["Value"] = value

            return None, err

        return template_instance, None

    @staticmethod
    def _normalize_listener_options(instance) -> None:
        """
        This is adapted from the old set_listener_option which does some coercions on the http fields.
        """
        for option_name, option_meta in instance.options.items():
            value = option_meta["Value"]
            if option_name == "StagingKey":
                # if the staging key isn't 32 characters, assume we're md5 hashing it
                value = str(value).strip()
                if len(value) != proto.STAGING_KEY_LENGTH:
                    # md5 is required here: its 32-char hex digest derives the
                    # protocol-required 32-char staging key from a shorter
                    # passphrase. Not an integrity check.
                    staging_key_hash = hashlib.md5(  # noqa: S324
                        value.encode("UTF-8")
                    ).hexdigest()
                    log.warning(
                        f"Warning: staging key not 32 characters, using hash of staging key instead: {staging_key_hash}"
                    )
                    instance.options[option_name]["Value"] = staging_key_hash
                else:
                    instance.options[option_name]["Value"] = str(value)
