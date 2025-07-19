import copy
import hashlib
import logging
import re
import typing
from typing import Any

from sqlalchemy.orm import Session

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
        return db.query(models.Listener).all()

    @staticmethod
    def get_by_id(db: Session, uid: int) -> models.Listener | None:
        return db.query(models.Listener).filter(models.Listener.id == uid).first()

    @staticmethod
    def get_by_name(db: Session, name: str) -> models.Listener | None:
        return db.query(models.Listener).filter(models.Listener.name == name).first()

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

    def create_listener(self, db: Session, listener_req):
        if self.get_by_name(db, listener_req.name):
            return None, f"Listener with name {listener_req.name} already exists."

        listener_req.options["Name"] = listener_req.name

        template_instance, err = self._validate_listener_options(
            db, listener_req.template, listener_req.options
        )

        if err:
            return None, err

        db_listener, err = self._start_listener(
            db, template_instance, listener_req.template
        )

        if err:
            return None, err

        hooks.run_hooks(hooks.AFTER_LISTENER_CREATED_HOOK, db, db_listener)

        return db_listener, None

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

    def start_existing_listener(self, db: Session, listener: models.Listener):
        listener.enabled = True

        options = {x[0]: x[1]["Value"] for x in listener.options.items()}
        template_instance, err = self._validate_listener_options(
            db, listener.module, options
        )

        if err:
            log.error(err)
            return None, err

        success = template_instance.start()
        db.flush()

        if success:
            self._active_listeners[listener.id] = template_instance
            log.info(f'Listener "{listener.name}" successfully started')
            return listener, None
        return None, f'Listener "{listener.name}" failed to start'

    def start_existing_listeners(self):
        with SessionLocal.begin() as db:
            listeners = (
                db.query(models.Listener)
                .filter(models.Listener.enabled == True)  # noqa: E712
                .all()
            )
            for listener in listeners:
                self.start_existing_listener(db, listener)

    def _start_listener(self, db: Session, template_instance, template_name):
        category = template_instance.info["Category"]
        name = template_instance.options["Name"]["Value"]
        try:
            log.info(f"v2: Starting listener '{name}'")
            success = template_instance.start()

            if not success:
                msg = f"Failed to start listener '{name}'"
                log.error(msg)
                return None, msg

            listener_options = copy.deepcopy(template_instance.options)

            # in a breaking change we could just store a str,str dict for the options.
            # we don't add the listener to the db unless it successfully starts. Makes it a problem when trying
            # to split this out.
            db_listener = models.Listener(
                name=name,
                module=template_name,
                listener_category=category,
                enabled=True,
                options=listener_options,
            )

            db.add(db_listener)
            db.flush()

            log.info(f'Listener "{name}" successfully started')
            self._active_listeners[db_listener.id] = template_instance

            return db_listener, None

        except Exception as e:
            msg = f"Failed to start listener '{name}': {e}"
            log.error(msg)
            return None, msg

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
    def _normalize_listener_options(instance) -> None:  # noqa: PLR0912
        """
        This is adapted from the old set_listener_option which does some coercions on the http fields.
        """
        for option_name, option_meta in instance.options.items():
            value = option_meta["Value"]
            # parse and auto-set some host parameters
            if option_name == "Host":
                host_rexp = r"^(https?)?:?/?/?([^:]+):?(\d+)?$"
                matches = re.match(host_rexp, value)
                try:
                    protocol, host, port = matches.groups()
                except AttributeError:
                    log.error(f"Unable to parse Host value: {value}")
                    protocol = None
                    host = value
                    port = None
                if not protocol:
                    if (
                        "CertPath" in instance.options
                        and instance.options["CertPath"]["Value"] != ""
                    ):
                        protocol = "https"
                    else:
                        protocol = "http"
                default_port = 443 if protocol == "https" else 80
                try:
                    int(instance.options["Port"]["Value"])
                except ValueError:
                    if port:
                        instance.options["Port"]["Value"] = port
                    else:
                        instance.options["Port"]["Value"] = default_port
                if port:
                    instance.options["Host"]["Value"] = f"{protocol}://{host}:{port}"
                else:
                    instance.options["Host"]["Value"] = f"{protocol}://{host}"

            elif option_name == "CertPath" and value != "":
                instance.options[option_name]["Value"] = value
                host = instance.options["Host"]["Value"]
                # if we're setting a SSL cert path, but the host is specific at http
                if host.startswith("http:"):
                    instance.options["Host"]["Value"] = instance.options["Host"][
                        "Value"
                    ].replace("http:", "https:")

            elif option_name == "Port":
                instance.options[option_name]["Value"] = value
                # Check if Port is set and add it to host
                try:
                    protocol, host, port = instance.options["Host"]["Value"].split(":")
                except ValueError:
                    instance.options["Host"]["Value"] = "{}:{}".format(
                        instance.options["Host"]["Value"],
                        instance.options["Port"]["Value"],
                    )

            elif option_name == "StagingKey":
                # if the staging key isn't 32 characters, assume we're md5 hashing it
                value = str(value).strip()
                if len(value) != 32:  # noqa: PLR2004
                    staging_key_hash = hashlib.md5(value.encode("UTF-8")).hexdigest()
                    log.warning(
                        f"Warning: staging key not 32 characters, using hash of staging key instead: {staging_key_hash}"
                    )
                    instance.options[option_name]["Value"] = staging_key_hash
                else:
                    instance.options[option_name]["Value"] = str(value)
