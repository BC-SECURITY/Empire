import logging
import typing
from typing import Any

from empire.server.core.db import models
from empire.server.core.db.models import PluginInfo
from empire.server.core.exceptions import PluginValidationException
from empire.server.utils.option_util import validate_options

log = logging.getLogger(__name__)

if typing.TYPE_CHECKING:
    from empire.server.core.db.base import SessionLocal
    from empire.server.core.download_service import DownloadService
    from empire.server.core.plugin_service import PluginService


class BasePlugin:
    def __init__(self, main_menu, plugin_info: PluginInfo, db: "SessionLocal"):
        self.main_menu = main_menu
        self.plugin_service: PluginService = self.main_menu.pluginsv2
        self.download_service: DownloadService = self.main_menu.downloadsv2
        self.info: PluginInfo = plugin_info

        log.info(f"Initializing plugin: {self.info.name}")

        self.enabled: bool = False
        self.execution_enabled: bool = True
        self.install_path: str = self.main_menu.installPath
        self.execution_options: dict = {}
        self.settings_options: dict = {}

        self.on_load(db)
        self._set_options_defaults()

    def _set_options_defaults(self):
        for value in self.execution_options.values():
            if value.get("SuggestedValues") is None:
                value["SuggestedValues"] = []
            if value.get("Strict") is None:
                value["Strict"] = False
            if value.get("Internal") is None:
                value["Internal"] = False
            if value.get("Depends_on") is None:
                value["Depends_on"] = []

        for value in self.settings_options.values():
            if value.get("SuggestedValues") is None:
                value["SuggestedValues"] = []
            if value.get("Strict") is None:
                value["Strict"] = False
            if value.get("Internal") is None:
                value["Internal"] = False
            if value.get("Depends_on") is None:
                value["Depends_on"] = []

    def set_initial_options(self, db):
        """
        Set the initial uneditable options for the plugin, based on
        the state_options. This is only used to initialize the fields in
        the database. Future updates should be done through the state functions
        or plugin_service.
        """
        settings = {}
        for key, value in self.settings_options.items():
            settings[key] = value["Value"]

        self.set_settings(db, settings, validate=False)

    def on_load(self, db):
        """Things to do during init: meant to be overridden by
        the inheriting plugin."""
        pass

    def on_unload(self, db):
        """Things to do when the plugin is unloaded: meant to be overridden by
        the inheriting plugin."""
        pass

    def on_start(self, db):
        """Things to do when the plugin is started: meant to be overridden by
        the inheriting plugin."""
        pass

    def on_stop(self, db):
        """Things to do when the plugin is stopped: meant to be overridden by
        the inheriting plugin."""
        pass

    def execute(self, command, **kwargs):
        """Execute a command: meant to be overridden by the inheriting plugin."""
        if "plugin_options" not in kwargs:
            kwargs["plugin_options"] = command
        pass

    def get_db_plugin(self, db) -> models.Plugin | None:
        return db.query(models.Plugin).filter(models.Plugin.id == self.info.id).first()

    def current_settings(self, db) -> dict[str, Any]:
        return self.get_db_plugin(db).settings

    def current_internal_state(self, db) -> dict[str, Any]:
        return self.get_db_plugin(db).internal_state

    def set_settings(self, db, settings: dict[str, Any], validate=True):
        if validate:
            cleaned_options, err = validate_options(
                self.settings_options, settings, db, self.download_service
            )

            if err:
                raise PluginValidationException(err)
        else:
            cleaned_options = settings

        # Add the uneditable settings back to the dict.
        current_settings = self.current_settings(db) or {}
        cleaned_options = {**current_settings, **cleaned_options}
        self.get_db_plugin(db).settings = cleaned_options
        db.flush()
        self.on_settings_change(db, settings)

        return cleaned_options

    def on_settings_change(self, db, settings: dict[str, Any]):
        """Things to do when the settings change: meant to be overridden by
        the inheriting plugin."""
        pass

    def set_internal_state(self, db, state: dict[str, Any]):
        db_plugin = self.get_db_plugin(db)
        db_plugin.internal_state = state
        db.flush()

    def set_settings_option(self, db, key, value):
        settings = self.current_settings(db)
        settings[key] = value
        self.set_settings(db, settings)

    def set_internal_state_option(self, db, key, value):
        state = self.current_internal_state(db)
        state[key] = value
        self.set_internal_state(db, state)

    def send_socketio_message(self, message):
        """Send a message to the socketio server"""
        self.plugin_service.plugin_socketio_message(self.info.name, message)
