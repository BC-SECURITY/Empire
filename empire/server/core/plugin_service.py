import asyncio
import importlib
import logging
import shutil
import sys
import tarfile
import tempfile
import typing
from pathlib import Path

import requests
import yaml
from pydantic import BaseModel
from requests_file import FileAdapter
from sqlalchemy.orm import Session
from starlette.status import HTTP_200_OK

from empire.server.api.v2.plugin.plugin_dto import PluginExecutePostRequest
from empire.server.core.config import config_manager
from empire.server.core.config.config_manager import (
    PluginConfig,
    empire_config,
)
from empire.server.core.db import models
from empire.server.core.db.base import SessionLocal
from empire.server.core.db.models import PluginInfo
from empire.server.core.exceptions import (
    PluginExecutionException,
    PluginValidationException,
)
from empire.server.core.plugins import BasePlugin
from empire.server.utils import git_util
from empire.server.utils.option_util import validate_options
from empire.server.utils.string_util import slugify

if typing.TYPE_CHECKING:
    from empire.server.common.empire import MainMenu

log = logging.getLogger(__name__)

s = requests.Session()
s.mount("file://", FileAdapter())


class PluginHolder(BaseModel):
    loaded_plugin: BasePlugin | None
    db_plugin: models.Plugin | None

    class Config:
        arbitrary_types_allowed = True


class PluginService:
    def __init__(self, main_menu: "MainMenu"):
        self.main_menu = main_menu
        self.download_service = main_menu.downloadsv2
        self.loaded_plugins = {}
        self.plugin_path = self.main_menu.install_path / "plugins"
        self.marketplace_path = config_manager.DATA_DIR / "plugins" / "marketplace"
        self.marketplace_path.mkdir(parents=True, exist_ok=True)

    def startup(self):
        """
        Called after plugin_service is initialized.
        This way plugin_service is fully initialized on MainMenu before plugins are loaded.
        """
        with SessionLocal.begin() as db:
            self.load_plugins(db)
            self.auto_execute_plugins(db)

    def update_plugin_enabled(
        self, db: Session, plugin_holder: PluginHolder, enabled: bool
    ):
        db_plugin = plugin_holder.db_plugin
        plugin = plugin_holder.loaded_plugin
        if db_plugin.enabled == enabled:
            return
        if enabled:
            plugin.on_start(db)
            db_plugin.enabled = True
            plugin.enabled = True
        else:
            plugin.on_stop(db)
            db_plugin.enabled = False
            plugin.enabled = False

    def update_plugin_settings(
        self, db: Session, plugin_holder: PluginHolder, settings: dict
    ):
        """
        Will skip any options that are not editable.
        """
        return plugin_holder.loaded_plugin.set_settings(db, settings)

    def auto_execute_plugins(self, db):
        """
        Autorun plugin commands at server startup.
        """
        plugins = self.loaded_plugins
        for plugin_name, plugin in plugins.items():
            auto_execute = self._determine_auto_execute(plugin.info, empire_config)

            if auto_execute is None or auto_execute.enabled is False:
                continue

            req = PluginExecutePostRequest(options=auto_execute.options)
            results, _err = self.execute_plugin(db, plugin, req, None)
            if results is False:
                log.error(f"Plugin failed to run: {plugin_name}")
            else:
                log.info(f"Plugin {plugin_name} ran successfully!")

    def load_plugins(self, db: Session):
        """
        Load plugins at the start of Empire
        """
        log.info(f"Searching for plugins at {self.plugin_path}")

        for plugin_dir in self._list_plugin_directories():
            try:
                plugin_config = self._validate_plugin(plugin_dir)
            except PluginValidationException as e:
                log.error(f"Failed to load plugin {plugin_dir.name}: {e}")
                continue

            self.load_plugin(db, plugin_dir, plugin_config)

    def load_plugin(
        self,
        db: Session,
        plugin_dir: Path,
        plugin_config: PluginInfo,
        version: str | None = None,
    ):
        plugin_holder = self.get_by_id(db, plugin_config.id)

        if not plugin_holder:
            auto_start = self._determine_auto_start(plugin_config, empire_config)

            db_plugin = models.Plugin(
                id=plugin_config.id,
                name=plugin_config.name,
                enabled=auto_start,
                settings={},
                settings_initialized=False,
                info=plugin_config,
                installed_version=version,
            )
            db.add(db_plugin)
            db.flush()
        else:
            db_plugin = plugin_holder.db_plugin

        file_path = plugin_dir / plugin_config.main
        try:
            plugin_obj = self._create_plugin_obj(db, file_path, plugin_config)
        except Exception as e:
            db_plugin.enabled = False
            db_plugin.load_error = str(e)
            log.warning(f"Failed to load plugin {plugin_config.name}: {e}")
            return

        # If you make it this far, the plugin has loaded successfully
        db_plugin.load_error = None

        if not db_plugin.settings_initialized:
            plugin_obj.set_initial_options(db)
            db_plugin.settings_initialized = True

        self.loaded_plugins[plugin_config.id] = plugin_obj

        try:
            if db_plugin.enabled:
                plugin_obj.on_start(db)
        except Exception as e:
            log.error(
                f"Failed to start plugin {plugin_obj.info.name}: {e}", exc_info=True
            )
            plugin_obj.enabled = False
            db_plugin.enabled = False

        plugin_obj.enabled = db_plugin.enabled

    def install_plugin_from_git(  # noqa: PLR0913
        self,
        db: Session,
        git_url: str,
        subdir: str | None = None,
        ref: str | None = None,
        version_name: str | None = None,
        registry_data: dict | None = None,
    ):
        temp_dir = git_util.clone_git_repo(git_url, ref)
        temp_dir = temp_dir / subdir if subdir else temp_dir
        plugin_dir, plugin_config = self._validate_temp_plugin(db, temp_dir)
        plugin_config = self._merge_plugin_config(plugin_config, registry_data)

        self.load_plugin(db, plugin_dir, plugin_config, version_name)

    def install_plugin_from_tar(
        self,
        db: Session,
        tar_url: str,
        subdir: str | None = None,
        version_name: str | None = None,
        registry_data: dict | None = None,
    ):
        temp_dir = (
            Path(tempfile.gettempdir()) / Path(tar_url.rsplit("/", maxsplit=1)[-1]).stem
        )

        response = s.get(tar_url, stream=True)

        if response.status_code != HTTP_200_OK:
            raise PluginValidationException(
                f"Failed to download plugin: {response.text}"
            )

        with tarfile.open(fileobj=response.raw, mode="r|*") as tar:
            tar.extractall(path=temp_dir)

        temp_dir = temp_dir / subdir if subdir else temp_dir

        plugin_dir, plugin_config = self._validate_temp_plugin(db, temp_dir)
        plugin_config = self._merge_plugin_config(plugin_config, registry_data)

        self.load_plugin(db, plugin_dir, plugin_config, version_name)

    @staticmethod
    def _merge_plugin_config(plugin_config, registry_data):
        """
        If a plugin is installed from a registry, merge the plugin config with the registry data.
        Things like author info and description from the registry will take presedence.
        """
        if not registry_data:
            return plugin_config

        registry_plugin = registry_data.get("plugins", {}).get(plugin_config.name)
        if not registry_plugin:
            return plugin_config

        plugin_config.authors = registry_plugin.get("authors", plugin_config.authors)
        plugin_config.description = registry_plugin.get(
            "description", plugin_config.description
        )
        plugin_config.comments = registry_plugin.get("comments", plugin_config.comments)

        return plugin_config

    def execute_plugin(
        self,
        db: Session,
        plugin,
        plugin_req: PluginExecutePostRequest,
        user: models.User | None = None,
    ) -> tuple[bool | str | None, str | None]:
        if plugin.enabled is False:
            raise PluginValidationException("Plugin is not running")
        if not plugin.execution_enabled:
            raise PluginValidationException("Plugin execution is disabled")

        cleaned_options, err = validate_options(
            plugin.execution_options, plugin_req.options, db, self.download_service
        )

        if err:
            raise PluginValidationException(err)

        try:
            res = plugin.execute(cleaned_options, db=db, user=user)
            # Tuple is deprecated. Will be removed in 7.x
            if isinstance(res, tuple):
                return res
            return res, None
        except (PluginValidationException, PluginExecutionException) as e:
            raise e
        except Exception as e:
            log.error(f"Plugin {plugin.info.name} failed to run: {e}", exc_info=True)
            return False, str(e)

    def plugin_socketio_message(self, plugin_name, msg):
        """
        Send socketio message to the socket address.
        Note: Use BasePlugin.send_socketio_message for easier use.
        """
        log.info(f"{plugin_name}: {msg}")
        if self.main_menu.socketio:
            try:  # https://stackoverflow.com/a/61331974/
                loop = asyncio.get_running_loop()
            except RuntimeError:
                loop = None

            if loop and loop.is_running():
                loop.create_task(
                    self.main_menu.socketio.emit(
                        f"plugins/{plugin_name}/notifications",
                        {"message": msg, "plugin_name": plugin_name},
                    )
                )
            else:
                asyncio.run(
                    self.main_menu.socketio.emit(
                        f"plugins/{plugin_name}/notifications",
                        {"message": msg, "plugin_name": plugin_name},
                    )
                )

    def get_all(self, db):
        loaded_plugins = self.loaded_plugins
        db_plugins = db.query(models.Plugin).all()

        ret = []
        for db_plugin in db_plugins:
            loaded_plugin = loaded_plugins.get(db_plugin.id)
            ret.append(PluginHolder(loaded_plugin=loaded_plugin, db_plugin=db_plugin))

        return ret

    def get_by_id(self, db: SessionLocal, uid: str) -> PluginHolder | None:
        loaded_plugin = self.loaded_plugins.get(uid)
        db_plugin = db.query(models.Plugin).filter(models.Plugin.id == uid).first()

        if not db_plugin:
            return None

        return PluginHolder(loaded_plugin=loaded_plugin, db_plugin=db_plugin)

    def shutdown(self):
        with SessionLocal.begin() as db:
            for plugin in self.loaded_plugins.values():
                plugin.on_stop(db)
                plugin.on_unload(db)

    def _validate_plugin(self, plugin_dir: Path) -> PluginInfo:
        plugin_yaml = plugin_dir / "plugin.yaml"
        if not plugin_yaml.exists():
            raise PluginValidationException("plugin.yaml not found")

        plugin_config = PluginInfo(**yaml.safe_load(plugin_yaml.read_text()))
        plugin_config.id = slugify(plugin_config.name)
        readme = plugin_dir / "README.md"
        if readme.exists():
            plugin_config.readme = readme.read_text()
        plugin_file = plugin_dir / plugin_config.main

        if not plugin_file.is_file():
            raise PluginValidationException(
                f"Plugin {plugin_config.name} does not have a valid main file"
            )

        return plugin_config

    def _validate_temp_plugin(
        self, db: Session, temp_dir: Path
    ) -> tuple[Path, PluginInfo]:
        """Validate the plugin in the temp directory
        and move it to the plugin directory."""
        plugin_config = self._validate_plugin(temp_dir)

        if self.get_by_id(db, plugin_config.id):
            raise PluginValidationException("Plugin already exists")

        plugin_dir = self.marketplace_path / plugin_config.id
        shutil.move(temp_dir, plugin_dir)
        shutil.rmtree(plugin_dir / ".git", ignore_errors=True)

        return plugin_dir, plugin_config

    def _create_plugin_obj(self, db, file_path, plugin_config: PluginInfo):
        plugin_file_name = file_path.stem
        package_name = file_path.parent.name
        sys.path.append(str(file_path.parent.parent))

        spec = importlib.util.spec_from_file_location(
            f"{package_name}.{plugin_file_name}", str(file_path)
        )
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        return module.Plugin(self.main_menu, plugin_config, db)

    @staticmethod
    def _determine_auto_start(plugin_config: PluginInfo, empire_config) -> bool:
        # Server Config -> Plugin Config (Default True)
        server_config = empire_config.plugins.get(plugin_config.id, PluginConfig())

        if server_config.auto_start is not None:
            return server_config.auto_start

        return plugin_config.auto_start

    @staticmethod
    def _determine_auto_execute(plugin_config, empire_config) -> PluginConfig | None:
        # Server Config -> Plugin Config -> Default (None)
        server_config = empire_config.plugins.get(plugin_config.id)

        if server_config is not None and server_config.auto_execute is not None:
            return server_config.auto_execute
        if plugin_config.auto_execute is not None:
            return plugin_config.auto_execute

        return None

    def _list_plugin_directories(self):
        def _ignore_plugin(plugin_dir):
            return (
                plugin_dir.name == "example"
                or not plugin_dir.is_dir()
                or plugin_dir.name.startswith(".")
                or plugin_dir.name.startswith("_")
            )

        main_dirs = [
            d
            for d in self.plugin_path.iterdir()
            if d.is_dir() and not _ignore_plugin(d)
        ]
        marketplace_dirs = [
            d
            for d in self.marketplace_path.iterdir()
            if d.is_dir() and not _ignore_plugin(d)
        ]

        return main_dirs + marketplace_dirs
