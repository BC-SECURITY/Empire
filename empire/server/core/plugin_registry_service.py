import logging
import typing
from pathlib import Path

import yaml
from pydantic import BaseModel, ValidationError, model_validator

from empire.server.core.config.config_manager import empire_config
from empire.server.core.config.data_manager import sync_plugin_registry
from empire.server.core.db import models
from empire.server.core.db.base import SessionLocal
from empire.server.core.exceptions import PluginValidationException
from empire.server.core.module_models import EmpireAuthor

if typing.TYPE_CHECKING:
    from empire.server.common.empire import MainMenu

log = logging.getLogger(__name__)

SCHEMA_VERSION = 1


class PluginRegistryPluginVersion(BaseModel):
    git_url: str | None = None
    tar_url: str | None = None
    subdirectory: str | None = None
    ref: str | None = None
    name: str

    @model_validator(mode="before")
    @classmethod
    def validate_git_or_tar(cls, values):
        if not values.get("git_url") and not values.get("tar_url"):
            raise ValueError("Either git_url or tar_url must be set")
        return values


class PluginRegistryPlugin(BaseModel):
    name: str
    homepage_url: str | None = None
    source_url: str | None = None
    authors: list[EmpireAuthor] = []
    versions: list[PluginRegistryPluginVersion] = []
    description: str


class PluginRegistry(BaseModel):
    schema_version: int
    plugins: list[PluginRegistryPlugin]


class PluginRegistryService:
    def __init__(self, main_menu: "MainMenu"):
        self.main_menu = main_menu
        self.plugin_service = main_menu.pluginsv2

        with SessionLocal.begin() as db:
            self.load_plugin_registries(db)

    def load_plugin_registries(self, db):
        registries = empire_config.plugin_marketplace.registries
        to_add = []
        for r in registries:
            if (
                db.query(models.PluginRegistry)
                .filter(models.PluginRegistry.name == r.name)
                .first()
            ):
                continue

            log.info(f"Loading plugin registry: {r.name}")

            synced_path = sync_plugin_registry(r)
            if synced_path and Path(str(synced_path)).exists():
                registry_yaml = Path(str(synced_path)).read_text()
            else:
                log.error(f"Failed to load plugin registry {r.name}")
                continue

            registry_data = yaml.safe_load(registry_yaml)
            try:
                registry = PluginRegistry.model_validate(registry_data)
            except ValidationError as e:
                log.error(f"Plugin registry {r.name} has invalid schema: {e.errors()}")
                continue

            if registry.schema_version != SCHEMA_VERSION:
                log.error(
                    f"Plugin registry {r.name} has an unsupported schema version."
                )
                continue

            to_add.append(
                models.PluginRegistry(
                    name=r.name,
                    location=str(r.location),
                    url=str(r.url),
                    data=registry_data,
                )
            )

        db.add_all(to_add)
        db.flush()

    def get_marketplace(self, db):
        registries = db.query(models.PluginRegistry).all()
        installed_plugins = self.plugin_service.get_all(db)
        installed_plugins = {p.db_plugin.name: p.db_plugin for p in installed_plugins}
        merged = {}
        for registry in registries:
            registry_data = registry.data
            for plugin in registry_data["plugins"]:
                plugin_name = plugin["name"]
                plugin["registry"] = registry.name
                if plugin_name not in merged:
                    merged[plugin_name] = {}
                merged[plugin_name][registry.name] = plugin

        return {
            "records": [
                {
                    "name": plugin_name,
                    "registries": registries,
                    "installed": installed_plugins.get(plugin_name) is not None,
                    "installed_version": (
                        installed_plugins.get(plugin_name).installed_version
                        if installed_plugins.get(plugin_name)
                        else None
                    ),
                }
                for plugin_name, registries in merged.items()
            ]
        }

    def install_plugin(self, db, name, version, registry):
        version = self._validate_install(db, name, registry, version)
        registry_data = self._get_plugin_registry_entry(db, name, registry)

        if version.get("git_url"):
            self.plugin_service.install_plugin_from_git(
                db,
                version["git_url"],
                version.get("subdirectory"),
                version.get("ref"),
                version.get("name"),
                registry_data,
            )

        else:
            self.plugin_service.install_plugin_from_tar(
                db,
                version["tar_url"],
                version.get("subdirectory"),
                version.get("name"),
                registry_data,
            )

    def _get_plugin_registry_entry(self, db, name, registry):
        plugin_registry = self.get_marketplace(db)
        plugin_reference = next(
            (p for p in plugin_registry["records"] if p["name"] == name), None
        )
        return plugin_reference["registries"].get(registry)

    def _validate_install(self, db, name, registry, version):
        marketplace = self.get_marketplace(db)
        plugin_reference = next(
            (p for p in marketplace["records"] if p["name"] == name), None
        )

        if not plugin_reference:
            raise PluginValidationException("Plugin not found in marketplace")

        if plugin_reference["installed"]:
            raise PluginValidationException("Plugin already installed")

        plugin = plugin_reference["registries"].get(registry)
        if not plugin:
            raise PluginValidationException("Plugin not found in registry")

        version = next((v for v in plugin["versions"] if v["name"] == version), None)

        if not version:
            raise PluginValidationException("Version not found in plugin")

        return version
