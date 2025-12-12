import logging
import os
import shutil
import sys
from pathlib import Path
from typing import Annotated

import netaddr
import yaml
from netaddr.core import AddrFormatError
from pydantic import (
    AfterValidator,
    BaseModel,
    Field,
    field_validator,
    model_validator,
)
from pydantic_settings import (
    BaseSettings,
    PydanticBaseSettingsSource,
    SettingsConfigDict,
)

log = logging.getLogger(__name__)


class EmpireBaseModel(BaseModel):
    @field_validator("*")
    @classmethod
    def set_path(cls, v):
        if isinstance(v, Path):
            if v.expanduser().is_absolute():
                return v.expanduser().resolve()
            return DATA_DIR / v
        return v


class ApiConfig(EmpireBaseModel):
    ip: str = "0.0.0.0"
    port: int = 1337
    secure: bool = False


class SubmodulesConfig(EmpireBaseModel):
    auto_update: bool = True


class StarkillerConfig(EmpireBaseModel):
    enabled: bool = True
    repo: str = "bc-security/starkiller"
    ref: str = "main"


class EmpireCompilerConfig(EmpireBaseModel):
    archive: str = ""
    confuser_proj: str = ""
    # This is only used if you are using a self-compiled
    # version that is not already tarred and published.
    directory: str | None = None


class DatabaseDefaultObfuscationConfig(EmpireBaseModel):
    language: str = "powershell"
    enabled: bool = False
    command: str = r"Token\All\1"
    module: str = "invoke-obfuscation"
    preobfuscatable: bool = True


def valid_ip(v: str):
    try:
        if "-" in v:
            start, end = v.split("-")
            netaddr.IPRange(start, end)
        elif "/" in v:
            netaddr.IPNetwork(v)
        else:
            netaddr.IPAddress(v)

        return v
    except AddrFormatError as e:
        raise ValueError(
            f"Invalid IP address {v}. Must be a valid IP Address, Range, or CIDR."
        ) from e


class DatabaseDefaultsConfig(EmpireBaseModel):
    staging_key: str = ""
    username: str = "empireadmin"
    password: str = "password123"
    obfuscation: list[DatabaseDefaultObfuscationConfig] = []
    keyword_obfuscation: list[str] = []
    bypasses: list[str] = []
    ip_allow_list: list[Annotated[str, AfterValidator(valid_ip)]] = []
    ip_deny_list: list[Annotated[str, AfterValidator(valid_ip)]] = []


class SQLiteDatabaseConfig(EmpireBaseModel):
    location: Path = Path("empire.db")


class MySQLDatabaseConfig(EmpireBaseModel):
    url: str = "localhost:3306"
    username: str = ""
    password: str = ""
    database_name: str = "empire"


class DatabaseConfig(EmpireBaseModel):
    # Support legacy DATABASE_USE env in addition to nested EMPIRE_DATABASE__USE
    use: str = Field(default="sqlite", env=["DATABASE_USE"])
    sqlite: SQLiteDatabaseConfig
    mysql: MySQLDatabaseConfig
    defaults: DatabaseDefaultsConfig

    def __getitem__(self, key):
        return getattr(self, key)


class DirectoriesConfig(EmpireBaseModel):
    downloads: Path = Path("downloads")


class LoggingConfig(EmpireBaseModel):
    level: str = "INFO"
    simple_console: bool = True


class LastTaskConfig(EmpireBaseModel):
    enabled: bool = False
    file: Path = Path("debug/last_task.txt")


class DebugConfig(EmpireBaseModel):
    last_task: LastTaskConfig


class PluginAutoExecuteConfig(EmpireBaseModel):
    enabled: bool = False
    options: dict[str, str] = {}


class PluginConfig(EmpireBaseModel):
    auto_start: bool | None = None
    auto_execute: PluginAutoExecuteConfig | None = None


class PluginRegistryConfig(EmpireBaseModel):
    name: str
    location: Path | None = None
    url: str | None = None
    git_url: str | None = None
    ref: str | None = None
    file: str | None = None

    @model_validator(mode="before")
    @classmethod
    def validate_location_or_url_or_git_url(cls, values):
        if not (values.get("location") or values.get("url") or values.get("git_url")):
            raise ValueError("Either location, url, or git_url must be set")
        return values


class PluginMarketplaceConfig(EmpireBaseModel):
    registries: list[PluginRegistryConfig] = []


class EmpireConfig(BaseSettings):
    suppress_self_cert_warning: bool = Field(default=True)
    api: ApiConfig = ApiConfig()
    empire_compiler: EmpireCompilerConfig = EmpireCompilerConfig()
    starkiller: StarkillerConfig = StarkillerConfig()
    submodules: SubmodulesConfig = SubmodulesConfig()
    database: DatabaseConfig = DatabaseConfig(
        sqlite=SQLiteDatabaseConfig(),
        mysql=MySQLDatabaseConfig(),
        defaults=DatabaseDefaultsConfig(),
    )
    plugins: dict[str, PluginConfig] = {}
    plugin_marketplace: PluginMarketplaceConfig = PluginMarketplaceConfig()
    directories: DirectoriesConfig = DirectoriesConfig()
    logging: LoggingConfig = LoggingConfig()
    debug: DebugConfig = DebugConfig(last_task=LastTaskConfig())

    # Settings configuration: allow extras (for backward compat),
    # and enable environment variable support with nested delimiter.
    model_config = SettingsConfigDict(
        env_nested_delimiter="__",
        env_prefix="EMPIRE_",
        case_sensitive=False,
        extra="allow",
        nested_model_default_partial_update=True,
    )

    @model_validator(mode="before")
    @classmethod
    def map_legacy_database_use_env(cls, values):
        # If the new nested env is provided, it should take precedence over legacy
        if os.environ.get("EMPIRE_DATABASE__USE") or os.environ.get(
            "EMPIRE__DATABASE__USE"
        ):
            return values
        legacy = os.environ.get("DATABASE_USE")
        if legacy:
            if not isinstance(values, dict):
                values = {}
            db = values.get("database") or {}
            if not isinstance(db, dict):
                db = {}
            db["use"] = legacy
            values["database"] = db
        return values

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,
        file_secret_settings: PydanticBaseSettingsSource,
    ) -> tuple[PydanticBaseSettingsSource, ...]:
        # Precedence: nested env > .env > YAML/init; legacy handled in validator above
        return (
            env_settings,
            dotenv_settings,
            init_settings,
        )

    def __getitem__(self, key):
        return getattr(self, key)

    # Backwards-compatible initialization from a single dict positional arg
    # to support existing tests/usages like EmpireConfig(test_config_dict).
    def __init__(self, config_dict: dict | None = None, **values):  # type: ignore[override]
        if config_dict is not None:
            if not isinstance(config_dict, dict):
                raise ValueError("config_dict must be a dictionary")
            values = {**config_dict, **values}
            # Preserve raw YAML dict for compatibility
            object.__setattr__(self, "yaml", config_dict)
        super().__init__(**values)


def set_yaml(location: str):
    location = Path(location).expanduser().resolve()
    try:
        with location.open() as stream:
            return yaml.safe_load(stream)
    except yaml.YAMLError as exc:
        log.warning(exc)
    except FileNotFoundError as exc:
        log.warning(exc)


DEFAULT_CONFIG = Path("empire/server/config.yaml")

if os.environ.get("TEST_MODE"):
    CONFIG_DIR = Path.home() / ".config" / "empire-test"
    DATA_DIR = Path.home() / ".local" / "share" / "empire-test"
    shutil.rmtree(CONFIG_DIR, ignore_errors=True)
    shutil.rmtree(DATA_DIR, ignore_errors=True)

    DATA_DIR.mkdir(parents=True, exist_ok=True)
    test_registry_1 = Path("empire/test/test_registry_1.yaml")
    test_registry_2 = Path("empire/test/test_registry_2.yaml")
    shutil.copy(test_registry_1, DATA_DIR / "test_registry_1.yaml")
    shutil.copy(test_registry_2, DATA_DIR / "test_registry_2.yaml")
else:
    CONFIG_DIR = Path.home() / ".config" / "empire"
    DATA_DIR = Path.home() / ".local" / "share" / "empire"

CONFIG_PATH = CONFIG_DIR / "config.yaml"
CONFIG_DIR.mkdir(parents=True, exist_ok=True)
DATA_DIR.mkdir(parents=True, exist_ok=True)

if not CONFIG_PATH.exists():
    shutil.copy(DEFAULT_CONFIG, CONFIG_PATH)
    log.info(f"Copied {DEFAULT_CONFIG} to {CONFIG_PATH}")


config_dict = EmpireConfig().model_dump()
if "--config" in sys.argv:
    location = sys.argv[sys.argv.index("--config") + 1]
    log.info(f"Loading config from {location}")
    loaded_config = set_yaml(location)
    if loaded_config:
        config_dict = loaded_config
elif CONFIG_PATH.exists():
    log.info("Loading default config")
    loaded_config = set_yaml(str(CONFIG_PATH))
    if loaded_config:
        config_dict = loaded_config

empire_config = EmpireConfig(**config_dict)
