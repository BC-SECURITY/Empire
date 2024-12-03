import logging
import sys
from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator

from empire import config_manager

log = logging.getLogger(__name__)


class EmpireBaseModel(BaseModel):
    @field_validator("*")
    @classmethod
    def set_path(cls, v):
        if isinstance(v, Path):
            return v.expanduser().resolve()
        return v


class ApiConfig(EmpireBaseModel):
    port: int = 1337
    cert_path: Path = "empire/server/data"


class SubmodulesConfig(EmpireBaseModel):
    auto_update: bool = True


class StarkillerConfig(EmpireBaseModel):
    repo: str = "bc-security/starkiller"
    directory: Path = "empire/server/api/v2/starkiller"
    ref: str = "main"
    auto_update: bool = True
    enabled: bool | None = True


class DatabaseDefaultObfuscationConfig(EmpireBaseModel):
    language: str = "powershell"
    enabled: bool = False
    command: str = r"Token\All\1"
    module: str = "invoke-obfuscation"
    preobfuscatable: bool = True


class DatabaseDefaultsConfig(EmpireBaseModel):
    staging_key: str = "RANDOM"
    username: str = "empireadmin"
    password: str = "password123"
    obfuscation: list[DatabaseDefaultObfuscationConfig] = []
    keyword_obfuscation: list[str] = []
    ip_whitelist: str = Field("", alias="ip-whitelist")
    ip_blacklist: str = Field("", alias="ip-blacklist")


class SQLiteDatabaseConfig(EmpireBaseModel):
    location: Path = "empire/server/data/empire.db"


class MySQLDatabaseConfig(EmpireBaseModel):
    url: str = "localhost:3306"
    username: str = ""
    password: str = ""
    database_name: str = "empire"


class DatabaseConfig(EmpireBaseModel):
    use: str = "sqlite"
    sqlite: SQLiteDatabaseConfig
    mysql: MySQLDatabaseConfig
    defaults: DatabaseDefaultsConfig

    def __getitem__(self, key):
        return getattr(self, key)


class DirectoriesConfig(EmpireBaseModel):
    downloads: Path = Path("empire/server/downloads")
    module_source: Path = Path("empire/server/modules")
    obfuscated_module_source: Path = Path("empire/server/data/obfuscated_module_source")


class LoggingConfig(EmpireBaseModel):
    level: str = "INFO"
    directory: Path = "empire/server/downloads/logs/"
    simple_console: bool = True


class LastTaskConfig(EmpireBaseModel):
    enabled: bool = False
    file: Path = "empire/server/data/last_task.txt"


class DebugConfig(EmpireBaseModel):
    last_task: LastTaskConfig


class EmpireConfig(EmpireBaseModel):
    supress_self_cert_warning: bool = Field(
        alias="supress-self-cert-warning", default=True
    )
    api: ApiConfig | None = ApiConfig()
    starkiller: StarkillerConfig = StarkillerConfig()
    submodules: SubmodulesConfig = SubmodulesConfig()
    database: DatabaseConfig = DatabaseConfig(
        sqlite=SQLiteDatabaseConfig(),
        mysql=MySQLDatabaseConfig(),
        defaults=DatabaseDefaultsConfig(),
    )
    plugins: dict[str, dict[str, str]] = {}
    directories: DirectoriesConfig = DirectoriesConfig()
    logging: LoggingConfig = LoggingConfig()
    debug: DebugConfig = DebugConfig(last_task=LastTaskConfig())

    model_config = ConfigDict(extra="allow")

    def __init__(self, config_dict: dict | None = None):
        if config_dict is None:
            config_dict = {}
        if not isinstance(config_dict, dict):
            raise ValueError("config_dict must be a dictionary")

        super().__init__(**config_dict)
        # For backwards compatibility
        self.yaml = config_dict


def set_yaml(location: str):
    location = Path(location).expanduser().resolve()
    try:
        with location.open() as stream:
            return yaml.safe_load(stream)
    except yaml.YAMLError as exc:
        log.warning(exc)
    except FileNotFoundError as exc:
        log.warning(exc)


config_dict = EmpireConfig().model_dump()
if "--config" in sys.argv:
    location = sys.argv[sys.argv.index("--config") + 1]
    log.info(f"Loading config from {location}")
    loaded_config = set_yaml(location)
    if loaded_config:
        config_dict = loaded_config
elif config_manager.CONFIG_SERVER_PATH.exists():
    log.info("Loading default config")
    loaded_config = set_yaml(config_manager.CONFIG_SERVER_PATH)
    if loaded_config:
        config_dict = loaded_config
        config_dict = config_manager.check_config_permission(config_dict, "server")

empire_config = EmpireConfig(config_dict)
