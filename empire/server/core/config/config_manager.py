import logging
import os
import shutil
import sys
from contextlib import suppress
from pathlib import Path
from typing import Annotated

import netaddr
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
    YamlConfigSettingsSource,
)

from empire.server.core.config import paths

log = logging.getLogger(__name__)

# Base directories. The platformdirs incantation lives in `paths` (a
# side-effect-free leaf module) so config_manager and the root conftest derive
# their dirs identically — without conftest importing config_manager at startup,
# which would trigger this module's mkdir/config-copy side effects too early.
# Defined here (not at module bottom) because DirectoriesConfig.cache uses
# CACHE_DIR as a class-level field default, evaluated at import time. TEST_MODE
# swaps in an isolated "empire-test" app name; on Linux/CI that resolves to the
# same ~/.local/share/empire-test as before.
#
# Under pytest-xdist each worker gets its own DATA_DIR (a worker-<gw> subdir of
# the shared base) so per-worker writable state — downloads/,
# obfuscated_module_source/, and the MySQL database name — cannot collide. The
# heavy read-only caches (empire-compiler, starkiller) still live under DATA_DIR,
# so they are symlinked back to the shared base near the bottom of this module —
# fetched once and reused across workers instead of re-downloaded per worker.
# CACHE_DIR is a single shared location, so it needs no per-worker handling. The
# first-download race on a cold shared cache is serialized by the
# _warm_external_caches fixture (empire/test/conftest.py).
_APP_NAME = "empire-test" if os.environ.get("TEST_MODE") else "empire"
CONFIG_DIR = paths.config_dir(_APP_NAME)
CACHE_DIR = paths.cache_dir(_APP_NAME)
_DATA_BASE = paths.data_dir(_APP_NAME)
_XDIST_WORKER = os.environ.get("PYTEST_XDIST_WORKER", "")
if os.environ.get("TEST_MODE") and _XDIST_WORKER:
    DATA_DIR = _DATA_BASE / f"worker-{_XDIST_WORKER}"
else:
    DATA_DIR = _DATA_BASE
CONFIG_PATH = CONFIG_DIR / paths.CONFIG_FILENAME
# The boot self-signed pair's directory. Anchored here so server.run (which
# generates it) and the malleable listener (which loads it) resolve the same
# path; cert_util owns the filenames but is a crypto leaf that can't import
# this module.
CERT_DIR = DATA_DIR / "cert"


class EmpireBaseModel(BaseModel):
    @field_validator("*")
    @classmethod
    def set_path(cls, v):
        if isinstance(v, Path):
            if v.expanduser().is_absolute():
                return v.expanduser().resolve()
            return DATA_DIR / v
        return v


class ServerConfig(EmpireBaseModel):
    socketio: bool = True


class ApiConfig(EmpireBaseModel):
    ip: str = "0.0.0.0"
    port: int = 1337
    secure: bool = False
    cors_origins: list[str] = ["*"]


class StarkillerConfig(EmpireBaseModel):
    enabled: bool = True
    repo: str = "bc-security/starkiller"
    ref: str = "main"
    # Points at an already-built Starkiller so the server doesn't clone one.
    # `str`, not `Path`: a `Path` field would pick up `EmpireBaseModel.set_path`,
    # which silently reinterprets a relative value as DATA_DIR-relative.
    # `sync_starkiller` calls `expanduser()` itself.
    directory: str | None = None


class EmpireCompilerConfig(EmpireBaseModel):
    repo: str = ""
    ref: str = ""
    confuser_proj: str = ""
    # This is only used if you are using a self-compiled
    # version that is not already tarred and published.
    directory: str | None = None


class ObfuscationSettings(EmpireBaseModel):
    timeout: int = Field(default=300, ge=0)


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
    except AddrFormatError as e:
        raise ValueError(
            f"Invalid IP address {v}. Must be a valid IP Address, Range, or CIDR."
        ) from e
    else:
        return v


class DatabaseDefaultsConfig(EmpireBaseModel):
    staging_key: str = ""
    username: str = "empireadmin"
    password: str = "password123"  # noqa: S105 - documented default admin password, overridden via config.yaml / env
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
    pool_size: int = 10
    max_overflow: int = 15
    pool_pre_ping: bool = True
    pool_recycle: int = 3600


class DatabaseConfig(EmpireBaseModel):
    # Legacy DATABASE_USE env is mapped in EmpireConfig.map_legacy_database_use_env;
    # the field itself only declares its default.
    use: str = Field(default="sqlite")
    sqlite: SQLiteDatabaseConfig
    mysql: MySQLDatabaseConfig
    defaults: DatabaseDefaultsConfig

    def __getitem__(self, key):
        return getattr(self, key)


class DirectoriesConfig(EmpireBaseModel):
    downloads: Path = Path("downloads")
    # Persistent on-disk caches (e.g. Go build cache). Defaults to the platform
    # cache dir (CACHE_DIR, e.g. ~/.cache/empire on Linux, ~/Library/Caches/empire
    # on macOS). A relative override in YAML lands under DATA_DIR via
    # EmpireBaseModel.set_path; an absolute override is used as-is.
    cache: Path = CACHE_DIR


class LoggingConfig(EmpireBaseModel):
    level: str = "INFO"
    simple_console: bool = True
    # See docs/settings/logging.md for file_logging and the rotation limits.
    file_logging: bool = True
    max_bytes: int = Field(default=10 * 1024 * 1024, ge=0)
    backup_count: int = Field(default=5, ge=0)


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


class PluginAutoInstallConfig(EmpireBaseModel):
    name: str
    version: str
    registry: str


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
    auto_install: list[PluginAutoInstallConfig] = []


class EmpireConfig(BaseSettings):
    suppress_self_cert_warning: bool = Field(default=True)
    obfuscation: ObfuscationSettings = ObfuscationSettings()
    api: ApiConfig = ApiConfig()
    server: ServerConfig = ServerConfig()
    empire_compiler: EmpireCompilerConfig = EmpireCompilerConfig()
    starkiller: StarkillerConfig = StarkillerConfig()
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
        # settings_customise_sources is a classmethod with no instance access,
        # so we use _module_base_config_path to pass the base config path in.
        base_path = _module_base_config_path or _resolve_base_config_path()

        sources: list[PydanticBaseSettingsSource] = [
            env_settings,
            dotenv_settings,
            init_settings,
        ]

        # User config: config.user.yaml next to base config
        user_path = base_path.parent / paths.USER_CONFIG_FILENAME
        if user_path.exists():
            log.info(f"Loading user config from {user_path}")
            sources.append(
                YamlConfigSettingsSource(
                    settings_cls,
                    yaml_file=user_path,
                )
            )

        # Base config
        if base_path.exists():
            sources.append(
                YamlConfigSettingsSource(
                    settings_cls,
                    yaml_file=base_path,
                )
            )

        return tuple(sources)

    def __getitem__(self, key):
        return getattr(self, key)

    # Backwards-compatible initialization from a single dict positional arg
    # to support existing tests/usages like EmpireConfig(test_config_dict).
    def __init__(
        self,
        config_dict: dict | None = None,
        /,
        _base_config_path: Path | None = None,
        **values,
    ):
        global _module_base_config_path  # noqa: PLW0603
        if _base_config_path is not None:
            _module_base_config_path = _base_config_path
        if config_dict is not None:
            if not isinstance(config_dict, dict):
                raise ValueError("config_dict must be a dictionary")
            values = {**config_dict, **values}
            # Preserve raw YAML dict for compatibility
            object.__setattr__(self, "yaml", config_dict)
        super().__init__(**values)


def _resolve_base_config_path() -> Path:
    """Determine the base config YAML path from --config flag or default location."""
    if "--config" in sys.argv:
        index = sys.argv.index("--config")
        try:
            location = sys.argv[index + 1]
        except IndexError:
            log.warning("--config flag provided without a path; using default config")
        else:
            log.info(f"Loading config from {location}")
            return Path(location).expanduser().resolve()
    log.info("Loading default config")
    return CONFIG_PATH


DEFAULT_CONFIG = paths.SERVER_ROOT / paths.CONFIG_FILENAME

# CONFIG_DIR / DATA_DIR / CACHE_DIR / CONFIG_PATH are defined near the top of this
# module (platformdirs). The TEST_MODE wipe lives in root conftest.py::
# _reset_test_dirs — if you change the path derivation, update _TEST_CONFIG_DIR /
# _TEST_DATA_DIR / _TEST_CACHE_DIR there too.
CONFIG_DIR.mkdir(parents=True, exist_ok=True)
DATA_DIR.mkdir(parents=True, exist_ok=True)

# Under pytest-xdist, symlink the shared heavy read-only caches into this
# worker's isolated DATA_DIR so they are fetched once (into _DATA_BASE) and
# reused across workers instead of re-downloaded per worker. Placed here (not at
# the top) so the path-derivation block stays side-effect-free.
if os.environ.get("TEST_MODE") and _XDIST_WORKER:
    for _shared_name in ("empire-compiler", "starkiller"):
        _shared_target = _DATA_BASE / _shared_name
        _shared_target.mkdir(parents=True, exist_ok=True)
        _worker_link = DATA_DIR / _shared_name
        if not _worker_link.exists():
            with suppress(FileExistsError):
                _worker_link.symlink_to(_shared_target)


def seed_config(source: Path, destination: Path) -> None:
    """Copy a shipped config template into the operator's config directory.

    ``copyfile``, not ``copy``: ``copy`` is ``copyfile`` + ``copymode``, and a
    packaged config.yaml can be read-only (0444 in a Nix store). Carrying that
    mode across leaves the operator unable to edit the very file Empire
    directs them to edit, and ``overwrite_base_config``'s PermissionError
    handler then advises ``sudo chown $USER`` -- useless for a mode problem on
    a file they already own.
    """
    shutil.copyfile(source, destination)
    log.info(f"Copied {source} to {destination}")


if not CONFIG_PATH.exists():
    seed_config(DEFAULT_CONFIG, CONFIG_PATH)

DEFAULT_USER_CONFIG = paths.SERVER_ROOT / paths.USER_CONFIG_FILENAME
USER_CONFIG_PATH = CONFIG_DIR / paths.USER_CONFIG_FILENAME
if DEFAULT_USER_CONFIG.exists() and not USER_CONFIG_PATH.exists():
    seed_config(DEFAULT_USER_CONFIG, USER_CONFIG_PATH)


_module_base_config_path: Path | None = _resolve_base_config_path()
empire_config = EmpireConfig()

# Per-xdist-worker database name. Mutated here (not in a fixture) because
# db/base.py captures database_config at import time, and that import is
# triggered transitively before any fixture runs. Each worker thus builds and
# tears down its own isolated database; without xdist, behavior is unchanged.
if os.environ.get("TEST_MODE") and os.environ.get("PYTEST_XDIST_WORKER"):
    _worker = os.environ["PYTEST_XDIST_WORKER"]
    empire_config.database.mysql.database_name = (
        f"{empire_config.database.mysql.database_name}_{_worker}"
    )
    _sqlite_loc = str(empire_config.database.sqlite.location)
    if _sqlite_loc.endswith(".db"):
        empire_config.database.sqlite.location = Path(
            _sqlite_loc[:-3] + f"_{_worker}.db"
        )
    else:
        empire_config.database.sqlite.location = Path(_sqlite_loc + f"_{_worker}")
