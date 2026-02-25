import copy
from pathlib import Path

import pytest
import yaml

from empire.server.core.config import config_manager
from empire.server.core.config.config_manager import EmpireConfig
from empire.server.core.db.defaults import get_staging_key
from empire.test.conftest import load_test_config

BASE_CONFIG = {
    "api": {"port": 1337, "ip": "0.0.0.0"},
    "database": {
        "use": "sqlite",
        "sqlite": {"location": "empire.db"},
        "mysql": {
            "url": "localhost:3306",
            "username": "",
            "password": "",
            "database_name": "empire",
        },
        "defaults": {
            "staging_key": "",
            "username": "empireadmin",
            "password": "password123",
            "obfuscation": [],
            "keyword_obfuscation": [],
            "bypasses": [],
            "ip_allow_list": [],
            "ip_deny_list": [],
        },
    },
}


def test_config_resolves_path():
    server_config_dict = load_test_config()
    server_config_dict["directories"]["downloads"] = "~/.empire/server/downloads"
    empire_config = EmpireConfig(server_config_dict)
    assert isinstance(empire_config.directories.downloads, Path)
    assert not str(empire_config.directories.downloads).startswith("~")
    assert empire_config.directories.downloads.is_absolute()

    server_config_dict["directories"]["downloads"] = "/tmp/empire"
    empire_config = EmpireConfig(server_config_dict)
    assert isinstance(empire_config.directories.downloads, Path)
    assert (str(empire_config.directories.downloads).startswith("/private/tmp")) or (
        str(empire_config.directories.downloads).startswith("/tmp")
    )
    assert empire_config.directories.downloads.is_absolute()

    server_config_dict["directories"]["downloads"] = "empire/test"
    empire_config = EmpireConfig(server_config_dict)
    assert isinstance(empire_config.directories.downloads, Path)
    assert str(empire_config.directories.downloads).endswith(
        ".local/share/empire-test/empire/test"
    )
    assert empire_config.directories.downloads.is_absolute()


def test_config_validates_registry_location_or_url():
    server_config_dict = load_test_config()

    server_config_dict["plugin_marketplace"]["registries"][0]["location"] = None
    server_config_dict["plugin_marketplace"]["registries"][0]["url"] = None

    with pytest.raises(
        ValueError, match="Either location, url, or git_url must be set"
    ):
        EmpireConfig(server_config_dict)


def test_staging_key_validation(monkeypatch):
    """
    Test that get_staging_key() properly validates provided staging keys.
    """
    expected_length = 32
    # No staging key set, should generate a valid random key (32 chars)
    monkeypatch.delenv("STAGING_KEY", raising=False)
    random_key = get_staging_key()
    assert random_key.isalnum(), (
        f"Generated key contains invalid characters: {random_key}"
    )
    assert len(random_key) == expected_length

    # Valid preset key (32 chars, letters + numbers only)
    monkeypatch.setenv("STAGING_KEY", "A1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6")
    assert get_staging_key() == "A1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6"

    # Invalid preset key (contains punctuation)
    monkeypatch.setenv("STAGING_KEY", "Bad#Key$With!Special")
    with pytest.raises(
        ValueError, match="Staging key must only contain letters .* and numbers"
    ):
        get_staging_key()

    # Invalid preset key (too short)
    monkeypatch.setenv("STAGING_KEY", "ShortKey123")
    with pytest.raises(
        ValueError, match="Staging key must be exactly 32 characters long"
    ):
        get_staging_key()

    # Invalid preset key (too long)
    monkeypatch.setenv("STAGING_KEY", "ThisKeyIsWayTooLongForValidation12345")
    with pytest.raises(
        ValueError, match="Staging key must be exactly 32 characters long"
    ):
        get_staging_key()

    # Empty staging key still generates a valid random key
    monkeypatch.setenv("STAGING_KEY", "")
    random_key = get_staging_key()
    assert random_key.isalnum(), (
        f"Generated key contains invalid characters: {random_key}"
    )
    assert len(random_key) == expected_length


def test_env_overrides_database_use_nested(monkeypatch):
    server_config_dict = load_test_config()
    # YAML says mysql in test_server_config.yaml; override to sqlite via env
    monkeypatch.setenv("EMPIRE_DATABASE__USE", "sqlite")
    config = EmpireConfig(server_config_dict)
    assert config.database.use.lower() == "sqlite"


def test_env_overrides_database_use_legacy(monkeypatch):
    server_config_dict = load_test_config()
    # YAML says mysql in test_server_config.yaml; legacy var overrides to sqlite
    monkeypatch.setenv("DATABASE_USE", "sqlite")
    config = EmpireConfig(server_config_dict)
    assert config.database.use.lower() == "sqlite"


def test_env_overrides_mysql_credentials(monkeypatch):
    server_config_dict = load_test_config()
    monkeypatch.setenv("EMPIRE_DATABASE__MYSQL__USERNAME", "env_user")
    monkeypatch.setenv("EMPIRE_DATABASE__MYSQL__PASSWORD", "env_pass")
    monkeypatch.setenv("EMPIRE_DATABASE__MYSQL__DATABASE_NAME", "env_db")
    config = EmpireConfig(server_config_dict)
    assert config.database.mysql.username == "env_user"
    assert config.database.mysql.password == "env_pass"
    assert config.database.mysql.database_name == "env_db"


def test_config_accepts_unknown_default_bypass_name():
    """
    EmpireConfig should not raise if the defaults.bypasses list contains a name
    that doesn't correspond to any YAML/DB bypass (e.g., 'fake_bypass').
    Validation of existence happens later in the load phase, not at config parse.
    """
    server_config_dict = load_test_config()
    server_config_dict["database"]["defaults"]["bypasses"] = [
        "mattifestation",
        "etw",
        "fake_bypass",
    ]
    cfg = EmpireConfig(server_config_dict)

    assert "fake_bypass" in cfg.database.defaults.bypasses
    assert set(cfg.database.defaults.bypasses) >= {"mattifestation", "etw"}


@pytest.fixture(autouse=False)
def _isolated_config(monkeypatch):
    """Isolate tests that use _base_config_path from env vars and global state."""
    original = config_manager._module_base_config_path
    # Clear env vars that would override YAML sources in the test
    monkeypatch.delenv("EMPIRE_DATABASE__USE", raising=False)
    monkeypatch.delenv("DATABASE_USE", raising=False)
    yield
    config_manager._module_base_config_path = original


@pytest.mark.usefixtures("_isolated_config")
def test_user_config_layers_on_base(tmp_path):
    """User config overrides specific values while base values fall through."""
    base = tmp_path / "config.yaml"
    base.write_text(yaml.dump(BASE_CONFIG))

    user = tmp_path / "config.user.yaml"
    user.write_text(yaml.dump({"api": {"port": 8443}}))

    config = EmpireConfig(_base_config_path=base)

    assert config.api.port == 8443  # noqa: PLR2004
    assert config.api.ip == "0.0.0.0"
    assert config.database.use == "sqlite"


@pytest.mark.usefixtures("_isolated_config")
def test_no_user_config_uses_base_only(tmp_path):
    """When no config.user.yaml exists, base config is used as-is."""
    base = tmp_path / "config.yaml"
    base.write_text(yaml.dump(BASE_CONFIG))

    config = EmpireConfig(_base_config_path=base)

    assert config.api.port == 1337  # noqa: PLR2004
    assert config.api.ip == "0.0.0.0"
    assert config.database.use == "sqlite"


@pytest.mark.usefixtures("_isolated_config")
def test_user_config_deep_merges_nested_dicts(tmp_path):
    """User config overrides nested fields without clobbering siblings."""
    base_config = copy.deepcopy(BASE_CONFIG)
    base_config["database"]["mysql"]["username"] = "default_user"
    base_config["database"]["mysql"]["password"] = "default_pass"

    base = tmp_path / "config.yaml"
    base.write_text(yaml.dump(base_config))

    user = tmp_path / "config.user.yaml"
    user.write_text(
        yaml.dump({"database": {"use": "mysql", "mysql": {"password": "secret"}}})
    )

    config = EmpireConfig(_base_config_path=base)

    assert config.database.use == "mysql"
    assert config.database.mysql.password == "secret"
    assert config.database.mysql.username == "default_user"
    assert config.database.mysql.url == "localhost:3306"
    assert config.api.port == 1337  # noqa: PLR2004
