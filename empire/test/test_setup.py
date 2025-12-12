from pathlib import Path

from empire.server.core.config.config_manager import (
    DATA_DIR,
    PluginRegistryConfig,
)
from empire.server.core.config.data_manager import sync_plugin_registry


def test_sync_plugin_registry_with_location_returns_path():
    location = DATA_DIR / "test_registry_1.yaml"
    cfg = PluginRegistryConfig(name="TEST", location=location)

    result = sync_plugin_registry(cfg)

    assert result == location
    assert Path(result).exists()


def test_sync_plugin_registry_with_git_url_clones_and_returns_file(monkeypatch):
    def fake_clone_git_repo(git_url, ref, directory):
        directory.mkdir(parents=True, exist_ok=True)
        (directory / "registry.yaml").write_text("schema_version: 1\nplugins: []\n")
        return directory

    monkeypatch.setattr(
        "empire.server.core.config.data_manager.clone_git_repo", fake_clone_git_repo
    )

    cfg = PluginRegistryConfig(
        name="TESTGIT",
        git_url="git://example.com/repo.git",
        ref="main",
        file="registry.yaml",
    )

    result = sync_plugin_registry(cfg)

    assert result is not None
    assert Path(result).exists()
    assert Path(result).read_text().startswith("schema_version:")
