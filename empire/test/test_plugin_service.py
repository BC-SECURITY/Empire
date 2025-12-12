import logging
from contextlib import contextmanager
from pathlib import Path
from typing import TYPE_CHECKING
from unittest.mock import MagicMock, Mock, patch

import pytest

from empire.server.api.v2.plugin.plugin_dto import PluginExecutePostRequest
from empire.server.core.config.config_manager import (
    PluginAutoExecuteConfig,
    PluginConfig,
)
from empire.server.core.db.models import PluginInfo
from empire.server.core.exceptions import PluginValidationException
from empire.server.core.plugin_service import PluginService
from empire.server.core.plugins import BasePlugin

if TYPE_CHECKING:
    from empire.server.common.empire import MainMenu


@contextmanager
def patch_plugin_execute(plugin, execute_func):
    old_execute = plugin.execute
    plugin.execute = execute_func
    yield
    plugin.execute = old_execute


@contextmanager
def patch_plugin_options(plugin, options):
    old_options = plugin.execution_options
    plugin.execution_options = options
    yield
    plugin.execution_options = old_options


@contextmanager
def patch_plugin_class_on_start_on_stop(plugin_class, on_start=None, on_stop=None):
    with (
        patch.object(plugin_class, "on_start", new=on_start),
        patch.object(plugin_class, "on_stop", new=on_stop),
    ):
        yield


@contextmanager
def patch_plugin_class_on_load_on_unload(plugin_class, on_load=None, on_unload=None):
    with (
        patch.object(plugin_class, "on_load", new=on_load),
        patch.object(plugin_class, "on_unload", new=on_unload),
    ):
        yield


def test_auto_execute_plugins(caplog, monkeypatch, models, empire_config, install_path):
    caplog.set_level(logging.DEBUG)

    main_menu_mock = MagicMock()
    main_menu_mock.installPath = str(install_path)
    plugin_service = PluginService(main_menu_mock)
    plugin_service.startup()

    assert "This function has been called 1 times." in caplog.text
    assert "Message: Hello World!" in caplog.text


def test_plugin_execute_with_kwargs(session_local, install_path):
    def execute(options, **kwargs):
        return f"This function was called with options: {options} and kwargs: {kwargs}"

    main_menu_mock = MagicMock()
    main_menu_mock.installPath = install_path
    plugin_service = PluginService(main_menu_mock)
    plugin_service.startup()

    with session_local.begin() as db:
        plugin_holder = plugin_service.get_by_id(db, "basic_reporting")
        plugin = plugin_holder.loaded_plugin
        with patch_plugin_execute(plugin, execute):
            req = PluginExecutePostRequest(options={"report": "session"})
            res, err = plugin_service.execute_plugin("db_session", plugin, req, 1)

    assert res == execute(req.options, db="db_session", user=1)


def test_execute_plugin_file_option_not_found(install_path, session_local):
    main_menu_mock = MagicMock()
    main_menu_mock.installPath = install_path

    main_menu_mock.downloadsv2 = MagicMock()
    main_menu_mock.downloadsv2.get_by_id.return_value = None

    plugin_service = PluginService(main_menu_mock)
    plugin_service.startup()

    with session_local.begin() as db:
        plugin_holder = plugin_service.get_by_id(db, "basic_reporting")
        plugin = plugin_holder.loaded_plugin

    with patch_plugin_options(
        plugin,
        {
            "file_option": {
                "Name": "file_option",
                "Description": "File option",
                "Type": "File",
                "Strict": False,
                "Required": True,
                "DependsOn": None,
            }
        },
    ):
        req = PluginExecutePostRequest(options={"file_option": 9999})

        with pytest.raises(PluginValidationException) as e:
            plugin_service.execute_plugin(db, plugin, req, None)
        assert str(e.value) == "File not found for 'file_option' id 9999"


def test_execute_plugin_file_option(install_path, session_local, models):
    main_menu_mock = MagicMock()
    main_menu_mock.installPath = install_path

    download = models.Download(id=9999, filename="test_file", location="/tmp/test_file")
    main_menu_mock.downloadsv2 = MagicMock()
    main_menu_mock.downloadsv2.get_by_id.return_value = download

    plugin_service = PluginService(main_menu_mock)
    plugin_service.startup()

    with session_local.begin() as db:
        plugin_holder = plugin_service.get_by_id(db, "basic_reporting")
        plugin = plugin_holder.loaded_plugin

    mocked_execute = MagicMock()
    mocked_execute.return_value = "success"

    with (
        patch_plugin_options(
            plugin,
            {
                "file_option": {
                    "Name": "file_option",
                    "Description": "File option",
                    "Type": "File",
                    "Strict": False,
                    "Required": True,
                    "DependsOn": None,
                }
            },
        ),
        patch_plugin_execute(plugin, mocked_execute),
    ):
        req = PluginExecutePostRequest(options={"file_option": "9999"})
        with session_local.begin() as db:
            res, err = plugin_service.execute_plugin(db, plugin, req, None)

            assert err is None
            assert res == "success"
            mocked_execute.assert_called_once_with(
                {"file_option": download}, db=db, user=None
            )


# Note this test is not great. If all plugins are overriding the on_start and on_stop
# then it will fail.
def test_on_start_on_stop_called(install_path):
    main_menu_mock = MagicMock()
    main_menu_mock.installPath = install_path

    plugin_service = PluginService(main_menu_mock)
    plugin_service.startup()

    on_start_mock = Mock()
    on_stop_mock = Mock()

    # Need to patch the class itself, not the instance
    # To capture the on_start.
    with patch_plugin_class_on_start_on_stop(
        BasePlugin, on_start=on_start_mock, on_stop=on_stop_mock
    ):
        plugin_service.startup()
        assert on_start_mock.call_count > 0

        plugin_service.shutdown()
        assert on_stop_mock.call_count > 0


# Note this test is not great. If all plugins are overriding the on_load and on_unload
# then it will fail.
def test_on_load_on_unload_called(install_path):
    main_menu_mock = MagicMock()
    main_menu_mock.installPath = install_path

    plugin_service = PluginService(main_menu_mock)
    plugin_service.startup()

    on_load_mock = Mock()
    on_unload_mock = Mock()

    # Need to patch the class itself, not the instance
    # To capture the on_load.
    with patch_plugin_class_on_load_on_unload(
        BasePlugin, on_load=on_load_mock, on_unload=on_unload_mock
    ):
        plugin_service.startup()
        assert on_load_mock.call_count > 0

        plugin_service.shutdown()
        assert on_unload_mock.call_count > 0


@pytest.fixture(scope="module")
def plugin_service(main: "MainMenu"):
    return main.pluginsv2


def test__determine_auto_start(empire_config, plugin_service):
    plugin_info = PluginInfo(
        id="test_auto_start", name="TestAutoStart", auto_start=False, main=""
    )

    empire_config_tmp = empire_config.model_copy()
    empire_config_tmp.plugins["test_auto_start"] = PluginConfig()

    # Test with plugin config False and server config empty
    # Should use plugin config value
    assert plugin_service._determine_auto_start(plugin_info, empire_config_tmp) is False

    # Test with plugin config false and server config true
    # Should use server config value
    empire_config_tmp.plugins["test_auto_start"].auto_start = True
    assert plugin_service._determine_auto_start(plugin_info, empire_config_tmp) is True


def test__determine_auto_execute(empire_config, plugin_service):
    plugin_config = PluginInfo(
        id="test_auto_execute", name="TestAutoExecute", auto_execute=None, main=""
    )

    # Test with plugin config None and server config None
    # Should use default value (None)
    assert plugin_service._determine_auto_execute(plugin_config, empire_config) is None

    # Test with plugin config None and server config true
    # Should use server config value
    empire_config.plugins["test_auto_execute"] = PluginConfig(
        auto_execute=PluginAutoExecuteConfig(enabled=True)
    )
    assert (
        plugin_service._determine_auto_execute(plugin_config, empire_config)
        is empire_config.plugins["test_auto_execute"].auto_execute
    )

    # Test with plugin config true and server_config None
    # Should use plugin config value
    plugin_config.auto_execute = PluginAutoExecuteConfig(enabled=True)
    empire_config.plugins["test_auto_execute"] = PluginConfig(auto_execute=None)
    assert (
        plugin_service._determine_auto_execute(plugin_config, empire_config)
        is plugin_config.auto_execute
    )


def test_plugin_load_exception(install_path, session_local):
    main_menu_mock = MagicMock()
    main_menu_mock.installPath = install_path

    plugin_service = PluginService(main_menu_mock)
    plugin_service.plugin_path = Path(install_path).parent / "test/plugin_install"
    plugin_service.startup()

    with session_local.begin() as db:
        plugin = plugin_service.get_by_id(db, "loadexceptionplugin")

        assert plugin is not None
        assert plugin.db_plugin.load_error == "This plugin is meant to fail to load."
        assert plugin.loaded_plugin is None
