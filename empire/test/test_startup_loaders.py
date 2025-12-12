import sys
from unittest.mock import MagicMock, Mock

from empire.server.core.bypass_service import BypassService
from empire.server.core.listener_template_service import ListenerTemplateService
from empire.server.core.profile_service import ProfileService
from empire.server.core.stager_template_service import StagerTemplateService
from empire.test.conftest import SERVER_CONFIG_LOC


def test_bypass_loader(monkeypatch):
    sys.argv = ["", "server", "--config", SERVER_CONFIG_LOC]
    session_mock = MagicMock()
    monkeypatch.setattr("empire.server.core.bypass_service.SessionLocal", session_mock)

    session_mock.begin.return_value.__enter__.return_value.query.return_value.first.return_value.install_path = "empire/server"

    session_mock.begin.return_value.__enter__.return_value.query.return_value.filter.return_value.first.return_value = None

    main_menu = Mock()
    main_menu.installPath = "empire/server"

    BypassService(main_menu)

    min_call_count = 4
    assert (
        session_mock.begin.return_value.__enter__.return_value.add.call_count
        > min_call_count
    )


def test_listener_template_loader(monkeypatch):
    sys.argv = ["", "server", "--config", SERVER_CONFIG_LOC]
    session_mock = MagicMock()
    monkeypatch.setattr(
        "empire.server.core.listener_template_service.SessionLocal", session_mock
    )

    session_mock.begin.return_value.__enter__.return_value.query.return_value.first.return_value.install_path = "empire/server"

    main_menu = Mock()
    main_menu.installPath = "empire/server"

    listener_template_service = ListenerTemplateService(main_menu)

    min_template_count = 5
    assert len(listener_template_service.get_listener_templates()) > min_template_count


def test_stager_template_loader(monkeypatch):
    sys.argv = ["", "server", "--config", SERVER_CONFIG_LOC]
    session_mock = MagicMock()
    monkeypatch.setattr(
        "empire.server.core.stager_template_service.SessionLocal", session_mock
    )

    session_mock.begin.return_value.__enter__.return_value.query.return_value.first.return_value.install_path = "empire/server"

    main_menu = Mock()
    main_menu.installPath = "empire/server"

    stager_template_service = StagerTemplateService(main_menu)

    min_template_count = 10
    assert len(stager_template_service.get_stager_templates()) > min_template_count


def test_profile_loader(monkeypatch):
    sys.argv = ["", "server", "--config", SERVER_CONFIG_LOC]
    session_mock = MagicMock()
    monkeypatch.setattr("empire.server.core.profile_service.SessionLocal", session_mock)

    session_mock.begin.return_value.__enter__.return_value.query.return_value.first.return_value.install_path = "empire/server"

    session_mock.begin.return_value.__enter__.return_value.query.return_value.filter.return_value.first.return_value = None

    main_menu = Mock()
    main_menu.installPath = "empire/server"

    ProfileService(main_menu)

    min_call_count = 20
    assert (
        session_mock.begin.return_value.__enter__.return_value.add.call_count
        > min_call_count
    )
