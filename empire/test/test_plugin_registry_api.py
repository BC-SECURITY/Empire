from contextlib import contextmanager
from typing import TYPE_CHECKING
from unittest.mock import ANY, Mock

import pytest
from starlette import status

if TYPE_CHECKING:
    from empire.server.common.empire import MainMenu


@pytest.fixture(scope="module")
def plugin_service(main: "MainMenu"):
    return main.pluginsv2


@pytest.fixture(scope="module")
def plugin_registry_service(main: "MainMenu"):
    return main.pluginregistriesv2


def test_get_marketplace(client, admin_auth_header):
    response = client.get(
        "/api/v2/plugin-registries/marketplace", headers=admin_auth_header
    )
    assert response.status_code == status.HTTP_200_OK

    marketplace = response.json()
    assert len(marketplace["records"]) > 0

    slack = marketplace["records"][0]
    assert slack["name"] == "slack"
    assert "BC-SECURITY" in slack["registries"]
    assert "BC-SECURITY-TEST" in slack["registries"]


def test_install_plugin_plugin_not_found(client, admin_auth_header):
    response = client.post(
        "/api/v2/plugin-registries/marketplace/install",
        json={"name": "not-a-plugin", "version": "1.0", "registry": "BC-SECURITY"},
        headers=admin_auth_header,
    )
    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert response.json() == {"detail": "Plugin not found in marketplace"}


@contextmanager
def patch_installed_plugin(plugin_name, session_local, models):
    with session_local.begin() as db:
        db.add(models.Plugin(id=plugin_name, name=plugin_name, enabled=True))

    yield

    with session_local.begin() as db:
        db.query(models.Plugin).filter(models.Plugin.id == plugin_name).delete()


def test_install_plugin_plugin_already_installed(
    client, admin_auth_header, session_local, models
):
    with patch_installed_plugin("slack", session_local, models):
        response = client.post(
            "/api/v2/plugin-registries/marketplace/install",
            json={"name": "slack", "version": "1.0.0", "registry": "BC-SECURITY"},
            headers=admin_auth_header,
        )
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert response.json() == {"detail": "Plugin already installed"}


def test_install_plugin_registry_not_found(client, admin_auth_header):
    response = client.post(
        "/api/v2/plugin-registries/marketplace/install",
        json={"name": "slack", "version": "1.0", "registry": "not-a-registry"},
        headers=admin_auth_header,
    )
    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert response.json() == {"detail": "Plugin not found in registry"}


def test_install_plugin_version_not_found(client, admin_auth_header):
    response = client.post(
        "/api/v2/plugin-registries/marketplace/install",
        json={"name": "slack", "version": "not-a-version", "registry": "BC-SECURITY"},
        headers=admin_auth_header,
    )
    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert response.json() == {"detail": "Version not found in plugin"}


@contextmanager
def patch_install_plugin_from_git(plugin_service):
    mock = Mock()
    original = plugin_service.install_plugin_from_git
    plugin_service.install_plugin_from_git = mock

    yield mock

    plugin_service.install_plugin_from_git = original


class IsDict:  # noqa: PLW1641
    def __eq__(self, other):
        return isinstance(other, dict)


def test_install_plugin_git(client, admin_auth_header, plugin_service):
    with patch_install_plugin_from_git(plugin_service) as mock:
        response = client.post(
            "/api/v2/plugin-registries/marketplace/install",
            json={"name": "slack", "version": "1.0.0", "registry": "BC-SECURITY"},
            headers=admin_auth_header,
        )
        assert response.status_code == status.HTTP_200_OK

        # db: Session,
        # git_url: str,
        # subdir: str | None = None,
        # ref: str | None = None,
        # version_name: str | None = None,
        # registry_data: dict | None = None,
        mock.assert_called_once_with(
            ANY,
            "https://github.com/bc-security/slack-plugin",
            None,
            "v1.0.0",
            "1.0.0",
            IsDict(),
        )


@contextmanager
def patch_install_plugin_from_tar(plugin_service):
    mock = Mock()
    original = plugin_service.install_plugin_from_tar
    plugin_service.install_plugin_from_tar = mock

    yield mock

    plugin_service.install_plugin_from_tar = original


def test_install_plugin_tar(client, admin_auth_header, plugin_service):
    with patch_install_plugin_from_tar(plugin_service) as mock:
        response = client.post(
            "/api/v2/plugin-registries/marketplace/install",
            json={"name": "slack", "version": "1.0.0", "registry": "BC-SECURITY-TEST"},
            headers=admin_auth_header,
        )
        assert response.status_code == status.HTTP_200_OK

        # db: Session,
        # tar_url: str,
        # subdir: str | None = None,
        # version_name: str | None = None,
        # registry_data: dict | None = None,
        mock.assert_called_once_with(
            ANY,
            "https://github.com/bc-security/slack-other/releases/download/v1.0.0/slack.tar.gz",
            None,
            "1.0.0",
            IsDict(),
        )
