from pathlib import Path

import pytest
from starlette import status

from empire.server.common.helpers import random_string


@pytest.fixture
def test_user_credentials():
    username = f"regular-user-{random_string(4)}"
    password = random_string(12)
    return {"username": username, "password": password}


@pytest.fixture
def test_user_id(client, admin_auth_header, test_user_credentials):
    """Module-scoped fixture that creates a non-admin test user and returns the user ID"""
    response = client.post(
        "/api/v2/users/",
        headers=admin_auth_header,
        json={
            "username": test_user_credentials["username"],
            "password": test_user_credentials["password"],
            "is_admin": False,
        },
    )

    assert response.status_code == status.HTTP_201_CREATED
    user_data = response.json()
    return user_data["id"]


@pytest.fixture
def test_user_auth_token(client, test_user_id, test_user_credentials):
    """Module-scoped fixture that provides auth token for the test user"""
    response = client.post(
        "/token",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        data={
            "grant_type": "password",
            "username": test_user_credentials["username"],
            "password": test_user_credentials["password"],
        },
    )

    assert response.status_code == status.HTTP_200_OK
    return response.json()["access_token"]


@pytest.fixture
def test_user_auth_header(test_user_auth_token):
    """Module-scoped fixture that provides Authorization header for the test user"""
    return {"X-Empire-Token": f"Bearer {test_user_auth_token}"}


def test_create_user(client, admin_auth_header):
    response = client.post(
        "/api/v2/users/",
        headers=admin_auth_header,
        json={"username": "another-user", "password": "hunter2", "is_admin": False},
    )

    assert response.status_code == status.HTTP_201_CREATED
    assert response.json()["username"] == "another-user"


def test_create_user_name_conflict(client, admin_auth_header):
    response = client.post(
        "/api/v2/users/",
        headers=admin_auth_header,
        json={"username": "empireadmin", "password": "password", "is_admin": False},
    )

    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert response.json()["detail"] == "A user with name empireadmin already exists."


def test_create_user_not_an_admin(client, test_user_auth_header):
    response = client.post(
        "/api/v2/users/",
        headers=test_user_auth_header,
        json={"username": "vinnybod2", "password": "hunter2", "admin": False},
    )

    assert response.status_code == status.HTTP_403_FORBIDDEN
    assert response.json()["detail"] == "Not an admin user"


def test_get_user_not_found(client, admin_auth_header):
    response = client.get("/api/v2/users/9999", headers=admin_auth_header)

    assert response.status_code == status.HTTP_404_NOT_FOUND
    assert response.json()["detail"] == "User not found for id 9999"


def test_get_user(client, admin_auth_header):
    response = client.get("/api/v2/users/1", headers=admin_auth_header)

    assert response.status_code == status.HTTP_200_OK
    assert response.json()["id"] == 1
    assert response.json()["username"] == "empireadmin"


def test_get_me(client, test_user_auth_header, test_user_credentials):
    response = client.get(
        "/api/v2/users/me",
        headers=test_user_auth_header,
    )

    assert response.status_code == status.HTTP_200_OK
    assert response.json()["username"] == test_user_credentials["username"]


def test_update_user_not_found(client, admin_auth_header):
    response = client.put(
        "/api/v2/users/9999",
        headers=admin_auth_header,
        json={"username": "not-gonna-happen", "enabled": False, "is_admin": False},
    )

    assert response.status_code == status.HTTP_404_NOT_FOUND
    assert response.json()["detail"] == "User not found for id 9999"


def test_update_user_as_admin(client, admin_auth_header):
    user_id = 2
    response = client.put(
        f"/api/v2/users/{user_id}",
        headers=admin_auth_header,
        json={"username": "empireadmin-2.0", "enabled": True, "is_admin": False},
    )

    assert response.status_code == status.HTTP_200_OK
    assert response.json()["id"] == user_id
    assert response.json()["username"] == "empireadmin-2.0"


def test_update_user_as_not_admin_not_me(client, test_user_auth_header):
    response = client.put(
        "/api/v2/users/1",
        headers=test_user_auth_header,
        json={"username": "regular-user", "enabled": True, "is_admin": False},
    )

    assert response.status_code == status.HTTP_403_FORBIDDEN
    assert (
        response.json()["detail"]
        == "User does not have access to update this resource."
    )


def test_update_user_as_not_admin_me(client, test_user_auth_header, test_user_id):
    response = client.put(
        f"/api/v2/users/{test_user_id}",
        headers=test_user_auth_header,
        json={"username": "xyz", "enabled": True, "is_admin": True},
    )

    assert response.status_code == status.HTTP_403_FORBIDDEN
    assert (
        response.json()["detail"] == "User does not have access to update admin status."
    )


def test_update_user_password_not_me(client, test_user_auth_header):
    response = client.put(
        "/api/v2/users/1/password",
        headers=test_user_auth_header,
        json={"password": "QWERTY"},
    )

    assert response.status_code == status.HTTP_403_FORBIDDEN
    assert (
        response.json()["detail"]
        == "User does not have access to update this resource."
    )


def test_update_user_password(client, test_user_credentials, test_user_id):
    response = client.post(
        "/token",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        data={
            "grant_type": "password",
            "username": test_user_credentials["username"],
            "password": test_user_credentials["password"],
        },
    )

    response = client.put(
        f"/api/v2/users/{test_user_id}/password",
        headers={"Authorization": f"Bearer {response.json()['access_token']}"},
        json={"password": "QWERTY"},
    )

    assert response.status_code == status.HTTP_200_OK

    response = client.post(
        "/token",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        data={
            "grant_type": "password",
            "username": test_user_credentials["username"],
            "password": "QWERTY",
        },
    )

    assert response.status_code == status.HTTP_200_OK


def test_upload_user_avatar_not_me(client, test_user_auth_header):
    response = client.post(
        "/api/v2/users/1/avatar",
        headers=test_user_auth_header,
        files={
            "file": (
                "avatar.png",
                Path("./empire/test/avatar.png").read_bytes(),
            )
        },
    )

    assert response.status_code == status.HTTP_403_FORBIDDEN
    assert (
        response.json()["detail"]
        == "User does not have access to update this resource."
    )


def test_upload_user_avatar_not_image(client, admin_auth_header):
    response = client.post(
        "/api/v2/users/1/avatar",
        headers=admin_auth_header,
        files={
            "file": (
                "test-upload.yaml",
                Path("./empire/test/test-upload.yaml").read_bytes(),
            )
        },
    )

    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert response.json()["detail"] == "File must be an image."


def test_upload_user_avatar(client, admin_auth_header):
    response = client.post(
        "/api/v2/users/1/avatar",
        headers=admin_auth_header,
        files={
            "file": (
                "avatar.png",
                Path("./empire/test/avatar.png").read_bytes(),
            )
        },
    )

    assert response.status_code == status.HTTP_201_CREATED

    response = client.get("/api/v2/users/1", headers=admin_auth_header)

    assert response.status_code == status.HTTP_200_OK

    avatar = response.json()["avatar"]
    first_avatar_id = avatar["id"]
    assert first_avatar_id > 0
    assert avatar["filename"] == "avatar.png"
    assert avatar["link"] == f"/api/v2/downloads/{first_avatar_id}/download"

    # Upload a second image to see if it replaces the first
    response = client.post(
        "/api/v2/users/1/avatar",
        headers=admin_auth_header,
        files={
            "file": (
                "avatar2.png",
                Path("./empire/test/avatar2.png").read_bytes(),
            )
        },
    )

    assert response.status_code == status.HTTP_201_CREATED

    response = client.get("/api/v2/users/1", headers=admin_auth_header)

    assert response.status_code == status.HTTP_200_OK

    avatar = response.json()["avatar"]
    assert avatar["id"] != first_avatar_id
    assert avatar["filename"] == "avatar2.png"
    assert avatar["link"] == f"/api/v2/downloads/{avatar['id']}/download"
