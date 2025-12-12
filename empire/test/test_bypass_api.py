from starlette import status


def test_get_bypass_not_found(client, admin_auth_header):
    response = client.get("/api/v2/bypasses/9999", headers=admin_auth_header)

    assert response.status_code == status.HTTP_404_NOT_FOUND
    assert response.json()["detail"] == "Bypass not found for id 9999"


def test_get_bypass(client, admin_auth_header):
    response = client.get("/api/v2/bypasses/1", headers=admin_auth_header)

    assert response.status_code == status.HTTP_200_OK
    assert response.json()["id"] == 1
    assert len(response.json()["code"]) > 0


def test_get_bypasses(client, admin_auth_header):
    response = client.get("/api/v2/bypasses", headers=admin_auth_header)

    assert response.status_code == status.HTTP_200_OK
    assert len(response.json()["records"]) > 0


def test_create_bypass_name_conflict(client, admin_auth_header):
    response = client.post(
        "/api/v2/bypasses/",
        headers=admin_auth_header,
        json={"name": "mattifestation", "code": "x=0;", "language": "powershell"},
    )

    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert (
        response.json()["detail"] == "Bypass with name mattifestation already exists."
    )


def test_create_bypass(client, admin_auth_header):
    response = client.post(
        "/api/v2/bypasses/",
        headers=admin_auth_header,
        json={"name": "Test Bypass", "code": "x=0;", "language": "powershell"},
    )

    assert response.status_code == status.HTTP_201_CREATED
    assert response.json()["name"] == "Test Bypass"
    assert response.json()["code"] == "x=0;"


def test_update_bypass_not_found(client, admin_auth_header):
    response = client.put(
        "/api/v2/bypasses/9999",
        headers=admin_auth_header,
        json={"name": "Test Bypass", "code": "x=0;"},
    )

    assert response.status_code == status.HTTP_404_NOT_FOUND
    assert response.json()["detail"] == "Bypass not found for id 9999"


def test_update_bypass_name_conflict(client, admin_auth_header):
    response = client.get("/api/v2/bypasses/1", headers=admin_auth_header)
    bypass_1_name = response.json()["name"]

    response = client.put(
        "/api/v2/bypasses/5",
        headers=admin_auth_header,
        json={"name": bypass_1_name, "code": "x=0;", "language": "powershell"},
    )

    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert (
        response.json()["detail"] == f"Bypass with name {bypass_1_name} already exists."
    )


def test_update_bypass(client, admin_auth_header):
    response = client.put(
        "/api/v2/bypasses/1",
        headers=admin_auth_header,
        json={"name": "Updated Bypass", "code": "x=1;", "language": "powershell"},
    )

    assert response.json()["name"] == "Updated Bypass"
    assert response.json()["code"] == "x=1;"


def test_delete_bypass(client, admin_auth_header):
    response = client.delete("/api/v2/bypasses/1", headers=admin_auth_header)

    assert response.status_code == status.HTTP_204_NO_CONTENT

    response = client.get("/api/v2/bypasses/1", headers=admin_auth_header)

    assert response.status_code == status.HTTP_404_NOT_FOUND


def test_reset_bypasses(client, admin_auth_header):
    response = client.post("/api/v2/bypasses/reset", headers=admin_auth_header)
    assert response.status_code == status.HTTP_204_NO_CONTENT

    initial_response = client.get("/api/v2/bypasses", headers=admin_auth_header)
    initial_bypasses = initial_response.json()["records"]

    response = client.post(
        "/api/v2/bypasses",
        headers=admin_auth_header,
        json={"name": "Test Bypass", "code": "x=0;", "language": "powershell"},
    )
    assert response.status_code == status.HTTP_201_CREATED

    response = client.post("/api/v2/bypasses/reset", headers=admin_auth_header)
    assert response.status_code == status.HTTP_204_NO_CONTENT

    final_response = client.get("/api/v2/bypasses", headers=admin_auth_header)
    final_bypasses = final_response.json()["records"]

    assert len(initial_bypasses) == len(final_bypasses)


def test_reload_bypasses(client, admin_auth_header):
    response = client.post(
        "/api/v2/bypasses",
        headers=admin_auth_header,
        json={"name": "Test Bypass", "code": "x=0;", "language": "powershell"},
    )
    assert response.status_code == status.HTTP_201_CREATED
    new_bypass_id = response.json()["id"]

    initial_response = client.get("/api/v2/bypasses", headers=admin_auth_header)
    initial_bypasses = initial_response.json()["records"]

    response = client.post("/api/v2/bypasses/reload", headers=admin_auth_header)
    assert response.status_code == status.HTTP_204_NO_CONTENT

    final_response = client.get("/api/v2/bypasses", headers=admin_auth_header)
    final_bypasses = final_response.json()["records"]

    assert len(initial_bypasses) == len(final_bypasses)
    assert any(bypass["id"] == new_bypass_id for bypass in final_bypasses)


def test_bypass_defaults(client, admin_auth_header):
    r = client.get("/api/v2/bypasses", headers=admin_auth_header)
    assert r.status_code == status.HTTP_200_OK
    records = r.json()["records"]

    default_names = sorted([b["name"] for b in records if b["is_default"]])
    assert set(default_names) == {"etw", "mattifestation"}
    assert all(
        (b["name"] in {"etw", "mattifestation"}) == b["is_default"] for b in records
    )
