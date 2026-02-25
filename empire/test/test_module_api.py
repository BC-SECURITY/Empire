from starlette import status


def test_get_module_not_found(client, admin_auth_header):
    response = client.get("/api/v2/modules/some_module", headers=admin_auth_header)

    assert response.status_code == status.HTTP_404_NOT_FOUND
    assert response.json()["detail"] == "Module not found for id some_module"


def test_get_module(client, admin_auth_header):
    uid = "python_trollsploit_osx_say"
    response = client.get(f"/api/v2/modules/{uid}", headers=admin_auth_header)

    assert response.status_code == status.HTTP_200_OK
    assert response.json()["id"] == uid
    assert response.json()["name"] == "Say"


def test_get_module_script_module_not_found(client, admin_auth_header):
    uid = "this_module_does_not_exist"
    response = client.get(f"/api/v2/modules/{uid}/script", headers=admin_auth_header)

    assert response.status_code == status.HTTP_404_NOT_FOUND
    assert response.json()["detail"] == f"Module not found for id {uid}"


def test_get_module_script_in_yaml(client, admin_auth_header):
    uid = "python_trollsploit_osx_say"
    response = client.get(f"/api/v2/modules/{uid}/script", headers=admin_auth_header)

    assert response.status_code == status.HTTP_200_OK
    assert response.json()["module_id"] == uid
    assert response.json()["script"].startswith(
        "run_command('say -v {{ Voice }} {{ Text }}')"
    )


def test_get_module_script_in_path(client, admin_auth_header):
    uid = "powershell_code_execution_invoke_boolang"
    response = client.get(f"/api/v2/modules/{uid}/script", headers=admin_auth_header)

    assert response.status_code == status.HTTP_200_OK
    assert response.json()["module_id"] == uid
    assert response.json()["script"].startswith("function Invoke-Boolang")


def test_get_module_script_in_generate_function(client, admin_auth_header):
    uid = "python_collection_osx_imessage_dump"
    response = client.get(f"/api/v2/modules/{uid}/script", headers=admin_auth_header)

    assert response.status_code == status.HTTP_404_NOT_FOUND
    assert response.json()["detail"] == f"Module script not found for id {uid}"


def test_get_modules(client, admin_auth_header):
    min_expected_modules = 383
    response = client.get("/api/v2/modules/", headers=admin_auth_header)

    assert response.status_code == status.HTTP_200_OK

    assert len(response.json()["records"]) >= min_expected_modules


def test_get_modules_hide_disabled(client, admin_auth_header):
    uid = "python_trollsploit_osx_say"

    response = client.put(
        f"/api/v2/modules/{uid}", headers=admin_auth_header, json={"enabled": False}
    )
    assert response.status_code == status.HTTP_200_OK

    # Without hide_disabled, module should be present
    response = client.get("/api/v2/modules/", headers=admin_auth_header)
    assert response.status_code == status.HTTP_200_OK
    module_ids = [m["id"] for m in response.json()["records"]]
    assert uid in module_ids

    # With hide_disabled=false, module should still be present
    response = client.get(
        "/api/v2/modules/?hide_disabled=false", headers=admin_auth_header
    )
    assert response.status_code == status.HTTP_200_OK
    module_ids = [m["id"] for m in response.json()["records"]]
    assert uid in module_ids

    # With hide_disabled=true, module should be hidden
    response = client.get(
        "/api/v2/modules/?hide_disabled=true", headers=admin_auth_header
    )
    assert response.status_code == status.HTTP_200_OK
    module_ids = [m["id"] for m in response.json()["records"]]
    assert uid not in module_ids

    # Re-enable the module
    response = client.put(
        f"/api/v2/modules/{uid}", headers=admin_auth_header, json={"enabled": True}
    )
    assert response.status_code == status.HTTP_200_OK


def test_update_module(client, admin_auth_header):
    uid = "python_trollsploit_osx_say"
    response = client.put(
        f"/api/v2/modules/{uid}", headers=admin_auth_header, json={"enabled": False}
    )

    assert response.status_code == status.HTTP_200_OK

    response = client.get(f"/api/v2/modules/{uid}", headers=admin_auth_header)

    assert response.status_code == status.HTTP_200_OK
    assert response.json()["enabled"] is False

    response = client.put(
        f"/api/v2/modules/{uid}", headers=admin_auth_header, json={"enabled": True}
    )

    assert response.status_code == status.HTTP_200_OK
    assert response.json()["enabled"] is True


def test_update_modules_bulk(client, admin_auth_header):
    uids = [
        "python_trollsploit_osx_say",
        "powershell_code_execution_invoke_boolang",
        "powershell_code_execution_invoke_ironpython",
    ]
    response = client.put(
        "/api/v2/modules/bulk/enable",
        headers=admin_auth_header,
        json={
            "enabled": False,
            "modules": uids,
        },
    )

    assert response.status_code == status.HTTP_204_NO_CONTENT

    for uid in uids:
        response = client.get(f"/api/v2/modules/{uid}", headers=admin_auth_header)

        assert response.status_code == status.HTTP_200_OK
        assert response.json()["enabled"] is False

    response = client.put(
        "/api/v2/modules/bulk/enable",
        headers=admin_auth_header,
        json={
            "enabled": True,
            "modules": uids,
        },
    )

    assert response.status_code == status.HTTP_204_NO_CONTENT


def test_reset_modules(client, admin_auth_header):
    initial_response = client.get("/api/v2/modules", headers=admin_auth_header)
    initial_modules = initial_response.json()["records"]

    uid = "python_trollsploit_osx_say"
    response = client.put(
        f"/api/v2/modules/{uid}", headers=admin_auth_header, json={"enabled": False}
    )
    assert response.status_code == status.HTTP_200_OK

    response = client.post("/api/v2/modules/reset", headers=admin_auth_header)
    assert response.status_code == status.HTTP_204_NO_CONTENT

    final_response = client.get("/api/v2/modules", headers=admin_auth_header)
    final_modules = final_response.json()["records"]

    assert len(initial_modules) == len(final_modules)

    response = client.get(f"/api/v2/modules/{uid}", headers=admin_auth_header)
    assert response.json()["enabled"] is True


def test_reload_modules(client, admin_auth_header):
    uid = "python_trollsploit_osx_say"
    response = client.put(
        f"/api/v2/modules/{uid}", headers=admin_auth_header, json={"enabled": False}
    )
    assert response.status_code == status.HTTP_200_OK

    initial_response = client.get("/api/v2/modules", headers=admin_auth_header)
    initial_modules = initial_response.json()["records"]

    response = client.post("/api/v2/modules/reload", headers=admin_auth_header)
    assert response.status_code == status.HTTP_204_NO_CONTENT

    final_response = client.get("/api/v2/modules", headers=admin_auth_header)
    final_modules = final_response.json()["records"]

    assert len(initial_modules) == len(final_modules)

    response = client.get(f"/api/v2/modules/{uid}", headers=admin_auth_header)
    assert response.json()["enabled"] is False

    # Adding a reset here, so it doesn't break other tests in test_module_service
    response = client.post("/api/v2/modules/reset", headers=admin_auth_header)
    assert response.status_code == status.HTTP_204_NO_CONTENT
