from starlette import status


def get_base_listener():
    return {
        "name": "new-listener-1",
        "template": "http",
        "options": {
            "Name": "new-listener-1",
            "Host": "http://localhost",
            "BindIP": "0.0.0.0",
            "Port": "1336",
            "Launcher": "powershell -noP -sta -w 1 -enc ",
            "StagingKey": "2c103f2c4ed1e59c0b4e2e01821770fa",
            "DefaultDelay": "5",
            "DefaultJitter": "0.0",
            "DefaultLostLimit": "60",
            "DefaultProfile": "/admin/get.php,/news.php,/login/process.php|Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko",
            "CertPath": "",
            "KillDate": "",
            "WorkingHours": "",
            "Headers": "Server:Microsoft-IIS/7.5",
            "Cookie": "session",
            "UserAgent": "default",
            "Proxy": "default",
            "ProxyCreds": "default",
            "JA3_Evasion": "False",
        },
    }


def get_base_malleable_listener():
    return {
        "name": "malleable_listener_1",
        "template": "http_malleable",
        "options": {
            "Name": "http_malleable",
            "Host": "http://localhost",
            "BindIP": "0.0.0.0",
            "Port": "1338",
            "Profile": "amazon.profile",
            "Launcher": "powershell -noP -sta -w 1 -enc ",
            "StagingKey": "2c103f2c4ed1e59c0b4e2e01821770fa",
            "DefaultDelay": "5",
            "DefaultJitter": "0.0",
            "DefaultLostLimit": "60",
            "CertPath": "",
            "KillDate": "",
            "WorkingHours": "",
            "Cookie": "",
            "UserAgent": "default",
            "Proxy": "default",
            "ProxyCreds": "default",
            "JA3_Evasion": "False",
        },
    }


def test_get_listener_templates(client, admin_auth_header):
    min_expected_templates = 6
    response = client.get(
        "/api/v2/listener-templates/",
        headers=admin_auth_header,
    )
    assert response.status_code == status.HTTP_200_OK
    assert len(response.json()["records"]) >= min_expected_templates


def test_get_listener_template(client, admin_auth_header):
    response = client.get(
        "/api/v2/listener-templates/http",
        headers=admin_auth_header,
    )
    assert response.status_code == status.HTTP_200_OK
    assert response.json()["name"] == "HTTP[S]"
    assert response.json()["id"] == "http"
    assert isinstance(response.json()["options"], dict)


def test_create_listener_validation_fails_required_field(client, admin_auth_header):
    base_listener = get_base_listener()
    base_listener["name"] = "temp123"
    base_listener["options"]["Port"] = ""
    response = client.post(
        "/api/v2/listeners/", headers=admin_auth_header, json=base_listener
    )
    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert response.json()["detail"] == "required option missing: Port"


# todo there are no listeners with strict fields. need to fake it somehow, or just wait until
#   we have one to worry about testing.
# def test_create_listener_validation_fails_strict_field():
#     listener = get_base_listener()
#     listener['options']['Port'] = ''
#     response = client.post("/api/v2/listeners/", json=listener)
#     assert response.status_code == status.HTTP_400_BAD_REQUEST
#     assert response.json()['detail'] == 'required listener option missing: Port'


def test_create_listener_custom_validation_fails(client, admin_auth_header):
    base_listener = get_base_malleable_listener()
    base_listener["name"] = "temp123"
    base_listener["options"]["Profile"] = "nonexistent.profile"
    response = client.post(
        "/api/v2/listeners/", headers=admin_auth_header, json=base_listener
    )
    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert (
        response.json()["detail"]
        == "[!] Malleable profile not found: nonexistent.profile"
    )


def test_create_listener_template_not_found(client, admin_auth_header):
    base_listener = get_base_listener()
    base_listener["name"] = "temp123"
    base_listener["template"] = "qwerty"

    response = client.post(
        "/api/v2/listeners/", headers=admin_auth_header, json=base_listener
    )
    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert response.json()["detail"] == "Listener Template qwerty not found"


def test_create_listener_normalization_adds_protocol_and_default_port(
    client, admin_auth_header
):
    base_listener = get_base_listener()
    base_listener["name"] = "temp123"
    base_listener["options"]["Host"] = "localhost"
    base_listener["options"]["Port"] = "80"

    response = client.post(
        "/api/v2/listeners/", headers=admin_auth_header, json=base_listener
    )
    assert response.status_code == status.HTTP_201_CREATED
    assert response.json()["host_address"] == "http://localhost/"
    assert response.json()["options"]["Port"] == "80"

    client.delete(
        f"/api/v2/listeners/{response.json()['id']}", headers=admin_auth_header
    )


def test_create_listener_normalization_adds_port_to_host(client, admin_auth_header):
    base_listener = get_base_listener()
    base_listener["name"] = "temp123"
    base_listener["options"]["Host"] = "http://localhost"
    base_listener["options"]["Port"] = "1234"

    response = client.post(
        "/api/v2/listeners/", headers=admin_auth_header, json=base_listener
    )
    assert response.status_code == status.HTTP_201_CREATED
    assert response.json()["host_address"] == "http://localhost:1234/"
    assert response.json()["options"]["Port"] == "1234"

    client.delete(
        f"/api/v2/listeners/{response.json()['id']}", headers=admin_auth_header
    )


def test_create_listener_normalization_preserves_user_defined_ports(
    client, admin_auth_header
):
    base_listener = get_base_listener()
    base_listener["name"] = "temp123"
    base_listener["options"]["Host"] = "http://localhost:443"
    base_listener["options"]["Port"] = "1234"

    response = client.post(
        "/api/v2/listeners/", headers=admin_auth_header, json=base_listener
    )
    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert response.json()["detail"] == "Port cannot be provided in a host name"


def test_create_listener_normalization_sets_host_port_as_bind_port(
    client, admin_auth_header
):
    base_listener = get_base_listener()
    base_listener["name"] = "temp123"
    base_listener["options"]["Host"] = "http://localhost"
    base_listener["options"]["Port"] = "443"

    response = client.post(
        "/api/v2/listeners/", headers=admin_auth_header, json=base_listener
    )
    assert response.status_code == status.HTTP_201_CREATED
    assert response.json()["host_address"] == "http://localhost:443/"

    client.delete(
        f"/api/v2/listeners/{response.json()['id']}", headers=admin_auth_header
    )


def test_create_listener_with_https_host_no_cert_path(client, admin_auth_header):
    # A listener should be able to have a host with https even if the cert path is blank.
    # because the listener might be behind a reverse proxy that handles TLS.
    base_listener = get_base_listener()
    base_listener["name"] = "temp123"
    base_listener["options"]["Host"] = "https://localhost"
    base_listener["options"]["Port"] = "443"
    base_listener["options"]["CertPath"] = ""
    response = client.post(
        "/api/v2/listeners/", headers=admin_auth_header, json=base_listener
    )

    assert response.status_code == status.HTTP_201_CREATED
    assert response.json()["host_address"] == "https://localhost/"
    assert response.json()["options"]["CertPath"] == ""

    client.delete(
        f"/api/v2/listeners/{response.json()['id']}", headers=admin_auth_header
    )


def test_create_listener(client, admin_auth_header):
    base_listener = get_base_listener()
    base_listener["name"] = "temp123"
    base_listener["options"]["Port"] = "1234"

    # test that it ignore extra params
    base_listener["options"]["xyz"] = "xyz"

    response = client.post(
        "/api/v2/listeners/", headers=admin_auth_header, json=base_listener
    )
    assert response.status_code == status.HTTP_201_CREATED
    assert response.json()["options"].get("xyz") is None

    assert response.json()["options"]["Name"] == base_listener["name"]
    assert response.json()["options"]["Port"] == base_listener["options"]["Port"]
    assert (
        response.json()["options"]["DefaultJitter"]
        == base_listener["options"]["DefaultJitter"]
    )
    assert (
        response.json()["options"]["DefaultDelay"]
        == base_listener["options"]["DefaultDelay"]
    )

    client.delete(
        f"/api/v2/listeners/{response.json()['id']}", headers=admin_auth_header
    )


def test_create_listener_name_conflict(client, admin_auth_header):
    base_listener = get_base_listener()
    response = client.post(
        "/api/v2/listeners/", headers=admin_auth_header, json=base_listener
    )
    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert (
        response.json()["detail"]
        == f"Listener with name {base_listener['name']} already exists."
    )


def test_get_listener(client, admin_auth_header, listener):
    response = client.get(
        f"/api/v2/listeners/{listener['id']}",
        headers=admin_auth_header,
    )
    assert response.status_code == status.HTTP_200_OK
    assert response.json()["id"] == listener["id"]


def test_get_listener_not_found(client, admin_auth_header):
    response = client.get(
        "/api/v2/listeners/9999",
        headers=admin_auth_header,
    )
    assert response.status_code == status.HTTP_404_NOT_FOUND
    assert response.json()["detail"] == "Listener not found for id 9999"


def test_update_listener_not_found(client, admin_auth_header):
    base_listener = get_base_listener()
    base_listener["enabled"] = False
    response = client.put(
        "/api/v2/listeners/9999", headers=admin_auth_header, json=base_listener
    )
    assert response.status_code == status.HTTP_404_NOT_FOUND
    assert response.json()["detail"] == "Listener not found for id 9999"


def test_update_listener_blocks_while_enabled(client, admin_auth_header, listener):
    response = client.get(
        f"/api/v2/listeners/{listener['id']}",
        headers=admin_auth_header,
    )
    assert response.json()["enabled"] is True

    response = client.put(
        f"/api/v2/listeners/{listener['id']}",
        headers=admin_auth_header,
        json=response.json(),
    )
    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert response.json()["detail"] == "Listener must be disabled before modifying"


def test_update_listener_allows_and_disables_while_enabled(
    client, admin_auth_header, listener
):
    response = client.get(
        f"/api/v2/listeners/{listener['id']}",
        headers=admin_auth_header,
    )
    assert response.json()["enabled"] is True

    listener = response.json()
    listener["enabled"] = False
    new_delay = str(int(listener["options"]["DefaultDelay"]) + 1)
    listener["options"]["DefaultDelay"] = new_delay
    response = client.put(
        f"/api/v2/listeners/{listener['id']}",
        headers=admin_auth_header,
        json=listener,
    )
    assert response.status_code == status.HTTP_200_OK
    assert response.json()["enabled"] is False
    assert response.json()["options"]["DefaultDelay"] == new_delay


def test_update_listener_allows_while_disabled(client, admin_auth_header, listener):
    original_name = listener["name"]
    response = client.get(
        f"/api/v2/listeners/{listener['id']}", headers=admin_auth_header
    )
    assert response.json()["enabled"] is False

    listener = response.json()
    new_delay = str(int(listener["options"]["DefaultDelay"]) + 1)
    listener["options"]["DefaultDelay"] = new_delay
    # test that it ignore extra params
    listener["options"]["xyz"] = "xyz"

    listener["name"] = "new-name"

    response = client.put(
        f"/api/v2/listeners/{listener['id']}",
        headers=admin_auth_header,
        json=listener,
    )
    assert response.status_code == status.HTTP_200_OK
    assert response.json()["enabled"] is False
    assert response.json()["options"]["DefaultDelay"] == new_delay
    assert response.json()["options"].get("xyz") is None
    assert response.json()["options"]["Name"] == "new-name"
    assert response.json()["name"] == "new-name"

    listener["name"] = original_name
    client.put(
        f"/api/v2/listeners/{listener['id']}",
        headers=admin_auth_header,
        json=listener,
    )


def test_update_listener_name_conflict(client, admin_auth_header):
    base_listener = get_base_listener()
    # Create a second listener.
    base_listener["name"] = "new-listener-2"
    base_listener["options"]["Port"] = "1299"
    response = client.post(
        "/api/v2/listeners/", headers=admin_auth_header, json=base_listener
    )
    assert response.status_code == status.HTTP_201_CREATED

    created = response.json()
    created["enabled"] = False
    response = client.put(
        f"/api/v2/listeners/{created['id']}",
        headers=admin_auth_header,
        json=created,
    )
    assert response.status_code == status.HTTP_200_OK

    created["name"] = "new-listener-1"
    response = client.put(
        f"/api/v2/listeners/{created['id']}",
        headers=admin_auth_header,
        json=created,
    )

    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert (
        response.json()["detail"] == "Listener with name new-listener-1 already exists."
    )


def test_update_listener_reverts_if_validation_fails(
    client, admin_auth_header, listener
):
    response = client.get(
        f"/api/v2/listeners/{listener['id']}",
        headers=admin_auth_header,
    )
    assert response.json()["enabled"] is False

    listener = response.json()
    listener["options"]["DefaultJitter"] = "Invalid"
    listener["options"]["BindIP"] = "1.1.1.1"
    response = client.put(
        f"/api/v2/listeners/{listener['id']}",
        headers=admin_auth_header,
        json=listener,
    )
    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert (
        response.json()["detail"]
        == "incorrect type for option DefaultJitter. Expected <class 'float'> but got <class 'str'>"
    )

    response = client.get(
        f"/api/v2/listeners/{listener['id']}", headers=admin_auth_header
    )
    assert response.json()["options"]["BindIP"] == "0.0.0.0"


def test_update_listener_reverts_if_custom_validation_fails(
    client, admin_auth_header, listener_malleable
):
    listener_malleable["enabled"] = False
    response = client.put(
        f"/api/v2/listeners/{listener_malleable['id']}",
        headers=admin_auth_header,
        json=listener_malleable,
    )
    assert response.status_code == status.HTTP_200_OK
    assert response.json()["enabled"] is False

    response = client.get(
        f"/api/v2/listeners/{listener_malleable['id']}",
        headers=admin_auth_header,
    )
    assert response.json()["enabled"] is False

    listener_malleable = response.json()
    listener_malleable["options"]["Profile"] = "nonexistent.profile"
    response = client.put(
        f"/api/v2/listeners/{listener_malleable['id']}",
        headers=admin_auth_header,
        json=listener_malleable,
    )
    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert (
        response.json()["detail"]
        == "[!] Malleable profile not found: nonexistent.profile"
    )

    response = client.get(
        f"/api/v2/listeners/{listener_malleable['id']}",
        headers=admin_auth_header,
    )
    assert response.json()["options"]["Profile"] == "amazon.profile"

    listener_malleable["options"]["Profile"] = "amazon.profile"
    listener_malleable["enabled"] = True
    response = client.put(
        f"/api/v2/listeners/{listener_malleable['id']}",
        headers=admin_auth_header,
        json=listener_malleable,
    )

    assert response.status_code == status.HTTP_200_OK


def test_update_listener_allows_and_enables_while_disabled(
    client, admin_auth_header, listener
):
    response = client.get(
        f"/api/v2/listeners/{listener['id']}",
        headers=admin_auth_header,
    )
    assert response.json()["enabled"] is False

    listener = response.json()
    new_delay = str(int(listener["options"]["DefaultDelay"]) + 1)
    listener["enabled"] = True
    listener["options"]["DefaultDelay"] = new_delay
    response = client.put(
        f"/api/v2/listeners/{listener['id']}",
        headers=admin_auth_header,
        json=listener,
    )
    assert response.status_code == status.HTTP_200_OK
    assert response.json()["enabled"] is True
    assert response.json()["options"]["DefaultDelay"] == new_delay


def test_get_listeners(client, admin_auth_header):
    response = client.get("/api/v2/listeners", headers=admin_auth_header)

    assert response.status_code == status.HTTP_200_OK
    assert len(response.json()["records"]) > 0


def test_delete_listener_while_enabled(client, admin_auth_header):
    to_delete = get_base_listener()
    to_delete["name"] = "to-delete"
    to_delete["options"]["Port"] = "1299"
    response = client.post(
        "/api/v2/listeners/", headers=admin_auth_header, json=to_delete
    )
    assert response.status_code == status.HTTP_201_CREATED
    to_delete_id = response.json()["id"]

    response = client.delete(
        f"/api/v2/listeners/{to_delete_id}", headers=admin_auth_header
    )
    assert response.status_code == status.HTTP_204_NO_CONTENT

    response = client.get(
        f"/api/v2/listeners/{to_delete_id}", headers=admin_auth_header
    )

    assert response.status_code == status.HTTP_404_NOT_FOUND


def test_delete_listener_while_disabled(client, admin_auth_header):
    to_delete = get_base_listener()
    to_delete["name"] = "to-delete"
    to_delete["options"]["Port"] = "1298"

    response = client.post(
        "/api/v2/listeners/", headers=admin_auth_header, json=to_delete
    )
    assert response.status_code == status.HTTP_201_CREATED
    to_delete_id = response.json()["id"]

    response = client.delete(
        f"/api/v2/listeners/{to_delete_id}", headers=admin_auth_header
    )
    assert response.status_code == status.HTTP_204_NO_CONTENT

    response = client.get(
        f"/api/v2/listeners/{to_delete_id}", headers=admin_auth_header
    )
    assert response.status_code == status.HTTP_404_NOT_FOUND


def test_update_listener_autorun(client, admin_auth_header, listener):
    autorun_tasks = [
        {
            "module_id": "bof_situational_awareness_whoami",
            "ignore_language_version_check": False,
            "ignore_admin_check": False,
            "options": {"Architecture": "x64"},
            "modified_input": None,
        }
    ]

    response = client.put(
        f"/api/v2/listeners/{listener['id']}/autorun",
        headers=admin_auth_header,
        json={"records": autorun_tasks},
    )

    assert response.status_code == status.HTTP_200_OK

    response = client.get(
        f"/api/v2/listeners/{listener['id']}/autorun",
        headers=admin_auth_header,
    )

    assert response.status_code == status.HTTP_200_OK
    assert response.json() == {"records": autorun_tasks}


def test_update_listener_autorun_invalid(client, admin_auth_header, listener):
    autorun_tasks = [
        {
            "module_id": None,
            "ignore_language_version_check": False,
            "ignore_admin_check": False,
            "options": {"Architecture": "x64"},
            "modified_input": None,
        }
    ]

    response = client.put(
        f"/api/v2/listeners/{listener['id']}/autorun",
        headers=admin_auth_header,
        json={"records": autorun_tasks},
    )

    assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY
    assert "detail" in response.json()
