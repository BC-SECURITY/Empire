import base64
import re

import pytest
from starlette import status


def get_base_stager():
    return {
        "name": "MyStager",
        "template": "multi_launcher",
        "options": {
            "Listener": "new-listener-1",
            "Language": "powershell",
            "StagerRetries": "0",
            "OutFile": "",
            "Base64": "True",
            "Obfuscate": "False",
            "ObfuscateCommand": "Token\\All\\1",
            "SafeChecks": "True",
            "UserAgent": "default",
            "Proxy": "default",
            "ProxyCreds": "default",
            "Bypasses": "mattifestation etw",
        },
    }


def get_base_stager_dll():
    return {
        "name": "MyStager2",
        "template": "windows_dll",
        "options": {
            "Listener": "new-listener-1",
            "Language": "powershell",
            "StagerRetries": "0",
            "Arch": "x86",
            "OutFile": "my-windows-dll.dll",
            "Base64": "True",
            "Obfuscate": "False",
            "ObfuscateCommand": "Token\\All\\1",
            "SafeChecks": "True",
            "UserAgent": "default",
            "Proxy": "default",
            "ProxyCreds": "default",
            "Bypasses": "mattifestation etw",
        },
    }


def get_base_stager_malleable():
    return {
        "name": "MyStager",
        "template": "multi_launcher",
        "options": {
            "Listener": "malleable_listener_1",
            "Language": "powershell",
            "StagerRetries": "0",
            "OutFile": "",
            "Base64": "True",
            "Obfuscate": "False",
            "ObfuscateCommand": "Token\\All\\1",
            "SafeChecks": "True",
            "UserAgent": "default",
            "Proxy": "default",
            "ProxyCreds": "default",
            "Bypasses": "mattifestation etw",
        },
    }


def get_bat_stager():
    return {
        "name": "bat_stager",
        "template": "windows_launcher_bat",
        "options": {
            "Listener": "new-listener-1",
            "Language": "powershell",
            "OutFile": "my-bat.bat",
            "Obfuscate": "False",
            "ObfuscateCommand": "Token\\All\\1",
            "Bypasses": "mattifestation etw",
        },
    }


def get_windows_macro_stager():
    return {
        "name": "macro_stager",
        "template": "windows_macro",
        "options": {
            "Listener": "new-listener-1",
            "Language": "powershell",
            "DocumentType": "word",
            "Trigger": "autoopen",
            "OutFile": "document_macro.txt",
            "Obfuscate": "False",
            "ObfuscateCommand": "Token\\All\\1",
            "Bypasses": "mattifestation etw",
            "SafeChecks": "True",
        },
    }


def get_pyinstaller_stager():
    return {
        "name": "MyStager3",
        "template": "linux_pyinstaller",
        "options": {
            "Listener": "new-listener-1",
            "Language": "python",
            "OutFile": "empire",
            "SafeChecks": "True",
            "UserAgent": "default",
        },
    }


def get_base_csharp_exe_stager():
    return {
        "name": "CSharpExeStager",
        "template": "windows_csharp_exe",
        "options": {
            "Listener": "new-listener-1",
            "Language": "csharp",
            "DotNetVersion": "net40",
            "StagerRetries": "0",
            "OutFile": "Sharpire.exe",
            "Obfuscate": "False",
            "ObfuscateCommand": "Token\\All\\1",
            "UserAgent": "default",
            "Proxy": "default",
            "ProxyCreds": "default",
            "Bypasses": "mattifestation etw",
            "Staged": "True",
        },
    }


def test_get_stager_templates(client, admin_auth_header):
    min_stagers = 30
    response = client.get(
        "/api/v2/stager-templates/",
        headers=admin_auth_header,
    )
    assert response.status_code == status.HTTP_200_OK
    assert len(response.json()["records"]) == min_stagers


def test_get_stager_template(client, admin_auth_header):
    response = client.get(
        "/api/v2/stager-templates/multi_launcher",
        headers=admin_auth_header,
    )
    assert response.status_code == status.HTTP_200_OK
    assert response.json()["name"] == "Launcher"
    assert response.json()["id"] == "multi_launcher"
    assert isinstance(response.json()["options"], dict)


def test_create_stager_validation_fails_required_field(client, admin_auth_header):
    base_stager = get_base_stager()
    base_stager["options"]["Listener"] = ""
    response = client.post(
        "/api/v2/stagers/", headers=admin_auth_header, json=base_stager
    )
    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert response.json()["detail"] == "required option missing: Listener"


def test_create_stager_validation_fails_strict_field(client, admin_auth_header):
    base_stager = get_base_stager()
    base_stager["options"]["Language"] = "ABCDEF"
    response = client.post(
        "/api/v2/stagers/", headers=admin_auth_header, json=base_stager
    )
    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert (
        response.json()["detail"]
        == "Language must be set to one of the suggested values."
    )


# def test_create_stager_custom_validation_fails():
#     stager = get_base_stager()
#     stager['options']['Language'] = 'powershell'
#     response = client.post("/api/v2/stagers/", json=stager)
#     assert response.status_code == status.HTTP_400_BAD_REQUEST
#     assert response.json()['detail'] == 'Error generating'


def test_create_stager_template_not_found(client, admin_auth_header):
    base_stager = get_base_stager()
    base_stager["template"] = "qwerty"

    response = client.post(
        "/api/v2/stagers/", headers=admin_auth_header, json=base_stager
    )
    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert response.json()["detail"] == "Stager Template qwerty not found"


def test_create_stager_one_liner(client, admin_auth_header):
    base_stager = get_base_stager()
    # test that it ignore extra params
    base_stager["options"]["xyz"] = "xyz"

    response = client.post(
        "/api/v2/stagers/?save=true", headers=admin_auth_header, json=base_stager
    )
    assert response.status_code == status.HTTP_201_CREATED
    assert response.json()["options"].get("xyz") is None
    assert len(response.json().get("downloads", [])) > 0
    assert (
        response.json().get("downloads", [])[0]["link"].startswith("/api/v2/downloads")
    )

    client.delete(f"/api/v2/stagers/{response.json()['id']}", headers=admin_auth_header)


def test_create_malleable_stager_one_liner(client, admin_auth_header):
    base_stager_malleable = get_base_stager_malleable()
    # test that it ignore extra params
    base_stager_malleable["options"]["xyz"] = "xyz"

    response = client.post(
        "/api/v2/stagers/?save=true",
        headers=admin_auth_header,
        json=base_stager_malleable,
    )
    assert response.status_code == status.HTTP_201_CREATED
    assert response.json()["options"].get("xyz") is None
    assert len(response.json().get("downloads", [])) > 0
    assert (
        response.json().get("downloads", [])[0]["link"].startswith("/api/v2/downloads")
    )

    client.delete(f"/api/v2/stagers/{response.json()['id']}", headers=admin_auth_header)


def test_create_obfuscated_stager_one_liner(client, admin_auth_header):
    base_stager = get_base_stager()
    # test that it ignore extra params
    base_stager["options"]["xyz"] = "xyz"

    base_stager["name"] = "My_Obfuscated_Stager"
    base_stager["options"]["Obfuscate"] = "True"

    response = client.post(
        "/api/v2/stagers/?save=true", headers=admin_auth_header, json=base_stager
    )
    assert response.status_code == status.HTTP_201_CREATED
    assert response.json()["options"].get("xyz") is None
    assert len(response.json().get("downloads", [])) > 0
    assert (
        response.json().get("downloads", [])[0]["link"].startswith("/api/v2/downloads")
    )

    client.delete(f"/api/v2/stagers/{response.json()['id']}", headers=admin_auth_header)


def test_create_obfuscated_malleable_stager_one_liner(client, admin_auth_header):
    base_stager_malleable = get_base_stager_malleable()
    # test that it ignore extra params
    base_stager_malleable["options"]["xyz"] = "xyz"

    base_stager_malleable["name"] = "My_Obfuscated_Stager"
    base_stager_malleable["options"]["Obfuscate"] = "True"

    response = client.post(
        "/api/v2/stagers/?save=true",
        headers=admin_auth_header,
        json=base_stager_malleable,
    )
    assert response.status_code == status.HTTP_201_CREATED
    assert response.json()["options"].get("xyz") is None
    assert len(response.json().get("downloads", [])) > 0
    assert (
        response.json().get("downloads", [])[0]["link"].startswith("/api/v2/downloads")
    )

    client.delete(f"/api/v2/stagers/{response.json()['id']}", headers=admin_auth_header)


def test_create_stager_file(client, admin_auth_header):
    base_stager_dll = get_base_stager_dll()
    # test that it ignore extra params
    base_stager_dll["options"]["xyz"] = "xyz"

    response = client.post(
        "/api/v2/stagers/?save=true", headers=admin_auth_header, json=base_stager_dll
    )
    assert response.status_code == status.HTTP_201_CREATED
    assert response.json()["options"].get("xyz") is None
    assert len(response.json().get("downloads", [])) > 0
    assert (
        response.json().get("downloads", [])[0]["link"].startswith("/api/v2/downloads")
    )

    client.delete(f"/api/v2/stagers/{response.json()['id']}", headers=admin_auth_header)


def test_create_stager_name_conflict(client, admin_auth_header):
    base_stager = get_base_stager()
    response = client.post(
        "/api/v2/stagers/?save=true", headers=admin_auth_header, json=base_stager
    )
    assert response.status_code == status.HTTP_201_CREATED
    stager_id = response.json()["id"]

    response = client.post(
        "/api/v2/stagers/?save=true", headers=admin_auth_header, json=base_stager
    )
    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert (
        response.json()["detail"]
        == f"Stager with name {base_stager['name']} already exists."
    )

    client.delete(f"/api/v2/stagers/{stager_id}", headers=admin_auth_header)


def test_create_stager_save_false(client, admin_auth_header):
    base_stager = get_base_stager()
    response = client.post(
        "/api/v2/stagers/?save=false", headers=admin_auth_header, json=base_stager
    )
    assert response.status_code == status.HTTP_201_CREATED
    assert response.json()["id"] == 0
    assert len(response.json().get("downloads", [])) > 0
    assert (
        response.json().get("downloads", [])[0]["link"].startswith("/api/v2/downloads")
    )


def test_get_stager(client, admin_auth_header):
    base_stager = get_base_stager()
    response = client.post(
        "/api/v2/stagers/?save=true", headers=admin_auth_header, json=base_stager
    )
    stager_id = response.json()["id"]

    assert response.status_code == status.HTTP_201_CREATED

    response = client.get(
        f"/api/v2/stagers/{stager_id}",
        headers=admin_auth_header,
    )
    assert response.status_code == status.HTTP_200_OK
    assert response.json()["id"] == stager_id

    client.delete(f"/api/v2/stagers/{stager_id}", headers=admin_auth_header)


def test_get_stager_not_found(client, admin_auth_header):
    response = client.get(
        "/api/v2/stagers/9999",
        headers=admin_auth_header,
    )
    assert response.status_code == status.HTTP_404_NOT_FOUND
    assert response.json()["detail"] == "Stager not found for id 9999"


def test_update_stager_not_found(client, admin_auth_header):
    base_stager = get_base_stager()
    response = client.put(
        "/api/v2/stagers/9999", headers=admin_auth_header, json=base_stager
    )
    assert response.status_code == status.HTTP_404_NOT_FOUND
    assert response.json()["detail"] == "Stager not found for id 9999"


def test_download_stager_one_liner(client, admin_auth_header):
    base_stager = get_base_stager()
    response = client.post(
        "/api/v2/stagers/?save=true",
        headers=admin_auth_header,
        json=base_stager,
    )
    assert response.status_code == status.HTTP_201_CREATED
    stager_id = response.json()["id"]

    response = client.get(
        f"/api/v2/stagers/{stager_id}",
        headers=admin_auth_header,
    )
    response = client.get(
        response.json()["downloads"][0]["link"],
        headers=admin_auth_header,
    )
    assert response.status_code == status.HTTP_200_OK
    assert response.headers.get("content-type").split(";")[0] == "text/plain"
    assert response.text.startswith("powershell -noP -sta")

    client.delete(f"/api/v2/stagers/{stager_id}", headers=admin_auth_header)


def test_download_stager_file(client, admin_auth_header):
    base_stager_dll = get_base_stager_dll()
    response = client.post(
        "/api/v2/stagers/?save=true",
        headers=admin_auth_header,
        json=base_stager_dll,
    )
    assert response.status_code == status.HTTP_201_CREATED
    stager_id = response.json()["id"]

    response = client.get(
        f"/api/v2/stagers/{stager_id}",
        headers=admin_auth_header,
    )
    response = client.get(
        response.json()["downloads"][0]["link"],
        headers=admin_auth_header,
    )
    assert response.status_code == status.HTTP_200_OK
    assert response.headers.get("content-type").split(";")[0] in [
        "application/x-msdownload",
        "application/x-msdos-program",
    ]
    assert isinstance(response.content, bytes)

    client.delete(f"/api/v2/stagers/{stager_id}", headers=admin_auth_header)


def test_update_stager_allows_edits_and_generates_new_file(client, admin_auth_header):
    base_stager = get_base_stager()
    response = client.post(
        "/api/v2/stagers/?save=true",
        headers=admin_auth_header,
        json=base_stager,
    )
    assert response.status_code == status.HTTP_201_CREATED
    stager_id = response.json()["id"]

    response = client.get(
        f"/api/v2/stagers/{stager_id}",
        headers=admin_auth_header,
    )
    assert response.status_code == status.HTTP_200_OK

    stager = response.json()
    original_name = stager["name"]
    stager["name"] = stager["name"] + "_updated!"
    stager["options"]["Base64"] = "False"

    response = client.put(
        f"/api/v2/stagers/{stager_id}",
        headers=admin_auth_header,
        json=stager,
    )
    assert response.status_code == status.HTTP_200_OK
    assert response.json()["options"]["Base64"] == "False"
    assert response.json()["name"] == original_name + "_updated!"

    client.delete(f"/api/v2/stagers/{stager_id}", headers=admin_auth_header)


def test_update_stager_name_conflict(client, admin_auth_header):
    base_stager = get_base_stager()
    response = client.post(
        "/api/v2/stagers/?save=true",
        headers=admin_auth_header,
        json=base_stager,
    )
    assert response.status_code == status.HTTP_201_CREATED
    stager_id = response.json()["id"]

    response = client.get(
        f"/api/v2/stagers/{stager_id}",
        headers=admin_auth_header,
    )
    assert response.status_code == status.HTTP_200_OK

    base_stager_2 = base_stager.copy()
    base_stager_2["name"] = "test_stager_2"
    response2 = client.post(
        "/api/v2/stagers/?save=true",
        headers=admin_auth_header,
        json=base_stager_2,
    )
    assert response2.status_code == status.HTTP_201_CREATED
    stager_id_2 = response2.json()["id"]

    response2 = client.get(
        f"/api/v2/stagers/{stager_id_2}",
        headers=admin_auth_header,
    )
    assert response.status_code == status.HTTP_200_OK
    stager_1 = response.json()
    stager_2 = response2.json()

    stager_1["name"] = stager_2["name"]
    response = client.put(
        f"/api/v2/stagers/{stager_id}",
        headers=admin_auth_header,
        json=stager_1,
    )

    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert (
        response.json()["detail"]
        == f"Stager with name {stager_2['name']} already exists."
    )

    client.delete(f"/api/v2/stagers/{stager_id}", headers=admin_auth_header)
    client.delete(f"/api/v2/stagers/{stager_id_2}", headers=admin_auth_header)


def test_get_stagers(client, admin_auth_header):
    base_stager = get_base_stager()
    response = client.post(
        "/api/v2/stagers/?save=true",
        headers=admin_auth_header,
        json=base_stager,
    )
    assert response.status_code == status.HTTP_201_CREATED
    stager_id = response.json()["id"]

    base_stager_2 = base_stager.copy()
    base_stager_2["name"] = "test_stager_2"
    response = client.post(
        "/api/v2/stagers/?save=true",
        headers=admin_auth_header,
        json=base_stager_2,
    )
    assert response.status_code == status.HTTP_201_CREATED
    stager_id_2 = response.json()["id"]

    response = client.get(
        "/api/v2/stagers",
        headers=admin_auth_header,
    )

    stager_count = 2
    assert response.status_code == status.HTTP_200_OK
    assert len(response.json()["records"]) == stager_count
    assert response.json()["records"][0]["id"] == stager_id
    assert response.json()["records"][1]["id"] == stager_id_2

    client.delete(f"/api/v2/stagers/{stager_id}", headers=admin_auth_header)
    client.delete(f"/api/v2/stagers/{stager_id_2}", headers=admin_auth_header)


def test_delete_stager(client, admin_auth_header):
    base_stager = get_base_stager()
    response = client.post(
        "/api/v2/stagers/?save=true",
        headers=admin_auth_header,
        json=base_stager,
    )
    assert response.status_code == status.HTTP_201_CREATED
    stager_id = response.json()["id"]

    response = client.delete(f"/api/v2/stagers/{stager_id}", headers=admin_auth_header)
    assert response.status_code == status.HTTP_204_NO_CONTENT

    response = client.get(f"/api/v2/stagers/{stager_id}", headers=admin_auth_header)
    assert response.status_code == status.HTTP_404_NOT_FOUND

    response = client.get("/api/v2/stagers", headers=admin_auth_header)
    assert response.status_code == status.HTTP_200_OK
    assert stager_id not in [stager["id"] for stager in response.json()["records"]]


def test_pyinstaller_stager_creation(client, admin_auth_header):
    pyinstaller_stager = get_pyinstaller_stager()
    response = client.post(
        "/api/v2/stagers/?save=true", headers=admin_auth_header, json=pyinstaller_stager
    )

    # Check if the stager is successfully created
    assert response.status_code == status.HTTP_201_CREATED
    assert response.json()["id"] != 0

    stager_id = response.json()["id"]

    response = client.get(
        f"/api/v2/stagers/{stager_id}",
        headers=admin_auth_header,
    )

    # Check if we can successfully retrieve the stager
    assert response.status_code == status.HTTP_200_OK
    assert response.json()["id"] == stager_id

    response = client.get(
        response.json()["downloads"][0]["link"],
        headers=admin_auth_header,
    )

    # Check if the file is downloaded successfully
    assert response.status_code == status.HTTP_200_OK
    assert response.headers.get("content-type").split(";")[0] == "text/plain"
    assert isinstance(response.content, bytes)

    # Check if the downloaded file is not empty
    assert len(response.content) > 0

    client.delete(f"/api/v2/stagers/{stager_id}", headers=admin_auth_header)


def test_bat_stager_creation(client, admin_auth_header):
    bat_stager = get_bat_stager()
    response = client.post(
        "/api/v2/stagers/?save=true", headers=admin_auth_header, json=bat_stager
    )

    # Check if the stager is successfully created
    assert response.status_code == status.HTTP_201_CREATED
    assert response.json()["id"] != 0

    stager_id = response.json()["id"]

    response = client.get(
        f"/api/v2/stagers/{stager_id}",
        headers=admin_auth_header,
    )

    # Check if we can successfully retrieve the stager
    assert response.status_code == status.HTTP_200_OK
    assert response.json()["id"] == stager_id

    response = client.get(
        response.json()["downloads"][0]["link"],
        headers=admin_auth_header,
    )

    # Check if the file is downloaded successfully
    assert response.status_code == status.HTTP_200_OK
    assert response.headers.get("content-type").split(";")[0] in [
        "application/x-msdownload",
        "application/x-msdos-program",
    ]
    assert isinstance(response.content, bytes)

    # Check if the downloaded file is not empty
    assert len(response.content) > 0

    bat_text = response.content.decode("utf-8")
    assert "@echo off" in bat_text
    assert "start /B powershell -noP -sta -w 1 -enc" in bat_text
    assert "timeout /t 1 > nul" in bat_text
    assert 'del "%~f0"' in bat_text

    # Validate the encoded payload without pinning it to an exact value.
    m = re.search(r"-enc\s+([A-Za-z0-9+/=]+)", bat_text)
    assert m, f"Expected a base64 payload after -enc. BAT was: {bat_text}"

    encoded = m.group(1)
    raw = base64.b64decode(encoded, validate=True)
    ps = raw.decode("utf-16le", errors="strict")

    # Stable invariants inside the launcher
    assert "System.Net.WebClient" in ps
    assert "Headers.Add" in ps
    assert "Cookie" in ps
    assert "DownloadData" in ps
    assert "IEX" in ps or "Invoke-Expression" in ps

    client.delete(f"/api/v2/stagers/{stager_id}", headers=admin_auth_header)


@pytest.mark.parametrize(
    ("document_type", "trigger_function", "expected_trigger"),
    [
        ("word", "autoopen", "Sub AutoOpen()"),
        ("word", "autoclose", "Sub AutoClose()"),
        ("excel", "autoopen", "Sub Workbook_Open()"),
        ("excel", "autoclose", "Sub Workbook_BeforeClose(Cancel As Boolean)"),
    ],
)
def test_macro_stager_generation(
    client,
    admin_auth_header,
    document_type,
    trigger_function,
    expected_trigger,
):
    windows_macro_stager = get_windows_macro_stager()
    windows_macro_stager["options"]["DocType"] = document_type
    windows_macro_stager["options"]["Trigger"] = trigger_function

    response = client.post(
        "/api/v2/stagers/?save=true",
        headers=admin_auth_header,
        json=windows_macro_stager,
    )

    # Check if the stager is successfully created
    assert response.status_code == status.HTTP_201_CREATED
    assert response.json()["id"] != 0

    stager_id = response.json()["id"]

    response = client.get(
        f"/api/v2/stagers/{stager_id}",
        headers=admin_auth_header,
    )

    # Check if we can successfully retrieve the stager
    assert response.status_code == status.HTTP_200_OK
    assert response.json()["id"] == stager_id

    response = client.get(
        response.json()["downloads"][0]["link"],
        headers=admin_auth_header,
    )

    # Check if the file is downloaded successfully
    assert response.status_code == status.HTTP_200_OK
    assert response.headers.get("content-type").split(";")[0] in [
        "text/plain",
    ]
    assert isinstance(response.content, bytes)

    # Check if the downloaded file is not empty
    assert len(response.content) > 0
    assert expected_trigger in response.content.decode("utf-8")

    client.delete(f"/api/v2/stagers/{stager_id}", headers=admin_auth_header)


def test_csharp_stager_creation(client, admin_auth_header):
    base_stager = get_base_csharp_exe_stager()

    response = client.post(
        "/api/v2/stagers/?save=true", headers=admin_auth_header, json=base_stager
    )

    # Check if the stager is successfully created
    assert response.status_code == status.HTTP_201_CREATED
    assert response.json()["id"] != 0

    stager_id = response.json()["id"]

    response = client.get(
        f"/api/v2/stagers/{stager_id}",
        headers=admin_auth_header,
    )

    # Check if we can successfully retrieve the stager
    assert response.status_code == status.HTTP_200_OK
    assert response.json()["id"] == stager_id

    response = client.get(
        response.json()["downloads"][0]["link"],
        headers=admin_auth_header,
    )

    # Check if the file is downloaded successfully
    assert response.status_code == status.HTTP_200_OK
    assert response.headers.get("content-type").split(";")[0] in [
        "application/x-msdownload",
        "application/x-msdos-program",
    ]
    assert isinstance(response.content, bytes)

    # Check if the downloaded file is not empty
    assert len(response.content) > 0

    client.delete(f"/api/v2/stagers/{stager_id}", headers=admin_auth_header)
