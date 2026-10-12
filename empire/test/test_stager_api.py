import base64
import logging
import re
import shutil
from unittest.mock import MagicMock

import pytest
from starlette import status

from empire.server.core.exceptions import (
    ModuleExecutionException,
    StagerGenerationException,
)
from empire.server.core.go import GoCompiler
from empire.server.core.stager_service import StagerService
from empire.server.stagers.windows import c_launcher
from empire.server.utils.string_util import get_random_string

MINGW_CC = "x86_64-w64-mingw32-gcc"

requires_mingw = pytest.mark.skipif(
    shutil.which(MINGW_CC) is None, reason=f"{MINGW_CC} not on PATH"
)


def _unique(name):
    """``Stager.name`` is ``unique=True``, so a leaked row 400s every later test
    that reuses its name.
    """
    return f"{name}_{get_random_string(8)}"


@pytest.fixture
def created_stagers(client, admin_auth_header):
    """Ids to delete when the test ends, however it ends. Register right after
    the ``201`` assertion - before it, a 400 body has no ``id``.
    """
    created = []
    yield created

    # Collect failures rather than asserting per id, so one bad id cannot abort
    # the loop and leak the rest. TestClient raises on a 500, hence the except.
    failed = []
    for stager_id in created:
        try:
            response = client.delete(
                f"/api/v2/stagers/{stager_id}", headers=admin_auth_header
            )
        except Exception as e:
            failed.append(f"{stager_id}: {e!r}")
        else:
            # 404 is fine, the test may have deleted it itself.
            if response.status_code not in (
                status.HTTP_204_NO_CONTENT,
                status.HTTP_404_NOT_FOUND,
            ):
                failed.append(f"{stager_id}: HTTP {response.status_code}")

    assert not failed, f"stager cleanup failed: {failed}"


def get_base_stager():
    return {
        "name": _unique("MyStager"),
        "template": "multi_launcher",
        "options": {
            "Listener": "new-listener-1",
            "Language": "powershell",
            "OutFile": "",
            "Base64": "True",
            "Obfuscate": "False",
            "ObfuscateCommand": "Token\\All\\1",
            "UserAgent": "default",
            "Proxy": "default",
            "ProxyCreds": "default",
            "Bypasses": "mattifestation etw",
        },
    }


def get_base_stager_dll():
    return {
        "name": _unique("MyStager2"),
        "template": "windows_dll",
        "options": {
            "Listener": "new-listener-1",
            "Language": "powershell",
            "Arch": "x86",
            "OutFile": "my-windows-dll.dll",
            "Base64": "True",
            "Obfuscate": "False",
            "ObfuscateCommand": "Token\\All\\1",
            "UserAgent": "default",
            "Proxy": "default",
            "ProxyCreds": "default",
            "Bypasses": "mattifestation etw",
        },
    }


def get_base_stager_malleable():
    return {
        "name": _unique("MyStager"),
        "template": "multi_launcher",
        "options": {
            "Listener": "malleable_listener_1",
            "Language": "powershell",
            "OutFile": "",
            "Base64": "True",
            "Obfuscate": "False",
            "ObfuscateCommand": "Token\\All\\1",
            "UserAgent": "default",
            "Proxy": "default",
            "ProxyCreds": "default",
            "Bypasses": "mattifestation etw",
        },
    }


def get_bat_stager():
    return {
        "name": _unique("bat_stager"),
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
        "name": _unique("macro_stager"),
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
        },
    }


def get_pyinstaller_stager():
    return {
        "name": _unique("MyStager3"),
        "template": "linux_pyinstaller",
        "options": {
            "Listener": "new-listener-1",
            "Language": "python",
            "OutFile": "empire",
            "UserAgent": "default",
        },
    }


def get_base_csharp_exe_stager():
    return {
        "name": _unique("CSharpExeStager"),
        "template": "windows_csharp_exe",
        "options": {
            "Listener": "new-listener-1",
            "Language": "csharp",
            "DotNetVersion": "net40",
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


def get_windows_c_stager():
    return {
        "name": _unique("windows-c-test-stager"),
        "template": "windows_c_launcher",
        "options": {"Listener": "new-listener-1", "OutFile": "test_stager.exe"},
    }


def test_get_stager_template_listener_default(
    client, admin_auth_header, listener, listener_malleable
):
    """Listener option is pre-filled and suggested_values contains all active listeners."""
    response = client.get(
        "/api/v2/stager-templates/multi_launcher",
        headers=admin_auth_header,
    )
    assert response.status_code == status.HTTP_200_OK
    listener_opt = response.json()["options"]["Listener"]
    # The option is pre-filled with the default (lowest-id) listener. Both
    # listener fixtures are session-scoped autouse, and under pytest-xdist the
    # order they instantiate across files isn't fixed, so don't assume *which*
    # listener is the default — only that it's pre-filled with a valid one.
    assert listener_opt["value"] in listener_opt["suggested_values"]
    assert listener["name"] in listener_opt["suggested_values"]
    assert listener_malleable["name"] in listener_opt["suggested_values"]


def test_get_stager_templates_listener_default(
    client, admin_auth_header, listener, listener_malleable
):
    """Listener option is pre-filled on the list endpoint too."""
    response = client.get("/api/v2/stager-templates/", headers=admin_auth_header)
    assert response.status_code == status.HTTP_200_OK

    template = next(
        (t for t in response.json()["records"] if t["id"] == "multi_launcher"), None
    )
    assert template is not None
    listener_opt = template["options"]["Listener"]
    # The option is pre-filled with the default (lowest-id) listener. Both
    # listener fixtures are session-scoped autouse, and under pytest-xdist the
    # order they instantiate across files isn't fixed, so don't assume *which*
    # listener is the default — only that it's pre-filled with a valid one.
    assert listener_opt["value"] in listener_opt["suggested_values"]
    assert listener["name"] in listener_opt["suggested_values"]
    assert listener_malleable["name"] in listener_opt["suggested_values"]


def test_get_stager_templates(client, admin_auth_header):
    min_stagers = 32
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


def test_stager_template_bool_value_type(client, admin_auth_header):
    response = client.get(
        "/api/v2/stager-templates/multi_launcher",
        headers=admin_auth_header,
    )
    assert response.status_code == status.HTTP_200_OK
    options = response.json()["options"]
    for bool_opt in ("Base64", "Obfuscate"):
        assert options[bool_opt]["value_type"] == "BOOLEAN", (
            f"{bool_opt} should advertise BOOLEAN, got {options[bool_opt]['value_type']}"
        )


def test_stager_template_bypass_language_map(client, admin_auth_header):
    response = client.get(
        "/api/v2/stager-templates/multi_launcher",
        headers=admin_auth_header,
    )
    assert response.status_code == status.HTTP_200_OK
    bypasses = response.json()["options"]["Bypasses"]
    assert bypasses["bypass_language_map"] == {
        "powershell": "powershell",
        "python": "python",
        "ironpython": "powershell",
        "csharp": "powershell",
        "go": "powershell",
    }

    response = client.get(
        "/api/v2/stager-templates/windows_launcher_bat",
        headers=admin_auth_header,
    )
    assert response.status_code == status.HTTP_200_OK
    bat_bypasses = response.json()["options"]["Bypasses"]
    assert bat_bypasses["bypass_language_map"] == {
        "powershell": "powershell",
        "csharp": "powershell",
        "ironpython": "powershell",
        "go": "powershell",
    }

    # Listener options never carry a bypass language map.
    listener_field = response.json()["options"]["Listener"]
    assert listener_field["bypass_language_map"] is None


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


def test_create_stager_one_liner(client, admin_auth_header, created_stagers):
    base_stager = get_base_stager()
    # test that it ignore extra params
    base_stager["options"]["xyz"] = "xyz"

    response = client.post(
        "/api/v2/stagers/?save=true", headers=admin_auth_header, json=base_stager
    )
    assert response.status_code == status.HTTP_201_CREATED
    created_stagers.append(response.json()["id"])
    assert response.json()["options"].get("xyz") is None
    assert len(response.json().get("downloads", [])) > 0
    assert (
        response.json().get("downloads", [])[0]["link"].startswith("/api/v2/downloads")
    )


def test_create_malleable_stager_one_liner(client, admin_auth_header, created_stagers):
    base_stager_malleable = get_base_stager_malleable()
    # test that it ignore extra params
    base_stager_malleable["options"]["xyz"] = "xyz"

    response = client.post(
        "/api/v2/stagers/?save=true",
        headers=admin_auth_header,
        json=base_stager_malleable,
    )
    assert response.status_code == status.HTTP_201_CREATED
    created_stagers.append(response.json()["id"])
    assert response.json()["options"].get("xyz") is None
    assert len(response.json().get("downloads", [])) > 0
    assert (
        response.json().get("downloads", [])[0]["link"].startswith("/api/v2/downloads")
    )


def test_create_malleable_csharp_launcher_no_longer_blocked(
    client, admin_auth_header, created_stagers
):
    """Regression for the allow-list gate that blocked C# / IronPython /
    Go stagers against the malleable HTTP listener even though Sharpire
    and Gopire support it. The routing helper now dispatches to the
    listener's stager endpoint instead of returning "" with an error.
    Smoke: multi_launcher + csharp + malleable_listener_1 must produce
    a non-empty stager download.
    """
    stager = get_base_stager_malleable()
    stager["name"] = _unique("MalleableCsharpSmoke")
    stager["options"]["Language"] = "csharp"

    response = client.post(
        "/api/v2/stagers/?save=true", headers=admin_auth_header, json=stager
    )
    assert response.status_code == status.HTTP_201_CREATED, response.json()
    created_stagers.append(response.json()["id"])
    downloads = response.json().get("downloads", [])
    assert downloads, "csharp launcher against malleable must produce a download link"


def test_create_malleable_dll_csharp_no_longer_blocked(
    client, admin_auth_header, created_stagers
):
    """Same regression as the multi_launcher test above, but for one of the
    11 wrapper stagers (windows_dll) that also had the gate. Spot-checks one
    wrapper; the other 10 share the textually-identical patch (allow-list
    block deleted, `generate_exe_oneliner_routed` substituted) so coverage
    here implies coverage there.
    """
    stager = get_base_stager_dll()
    stager["name"] = _unique("MalleableDllSmoke")
    stager["options"]["Listener"] = "malleable_listener_1"
    stager["options"]["Language"] = "csharp"

    response = client.post(
        "/api/v2/stagers/?save=true", headers=admin_auth_header, json=stager
    )
    assert response.status_code == status.HTTP_201_CREATED, response.json()
    created_stagers.append(response.json()["id"])
    downloads = response.json().get("downloads", [])
    assert downloads, "dll wrapper for csharp+malleable must produce a download link"


def test_create_obfuscated_stager_one_liner(client, admin_auth_header, created_stagers):
    base_stager = get_base_stager()
    # test that it ignore extra params
    base_stager["options"]["xyz"] = "xyz"

    base_stager["name"] = _unique("My_Obfuscated_Stager")
    base_stager["options"]["Obfuscate"] = "True"

    response = client.post(
        "/api/v2/stagers/?save=true", headers=admin_auth_header, json=base_stager
    )
    assert response.status_code == status.HTTP_201_CREATED
    created_stagers.append(response.json()["id"])
    assert response.json()["options"].get("xyz") is None
    assert len(response.json().get("downloads", [])) > 0
    assert (
        response.json().get("downloads", [])[0]["link"].startswith("/api/v2/downloads")
    )


def test_create_obfuscated_malleable_stager_one_liner(
    client, admin_auth_header, created_stagers
):
    base_stager_malleable = get_base_stager_malleable()
    # test that it ignore extra params
    base_stager_malleable["options"]["xyz"] = "xyz"

    base_stager_malleable["name"] = _unique("My_Obfuscated_Stager")
    base_stager_malleable["options"]["Obfuscate"] = "True"

    response = client.post(
        "/api/v2/stagers/?save=true",
        headers=admin_auth_header,
        json=base_stager_malleable,
    )
    assert response.status_code == status.HTTP_201_CREATED
    created_stagers.append(response.json()["id"])
    assert response.json()["options"].get("xyz") is None
    assert len(response.json().get("downloads", [])) > 0
    assert (
        response.json().get("downloads", [])[0]["link"].startswith("/api/v2/downloads")
    )


def test_create_stager_file(client, admin_auth_header, created_stagers):
    base_stager_dll = get_base_stager_dll()
    # test that it ignore extra params
    base_stager_dll["options"]["xyz"] = "xyz"

    response = client.post(
        "/api/v2/stagers/?save=true", headers=admin_auth_header, json=base_stager_dll
    )
    assert response.status_code == status.HTTP_201_CREATED
    created_stagers.append(response.json()["id"])
    assert response.json()["options"].get("xyz") is None
    assert len(response.json().get("downloads", [])) > 0
    assert (
        response.json().get("downloads", [])[0]["link"].startswith("/api/v2/downloads")
    )


def test_create_stager_name_conflict(client, admin_auth_header, created_stagers):
    base_stager = get_base_stager()
    response = client.post(
        "/api/v2/stagers/?save=true", headers=admin_auth_header, json=base_stager
    )
    assert response.status_code == status.HTTP_201_CREATED
    stager_id = response.json()["id"]
    created_stagers.append(stager_id)

    response = client.post(
        "/api/v2/stagers/?save=true", headers=admin_auth_header, json=base_stager
    )
    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert (
        response.json()["detail"]
        == f"Stager with name {base_stager['name']} already exists."
    )


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


def test_get_stager(client, admin_auth_header, created_stagers):
    base_stager = get_base_stager()
    response = client.post(
        "/api/v2/stagers/?save=true", headers=admin_auth_header, json=base_stager
    )
    assert response.status_code == status.HTTP_201_CREATED
    stager_id = response.json()["id"]
    created_stagers.append(stager_id)

    response = client.get(
        f"/api/v2/stagers/{stager_id}",
        headers=admin_auth_header,
    )
    assert response.status_code == status.HTTP_200_OK
    assert response.json()["id"] == stager_id


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


def test_download_stager_one_liner(client, admin_auth_header, created_stagers):
    base_stager = get_base_stager()
    response = client.post(
        "/api/v2/stagers/?save=true",
        headers=admin_auth_header,
        json=base_stager,
    )
    assert response.status_code == status.HTTP_201_CREATED
    stager_id = response.json()["id"]
    created_stagers.append(stager_id)

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


def test_download_stager_file(client, admin_auth_header, created_stagers):
    base_stager_dll = get_base_stager_dll()
    response = client.post(
        "/api/v2/stagers/?save=true",
        headers=admin_auth_header,
        json=base_stager_dll,
    )
    assert response.status_code == status.HTTP_201_CREATED
    stager_id = response.json()["id"]
    created_stagers.append(stager_id)

    response = client.get(
        f"/api/v2/stagers/{stager_id}",
        headers=admin_auth_header,
    )
    response = client.get(
        response.json()["downloads"][0]["link"],
        headers=admin_auth_header,
    )
    assert response.status_code == status.HTTP_200_OK
    assert (
        response.headers.get("content-type").split(";")[0] == "application/octet-stream"
    )
    assert response.content[:2] == b"MZ", "not a PE binary"
    assert isinstance(response.content, bytes)


def test_update_stager_allows_edits_and_generates_new_file(
    client, admin_auth_header, created_stagers
):
    base_stager = get_base_stager()
    response = client.post(
        "/api/v2/stagers/?save=true",
        headers=admin_auth_header,
        json=base_stager,
    )
    assert response.status_code == status.HTTP_201_CREATED
    stager_id = response.json()["id"]
    created_stagers.append(stager_id)

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


def test_update_stager_name_conflict(client, admin_auth_header, created_stagers):
    base_stager = get_base_stager()
    response = client.post(
        "/api/v2/stagers/?save=true",
        headers=admin_auth_header,
        json=base_stager,
    )
    assert response.status_code == status.HTTP_201_CREATED
    stager_id = response.json()["id"]
    created_stagers.append(stager_id)

    response = client.get(
        f"/api/v2/stagers/{stager_id}",
        headers=admin_auth_header,
    )
    assert response.status_code == status.HTTP_200_OK

    base_stager_2 = base_stager.copy()
    base_stager_2["name"] = _unique("test_stager_2")
    response2 = client.post(
        "/api/v2/stagers/?save=true",
        headers=admin_auth_header,
        json=base_stager_2,
    )
    assert response2.status_code == status.HTTP_201_CREATED
    stager_id_2 = response2.json()["id"]
    created_stagers.append(stager_id_2)

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


def test_get_stagers(client, admin_auth_header, created_stagers):
    base_stager = get_base_stager()
    response = client.post(
        "/api/v2/stagers/?save=true",
        headers=admin_auth_header,
        json=base_stager,
    )
    assert response.status_code == status.HTTP_201_CREATED
    stager_id = response.json()["id"]
    created_stagers.append(stager_id)

    base_stager_2 = base_stager.copy()
    base_stager_2["name"] = _unique("test_stager_2")
    response = client.post(
        "/api/v2/stagers/?save=true",
        headers=admin_auth_header,
        json=base_stager_2,
    )
    assert response.status_code == status.HTTP_201_CREATED
    stager_id_2 = response.json()["id"]
    created_stagers.append(stager_id_2)

    response = client.get(
        "/api/v2/stagers",
        headers=admin_auth_header,
    )

    assert response.status_code == status.HTTP_200_OK
    # Scoped to this test's rows: a global count blames the next test for an
    # earlier leak, and indexing bets on the query's row order.
    ids = [record["id"] for record in response.json()["records"]]
    assert ids.count(stager_id) == 1
    assert ids.count(stager_id_2) == 1


def test_delete_stager(client, admin_auth_header, created_stagers):
    base_stager = get_base_stager()
    response = client.post(
        "/api/v2/stagers/?save=true",
        headers=admin_auth_header,
        json=base_stager,
    )
    assert response.status_code == status.HTTP_201_CREATED
    stager_id = response.json()["id"]
    # Registered even though this test deletes it: if the 204 below fails the
    # row would leak. The fixture accepts the resulting 404.
    created_stagers.append(stager_id)

    response = client.delete(f"/api/v2/stagers/{stager_id}", headers=admin_auth_header)
    assert response.status_code == status.HTTP_204_NO_CONTENT

    response = client.get(f"/api/v2/stagers/{stager_id}", headers=admin_auth_header)
    assert response.status_code == status.HTTP_404_NOT_FOUND

    response = client.get("/api/v2/stagers", headers=admin_auth_header)
    assert response.status_code == status.HTTP_200_OK
    assert stager_id not in [stager["id"] for stager in response.json()["records"]]


@pytest.mark.slow
def test_pyinstaller_stager_creation(client, admin_auth_header, created_stagers):
    pyinstaller_stager = get_pyinstaller_stager()
    response = client.post(
        "/api/v2/stagers/?save=true", headers=admin_auth_header, json=pyinstaller_stager
    )

    # Check if the stager is successfully created
    assert response.status_code == status.HTTP_201_CREATED
    stager_id = response.json()["id"]
    created_stagers.append(stager_id)

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
    assert (
        response.headers.get("content-type").split(";")[0] == "application/octet-stream"
    )
    assert isinstance(response.content, bytes)

    # Check if the downloaded file is not empty
    assert len(response.content) > 0


def test_bat_stager_creation(client, admin_auth_header, created_stagers):
    bat_stager = get_bat_stager()
    response = client.post(
        "/api/v2/stagers/?save=true", headers=admin_auth_header, json=bat_stager
    )

    # Check if the stager is successfully created
    assert response.status_code == status.HTTP_201_CREATED
    stager_id = response.json()["id"]
    created_stagers.append(stager_id)

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
    created_stagers,
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
    stager_id = response.json()["id"]
    created_stagers.append(stager_id)

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
    assert expected_trigger in response.content.decode("utf-8")


@pytest.mark.slow
def test_csharp_stager_creation(client, admin_auth_header, created_stagers):
    base_stager = get_base_csharp_exe_stager()

    response = client.post(
        "/api/v2/stagers/?save=true", headers=admin_auth_header, json=base_stager
    )

    # Check if the stager is successfully created
    assert response.status_code == status.HTTP_201_CREATED
    stager_id = response.json()["id"]
    created_stagers.append(stager_id)

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
    assert (
        response.headers.get("content-type").split(";")[0] == "application/octet-stream"
    )
    assert response.content[:2] == b"MZ", "not a PE binary"
    assert isinstance(response.content, bytes)

    # Check if the downloaded file is not empty
    assert len(response.content) > 0


@pytest.mark.slow
def test_csharp_malleable_stager_creation(
    client, admin_auth_header, created_stagers, listener_malleable
):
    """SharpireMalleable pulls in a second source library; compile it with
    the real pinned compiler, not just plain Sharpire."""
    stager = get_base_csharp_exe_stager()
    stager["options"]["Listener"] = listener_malleable["name"]

    response = client.post(
        "/api/v2/stagers/?save=true", headers=admin_auth_header, json=stager
    )

    assert response.status_code == status.HTTP_201_CREATED, response.text
    created_stagers.append(response.json()["id"])
    download = client.get(
        response.json()["downloads"][0]["link"], headers=admin_auth_header
    )
    assert download.status_code == status.HTTP_200_OK
    assert len(download.content) > 0


@pytest.mark.mingw
@requires_mingw
def test_windows_c_stager_creation(client, admin_auth_header, created_stagers):
    stager_data = get_windows_c_stager()

    response = client.post(
        "/api/v2/stagers/?save=true", headers=admin_auth_header, json=stager_data
    )

    assert response.status_code == status.HTTP_201_CREATED, response.text
    stager_id = response.json()["id"]
    created_stagers.append(stager_id)


def test_create_stager_download_metadata(client, admin_auth_header, created_stagers):
    """Verify that stager download metadata has basename-only filename."""
    base_stager = get_base_stager()
    response = client.post(
        "/api/v2/stagers/?save=true", headers=admin_auth_header, json=base_stager
    )
    assert response.status_code == status.HTTP_201_CREATED
    stager_id = response.json()["id"]
    created_stagers.append(stager_id)

    downloads = response.json().get("downloads", [])
    assert len(downloads) > 0

    download = downloads[0]
    filename = download["filename"]
    # filename should be a basename, not a full path
    assert "/" not in filename
    assert "\\" not in filename
    assert len(filename) > 0


def test_generate_stager_catches_module_execution_exception(caplog):
    """`generate_stager` now wraps `template_instance.generate()` so a compile
    failure (subprocess timeout, EmpireCompiler error, go build kill) surfaces
    as a structured (None, err) tuple — yielding a 400 with the message —
    instead of a 500 stack trace. The catch must also log with exc_info=True
    so the empire-side log keeps the chained subprocess context for debugging.
    """
    service = StagerService(MagicMock())
    template_instance = MagicMock()
    template_instance.generate.side_effect = ModuleExecutionException(
        "Go build failed (rc=-9): <no output — likely killed by signal>"
    )

    with caplog.at_level(logging.ERROR, logger="empire.server.core.stager_service"):
        result, err = service.generate_stager(template_instance)

    assert result is None
    assert err == "Go build failed (rc=-9): <no output — likely killed by signal>"

    matching = [
        rec
        for rec in caplog.records
        if rec.levelname == "ERROR"
        and "Stager generation failed" in rec.message
        and rec.exc_info is not None
    ]
    assert matching, (
        f"expected an ERROR log with exc_info=True; got: "
        f"{[(r.levelname, r.message) for r in caplog.records]}"
    )


@pytest.mark.mingw
@requires_mingw
def test_windows_c_stager_download(client, admin_auth_header, created_stagers):
    stager_data = get_windows_c_stager()

    response = client.post(
        "/api/v2/stagers/?save=true", headers=admin_auth_header, json=stager_data
    )
    assert response.status_code == status.HTTP_201_CREATED

    stager_id = response.json()["id"]
    created_stagers.append(stager_id)
    download_link = response.json()["downloads"][0]["link"]

    response = client.get(download_link, headers=admin_auth_header)
    assert response.status_code == status.HTTP_200_OK
    assert isinstance(response.content, bytes)
    assert len(response.content) > 0


@pytest.mark.slow
def test_create_go_stager_compile_failure_returns_400_not_500(
    client, admin_auth_header, monkeypatch
):
    """A ModuleExecutionException from compile_stager must produce a 400 Bad
    Request with the error detail, not a 500 Internal Server Error.

    Previously the exception escaped generate_stager unhandled and hit
    FastAPI's default exception handler, giving operators an opaque 500 with
    no actionable message in the UI.
    """
    monkeypatch.setattr(
        GoCompiler,
        "compile_stager",
        lambda *a, **k: (_ for _ in ()).throw(
            ModuleExecutionException("Go build failed (rc=1): injected failure")
        ),
    )

    go_stager = {
        "name": _unique("test-go-compile-failure"),
        "template": "multi_go_exe",
        "options": {"Listener": "new-listener-1"},
    }

    response = client.post(
        "/api/v2/stagers/?save=false", headers=admin_auth_header, json=go_stager
    )

    assert response.status_code == status.HTTP_400_BAD_REQUEST, (
        f"Expected 400 for compile failure, got {response.status_code}: {response.text}"
    )
    assert "Go build failed" in response.json().get("detail", ""), (
        "Error detail must reach the API response so operators see it in the UI"
    )


def test_windows_c_stager_missing_mingw_raises_generation_exception(main, monkeypatch):
    """Monkeypatched because the branch is unreachable on a host that has the
    toolchain. ``generate_stager`` turns this exception into a 400.
    """
    stager = c_launcher.Stager(main)
    stager.options["Listener"]["Value"] = "new-listener-1"

    monkeypatch.setattr(
        c_launcher.subprocess, "run", MagicMock(side_effect=FileNotFoundError(MINGW_CC))
    )

    with pytest.raises(StagerGenerationException, match="gcc-mingw-w64-x86-64"):
        stager.generate()
