from pathlib import Path
from textwrap import dedent
from types import SimpleNamespace

import pytest
from starlette import status

from empire.server.core.exceptions import (
    ModuleExecutionException,
    ModuleValidationException,
)
from empire.server.core.module_models import (
    EmpireModule,
    EmpireModuleAdvanced,
    LanguageEnum,
)
from empire.server.utils.module_util import handle_error_message


@pytest.fixture(scope="module", autouse=True)
def agent_low_version(session_local, models, main):
    with session_local.begin() as db:
        agent = db.query(models.Agent).filter(models.Agent.session_id == "WEAK").first()
        if not agent:
            agent = models.Agent(
                name="WEAK",
                session_id="WEAK",
                delay=1,
                jitter=0.1,
                external_ip="1.1.1.1",
                session_key="qwerty",
                nonce="nonce",
                profile="profile",
                kill_date="killDate",
                working_hours="workingHours",
                lost_limit=60,
                listener="http",
                language="powershell",
                language_version="1",
                high_integrity=True,
                archived=False,
            )
            db.add(agent)
            db.add(models.AgentCheckIn(agent_id=agent.session_id))
            db.flush()

        main.agentcommsv2.agents["WEAK"] = {
            "sessionKey": agent.session_key,
        }

        session_id = agent.session_id

    return session_id  # noqa RET504


@pytest.fixture(scope="module", autouse=True)
def agent_archived(session_local, models, main):
    with session_local.begin() as db:
        agent = (
            db.query(models.Agent)
            .filter(models.Agent.session_id == "iamarchived")
            .first()
        )
        if not agent:
            agent = models.Agent(
                name="iamarchived",
                session_id="iamarchived",
                delay=1,
                jitter=0.1,
                external_ip="1.1.1.1",
                session_key="qwerty",
                nonce="nonce",
                profile="profile",
                kill_date="killDate",
                working_hours="workingHours",
                lost_limit=60,
                listener="http",
                language="powershell",
                language_version="1",
                high_integrity=True,
                archived=True,
            )
            db.add(agent)
            db.add(models.AgentCheckIn(agent_id=agent.session_id))
            db.flush()

        main.agentcommsv2.agents["iamarchived"] = {
            "sessionKey": agent.session_key,
        }

        session_id = agent.session_id

    return session_id  # noqa RET504


@pytest.fixture(scope="module", autouse=True)
def agent_low_integrity(session_local, models, main):
    with session_local.begin() as db:
        agent = (
            db.query(models.Agent).filter(models.Agent.session_id == "WEAK2").first()
        )
        if not agent:
            agent = models.Agent(
                name="WEAK2",
                session_id="WEAK2",
                delay=1,
                jitter=0.1,
                external_ip="1.1.1.1",
                session_key="qwerty",
                nonce="nonce",
                profile="profile",
                kill_date="killDate",
                working_hours="workingHours",
                lost_limit=60,
                listener="http",
                language="powershell",
                language_version="5",
                high_integrity=False,
                archived=False,
            )
            db.add(agent)
            db.add(models.AgentCheckIn(agent_id=agent.session_id))
            db.flush()

        main.agentcommsv2.agents["WEAK2"] = {
            "sessionKey": agent.session_key,
        }

        session_id = agent.session_id

    return session_id  # noqa RET504


@pytest.fixture(scope="module", autouse=True)
def download(client, admin_auth_header, session_local, models):
    response = client.post(
        "/api/v2/downloads",
        headers=admin_auth_header,
        files={
            "file": (
                "test-upload.yaml",
                Path("./empire/test/test-upload.yaml").read_bytes(),
            )
        },
    )

    return response.json()


@pytest.fixture(scope="module", autouse=True)
def bof_download(client, admin_auth_header, session_local, models):
    response = client.post(
        "/api/v2/downloads",
        headers=admin_auth_header,
        files={
            "file": (
                "whoami.x64.o",
                Path("./empire/test/data/whoami.x64.o").read_bytes(),
            )
        },
    )

    return response.json()


@pytest.fixture
def agent_task(client, admin_auth_header, agent):
    resp = client.post(
        f"/api/v2/agents/{agent}/tasks/shell",
        headers=admin_auth_header,
        json={"command": 'echo "HELLO WORLD"'},
    )

    return resp.json()

    # No need to delete the task, it will be deleted when the agent is deleted
    # After the test.


def raise_exception_wrapper(exception):
    def raise_exception(*args, **kwargs):
        raise exception

    return raise_exception


def return_handle_error_message_wrapper(message):
    def return_handle_error_message(*args, **kwargs):
        return handle_error_message(message)

    return return_handle_error_message


@pytest.fixture(scope="module", autouse=True)
def _module_with_validation_exception(main):
    module_name = "this_module_has_a_validation_exception"
    main.modulesv2.modules[module_name] = EmpireModule(
        id=module_name,
        name=module_name,
        language=LanguageEnum.powershell,
        advanced=EmpireModuleAdvanced(
            custom_generate=True,
            generate_class=SimpleNamespace(
                generate=raise_exception_wrapper(ModuleValidationException(module_name))
            ),
        ),
    )

    yield

    del main.modulesv2.modules[module_name]


@pytest.fixture(scope="module", autouse=True)
def _module_with_execution_exception(main):
    module_name = "this_module_has_an_execution_exception"
    main.modulesv2.modules[module_name] = EmpireModule(
        id=module_name,
        name=module_name,
        language=LanguageEnum.powershell,
        advanced=EmpireModuleAdvanced(
            custom_generate=True,
            generate_class=SimpleNamespace(
                generate=raise_exception_wrapper(ModuleExecutionException(module_name))
            ),
        ),
    )

    yield

    del main.modulesv2.modules[module_name]


@pytest.fixture(scope="module", autouse=True)
def _module_with_legacy_handle_error_message(main):
    module_name = "this_module_uses_legacy_handle_error_message"
    main.modulesv2.modules[module_name] = EmpireModule(
        id=module_name,
        name=module_name,
        language=LanguageEnum.powershell,
        advanced=EmpireModuleAdvanced(
            custom_generate=True,
            generate_class=SimpleNamespace(
                generate=return_handle_error_message_wrapper(
                    module_name + ": this is the error"
                )
            ),
        ),
    )

    yield

    del main.modulesv2.modules[module_name]


def test_create_task_shell_agent_not_found(client, admin_auth_header):
    response = client.post(
        "/api/v2/agents/abc/tasks/shell",
        headers=admin_auth_header,
        json={"command": 'echo "HELLO WORLD"'},
    )
    assert response.status_code == status.HTTP_404_NOT_FOUND
    assert response.json()["detail"] == "Agent not found for id abc"


def test_create_task_shell(client, admin_auth_header, agent):
    response = client.post(
        f"/api/v2/agents/{agent}/tasks/shell",
        headers=admin_auth_header,
        json={"command": 'echo "HELLO WORLD"'},
    )
    assert response.status_code == status.HTTP_201_CREATED
    assert response.json()["input"] == 'echo "HELLO WORLD"'
    assert response.json()["id"] > 0


def test_create_task_module_agent_not_found(client, admin_auth_header):
    response = client.post(
        "/api/v2/agents/abc/tasks/module",
        headers=admin_auth_header,
        json={"module_id": "some_module", "options": {}},
    )

    assert response.status_code == status.HTTP_404_NOT_FOUND
    assert response.json()["detail"] == "Agent not found for id abc"


def test_create_task_module_not_found(client, admin_auth_header, agent):
    response = client.post(
        f"/api/v2/agents/{agent}/tasks/module",
        headers=admin_auth_header,
        json={"module_id": "some_module", "options": {}},
    )

    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert response.json()["detail"] == "Module not found for id some_module"


def test_create_task_module(client, admin_auth_header, agent):
    response = client.post(
        f"/api/v2/agents/{agent}/tasks/module",
        headers=admin_auth_header,
        json={
            "module_id": "powershell_credentials_invoke_internal_monologue",
            "options": {
                "Challenge": "1122334455667788",
                "Downgrade": "False",
                "Impersonate": "False",
                "Restore": "False",
                "Verbose": "False",
            },
        },
    )

    assert response.status_code == status.HTTP_201_CREATED
    assert response.json()["id"] > 0
    assert response.json()["input"].startswith("function Invoke-InternalMonologue")
    assert response.json()["agent_id"] == agent
    assert (
        response.json()["module_name"]
        == "powershell_credentials_invoke_internal_monologue"
    )
    assert response.json()["module_options"] == {
        "Agent": agent,
        "Challenge": "1122334455667788",
        "Downgrade": "False",
        "Impersonate": "False",
        "Restore": "False",
        "Verbose": "False",
    }


def test_create_task_module_bof(client, admin_auth_header, agent, bof_download):
    response = client.post(
        f"/api/v2/agents/{agent}/tasks/module",
        headers=admin_auth_header,
        json={
            "module_id": "bof_credentials_nanodump",
            "options": {},
        },
    )

    assert response.status_code == status.HTTP_201_CREATED
    assert response.json()["id"] > 0
    downloads = response.json()["downloads"]
    assert len(downloads) > 0
    download_id = downloads[0]["id"]
    response = client.get(f"/api/v2/downloads/{download_id}", headers=admin_auth_header)

    assert response.status_code == status.HTTP_200_OK
    assert response.json()["id"] == download_id
    assert response.json()["size"] > 0
    tags = response.json()["tags"]
    assert len(tags) > 0
    assert tags[0]["label"] == "task:input"


def test_create_task_module_csharp(client, admin_auth_header, agent):
    response = client.post(
        f"/api/v2/agents/{agent}/tasks/module",
        headers=admin_auth_header,
        json={
            "module_id": "csharp_credentials_sharpdpapi",
            "options": {
                "Command": "triage",
            },
        },
    )

    assert response.status_code == status.HTTP_201_CREATED
    assert response.json()["id"] > 0
    downloads = response.json()["downloads"]
    assert len(downloads) > 0
    download_id = downloads[0]["id"]
    response = client.get(f"/api/v2/downloads/{download_id}", headers=admin_auth_header)

    assert response.status_code == status.HTTP_200_OK
    assert response.json()["id"] == download_id
    assert response.json()["size"] > 0
    tags = response.json()["tags"]
    assert len(tags) > 0
    assert tags[0]["label"] == "task:input"


def test_create_task_module_modified_input(client, admin_auth_header, agent):
    modified_input = dedent(
        """
                function Invoke-InternalMonologue {
                    This is a modified input
                }
            """
    ).lstrip("\n")

    response = client.post(
        f"/api/v2/agents/{agent}/tasks/module",
        headers=admin_auth_header,
        json={
            "module_id": "powershell_credentials_invoke_internal_monologue",
            "options": {
                "Challenge": "1122334455667788",
                "Downgrade": "False",
                "Impersonate": "False",
                "Restore": "False",
                "Verbose": "False",
            },
            "modified_input": modified_input,
        },
    )

    assert response.status_code == status.HTTP_201_CREATED
    assert response.json()["id"] > 0
    assert response.json()["input"].startswith(modified_input)
    assert response.json()["agent_id"] == agent


def test_create_task_module_with_file_option_not_found(
    client, admin_auth_header, agent, bof_download
):
    response = client.post(
        f"/api/v2/agents/{agent}/tasks/module",
        headers=admin_auth_header,
        json={
            "module_id": "powershell_code_execution_invoke_shellcode",
            "options": {
                "File": "999",
            },
        },
    )

    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert response.json()["detail"] == "File not found for 'File' id 999"


def test_create_task_module_with_file_option(
    client, admin_auth_header, agent, bof_download
):
    response = client.post(
        f"/api/v2/agents/{agent}/tasks/module",
        headers=admin_auth_header,
        json={
            "module_id": "powershell_code_execution_invoke_shellcode",
            "options": {
                "File": bof_download["id"],
            },
        },
    )

    assert response.status_code == status.HTTP_201_CREATED
    assert response.json()["id"] > 0


def test_create_task_module_validates_required_options(
    client, admin_auth_header, agent
):
    response = client.post(
        f"/api/v2/agents/{agent}/tasks/module",
        headers=admin_auth_header,
        json={
            "module_id": "powershell_trollsploit_message",
            "options": {
                "MsgText": "",
                "IconType": "Critical",
                "Title": "ERROR - 0xA801B720",
            },
        },
    )

    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert response.json()["detail"] == "required option missing: MsgText"


def test_create_task_module_validates_options_strict(client, admin_auth_header, agent):
    response = client.post(
        f"/api/v2/agents/{agent}/tasks/module",
        headers=admin_auth_header,
        json={
            "module_id": "powershell_situational_awareness_host_foxdump",
            "options": {
                "OutputFunction": "not-valid-choice",
            },
        },
    )

    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert (
        response.json()["detail"]
        == "OutputFunction must be set to one of the suggested values."
    )


def test_create_task_module_language_version_check(
    client, admin_auth_header, agent_low_version
):
    response = client.post(
        f"/api/v2/agents/{agent_low_version}/tasks/module",
        headers=admin_auth_header,
        json={
            "module_id": "powershell_trollsploit_message",
            "options": {
                "MsgText": "TestTestTest",
                "IconType": "Critical",
                "Title": "ERROR - 0xA801B720",
            },
        },
    )

    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert (
        response.json()["detail"]
        == "module requires language version 2 but agent running language version 1"
    )


def test_create_task_module_ignore_language_version_check(
    client, admin_auth_header, agent_low_version
):
    response = client.post(
        f"/api/v2/agents/{agent_low_version}/tasks/module",
        headers=admin_auth_header,
        json={
            "module_id": "powershell_trollsploit_message",
            "ignore_language_version_check": True,
            "options": {
                "MsgText": "TestTestTest",
                "IconType": "Critical",
                "Title": "ERROR - 0xA801B720",
            },
        },
    )

    assert response.status_code == status.HTTP_201_CREATED
    assert response.json()["id"] > 0


def test_create_task_module_admin_check(client, admin_auth_header, agent_low_integrity):
    response = client.post(
        f"/api/v2/agents/{agent_low_integrity}/tasks/module",
        headers=admin_auth_header,
        json={
            "module_id": "powershell_credentials_mimikatz_logonpasswords",
            "options": {},
        },
    )

    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert response.json()["detail"] == "module needs to run in an elevated context"


def test_create_task_module_ignore_admin_check(
    client, admin_auth_header, agent_low_integrity
):
    response = client.post(
        f"/api/v2/agents/{agent_low_integrity}/tasks/module",
        headers=admin_auth_header,
        json={
            "module_id": "powershell_credentials_mimikatz_logonpasswords",
            "ignore_admin_check": True,
            "options": {},
        },
    )

    assert response.status_code == status.HTTP_201_CREATED
    assert response.json()["id"] > 0


def test_create_task_module_validation_exception(
    client, admin_auth_header, agent_low_integrity
):
    response = client.post(
        f"/api/v2/agents/{agent_low_integrity}/tasks/module",
        headers=admin_auth_header,
        json={
            "module_id": "this_module_uses_legacy_handle_error_message",
            "ignore_admin_check": True,
            "options": {},
        },
    )

    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert (
        response.json()["detail"]
        == "this_module_uses_legacy_handle_error_message: this is the error"
    )


def test_create_task_module_execution_exception(
    client, admin_auth_header, agent_low_integrity
):
    response = client.post(
        f"/api/v2/agents/{agent_low_integrity}/tasks/module",
        headers=admin_auth_header,
        json={
            "module_id": "this_module_has_an_execution_exception",
            "ignore_admin_check": True,
            "options": {},
        },
    )

    assert response.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR
    assert response.json()["detail"] == "this_module_has_an_execution_exception"


def test_create_task_handle_error_message(
    client, admin_auth_header, agent_low_integrity
):
    response = client.post(
        f"/api/v2/agents/{agent_low_integrity}/tasks/module",
        headers=admin_auth_header,
        json={
            "module_id": "this_module_has_an_execution_exception",
            "ignore_admin_check": True,
            "options": {},
        },
    )

    assert response.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR
    assert response.json()["detail"] == "this_module_has_an_execution_exception"


def test_create_task_upload_file_not_found(client, admin_auth_header, agent):
    response = client.post(
        f"/api/v2/agents/{agent}/tasks/upload",
        headers=admin_auth_header,
        json={
            "path_to_file": "/tmp",
            "file_id": 9999,
        },
    )

    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert response.json()["detail"] == "Download not found for id 9999"


def test_create_task_upload_agent_not_found(client, admin_auth_header, agent):
    response = client.post(
        "/api/v2/agents/abc/tasks/upload",
        headers=admin_auth_header,
        json={
            "path_to_file": "/tmp",
            "file_id": 1,
        },
    )

    assert response.status_code == status.HTTP_404_NOT_FOUND
    assert response.json()["detail"] == "Agent not found for id abc"


def test_create_task_upload(client, admin_auth_header, agent, download):
    response = client.post(
        f"/api/v2/agents/{agent}/tasks/upload",
        headers=admin_auth_header,
        json={
            "path_to_file": "/tmp",
            "file_id": download["id"],
        },
    )

    assert response.status_code == status.HTTP_201_CREATED
    assert response.json()["id"] > 0
    assert response.json()["input"].startswith("/tmp")


def test_create_task_download_agent_not_found(client, admin_auth_header):
    response = client.post(
        "/api/v2/agents/abc/tasks/download",
        headers=admin_auth_header,
        json={"path_to_file": "/tmp/downloadme.zip"},
    )

    assert response.status_code == status.HTTP_404_NOT_FOUND
    assert response.json()["detail"] == "Agent not found for id abc"


def test_create_task_download(client, admin_auth_header, agent):
    response = client.post(
        f"/api/v2/agents/{agent}/tasks/download",
        headers=admin_auth_header,
        json={"path_to_file": "/tmp/downloadme.zip"},
    )

    assert response.status_code == status.HTTP_201_CREATED
    assert response.json()["id"] > 0


def test_create_socks_agent_not_found(client, admin_auth_header, agent):
    response = client.post(
        "/api/v2/agents/abc/tasks/socks",
        headers=admin_auth_header,
        json={},
    )

    assert response.status_code == status.HTTP_404_NOT_FOUND


def test_create_task_socks(client, admin_auth_header, agent):
    response = client.post(
        f"/api/v2/agents/{agent}/tasks/socks",
        headers=admin_auth_header,
        json={"port": 1080},
    )

    assert response.status_code == status.HTTP_201_CREATED
    assert response.json()["id"] > 0


def test_create_task_jobs_agent_not_found(client, admin_auth_header, agent):
    response = client.post(
        "/api/v2/agents/abc/tasks/jobs",
        headers=admin_auth_header,
        json={},
    )

    assert response.status_code == status.HTTP_404_NOT_FOUND
    assert response.json()["detail"] == "Agent not found for id abc"


def test_create_task_jobs(client, admin_auth_header, agent):
    response = client.post(
        f"/api/v2/agents/{agent}/tasks/jobs",
        headers=admin_auth_header,
        json={},
    )

    assert response.status_code == status.HTTP_200_OK


def test_kill_task_jobs(client, admin_auth_header, agent):
    response = client.post(
        f"/api/v2/agents/{agent}/tasks/kill_job",
        headers=admin_auth_header,
        json={"id": 0},
    )

    assert response.status_code == status.HTTP_200_OK


def test_stop_task_jobs(client, admin_auth_header, agent):
    response = client.post(
        f"/api/v2/agents/{agent}/tasks/stop_job",
        headers=admin_auth_header,
        json={"id": 0},
    )

    assert response.status_code == status.HTTP_200_OK


def test_kill_task_jobs_agent_not_found(client, admin_auth_header, agent):
    response = client.post(
        "/api/v2/agents/abc/tasks/kill_job",
        headers=admin_auth_header,
        json={"id": 0},
    )

    assert response.status_code == status.HTTP_404_NOT_FOUND
    assert response.json()["detail"] == "Agent not found for id abc"


def test_create_task_sysinfo_agent_not_found(client, admin_auth_header):
    response = client.post(
        "/api/v2/agents/abc/tasks/sysinfo", headers=admin_auth_header
    )

    assert response.status_code == status.HTTP_404_NOT_FOUND
    assert response.json()["detail"] == "Agent not found for id abc"


def test_create_task_sysinfo(client, admin_auth_header, agent):
    response = client.post(
        f"/api/v2/agents/{agent}/tasks/sysinfo",
        headers=admin_auth_header,
        json={},
    )

    assert response.status_code == status.HTTP_201_CREATED
    assert response.json()["id"] > 0


def test_create_task_update_comms_agent_not_found(client, admin_auth_header, listener):
    response = client.post(
        "/api/v2/agents/abc/tasks/update_comms",
        headers=admin_auth_header,
        json={"new_listener_id": listener["id"]},
    )

    assert response.status_code == status.HTTP_404_NOT_FOUND
    assert response.json()["detail"] == "Agent not found for id abc"


def test_create_task_update_comms(client, admin_auth_header, agent, listener):
    response = client.post(
        f"/api/v2/agents/{agent}/tasks/update_comms",
        headers=admin_auth_header,
        json={"new_listener_id": listener["id"]},
    )

    assert response.status_code == status.HTTP_201_CREATED
    assert response.json()["id"] > 0


def test_create_task_update_sleep_agent_not_found(client, admin_auth_header, listener):
    response = client.post(
        "/api/v2/agents/abc/tasks/sleep",
        headers=admin_auth_header,
        json={"new_listener_id": listener["id"]},
    )

    assert response.status_code == status.HTTP_404_NOT_FOUND
    assert response.json()["detail"] == "Agent not found for id abc"


def test_create_task_update_sleep_validates_fields(client, admin_auth_header, agent):
    response = client.post(
        f"/api/v2/agents/{agent}/tasks/sleep",
        headers=admin_auth_header,
        json={"delay": -1, "jitter": 5},
    )

    assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    delay_err = next(filter(lambda x: "delay" in x["loc"], response.json()["detail"]))
    jitter_err = next(filter(lambda x: "jitter" in x["loc"], response.json()["detail"]))
    assert delay_err["loc"] == ["body", "delay"]
    assert delay_err["msg"] == "Input should be greater than or equal to 0"
    assert jitter_err["loc"] == ["body", "jitter"]
    assert jitter_err["msg"] == "Input should be less than or equal to 1"


def test_create_task_update_sleep(client, admin_auth_header, agent):
    response = client.post(
        f"/api/v2/agents/{agent}/tasks/sleep",
        headers=admin_auth_header,
        json={"delay": 30, "jitter": 0.5},
    )

    assert response.status_code == status.HTTP_201_CREATED
    assert response.json()["id"] > 0


def test_create_task_update_kill_date_agent_not_found(client, admin_auth_header):
    response = client.post(
        "/api/v2/agents/abc/tasks/kill_date",
        headers=admin_auth_header,
        json={"kill_date": "2021-05-06T00:00Z"},
    )

    assert response.status_code == status.HTTP_404_NOT_FOUND
    assert response.json()["detail"] == "Agent not found for id abc"


def test_create_task_update_kill_date(client, admin_auth_header, agent):
    response = client.post(
        f"/api/v2/agents/{agent}/tasks/kill_date",
        headers=admin_auth_header,
        json={"kill_date": "2021-05-06T00:00Z"},
    )

    assert response.status_code == status.HTTP_201_CREATED
    assert response.json()["id"] > 0


def test_create_task_update_working_hours_agent_not_found(client, admin_auth_header):
    response = client.post(
        "/api/v2/agents/abc/tasks/working_hours",
        headers=admin_auth_header,
        json={"working_hours": "05:00-12:00"},
    )

    assert response.status_code == status.HTTP_404_NOT_FOUND
    assert response.json()["detail"] == "Agent not found for id abc"


def test_create_task_update_working_hours(client, admin_auth_header, agent):
    response = client.post(
        f"/api/v2/agents/{agent}/tasks/working_hours",
        headers=admin_auth_header,
        json={"working_hours": "05:00-12:00"},
    )

    assert response.status_code == status.HTTP_201_CREATED
    assert response.json()["id"] > 0


def test_create_task_directory_list_agent_not_found(client, admin_auth_header):
    response = client.post(
        "/api/v2/agents/abc/tasks/directory_list",
        headers=admin_auth_header,
        json={"path": "/"},
    )

    assert response.status_code == status.HTTP_404_NOT_FOUND
    assert response.json()["detail"] == "Agent not found for id abc"


def test_create_task_directory_list(client, admin_auth_header, agent):
    response = client.post(
        f"/api/v2/agents/{agent}/tasks/directory_list",
        headers=admin_auth_header,
        json={"path": "/"},
    )

    assert response.status_code == status.HTTP_201_CREATED
    assert response.json()["id"] > 0


def test_create_task_exit_agent_not_found(client, admin_auth_header):
    response = client.post("/api/v2/agents/abc/tasks/exit", headers=admin_auth_header)

    assert response.status_code == status.HTTP_404_NOT_FOUND
    assert response.json()["detail"] == "Agent not found for id abc"


def test_get_tasks_for_agent_agent_not_found(client, admin_auth_header):
    response = client.get("/api/v2/agents/abc/tasks", headers=admin_auth_header)
    assert response.status_code == status.HTTP_404_NOT_FOUND
    assert response.json()["detail"] == "Agent not found for id abc"


def test_get_tasks_for_agent(client, admin_auth_header, agent, agent_task):
    response = client.get(f"/api/v2/agents/{agent}/tasks", headers=admin_auth_header)
    assert response.status_code == status.HTTP_200_OK
    assert len(response.json()["records"]) > 0
    assert (
        len(
            list(
                filter(
                    lambda x: x["agent_id"] != agent,
                    response.json()["records"],
                )
            )
        )
        == 0
    )


def test_get_tasks_for_agent_through_all_endpoint(
    client, admin_auth_header, agent, agent_task
):
    response = client.get(
        "/api/v2/agents/tasks",
        headers=admin_auth_header,
        params={"agents": agent},
    )
    assert response.status_code == status.HTTP_200_OK
    assert len(response.json()["records"]) > 0
    assert all(x["agent_id"] == agent for x in response.json()["records"])


def test_get_task_for_agent_agent_not_found(client, admin_auth_header, agent):
    response = client.get("/api/v2/agents/abc/tasks/1", headers=admin_auth_header)
    assert response.status_code == status.HTTP_404_NOT_FOUND
    assert response.json()["detail"] == "Agent not found for id abc"


def test_get_task_for_agent_not_found(client, admin_auth_header, agent):
    response = client.get(
        f"/api/v2/agents/{agent}/tasks/9999", headers=admin_auth_header
    )
    assert response.status_code == status.HTTP_404_NOT_FOUND
    assert (
        response.json()["detail"]
        == f"Task not found for agent {agent} and task id 9999"
    )


def test_get_task_for_agent(client, admin_auth_header, agent, agent_task):
    response = client.get(f"/api/v2/agents/{agent}/tasks/1", headers=admin_auth_header)
    assert response.status_code == status.HTTP_200_OK
    assert response.json()["id"] == 1
    assert response.json()["agent_id"] == agent


def test_create_task_archived_agent(client, admin_auth_header, agent_archived):
    response = client.post(
        f"/api/v2/agents/{agent_archived}/tasks/shell",
        headers=admin_auth_header,
        json={"command": 'echo "HELLO WORLD"'},
    )
    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert response.json()["detail"] == f"[!] Agent {agent_archived} is archived."


def test_delete_task(client, admin_auth_header, agent):
    response = client.post(
        f"/api/v2/agents/{agent}/tasks/shell",
        headers=admin_auth_header,
        json={"command": 'echo "HELLO WORLD"'},
    )
    assert response.status_code == status.HTTP_201_CREATED

    response = client.delete(
        f"/api/v2/agents/{agent}/tasks/{response.json()['id']}",
        headers=admin_auth_header,
    )

    assert response.status_code == status.HTTP_204_NO_CONTENT


def test_last_task(client, admin_auth_header, agent, empire_config):
    response = client.post(
        f"/api/v2/agents/{agent}/tasks/shell",
        headers=admin_auth_header,
        json={"command": 'echo "HELLO WORLD"'},
    )

    assert response.status_code == status.HTTP_201_CREATED
    last_task = empire_config.debug.last_task.file.read_text()
    assert 'echo "HELLO WORLD"' in last_task


def test_create_task_exit(client, admin_auth_header, agent):
    """
    This is at the end so it doesn't interfere with other tests
    """
    response = client.post(
        f"/api/v2/agents/{agent}/tasks/exit",
        headers=admin_auth_header,
        json={},
    )

    assert response.status_code == status.HTTP_201_CREATED
    assert response.json()["id"] > 0
