import pytest
from starlette import status

from empire.server.core.db.models import PluginTaskStatus

PLUGIN_ID = "basic_reporting"


def _test_add_tag(client, admin_auth_header, path, taggable_id):
    resp = client.post(
        f"{path}/{taggable_id}/tags",
        headers=admin_auth_header,
        json={"name": "test:tag", "value": "test:value"},
    )
    assert resp.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    actual = resp.json()
    assert actual == {
        "detail": [
            {
                "ctx": {"pattern": "^[^:]+$"},
                "input": "test:tag",
                "loc": ["body", "name"],
                "msg": "String should match pattern '^[^:]+$'",
                "type": "string_pattern_mismatch",
            },
            {
                "ctx": {"pattern": "^[^:]+$"},
                "input": "test:value",
                "loc": ["body", "value"],
                "msg": "String should match pattern '^[^:]+$'",
                "type": "string_pattern_mismatch",
            },
        ]
    }

    resp = client.post(
        f"{path}/{taggable_id}/tags",
        headers=admin_auth_header,
        json={"name": "test_tag", "value": "test_value"},
    )

    expected_tag_1 = {
        "name": "test_tag",
        "value": "test_value",
        "color": None,
        "label": "test_tag:test_value",
    }

    assert resp.status_code == status.HTTP_201_CREATED
    actual_tag_1 = resp.json()
    actual_tag_1.pop("id")
    assert actual_tag_1 == expected_tag_1

    resp = client.get(f"{path}/{taggable_id}", headers=admin_auth_header)
    assert resp.status_code == status.HTTP_200_OK

    actual_tags = resp.json()["tags"]
    assert len(actual_tags) == 1

    actual_tags[0].pop("id")
    assert actual_tags == [expected_tag_1]

    resp = client.post(
        f"{path}/{taggable_id}/tags",
        headers=admin_auth_header,
        json={
            "name": "test_tag",
            "value": "test_value",
            "color": "#0000FF",
        },
    )

    expected_tag_2 = {
        "name": "test_tag",
        "value": "test_value",
        "color": "#0000FF",
        "label": "test_tag:test_value",
    }

    assert resp.status_code == status.HTTP_201_CREATED
    actual_tag_2 = resp.json()
    actual_tag_2.pop("id")
    assert actual_tag_2 == expected_tag_2

    resp = client.get(f"{path}/{taggable_id}", headers=admin_auth_header)
    assert resp.status_code == status.HTTP_200_OK

    actual_tags = resp.json()["tags"]
    tag_count = 2
    assert len(actual_tags) == tag_count

    for tag in actual_tags:
        tag.pop("id")

    assert actual_tags == [expected_tag_1, expected_tag_2]

    for tag in resp.json()["tags"]:
        resp = client.delete(
            f"{path}/{taggable_id}/tags/{tag['id']}",
            headers=admin_auth_header,
        )
        assert resp.status_code == status.HTTP_204_NO_CONTENT


def _test_update_tag(client, admin_auth_header, path, taggable_id):
    resp = client.post(
        f"{path}/{taggable_id}/tags",
        headers=admin_auth_header,
        json={"name": "test_tag", "value": "test_value"},
    )

    assert resp.status_code == status.HTTP_201_CREATED

    expected_tag = {
        "name": "test_tag_updated",
        "value": "test_value_updated",
        "color": "#0000FF",
        "label": "test_tag_updated:test_value_updated",
    }

    resp_bad = client.put(
        f"{path}/{taggable_id}/tags/{resp.json()['id']}",
        headers=admin_auth_header,
        json={"name": "test:tag", "value": "test:value"},
    )
    assert resp_bad.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    actual = resp_bad.json()
    assert actual == {
        "detail": [
            {
                "ctx": {"pattern": "^[^:]+$"},
                "input": "test:tag",
                "loc": ["body", "name"],
                "msg": "String should match pattern '^[^:]+$'",
                "type": "string_pattern_mismatch",
            },
            {
                "ctx": {"pattern": "^[^:]+$"},
                "input": "test:value",
                "loc": ["body", "value"],
                "msg": "String should match pattern '^[^:]+$'",
                "type": "string_pattern_mismatch",
            },
        ]
    }

    resp = client.put(
        f"{path}/{taggable_id}/tags/{resp.json()['id']}",
        headers=admin_auth_header,
        json=expected_tag,
    )

    assert resp.status_code == status.HTTP_200_OK

    actual_tag = resp.json()
    actual_tag.pop("id")
    assert actual_tag == expected_tag

    resp = client.delete(
        f"{path}/{taggable_id}/tags/{resp.json()['id']}",
        headers=admin_auth_header,
    )
    assert resp.status_code == status.HTTP_204_NO_CONTENT


def _test_delete_tag(client, admin_auth_header, path, taggable_id):
    resp = client.post(
        f"{path}/{taggable_id}/tags",
        headers=admin_auth_header,
        json={"name": "test_tag", "value": "test_value"},
    )

    assert resp.status_code == status.HTTP_201_CREATED

    resp = client.delete(
        f"{path}/{taggable_id}/tags/{resp.json()['id']}",
        headers=admin_auth_header,
    )
    assert resp.status_code == status.HTTP_204_NO_CONTENT

    resp = client.get(f"{path}/{taggable_id}", headers=admin_auth_header)
    assert resp.status_code == status.HTTP_200_OK
    assert resp.json()["tags"] == []


def test_listener_add_tag(client, admin_auth_header, listener):
    _test_add_tag(client, admin_auth_header, "/api/v2/listeners", listener["id"])


def test_agent_add_tag(client, admin_auth_header, agent):
    _test_add_tag(client, admin_auth_header, "/api/v2/agents", agent)


def test_agent_task_add_tag(client, admin_auth_header, agent_task):
    _test_add_tag(
        client,
        admin_auth_header,
        f"/api/v2/agents/{agent_task['agent_id']}/tasks",
        agent_task["id"],
    )


def test_plugin_task_add_tag(client, admin_auth_header, plugin_task):
    _test_add_tag(
        client,
        admin_auth_header,
        "/api/v2/plugins/basic_reporting/tasks",
        plugin_task,
    )


def test_credential_add_tag(client, admin_auth_header, credential):
    _test_add_tag(client, admin_auth_header, "/api/v2/credentials", credential)


def test_download_add_tag(client, admin_auth_header, download):
    _test_add_tag(client, admin_auth_header, "/api/v2/downloads", download)


def test_listener_update_tag(client, admin_auth_header, listener):
    _test_update_tag(client, admin_auth_header, "/api/v2/listeners", listener["id"])


def test_agent_update_tag(client, admin_auth_header, agent):
    _test_update_tag(client, admin_auth_header, "/api/v2/agents", agent)


def test_agent_task_update_tag(client, admin_auth_header, agent_task):
    _test_update_tag(
        client,
        admin_auth_header,
        f"/api/v2/agents/{agent_task['agent_id']}/tasks",
        agent_task["id"],
    )


def test_plugin_task_update_tag(client, admin_auth_header, plugin_task):
    _test_update_tag(
        client,
        admin_auth_header,
        "/api/v2/plugins/basic_reporting/tasks",
        plugin_task,
    )


def test_credential_update_tag(client, admin_auth_header, credential):
    _test_update_tag(client, admin_auth_header, "/api/v2/credentials", credential)


def test_download_update_tag(client, admin_auth_header, download):
    _test_update_tag(client, admin_auth_header, "/api/v2/downloads", download)


def test_listener_delete_tag(client, admin_auth_header, listener):
    _test_delete_tag(client, admin_auth_header, "/api/v2/listeners", listener["id"])


def test_agent_delete_tag(client, admin_auth_header, agent):
    _test_delete_tag(client, admin_auth_header, "/api/v2/agents", agent)


def test_agent_task_delete_tag(client, admin_auth_header, agent_task):
    _test_delete_tag(
        client,
        admin_auth_header,
        f"/api/v2/agents/{agent_task['agent_id']}/tasks",
        agent_task["id"],
    )


def test_plugin_task_delete_tag(client, admin_auth_header, plugin_task):
    _test_delete_tag(
        client,
        admin_auth_header,
        "/api/v2/plugins/basic_reporting/tasks",
        plugin_task,
    )


def test_credential_delete_tag(client, admin_auth_header, credential):
    _test_delete_tag(client, admin_auth_header, "/api/v2/credentials", credential)


def test_download_delete_tag(client, admin_auth_header, download):
    _test_delete_tag(client, admin_auth_header, "/api/v2/downloads", download)


@pytest.fixture
def create_tags(
    client,
    admin_auth_header,
    listener,
    agent,
    agent_task,
    plugin_task,
    credential,
    download,
):
    paths = [
        "/api/v2/listeners",
        "/api/v2/agents",
        f"/api/v2/agents/{agent_task['agent_id']}/tasks",
        "/api/v2/plugins/basic_reporting/tasks",
        "/api/v2/credentials",
        "/api/v2/downloads",
    ]
    cleanup = []
    expected_tags = []
    for taggable in zip(
        [listener, agent, agent_task, plugin_task, credential, download],
        paths,
        strict=True,
    ):
        if isinstance(taggable[0], dict):
            taggable_id = taggable[0]["id"]
        else:
            taggable_id = taggable[0]
        resp = client.post(
            f"{taggable[1]}/{taggable_id}/tags",
            headers=admin_auth_header,
            json={"name": f"test_tag_{taggable[1]}", "value": "test_value"},
        )
        assert resp.status_code == status.HTTP_201_CREATED

        res = resp.json()
        cleanup.append(f"{taggable[1]}/{taggable_id}/tags/{res['id']}")
        res.pop("id")
        expected_tags.append(res)

    yield expected_tags

    for tag in cleanup:
        resp = client.delete(tag, headers=admin_auth_header)
        assert resp.status_code == status.HTTP_204_NO_CONTENT


def test_get_tags(client, admin_auth_header, create_tags):
    expected_tags = create_tags
    resp = client.get("/api/v2/tags?order_by=name", headers=admin_auth_header)
    assert resp.status_code == status.HTTP_200_OK

    actual_tags = resp.json()["records"]
    for tag in actual_tags:
        tag.pop("id")

    for tag in expected_tags:
        assert tag in actual_tags


@pytest.fixture
def create_agent_tasks_with_tags(
    client, admin_auth_header, agent, session_local, models
):
    agent_id = agent
    agent_tasks = []
    tags = []
    for i in range(3):
        resp = client.post(
            f"/api/v2/agents/{agent_id}/tasks/shell",
            headers=admin_auth_header,
            json={"command": f"whoami_{i}"},
        )
        assert resp.status_code == status.HTTP_201_CREATED
        agent_tasks.append(resp.json())

    for i, agent_task in enumerate(agent_tasks):
        resp = client.post(
            f"/api/v2/agents/{agent_id}/tasks/{agent_task['id']}/tags",
            headers=admin_auth_header,
            json={"name": f"test_tag_{i}", "value": f"test_value_{i}"},
        )
        assert resp.status_code == status.HTTP_201_CREATED
        tags.append((agent_task, resp.json()))

    return agent_tasks


def test_get_agent_tasks_tag_filter(
    client, admin_auth_header, agent, create_agent_tasks_with_tags
):
    resp = client.get(f"/api/v2/agents/{agent}/tasks", headers=admin_auth_header)

    task_count = 3
    assert resp.status_code == status.HTTP_200_OK
    assert len(resp.json()["records"]) == task_count

    resp = client.get(
        f"/api/v2/agents/{agent}/tasks?tags=test_tag_0:test_value_0",
        headers=admin_auth_header,
    )

    assert resp.status_code == status.HTTP_200_OK
    assert len(resp.json()["records"]) == 1
    assert resp.json()["records"][0]["input"] == "whoami_0"
    assert resp.json()["records"][0]["tags"][0]["name"] == "test_tag_0"

    resp = client.get(
        f"/api/v2/agents/{agent}/tasks?tags=test_tag_0:test_value_0&tags=test_tag_1:test_value_1",
        headers=admin_auth_header,
    )

    task_count = 2
    assert resp.status_code == status.HTTP_200_OK
    assert len(resp.json()["records"]) == task_count
    assert resp.json()["records"][1]["input"] == "whoami_0"
    assert resp.json()["records"][1]["tags"][0]["name"] == "test_tag_0"
    assert resp.json()["records"][0]["input"] == "whoami_1"
    assert resp.json()["records"][0]["tags"][0]["name"] == "test_tag_1"

    # Test tag value bad
    resp = client.get(
        f"/api/v2/agents/{agent}/tasks?tags=test_tag_0", headers=admin_auth_header
    )

    assert resp.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY
    assert (
        resp.json()["detail"][0]["msg"] == "String should match pattern '^[^:]+:[^:]+$'"
    )


@pytest.fixture
def create_plugin_tasks_with_tags(models, session_local, client, admin_auth_header):
    plugin_tasks = []
    tags = []
    for i in range(3):
        plugin_task = models.PluginTask(
            plugin_id=PLUGIN_ID,
            input=f"input {i}",
            input_full=f"input {i}",
            user_id=None,
            status=PluginTaskStatus.completed,
        )
        with session_local.begin() as db:
            db.add(plugin_task)
            db.flush()
            plugin_tasks.append({"id": plugin_task.id})

    for i, plugin_task in enumerate(plugin_tasks):
        resp = client.post(
            f"/api/v2/plugins/{PLUGIN_ID}/tasks/{plugin_task['id']}/tags",
            headers=admin_auth_header,
            json={"name": f"test_tag_{i}", "value": f"test_value_{i}"},
        )
        assert resp.status_code == status.HTTP_201_CREATED
        tags.append((plugin_task, resp.json()))

    yield plugin_tasks

    for task, tag in tags:
        resp = client.delete(
            f"/api/v2/plugins/{PLUGIN_ID}/tasks/{task['id']}/tags/{tag['id']}",
            headers=admin_auth_header,
        )
        assert resp.status_code == status.HTTP_204_NO_CONTENT


def test_get_plugin_tasks_tag_filter(
    client, admin_auth_header, create_plugin_tasks_with_tags
):
    resp = client.get(f"/api/v2/plugins/{PLUGIN_ID}/tasks", headers=admin_auth_header)

    task_count = 3
    assert resp.status_code == status.HTTP_200_OK
    assert len(resp.json()["records"]) > task_count

    resp = client.get(
        f"/api/v2/plugins/{PLUGIN_ID}/tasks?tags=test_tag_0:test_value_0",
        headers=admin_auth_header,
    )

    assert resp.status_code == status.HTTP_200_OK
    assert len(resp.json()["records"]) == 1
    assert resp.json()["records"][0]["input"] == "input 0"
    assert resp.json()["records"][0]["tags"][0]["name"] == "test_tag_0"

    resp = client.get(
        f"/api/v2/plugins/{PLUGIN_ID}/tasks?tags=test_tag_0:test_value_0&tags=test_tag_1:test_value_1",
        headers=admin_auth_header,
    )

    task_count = 2
    assert resp.status_code == status.HTTP_200_OK
    assert len(resp.json()["records"]) == task_count
    assert resp.json()["records"][1]["input"] == "input 0"
    assert resp.json()["records"][1]["tags"][0]["name"] == "test_tag_0"
    assert resp.json()["records"][0]["input"] == "input 1"
    assert resp.json()["records"][0]["tags"][0]["name"] == "test_tag_1"

    # Test tag value bad
    resp = client.get(
        f"/api/v2/plugins/{PLUGIN_ID}/tasks?tags=test_tag_0",
        headers=admin_auth_header,
    )

    assert resp.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY
    assert (
        resp.json()["detail"][0]["msg"] == "String should match pattern '^[^:]+:[^:]+$'"
    )


@pytest.fixture
def create_downloads_with_tags(models, session_local, client, admin_auth_header):
    downloads = []
    tags = []
    for i in range(3):
        download = models.Download(
            location=f"path/{i}", filename=f"filename_{i}", size=1
        )
        with session_local.begin() as db:
            db.add(download)
            db.flush()
            downloads.append({"id": download.id})

    for i, download in enumerate(downloads):
        resp = client.post(
            f"/api/v2/downloads/{download['id']}/tags",
            headers=admin_auth_header,
            json={"name": f"test_tag_{i}", "value": f"test_value_{i}"},
        )
        assert resp.status_code == status.HTTP_201_CREATED
        tags.append(resp.json())

    yield downloads

    for tag in tags:
        resp = client.delete(
            f"/api/v2/downloads/{downloads[0]['id']}/tags/{tag['id']}",
            headers=admin_auth_header,
        )
        assert resp.status_code == status.HTTP_204_NO_CONTENT


def test_get_downloads_tag_filter(
    client, admin_auth_header, create_downloads_with_tags
):
    resp = client.get("/api/v2/downloads/", headers=admin_auth_header)

    download_count = 3
    assert resp.status_code == status.HTTP_200_OK
    assert len(resp.json()["records"]) > download_count

    resp = client.get(
        "/api/v2/downloads?tags=test_tag_0:test_value_0",
        headers=admin_auth_header,
    )

    tag_count = 1
    assert resp.status_code == status.HTTP_200_OK
    assert len(resp.json()["records"]) == tag_count
    assert resp.json()["records"][0]["location"] == "path/0"
    assert resp.json()["records"][0]["tags"][0]["name"] == "test_tag_0"

    resp = client.get(
        "/api/v2/downloads?tags=test_tag_0:test_value_0&tags=test_tag_1:test_value_1",
        headers=admin_auth_header,
    )

    download_count = 2
    assert resp.status_code == status.HTTP_200_OK
    assert len(resp.json()["records"]) == download_count

    record_0 = next(filter(lambda x: x["location"] == "path/0", resp.json()["records"]))
    record_1 = next(filter(lambda x: x["location"] == "path/1", resp.json()["records"]))

    assert record_0
    assert record_0["location"] == "path/0"
    assert record_0["tags"][0]["name"] == "test_tag_0"

    assert record_1
    assert record_1["location"] == "path/1"
    assert record_1["tags"][0]["name"] == "test_tag_1"

    # Test tag value bad
    resp = client.get("/api/v2/downloads?tags=test_tag_0", headers=admin_auth_header)

    assert resp.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY
    assert (
        resp.json()["detail"][0]["msg"] == "String should match pattern '^[^:]+:[^:]+$'"
    )
