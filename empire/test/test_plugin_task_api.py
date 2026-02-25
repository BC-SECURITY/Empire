import pytest
from starlette import status

PLUGIN_ID = "basic_reporting"


@pytest.fixture
def plugin_task(main, session_local, models):
    with session_local.begin() as db:
        task = models.PluginTask(
            plugin_id=PLUGIN_ID,
            input="This is the trimmed input for the task.",
            input_full="This is the full input for the task.",
            user_id=1,
            plugin_options={"report": "all"},
        )
        db.add(task)
        db.flush()

        task_id = task.id

    return task_id  # noqa RET504


def test_get_tasks_for_plugin_not_found(client, admin_auth_header):
    response = client.get("/api/v2/plugins/abc/tasks", headers=admin_auth_header)
    assert response.status_code == status.HTTP_404_NOT_FOUND
    assert response.json()["detail"] == "Plugin not found for id abc"


def test_get_tasks_for_plugin(client, admin_auth_header, plugin_task):
    response = client.get(
        f"/api/v2/plugins/{PLUGIN_ID}/tasks", headers=admin_auth_header
    )
    assert response.status_code == status.HTTP_200_OK
    assert len(response.json()["records"]) > 0
    assert all(x["plugin_id"] == PLUGIN_ID for x in response.json()["records"])


def test_get_tasks_for_plugin_through_all_endpoint(
    client, admin_auth_header, plugin_task
):
    response = client.get(
        "/api/v2/plugins/tasks",
        headers=admin_auth_header,
        params={"plugins": PLUGIN_ID},
    )
    assert response.status_code == status.HTTP_200_OK
    assert len(response.json()["records"]) > 0
    assert all(x["plugin_id"] == PLUGIN_ID for x in response.json()["records"])


def test_get_task_for_plugin_plugin_not_found(client, admin_auth_header):
    response = client.get("/api/v2/plugins/abc/tasks/1", headers=admin_auth_header)
    assert response.status_code == status.HTTP_404_NOT_FOUND
    assert response.json()["detail"] == "Plugin not found for id abc"


def test_get_task_for_plugin_not_found(client, admin_auth_header):
    response = client.get(
        f"/api/v2/plugins/{PLUGIN_ID}/tasks/9999", headers=admin_auth_header
    )
    assert response.status_code == status.HTTP_404_NOT_FOUND
    assert (
        response.json()["detail"]
        == f"Task not found for plugin {PLUGIN_ID} and task id 9999"
    )


def test_get_task_for_plugin(client, admin_auth_header, plugin_task):
    response = client.get(
        f"/api/v2/plugins/{PLUGIN_ID}/tasks/{plugin_task}",
        headers=admin_auth_header,
    )
    assert response.status_code == status.HTTP_200_OK
    assert response.json()["id"] == plugin_task
    assert response.json()["plugin_id"] == PLUGIN_ID
    assert response.json()["plugin_options"] == {"report": "all"}
