import re
from collections import Counter

import pytest
from fastapi import APIRouter, FastAPI
from fastapi.testclient import TestClient
from starlette import status

from empire.server.api.app import custom_generate_unique_id

HTTP_METHODS = frozenset(
    {"get", "put", "post", "delete", "options", "head", "patch", "trace"}
)

# Every operation id in the spec. These are the method names a generated
# client exposes, so a change here is a change to every consumer: the map
# is exhaustive on purpose, to make that a reviewable diff rather than a
# silent rename. Regenerate deliberately, never to make the test pass.
EXPECTED_OPERATION_IDS = {
    ("get", "/api/v2/admin/ip_filtering"): "admin_get_ip_filtering",
    ("put", "/api/v2/admin/ip_filtering"): "admin_toggle_ip_filtering",
    ("get", "/api/v2/agents"): "agents_read_agents",
    ("get", "/api/v2/agents/checkins"): "agents_read_agent_checkins_all",
    (
        "get",
        "/api/v2/agents/checkins/aggregate",
    ): "agents_read_agent_checkins_aggregate",
    ("get", "/api/v2/agents/tasks"): "agents_read_tasks_all_agents",
    ("get", "/api/v2/agents/{agent_id}/files/root"): "agents_read_file_root",
    ("get", "/api/v2/agents/{agent_id}/files/{uid}"): "agents_read_file",
    ("get", "/api/v2/agents/{agent_id}/tasks"): "agents_read_tasks",
    ("post", "/api/v2/agents/{agent_id}/tasks/chdir"): "agents_create_task_chdir",
    (
        "post",
        "/api/v2/agents/{agent_id}/tasks/directory_list",
    ): "agents_create_task_update_directory_list",
    ("post", "/api/v2/agents/{agent_id}/tasks/download"): "agents_create_task_download",
    ("post", "/api/v2/agents/{agent_id}/tasks/exit"): "agents_create_task_exit",
    ("post", "/api/v2/agents/{agent_id}/tasks/jobs"): "agents_create_task_jobs",
    (
        "post",
        "/api/v2/agents/{agent_id}/tasks/kill_date",
    ): "agents_create_task_update_kill_date",
    ("post", "/api/v2/agents/{agent_id}/tasks/kill_job"): "agents_create_task_kill_job",
    ("post", "/api/v2/agents/{agent_id}/tasks/module"): "agents_create_task_module",
    (
        "post",
        "/api/v2/agents/{agent_id}/tasks/processes",
    ): "agents_create_task_processes",
    ("post", "/api/v2/agents/{agent_id}/tasks/shell"): "agents_create_task_shell",
    (
        "post",
        "/api/v2/agents/{agent_id}/tasks/sleep",
    ): "agents_create_task_update_sleep",
    ("post", "/api/v2/agents/{agent_id}/tasks/socks"): "agents_create_task_socks",
    ("post", "/api/v2/agents/{agent_id}/tasks/stop_job"): "agents_create_task_stop_job",
    ("post", "/api/v2/agents/{agent_id}/tasks/sysinfo"): "agents_create_task_sysinfo",
    ("post", "/api/v2/agents/{agent_id}/tasks/upload"): "agents_create_task_upload",
    (
        "post",
        "/api/v2/agents/{agent_id}/tasks/working_hours",
    ): "agents_create_task_update_working_hours",
    ("delete", "/api/v2/agents/{agent_id}/tasks/{uid}"): "agents_delete_task",
    ("get", "/api/v2/agents/{agent_id}/tasks/{uid}"): "agents_read_task",
    ("post", "/api/v2/agents/{agent_id}/tasks/{uid}/tags"): "agents_add_task_tag",
    (
        "delete",
        "/api/v2/agents/{agent_id}/tasks/{uid}/tags/{tag_id}",
    ): "agents_delete_task_tag",
    ("get", "/api/v2/agents/{uid}"): "agents_read_agent",
    ("put", "/api/v2/agents/{uid}"): "agents_update_agent",
    ("get", "/api/v2/agents/{uid}/checkins"): "agents_read_agent_checkins",
    ("post", "/api/v2/agents/{uid}/tags"): "agents_add_agent_tag",
    ("delete", "/api/v2/agents/{uid}/tags/{tag_id}"): "agents_delete_agent_tag",
    ("get", "/api/v2/bypasses"): "bypasses_read_bypasses",
    ("post", "/api/v2/bypasses"): "bypasses_create_bypass",
    ("post", "/api/v2/bypasses/reload"): "bypasses_reload_bypasses",
    ("post", "/api/v2/bypasses/reset"): "bypasses_reset_bypasses",
    ("delete", "/api/v2/bypasses/{uid}"): "bypasses_delete_bypass",
    ("get", "/api/v2/bypasses/{uid}"): "bypasses_read_bypass",
    ("put", "/api/v2/bypasses/{uid}"): "bypasses_update_bypass",
    ("get", "/api/v2/credentials"): "credentials_read_credentials",
    ("post", "/api/v2/credentials"): "credentials_create_credential",
    ("delete", "/api/v2/credentials/{uid}"): "credentials_delete_credential",
    ("get", "/api/v2/credentials/{uid}"): "credentials_read_credential",
    ("put", "/api/v2/credentials/{uid}"): "credentials_update_credential",
    ("post", "/api/v2/credentials/{uid}/tags"): "credentials_add_tag",
    ("delete", "/api/v2/credentials/{uid}/tags/{tag_id}"): "credentials_delete_tag",
    ("get", "/api/v2/downloads"): "downloads_read_downloads",
    ("post", "/api/v2/downloads"): "downloads_create_download",
    ("get", "/api/v2/downloads/{uid}"): "downloads_read_download",
    ("get", "/api/v2/downloads/{uid}/download"): "downloads_download_download",
    ("post", "/api/v2/downloads/{uid}/tags"): "downloads_add_tag",
    ("delete", "/api/v2/downloads/{uid}/tags/{tag_id}"): "downloads_delete_tag",
    ("get", "/api/v2/hosts"): "hosts_read_hosts",
    ("get", "/api/v2/hosts/{host_id}/processes"): "hosts_read_processes",
    ("get", "/api/v2/hosts/{host_id}/processes/{uid}"): "hosts_read_process",
    ("get", "/api/v2/hosts/{uid}"): "hosts_read_host",
    ("get", "/api/v2/ips"): "ips_read_ips",
    ("post", "/api/v2/ips"): "ips_create_ip",
    ("delete", "/api/v2/ips/{uid}"): "ips_delete_ip",
    ("get", "/api/v2/ips/{uid}"): "ips_read_ip",
    ("get", "/api/v2/listener-templates"): "listener_templates_get_listener_templates",
    (
        "get",
        "/api/v2/listener-templates/{uid}",
    ): "listener_templates_get_listener_template",
    ("get", "/api/v2/listeners"): "listeners_read_listeners",
    ("post", "/api/v2/listeners"): "listeners_create_listener",
    ("delete", "/api/v2/listeners/{uid}"): "listeners_delete_listener",
    ("get", "/api/v2/listeners/{uid}"): "listeners_read_listener",
    ("put", "/api/v2/listeners/{uid}"): "listeners_update_listener",
    ("get", "/api/v2/listeners/{uid}/autorun"): "listeners_get_listener_autorun",
    ("put", "/api/v2/listeners/{uid}/autorun"): "listeners_update_listener_autorun",
    ("post", "/api/v2/listeners/{uid}/tags"): "listeners_add_tag",
    ("delete", "/api/v2/listeners/{uid}/tags/{tag_id}"): "listeners_delete_tag",
    ("get", "/api/v2/malleable-profiles"): "malleable_profiles_read_profiles",
    ("post", "/api/v2/malleable-profiles"): "malleable_profiles_create_profile",
    ("post", "/api/v2/malleable-profiles/reload"): "malleable_profiles_reload_profiles",
    ("post", "/api/v2/malleable-profiles/reset"): "malleable_profiles_reset_profiles",
    ("delete", "/api/v2/malleable-profiles/{uid}"): "malleable_profiles_delete_profile",
    ("get", "/api/v2/malleable-profiles/{uid}"): "malleable_profiles_read_profile",
    ("put", "/api/v2/malleable-profiles/{uid}"): "malleable_profiles_update_profile",
    ("get", "/api/v2/meta/version"): "meta_read_empire_version",
    ("get", "/api/v2/modules"): "modules_read_modules",
    ("put", "/api/v2/modules/bulk/enable"): "modules_update_bulk_enable",
    ("post", "/api/v2/modules/reload"): "modules_reload_modules",
    ("post", "/api/v2/modules/reset"): "modules_reset_modules",
    ("get", "/api/v2/modules/{uid}"): "modules_read_module",
    ("put", "/api/v2/modules/{uid}"): "modules_update_module",
    ("get", "/api/v2/modules/{uid}/script"): "modules_read_module_script",
    ("get", "/api/v2/obfuscation/global"): "obfuscation_read_obfuscation_configs",
    (
        "get",
        "/api/v2/obfuscation/global/{language}",
    ): "obfuscation_read_obfuscation_config",
    (
        "put",
        "/api/v2/obfuscation/global/{language}",
    ): "obfuscation_update_obfuscation_config",
    (
        "delete",
        "/api/v2/obfuscation/global/{language}/preobfuscate",
    ): "obfuscation_remove_preobfuscated_modules",
    (
        "post",
        "/api/v2/obfuscation/global/{language}/preobfuscate",
    ): "obfuscation_preobfuscate_modules",
    ("get", "/api/v2/obfuscation/keywords"): "obfuscation_read_keywords",
    ("post", "/api/v2/obfuscation/keywords"): "obfuscation_create_keyword",
    ("delete", "/api/v2/obfuscation/keywords/{uid}"): "obfuscation_delete_keyword",
    ("get", "/api/v2/obfuscation/keywords/{uid}"): "obfuscation_read_keyword",
    ("put", "/api/v2/obfuscation/keywords/{uid}"): "obfuscation_update_keyword",
    (
        "post",
        "/api/v2/obfuscation/modules/preobfuscate",
    ): "obfuscation_preobfuscate_specific_modules",
    ("get", "/api/v2/plugin-registries/marketplace"): "plugins_get_marketplace",
    ("post", "/api/v2/plugin-registries/marketplace/install"): "plugins_install_plugin",
    ("get", "/api/v2/plugins"): "plugins_read_plugins",
    ("post", "/api/v2/plugins/install/git"): "plugins_install_plugin_git",
    ("post", "/api/v2/plugins/install/tar"): "plugins_install_plugin_tar",
    ("post", "/api/v2/plugins/reload"): "plugins_reload_plugins",
    ("get", "/api/v2/plugins/tasks"): "plugins_read_tasks_all_plugins",
    ("get", "/api/v2/plugins/{plugin_id}"): "plugins_read_plugin",
    ("put", "/api/v2/plugins/{plugin_id}"): "plugins_update_plugin",
    ("post", "/api/v2/plugins/{plugin_id}/execute"): "plugins_execute_plugin",
    ("put", "/api/v2/plugins/{plugin_id}/settings"): "plugins_update_plugin_settings",
    ("get", "/api/v2/plugins/{plugin_id}/tasks"): "plugins_read_tasks",
    ("get", "/api/v2/plugins/{plugin_id}/tasks/{uid}"): "plugins_read_task",
    ("post", "/api/v2/plugins/{plugin_id}/tasks/{uid}/tags"): "plugins_add_task_tag",
    (
        "delete",
        "/api/v2/plugins/{plugin_id}/tasks/{uid}/tags/{tag_id}",
    ): "plugins_delete_task_tag",
    ("get", "/api/v2/stager-templates"): "stager_templates_get_stager_templates",
    ("get", "/api/v2/stager-templates/{uid}"): "stager_templates_get_stager_template",
    ("get", "/api/v2/stagers"): "stagers_read_stagers",
    ("post", "/api/v2/stagers"): "stagers_create_stager",
    ("delete", "/api/v2/stagers/{uid}"): "stagers_delete_stager",
    ("get", "/api/v2/stagers/{uid}"): "stagers_read_stager",
    ("put", "/api/v2/stagers/{uid}"): "stagers_update_stager",
    ("get", "/api/v2/tags"): "tags_get_tags",
    ("post", "/api/v2/tags"): "tags_create_tag",
    ("delete", "/api/v2/tags/{tag_id}"): "tags_delete_tag",
    ("get", "/api/v2/tags/{tag_id}"): "tags_get_tag",
    ("put", "/api/v2/tags/{tag_id}"): "tags_update_tag",
    ("get", "/api/v2/users"): "users_read_users",
    ("post", "/api/v2/users"): "users_create_user",
    ("get", "/api/v2/users/me"): "users_read_user_me",
    ("get", "/api/v2/users/{uid}"): "users_read_user",
    ("put", "/api/v2/users/{uid}"): "users_update_user",
    ("post", "/api/v2/users/{uid}/avatar"): "users_create_avatar",
    ("put", "/api/v2/users/{uid}/password"): "users_update_user_password",
    ("get", "/healthz"): "admin_health_check",
    ("post", "/token"): "users_login_for_access_token",
}


@pytest.fixture(scope="module")
def operations(client):
    response = client.get("/openapi.json")
    assert response.status_code == status.HTTP_200_OK
    spec = response.json()
    # A path item may also carry non-operation keys (`parameters`, `servers`,
    # `summary`); unfiltered they reach the assertions as a bare KeyError.
    found = [
        (method, path, operation)
        for path, path_item in spec["paths"].items()
        for method, operation in path_item.items()
        if method in HTTP_METHODS
    ]
    # Every invariant below is filter-then-assert, so an empty list would
    # satisfy all of them without checking anything.
    assert found
    return found


def test_openapi(client):
    response = client.get("/openapi.json")
    assert response.status_code == status.HTTP_200_OK
    assert response.json()["openapi"] == "3.1.0"


def test_every_operation_has_exactly_one_tag(operations):
    # custom_generate_unique_id names an operation after its first tag, so a
    # second tag would silently drop out of the id.
    assert [
        (method, path)
        for method, path, operation in operations
        if len(operation.get("tags", [])) != 1
    ] == []


def test_operation_ids_are_unique(operations):
    ids = [operation["operationId"] for _, _, operation in operations]
    assert [oid for oid, count in Counter(ids).items() if count > 1] == []


def test_operation_ids_are_identifier_safe(operations):
    # Generated clients turn these into method names, and every generator
    # mangles a non-identifier differently.
    assert [
        operation["operationId"]
        for _, _, operation in operations
        if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]*", operation["operationId"])
    ] == []


def test_operation_ids_start_with_their_tag(operations):
    # EXPECTED_OPERATION_IDS pins today's ids but states no rule, so once it is
    # regenerated it accepts whatever the new ids are; this states the rule. The
    # normalization is spelled out again here on purpose: importing it from
    # app.py would make the assertion agree with whatever that function does.
    assert [
        (method, path, operation["operationId"])
        for method, path, operation in operations
        if not operation["operationId"].startswith(
            re.sub(r"[^a-zA-Z0-9]+", "_", operation["tags"][0]) + "_"
        )
    ] == []


def test_operation_ids_match_the_snapshot(operations):
    actual = {
        (method, path): operation["operationId"]
        for method, path, operation in operations
    }
    assert actual == EXPECTED_OPERATION_IDS


def test_untagged_route_is_rejected_by_name():
    # Ids are built lazily, so an untagged route registers cleanly and then
    # breaks the schema and the route table alike; see custom_generate_unique_id.
    app = FastAPI(generate_unique_id_function=custom_generate_unique_id)
    router = APIRouter(prefix="/untagged")

    @router.get("/thing")
    def read_thing():
        return {}

    app.include_router(router)

    # Registered after the untagged route, so reaching it walks past the fault.
    tagged = APIRouter(prefix="/tagged", tags=["sibling"])

    @tagged.get("/thing")
    def read_sibling():
        return {}

    app.include_router(tagged)

    with pytest.raises(ValueError, match="/untagged/thing declares no tag"):
        app.openapi()

    with TestClient(app) as test_client:
        with pytest.raises(ValueError, match="/untagged/thing declares no tag"):
            test_client.get("/untagged/thing")

        # The point of the named error: a request for an entirely different
        # route still fails, and the message names the route actually at fault.
        # Unguarded this is a bare `IndexError: list index out of range`.
        with pytest.raises(ValueError, match="/untagged/thing declares no tag"):
            test_client.get("/tagged/thing")
