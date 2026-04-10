import os
import shutil
import sys
from contextlib import suppress
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING

import pytest
import yaml
from starlette.testclient import TestClient

from empire.server.utils.string_util import get_random_string
from empire.test.test_listener_api import get_base_listener, get_base_malleable_listener

if TYPE_CHECKING:
    from empire.server.core.config.config_manager import EmpireConfig

SERVER_CONFIG_LOC = "empire/test/test_server_config.yaml"
DEFAULT_ARGV = ["", "server", "--config", SERVER_CONFIG_LOC]


os.chdir(Path(__file__).parent.parent.parent)
sys.argv = DEFAULT_ARGV


@pytest.fixture(scope="session")
def install_path():
    return str(Path(os.path.realpath(__file__)).parent.parent / "server")


@pytest.fixture(scope="session", autouse=True)
def client(_example_2_plugin):
    sys.argv = ["", "server", "--config", SERVER_CONFIG_LOC]

    import empire.server.core.db.base
    from empire.server.core.db.base import reset_db, startup_db

    startup_db()

    shutil.rmtree("empire/test/downloads", ignore_errors=True)
    shutil.rmtree("empire/test/data/obfuscated_module_source", ignore_errors=True)

    from empire import arguments

    args = arguments.parent_parser.parse_args()

    import empire.server.server
    from empire.server.api.app import initialize
    from empire.server.common.empire import MainMenu

    empire.server.server.main = MainMenu(args)

    app = initialize(run=False)

    # fix for pycharm debugger
    # https://stackoverflow.com/a/77926544/5849681
    # yield TestClient(app, backend_options={"loop_factory": asyncio.new_event_loop})
    yield TestClient(app)

    from empire.server.server import main

    with suppress(Exception):
        main.shutdown()
        reset_db()


@pytest.fixture(scope="session", autouse=True)
def _example_2_plugin(install_path):
    example_plugin_path = Path(install_path) / "plugins" / "example"
    example_plugin_copy_path = Path(install_path) / "plugins" / "example_2"

    shutil.copytree(
        str(example_plugin_path), str(example_plugin_copy_path), dirs_exist_ok=True
    )

    config = (example_plugin_copy_path / "plugin.yaml").read_text()
    config = config.replace("name: example", "name: example_2")
    (example_plugin_copy_path / "plugin.yaml").write_text(config)

    yield

    shutil.rmtree(str(example_plugin_copy_path), ignore_errors=True)


@pytest.fixture(scope="session", autouse=True)
def empire_config() -> "EmpireConfig":
    from empire.server.core.config import config_manager

    return config_manager.empire_config


@pytest.fixture(scope="session")
def models():
    from empire.server.core.db import models

    return models


@pytest.fixture(scope="session")
def admin_auth_token(client):
    response = client.post(
        "/token",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        data={
            "grant_type": "password",
            "username": "empireadmin",
            "password": "password123",
        },
    )

    return response.json()["access_token"]


@pytest.fixture(scope="session")
def admin_auth_header(admin_auth_token):
    return {"X-Empire-Token": f"Bearer {admin_auth_token}"}


@pytest.fixture(scope="session")
def regular_auth_header(regular_auth_token):
    return {"X-Empire-Token": f"Bearer {regular_auth_token}"}


@pytest.fixture(scope="session")
def regular_auth_token(client, admin_auth_token):
    client.post(
        "/api/v2/users/",
        headers={"X-Empire-Token": f"Bearer {admin_auth_token}"},
        json={"username": "vinnybod", "password": "hunter2", "is_admin": False},
    )

    response = client.post(
        "/token",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        data={"grant_type": "password", "username": "vinnybod", "password": "hunter2"},
    )

    return response.json()["access_token"]


@pytest.fixture(scope="session")
def main():
    from empire.server.server import main

    return main


@pytest.fixture(scope="session", autouse=True)
def listener(client, admin_auth_header):
    # not using fixture because scope issues
    response = client.post(
        "/api/v2/listeners/",
        headers=admin_auth_header,
        json=get_base_listener(),
    )

    return response.json()


@pytest.fixture(scope="session", autouse=True)
def listener_malleable(client, admin_auth_header):
    # not using fixture because scope issues
    response = client.post(
        "/api/v2/listeners/",
        headers=admin_auth_header,
        json=get_base_malleable_listener(),
    )

    return response.json()


@pytest.fixture(scope="session")
def session_local(client):
    from empire.server.core.db.base import SessionLocal

    return SessionLocal


def make_agent(models, **overrides):
    """Factory for creating Agent model instances with sensible defaults."""
    name = overrides.pop("name", f"agent_{get_random_string(5)}")
    overrides.setdefault("session_id", name)
    defaults = {
        "name": name,
        "delay": 1,
        "jitter": 0.1,
        "external_ip": "1.1.1.1",
        "session_key": "qwerty",
        "nonce": "nonce",
        "profile": "profile",
        "kill_date": "killDate",
        "working_hours": "workingHours",
        "lost_limit": 60,
        "listener": "http",
        "language": "powershell",
        "language_version": "5",
        "high_integrity": True,
        "process_name": "proc",
        "process_id": 12345,
        "archived": False,
    }
    defaults.update(overrides)
    return models.Agent(**defaults)


@pytest.fixture
def host(session_local, models):
    with session_local.begin() as db:
        host = models.Host(
            name=f"host_{get_random_string(5)}", internal_ip="192.168.0.1"
        )
        db.add(host)
        db.flush()
        host_id = host.id

    return host_id  # noqa RET504


# This provides a new agent to any test that requests it.
@pytest.fixture
def agent(session_local, models, host, main):
    with session_local.begin() as db:
        agent = make_agent(
            models,
            session_key="2c103f2c4ed1e59c0b4e2e01821770fa",
            process_name="abc",
            process_id=123,
            host_id=host,
        )
        db.add(agent)
        db.add(models.AgentCheckIn(agent_id=agent.session_id))
        db.flush()

        main.agentcommsv2.agents[agent.session_id] = {
            "sessionKey": agent.session_key,
            "language": agent.language,
        }

        agent_id = agent.session_id

    return agent_id  # noqa RET504


# These are global for test_agent_api and test_agents
@pytest.fixture(scope="session")
def agents(session_local, models, main):
    random_string = get_random_string(5)
    with session_local.begin() as db:
        host = models.Host(name=f"host_{get_random_string(5)}", internal_ip="127.0.0.1")

        agent_defs = [
            {
                "name": f"TEST123_{random_string}",
                "delay": 60,
                "high_integrity": False,
                "hostname": "vinnybod",
                "host": host,
            },
            {
                "name": f"SECOND_{random_string}",
                "delay": 60,
                "high_integrity": False,
                "hostname": "vinnybod",
                "host": host,
            },
            {
                "name": f"ARCHIVED_{random_string}",
                "delay": 60,
                "high_integrity": False,
                "hostname": "vinnybod",
                "host": host,
                "archived": True,
            },
            {
                "name": f"STALE_{random_string}",
                "delay": 1,
                "high_integrity": False,
                "hostname": "vinnybod",
                "host": host,
            },
        ]

        db.add(host)
        agent_objs = []
        for kwargs in agent_defs:
            agent_obj = make_agent(models, **kwargs)
            db.add(agent_obj)
            agent_objs.append(agent_obj)

        stale_index = len(agent_defs) - 1
        for i, agent_obj in enumerate(agent_objs):
            checkin_kwargs = {"agent_id": agent_obj.session_id}
            if i == stale_index:  # STALE agent gets an old checkin
                checkin_kwargs["checkin_time"] = datetime.now(UTC) - timedelta(days=2)
            db.add(models.AgentCheckIn(**checkin_kwargs))

        db.flush()

        for agent_obj in agent_objs:
            main.agentcommsv2.agents[agent_obj.session_id] = {
                "sessionKey": agent_obj.session_key,
                "functions": agent_obj.functions,
            }

        return [agent_obj.session_id for agent_obj in agent_objs]


@pytest.fixture
def agent_task(client, admin_auth_header, agent):
    resp = client.post(
        f"/api/v2/agents/{agent}/tasks/shell",
        headers=admin_auth_header,
        json={"command": 'echo "HELLO WORLD"'},
    )

    return resp.json()


@pytest.fixture
def plugin_task(main, session_local, models):
    with session_local.begin() as db:
        task = models.PluginTask(
            plugin_id="basic_reporting",
            input="This is the trimmed input for the task.",
            input_full="This is the full input for the task.",
            user_id=1,
            plugin_options={"report": "all"},
        )
        db.add(task)
        db.flush()
        task_id = task.id

    return task_id  # noqa RET504


@pytest.fixture
def credential(client, admin_auth_header):
    resp = client.post(
        "/api/v2/credentials/",
        headers=admin_auth_header,
        json={
            "credtype": "hash",
            "domain": "the-domain",
            "username": get_random_string(8),
            "password": get_random_string(8),
            "host": "host1",
        },
    )

    return resp.json()["id"]


@pytest.fixture
def download(client, admin_auth_header):
    response = client.post(
        "/api/v2/downloads",
        headers=admin_auth_header,
        files={
            "file": (
                "test-upload-2.yaml",
                Path("./empire/test/test-upload-2.yaml").read_bytes(),
            )
        },
    )

    return response.json()["id"]


def load_test_config():
    with Path(SERVER_CONFIG_LOC).open() as f:
        return yaml.safe_load(f)
