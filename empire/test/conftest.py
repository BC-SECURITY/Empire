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

    args = arguments.parse_args()

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
    return {"Authorization": f"Bearer {admin_auth_token}"}


@pytest.fixture(scope="session")
def regular_auth_token(client, admin_auth_token):
    client.post(
        "/api/v2/users/",
        headers={"Authorization": f"Bearer {admin_auth_token}"},
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
        name = f"agent_{get_random_string(5)}"
        agent = models.Agent(
            name=name,
            session_id=name,
            delay=1,
            jitter=0.1,
            external_ip="1.1.1.1",
            session_key="2c103f2c4ed1e59c0b4e2e01821770fa",
            nonce="nonce",
            profile="profile",
            kill_date="killDate",
            working_hours="workingHours",
            lost_limit=60,
            listener="http",
            language="powershell",
            language_version="5",
            high_integrity=True,
            process_name="abc",
            process_id=123,
            host_id=host,
            archived=False,
        )
        db.add(agent)
        db.add(models.AgentCheckIn(agent_id=agent.session_id))
        db.flush()

        main.agentcommsv2.agents[name] = {
            "sessionKey": agent.session_key,
            "language": agent.language,
        }

        agent_id = agent.session_id

    return agent_id  # noqa RET504


# These are global for test_agent_api and test_agents
@pytest.fixture(scope="session", autouse=True)
def agents(session_local, models, main):
    random_string = get_random_string(5)
    with session_local.begin() as db:
        host = models.Host(name=f"host_{get_random_string(5)}", internal_ip="127.0.0.1")

        agent = models.Agent(
            name=f"TEST123_{random_string}",
            session_id=f"TEST123_{random_string}",
            delay=60,
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
            process_name="proc",
            process_id=12345,
            hostname="vinnybod",
            host=host,
            archived=False,
        )

        agent2 = models.Agent(
            name=f"SECOND_{random_string}",
            session_id=f"SECOND_{random_string}",
            delay=60,
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
            process_name="proc",
            process_id=12345,
            hostname="vinnybod",
            host=host,
            archived=False,
        )

        agent3 = models.Agent(
            name=f"ARCHIVED_{random_string}",
            session_id=f"ARCHIVED_{random_string}",
            delay=60,
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
            process_name="proc",
            process_id=12345,
            hostname="vinnybod",
            host=host,
            archived=True,
        )

        agent4 = models.Agent(
            name=f"STALE_{random_string}",
            session_id=f"STALE_{random_string}",
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
            process_name="proc",
            process_id=12345,
            hostname="vinnybod",
            host=host,
            archived=False,
        )

        db.add(host)
        db.add(agent)
        db.add(agent2)
        db.add(agent3)
        db.add(agent4)
        db.add(models.AgentCheckIn(agent_id=agent.session_id))
        db.add(models.AgentCheckIn(agent_id=agent2.session_id))
        db.add(models.AgentCheckIn(agent_id=agent3.session_id))
        db.add(
            models.AgentCheckIn(
                agent_id=agent4.session_id,
                checkin_time=datetime.now(UTC) - timedelta(days=2),
            )
        )
        db.flush()
        agents = [agent, agent2, agent3, agent4]

        main.agentcommsv2.agents[f"TEST123_{random_string}"] = {
            "sessionKey": agents[0].session_key,
            "functions": agents[0].functions,
        }
        main.agentcommsv2.agents[f"SECOND_{random_string}"] = {
            "sessionKey": agents[1].session_key,
            "functions": agents[1].functions,
        }
        main.agentcommsv2.agents[f"ARCHIVED_{random_string}"] = {
            "sessionKey": agents[2].session_key,
            "functions": agents[2].functions,
        }
        main.agentcommsv2.agents[f"STALE_{random_string}"] = {
            "sessionKey": agents[3].session_key,
            "functions": agents[3].functions,
        }

        return [agent.session_id for agent in agents]


@pytest.fixture
def agent_task(client, admin_auth_header, agent, session_local, main):
    resp = client.post(
        f"/api/v2/agents/{agent}/tasks/shell",
        headers=admin_auth_header,
        json={"command": 'echo "HELLO WORLD"'},
    )

    return resp.json()


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
