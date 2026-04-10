from starlette import status

from empire.server.common.empire import MainMenu


def test_get_agent_not_found(client, admin_auth_header):
    response = client.get("/api/v2/agents/XYZ123", headers=admin_auth_header)

    assert response.status_code == status.HTTP_404_NOT_FOUND
    assert response.json()["detail"] == "Agent not found for id XYZ123"


def test_get_agent(client, agent, admin_auth_header):
    response = client.get(f"/api/v2/agents/{agent}", headers=admin_auth_header)

    assert response.status_code == status.HTTP_200_OK
    assert response.json()["session_id"] == agent


def test_get_agents(client, admin_auth_header, agents):
    response = client.get("/api/v2/agents", headers=admin_auth_header)

    assert response.status_code == status.HTTP_200_OK
    assert len(response.json()["records"]) > 0


def test_get_agents_include_stale_false(client, admin_auth_header, agents):
    response = client.get(
        "/api/v2/agents?include_stale=false", headers=admin_auth_header
    )

    assert response.status_code == status.HTTP_200_OK
    assert len(response.json()["records"]) > 0
    assert all(record["stale"] is False for record in response.json()["records"])


def test_get_agents_include_archived_true(client, admin_auth_header, agents):
    response = client.get(
        "/api/v2/agents?include_archived=true", headers=admin_auth_header
    )

    assert response.status_code == status.HTTP_200_OK
    assert len(response.json()["records"]) > 0
    assert any(record["archived"] is True for record in response.json()["records"])


def test_update_agent_not_found(client, admin_auth_header):
    response = client.get("/api/v2/agents/TEST123", headers=admin_auth_header)
    agent = response.json()

    response = client.put(
        "/api/v2/agents/XYZ123", json=agent, headers=admin_auth_header
    )

    assert response.status_code == status.HTTP_404_NOT_FOUND
    assert response.json()["detail"] == "Agent not found for id XYZ123"


def test_update_agent_name_conflict(client, agents, admin_auth_header):
    response = client.get(f"/api/v2/agents/{agents[0]}", headers=admin_auth_header)
    agent = response.json()
    agent["name"] = agents[1]

    response = client.put(
        f"/api/v2/agents/{agents[0]}", json=agent, headers=admin_auth_header
    )
    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert response.json()["detail"] == f"Agent with name {agents[1]} already exists."


def test_update_agent(client, agent, admin_auth_header):
    response = client.get(f"/api/v2/agents/{agent}", headers=admin_auth_header)

    agent = response.json()
    agent["name"] = "My New Agent Name"
    agent["notes"] = "The new notes!"
    response = client.put(
        f"/api/v2/agents/{agent['session_id']}", json=agent, headers=admin_auth_header
    )

    assert response.status_code == status.HTTP_200_OK
    assert response.json()["name"] == "My New Agent Name"
    assert response.json()["notes"] == "The new notes!"


def test_create_agent(main: MainMenu, session_local):
    with session_local() as db:
        agent = main.agentsv2.create_agent(
            db,
            "ABC123",
            "1.1.1.1",
            60,
            0.1,
            "Windows",
            None,
            None,
            None,
            "SESSION_KEY",
            "",
            "http",
            "powershell",
        )

        assert agent is not None
