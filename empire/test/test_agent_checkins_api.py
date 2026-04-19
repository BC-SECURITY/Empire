import asyncio
import logging
from datetime import UTC, datetime, timedelta, timezone

import pytest
from starlette import status

from empire.server.utils.string_util import get_random_string
from empire.test.conftest import make_agent

log = logging.getLogger(__name__)


async def _create_checkins(session_local, models, agent_ids):
    await asyncio.gather(
        *[_create_checkin(session_local, models, agent_id) for agent_id in agent_ids]
    )


agent_count = 2
time_delta = 20  # 4320 checkins per agent per day
days_back = 3
end_time = datetime(2023, 1, 8, tzinfo=UTC)
start_time = end_time - timedelta(days=days_back)


async def _create_checkin(session_local, models, agent_id):
    with session_local.begin() as db_2:
        checkins = []
        iter_time = start_time
        while iter_time < end_time:
            iter_time += timedelta(seconds=time_delta)
            checkins.append(
                models.AgentCheckIn(agent_id=agent_id, checkin_time=iter_time)
            )

        log.info(f"adding {len(checkins)} checkins for {agent_id}")
        db_2.add_all(checkins)


@pytest.fixture(scope="module")
def agents_with_checkins(session_local, models):
    with session_local.begin() as db:
        host = db.merge(
            models.Host(name=f"host_{get_random_string(5)}", internal_ip="192.168.0.1")
        )
        db.flush()
        host_id = host.id

    agent_ids = []
    with session_local.begin() as db:
        for n in range(agent_count):
            agent_id = f"agent_{get_random_string(5)}_{n}"
            agent_ids.append(agent_id)
            db.add(
                make_agent(
                    models,
                    name=agent_id,
                    delay=60,
                    high_integrity=False,
                    hostname="vinnybod",
                    internal_ip="1.2.3.4",
                    host_id=host_id,
                )
            )

    asyncio.run(_create_checkins(session_local, models, agent_ids))

    yield agent_ids

    with session_local.begin() as db:
        db.query(models.AgentCheckIn).filter(
            models.AgentCheckIn.agent_id.in_(agent_ids)
        ).delete()

        # Keep one check-in for each agent
        for agent_id in agent_ids:
            db.add(
                models.AgentCheckIn(agent_id=agent_id, checkin_time=datetime.now(UTC))
            )


def test_get_agent_checkins_agent_not_found(client, admin_auth_header):
    response = client.get("/api/v2/agents/XYZ123/checkins", headers=admin_auth_header)

    assert response.status_code == status.HTTP_404_NOT_FOUND
    assert response.json()["detail"] == "Agent not found for id XYZ123"


@pytest.mark.slow
def test_get_agent_checkins_with_limit_and_page(
    client, admin_auth_header, agents_with_checkins
):
    agents = agents_with_checkins

    response = client.get(
        f"/api/v2/agents/{agents[0]}/checkins?limit=10&page=1",
        headers=admin_auth_header,
    )

    limit = 10
    assert response.status_code == status.HTTP_200_OK
    assert len(response.json()["records"]) == limit
    assert response.json()["total"] >= days_back * 4320
    assert response.json()["page"] == 1

    page1 = response.json()["records"]

    response = client.get(
        f"/api/v2/agents/{agents[0]}/checkins?limit=10&page=2",
        headers=admin_auth_header,
    )

    assert response.status_code == status.HTTP_200_OK
    assert len(response.json()["records"]) == limit
    assert response.json()["total"] >= days_back * 4320
    assert response.json()["page"] == 2  # noqa: PLR2004

    page2 = response.json()["records"]

    assert page1 != page2


@pytest.mark.slow
def test_get_agent_checkins_multiple_agents(
    client, admin_auth_header, agents_with_checkins
):
    agents = agents_with_checkins

    response = client.get(
        "/api/v2/agents/checkins",
        headers=admin_auth_header,
        params={"agents": agents, "limit": 400000},
    )

    assert response.status_code == status.HTTP_200_OK
    assert len(response.json()["records"]) == days_back * 4320 * agent_count
    assert {r["agent_id"] for r in response.json()["records"]} == set(agents)


@pytest.mark.slow
def test_agent_checkins_aggregate(
    client, admin_auth_header, agents_with_checkins, empire_config
):
    if empire_config.database.use == "sqlite":
        pytest.skip("sqlite not supported for checkin aggregation")

    response = client.get(
        "/api/v2/agents/checkins/aggregate",
        headers=admin_auth_header,
    )

    assert response.status_code == status.HTTP_200_OK
    assert response.elapsed.total_seconds() < 5  # noqa: PLR2004
    assert response.json()["bucket_size"] == "day"
    assert response.json()["records"][1]["count"] == 4320 * agent_count

    response = client.get(
        "/api/v2/agents/checkins/aggregate",
        headers=admin_auth_header,
        params={"bucket_size": "hour"},
    )

    assert response.status_code == status.HTTP_200_OK
    assert response.elapsed.total_seconds() < 5  # noqa: PLR2004
    assert response.json()["bucket_size"] == "hour"
    assert response.json()["records"][1]["count"] == 180 * agent_count

    response = client.get(
        "/api/v2/agents/checkins/aggregate",
        headers=admin_auth_header,
        params={"bucket_size": "minute"},
    )

    assert response.status_code == status.HTTP_200_OK
    assert response.elapsed.total_seconds() < 5  # noqa: PLR2004
    assert response.json()["bucket_size"] == "minute"
    assert response.json()["records"][1]["count"] == 3 * agent_count

    response = client.get(
        "/api/v2/agents/checkins/aggregate",
        headers=admin_auth_header,
        params={
            "bucket_size": "second",
            "start_date": start_time,
            "end_date": start_time + timedelta(hours=2),
        },
    )

    assert response.status_code == status.HTTP_200_OK
    assert response.elapsed.total_seconds() < 5  # noqa: PLR2004
    assert response.json()["bucket_size"] == "second"
    assert response.json()["records"][1]["count"] == 1 * agent_count

    # Test start date and end date
    response = client.get(
        "/api/v2/agents/checkins/aggregate",
        headers=admin_auth_header,
        params={"bucket_size": "hour", "start_date": start_time + timedelta(days=3)},
    )

    assert response.status_code == status.HTTP_200_OK
    assert response.json()["bucket_size"] == "hour"
    checkin_time_string = response.json()["records"][0]["checkin_time"]
    checkin_time = datetime.strptime(checkin_time_string, "%Y-%m-%dT%H:%M:%S%z")
    assert checkin_time == start_time + timedelta(days=3)

    response = client.get(
        "/api/v2/agents/checkins/aggregate",
        headers=admin_auth_header,
        params={"bucket_size": "hour", "end_date": start_time + timedelta(days=3)},
    )

    assert response.status_code == status.HTTP_200_OK
    assert response.json()["bucket_size"] == "hour"
    checkin_time_string = response.json()["records"][-1]["checkin_time"]
    checkin_time = datetime.strptime(checkin_time_string, "%Y-%m-%dT%H:%M:%S%z")
    assert checkin_time == start_time + timedelta(days=3)

    # Test using timestamps with offset
    with_tz = start_time + timedelta(days=3)
    with_tz = with_tz.astimezone(timezone(timedelta(hours=-5)))

    response = client.get(
        "/api/v2/agents/checkins/aggregate",
        headers=admin_auth_header,
        params={"bucket_size": "hour", "start_date": with_tz},
    )

    assert response.status_code == status.HTTP_200_OK
    assert response.json()["bucket_size"] == "hour"
    checkin_time_string = response.json()["records"][0]["checkin_time"]
    checkin_time = datetime.strptime(checkin_time_string, "%Y-%m-%dT%H:%M:%S%z")
    assert checkin_time == start_time + timedelta(days=3)
