import math
from datetime import datetime
from typing import Annotated

from fastapi import Depends, HTTPException, Query

from empire.server.api.api_router import APIRouter
from empire.server.api.jwt_auth import get_current_active_user
from empire.server.api.v2.agent.agent_dto import (
    Agent,
    AgentCheckIns,
    AgentCheckInsAggregate,
    Agents,
    AgentUpdateRequest,
    AggregateBucket,
    domain_to_dto_agent,
    domain_to_dto_agent_checkin,
    domain_to_dto_agent_checkin_agg,
)
from empire.server.api.v2.shared_dependencies import AppCtx, CurrentSession
from empire.server.api.v2.shared_dto import (
    BadRequestResponse,
    NotFoundResponse,
    OrderDirection,
)
from empire.server.api.v2.tag import tag_api
from empire.server.core.agent_service import AgentService
from empire.server.core.config.config_manager import empire_config
from empire.server.core.db import models


def get_agent_service(main: AppCtx) -> AgentService:
    return main.agentsv2


AgentServiceDep = Annotated[AgentService, Depends(get_agent_service)]


router = APIRouter(
    prefix="/api/v2/agents",
    tags=["agents"],
    responses={
        404: {"description": "Not found", "model": NotFoundResponse},
        400: {"description": "Bad request", "model": BadRequestResponse},
    },
    dependencies=[Depends(get_current_active_user)],
)


async def get_agent(
    uid: str,
    db: CurrentSession,
    agent_service: AgentServiceDep,
):
    agent = agent_service.get_by_id(db, uid)

    if agent:
        return agent

    raise HTTPException(404, f"Agent not found for id {uid}")


AgentDep = Annotated[models.Agent, Depends(get_agent)]


tag_api.add_endpoints_to_taggable(router, "/{uid}/tags", get_agent)


@router.get("/checkins", response_model=AgentCheckIns)
def read_agent_checkins_all(
    db: CurrentSession,
    agent_service: AgentServiceDep,
    agents: list[str] = Query(None),
    limit: int = 1000,
    page: int = 1,
    start_date: datetime | None = None,
    end_date: datetime | None = None,
    order_direction: OrderDirection = OrderDirection.desc,
):
    checkins, total = agent_service.get_agent_checkins(
        db, agents, limit, (page - 1) * limit, start_date, end_date, order_direction
    )
    checkins = [domain_to_dto_agent_checkin(x) for x in checkins]

    return AgentCheckIns(
        records=checkins,
        page=page,
        total_pages=math.ceil(total / limit),
        limit=limit,
        total=total,
    )


@router.get("/checkins/aggregate", response_model=AgentCheckInsAggregate)
def read_agent_checkins_aggregate(
    db: CurrentSession,
    agent_service: AgentServiceDep,
    agents: list[str] = Query(None),
    start_date: datetime | None = None,
    end_date: datetime | None = None,
    bucket_size: AggregateBucket | None = AggregateBucket.day,
):
    if empire_config.database.use == "sqlite":
        raise HTTPException(
            400,
            "Aggregate checkins not supported with sqlite. Please use MySQL.",
        )

    checkins = agent_service.get_agent_checkins_aggregate(
        db, agents, start_date, end_date, bucket_size
    )
    checkins = [domain_to_dto_agent_checkin_agg(x) for x in checkins]

    return AgentCheckInsAggregate(
        records=checkins,
        start_date=start_date,
        end_date=end_date,
        bucket_size=bucket_size,
    )


@router.get("/{uid}", response_model=Agent)
async def read_agent(uid: str, db_agent: AgentDep):
    return domain_to_dto_agent(db_agent)


@router.get("/", response_model=Agents)
async def read_agents(
    db: CurrentSession,
    agent_service: AgentServiceDep,
    include_archived: bool = False,
    include_stale: bool = True,
):
    agents = [
        domain_to_dto_agent(x)
        for x in agent_service.get_all(db, include_archived, include_stale)
    ]

    return {"records": agents}


@router.put("/{uid}", response_model=Agent)
async def update_agent(
    uid: str,
    agent_req: AgentUpdateRequest,
    db: CurrentSession,
    db_agent: AgentDep,
    agent_service: AgentServiceDep,
):
    resp, err = agent_service.update_agent(db, db_agent, agent_req)

    if err:
        raise HTTPException(status_code=400, detail=err)

    return domain_to_dto_agent(resp)


@router.get("/{uid}/checkins", response_model=AgentCheckIns)
def read_agent_checkins(
    db: CurrentSession,
    db_agent: AgentDep,
    agent_service: AgentServiceDep,
    limit: int = -1,
    page: int = 1,
    start_date: datetime | None = None,
    end_date: datetime | None = None,
    order_direction: OrderDirection = OrderDirection.desc,
):
    checkins, total = agent_service.get_agent_checkins(
        db,
        [db_agent.session_id],
        limit,
        (page - 1) * limit,
        start_date,
        end_date,
        order_direction,
    )
    checkins = [domain_to_dto_agent_checkin(x) for x in checkins]

    return AgentCheckIns(
        records=checkins,
        page=page,
        total_pages=math.ceil(total / limit),
        limit=limit,
        total=total,
    )
