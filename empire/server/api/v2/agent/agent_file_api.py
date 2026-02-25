from typing import Annotated

from fastapi import Depends, HTTPException

from empire.server.api.api_router import APIRouter
from empire.server.api.jwt_auth import get_current_active_user
from empire.server.api.v2.agent.agent_file_dto import AgentFile, domain_to_dto_file
from empire.server.api.v2.shared_dependencies import AppCtx, CurrentSession
from empire.server.api.v2.shared_dto import BadRequestResponse, NotFoundResponse
from empire.server.core.agent_file_service import AgentFileService
from empire.server.core.agent_service import AgentService
from empire.server.core.db import models


def get_agent_file_service(main: AppCtx) -> AgentFileService:
    return main.agentfilesv2


AgentFileServiceDep = Annotated[AgentFileService, Depends(get_agent_file_service)]


def get_agent_service(main: AppCtx) -> AgentService:
    return main.agentsv2


AgentServiceDep = Annotated[AgentService, Depends(get_agent_service)]


router = APIRouter(
    prefix="/api/v2/agents/{agent_id}/files",
    tags=["agents"],
    responses={
        404: {"description": "Not found", "model": NotFoundResponse},
        400: {"description": "Bad request", "model": BadRequestResponse},
    },
    dependencies=[Depends(get_current_active_user)],
)


async def get_agent(
    agent_id: str,
    db: CurrentSession,
    agent_service: AgentServiceDep,
):
    agent = agent_service.get_by_id(db, agent_id)

    if agent:
        return agent

    raise HTTPException(404, f"Agent not found for id {agent_id}")


AgentDep = Annotated[models.Agent, Depends(get_agent)]


async def get_file(
    uid: int,
    db: CurrentSession,
    db_agent: AgentDep,
    agent_file_service: AgentFileServiceDep,
):
    file = agent_file_service.get_file(db, db_agent.session_id, uid)

    if file:
        return file

    raise HTTPException(
        404, f"File not found for agent {db_agent.session_id} and file id {uid}"
    )


FileDep = Annotated[
    tuple[models.AgentFile, list[models.AgentFile]] | None, Depends(get_file)
]


@router.get("/root")
async def read_file_root(
    db: CurrentSession,
    db_agent: AgentDep,
    agent_file_service: AgentFileServiceDep,
):
    file = agent_file_service.get_file_by_path(db, db_agent.session_id, "/")

    if file:
        return domain_to_dto_file(*file)

    raise HTTPException(
        404, f'File not found for agent {db_agent.session_id} and file path "/"'
    )


@router.get("/{uid}", response_model=AgentFile)
async def read_file(
    uid: int,
    db_agent: AgentDep,
    db_file: FileDep,
):
    if db_file:
        return domain_to_dto_file(*db_file)

    raise HTTPException(
        404, f'File not found for agent {db_agent.session_id} and file path "/"'
    )
