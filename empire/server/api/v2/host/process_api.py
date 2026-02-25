from typing import Annotated

from fastapi import Depends, HTTPException

from empire.server.api.api_router import APIRouter
from empire.server.api.jwt_auth import get_current_active_user
from empire.server.api.v2.host.process_dto import (
    Process,
    Processes,
    domain_to_dto_process,
)
from empire.server.api.v2.shared_dependencies import AppCtx, CurrentSession
from empire.server.api.v2.shared_dto import BadRequestResponse, NotFoundResponse
from empire.server.core.db import models
from empire.server.core.host_process_service import HostProcessService
from empire.server.core.host_service import HostService


def get_host_process_service(main: AppCtx) -> HostProcessService:
    return main.processesv2


HostProcessServiceDep = Annotated[HostProcessService, Depends(get_host_process_service)]


def get_host_service(main: AppCtx) -> HostService:
    return main.hostsv2


HostServiceDep = Annotated[HostService, Depends(get_host_service)]


router = APIRouter(
    prefix="/api/v2/hosts/{host_id}/processes",
    tags=["hosts"],
    responses={
        404: {"description": "Not found", "model": NotFoundResponse},
        400: {"description": "Bad request", "model": BadRequestResponse},
    },
    dependencies=[Depends(get_current_active_user)],
)


async def get_host(
    host_id: int,
    db: CurrentSession,
    host_service: HostServiceDep,
):
    host = host_service.get_by_id(db, host_id)

    if host:
        return host

    raise HTTPException(status_code=404, detail=f"Host not found for id {host_id}")


HostDep = Annotated[models.Host, Depends(get_host)]


async def get_process(
    uid: int,
    db: CurrentSession,
    db_host: HostDep,
    host_process_service: HostProcessServiceDep,
):
    process = host_process_service.get_process_for_host(db, db_host, uid)

    if process:
        return process

    raise HTTPException(
        404, f"Process not found for host id {db_host.id} and process id {uid}"
    )


ProcessDep = Annotated[models.HostProcess, Depends(get_process)]


@router.get("/{uid}", response_model=Process)
async def read_process(uid: int, db_process: ProcessDep):
    return domain_to_dto_process(db_process)


@router.get("/", response_model=Processes)
async def read_processes(
    db: CurrentSession,
    db_host: HostDep,
    host_process_service: HostProcessServiceDep,
):
    processes = [
        domain_to_dto_process(x)
        for x in host_process_service.get_processes_for_host(db, db_host)
    ]

    return {"records": processes}
