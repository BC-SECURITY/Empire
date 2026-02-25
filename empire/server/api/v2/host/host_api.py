from typing import Annotated

from fastapi import Depends, HTTPException

from empire.server.api.api_router import APIRouter
from empire.server.api.jwt_auth import get_current_active_user
from empire.server.api.v2.host.host_dto import Host, Hosts, domain_to_dto_host
from empire.server.api.v2.shared_dependencies import AppCtx, CurrentSession
from empire.server.api.v2.shared_dto import BadRequestResponse, NotFoundResponse
from empire.server.core.db import models
from empire.server.core.host_service import HostService


def get_host_service(main: AppCtx) -> HostService:
    return main.hostsv2


HostServiceDep = Annotated[HostService, Depends(get_host_service)]


router = APIRouter(
    prefix="/api/v2/hosts",
    tags=["hosts"],
    responses={
        404: {"description": "Not found", "model": NotFoundResponse},
        400: {"description": "Bad request", "model": BadRequestResponse},
    },
    dependencies=[Depends(get_current_active_user)],
)


async def get_host(uid: int, db: CurrentSession, host_service: HostServiceDep):
    host = host_service.get_by_id(db, uid)

    if host:
        return host

    raise HTTPException(status_code=404, detail=f"Host not found for id {uid}")


HostDep = Annotated[models.Host, Depends(get_host)]


@router.get("/{uid}", response_model=Host)
async def read_host(uid: int, db_host: HostDep):
    return domain_to_dto_host(db_host)


@router.get("/", response_model=Hosts)
async def read_hosts(db: CurrentSession, host_service: HostServiceDep):
    hosts = [domain_to_dto_host(x) for x in host_service.get_all(db)]

    return {"records": hosts}
