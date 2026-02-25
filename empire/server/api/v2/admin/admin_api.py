from typing import Annotated

from fastapi import Depends

from empire.server.api.api_router import APIRouter
from empire.server.api.jwt_auth import (
    get_current_active_admin_user,
    get_current_active_user,
)
from empire.server.api.v2.shared_dependencies import AppCtx, CurrentSession
from empire.server.api.v2.shared_dto import BadRequestResponse, NotFoundResponse
from empire.server.core.ip_service import IpService


def get_ip_service(main: AppCtx) -> IpService:
    return main.ipsv2


IpServiceDep = Annotated[IpService, Depends(get_ip_service)]


router = APIRouter(
    prefix="/api/v2/admin",
    tags=["admin"],
    responses={
        404: {"description": "Not found", "model": NotFoundResponse},
        400: {"description": "Bad request", "model": BadRequestResponse},
    },
    dependencies=[Depends(get_current_active_user)],
)


@router.put("/ip_filtering", dependencies=[Depends(get_current_active_admin_user)])
def toggle_ip_filtering(db: CurrentSession, enabled: bool, ip_service: IpServiceDep):
    ip_service.toggle_ip_filtering(db, enabled)


@router.get("/ip_filtering", dependencies=[Depends(get_current_active_user)])
def get_ip_filtering(ip_service: IpServiceDep):
    return {"enabled": ip_service.ip_filtering}
