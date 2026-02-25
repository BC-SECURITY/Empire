from typing import Annotated

from fastapi import Depends, HTTPException
from starlette.responses import Response
from starlette.status import HTTP_204_NO_CONTENT

from empire.server.api.api_router import APIRouter
from empire.server.api.jwt_auth import CurrentActiveUser, get_current_active_user
from empire.server.api.v2.shared_dependencies import AppCtx, CurrentSession
from empire.server.api.v2.shared_dto import BadRequestResponse, NotFoundResponse
from empire.server.api.v2.stager.stager_dto import (
    Stager,
    StagerPostRequest,
    Stagers,
    StagerUpdateRequest,
    domain_to_dto_stager,
)
from empire.server.core.db import models
from empire.server.core.stager_generation_service import StagerGenerationService


def get_stager_service(main: AppCtx) -> StagerGenerationService:
    return main.stagersv2


StagerServiceDep = Annotated[StagerGenerationService, Depends(get_stager_service)]


router = APIRouter(
    prefix="/api/v2/stagers",
    tags=["stagers"],
    responses={
        404: {"description": "Not found", "model": NotFoundResponse},
        400: {"description": "Bad request", "model": BadRequestResponse},
    },
    dependencies=[Depends(get_current_active_user)],
)


async def get_stager(
    uid: int,
    db: CurrentSession,
    stager_service: StagerServiceDep,
):
    stager = stager_service.get_by_id(db, uid)

    if stager:
        return stager

    raise HTTPException(404, f"Stager not found for id {uid}")


StagerDep = Annotated[models.Stager, Depends(get_stager)]


@router.get("/", response_model=Stagers)
async def read_stagers(
    db: CurrentSession,
    stager_service: StagerServiceDep,
):
    stagers = [domain_to_dto_stager(x) for x in stager_service.get_all(db)]

    return {"records": stagers}


@router.get("/{uid}", response_model=Stager)
async def read_stager(uid: int, db_stager: StagerDep):
    return domain_to_dto_stager(db_stager)


@router.post("/", status_code=201, response_model=Stager)
async def create_stager(
    stager_req: StagerPostRequest,
    current_user: CurrentActiveUser,
    db: CurrentSession,
    stager_service: StagerServiceDep,
    save: bool = True,
):
    resp, err = stager_service.create_stager(
        db, stager_req, save, user_id=current_user.id
    )

    if err:
        raise HTTPException(status_code=400, detail=err)

    return domain_to_dto_stager(resp)


@router.put("/{uid}", response_model=Stager)
async def update_stager(
    uid: int,
    stager_req: StagerUpdateRequest,
    db: CurrentSession,
    db_stager: StagerDep,
    stager_service: StagerServiceDep,
):
    resp, err = stager_service.update_stager(db, db_stager, stager_req)

    if err:
        raise HTTPException(status_code=400, detail=err)

    return domain_to_dto_stager(resp)


@router.delete(
    "/{uid}",
    status_code=HTTP_204_NO_CONTENT,
    response_class=Response,
)
async def delete_stager(
    uid: int,
    db: CurrentSession,
    db_stager: StagerDep,
    stager_service: StagerServiceDep,
):
    stager_service.delete_stager(db, db_stager)
