from typing import Annotated

from fastapi import Depends, HTTPException
from starlette.responses import Response
from starlette.status import HTTP_204_NO_CONTENT

from empire.server.api.api_router import APIRouter
from empire.server.api.jwt_auth import get_current_active_user
from empire.server.api.v2.listener.listener_dto import (
    AutorunConfig,
    Listener,
    ListenerPostRequest,
    Listeners,
    ListenerUpdateRequest,
    domain_to_dto_listener,
)
from empire.server.api.v2.shared_dependencies import AppCtx, CurrentSession
from empire.server.api.v2.shared_dto import BadRequestResponse, NotFoundResponse
from empire.server.api.v2.tag import tag_api
from empire.server.core.db import models
from empire.server.core.listener_service import ListenerService


def get_listener_service(main: AppCtx) -> ListenerService:
    return main.listenersv2


ListenerServiceDep = Annotated[ListenerService, Depends(get_listener_service)]


router = APIRouter(
    prefix="/api/v2/listeners",
    tags=["listeners"],
    responses={
        404: {"description": "Not found", "model": NotFoundResponse},
        400: {"description": "Bad request", "model": BadRequestResponse},
    },
    dependencies=[Depends(get_current_active_user)],
)


async def get_listener(
    uid: int,
    db: CurrentSession,
    listener_service: ListenerServiceDep,
):
    listener = listener_service.get_by_id(db, uid)

    if listener:
        return listener

    raise HTTPException(404, f"Listener not found for id {uid}")


ListenerDep = Annotated[models.Listener, Depends(get_listener)]


tag_api.add_endpoints_to_taggable(router, "/{uid}/tags", get_listener)


@router.get("/{uid}", response_model=Listener)
async def read_listener(uid: int, db_listener: ListenerDep):
    return domain_to_dto_listener(db_listener)


@router.get("/", response_model=Listeners)
async def read_listeners(
    db: CurrentSession,
    listener_service: ListenerServiceDep,
):
    listeners = [domain_to_dto_listener(x) for x in listener_service.get_all(db)]

    return {"records": listeners}


@router.post("/", status_code=201, response_model=Listener)
async def create_listener(
    listener_req: ListenerPostRequest,
    db: CurrentSession,
    listener_service: ListenerServiceDep,
):
    """
    Note: options['Name'] will be overwritten by name. When v1 api is eventually removed, it wil no longer be needed.
    :param listener_req:
    :param db
    :return:
    """
    resp, err = listener_service.create_listener(db, listener_req)

    if err:
        raise HTTPException(status_code=400, detail=err)

    return domain_to_dto_listener(resp)


@router.put("/{uid}", response_model=Listener)
async def update_listener(
    uid: int,
    listener_req: ListenerUpdateRequest,
    db: CurrentSession,
    db_listener: ListenerDep,
    listener_service: ListenerServiceDep,
):
    if listener_req.enabled and not db_listener.enabled:
        # update then turn on
        resp, err = listener_service.update_listener(db, db_listener, listener_req)

        if err:
            raise HTTPException(status_code=400, detail=err)

        resp, err = listener_service.start_existing_listener(db, resp)

        if err:
            raise HTTPException(status_code=400, detail=err)

        return domain_to_dto_listener(resp)
    if listener_req.enabled and db_listener.enabled:
        # err already running / cannot update
        raise HTTPException(
            status_code=400, detail="Listener must be disabled before modifying"
        )
    if not listener_req.enabled and db_listener.enabled:
        # disable and update
        listener_service.stop_listener(db_listener)
        resp, err = listener_service.update_listener(db, db_listener, listener_req)

        if err:
            raise HTTPException(status_code=400, detail=err)

        return domain_to_dto_listener(resp)
    if not listener_req.enabled and not db_listener.enabled:
        # update
        resp, err = listener_service.update_listener(db, db_listener, listener_req)

        if err:
            raise HTTPException(status_code=400, detail=err)

        return domain_to_dto_listener(resp)

    raise HTTPException(status_code=500, detail="This Shouldn't Happen")


@router.delete(
    "/{uid}",
    status_code=HTTP_204_NO_CONTENT,
    response_class=Response,
)
async def delete_listener(
    uid: int,
    db: CurrentSession,
    db_listener: ListenerDep,
    listener_service: ListenerServiceDep,
):
    listener_service.delete_listener(db, db_listener)


@router.put("/{uid}/autorun", response_model=Listener)
async def update_listener_autorun(
    uid: int,
    autorun_config: AutorunConfig,
    db: CurrentSession,
    db_listener: ListenerDep,
):
    module_list_serializable = [
        module.model_dump() for module in autorun_config.records
    ]
    db_listener.autorun_tasks = module_list_serializable
    return domain_to_dto_listener(db_listener)


@router.get("/{uid}/autorun", response_model=AutorunConfig)
async def get_listener_autorun(
    uid: int,
    db_listener: ListenerDep,
):
    autorun_tasks = db_listener.autorun_tasks or []
    return AutorunConfig(records=autorun_tasks)
