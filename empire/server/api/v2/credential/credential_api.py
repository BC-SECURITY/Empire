from typing import Annotated

from fastapi import Depends, HTTPException, Query
from starlette.responses import Response
from starlette.status import HTTP_204_NO_CONTENT

from empire.server.api.api_router import APIRouter
from empire.server.api.jwt_auth import get_current_active_user
from empire.server.api.v2.credential.credential_dto import (
    Credential,
    CredentialPostRequest,
    Credentials,
    CredentialUpdateRequest,
    domain_to_dto_credential,
)
from empire.server.api.v2.shared_dependencies import AppCtx, CurrentSession
from empire.server.api.v2.shared_dto import BadRequestResponse, NotFoundResponse
from empire.server.api.v2.tag import tag_api
from empire.server.api.v2.tag.tag_dto import TagStr
from empire.server.core.credential_service import CredentialService
from empire.server.core.db import models


def get_credential_service(main: AppCtx) -> CredentialService:
    return main.credentialsv2


CredentialServiceDep = Annotated[CredentialService, Depends(get_credential_service)]


router = APIRouter(
    prefix="/api/v2/credentials",
    tags=["credentials"],
    responses={
        404: {"description": "Not found", "model": NotFoundResponse},
        400: {"description": "Bad request", "model": BadRequestResponse},
    },
    dependencies=[Depends(get_current_active_user)],
)


async def get_credential(
    uid: int,
    db: CurrentSession,
    credential_service: CredentialServiceDep,
):
    credential = credential_service.get_by_id(db, uid)

    if credential:
        return credential

    raise HTTPException(404, f"Credential not found for id {uid}")


CredentialDep = Annotated[models.Credential, Depends(get_credential)]


tag_api.add_endpoints_to_taggable(router, "/{uid}/tags", get_credential)


@router.get("/{uid}", response_model=Credential)
async def read_credential(uid: int, db_credential: CredentialDep):
    return domain_to_dto_credential(db_credential)


@router.get("/", response_model=Credentials)
async def read_credentials(
    db: CurrentSession,
    credential_service: CredentialServiceDep,
    search: str | None = None,
    credtype: str | None = None,
    tags: list[TagStr] | None = Query(None),
):
    credentials = [
        domain_to_dto_credential(x)
        for x in credential_service.get_all(db, search, credtype, tags)
    ]

    return {"records": credentials}


@router.post(
    "/",
    status_code=201,
    response_model=Credential,
)
async def create_credential(
    credential_req: CredentialPostRequest,
    db: CurrentSession,
    credential_service: CredentialServiceDep,
):
    resp, err = credential_service.create_credential(db, credential_req)

    if err:
        raise HTTPException(status_code=400, detail=err)

    return domain_to_dto_credential(resp)


@router.put("/{uid}", response_model=Credential)
async def update_credential(
    uid: int,
    credential_req: CredentialUpdateRequest,
    db: CurrentSession,
    db_credential: CredentialDep,
    credential_service: CredentialServiceDep,
):
    resp, err = credential_service.update_credential(db, db_credential, credential_req)

    if err:
        raise HTTPException(status_code=400, detail=err)

    return domain_to_dto_credential(resp)


@router.delete(
    "/{uid}",
    status_code=HTTP_204_NO_CONTENT,
    response_class=Response,
)
async def delete_credential(
    uid: str,
    db: CurrentSession,
    db_credential: CredentialDep,
    credential_service: CredentialServiceDep,
):
    credential_service.delete_credential(db, db_credential)
