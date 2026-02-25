from typing import Annotated

from fastapi import Depends, HTTPException
from starlette.responses import Response
from starlette.status import HTTP_204_NO_CONTENT

from empire.server.api.api_router import APIRouter
from empire.server.api.jwt_auth import get_current_active_user
from empire.server.api.v2.profile.profile_dto import (
    Profile,
    ProfilePostRequest,
    Profiles,
    ProfileUpdateRequest,
)
from empire.server.api.v2.shared_dependencies import AppCtx, CurrentSession
from empire.server.api.v2.shared_dto import BadRequestResponse, NotFoundResponse
from empire.server.core.db import models
from empire.server.core.profile_service import ProfileService


def get_profile_service(main: AppCtx) -> ProfileService:
    return main.profilesv2


ProfileServiceDep = Annotated[ProfileService, Depends(get_profile_service)]


router = APIRouter(
    prefix="/api/v2/malleable-profiles",
    tags=["malleable-profiles"],
    responses={
        404: {"description": "Not found", "model": NotFoundResponse},
        400: {"description": "Bad request", "model": BadRequestResponse},
    },
    dependencies=[Depends(get_current_active_user)],
)


async def get_profile(
    uid: int,
    db: CurrentSession,
    profile_service: ProfileServiceDep,
):
    profile = profile_service.get_by_id(db, uid)

    if profile:
        return profile

    raise HTTPException(status_code=404, detail=f"Profile not found for id {uid}")


ProfileDep = Annotated[models.Profile, Depends(get_profile)]


@router.get("/{uid}", response_model=Profile)
async def read_profile(uid: int, db_profile: ProfileDep):
    return db_profile


@router.get("/", response_model=Profiles)
async def read_profiles(db: CurrentSession, profile_service: ProfileServiceDep):
    profiles = profile_service.get_all(db)

    return {"records": profiles}


@router.post(
    "/",
    status_code=201,
    response_model=Profile,
)
async def create_profile(
    profile_req: ProfilePostRequest,
    db: CurrentSession,
    profile_service: ProfileServiceDep,
):
    resp, err = profile_service.create_profile(db, profile_req)

    if err:
        raise HTTPException(status_code=400, detail=err)

    return resp


@router.put("/{uid}", response_model=Profile)
async def update_profile(
    uid: int,
    profile_req: ProfileUpdateRequest,
    db: CurrentSession,
    db_profile: ProfileDep,
    profile_service: ProfileServiceDep,
):
    resp, err = profile_service.update_profile(db, db_profile, profile_req)

    if err:
        raise HTTPException(status_code=400, detail=err)

    return resp


@router.delete(
    "/{uid}",
    status_code=HTTP_204_NO_CONTENT,
    response_class=Response,
)
async def delete_profile(
    uid: str,
    db: CurrentSession,
    db_profile: ProfileDep,
    profile_service: ProfileServiceDep,
):
    profile_service.delete_profile(db, db_profile)


@router.post(
    "/reload",
    status_code=HTTP_204_NO_CONTENT,
    response_class=Response,
)
async def reload_profiles(
    db: CurrentSession,
    profile_service: ProfileServiceDep,
):
    profile_service.load_malleable_profiles(db)


@router.post(
    "/reset",
    status_code=HTTP_204_NO_CONTENT,
    response_class=Response,
)
async def reset_profiles(
    db: CurrentSession,
    profile_service: ProfileServiceDep,
):
    profile_service.delete_all_profiles(db)
    profile_service.load_malleable_profiles(db)
