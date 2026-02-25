from typing import Annotated

from fastapi import Depends, HTTPException
from starlette.background import BackgroundTasks
from starlette.responses import Response
from starlette.status import HTTP_202_ACCEPTED, HTTP_204_NO_CONTENT

from empire.server.api.api_router import APIRouter
from empire.server.api.jwt_auth import get_current_active_user
from empire.server.api.v2.obfuscation.obfuscation_dto import (
    Keyword,
    KeywordPostRequest,
    Keywords,
    KeywordUpdateRequest,
    ObfuscationConfig,
    ObfuscationConfigs,
    ObfuscationConfigUpdateRequest,
    domain_to_dto_obfuscation_config,
)
from empire.server.api.v2.shared_dependencies import AppCtx, CurrentSession
from empire.server.api.v2.shared_dto import BadRequestResponse, NotFoundResponse
from empire.server.core.db import models
from empire.server.core.module_service import ModuleService
from empire.server.core.obfuscation_service import ObfuscationService


def get_obfuscation_service(main: AppCtx) -> ObfuscationService:
    return main.obfuscationv2


ObfuscationServiceDep = Annotated[ObfuscationService, Depends(get_obfuscation_service)]


def get_module_service(main: AppCtx) -> ModuleService:
    return main.modulesv2


ModuleServiceDep = Annotated[ModuleService, Depends(get_module_service)]


router = APIRouter(
    prefix="/api/v2/obfuscation",
    tags=["keywords"],
    responses={
        404: {"description": "Not found", "model": NotFoundResponse},
        400: {"description": "Bad request", "model": BadRequestResponse},
    },
    dependencies=[Depends(get_current_active_user)],
)


async def get_keyword(
    uid: int,
    db: CurrentSession,
    obfuscation_service: ObfuscationServiceDep,
):
    keyword = obfuscation_service.get_keyword_by_id(db, uid)

    if keyword:
        return keyword

    raise HTTPException(404, f"Keyword not found for id {uid}")


KeywordDep = Annotated[models.Keyword, Depends(get_keyword)]


@router.get("/keywords/{uid}", response_model=Keyword)
async def read_keyword(uid: int, db_keyword: KeywordDep):
    return db_keyword


@router.get("/keywords", response_model=Keywords)
async def read_keywords(
    db: CurrentSession,
    obfuscation_service: ObfuscationServiceDep,
):
    keywords = obfuscation_service.get_all_keywords(db)
    return {"records": keywords}


@router.post("/keywords", response_model=Keyword, status_code=201)
async def create_keyword(
    keyword_req: KeywordPostRequest,
    db: CurrentSession,
    obfuscation_service: ObfuscationServiceDep,
):
    resp, err = obfuscation_service.create_keyword(db, keyword_req)

    if err:
        raise HTTPException(status_code=400, detail=err)

    return resp


@router.put("/keywords/{uid}", response_model=Keyword)
async def update_keyword(
    uid: int,
    keyword_req: KeywordUpdateRequest,
    db: CurrentSession,
    db_keyword: KeywordDep,
    obfuscation_service: ObfuscationServiceDep,
):
    resp, err = obfuscation_service.update_keyword(db, db_keyword, keyword_req)

    if err:
        raise HTTPException(status_code=400, detail=err)

    return resp


@router.delete(
    "/keywords/{uid}",
    status_code=HTTP_204_NO_CONTENT,
)
async def delete_keyword(
    uid: str,
    db: CurrentSession,
    db_keyword: KeywordDep,
    obfuscation_service: ObfuscationServiceDep,
):
    obfuscation_service.delete_keyword(db, db_keyword)


async def get_obfuscation_config(
    language: str,
    db: CurrentSession,
    obfuscation_service: ObfuscationServiceDep,
):
    obf_config = obfuscation_service.get_obfuscation_config(db, language)

    if obf_config:
        return obf_config

    raise HTTPException(
        404,
        f"Obfuscation config not found for language {language}. Only powershell is supported.",
    )


ObfuscationConfigDep = Annotated[
    models.ObfuscationConfig, Depends(get_obfuscation_config)
]


@router.get("/global", response_model=ObfuscationConfigs)
async def read_obfuscation_configs(
    db: CurrentSession,
    obfuscation_service: ObfuscationServiceDep,
):
    obf_configs = obfuscation_service.get_all_obfuscation_configs(db)

    return {"records": obf_configs}


@router.get("/global/{language}", response_model=ObfuscationConfig)
async def read_obfuscation_config(
    language: str,
    db_obf_config: ObfuscationConfigDep,
):
    return domain_to_dto_obfuscation_config(db_obf_config)


@router.put("/global/{language}", response_model=ObfuscationConfig)
async def update_obfuscation_config(
    language: str,
    obf_req: ObfuscationConfigUpdateRequest,
    db: CurrentSession,
    db_obf_config: ObfuscationConfigDep,
    obfuscation_service: ObfuscationServiceDep,
):
    resp, err = obfuscation_service.update_obfuscation_config(
        db, db_obf_config, obf_req
    )

    if err:
        raise HTTPException(status_code=400, detail=err)

    return domain_to_dto_obfuscation_config(resp)


@router.post(
    "/global/{language}/preobfuscate",
    status_code=HTTP_202_ACCEPTED,
    response_class=Response,
)
async def preobfuscate_modules(
    language: str,
    background_tasks: BackgroundTasks,
    db: CurrentSession,
    db_obf_config: ObfuscationConfigDep,
    module_service: ModuleServiceDep,
    reobfuscate: bool = False,
):
    if not db_obf_config.preobfuscatable:
        raise HTTPException(
            status_code=400,
            detail=f"Obfuscation language {language} is not preobfuscatable.",
        )

    background_tasks.add_task(
        module_service.preobfuscate_modules, language, reobfuscate
    )


@router.delete(
    "/global/{language}/preobfuscate",
    status_code=HTTP_204_NO_CONTENT,
    response_class=Response,
)
async def remove_preobfuscated_modules(
    language: str,
    db_obf_config: ObfuscationConfigDep,
    module_service: ModuleServiceDep,
):
    if not db_obf_config.preobfuscatable:
        raise HTTPException(
            status_code=400,
            detail=f"Obfuscation language {language} is not preobfuscatable.",
        )

    module_service.remove_preobfuscated_modules(language)
