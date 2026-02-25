import logging
from typing import Annotated

from fastapi import Depends, HTTPException, Response

from empire.server.api.api_router import APIRouter
from empire.server.api.jwt_auth import get_current_active_user
from empire.server.api.v2.module.module_dto import (
    Module,
    ModuleBulkUpdateRequest,
    ModuleScript,
    ModuleUpdateRequest,
    domain_to_dto_module,
)
from empire.server.api.v2.shared_dependencies import AppCtx, CurrentSession
from empire.server.api.v2.shared_dto import BadRequestResponse, NotFoundResponse
from empire.server.core.module_models import EmpireModule
from empire.server.core.module_service import ModuleService

log = logging.getLogger(__name__)


def get_module_service(main: AppCtx) -> ModuleService:
    return main.modulesv2


ModuleServiceDep = Annotated[ModuleService, Depends(get_module_service)]


router = APIRouter(
    prefix="/api/v2/modules",
    tags=["modules"],
    responses={
        404: {"description": "Not found", "model": NotFoundResponse},
        400: {"description": "Bad request", "model": BadRequestResponse},
    },
    dependencies=[Depends(get_current_active_user)],
)


async def get_module(uid: str, module_service: ModuleServiceDep):
    module = module_service.get_by_id(uid)

    if module:
        return module

    raise HTTPException(status_code=404, detail=f"Module not found for id {uid}")


ModuleDep = Annotated[EmpireModule, Depends(get_module)]


@router.get(
    "/",
    # todo is there an equivalent for this that doesn't cause fastapi to convert the object twice?
    #  Still want to display the response type in the docs
    # response_model=Modules,
)
async def read_modules(
    module_service: ModuleServiceDep,
    hide_disabled: bool = False,
):
    modules = [
        domain_to_dto_module(x[1], x[0])
        for x in module_service.get_all(hide_disabled).items()
    ]

    return {"records": modules}


@router.get("/{uid}", response_model=Module)
async def read_module(
    uid: str,
    module: ModuleDep,
):
    return domain_to_dto_module(module, uid)


@router.get("/{uid}/script", response_model=ModuleScript)
async def read_module_script(
    uid: str,
    module: ModuleDep,
    module_service: ModuleServiceDep,
):
    script = module_service.get_module_script(module.id)

    if script:
        return ModuleScript(module_id=uid, script=script)

    raise HTTPException(status_code=404, detail=f"Module script not found for id {uid}")


@router.put("/{uid}", response_model=Module)
async def update_module(
    uid: str,
    module_req: ModuleUpdateRequest,
    db: CurrentSession,
    module: ModuleDep,
    module_service: ModuleServiceDep,
):
    module_service.update_module(db, module, module_req)

    return domain_to_dto_module(module, uid)


@router.put("/bulk/enable", status_code=204, response_class=Response)
async def update_bulk_enable(
    module_req: ModuleBulkUpdateRequest,
    db: CurrentSession,
    module_service: ModuleServiceDep,
):
    module_service.update_modules(db, module_req)


@router.post("/reload", status_code=204, response_class=Response)
async def reload_modules(db: CurrentSession, module_service: ModuleServiceDep):
    module_service.load_modules(db)


@router.post("/reset", status_code=204, response_class=Response)
async def reset_modules(db: CurrentSession, module_service: ModuleServiceDep):
    module_service.delete_all_modules(db)
    module_service.load_modules(db)
