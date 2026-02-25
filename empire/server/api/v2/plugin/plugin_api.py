from typing import Annotated

from fastapi import Depends, HTTPException
from starlette.responses import Response

from empire.server.api.api_router import APIRouter
from empire.server.api.jwt_auth import (
    CurrentUser,
    get_current_active_user,
)
from empire.server.api.v2.plugin.plugin_dto import (
    PluginExecutePostRequest,
    PluginExecuteResponse,
    PluginInstallGitRequest,
    PluginInstallTarRequest,
    Plugins,
    PluginUpdateRequest,
    domain_to_dto_plugin,
)
from empire.server.api.v2.shared_dependencies import AppCtx, CurrentSession
from empire.server.api.v2.shared_dto import BadRequestResponse, NotFoundResponse
from empire.server.core.exceptions import (
    PluginExecutionException,
    PluginValidationException,
)
from empire.server.core.plugin_service import PluginHolder, PluginService
from empire.server.utils.git_util import GitOperationException


def get_plugin_service(main: AppCtx) -> PluginService:
    return main.pluginsv2


PluginServiceDep = Annotated[PluginService, Depends(get_plugin_service)]


router = APIRouter(
    prefix="/api/v2/plugins",
    tags=["plugins"],
    responses={
        404: {"description": "Not found", "model": NotFoundResponse},
        400: {"description": "Bad request", "model": BadRequestResponse},
    },
    dependencies=[Depends(get_current_active_user)],
)


async def get_plugin(
    plugin_id: str,
    db: CurrentSession,
    plugin_service: PluginServiceDep,
) -> PluginHolder:
    plugin = plugin_service.get_by_id(db, plugin_id)

    if plugin:
        return plugin

    raise HTTPException(status_code=404, detail=f"Plugin not found for id {plugin_id}")


PluginDep = Annotated[PluginHolder, Depends(get_plugin)]


async def get_loaded_plugin(plugin_id: str, plugin_holder: PluginDep) -> PluginHolder:
    if plugin_holder.loaded_plugin:
        return plugin_holder

    raise HTTPException(status_code=400, detail=f"Plugin not loaded for id {plugin_id}")


LoadedPluginDep = Annotated[PluginHolder, Depends(get_loaded_plugin)]


@router.get("/", response_model=Plugins)
async def read_plugins(db: CurrentSession, plugin_service: PluginServiceDep):
    plugins = plugin_service.get_all(db)
    return {"records": [domain_to_dto_plugin(x, db) for x in plugins]}


@router.get("/{plugin_id}")
async def read_plugin(
    plugin_id: str,
    db: CurrentSession,
    plugin: PluginDep,
):
    return domain_to_dto_plugin(plugin, db)


@router.post("/{plugin_id}/execute", response_model=PluginExecuteResponse)
async def execute_plugin(
    plugin_id: str,
    plugin_req: PluginExecutePostRequest,
    db: CurrentSession,
    current_user: CurrentUser,
    plugin: LoadedPluginDep,
    plugin_service: PluginServiceDep,
):
    try:
        results, err = plugin_service.execute_plugin(
            db, plugin.loaded_plugin, plugin_req, current_user
        )
    except PluginValidationException as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    except PluginExecutionException as e:
        raise HTTPException(status_code=500, detail=str(e)) from e

    if results is False or err:
        raise HTTPException(500, err or "internal plugin error")

    if results in [True, None]:
        return {"detail": "Plugin executed successfully"}

    return {"detail": results}


@router.put("/{plugin_id}", status_code=200)
async def update_plugin(
    plugin_id: str,
    plugin_update_req: PluginUpdateRequest,
    db: CurrentSession,
    plugin: LoadedPluginDep,
    plugin_service: PluginServiceDep,
):
    try:
        plugin_service.update_plugin_enabled(db, plugin, plugin_update_req.enabled)
        return domain_to_dto_plugin(plugin, db)
    except PluginValidationException as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    except PluginExecutionException as e:
        raise HTTPException(status_code=500, detail=str(e)) from e


@router.put("/{plugin_id}/settings", status_code=200)
async def update_plugin_settings(
    plugin_id: str,
    plugin_settings: dict,
    db: CurrentSession,
    plugin: LoadedPluginDep,
    plugin_service: PluginServiceDep,
):
    try:
        plugin_service.update_plugin_settings(db, plugin, plugin_settings)
    except PluginValidationException as e:
        raise HTTPException(status_code=400, detail=str(e)) from e


@router.post("/reload", status_code=204, response_class=Response)
async def reload_plugins(
    db: CurrentSession,
    plugin_service: PluginServiceDep,
):
    plugin_service.shutdown()
    plugin_service.load_plugins(db)


@router.post("/install/git")
async def install_plugin_git(
    req: PluginInstallGitRequest,
    db: CurrentSession,
    plugin_service: PluginServiceDep,
):
    try:
        plugin_service.install_plugin_from_git(db, req.url, req.subdirectory, req.ref)
    except GitOperationException as e:
        raise HTTPException(
            status_code=400, detail=f"Failed to install plugin from git: {e}"
        ) from e
    except PluginValidationException as e:
        raise HTTPException(status_code=400, detail=str(e)) from e


@router.post("/install/tar")
async def install_plugin_tar(
    req: PluginInstallTarRequest,
    db: CurrentSession,
    plugin_service: PluginServiceDep,
):
    try:
        plugin_service.install_plugin_from_tar(db, req.url, req.subdirectory)
    except PluginValidationException as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
