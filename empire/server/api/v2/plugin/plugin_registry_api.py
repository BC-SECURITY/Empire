from typing import Annotated

from fastapi import Depends, HTTPException

from empire.server.api.api_router import APIRouter
from empire.server.api.jwt_auth import (
    get_current_active_user,
)
from empire.server.api.v2.plugin.plugin_registry_dto import (
    MarketplaceResponse,
    PluginInstallRequest,
)
from empire.server.api.v2.shared_dependencies import AppCtx, CurrentSession
from empire.server.api.v2.shared_dto import BadRequestResponse, NotFoundResponse
from empire.server.core.exceptions import PluginValidationException
from empire.server.core.plugin_registry_service import PluginRegistryService
from empire.server.core.plugin_service import PluginService


def get_plugin_registry_service(main: AppCtx) -> PluginRegistryService:
    return main.pluginregistriesv2


PluginRegistryServiceDep = Annotated[
    PluginRegistryService, Depends(get_plugin_registry_service)
]


def get_plugin_service(main: AppCtx) -> PluginService:
    return main.pluginsv2


router = APIRouter(
    prefix="/api/v2/plugin-registries",
    tags=["plugins"],
    responses={
        404: {"description": "Not found", "model": NotFoundResponse},
        400: {"description": "Bad request", "model": BadRequestResponse},
    },
    dependencies=[Depends(get_current_active_user)],
)


@router.get("/marketplace", response_model=MarketplaceResponse)
async def get_marketplace(
    db: CurrentSession,
    plugin_registry_service: PluginRegistryServiceDep,
):
    return MarketplaceResponse.model_validate(
        plugin_registry_service.get_marketplace(db)
    )


@router.post("/marketplace/install")
async def install_plugin(
    install_req: PluginInstallRequest,
    db: CurrentSession,
    plugin_registry_service: PluginRegistryServiceDep,
):
    try:
        plugin_registry_service.install_plugin(
            db, install_req.name, install_req.version, install_req.registry
        )
    except PluginValidationException as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
