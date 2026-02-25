from typing import Annotated

from fastapi import Depends, HTTPException

from empire.server.api.api_router import APIRouter
from empire.server.api.jwt_auth import get_current_active_user
from empire.server.api.v2.listener.listener_dto import (
    ListenerTemplate,
    ListenerTemplates,
    domain_to_dto_template,
)
from empire.server.api.v2.shared_dependencies import AppCtx
from empire.server.api.v2.shared_dto import BadRequestResponse, NotFoundResponse
from empire.server.core.listener_template_service import ListenerTemplateService


def get_listener_template_service(main: AppCtx) -> ListenerTemplateService:
    return main.listenertemplatesv2


ListenerTemplateServiceDep = Annotated[
    ListenerTemplateService, Depends(get_listener_template_service)
]


router = APIRouter(
    prefix="/api/v2/listener-templates",
    tags=["listener-templates"],
    responses={
        404: {"description": "Not found", "model": NotFoundResponse},
        400: {"description": "Bad request", "model": BadRequestResponse},
    },
    dependencies=[Depends(get_current_active_user)],
)


@router.get(
    "/",
    response_model=ListenerTemplates,
)
async def get_listener_templates(
    listener_template_service: ListenerTemplateServiceDep,
):
    templates = [
        domain_to_dto_template(x[1], x[0])
        for x in listener_template_service.get_listener_templates().items()
    ]

    return {"records": templates}


@router.get(
    "/{uid}",
    response_model=ListenerTemplate,
)
async def get_listener_template(
    uid: str,
    listener_template_service: ListenerTemplateServiceDep,
):
    template = listener_template_service.get_listener_template(uid)

    if not template:
        raise HTTPException(status_code=404, detail="Listener template not found")

    return domain_to_dto_template(template, uid)
