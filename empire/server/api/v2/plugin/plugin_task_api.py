import math
from datetime import datetime
from typing import Annotated

from fastapi import Depends, HTTPException, Query

from empire.server.api.api_router import APIRouter
from empire.server.api.jwt_auth import get_current_active_user
from empire.server.api.v2.plugin.plugin_task_dto import (
    PluginTask,
    PluginTaskOrderOptions,
    PluginTasks,
    domain_to_dto_plugin_task,
)
from empire.server.api.v2.shared_dependencies import AppCtx, CurrentSession
from empire.server.api.v2.shared_dto import (
    BadRequestResponse,
    NotFoundResponse,
    OrderDirection,
)
from empire.server.api.v2.tag import tag_api
from empire.server.api.v2.tag.tag_dto import TagStr
from empire.server.core.db import models
from empire.server.core.db.models import PluginTaskStatus
from empire.server.core.download_service import DownloadService
from empire.server.core.plugin_service import PluginHolder, PluginService
from empire.server.core.plugin_task_service import PluginTaskService


def get_plugin_task_service(main: AppCtx) -> PluginTaskService:
    return main.plugintasksv2


PluginTaskServiceDep = Annotated[PluginTaskService, Depends(get_plugin_task_service)]


def get_plugin_service(main: AppCtx) -> PluginService:
    return main.pluginsv2


PluginServiceDep = Annotated[PluginService, Depends(get_plugin_service)]


def get_download_service(main: AppCtx) -> DownloadService:
    return main.downloadsv2


DownloadServiceDep = Annotated[DownloadService, Depends(get_download_service)]


router = APIRouter(
    prefix="/api/v2/plugins",
    tags=["plugins", "tasks"],
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


async def get_task(
    uid: int,
    db: CurrentSession,
    plugin: PluginDep,
    plugin_task_service: PluginTaskServiceDep,
):
    task = plugin_task_service.get_task(db, plugin.db_plugin.id, uid)

    if task:
        return task

    raise HTTPException(
        404, f"Task not found for plugin {plugin.db_plugin.id} and task id {uid}"
    )


TaskDep = Annotated[models.PluginTask, Depends(get_task)]


tag_api.add_endpoints_to_taggable(router, "/{plugin_id}/tasks/{uid}/tags", get_task)


@router.get("/tasks", response_model=PluginTasks)
async def read_tasks_all_plugins(
    db: CurrentSession,
    limit: int = -1,
    page: int = 1,
    include_full_input: bool = False,
    include_output: bool = True,
    since: datetime | None = None,
    order_by: PluginTaskOrderOptions = PluginTaskOrderOptions.id,
    order_direction: OrderDirection = OrderDirection.desc,
    status: PluginTaskStatus | None = None,
    plugins: list[str] | None = Query(None),
    users: list[int] | None = Query(None),
    tags: list[TagStr] | None = Query(None),
    query: str | None = None,
    *,
    plugin_task_service: PluginTaskServiceDep,
):
    tasks, total = plugin_task_service.get_tasks(
        db,
        plugins=plugins,
        users=users,
        tags=tags,
        limit=limit,
        offset=(page - 1) * limit,
        include_full_input=include_full_input,
        include_output=include_output,
        since=since,
        order_by=order_by,
        order_direction=order_direction,
        status=status,
        q=query,
    )

    tasks_converted = [
        domain_to_dto_plugin_task(x, include_full_input, include_output) for x in tasks
    ]

    return PluginTasks(
        records=tasks_converted,
        page=page,
        total_pages=math.ceil(total / limit),
        limit=limit,
        total=total,
    )


@router.get("/{plugin_id}/tasks", response_model=PluginTasks)
async def read_tasks(
    db: CurrentSession,
    plugin: PluginDep,
    plugin_task_service: PluginTaskServiceDep,
    limit: int = -1,
    page: int = 1,
    include_full_input: bool = False,
    include_output: bool = True,
    since: datetime | None = None,
    order_by: PluginTaskOrderOptions = PluginTaskOrderOptions.id,
    order_direction: OrderDirection = OrderDirection.desc,
    status: PluginTaskStatus | None = None,
    users: list[int] | None = Query(None),
    tags: list[TagStr] | None = Query(None),
    query: str | None = None,
):
    tasks, total = plugin_task_service.get_tasks(
        db,
        plugins=[plugin.db_plugin.id],
        users=users,
        tags=tags,
        limit=limit,
        offset=(page - 1) * limit,
        include_full_input=include_full_input,
        include_output=include_output,
        since=since,
        order_by=order_by,
        order_direction=order_direction,
        status=status,
        q=query,
    )

    tasks_converted = [
        domain_to_dto_plugin_task(x, include_full_input, include_output) for x in tasks
    ]

    return PluginTasks(
        records=tasks_converted,
        page=page,
        total_pages=math.ceil(total / limit) if limit > 0 else page,
        limit=limit,
        total=total,
    )


@router.get("/{plugin_id}/tasks/{uid}", response_model=PluginTask)
async def read_task(
    uid: int,
    db_task: TaskDep,
):
    if not db_task:
        raise HTTPException(status_code=404, detail="Task not found")

    return domain_to_dto_plugin_task(db_task)
