from datetime import datetime
from enum import Enum

from pydantic import BaseModel

from empire.server.api.v2.shared_dto import (
    DownloadDescription,
    domain_to_dto_download_description,
)
from empire.server.api.v2.tag.tag_dto import Tag, domain_to_dto_tag
from empire.server.core.db import models


class PluginTaskOrderOptions(str, Enum):
    id = "id"
    updated_at = "updated_at"
    status = "status"
    plugin = "plugin"


def domain_to_dto_plugin_task(
    task: models.PluginTask,
    include_full_input: bool = True,
    include_output: bool = True,
):
    return PluginTask.model_construct(  # .construct doesn't do any validation and speeds up the request a bit
        id=task.id,
        input=task.input,
        full_input=None if not include_full_input else task.input_full,
        output=None if not include_output else task.output,
        user_id=task.user_id,
        username=None if not task.user else task.user.username,
        plugin_id=task.plugin_id,
        plugin_options=task.plugin_options,
        downloads=[domain_to_dto_download_description(x) for x in task.downloads],
        status=task.status,
        created_at=task.created_at,
        updated_at=task.updated_at,
        tags=[domain_to_dto_tag(x) for x in task.tags],
    )


class PluginTask(BaseModel):
    id: int
    input: str
    full_input: str | None = None
    output: str | None = None
    user_id: int | None = None
    username: str | None = None
    plugin_id: str
    plugin_options: dict | None = None
    downloads: list[DownloadDescription]
    status: models.PluginTaskStatus | None = None
    created_at: datetime
    updated_at: datetime
    tags: list[Tag]


class PluginTasks(BaseModel):
    records: list[PluginTask]
    limit: int
    page: int
    total_pages: int
    total: int
