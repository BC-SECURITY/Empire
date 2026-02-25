from datetime import datetime
from enum import Enum

from pydantic import BaseModel, Field

from empire.server.api.v2.shared_dto import (
    DownloadDescription,
    domain_to_dto_download_description,
)
from empire.server.api.v2.tag.tag_dto import Tag, domain_to_dto_tag
from empire.server.core.db import models


class AgentTaskOrderOptions(str, Enum):
    id = "id"
    updated_at = "updated_at"
    status = "status"
    agent = "agent"


def domain_to_dto_task(
    task: models.AgentTask,
    include_full_input: bool = True,
    include_original_output: bool = True,
    include_output: bool = True,
):
    return AgentTask.model_construct(  # .construct doesn't do any validation and speeds up the request a bit
        id=task.id,
        input=task.input,
        full_input=None if not include_full_input else task.input_full,
        output=None if not include_output else task.output,
        original_output=None if not include_original_output else task.original_output,
        user_id=task.user_id,
        username=None if not task.user else task.user.username,
        agent_id=task.agent_id,
        downloads=[domain_to_dto_download_description(x) for x in task.downloads],
        module_name=task.module_name,
        module_options=task.module_options,
        task_name=task.task_name,
        status=task.status,
        created_at=task.created_at,
        updated_at=task.updated_at,
        tags=[domain_to_dto_tag(x) for x in task.tags],
    )


class AgentTask(BaseModel):
    id: int
    input: str
    full_input: str | None = None
    output: str | None = None
    original_output: str | None = None
    user_id: int | None = None
    username: str | None = None
    agent_id: str
    downloads: list[DownloadDescription]
    module_name: str | None = None
    module_options: dict | None = None
    task_name: str | None = None
    status: models.AgentTaskStatus
    created_at: datetime
    updated_at: datetime
    tags: list[Tag]


class AgentTasks(BaseModel):
    records: list[AgentTask]
    limit: int
    page: int
    total_pages: int
    total: int


class ShellPostRequest(BaseModel):
    command: str
    literal: bool = False


class ModulePostRequest(BaseModel):
    module_id: str
    ignore_language_version_check: bool = False
    ignore_admin_check: bool = False
    options: dict[str, str | int | float]
    modified_input: str | None = None


class DownloadPostRequest(BaseModel):
    path_to_file: str


class UploadPostRequest(BaseModel):
    path_to_file: str
    file_id: int


class ScriptCommandPostRequest(BaseModel):
    command: str


class SysinfoPostRequest(BaseModel):
    pass


class SleepPostRequest(BaseModel):
    delay: int = Field(ge=0)
    jitter: float = Field(ge=0, le=1)


class CommsPostRequest(BaseModel):
    new_listener_id: int


class KillDatePostRequest(BaseModel):
    kill_date: str  # todo validator. Or can we just set it to a datetime. same with killdate on the agent dto


class WorkingHoursPostRequest(BaseModel):
    working_hours: str  # todo validator.


class DirectoryListPostRequest(BaseModel):
    path: str


class ExitPostRequest(BaseModel):
    pass


class SocksPostRequest(BaseModel):
    port: int


class KillJobPostRequest(BaseModel):
    id: int


class StopJobPostRequest(BaseModel):
    id: int
