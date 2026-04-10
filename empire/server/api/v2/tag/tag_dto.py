from enum import StrEnum
from typing import Annotated

from pydantic import BaseModel, StringConstraints

from empire.server.core.db import models

# Validate the string contains 1 colon
TagStr = Annotated[str, StringConstraints(pattern=r"^[^:]+:[^:]+$")]

# Validate the string has no colons
TagStrNoColon = Annotated[str, StringConstraints(pattern=r"^[^:]+$")]


class TagSourceFilter(StrEnum):
    listener = "listener"
    agent = "agent"
    agent_task = "agent_task"
    plugin_task = "plugin_task"
    download = "download"
    credential = "credential"


class Tag(BaseModel):
    id: int
    name: str
    value: str
    label: str
    color: str | None = None


class Tags(BaseModel):
    records: list[Tag]
    limit: int
    page: int
    total_pages: int
    total: int


class TagRequest(BaseModel):
    name: TagStrNoColon
    value: TagStrNoColon
    color: str | None = None


class TagOrderOptions(StrEnum):
    name = "name"
    created_at = "created_at"
    updated_at = "updated_at"


def domain_to_dto_tag(tag: models.Tag):
    return Tag(
        id=tag.id,
        name=tag.name,
        value=tag.value,
        label=f"{tag.name}:{tag.value}",
        color=tag.color,
    )
