import typing
from enum import Enum
from typing import Annotated, Any

from pydantic import (
    BaseModel,
    BeforeValidator,
    ConfigDict,
)

if typing.TYPE_CHECKING:
    from empire.server.core.db import models


class BadRequestResponse(BaseModel):
    detail: str


class NotFoundResponse(BaseModel):
    detail: str


class ValueType(str, Enum):
    string = "STRING"
    float = "FLOAT"
    integer = "INTEGER"
    boolean = "BOOLEAN"
    file = "FILE"


# Ensure the functionality of pydantic v1 coercing values to strings
# https://github.com/pydantic/pydantic/issues/5606
def coerce_to_string(v: Any):
    if isinstance(v, list):
        return [str(value) for value in v]
    return str(v)


class DependentOption(BaseModel):
    name: str
    values: list[str] | None


class CustomOptionSchema(BaseModel):
    description: str
    required: bool
    value: Annotated[str, BeforeValidator(coerce_to_string)]
    suggested_values: Annotated[list[str], BeforeValidator(coerce_to_string)]
    strict: bool
    editable: bool = True
    value_type: ValueType
    internal: bool
    depends_on: list[DependentOption] = []


class OrderDirection(str, Enum):
    asc = "asc"
    desc = "desc"


class DownloadDescription(BaseModel):
    id: int
    filename: str
    link: str
    model_config = ConfigDict(from_attributes=True)


class Author(BaseModel):
    name: str | None = None
    handle: str | None = None
    link: str | None = None


def domain_to_dto_download_description(download: "models.Download"):
    filename = download.filename or download.location.split("/")[-1]

    return DownloadDescription(
        id=download.id,
        filename=filename,
        link=f"/api/v2/downloads/{download.id}/download",
    )


def to_value_type(value: Any, type: str = "") -> ValueType:
    type = type or ""
    if type.lower() == "file":
        return ValueType.file
    if type.lower() in ["string", "str"] or isinstance(value, str):
        return ValueType.string
    if type.lower() in ["boolean", "bool"] or isinstance(value, bool):
        return ValueType.boolean
    if type.lower() == "float" or isinstance(value, float):
        return ValueType.float
    if type.lower() in ["integer", "int"] or isinstance(value, int):
        return ValueType.integer

    return ValueType.string


def to_string(value):
    return str(value)


# This is sort of an undocumented behavior for the Empire API. The openapi spec says
#   the values should be strings, but it has allowed other types.
# The behavior in pydantic v1 was to just coerce values to strings, but in v2
#   this behavior was changed to raise a validation error. Using this custom
#   type with a BeforeValidator allows us to coerce the value to a string before
#   validation.
# This could be removed in Empire 6 as a breaking change.
coerced_dict = dict[str, Annotated[str, BeforeValidator(to_string)]]
