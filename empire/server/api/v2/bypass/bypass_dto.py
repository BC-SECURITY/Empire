from datetime import datetime

from pydantic import BaseModel

from empire.server.api.v2.shared_dto import Author


def domain_to_dto_bypass(bypass):
    return Bypass(
        id=bypass.id,
        name=bypass.name,
        authors=bypass.authors or [],
        language=bypass.language,
        code=bypass.code,
        is_default=bypass.is_default,
        created_at=bypass.created_at,
        updated_at=bypass.updated_at,
    )


class Bypass(BaseModel):
    id: int
    name: str
    authors: list[Author]
    language: str
    code: str
    is_default: bool
    created_at: datetime
    updated_at: datetime


class Bypasses(BaseModel):
    records: list[Bypass]


class BypassUpdateRequest(BaseModel):
    name: str
    language: str
    code: str


class BypassPostRequest(BaseModel):
    name: str
    language: str
    code: str
