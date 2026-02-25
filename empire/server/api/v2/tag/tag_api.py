import math
from typing import Annotated, Any

from fastapi import Depends, HTTPException, Query
from starlette.responses import Response
from starlette.status import HTTP_201_CREATED, HTTP_204_NO_CONTENT

from empire.server.api.api_router import APIRouter
from empire.server.api.jwt_auth import get_current_active_user
from empire.server.api.v2.shared_dependencies import AppCtx, CurrentSession
from empire.server.api.v2.shared_dto import (
    BadRequestResponse,
    NotFoundResponse,
    OrderDirection,
)
from empire.server.api.v2.tag.tag_dto import (
    TagOrderOptions,
    TagRequest,
    Tags,
    TagSourceFilter,
    domain_to_dto_tag,
)
from empire.server.core.db import models
from empire.server.core.tag_service import TagService


def get_tag_service(main: AppCtx) -> TagService:
    return main.tagsv2


TagServiceDep = Annotated[TagService, Depends(get_tag_service)]


router = APIRouter(
    prefix="/api/v2/tags",
    tags=["tags"],
    responses={
        404: {"description": "Not found", "model": NotFoundResponse},
        400: {"description": "Bad request", "model": BadRequestResponse},
    },
    dependencies=[Depends(get_current_active_user)],
)


@router.get("/")
async def get_tags(
    db: CurrentSession,
    tag_service: TagServiceDep,
    limit: int = -1,
    page: int = 1,
    order_direction: OrderDirection = OrderDirection.asc,
    order_by: TagOrderOptions = TagOrderOptions.updated_at,
    query: str | None = None,
    sources: list[TagSourceFilter] | None = Query(None),
):
    tags, total = tag_service.get_all(
        db=db,
        tag_types=sources,
        q=query,
        limit=limit,
        offset=(page - 1) * limit,
        order_by=order_by,
        order_direction=order_direction,
    )

    tags_converted = [domain_to_dto_tag(x) for x in tags]

    return Tags(
        records=tags_converted,
        page=page,
        total_pages=math.ceil(total / limit) if limit > 0 else page,
        limit=limit,
        total=total,
    )


def add_endpoints_to_taggable(router, path, get_taggable):
    async def get_tag(
        tag_id: int,
        db: CurrentSession,
        tag_service: TagServiceDep,
    ):
        tag = tag_service.get_by_id(db, tag_id)

        if tag:
            return tag

        raise HTTPException(404, f"Tag not found for id {tag_id}")

    TagDep = Annotated[models.Tag, Depends(get_tag)]

    async def add_tag(
        uid: int | str,
        tag_req: TagRequest,
        db: CurrentSession,
        db_taggable: Annotated[Any, Depends(get_taggable)],
        tag_service: TagServiceDep,
    ):
        tag = tag_service.add_tag(
            db, db_taggable, tag_req.name, tag_req.value, tag_req.color
        )

        return domain_to_dto_tag(tag)

    async def update_tag(
        uid: int | str,
        tag_req: TagRequest,
        db: CurrentSession,
        db_taggable: Annotated[Any, Depends(get_taggable)],
        db_tag: TagDep,
        tag_service: TagServiceDep,
    ):
        tag = tag_service.update_tag(db, db_tag, db_taggable, tag_req)

        return domain_to_dto_tag(tag)

    async def delete_tag(
        uid: int | str,
        tag_id: int,
        db: CurrentSession,
        db_taggable: Annotated[Any, Depends(get_taggable)],
        tag_service: TagServiceDep,
    ):
        tag_service.delete_tag(db, db_taggable, tag_id)

        return Response(status_code=HTTP_204_NO_CONTENT)

    router.add_api_route(
        path, endpoint=add_tag, methods=["POST"], status_code=HTTP_201_CREATED
    )
    router.add_api_route(path + "/{tag_id}", endpoint=update_tag, methods=["PUT"])
    router.add_api_route(
        path + "/{tag_id}",
        endpoint=delete_tag,
        methods=["DELETE"],
        status_code=HTTP_204_NO_CONTENT,
    )
