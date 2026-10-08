from typing import Annotated, Any

from fastapi import Depends, HTTPException, Query
from sqlalchemy.orm import Session
from starlette.responses import Response
from starlette.status import (
    HTTP_201_CREATED,
    HTTP_204_NO_CONTENT,
    HTTP_409_CONFLICT,
)

from empire.server.api.api_router import APIRouter
from empire.server.api.jwt_auth import get_current_active_user
from empire.server.api.v2.shared_dependencies import AppCtx, CurrentSession, paginate
from empire.server.api.v2.shared_dto import (
    BadRequestResponse,
    NotFoundResponse,
    OrderDirection,
)
from empire.server.api.v2.tag.tag_dto import (
    TagAttachRequest,
    TagCreateRequest,
    TagOrderOptions,
    Tags,
    TagSourceFilter,
    TagUpdateRequest,
    domain_to_dto_tag,
    domain_to_dto_tag_with_usage,
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
def get_tags(
    db: CurrentSession,
    tag_service: TagServiceDep,
    limit: int = -1,
    page: int = 1,
    order_direction: OrderDirection = OrderDirection.desc,
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
    usage = tag_service.usage_counts(db, [t.id for t in tags])
    records = [domain_to_dto_tag_with_usage(t, usage.get(t.id, 0)) for t in tags]
    page, total_pages = paginate(total, page, limit)
    return Tags(
        records=records,
        page=page,
        total_pages=total_pages,
        limit=limit,
        total=total,
    )


def _get_tag_or_404(tag_id: int, db: Session, tag_service: TagService) -> models.Tag:
    tag = tag_service.get_by_id(db, tag_id)
    if tag is None:
        raise HTTPException(404, f"Tag not found for id {tag_id}")
    return tag


@router.get("/{tag_id}")
def get_tag(tag_id: int, db: CurrentSession, tag_service: TagServiceDep):
    return domain_to_dto_tag(_get_tag_or_404(tag_id, db, tag_service))


@router.post("/", status_code=HTTP_201_CREATED)
def create_tag(req: TagCreateRequest, db: CurrentSession, tag_service: TagServiceDep):
    try:
        tag = tag_service.create_tag(db, req.name, req.color, req.description)
    except ValueError as e:
        raise HTTPException(HTTP_409_CONFLICT, str(e)) from e
    return domain_to_dto_tag(tag)


@router.put("/{tag_id}")
def update_tag(
    tag_id: int, req: TagUpdateRequest, db: CurrentSession, tag_service: TagServiceDep
):
    tag = _get_tag_or_404(tag_id, db, tag_service)
    try:
        tag = tag_service.update_tag(db, tag, req.name, req.color, req.description)
    except ValueError as e:
        raise HTTPException(HTTP_409_CONFLICT, str(e)) from e
    return domain_to_dto_tag(tag)


@router.delete("/{tag_id}", status_code=HTTP_204_NO_CONTENT)
def delete_tag(tag_id: int, db: CurrentSession, tag_service: TagServiceDep):
    tag = _get_tag_or_404(tag_id, db, tag_service)
    try:
        tag_service.delete_tag(db, tag)
    except ValueError as e:
        raise HTTPException(HTTP_409_CONFLICT, str(e)) from e
    return Response(status_code=HTTP_204_NO_CONTENT)


# app.custom_generate_unique_id names a route after its tag and its route name,
# leaving these two as `{tag}_add_tag` / `{tag}_delete_tag`. That only reads
# correctly when the taggable is the tag's namesake; anywhere else, and
# certainly where two taggables share a tag and would collide outright, the
# caller names the taggable and both the operation id and the rendered summary
# pick it up.
def add_endpoints_to_taggable(router, path, get_taggable, taggable_name=None):
    def add_tag(
        uid: int | str,
        tag_req: TagAttachRequest,
        db: CurrentSession,
        db_taggable: Annotated[Any, Depends(get_taggable)],
        tag_service: TagServiceDep,
    ):
        tag, _ = tag_service.attach_tag(db, db_taggable, tag_id=tag_req.tag_id)
        if tag is None:
            raise HTTPException(404, f"Tag not found for id {tag_req.tag_id}")
        return domain_to_dto_tag(tag)

    def detach_tag_route(
        uid: int | str,
        tag_id: int,
        db: CurrentSession,
        db_taggable: Annotated[Any, Depends(get_taggable)],
        tag_service: TagServiceDep,
    ):
        tag_service.detach_tag(db, db_taggable, tag_id)
        return Response(status_code=HTTP_204_NO_CONTENT)

    noun = f"{taggable_name}_tag" if taggable_name else "tag"

    # POST attaches an existing tag by id (200, or 404 if unknown). Editing a tag
    # is global via PUT /api/v2/tags/{id}; there is no per-entity edit route.
    router.add_api_route(path, endpoint=add_tag, methods=["POST"], name=f"add_{noun}")
    router.add_api_route(
        path + "/{tag_id}",
        endpoint=detach_tag_route,
        methods=["DELETE"],
        status_code=HTTP_204_NO_CONTENT,
        name=f"delete_{noun}",
    )
