import math

from fastapi import Depends, File, HTTPException, Query, UploadFile
from starlette.responses import FileResponse

from empire.server.api.api_router import APIRouter
from empire.server.api.jwt_auth import CurrentActiveUser, get_current_active_user
from empire.server.api.v2.download.download_dto import (
    Download,
    DownloadOrderOptions,
    Downloads,
    DownloadSourceFilter,
    domain_to_dto_download,
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
from empire.server.core.download_service import DownloadService


def get_download_service(main: AppCtx) -> DownloadService:
    return main.downloadsv2


router = APIRouter(
    prefix="/api/v2/downloads",
    tags=["downloads"],
    responses={
        404: {"description": "Not found", "model": NotFoundResponse},
        400: {"description": "Bad request", "model": BadRequestResponse},
    },
    dependencies=[Depends(get_current_active_user)],
)


async def get_download(
    uid: int,
    db: CurrentSession,
    download_service: DownloadService = Depends(get_download_service),
):
    download = download_service.get_by_id(db, uid)

    if download:
        return download

    raise HTTPException(404, f"Download not found for id {uid}")


@router.get("/{uid}/download", response_class=FileResponse)
async def download_download(
    uid: int,
    db: CurrentSession,
    db_download: models.Download = Depends(get_download),
):
    filename = db_download.filename or db_download.location.split("/")[-1]

    return FileResponse(db_download.location, filename=filename)


tag_api.add_endpoints_to_taggable(router, "/{uid}/tags", get_download)


@router.get(
    "/{uid}",
    response_model=Download,
)
async def read_download(
    uid: int,
    db: CurrentSession,
    db_download: models.Download = Depends(get_download),
):
    return domain_to_dto_download(db_download)


@router.get("/", response_model=Downloads)
async def read_downloads(
    db: CurrentSession,
    limit: int = -1,
    page: int = 1,
    order_direction: OrderDirection = OrderDirection.desc,
    order_by: DownloadOrderOptions = DownloadOrderOptions.updated_at,
    query: str | None = None,
    sources: list[DownloadSourceFilter] | None = Query(None),
    tags: list[TagStr] | None = Query(None),
    download_service: DownloadService = Depends(get_download_service),
):
    downloads, total = download_service.get_all(
        db=db,
        download_types=sources,
        tags=tags,
        q=query,
        limit=limit,
        offset=(page - 1) * limit,
        order_by=order_by,
        order_direction=order_direction,
    )

    downloads_converted = [domain_to_dto_download(x) for x in downloads]

    return Downloads(
        records=downloads_converted,
        page=page,
        total_pages=math.ceil(total / limit) if limit > 0 else page,
        limit=limit,
        total=total,
    )


@router.post("/", status_code=201, response_model=Download)
async def create_download(
    user: CurrentActiveUser,
    db: CurrentSession,
    file: UploadFile = File(...),
    download_service: DownloadService = Depends(get_download_service),
):
    return domain_to_dto_download(download_service.create_download(db, user, file))
