import logging
import shutil
import typing
from pathlib import Path

from fastapi import HTTPException, UploadFile
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from empire.server.api.v2.download.download_dto import (
    DownloadOrderOptions,
    DownloadSourceFilter,
)
from empire.server.api.v2.shared_dto import OrderDirection
from empire.server.core.config.config_manager import empire_config
from empire.server.core.db import models
from empire.server.core.tag_service import tag_name_filter
from empire.server.utils.file_util import is_path_within, safe_filename

if typing.TYPE_CHECKING:
    from empire.server.common.empire import MainMenu

log = logging.getLogger(__name__)


class DownloadService:
    def __init__(self, main_menu: "MainMenu"):
        self.main_menu = main_menu
        self.tag_service = main_menu.tagsv2

    @staticmethod
    def get_by_id(db: Session, uid: int):
        return db.scalars(
            select(models.Download).where(models.Download.id == uid)
        ).first()

    @staticmethod
    def get_all(  # noqa: PLR0913 PLR0912
        db: Session,
        download_types: list[DownloadSourceFilter] | None,
        tags: list[str] | None = None,
        q: str | None = None,
        limit: int = -1,
        offset: int = 0,
        order_by: DownloadOrderOptions = DownloadOrderOptions.updated_at,
        order_direction: OrderDirection = OrderDirection.desc,
    ) -> tuple[list[models.Download], int]:
        stmt = select(
            models.Download, func.count(models.Download.id).over().label("total")
        )

        download_types = download_types or []
        sub = []
        if DownloadSourceFilter.agent_task in download_types:
            sub.append(
                select(
                    models.agent_task_download_assc.c.download_id.label("download_id")
                )
            )
        if DownloadSourceFilter.agent_file in download_types:
            sub.append(
                select(
                    models.agent_file_download_assc.c.download_id.label("download_id")
                )
            )
        if DownloadSourceFilter.stager in download_types:
            sub.append(
                select(models.stager_download_assc.c.download_id.label("download_id"))
            )
        if DownloadSourceFilter.upload in download_types:
            sub.append(
                select(models.upload_download_assc.c.download_id.label("download_id"))
            )

        subquery = None
        if sub:
            subquery = sub[0]
            if len(sub) > 1:
                subquery = subquery.union(*sub[1:])
            subquery = subquery.subquery()

        if subquery is not None:
            stmt = stmt.join(subquery, subquery.c.download_id == models.Download.id)

        if q:
            stmt = stmt.where(
                or_(
                    models.Download.filename.like(f"%{q}%"),
                    models.Download.location.like(f"%{q}%"),
                )
            )

        if tags:
            stmt = stmt.where(tag_name_filter(models.Download.tags, tags))

        if order_by == DownloadOrderOptions.filename:
            order_by_prop = func.lower(models.Download.filename)
        elif order_by == DownloadOrderOptions.location:
            order_by_prop = func.lower(models.Download.location)
        elif order_by == DownloadOrderOptions.size:
            order_by_prop = models.Download.size
        elif order_by == DownloadOrderOptions.created_at:
            order_by_prop = models.Download.created_at
        else:
            order_by_prop = models.Download.updated_at

        if order_direction == OrderDirection.asc:
            stmt = stmt.order_by(order_by_prop.asc())
        else:
            stmt = stmt.order_by(order_by_prop.desc())

        if limit > 0:
            stmt = stmt.limit(limit).offset(offset)

        results = db.execute(stmt).all()

        total = 0 if not results else results[0].total
        results = [x[0] for x in results]

        return results, total

    def create_download_from_text(  # noqa: PLR0913
        self,
        db: Session,
        user: models.User,
        file: str,
        filename: str,
        subdirectory: str | None = None,
        tags: list[str] | None = None,
    ):
        """
        Upload the file to the downloads directory and save a reference to the db.
        If a subdirectory is supplied, it will use that, otherwise it will use the user
        """
        subdirectory = subdirectory or f"user/{user.username}"
        base_dir = empire_config.directories.downloads / "uploads" / subdirectory
        location = self._secure_upload_location(base_dir, filename)
        location.parent.mkdir(parents=True, exist_ok=True)

        filename, location = self._increment_filename(location)

        with location.open("w") as buffer:
            buffer.write(file)

        return self._save_download(db, filename, location, tags)

    def create_download(
        self,
        db: Session,
        user: models.User | None,
        file: UploadFile | Path,
        tags: list[str] | None = None,
    ):
        """
        Upload the file to the downloads directory and save a reference to the db.
        Each string in ``tags`` is attached as a label by that exact name (a label
        is created on miss); the string is used verbatim and is no longer split.

        If ``user`` is None, the file is stored under ``uploads_system/`` for
        system-attributed uploads (e.g. listener autorun tasks).
        """
        filename = file.name if isinstance(file, Path) else file.filename

        if user is not None:
            base_dir = empire_config.directories.downloads / "uploads" / user.username
        else:
            # System-attributed uploads (e.g. listener autorun_tasks) have no user.
            # Kept outside uploads/<username>/ so no real username can collide.
            base_dir = empire_config.directories.downloads / "uploads_system"
        location = self._secure_upload_location(base_dir, filename)
        location.parent.mkdir(parents=True, exist_ok=True)

        filename, location = self._increment_filename(location)

        with location.open("wb") as buffer:
            if isinstance(file, Path):
                with file.open("rb") as f:
                    shutil.copyfileobj(f, buffer)
            else:
                shutil.copyfileobj(file.file, buffer)

        return self._save_download(db, filename, location, tags)

    @staticmethod
    def _secure_upload_location(base_dir: Path, filename: str) -> Path:
        """Resolve a client-supplied filename under base_dir, rejecting traversal.

        Multipart upload filenames are untrusted: Starlette copies the raw
        Content-Disposition value straight into ``UploadFile.filename``. Require
        a bare basename and confirm the result stays inside base_dir so ``..``
        sequences can't escape the downloads directory.

        base_dir is untrusted too: callers compose it from ``user.username``,
        which any enabled operator can set through ``PUT /api/v2/users/{uid}``,
        and from the ``subdirectory`` argument. Anchor it to the downloads root
        before touching the filename, so a traversing directory component can't
        slip past a perfectly safe basename.
        """
        if not is_path_within(base_dir, empire_config.directories.downloads):
            log.warning(
                "Blocked upload to a directory outside downloads: %r", str(base_dir)
            )
            raise HTTPException(status_code=400, detail="Invalid upload location.")

        safe_name = safe_filename(filename)
        location = base_dir / safe_name if safe_name else None
        if location is None or not is_path_within(location, base_dir):
            log.warning(
                "Blocked path traversal attempt in upload filename: %r", filename
            )
            raise HTTPException(status_code=400, detail="Invalid filename.")
        return location

    @staticmethod
    def _increment_filename(location: Path) -> tuple[str, Path]:
        filename_stem = location.stem
        file_extension = location.suffix
        i = 1
        while location.exists():
            temp_name = f"{filename_stem}({i}){file_extension}"
            location = location.parent / temp_name
            i += 1
        filename = location.name

        return filename, location

    def _save_download(
        self, db: Session, filename: str, location: Path, tags: list[str] | None
    ):
        download = models.Download(
            location=str(location), filename=filename, size=location.stat().st_size
        )
        db.add(download)
        db.flush()

        for tag in tags or []:
            self.tag_service.attach_tag(db, download, name=tag)

        db.execute(models.upload_download_assc.insert().values(download_id=download.id))

        return download
