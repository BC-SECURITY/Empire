import logging
import typing
from datetime import datetime

from sqlalchemy import and_, func, or_
from sqlalchemy.orm import Session, joinedload, undefer

from empire.server.api.v2.plugin.plugin_task_dto import PluginTaskOrderOptions
from empire.server.api.v2.shared_dto import OrderDirection
from empire.server.core.db import models
from empire.server.core.db.base import SessionLocal
from empire.server.core.db.models import AgentTaskStatus

if typing.TYPE_CHECKING:
    from empire.server.common.empire import MainMenu

log = logging.getLogger(__name__)


class PluginTaskService:
    def __init__(self, main_menu: "MainMenu"):
        self.main_menu = main_menu
        self.plugin_service = main_menu.pluginsv2

    @staticmethod
    def get_tasks(  # noqa: PLR0913 PLR0912
        db: Session,
        plugins: list[str] | None = None,
        users: list[int] | None = None,
        tags: list[str] | None = None,
        limit: int = -1,
        offset: int = 0,
        include_full_input: bool = False,
        include_output: bool = True,
        since: datetime | None = None,
        order_by: PluginTaskOrderOptions = PluginTaskOrderOptions.id,
        order_direction: OrderDirection = OrderDirection.desc,
        status: AgentTaskStatus | None = None,
        q: str | None = None,
    ):
        query = db.query(
            models.PluginTask, func.count(models.PluginTask.id).over().label("total")
        )

        if plugins:
            query = query.filter(models.PluginTask.plugin_id.in_(plugins))

        if users:
            user_filters = [models.PluginTask.user_id.in_(users)]
            if 0 in users:
                user_filters.append(models.PluginTask.user_id.is_(None))
            query = query.filter(or_(*user_filters))

        if tags:
            tags_split = [tag.split(":", 1) for tag in tags]
            query = query.join(models.PluginTask.tags).filter(
                and_(
                    models.Tag.name.in_([tag[0] for tag in tags_split]),
                    models.Tag.value.in_([tag[1] for tag in tags_split]),
                )
            )

        query_options = [
            joinedload(models.PluginTask.user),
        ]

        if include_full_input:
            query_options.append(undefer(models.PluginTask.input_full))
        if include_output:
            query_options.append(undefer(models.PluginTask.output))
        query = query.options(*query_options)

        if since:
            query = query.filter(models.PluginTask.updated_at > since)

        if status:
            query = query.filter(models.AgentTask.status == status)

        if q:
            query = query.filter(
                or_(
                    models.PluginTask.input.like(f"%{q}%"),
                    models.PluginTask.output.like(f"%{q}%"),
                )
            )

        if order_by == PluginTaskOrderOptions.status:
            order_by_prop = models.PluginTask.status
        elif order_by == PluginTaskOrderOptions.updated_at:
            order_by_prop = models.PluginTask.updated_at
        elif order_by == PluginTaskOrderOptions.plugin:
            order_by_prop = models.PluginTask.plugin_id
        else:
            order_by_prop = models.PluginTask.id

        if order_direction == OrderDirection.asc:
            query = query.order_by(order_by_prop.asc())
        else:
            query = query.order_by(order_by_prop.desc())

        if limit > 0:
            query = query.limit(limit).offset(offset)

        results = query.all()

        total = 0 if not results else results[0].total
        results = [x[0] for x in results]

        return results, total

    def get_task(self, db: SessionLocal, plugin_id: str, task_id: int):
        # TODO: Check all the uses of get_by_id
        plugin = self.plugin_service.get_by_id(db, plugin_id)
        if plugin:
            task = (
                db.query(models.PluginTask)
                .filter(models.PluginTask.id == task_id)
                .first()
            )
            if task:
                return task

        return None
