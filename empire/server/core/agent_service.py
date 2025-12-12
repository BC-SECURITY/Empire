import logging
import threading
import typing
from datetime import UTC, datetime

from sqlalchemy import and_, func
from sqlalchemy.orm import Session

from empire.server.api.v2.agent.agent_dto import AggregateBucket
from empire.server.api.v2.shared_dto import OrderDirection
from empire.server.common import helpers
from empire.server.common.encryption import AESCipher
from empire.server.core.config.config_manager import empire_config
from empire.server.core.db import models
from empire.server.utils import datetime_util

if typing.TYPE_CHECKING:
    from empire.server.common.empire import MainMenu

log = logging.getLogger(__name__)


class AgentService:
    def __init__(self, main_menu: "MainMenu"):
        self.main_menu = main_menu

        # Since each agent logs to a different file,
        # we can have multiple locks to reduce waiting time when writing to the file.
        self._agent_log_locks: dict[str, threading.Lock] = {}

    @staticmethod
    def get_for_listener(db: Session, listener_name: str):
        return (
            db.query(models.Agent)
            .filter(
                and_(
                    models.Agent.listener == listener_name,
                    models.Agent.archived == False,  # noqa: E712
                )
            )
            .all()
        )

    @staticmethod
    def get_all(
        db: Session, include_archived: bool = False, include_stale: bool = True
    ):
        query = db.query(models.Agent).filter(
            models.Agent.host_id != ""
        )  # don't return agents that haven't fully checked in.

        if not include_archived:
            query = query.filter(models.Agent.archived == False)  # noqa: E712

        if not include_stale:
            query = query.filter(models.Agent.stale == False)  # noqa: E712

        return query.all()

    @staticmethod
    def get_by_id(db: Session, uid: str):
        return db.query(models.Agent).filter(models.Agent.session_id == uid).first()

    @staticmethod
    def get_by_name(db: Session, name: str):
        return db.query(models.Agent).filter(models.Agent.name == name).first()

    def create_agent(  # noqa: PLR0913
        self,
        db: Session,
        session_id,
        external_ip,
        delay,
        jitter,
        profile,
        kill_date,
        working_hours,
        lost_limit,
        session_key=None,
        nonce="",
        listener="",
        language="",
    ):
        """
        Add an agent to the internal cache and database.
        """
        if not session_key:
            session_key = AESCipher.generate_key()

        if not profile or profile == "":
            profile = "/admin/get.php,/news.php,/login/process.php|Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko"

        agent = models.Agent(
            name=session_id,
            session_id=session_id,
            delay=delay,
            jitter=jitter,
            external_ip=external_ip,
            session_key=session_key,
            nonce=nonce,
            profile=profile,
            kill_date=kill_date,
            working_hours=working_hours,
            lost_limit=lost_limit,
            listener=listener,
            language=language.lower(),
            archived=False,
        )

        db.add(agent)
        self.update_agent_lastseen(db, session_id)
        db.flush()

        message = f"New agent {session_id} checked in"
        log.info(message)

        return agent

    def update_agent(self, db: Session, db_agent: models.Agent, agent_req):
        if agent_req.name != db_agent.name:
            if not self.get_by_name(db, agent_req.name):
                db_agent.name = agent_req.name
            else:
                return None, f"Agent with name {agent_req.name} already exists."

        db_agent.notes = agent_req.notes

        return db_agent, None

    @staticmethod
    def update_agent_lastseen(db: Session, session_id: str):
        """
        Update the agent's last seen timestamp in the database.

        This checks to see if a timestamp already exists for the agent and ignores
        it if it does. It is not super efficient to check the database on every checkin.
        A better alternative would be to find a way to configure sqlalchemy to ignore
        duplicate inserts or do upserts.
        """
        checkin_time = datetime_util.getutcnow().replace(microsecond=0)
        exists = (
            db.query(models.AgentCheckIn)
            .filter(
                and_(
                    models.AgentCheckIn.agent_id == session_id,
                    models.AgentCheckIn.checkin_time == checkin_time,
                )
            )
            .first()
        )
        if not exists:
            db.add(models.AgentCheckIn(agent_id=session_id, checkin_time=checkin_time))

    @staticmethod
    def get_agent_checkins(  # noqa: PLR0913
        db: Session,
        agents: list[str] | None = None,
        limit: int = -1,
        offset: int = 0,
        start_date: datetime | None = None,
        end_date: datetime | None = None,
        order_direction: OrderDirection = OrderDirection.desc,
    ):
        query = db.query(
            models.AgentCheckIn,
            func.count(models.AgentCheckIn.checkin_time).over().label("total"),
        )

        if agents:
            query = query.filter(models.AgentCheckIn.agent_id.in_(agents))

        if start_date:
            query = query.filter(models.AgentCheckIn.checkin_time >= start_date)

        if end_date:
            query = query.filter(models.AgentCheckIn.checkin_time <= end_date)

        if order_direction == OrderDirection.asc:
            query = query.order_by(models.AgentCheckIn.checkin_time.asc())
        else:
            query = query.order_by(models.AgentCheckIn.checkin_time.desc())

        if limit > 0:
            query = query.limit(limit).offset(offset)

        results = query.all()

        total = 0 if len(results) == 0 else results[0].total
        results = [x[0] for x in results]

        return results, total

    @staticmethod
    def get_agent_checkins_aggregate(
        db: Session,
        agents: list[str] | None = None,
        start_date: datetime | None = None,
        end_date: datetime | None = None,
        bucket_size: AggregateBucket = None,
    ):
        """
        Returns a list of checkin counts for the given agents, start_date, end_date, and bucket_size.
        This will raise a database exception if the empire server is using SQLite.
        Additional work could be done to build a query for SQLite, but I don't think it's worth the effort,
        given that we are moving towards a more robust database.
        """
        hour_format = {"sql": "%Y-%m-%d %H:00:00Z", "python": "%Y-%m-%d %H:00:00Z"}
        minute_format = {"sql": "%Y-%m-%d %H:%i:00Z", "python": "%Y-%m-%d %H:%M:00Z"}
        second_format = {"sql": "%Y-%m-%d %H:%i:%sZ", "python": "%Y-%m-%d %H:%M:%SZ"}
        day_format = {"sql": "%Y-%m-%d", "python": "%Y-%m-%d"}
        if bucket_size == AggregateBucket.hour:
            format = hour_format
        elif bucket_size == AggregateBucket.minute:
            format = minute_format
        elif bucket_size == AggregateBucket.second:
            format = second_format
        else:
            format = day_format

        time_agg = func.date_format(models.AgentCheckIn.checkin_time, format["sql"])

        query = db.query(
            time_agg.label("time_agg"),
            func.count(models.AgentCheckIn.checkin_time).label("count"),
        )

        if agents:
            query = query.filter(models.AgentCheckIn.agent_id.in_(agents))

        if start_date:
            query = query.filter(models.AgentCheckIn.checkin_time >= start_date)

        if end_date:
            query = query.filter(models.AgentCheckIn.checkin_time <= end_date)

        query = query.group_by("time_agg")

        results = query.all()
        converted_results = []

        for result in results:
            converted_results.append(
                {
                    "checkin_time": datetime.strptime(
                        result[0], format["python"]
                    ).replace(tzinfo=UTC),
                    "count": result[1],
                }
            )

        return converted_results

    def save_agent_log(self, session_id, data):
        """
        Save the agent console output to the agent's log file.
        """
        if isinstance(data, bytes):
            try:
                data = data.decode("UTF-8")
            except UnicodeDecodeError:
                data = data.decode("latin-1")

        save_path = empire_config.directories.downloads / session_id

        if not save_path.exists():
            save_path.mkdir(parents=True, exist_ok=True)

        current_time = helpers.get_datetime()

        if session_id not in self._agent_log_locks:
            self._agent_log_locks[session_id] = threading.Lock()
        lock = self._agent_log_locks[session_id]

        with lock, (save_path / "agent.log").open("a") as f:
            f.write("\n" + current_time + " : " + "\n")
            f.write(data + "\n")
