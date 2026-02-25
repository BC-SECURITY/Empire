import base64
import json
import logging
import threading
import typing
from collections import defaultdict
from datetime import datetime
from pathlib import Path

from pydantic import BaseModel
from sqlalchemy import and_, func, or_
from sqlalchemy.orm import Session, joinedload, undefer

from empire.server.api.v2.agent.agent_task_dto import (
    AgentTaskOrderOptions,
    ModulePostRequest,
)
from empire.server.api.v2.shared_dto import OrderDirection
from empire.server.core.config.config_manager import empire_config
from empire.server.core.db import models
from empire.server.core.db.models import AgentTaskStatus
from empire.server.core.hooks import hooks

if typing.TYPE_CHECKING:
    from empire.server.common.empire import MainMenu

log = logging.getLogger(__name__)


class AgentTaskService:
    def __init__(self, main_menu: "MainMenu"):
        self.main_menu = main_menu

        self.module_service = main_menu.modulesv2
        self.listener_service = main_menu.listenersv2
        self.agent_socks_service = main_menu.agentsocksv2
        self.agent_service = main_menu.agentsv2
        self.download_service = main_menu.downloadsv2

        # { agent_id: [TemporaryTask] }
        self.temporary_tasks = defaultdict(list)

        self.last_task_lock = threading.Lock()

    @staticmethod
    def get_tasks(  # noqa: PLR0913 PLR0912
        db: Session,
        agents: list[str] | None = None,
        users: list[int] | None = None,
        tags: list[str] | None = None,
        limit: int = -1,
        offset: int = 0,
        include_full_input: bool = False,
        include_original_output: bool = False,
        include_output: bool = True,
        since: datetime | None = None,
        order_by: AgentTaskOrderOptions = AgentTaskOrderOptions.id,
        order_direction: OrderDirection = OrderDirection.desc,
        status: AgentTaskStatus | None = None,
        q: str | None = None,
    ):
        query = db.query(
            models.AgentTask, func.count(models.AgentTask.id).over().label("total")
        )

        if agents:
            query = query.filter(models.AgentTask.agent_id.in_(agents))

        if users:
            user_filters = [models.AgentTask.user_id.in_(users)]
            if 0 in users:
                user_filters.append(models.AgentTask.user_id.is_(None))
            query = query.filter(or_(*user_filters))

        if tags:
            tags_split = [tag.split(":", 1) for tag in tags]
            query = query.join(models.AgentTask.tags).filter(
                and_(
                    models.Tag.name.in_([tag[0] for tag in tags_split]),
                    models.Tag.value.in_([tag[1] for tag in tags_split]),
                )
            )

        query_options = [
            joinedload(models.AgentTask.user),
            joinedload(models.AgentTask.agent).joinedload(models.Agent.host),
        ]
        if include_full_input:
            query_options.append(undefer(models.AgentTask.input_full))
        if include_original_output:
            query_options.append(undefer(models.AgentTask.output_original))
        if include_output:
            query_options.append(undefer(models.AgentTask.output))
        query = query.options(*query_options)

        if since:
            query = query.filter(models.AgentTask.updated_at > since)

        if status:
            query = query.filter(models.AgentTask.status == status)

        if q:
            query = query.filter(
                or_(
                    models.AgentTask.input.like(f"%{q}%"),
                    models.AgentTask.output.like(f"%{q}%"),
                )
            )

        if order_by == AgentTaskOrderOptions.status:
            order_by_prop = models.AgentTask.status
        elif order_by == AgentTaskOrderOptions.updated_at:
            order_by_prop = models.AgentTask.updated_at
        elif order_by == AgentTaskOrderOptions.agent:
            order_by_prop = models.AgentTask.agent_id
        else:
            order_by_prop = models.AgentTask.id

        if order_direction == OrderDirection.asc:
            query = query.order_by(order_by_prop.asc())
        else:
            query = query.order_by(order_by_prop.desc())

        if limit > 0:
            query = query.limit(limit).offset(offset)

        results = query.all()

        total = 0 if len(results) == 0 else results[0].total
        results = [x[0] for x in results]

        return results, total

    @staticmethod
    def get_task_for_agent(db: Session, agent_id: str, uid: int):
        return (
            db.query(models.AgentTask)
            .filter(
                and_(models.AgentTask.agent_id == agent_id, models.AgentTask.id == uid)
            )
            .first()
        )

    def get_temporary_tasks_for_agent(self, agent_id: str, clear: bool = True):
        tasks = self.temporary_tasks[agent_id]

        if clear:
            self.temporary_tasks[agent_id] = []

        return tasks

    def create_task_shell(
        self,
        db: Session,
        agent: models.Agent,
        command: str,
        literal: bool = False,
        user: models.User | None = None,
    ):
        if literal and not command.startswith("shell"):
            command = f"shell {command}"
        return self.add_task(db, agent, "TASK_SHELL", command, user=user)

    def create_task_upload(
        self,
        db: Session,
        agent: models.Agent,
        file_data: str,
        directory: str,
        user: models.User | None = None,
    ):
        data = f"{directory}|{file_data}"
        return self.add_task(db, agent, "TASK_UPLOAD", data, user=user)

    def create_task_download(
        self,
        db: Session,
        agent: models.Agent,
        path_to_file: str,
        user: models.User | None = None,
    ):
        return self.add_task(db, agent, "TASK_DOWNLOAD", path_to_file, user=user)

    def create_task_sysinfo(
        self, db: Session, agent: models.Agent, user: models.User | None = None
    ):
        return self.add_task(db, agent, "TASK_SYSINFO", user=user)

    def create_task_jobs(
        self, db: Session, agent: models.Agent, user: models.User | None = None
    ):
        return self.add_task(db, agent, "TASK_GETJOBS", user=user)

    def create_task_kill_job(
        self,
        db: Session,
        agent: models.Agent,
        job_id: str,
        user: models.User | None = None,
    ):
        return self.add_task(db, agent, "TASK_STOPJOB", job_id, user=user)

    def create_task_stop_job(
        self,
        db: Session,
        agent: models.Agent,
        job_id: str,
        user: models.User | None = None,
    ):
        return self.create_task_kill_job(db, agent, job_id, user=user)

    def create_task_exit(
        self, db: Session, agent: models.Agent, user: models.User | None = None
    ):
        resp, err = self.add_task(db, agent, "TASK_EXIT", user=user)
        agent.archived = True

        self.agent_socks_service.close_socks_client(agent)

        return resp, err

    def create_task_socks(
        self,
        db: Session,
        agent: models.Agent,
        socks_port,
        user: models.User | None = None,
    ):
        agent.socks = True
        agent.socks_port = socks_port
        resp, err = self.add_task(db, agent, "TASK_SOCKS", user=user)
        return resp, err

    def create_task_socks_data(self, agent_id: str, data: str):
        return self.add_temporary_task(agent_id, "TASK_SOCKS_DATA", data)

    def create_task_smb(
        self,
        db: Session,
        agent: models.Agent,
        pipe_name,
        user: models.User | None = None,
    ):
        resp, err = self.add_task(db, agent, "TASK_SMB_SERVER", pipe_name, user=user)
        return resp, err

    def create_task_update_comms(
        self,
        db: Session,
        agent: models.Agent,
        new_listener_id: int,
        user: models.User | None = None,
    ):
        listener = self.listener_service.get_by_id(db, new_listener_id)

        if not listener:
            return None, f"Listener not found for id {new_listener_id}"
        if listener.module in ["meterpreter", "http_mapi"]:
            return (
                None,
                f"Listener template {listener.module} not eligible for updating comms",
            )

        new_comms = self.listener_service.get_active_listeners()[
            listener.id
        ].generate_comms(listener.options, agent.language)

        self.add_task(db, agent, "TASK_UPDATE_LISTENERNAME", listener.name, user=user)
        return self.add_task(db, agent, "TASK_SWITCH_LISTENER", new_comms, user=user)

    def create_task_update_sleep(
        self,
        db: Session,
        agent: models.Agent,
        delay: int,
        jitter: float,
        user: models.User | None = None,
    ):
        agent.delay = delay
        agent.jitter = jitter
        if agent.language == "powershell":
            return self.add_task(
                db,
                agent,
                "TASK_SHELL",
                f"Set-Delay {delay!s} {jitter!s}",
                user=user,
            )
        if agent.language in ["python", "ironpython"]:
            return self.add_task(
                db,
                agent,
                "TASK_PYTHON_CMD_WAIT",
                f"global agent; agent.delay={delay}; agent.jitter={jitter}; print('delay/jitter set to {delay}/{jitter}')",
                user=user,
            )
        if agent.language == "csharp":
            return self.add_task(
                db,
                agent,
                "TASK_SHELL",
                f"Set-Delay {delay!s} {jitter!s}",
                user=user,
            )

        return None, "Unsupported language."

    def create_task_update_kill_date(
        self,
        db: Session,
        agent: models.Agent,
        kill_date: str,
        user: models.User | None = None,
    ):
        # todo handle different languages
        agent.kill_date = kill_date
        return self.add_task(
            db, agent, "TASK_SHELL", f"Set-KillDate {kill_date}", user=user
        )

    def create_task_update_working_hours(
        self,
        db: Session,
        agent: models.Agent,
        working_hours: str,
        user: models.User | None = None,
    ):
        # todo handle different languages.
        agent.working_hours = working_hours
        return self.add_task(
            db,
            agent,
            "TASK_SHELL",
            f"Set-WorkingHours {working_hours}",
            user=user,
        )

    def create_task_module(
        self,
        db: Session,
        agent: models.Agent,
        module_req: ModulePostRequest,
        user: models.User | None = None,
    ):
        module_req.options["Agent"] = agent.session_id
        resp, err = self.module_service.execute_module(
            db,
            agent,
            module_req.module_id,
            module_req.options,
            module_req.ignore_language_version_check,
            module_req.ignore_admin_check,
            modified_input=module_req.modified_input,
        )

        if err:
            return None, err

        return self.add_task(
            db,
            agent,
            task_name=resp.command,
            task_input=resp.data,
            module_name=module_req.module_id,
            module_options=module_req.options,
            user=user,
            files=resp.files,
        )

    def create_task_directory_list(
        self,
        db: Session,
        agent: models.Agent,
        path: str,
        user: models.User | None = None,
    ):
        return self.add_task(db, agent, "TASK_DIR_LIST", path, user=user)

    class TemporaryTask(BaseModel):
        """
        Fields should match the Task db model, so that we can use the same
        functions to retrieve tasks.
        """

        id: int = 0  # We don't need an ID for these, but it is used in agents.py:1206, so we just initialize it to 0
        agent_id: str
        task_name: str
        input_full: str
        module_name: str | None = None
        module_options: dict | None = None

    def add_temporary_task(
        self,
        agent_id: str,
        task_name,
        task_input="",
        module_name: str | None = None,
        module_options: dict | None = None,
    ) -> tuple[TemporaryTask | None, str | None]:
        """
        Add a temporary task for the agent to execute. These tasks are not saved in the database,
        since they don't provide any value to end users and can be very write-heavy.
        """
        task = self.TemporaryTask(
            agent_id=agent_id,
            task_name=task_name,
            input_full=task_input,
            module_name=module_name,
            module_options=module_options,
        )
        self.temporary_tasks[agent_id].append(task)

        return task, None

    def add_task(  # noqa: PLR0913
        self,
        db: Session,
        agent: models.Agent,
        task_name,
        task_input="",
        module_name: str | None = None,
        module_options: dict | None = None,
        user: models.User | None = None,
        files: list[Path] | None = None,
    ) -> tuple[models.AgentTask | None, str | None]:
        """
        Task an agent. Adapted from agents.py
        """
        files = files or []
        if agent.archived:
            return None, f"[!] Agent {agent.session_id} is archived."

        message = f"Tasked {agent.session_id} to run {task_name}"
        log.info(message)
        self.agent_service.save_agent_log(agent.session_id, message)

        pk = (
            db.query(func.max(models.AgentTask.id))
            .filter(models.AgentTask.agent_id == agent.session_id)
            .first()[0]
        )

        if pk is None:
            pk = 0
        pk = (pk + 1) % 65536

        if task_name in ["TASK_CSHARP_CMD_JOB", "TASK_CSHARP_CMD_WAIT"]:
            compiled_path, arguments = task_input.split("|")
            arguments = arguments.lstrip(",").strip()

            if module_name.startswith("bof_"):
                decoded_arguments = base64.b64decode(arguments).decode("UTF-8")
                data_dict = json.loads(decoded_arguments)
                base64_data = data_dict.get("base64_bof_data", "")
                truncated_base64_data = (
                    base64_data[:15] + "..."
                    if len(base64_data) > 10  # noqa: PLR2004
                    else base64_data
                )
                data_dict["base64_bof_data"] = truncated_base64_data
                short_task_input = f"{module_name} {json.dumps(data_dict)}"

            else:
                filename = compiled_path.rsplit("/", 1)[-1].split(".")[0].split("_")[0]
                short_task_input = f"{filename} " + base64.b64decode(
                    arguments.encode("UTF-8")
                ).decode("UTF-8")

            task = models.AgentTask(
                id=pk,
                agent_id=agent.session_id,
                input=short_task_input[:150],
                input_full=task_input,
                user_id=user.id if user else None,
                module_name=module_name,
                module_options=module_options,
                task_name=task_name,
                status=AgentTaskStatus.queued,
            )
        else:
            task = models.AgentTask(
                id=pk,
                agent_id=agent.session_id,
                input=task_input[:100],
                input_full=task_input,
                user_id=user.id if user else None,
                module_name=module_name,
                module_options=module_options,
                task_name=task_name,
                status=AgentTaskStatus.queued,
            )
        db.add(task)
        db.flush()

        for path in files:
            task.downloads.append(
                self.download_service.create_download(
                    db, user, path, tags=["task:input"]
                )
            )
        db.flush()

        last_task_config = empire_config.debug.last_task
        if last_task_config.enabled:
            with self.last_task_lock:
                location = Path(last_task_config.file)
                location.parent.mkdir(parents=True, exist_ok=True)
                location.write_text(task_input)

        hooks.run_hooks(hooks.AFTER_TASKING_HOOK, db, task)

        message = f"Agent {agent.session_id} tasked with task ID {pk}"
        log.info(message)

        return task, None

    @staticmethod
    def delete_task(db: Session, task: models.AgentTask):
        db.delete(task)
