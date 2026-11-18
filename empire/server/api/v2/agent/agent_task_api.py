from datetime import datetime
from pathlib import Path
from typing import Annotated

from fastapi import Depends, HTTPException, Query
from starlette.responses import Response
from starlette.status import HTTP_204_NO_CONTENT

from empire.server.api.api_router import APIRouter
from empire.server.api.jwt_auth import (
    CurrentActiveUser,
    get_current_active_user,
)
from empire.server.api.v2.agent.agent_task_dto import (
    AgentTask,
    AgentTaskOrderOptions,
    AgentTasks,
    ChdirPostRequest,
    DirectoryListPostRequest,
    DownloadPostRequest,
    ExitPostRequest,
    KillDatePostRequest,
    KillJobPostRequest,
    ModulePostRequest,
    ShellPostRequest,
    SleepPostRequest,
    SocksPostRequest,
    StopJobPostRequest,
    SysinfoPostRequest,
    UploadPostRequest,
    WorkingHoursPostRequest,
    domain_to_dto_task,
)
from empire.server.api.v2.shared_dependencies import AppCtx, CurrentSession, paginate
from empire.server.api.v2.shared_dto import (
    BadRequestResponse,
    NotFoundResponse,
    OrderDirection,
)
from empire.server.api.v2.tag import tag_api
from empire.server.core.agent_service import AgentService
from empire.server.core.agent_task_service import AgentTaskService
from empire.server.core.db import models
from empire.server.core.db.models import AgentTaskStatus
from empire.server.core.download_service import DownloadService
from empire.server.core.exceptions import (
    ModuleExecutionException,
    ModuleValidationException,
)
from empire.server.utils.data_util import is_port_in_use


def get_agent_task_service(main: AppCtx) -> AgentTaskService:
    return main.agenttasksv2


AgentTaskServiceDep = Annotated[AgentTaskService, Depends(get_agent_task_service)]


def get_agent_service(main: AppCtx) -> AgentService:
    return main.agentsv2


AgentServiceDep = Annotated[AgentService, Depends(get_agent_service)]


def get_download_service(main: AppCtx) -> DownloadService:
    return main.downloadsv2


DownloadServiceDep = Annotated[DownloadService, Depends(get_download_service)]


router = APIRouter(
    prefix="/api/v2/agents",
    tags=["agents"],
    responses={
        404: {"description": "Not found", "model": NotFoundResponse},
        400: {"description": "Bad request", "model": BadRequestResponse},
    },
    dependencies=[Depends(get_current_active_user)],
)


def get_agent(
    agent_id: str,
    db: CurrentSession,
    agent_service: AgentServiceDep,
):
    agent = agent_service.get_by_id(db, agent_id)

    if agent:
        return agent

    raise HTTPException(404, f"Agent not found for id {agent_id}")


AgentDep = Annotated[models.Agent, Depends(get_agent)]


def get_task(
    uid: int,
    db: CurrentSession,
    db_agent: AgentDep,
    agent_task_service: AgentTaskServiceDep,
):
    task = agent_task_service.get_task_for_agent(db, db_agent.session_id, uid)

    if task:
        return task

    raise HTTPException(
        404, f"Task not found for agent {db_agent.session_id} and task id {uid}"
    )


TaskDep = Annotated[models.AgentTask, Depends(get_task)]


tag_api.add_endpoints_to_taggable(
    router, "/{agent_id}/tasks/{uid}/tags", get_task, "task"
)


@router.get("/tasks", response_model=AgentTasks)
def read_tasks_all_agents(
    db: CurrentSession,
    limit: int = -1,
    page: int = 1,
    include_full_input: bool = False,
    include_original_output: bool = False,
    include_output: bool = True,
    since: datetime | None = None,
    order_by: AgentTaskOrderOptions = AgentTaskOrderOptions.id,
    order_direction: OrderDirection = OrderDirection.desc,
    status: AgentTaskStatus | None = None,
    agents: list[str] | None = Query(None),
    users: list[int] | None = Query(None),
    tags: list[str] | None = Query(None),
    query: str | None = None,
    *,
    agent_task_service: AgentTaskServiceDep,
):
    tasks, total = agent_task_service.get_tasks(
        db,
        agents=agents,
        users=users,
        tags=tags,
        limit=limit,
        offset=(page - 1) * limit,
        include_full_input=include_full_input,
        include_original_output=include_original_output,
        include_output=include_output,
        since=since,
        order_by=order_by,
        order_direction=order_direction,
        status=status,
        q=query,
    )

    tasks_converted = [
        domain_to_dto_task(
            x, include_full_input, include_original_output, include_output
        )
        for x in tasks
    ]

    page, total_pages = paginate(total, page, limit)
    return AgentTasks(
        records=tasks_converted,
        page=page,
        total_pages=total_pages,
        limit=limit,
        total=total,
    )


@router.get("/{agent_id}/tasks", response_model=AgentTasks)
def read_tasks(
    db: CurrentSession,
    db_agent: AgentDep,
    agent_task_service: AgentTaskServiceDep,
    limit: int = -1,
    page: int = 1,
    include_full_input: bool = False,
    include_original_output: bool = False,
    include_output: bool = True,
    since: datetime | None = None,
    order_by: AgentTaskOrderOptions = AgentTaskOrderOptions.id,
    order_direction: OrderDirection = OrderDirection.desc,
    status: AgentTaskStatus | None = None,
    users: list[int] | None = Query(None),
    tags: list[str] | None = Query(None),
    query: str | None = None,
):
    tasks, total = agent_task_service.get_tasks(
        db,
        agents=[db_agent.session_id],
        users=users,
        tags=tags,
        limit=limit,
        offset=(page - 1) * limit,
        include_full_input=include_full_input,
        include_original_output=include_original_output,
        include_output=include_output,
        since=since,
        order_by=order_by,
        order_direction=order_direction,
        status=status,
        q=query,
    )

    tasks_converted = [
        domain_to_dto_task(
            x, include_full_input, include_original_output, include_output
        )
        for x in tasks
    ]

    page, total_pages = paginate(total, page, limit)
    return AgentTasks(
        records=tasks_converted,
        page=page,
        total_pages=total_pages,
        limit=limit,
        total=total,
    )


@router.get("/{agent_id}/tasks/{uid}", response_model=AgentTask)
def read_task(
    uid: int,
    db: CurrentSession,
    db_agent: AgentDep,
    db_task: TaskDep,
):
    if not db_task:
        raise HTTPException(status_code=404, detail="Task not found")

    return domain_to_dto_task(db_task)


@router.post("/{agent_id}/tasks/jobs", response_model=AgentTask)
def create_task_jobs(
    db: CurrentSession,
    current_user: CurrentActiveUser,
    db_agent: AgentDep,
    agent_task_service: AgentTaskServiceDep,
):
    resp, _err = agent_task_service.create_task_jobs(db, db_agent, current_user)

    return domain_to_dto_task(resp)


@router.post("/{agent_id}/tasks/kill_job", response_model=AgentTask)
def create_task_kill_job(
    jobs: KillJobPostRequest,
    db: CurrentSession,
    current_user: CurrentActiveUser,
    db_agent: AgentDep,
    agent_task_service: AgentTaskServiceDep,
):
    kill_job = str(jobs.id)
    resp, _err = agent_task_service.create_task_kill_job(
        db, db_agent, kill_job, current_user
    )

    return domain_to_dto_task(resp)


@router.post("/{agent_id}/tasks/stop_job", response_model=AgentTask)
def create_task_stop_job(
    jobs: StopJobPostRequest,
    db: CurrentSession,
    current_user: CurrentActiveUser,
    db_agent: AgentDep,
    agent_task_service: AgentTaskServiceDep,
):
    stop_job = str(jobs.id)
    resp, _err = agent_task_service.create_task_stop_job(
        db, db_agent, stop_job, current_user
    )

    return domain_to_dto_task(resp)


@router.post("/{agent_id}/tasks/shell", status_code=201, response_model=AgentTask)
def create_task_shell(
    shell_request: ShellPostRequest,
    db: CurrentSession,
    current_user: CurrentActiveUser,
    db_agent: AgentDep,
    agent_task_service: AgentTaskServiceDep,
):
    """
    Executes a command on the agent via the system shell. The `literal` flag is
    accepted in the request body for API backwards compatibility but is ignored:
    agent-side command aliases were removed in 7.0, so every command is run by
    the system shell.
    """
    resp, err = agent_task_service.create_task_shell(
        db, db_agent, shell_request.command, current_user
    )

    if err:
        raise HTTPException(status_code=400, detail=err)

    return domain_to_dto_task(resp)


@router.post("/{agent_id}/tasks/chdir", status_code=201, response_model=AgentTask)
def create_task_chdir(
    chdir_request: ChdirPostRequest,
    db: CurrentSession,
    current_user: CurrentActiveUser,
    db_agent: AgentDep,
    agent_task_service: AgentTaskServiceDep,
):
    """
    Changes the agent's working directory. Subsequent shell tasks run in the new
    directory until another chdir is issued.
    """
    resp, err = agent_task_service.create_task_chdir(
        db, db_agent, chdir_request.path, current_user
    )

    if err:
        raise HTTPException(status_code=400, detail=err)

    return domain_to_dto_task(resp)


@router.post("/{agent_id}/tasks/module", status_code=201, response_model=AgentTask)
def create_task_module(
    module_request: ModulePostRequest,
    db: CurrentSession,
    current_user: CurrentActiveUser,
    db_agent: AgentDep,
    agent_task_service: AgentTaskServiceDep,
):
    try:
        resp, err = agent_task_service.create_task_module(
            db, db_agent, module_request, current_user
        )
    except HTTPException:
        raise
    except ModuleValidationException as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    except ModuleExecutionException as e:
        raise HTTPException(status_code=500, detail=str(e)) from e
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e)) from e

    # This is for backwards compatibility with modules returning
    # tuples for exceptions. All modules should remove returning
    # tuples in favor of raising exceptions by Empire 6.0
    if err:
        raise HTTPException(status_code=400, detail=err)

    return domain_to_dto_task(resp)


@router.post("/{agent_id}/tasks/processes", status_code=201, response_model=AgentTask)
def create_task_processes(
    db: CurrentSession,
    current_user: CurrentActiveUser,
    db_agent: AgentDep,
    agent_task_service: AgentTaskServiceDep,
):
    """
    Enumerate host processes for the agent. The module is chosen server-side from
    the agent's language/OS (C# SharpSploit for Windows agents, the Python module
    for Python agents). Powers Starkiller's Processes-tab refresh.
    """
    try:
        resp, err = agent_task_service.create_task_processes(db, db_agent, current_user)
    except HTTPException:
        raise
    except ModuleValidationException as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    except ModuleExecutionException as e:
        raise HTTPException(status_code=500, detail=str(e)) from e
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e)) from e

    if err:
        raise HTTPException(status_code=400, detail=err)

    return domain_to_dto_task(resp)


@router.post("/{agent_id}/tasks/upload", status_code=201, response_model=AgentTask)
def create_task_upload(
    upload_request: UploadPostRequest,
    db: CurrentSession,
    current_user: CurrentActiveUser,
    db_agent: AgentDep,
    download_service: DownloadServiceDep,
    agent_task_service: AgentTaskServiceDep,
):
    download = download_service.get_by_id(db, upload_request.file_id)

    if not download:
        raise HTTPException(
            status_code=400,
            detail=f"Download not found for id {upload_request.file_id}",
        )

    try:
        file_size = Path(download.location).stat().st_size
    except FileNotFoundError as e:
        raise HTTPException(
            status_code=404,
            detail=f"File for download id {upload_request.file_id} not found on disk",
        ) from e
    except OSError as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to read file for download id {upload_request.file_id}: {e}",
        ) from e

    chunk_size = 524288  # 512KB

    if file_size <= chunk_size:
        file_data = download.get_base64_file()
        resp, err = agent_task_service.create_task_upload(
            db, db_agent, file_data, upload_request.path_to_file, current_user
        )
    else:
        resp, err = agent_task_service.create_task_upload_chunked(
            db,
            db_agent,
            download.location,
            file_size,
            upload_request.path_to_file,
            current_user,
            chunk_size=chunk_size,
        )

    if err:
        raise HTTPException(status_code=400, detail=err)

    return domain_to_dto_task(resp)


@router.post("/{agent_id}/tasks/download", status_code=201, response_model=AgentTask)
def create_task_download(
    download_request: DownloadPostRequest,
    db: CurrentSession,
    current_user: CurrentActiveUser,
    db_agent: AgentDep,
    agent_task_service: AgentTaskServiceDep,
):
    resp, err = agent_task_service.create_task_download(
        db, db_agent, download_request.path_to_file, current_user
    )

    if err:
        raise HTTPException(status_code=400, detail=err)

    return domain_to_dto_task(resp)


@router.post("/{agent_id}/tasks/sysinfo", status_code=201, response_model=AgentTask)
def create_task_sysinfo(
    sysinfo_request: SysinfoPostRequest,
    db: CurrentSession,
    current_user: CurrentActiveUser,
    db_agent: AgentDep,
    agent_task_service: AgentTaskServiceDep,
):
    resp, err = agent_task_service.create_task_sysinfo(db, db_agent, current_user)

    if err:
        raise HTTPException(status_code=400, detail=err)

    return domain_to_dto_task(resp)


@router.post("/{agent_id}/tasks/sleep", status_code=201, response_model=AgentTask)
def create_task_update_sleep(
    sleep_request: SleepPostRequest,
    db: CurrentSession,
    current_user: CurrentActiveUser,
    db_agent: AgentDep,
    agent_task_service: AgentTaskServiceDep,
):
    resp, err = agent_task_service.create_task_update_sleep(
        db, db_agent, sleep_request.delay, sleep_request.jitter, current_user
    )

    if err:
        raise HTTPException(status_code=400, detail=err)

    return domain_to_dto_task(resp)


@router.post("/{agent_id}/tasks/kill_date", status_code=201, response_model=AgentTask)
def create_task_update_kill_date(
    kill_date_request: KillDatePostRequest,
    db: CurrentSession,
    current_user: CurrentActiveUser,
    db_agent: AgentDep,
    agent_task_service: AgentTaskServiceDep,
):
    resp, err = agent_task_service.create_task_update_kill_date(
        db, db_agent, kill_date_request.kill_date, current_user
    )

    if err:
        raise HTTPException(status_code=400, detail=err)

    return domain_to_dto_task(resp)


@router.post(
    "/{agent_id}/tasks/working_hours", status_code=201, response_model=AgentTask
)
def create_task_update_working_hours(
    working_hours_request: WorkingHoursPostRequest,
    db: CurrentSession,
    current_user: CurrentActiveUser,
    db_agent: AgentDep,
    agent_task_service: AgentTaskServiceDep,
):
    resp, err = agent_task_service.create_task_update_working_hours(
        db, db_agent, working_hours_request.working_hours, current_user
    )

    if err:
        raise HTTPException(status_code=400, detail=err)

    return domain_to_dto_task(resp)


@router.post(
    "/{agent_id}/tasks/directory_list", status_code=201, response_model=AgentTask
)
def create_task_update_directory_list(
    directory_list_request: DirectoryListPostRequest,
    db: CurrentSession,
    current_user: CurrentActiveUser,
    db_agent: AgentDep,
    agent_task_service: AgentTaskServiceDep,
):
    resp, err = agent_task_service.create_task_directory_list(
        db, db_agent, directory_list_request.path, current_user
    )

    if err:
        raise HTTPException(status_code=400, detail=err)

    return domain_to_dto_task(resp)


@router.post("/{agent_id}/tasks/exit", status_code=201, response_model=AgentTask)
def create_task_exit(
    exit_request: ExitPostRequest,
    db: CurrentSession,
    current_user: CurrentActiveUser,
    db_agent: AgentDep,
    agent_task_service: AgentTaskServiceDep,
):
    resp, err = agent_task_service.create_task_exit(db, db_agent, current_user)

    if err:
        raise HTTPException(status_code=400, detail=err)

    return domain_to_dto_task(resp)


@router.delete(
    "/{agent_id}/tasks/{uid}", status_code=HTTP_204_NO_CONTENT, response_class=Response
)
def delete_task(
    uid: int,
    db: CurrentSession,
    db_task: TaskDep,
    agent_task_service: AgentTaskServiceDep,
):
    if db_task.status != AgentTaskStatus.queued:
        raise HTTPException(
            status_code=400, detail="Task must be in a queued state to be deleted"
        )

    agent_task_service.delete_task(db, db_task)


@router.post("/{agent_id}/tasks/socks", status_code=201, response_model=AgentTask)
def create_task_socks(
    socks: SocksPostRequest,
    db: CurrentSession,
    current_user: CurrentActiveUser,
    db_agent: AgentDep,
    agent_task_service: AgentTaskServiceDep,
):
    if is_port_in_use(socks.port):
        raise HTTPException(status_code=400, detail="Socks port is in use")

    resp, err = agent_task_service.create_task_socks(
        db, db_agent, socks.port, current_user
    )
    if err:
        raise HTTPException(status_code=400, detail=err)

    return domain_to_dto_task(resp)
