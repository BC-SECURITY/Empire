import json
import logging
from json.decoder import JSONDecodeError

import jq
from terminaltables3 import AsciiTable
from sqlalchemy import and_
from sqlalchemy.orm import Session

from empire.server.core.db import models
from empire.server.core.hooks import hooks

log = logging.getLogger(__name__)


def ps_hook(db: Session, task: models.AgentTask):
    """
    This hook watches for the 'ps' command and writes the processes into the processes table.

    For Powershell Agents, the data comes back (as of 4.1) as JSON.
    For Python Agents, the data comes back in the typical 'ls' format.
    For C# Agents, no support yet.

    AFAIK, it is not easy to convert the shell tables into JSON, but I found this jq wizardry
    on StackOverflow, so that's what we'll stick with for now for the python results, even though it is imperfect.
    https://unix.stackexchange.com/a/243485
    """
    if task.input.strip() not in ["ps", "tasklist"] or task.agent.language == "csharp":
        return

    if task.agent.language == "python":
        output = (
            jq.compile(
                """[sub("\n$";"") | splits("\n") | sub("^ +";"") | [splits(" +")]] | .[0] as $header | .[1:] | [.[] | [. as $x | range($header | length) | {"key": $header[.], "value": $x[.]}] | from_entries]"""
            )
            .input(task.output.split("\r\n ..Command execution completed.")[0])
            .first()
        )
    else:
        try:
            output = json.loads(task.output)
        except JSONDecodeError:
            log.warning(
                "Failed to decode JSON output from ps command. Most likely, the command returned an error."
            )
            return

    existing_processes = (
        db.query(models.HostProcess.process_id)
        .filter(models.HostProcess.host_id == task.agent.host_id)
        .all()
    )
    existing_processes = [p[0] for p in existing_processes]

    for process in output:
        process_name = process.get("CMD") or process.get("ProcessName") or ""
        process_id = process.get("PID")
        arch = process.get("Arch")
        user = process.get("UserName")
        if process_id:
            # new process
            if int(process_id) not in existing_processes:
                db.add(
                    models.HostProcess(
                        host_id=task.agent.host_id,
                        process_id=process_id,
                        process_name=process_name,
                        architecture=arch,
                        user=user,
                    )
                )
            # update existing process
            elif int(process_id) in existing_processes:
                db_process: models.HostProcess = (
                    db.query(models.HostProcess)
                    .filter(
                        and_(
                            models.HostProcess.host_id == task.agent.host_id,
                            models.HostProcess.process_id == process_id,
                        )
                    )
                    .first()
                )
                if not db_process.agent:
                    db_process.architecture = arch
                    db_process.process_name = process_name
                    db_process.user = user

    for process in existing_processes:
        # mark processes that are no longer running stale
        if process not in [int(p.get("PID")) for p in output]:
            db_process: models.HostProcess | None = (
                db.query(models.HostProcess)
                .filter(
                    and_(
                        models.HostProcess.host_id == task.agent.host_id,
                        models.HostProcess.process_id == process,
                    )
                )
                .first()
            )
            db_process.stale = True


def ps_filter(db: Session, task: models.AgentTask):
    """
    This filter converts the JSON results of the ps command and converts it to a PowerShell-ish table.

    if the results are from the Python or C# agents, it does nothing.
    """
    if task.input.strip() not in [
        "ps",
        "tasklist",
    ] or task.agent.language not in ["powershell", "ironpython"]:
        return db, task

    try:
        output = json.loads(task.output)
    except JSONDecodeError:
        log.warning(
            "Failed to decode JSON output from ps command. Most likely, the command returned an error."
        )
        return db, task

    output_list = []
    for rec in output:
        output_list.append(
            [
                rec.get("PID"),
                rec.get("ProcessName"),
                rec.get("Arch"),
                rec.get("UserName"),
                rec.get("MemUsage"),
            ]
        )

    output_list.insert(0, ["PID", "ProcessName", "Arch", "UserName", "MemUsage"])

    table = AsciiTable(output_list)
    table.inner_row_border = False
    table.outer_border = False
    table.inner_column_border = False
    task.output = table.table

    return db, task


def ls_filter(db: Session, task: models.AgentTask):
    """
    This filter converts the JSON results of the ls command and converts it to a PowerShell-ish table.

    if the results are from the Python or C# agents, it does nothing.
    """
    task_input = task.input.strip().split()
    if (
        len(task_input) == 0
        or task_input[0] not in ["ls", "dir"]
        or task.agent.language != "powershell"
    ):
        return db, task

    try:
        output = json.loads(task.output)
    except JSONDecodeError:
        log.warning(
            "Failed to decode JSON output from ls command. Most likely, the command returned an error."
        )
        return db, task

    output_list = []
    for rec in output:
        output_list.append(
            [
                rec.get("Mode"),
                rec.get("Owner"),
                rec.get("LastWriteTime"),
                rec.get("Length"),
                rec.get("Name"),
            ]
        )

    output_list.insert(0, ["Mode", "Owner", "LastWriteTime", "Length", "Name"])

    table = AsciiTable(output_list)
    table.inner_row_border = False
    table.outer_border = False
    table.inner_column_border = False
    task.output = table.table

    return db, task


def ipconfig_filter(db: Session, task: models.AgentTask):
    """
    This filter converts the JSON results of the ifconfig/ipconfig command and converts it to a PowerShell-ish table.

    if the results are from the Python or C# agents, it does nothing.
    """
    if (
        task.input.strip() not in ["ipconfig", "ifconfig"]
        or task.agent.language != "powershell"
    ):
        return db, task

    output = json.loads(task.output)
    if isinstance(output, dict):  # if there's only one adapter, it won't be a list.
        output = [output]

    output_list = []
    for rec in output:
        for key, value in rec.items():
            output_list.append([key, f": {value}"])
        output_list.append([])

    table = AsciiTable(output_list)
    table.inner_heading_row_border = False
    table.inner_row_border = False
    table.outer_border = False
    table.inner_column_border = False
    task.output = table.table

    return db, task


def route_filter(db: Session, task: models.AgentTask):
    """
    This filter converts the JSON results of the route command and converts it to a PowerShell-ish table.

    if the results are from the Python or C# agents, it does nothing.
    """
    if task.input.strip() not in ["route"] or task.agent.language != "powershell":
        return db, task

    output = json.loads(task.output)

    output_list = []
    for rec in output:
        output_list.append(
            [
                rec.get("Destination"),
                rec.get("Netmask"),
                rec.get("NextHop"),
                rec.get("Interface"),
                rec.get("Metric"),
            ]
        )

    output_list.insert(0, ["Destination", "Netmask", "NextHop", "Interface", "Metric"])

    table = AsciiTable(output_list)
    table.inner_row_border = False
    table.outer_border = False
    table.inner_column_border = False
    task.output = table.table

    return db, task


def initialize():
    hooks.register_hook(hooks.BEFORE_TASKING_RESULT_HOOK, "ps_hook_internal", ps_hook)

    hooks.register_filter(
        hooks.BEFORE_TASKING_RESULT_FILTER, "ps_filter_internal", ps_filter
    )
    hooks.register_filter(
        hooks.BEFORE_TASKING_RESULT_FILTER, "ls_filter_internal", ls_filter
    )
    hooks.register_filter(
        hooks.BEFORE_TASKING_RESULT_FILTER, "ipconfig_filter_internal", ipconfig_filter
    )
    hooks.register_filter(
        hooks.BEFORE_TASKING_RESULT_FILTER, "route_filter_internal", route_filter
    )
