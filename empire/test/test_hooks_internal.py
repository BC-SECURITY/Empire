import json

import pytest

from empire.server.core.hooks import hooks
from empire.server.core.hooks_internal import _format_table


def test_format_table():
    result = _format_table(
        ["PID", "ProcessName", "Arch", "UserName", "MemUsage"],
        [
            ["1234", "svchost", "x64", "SYSTEM", "15MB"],
            ["5678", "explorer.exe", "x64", "Admin", "120MB"],
            ["9", "idle", "", "", "0MB"],
            ["42", "System", None, None, "1MB"],
        ],
    )

    expected = (
        " PID   ProcessName   Arch  UserName  MemUsage \n"
        "----------------------------------------------\n"
        " 1234  svchost       x64   SYSTEM    15MB     \n"
        " 5678  explorer.exe  x64   Admin     120MB    \n"
        " 9     idle                          0MB      \n"
        " 42    System        None  None      1MB      "
    )
    assert result == expected


@pytest.fixture
def _existing_processes(session_local, models, host):
    with session_local.begin() as db:
        db.query(models.HostProcess).delete()
        existing_processes = [
            models.HostProcess(
                host_id=host,
                process_id=1,
                process_name="should_be_stale",
                architecture="x86",
                user="test_user",
            ),
            models.HostProcess(
                host_id=host,
                process_id=2,
                process_name="should_be_updated",
                architecture="x86",
                user="test_user",
            ),
            models.HostProcess(
                host_id=host,
                process_id=3,
                process_name="should_be_same",
                architecture="x86",
                user="test_user",
            ),
        ]
        db.add_all(existing_processes)

    yield

    with session_local.begin() as db:
        db.query(models.HostProcess).delete()


@pytest.mark.usefixtures("_existing_processes")
def test_ps_hook(client, session_local, models, host, agent):
    with session_local.begin() as db:
        output = json.dumps(
            [
                {
                    "CMD": "has_been_updated",
                    "PID": 2,
                    "Arch": "x86_64",
                    "UserName": "test_user",
                },
                {
                    "CMD": "should_be_same",
                    "PID": 3,
                    "Arch": "x86",
                    "UserName": "test_user",
                },
                {
                    "CMD": "should_be_new",
                    "PID": 4,
                    "Arch": "x86",
                    "UserName": "test_user",
                },
            ]
        )
        db_agent = (
            db.query(models.Agent).filter(models.Agent.session_id == agent).first()
        )
        task = models.AgentTask(
            id=1,
            agent_id=agent,
            agent=db_agent,
            input="ps",
            status=models.AgentTaskStatus.pulled,
            output=output,
            original_output=output,
        )
        hooks.run_hooks(hooks.BEFORE_TASKING_RESULT_HOOK, db, task)
        db.flush()
        processes = db.query(models.HostProcess).all()

        expected_processes = 4
        assert len(processes) == expected_processes
        assert processes[0].process_name == "should_be_stale"
        assert processes[0].stale is True
        assert processes[1].process_name == "has_been_updated"
        assert processes[1].stale is False
        assert processes[2].process_name == "should_be_same"
        assert processes[2].stale is False
        assert processes[3].process_name == "should_be_new"
        assert processes[3].stale is False
