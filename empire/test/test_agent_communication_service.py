import os
import struct
import zlib

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

from empire.server.common import packets
from empire.server.common.empire import MainMenu
from empire.server.core.agent_communication_service import AgentCommunicationService
from empire.server.core.db.base import engine as original_engine
from empire.server.core.db.models import AgentTaskStatus


@pytest.fixture(scope="module")
def agent_communication_service(main: MainMenu):
    return main.agentcommsv2


@pytest.fixture(scope="module")
def agent_task_service(main: MainMenu):
    return main.agenttasksv2


@pytest.fixture(scope="module")
def agent_service(main: MainMenu):
    return main.agentsv2


def test_save_file_non_python(
    agent_task_service,
    agent_communication_service,
    session_local,
    models,
    agent,
    agent_task,
    empire_config,
):
    data = b"This is a test file"
    file_path = r"C:\Users\Public\test.txt"
    with session_local.begin() as db:
        agent_communication_service.save_file(
            db,
            agent,
            file_path,
            data,
            len(data),
            agent_task_service.get_task_for_agent(db, agent, agent_task["id"]),
            "powershell",
        )

    with session_local.begin() as db:
        task = agent_task_service.get_task_for_agent(db, agent, agent_task["id"])
        assert len(task.downloads) == 1
        download = task.downloads[0]
        assert download.filename == "test.txt"
        assert download.size == len(data)
        assert download.get_bytes_file() == data
        assert f"downloads/{agent}/{file_path.replace('\\', '/')}" in download.location


def test_save_file_python(
    agent_task_service,
    agent_communication_service,
    session_local,
    models,
    agent,
    agent_task,
    empire_config,
):
    raw = b"Hello from python agent"
    crc = zlib.crc32(raw) & 0xFFFFFFFF
    header = struct.pack("!I", crc)
    compressed = header + zlib.compress(raw, 9)

    file_path = r"C:\Users\Public\python_test.txt"

    # Mark the agent as a python agent in the comms cache
    agent_communication_service.agents[agent]["language"] = "python"

    try:
        with session_local.begin() as db:
            agent_communication_service.save_file(
                db,
                agent,
                file_path,
                compressed,
                len(raw),
                agent_task_service.get_task_for_agent(db, agent, agent_task["id"]),
                "python",
            )

        with session_local.begin() as db:
            task = agent_task_service.get_task_for_agent(db, agent, agent_task["id"])
            download = task.downloads[-1]
            assert download.filename == "python_test.txt"
            assert download.get_bytes_file() == raw
    finally:
        agent_communication_service.agents[agent]["language"] = "powershell"


def test_save_module_file(agent_communication_service, agent, empire_config):
    data = b"module output data here"
    path = "screenshots/test_capture.png"

    result = agent_communication_service.save_module_file(
        agent, path, data, "powershell"
    )

    assert result is not None
    assert result.name == "test_capture.png"
    assert result.read_bytes() == data


class TestIsPathSafe:
    """Direct unit tests for _is_path_safe against adversarial inputs.

    The integration-level skywalker test lives in test_agents.py.
    These tests exercise the static method directly with various
    traversal and bypass techniques.
    """

    @pytest.fixture
    def download_dir(self, tmp_path):
        d = tmp_path / "downloads"
        d.mkdir()
        return d

    @pytest.mark.parametrize(
        "relative_path",
        [
            "AGENT123/file.txt",
            "AGENT123/subdir/file.txt",
            "AGENT123/a/b/c/deep.bin",
        ],
    )
    def test_safe_paths(self, download_dir, relative_path):
        save_path = download_dir / relative_path
        assert (
            AgentCommunicationService._is_path_safe(save_path, download_dir, "TEST")
            is True
        )

    @pytest.mark.parametrize(
        ("traversal", "description"),
        [
            ("../etc/passwd", "basic unix traversal"),
            ("../../etc/shadow", "multi-level unix traversal"),
            ("AGENT123/../../etc/cron.d/evil", "traversal after valid prefix"),
            ("../../../../../../../etc/passwd", "deep traversal"),
            ("AGENT123/../../../etc/passwd", "agent dir then deep traversal"),
        ],
    )
    def test_traversal_blocked(self, download_dir, traversal, description):
        save_path = download_dir / traversal
        assert (
            AgentCommunicationService._is_path_safe(save_path, download_dir, "TEST")
            is False
        ), f"Should block: {description}"

    @pytest.mark.parametrize(
        "traversal",
        [
            r"..\Windows\System32\evil.dll",
            r"AGENT123\..\..\evil.txt",
        ],
    )
    @pytest.mark.skipif(
        os.name != "nt", reason="Backslash is only a path separator on Windows"
    )
    def test_backslash_traversal_blocked_on_windows(self, download_dir, traversal):
        save_path = download_dir / traversal
        assert (
            AgentCommunicationService._is_path_safe(save_path, download_dir, "TEST")
            is False
        )

    def test_traversal_to_sibling_directory(self, download_dir):
        """Ensure traversal to a sibling of the download dir is blocked."""
        sibling = download_dir.parent / "secrets" / "key.pem"
        assert (
            AgentCommunicationService._is_path_safe(sibling, download_dir, "TEST")
            is False
        )

    def test_prefix_attack(self, tmp_path):
        """A dir whose name starts with the download dir name must be rejected.

        e.g. /tmp/downloads-evil should NOT pass a check for /tmp/downloads.
        The old startswith() implementation was vulnerable to this.
        """
        download_dir = tmp_path / "downloads"
        download_dir.mkdir()
        evil_dir = tmp_path / "downloads-evil"
        evil_dir.mkdir()
        save_path = evil_dir / "payload.txt"
        assert (
            AgentCommunicationService._is_path_safe(save_path, download_dir, "TEST")
            is False
        )

    def test_dot_segments_in_middle(self, download_dir):
        """Path with /./ segments that resolve to the download dir should be safe."""
        save_path = download_dir / "AGENT123" / "." / "file.txt"
        assert (
            AgentCommunicationService._is_path_safe(save_path, download_dir, "TEST")
            is True
        )

    def test_null_byte_in_path(self, download_dir):
        """Null bytes in paths should not bypass the check."""
        # Path() on most OSes will raise ValueError or the resolve will fail
        # Either way, it should not return True
        try:
            save_path = download_dir / "AGENT123/\x00/../../etc/passwd"
            result = AgentCommunicationService._is_path_safe(
                save_path, download_dir, "TEST"
            )
            # If it didn't raise, it must have blocked it
            assert result is False
        except (ValueError, OSError):
            pass  # Expected on most platforms

    def test_logs_warning_on_traversal(self, download_dir, caplog):
        save_path = download_dir / "../evil.txt"
        AgentCommunicationService._is_path_safe(save_path, download_dir, "EVIL_AGENT")
        assert any(
            "EVIL_AGENT" in msg and "skywalker" in msg for msg in caplog.messages
        )

    def test_no_warning_on_safe_path(self, download_dir, caplog):
        save_path = download_dir / "AGENT123/safe.txt"
        AgentCommunicationService._is_path_safe(save_path, download_dir, "GOOD_AGENT")
        assert not any("skywalker" in msg for msg in caplog.messages)


def test__remove_agent(
    agent_service, agent_communication_service, agent, session_local
):
    with session_local.begin() as db:
        assert agent in agent_communication_service.agents
        assert agent_service.get_by_id(db, agent)

        agent_communication_service._remove_agent(db, agent)

        assert agent not in agent_communication_service.agents
        assert not agent_service.get_by_id(db, agent)


def test__get_agent_nonce(main, agent_communication_service, agent, session_local):
    with session_local.begin() as db:
        db_agent = main.agentsv2.get_by_id(db, agent)
        nonce = agent_communication_service._get_agent_nonce(db, agent)

        assert nonce == db_agent.nonce


def test__update_dir_list(agent_communication_service, agent, session_local, models):
    with session_local.begin() as db:
        response = {
            "directory_path": r"C:\Users\Public",
            "directory_name": "Desktop",
            "items": [
                {
                    "name": "test.txt",
                    "path": r"C:\Users\Public\Desktop\test.txt",
                    "is_file": True,
                },
                {
                    "name": "Stuff",
                    "path": r"C:\Users\Public\Desktop\Stuff",
                    "is_file": False,
                },
            ],
        }

        agent_communication_service._update_dir_list(db, agent, response)

        files = (
            db.query(models.AgentFile)
            .filter(models.AgentFile.session_id == agent)
            .all()
        )

        assert len(files) == 3  # noqa: PLR2004

        root = files[0]
        assert root.name == "Desktop"
        assert root.path == r"C:\Users\Public"

        test_txt = files[1]
        assert test_txt.name == "test.txt"
        assert test_txt.path == r"C:\Users\Public\Desktop\test.txt"
        assert test_txt.parent_id == root.id

        stuff = files[2]
        assert stuff.name == "Stuff"
        assert stuff.path == r"C:\Users\Public\Desktop\Stuff"
        assert stuff.parent_id == root.id


def test_update_agent_sysinfo(
    agent_communication_service, session_local, agent, models
):
    listener = "ABC"
    external_ip = "1.2.3.4"
    internal_ip = "4.3.2.1"
    username = "testuser"
    hostname = "testhost"
    os_details = "Windows 10"
    high_integrity = True
    process_name = "test.exe"
    process_id = 1234
    language_version = "3.9.1"
    language = "python"
    architecture = "x64"
    with session_local.begin() as db:
        agent_communication_service.update_agent_sysinfo(
            db,
            agent,
            listener,
            external_ip,
            internal_ip,
            username,
            hostname,
            os_details,
            high_integrity,
            process_name,
            process_id,
            language_version,
            language,
            architecture,
        )

    with session_local.begin() as db:
        agent = db.query(models.Agent).filter(models.Agent.session_id == agent).first()

        # TODO: Should these fields be updated?
        # assert agent.listener == listener
        # assert agent.external_ip == external_ip
        assert agent.internal_ip == internal_ip
        assert agent.username == username
        assert agent.hostname == hostname
        assert agent.os_details == os_details
        assert agent.high_integrity == high_integrity
        assert agent.process_name == process_name
        assert agent.process_id == process_id
        assert agent.language_version == language_version
        assert agent.language == language
        assert agent.architecture == architecture


def test__get_queued_agent_tasks(
    agent_task_service, agent_communication_service, session_local, agent, agent_task
):
    with session_local.begin() as db:
        tasks, _ = agent_task_service.get_tasks(db, agents=[agent])
        assert len(tasks) == 1
        assert all(task.status == AgentTaskStatus.queued for task in tasks)

        queued_tasks = agent_communication_service._get_queued_agent_tasks(db, agent)
        assert len(queued_tasks) == 1
        assert all(task.status == AgentTaskStatus.pulled for task in queued_tasks)


def test__get_queued_agent_temporary_tasks(
    agent_task_service, agent_communication_service, agent
):
    task, _ = agent_task_service.add_temporary_task(agent, "TEST_TASK", "TEST_DATA")

    assert agent_task_service.temporary_tasks[agent][0] == task

    queued_tasks = agent_communication_service._get_queued_agent_temporary_tasks(agent)

    assert queued_tasks[0] == task
    assert agent_task_service.temporary_tasks[agent] == []


def test__handle_agent_staging():
    pass


def test_handle_agent_data():
    pass


def test_handle_agent_request(
    agent_task_service,
    agent_communication_service,
    agent,
    agent_task,
    session_local,
):
    _task, _ = agent_task_service.add_temporary_task(
        agent, "TASK_SHELL", "echo 'hello world'"
    )

    packet = agent_communication_service.handle_agent_request(
        agent, "python", "2c103f2c4ed1e59c0b4e2e01821770fa"
    )

    assert packet is not None

    # Verify DB task status was persisted as "pulled" (not still "queued")
    with session_local.begin() as db:
        task = agent_task_service.get_task_for_agent(db, agent, agent_task["id"])
        assert task.status == AgentTaskStatus.pulled


def test_handle_agent_request_db_task_attributes_accessible_after_expunge(
    agent_task_service,
    agent_communication_service,
    agent,
    agent_task,
    session_local,
):
    """DB-backed ORM task attributes (including deferred input_full) must
    remain accessible after expunge_all() detaches them from the session.

    _get_queued_agent_tasks loads tasks with include_full_input=True to
    eagerly load the deferred input_full column. If that option is ever
    removed, accessing input_full on an expunged object raises
    DetachedInstanceError — this test catches that regression.
    """
    # Reproduce the exact sequence handle_agent_request uses:
    # load tasks inside a session, flush, expunge, then access attributes
    # outside the session.
    with session_local.begin() as db:
        tasks = agent_communication_service._get_queued_agent_tasks(db, agent)
        assert len(tasks) > 0
        db.flush()
        db.expunge_all()

    # These attribute accesses happen in Phase 2 (outside the session).
    # If input_full were not eagerly loaded, this would raise
    # DetachedInstanceError.
    for task in tasks:
        assert task.input_full is not None
        assert task.task_name is not None
        assert task.id is not None


def test_handle_agent_request_no_tasks(agent_communication_service, agent):
    """When no tasks are queued, handle_agent_request returns None."""
    packet = agent_communication_service.handle_agent_request(
        agent, "python", "2c103f2c4ed1e59c0b4e2e01821770fa"
    )
    assert packet is None


def test_handle_agent_request_releases_session_before_packet_building(
    agent_task_service, agent_communication_service, agent, agent_task, monkeypatch
):
    """The DB session must be closed before expensive packet building begins.

    Creates a connection pool with only 1 slot and monkeypatches
    build_task_packet to try acquiring a second connection. If the session
    from handle_agent_request is still held during build_task_packet, the
    second acquisition fails with a pool timeout — reproducing the root
    cause of the production pool exhaustion bug.
    """
    connect_args = {}
    if "sqlite" in str(original_engine.url):
        connect_args["check_same_thread"] = False

    constrained_engine = create_engine(
        original_engine.url,
        pool_size=1,
        max_overflow=0,
        pool_timeout=2,
        connect_args=connect_args,
    )
    try:
        ConstrainedSessionLocal = sessionmaker(bind=constrained_engine)
        monkeypatch.setattr(
            "empire.server.core.agent_communication_service.SessionLocal",
            ConstrainedSessionLocal,
        )

        original_build = packets.build_task_packet
        pool_was_available = False

        def build_task_packet_checking_pool(*args, **kwargs):
            nonlocal pool_was_available
            # If the session is still held, this will time out (pool exhausted)
            with ConstrainedSessionLocal.begin() as probe:
                probe.execute(text("SELECT 1"))
            pool_was_available = True
            return original_build(*args, **kwargs)

        monkeypatch.setattr(
            packets, "build_task_packet", build_task_packet_checking_pool
        )

        agent_task_service.add_temporary_task(agent, "TASK_SHELL", "echo 'hello'")

        packet = agent_communication_service.handle_agent_request(
            agent, "python", "2c103f2c4ed1e59c0b4e2e01821770fa"
        )

        assert packet is not None
        assert pool_was_available, "Session was not released before packet building"
    finally:
        constrained_engine.dispose()


def test__handle_agent_response():
    pass


def test__process_agent_packet():
    pass


def _test_autorun_task(
    agent_task_service,
    agent_communication_service,
    agent,
    session_local,
    db,
    listener,
    agent_service,
    main: MainMenu,
):
    mock_autorun_task = [
        {
            "module_id": "powershell_code_execution_invoke_boolang",
            "ignore_language_version_check": False,
            "ignore_admin_check": False,
            "options": {"BooSource": "Hello World"},
            "modified_input": "",
        },
        {
            "module_id": "powershell_code_execution_invoke_ironpython",
            "ignore_language_version_check": False,
            "ignore_admin_check": False,
            "options": {"ipyscript": "Hello World"},
            "modified_input": "",
        },
    ]

    db_listener = main.listenersv2.get_by_name(db, "new-listener-1")
    db_listener.autorun_tasks = mock_autorun_task

    db_agent = agent_service.get_by_name(db, agent)
    db_agent.listener = "new-listener-1"

    agent_communication_service.autorun_tasks(db, agent)

    tasks, _total = agent_task_service.get_tasks(db, agents=[agent])

    assert len(tasks) == 2  # noqa: PLR2004
    assert tasks[0].task_name == "TASK_POWERSHELL_CMD_JOB"
    assert tasks[0].module_name == mock_autorun_task[1]["module_id"]
    assert tasks[0].status == "queued"
