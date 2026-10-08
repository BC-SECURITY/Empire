"""Unit tests for the Python agent packet handlers in data/agent/agent.py.

The agent file is stdlib-only, so it is loaded directly by path rather than
through a package import. The packet handler is injected at staging time
(assembled from listeners/common/aesgcm.py.j2), so a stub mirroring its
response format is used here.

Regression tests for:
- BC-SECURITY/Empire#825 — packet 50/51 dispatch called nonexistent
  job_list/stop_job instead of task_list/stop_task.
- BC-SECURITY/Empire#836 — TASK_PYTHON_CMD_WAIT (110) exception path built
  the error response but never sent it, leaving tasks stuck "pulled".
- BC-SECURITY/Empire#827 — job code calling bare job_message_buffer() had no
  such name in its exec globals.
"""

import importlib.util
import time
from pathlib import Path

import pytest

# Packet types from common/packets.py relevant to these tests
TASK_ERROR = 0
TASK_GETJOBS = 50
TASK_STOP_JOB = 51
TASK_PYTHON_CMD_WAIT = 110
TASK_PYTHON_CMD = 112


def _load_main_agent_class():
    path = Path(__file__).parent.parent / "server" / "data" / "agent" / "agent.py"
    spec = importlib.util.spec_from_file_location("empire_agent_module", path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.MainAgent


MainAgentClass = _load_main_agent_class()


class StubPacketHandler:
    """Mirrors the assembled agent's packet handler response format.

    build_response_packet returns (tasking_id, packet_data, result_id) instead
    of the wire format -- the tests only need to observe which packets were
    sent with what data.
    """

    def __init__(self):
        self.sent = []
        self.missedCheckins = 0

    def send_message(self, message):
        self.sent.append(message)

    @staticmethod
    def build_response_packet(tasking_id, packet_data, result_id=0):
        return (tasking_id, packet_data, result_id)


@pytest.fixture
def agent():
    handler = StubPacketHandler()
    return MainAgentClass(
        packet_handler=handler,
        profile="profile|Mozilla/5.0|Cookie:session=abc",
        server="http://127.0.0.1",
        session_id="ABCDEF1234567890",
        kill_date="",
        working_hours="",
    )


def _sent_types(agent):
    return [message[0] for message in agent.packet_handler.sent]


def _wait_for_sent(agent, count, timeout=3.0):
    deadline = time.time() + timeout
    while time.time() < deadline and len(agent.packet_handler.sent) < count:
        time.sleep(0.05)
    assert len(agent.packet_handler.sent) >= count, (
        f"timed out after {timeout}s waiting for {count} sent packets; "
        f"got {len(agent.packet_handler.sent)}"
    )


def _make_task_entry(result_id, packet_type=TASK_PYTHON_CMD):
    """Mirror the task dict process_packet creates."""
    return {
        "result_id": result_id,
        "packet_type": packet_type,
        "status": "running",
        "task_thread": None,
        "reading_thread": None,
        "language": None,
        "powershell": {
            "app_domain": None,
            "ps_host": None,
            "buffer": None,
            "ps_host_exec": None,
        },
    }


class TestPacket50JobList:
    """#825: packet type 50 (GETJOBS) must reach task_list, not raise."""

    def test_packet_type_50_returns_task_table(self, agent):
        agent.process_packet(TASK_GETJOBS, "", 50)

        assert _sent_types(agent) == [50]
        assert "Task ID" in agent.packet_handler.sent[0][1]
        assert agent.tasks[50]["status"] == "completed"


class TestPacket51StopJob:
    """#825: packet type 51 (STOPJOB) must reach stop_task, not raise."""

    def test_packet_type_51_reports_unknown_job(self, agent):
        agent.process_packet(TASK_STOP_JOB, "9999", 51)

        # stop_task responds with an error packet (type 0) for unknown jobs
        assert _sent_types(agent) == [TASK_ERROR]
        assert "not found" in agent.packet_handler.sent[0][1]

    def test_stop_job_matches_int_task_key(self, agent):
        # The wire carries the job id as a string; self.tasks is keyed by the
        # int result_id from parse_task_packet. A real job id must be found.
        code = "import time\nfor _ in range(100):\n    time.sleep(0.1)"
        agent.process_packet(TASK_PYTHON_CMD, code, 5)
        agent.process_packet(TASK_STOP_JOB, "5", 51)
        # the killed job never emits its output packet, so exactly one
        # response (the stop confirmation) is expected
        _wait_for_sent(agent, 1)

        types = _sent_types(agent)
        assert types == [TASK_STOP_JOB], (
            f"STOPJOB for a live job id was not matched: sent {types}"
        )
        assert "stopped successfully" in agent.packet_handler.sent[0][1]

    def test_stop_job_without_threads_does_not_raise(self, agent):
        # reading_thread/task_thread are None for jobs whose thread never
        # started; a successful stop must not also emit an error packet.
        agent.tasks[7] = _make_task_entry(7)

        agent.process_packet(TASK_STOP_JOB, "7", 51)

        # exactly one response: "already stopped" (51), no AttributeError error packet
        assert _sent_types(agent) == [51]
        assert "already stopped" in agent.packet_handler.sent[0][1]

    def test_stop_job_marks_own_task_completed(self, agent):
        # process_packet tracks every packet, including the STOPJOB itself;
        # its status must not stay "started" forever.
        agent.process_packet(TASK_STOP_JOB, "9999", 51)
        assert agent.tasks[51]["status"] == "error"  # job not found -> error path

        # a registered task whose thread never started -> "already stopped"
        agent.tasks[7] = _make_task_entry(7)
        agent.process_packet(TASK_STOP_JOB, "7", 52)
        assert agent.tasks[52]["status"] == "completed"  # already-stopped path


class TestJobStatusRace:
    """start_python_job must mark 'running' BEFORE thread.start(), or a fast
    job's final status gets clobbered back to 'running' permanently."""

    def test_instant_job_reaches_terminal_status(self, agent):
        for i in range(20):
            result_id = 200 + i
            agent.process_packet(TASK_PYTHON_CMD, "pass", result_id)
            _wait_for_sent(agent, i + 1)

        statuses = [agent.tasks[200 + i]["status"] for i in range(20)]
        assert "running" not in statuses, f"fast jobs stuck in 'running': {statuses}"
        assert all(s == "completed" for s in statuses)


class TestTaskPythonCmdWaitErrors:
    """#836: task 110 exception path must actually send the error packet."""

    def test_error_response_is_sent_on_exception(self, agent):
        agent.process_packet(TASK_PYTHON_CMD_WAIT, "raise RuntimeError('boom')", 110)

        assert len(agent.packet_handler.sent) == 1, (
            "error packet was built but never sent; task stays 'pulled' forever"
        )
        task_type, data, _ = agent.packet_handler.sent[0]
        # error responses go out on packet type 0
        assert task_type == TASK_ERROR
        assert "boom" in data
        assert agent.tasks[110]["status"] == "error"

    def test_success_response_still_sent(self, agent):
        agent.process_packet(TASK_PYTHON_CMD_WAIT, "print('hello')", 111)

        assert len(agent.packet_handler.sent) == 1
        task_type, data, _ = agent.packet_handler.sent[0]
        assert task_type == TASK_PYTHON_CMD_WAIT
        assert "hello" in data


class TestJobMessageBufferInjection:
    """#827: bare job_message_buffer() calls in job code must work."""

    @staticmethod
    def _wait_for_response(agent, timeout=3.0):
        deadline = time.time() + timeout
        while time.time() < deadline and not agent.packet_handler.sent:
            time.sleep(0.05)

    def test_job_code_can_call_job_message_buffer(self, agent):
        agent.process_packet(
            TASK_PYTHON_CMD, "job_message_buffer('buffer message')", 112
        )
        self._wait_for_response(agent)

        # the job ran, appended to the agent's buffer, and its response went out
        assert "buffer message" in agent.job_message_buffer
        assert _sent_types(agent) == [TASK_PYTHON_CMD]

    def test_template_module_code_pattern(self, agent):
        # Mirrors python_jobs_template.py's generated loop, unrolled.
        code = "\n".join(
            [
                "x = 0",
                "msg = 'NOW inside buffer at message: ' + str(x) + '\\n'",
                "job_message_buffer(msg)",
            ]
        )

        agent.process_packet(TASK_PYTHON_CMD, code, 113)
        self._wait_for_response(agent)

        assert "NOW inside buffer at message: 0" in agent.job_message_buffer
        assert _sent_types(agent) == [TASK_PYTHON_CMD]
