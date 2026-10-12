import contextlib
import logging
import os
import string
import struct
import zlib

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

from empire.server.common import encryption, packets
from empire.server.common.empire import MainMenu
from empire.server.common.encryption import AESCipher, DiffieHellman
from empire.server.core import hooks as hooks_module
from empire.server.core import protocol_constants as proto
from empire.server.core.agent_communication_service import AgentCommunicationService
from empire.server.core.db.base import engine as original_engine
from empire.server.core.db.models import AgentTaskStatus
from empire.server.core.exceptions import (
    ModuleExecutionException,
    ModuleValidationException,
)


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


def _ed25519_keypair():
    """Return (private_raw, public_raw) for an Ed25519 agent certificate key."""
    private_raw = Ed25519PrivateKey.generate().private_bytes_raw()
    return private_raw, encryption.publickey_unsafe(private_raw)


def _client_pub() -> bytes:
    """A fresh client DH public key, fixed-width big-endian."""
    return DiffieHellman().publicKey.to_bytes(proto.DH_PUBLIC_KEY_BYTES, "big")


def _bound_cert(private_raw: bytes, public_raw: bytes, client_pub: bytes) -> bytes:
    """An agent certificate signing the STAGE1 transcript for `client_pub`."""
    return encryption.signature_unsafe(
        encryption.stage1_agent_transcript(client_pub), private_raw, public_raw
    )


def _stage1_body(staging_key: str, client_pub: bytes, agent_cert: bytes) -> bytes:
    """Build a STAGE1 payload: 768-byte DH public key || 64-byte agent cert."""
    return AESCipher.encrypt_then_hmac(
        staging_key.encode("UTF-8"), client_pub + agent_cert
    )


def _listener_options(name="test-listener"):
    return {
        "Name": {"Value": name},
        "DefaultDelay": {"Value": 5},
        "DefaultJitter": {"Value": 0.0},
        "DefaultProfile": {"Value": "/admin/get.php|Mozilla/5.0"},
        "KillDate": {"Value": ""},
        "WorkingHours": {"Value": ""},
        "DefaultLostLimit": {"Value": 60},
    }


STAGING_KEY = "A1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6"

# The session-scoped fixture listener; the agent row used by the autorun tests
# is registered under this name.
FIXTURE_LISTENER = "new-listener-1"


def _valid_autorun_entry(module_id="powershell_code_execution_invoke_ironpython"):
    """A minimal, valid autorun module-request dict."""
    option_key = (
        "BooSource"
        if module_id == "powershell_code_execution_invoke_boolang"
        else "ipyscript"
    )
    return {
        "module_id": module_id,
        "ignore_language_version_check": False,
        "ignore_admin_check": False,
        "options": {option_key: "Hello World"},
        "modified_input": "",
    }


@contextlib.contextmanager
def _autorun_configured(db, main, agent_service, agent, entries):
    """Point the fixture listener's autorun_tasks at `entries` for the block.

    Also points the agent row at the fixture listener. Yields the listener
    row; resets autorun_tasks on exit.
    """
    db_listener = main.listenersv2.get_by_name(db, FIXTURE_LISTENER)
    db_listener.autorun_tasks = entries

    db_agent = agent_service.get_by_name(db, agent)
    db_agent.listener = FIXTURE_LISTENER

    try:
        yield db_listener
    finally:
        db_listener.autorun_tasks = None


def _stage(
    service, db, session_id, language, staging_key, client_pub, agent_cert, agent_pub
):
    server_priv, server_pub = _ed25519_keypair()
    return service._handle_agent_staging(
        db,
        session_id,
        language,
        "STAGE1",
        0,
        _stage1_body(staging_key, client_pub, agent_cert),
        staging_key,
        agent_pub,
        server_priv,
        server_pub,
        _listener_options(),
        "1.2.3.4",
    )


def _stage_full(service, db, session_id, language, agent_priv, agent_pub):
    """Run a complete STAGE1 → STAGE2 negotiation against the real handler.

    Returns (db_agent, stage2_response). The STAGE2 body is encrypted with
    the session key derived client-side from the server's returned public key.
    """
    client = DiffieHellman()

    # The agent row is registered under this listener name; autorun_tasks()
    # resolves it via agent.listener (set at STAGE1 from the listener options),
    # so it must be a listener that exists in the test DB — the session-scoped
    # fixture listener.
    listener_options = _listener_options(name=FIXTURE_LISTENER)

    client_pub = client.publicKey.to_bytes(proto.DH_PUBLIC_KEY_BYTES, "big")
    agent_cert = _bound_cert(agent_priv, agent_pub, client_pub)

    server_priv, server_pub = _ed25519_keypair()
    stage1_resp = service._handle_agent_staging(
        db,
        session_id,
        language,
        "STAGE1",
        0,
        _stage1_body(STAGING_KEY, client_pub, agent_cert),
        STAGING_KEY,
        agent_pub,
        server_priv,
        server_pub,
        listener_options,
        "1.2.3.4",
    )
    assert isinstance(stage1_resp, bytes)

    # Unwrap the routing packet to get (nonce, server DH pub).
    parsed = packets.parse_routing_packet(STAGING_KEY, stage1_resp)
    ((_, (_, _, _, enc_data)),) = parsed.items()
    payload = AESCipher.decrypt_and_verify(STAGING_KEY.encode("UTF-8"), enc_data)
    nonce = payload[:16].decode("UTF-8")
    # payload = nonce(16) || server DH pub (768 bytes, big-endian) || server_cert (64-byte Ed25519 signature)
    server_pub_bytes = payload[16:-64]

    # Derive the same session key the server stored (HKDF-SHA256 over the
    # 768-byte normalized shared secret — see DiffieHellman.gen_key).
    client.gen_key(int.from_bytes(server_pub_bytes, "big"))
    session_key = client.getKey()

    # STAGE2 body: nonce+1|listener|domain|user|host|internal_ip|os|high_integrity|process_name|pid|language|lang_version|arch
    # The listener field here is unused by the handler (the agent's listener
    # comes from STAGE1), but keep it consistent with the fixture listener.
    sysinfo = "|".join(
        [
            str(int(nonce) + 1),
            FIXTURE_LISTENER,
            "",
            "testuser",
            "testhost",
            "10.0.0.5",
            "Windows 10 x64",
            "true",
            "explorer",
            "4242",
            language,
            "3.0",
            "x64",
        ]
    ).encode("UTF-8")

    stage2_resp = service._handle_agent_staging(
        db,
        session_id,
        language,
        "STAGE2",
        0,
        AESCipher.encrypt_then_hmac(session_key, sysinfo),
        STAGING_KEY,
        agent_pub,
        server_priv,
        server_pub,
        listener_options,
        "1.2.3.4",
    )
    db_agent = service.agent_service.get_by_id(db, session_id)
    return db_agent, stage2_resp


# A 768-byte peer key that is a quadratic non-residue mod the group-17 prime, so
# check_public_key() rejects it.
DH_PUBLIC_KEY_REJECTED = b"A" * 768


def _sid(prefix, language):
    """A stable 8-char [A-Z0-9] session id, unique per (prefix, language)."""
    base = "".join(c for c in (prefix + language).upper() if c.isalnum())
    return (base + "00000000")[:8]


def _stage_capturing_server_key(
    service, db, session_id, language, staging_key, client_pub, agent_cert, agent_pub
):
    """Like _stage, but also returns the server's public cert key so the test
    can verify the server certificate the server produced."""
    server_priv, server_pub = _ed25519_keypair()
    result = service._handle_agent_staging(
        db,
        session_id,
        language,
        "STAGE1",
        0,
        _stage1_body(staging_key, client_pub, agent_cert),
        staging_key,
        agent_pub,
        server_priv,
        server_pub,
        _listener_options(),
        "1.2.3.4",
    )
    return result, server_pub


@pytest.mark.parametrize("language", ["powershell", "csharp"])
def test__handle_agent_staging_rejects_zeroed_agent_cert(
    agent_communication_service, session_local, language
):
    """An all-zero certificate must not bypass Ed25519 verification.

    The check used to be guarded by `if any(agent_cert)`, so sending 64 zero
    bytes skipped verification entirely.
    """
    staging_key = STAGING_KEY
    _agent_priv, agent_pub = _ed25519_keypair()

    with session_local.begin() as db:
        result = _stage(
            agent_communication_service,
            db,
            "ZERO" + language[:4].upper(),
            language,
            staging_key,
            _client_pub(),
            b"\x00" * 64,
            agent_pub,
        )

    assert isinstance(result, str)
    assert "Invalid agent certificate" in result


@pytest.mark.parametrize("language", ["powershell", "csharp"])
def test__handle_agent_staging_rejects_wrong_signing_key(
    agent_communication_service, session_local, language
):
    """A well-formed signature from the wrong key must be rejected."""
    staging_key = STAGING_KEY
    attacker_priv, attacker_pub = _ed25519_keypair()
    _expected_priv, expected_pub = _ed25519_keypair()
    client_pub = _client_pub()
    forged = _bound_cert(attacker_priv, attacker_pub, client_pub)

    with session_local.begin() as db:
        result = _stage(
            agent_communication_service,
            db,
            "WRNG" + language[:4].upper(),
            language,
            staging_key,
            client_pub,
            forged,
            expected_pub,
        )

    assert isinstance(result, str)
    assert "Invalid agent certificate" in result


@pytest.mark.parametrize("language", ["powershell", "csharp", "python", "go"])
def test__handle_agent_staging_accepts_valid_agent_cert(
    agent_communication_service, session_local, language
):
    """The happy path completes for every language, registers the agent, and
    returns a server certificate that is bound to the STAGE1 transcript.

    This is the server->agent half of the handshake: an agent verifies exactly
    this signature, so a regression that signed the wrong bytes, reverted to the
    constant b"SIGNATURE", emitted a short/variable-width pubkey, or dropped the
    C# server cert must fail here rather than silently returning bytes.
    """
    sid = _sid("GOOD", language)
    agent_priv, agent_pub = _ed25519_keypair()
    client_pub = _client_pub()
    cert = _bound_cert(agent_priv, agent_pub, client_pub)

    with session_local.begin() as db:
        result, server_pub = _stage_capturing_server_key(
            agent_communication_service,
            db,
            sid,
            language,
            STAGING_KEY,
            client_pub,
            cert,
            agent_pub,
        )

    # A successful stage returns the raw routing packet, not an error string.
    assert isinstance(result, bytes)
    assert len(result) > 0
    # ...and the agent is actually registered under our session id.
    assert sid in agent_communication_service.agents

    # Decrypt the server reply the way an agent does: staging-key AES/HMAC over
    # nonce(16) || server_pub(768, big-endian) || server_cert(64).
    parsed = packets.parse_routing_packet(STAGING_KEY, result)
    assert sid in parsed
    data = AESCipher.decrypt_and_verify(STAGING_KEY.encode("UTF-8"), parsed[sid][3])
    nonce, server_dh_pub, server_cert = data[:16], data[16:784], data[784:848]
    assert len(server_dh_pub) == proto.DH_PUBLIC_KEY_BYTES  # fixed width, not variable
    assert len(server_cert) == proto.AGENT_CERT_SIZE

    # The server certificate must verify against the transcript it signed, and
    # must NOT verify once any transcript field is perturbed.
    transcript = encryption.stage1_server_transcript(sid, nonce, server_dh_pub)
    assert encryption.checkvalid(server_cert, transcript, server_pub)
    tampered_pub = server_dh_pub[:-1] + bytes([server_dh_pub[-1] ^ 0x01])
    assert not encryption.checkvalid(
        server_cert,
        encryption.stage1_server_transcript(sid, nonce, tampered_pub),
        server_pub,
    )


@pytest.mark.parametrize("language", ["powershell", "csharp", "python", "go"])
def test__handle_agent_staging_rejects_invalid_dh_public_key(
    agent_communication_service, session_local, language, caplog
):
    """A peer DH public key that fails validation is an error string, not a raise.

    gen_key() raises a bare Exception out of gen_secret() for any key that is not
    a quadratic residue. Unguarded, that escaped _handle_agent_staging entirely
    and became a Werkzeug 500 on the listener.
    """
    staging_key = STAGING_KEY
    agent_priv, agent_pub = _ed25519_keypair()
    cert = _bound_cert(agent_priv, agent_pub, DH_PUBLIC_KEY_REJECTED)

    with (
        caplog.at_level(
            logging.ERROR, logger="empire.server.core.agent_communication_service"
        ),
        session_local.begin() as db,
    ):
        result = _stage(
            agent_communication_service,
            db,
            f"BADK{language[:4].upper().ljust(4, 'X')}",
            language,
            staging_key,
            DH_PUBLIC_KEY_REJECTED,
            cert,
            agent_pub,
        )

    assert isinstance(result, str)
    assert "DH public key" in result
    assert "DH public key from BADK" in caplog.text


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


def test_autorun_tasks_happy_path(
    agent_task_service,
    agent_communication_service,
    agent,
    session_local,
    agent_service,
    main: MainMenu,
):
    mock_autorun_task = [
        _valid_autorun_entry("powershell_code_execution_invoke_boolang"),
        _valid_autorun_entry("powershell_code_execution_invoke_ironpython"),
    ]

    with (
        session_local.begin() as db,
        _autorun_configured(db, main, agent_service, agent, mock_autorun_task),
    ):
        agent_communication_service.autorun_tasks(db, agent)

        tasks, _total = agent_task_service.get_tasks(db, agents=[agent])

        assert len(tasks) == 2  # noqa: PLR2004
        assert tasks[0].task_name == "TASK_POWERSHELL_CMD_JOB"
        assert tasks[0].module_name == mock_autorun_task[1]["module_id"]
        assert tasks[0].status == "queued"


def test_autorun_tasks_survives_malformed_entry(
    agent_task_service,
    agent_communication_service,
    agent,
    session_local,
    agent_service,
    main: MainMenu,
):
    """A malformed autorun entry (not a valid module request) is skipped;
    the valid entry after it still queues a task."""
    mock_autorun_task = [
        "this-is-not-a-module-request",  # ValidationError from parse_obj
        _valid_autorun_entry(),
    ]

    with (
        session_local.begin() as db,
        _autorun_configured(db, main, agent_service, agent, mock_autorun_task),
    ):
        agent_communication_service.autorun_tasks(db, agent)  # must not raise

        tasks, _total = agent_task_service.get_tasks(db, agents=[agent])
        assert len(tasks) == 1
        assert tasks[0].module_name == "powershell_code_execution_invoke_ironpython"
        assert tasks[0].status == "queued"


@pytest.mark.parametrize(
    "exc",
    [ModuleValidationException, ModuleExecutionException],
)
def test_autorun_tasks_survives_module_failure(
    agent_task_service,
    agent_communication_service,
    agent,
    session_local,
    agent_service,
    main: MainMenu,
    monkeypatch,
    exc,
):
    """An autorun entry whose module raises at the validation or compile
    boundary is skipped without propagating. This is the #837 failure class."""

    def raise_exc(*args, **kwargs):
        raise exc("autorun module failure")

    monkeypatch.setattr(
        agent_communication_service.agent_task_service,
        "create_task_module",
        raise_exc,
    )

    # create_task_module is monkeypatched to always raise, so there is no
    # "valid second entry" — the assertion is only that no exception escapes.
    with (
        session_local.begin() as db,
        _autorun_configured(db, main, agent_service, agent, [_valid_autorun_entry()]),
    ):
        agent_communication_service.autorun_tasks(db, agent)  # must not raise


def test_stage_full_harness_smoke(
    agent_communication_service,
    session_local,
):
    """The STAGE1→STAGE2 harness completes a real negotiation."""
    agent_priv, agent_pub = _ed25519_keypair()
    with session_local.begin() as db:
        db_agent, resp = _stage_full(
            agent_communication_service,
            db,
            "HARNES01",
            "powershell",
            agent_priv,
            agent_pub,
        )

        assert resp.startswith("STAGE2: ")
        assert db_agent.hostname == "testhost"
        assert db_agent.username == "testuser"


def test_handle_agent_staging_fires_checkin_hook_despite_failing_autorun(
    agent_communication_service,
    session_local,
    monkeypatch,
):
    """STAGE2 with a failing autorun: hook still fires, agent still exists,
    staging still returns STAGE2. This is the end-to-end #837 contract."""
    calls = []

    def spy_hook(db, agent_obj):
        calls.append(agent_obj.session_id)

    hooks_module.hooks.register_hook(
        hooks_module.hooks.AFTER_AGENT_CHECKIN_HOOK, "test-spy", spy_hook
    )

    def failing_autorun(db, session_id):
        raise RuntimeError("autorun exploded")

    monkeypatch.setattr(agent_communication_service, "autorun_tasks", failing_autorun)

    agent_priv, agent_pub = _ed25519_keypair()
    try:
        with session_local.begin() as db:
            db_agent, resp = _stage_full(
                agent_communication_service,
                db,
                "E2EAUTOR",
                "powershell",
                agent_priv,
                agent_pub,
            )

            assert resp.startswith("STAGE2: ")
            assert db_agent is not None
            assert db_agent.hostname == "testhost"
            assert calls == ["E2EAUTOR"]
    finally:
        hooks_module.hooks.unregister_hook(
            "test-spy", hooks_module.hooks.AFTER_AGENT_CHECKIN_HOOK
        )


class _PoppingDict(dict):
    """Race-condition simulator: `in` check pops the key as a side effect.

    Models the TOCTOU window where another thread calls
    self.agents.pop(session_id) between `session_id in self.agents`
    and `self.agents[session_id]`.
    """

    def __contains__(self, key):
        hit = super().__contains__(key)
        if hit:
            self.pop(key, None)
        return hit


def test_handle_agent_response_survives_cache_pop_between_check_and_subscript(
    agent_communication_service, agent
):
    session_id = agent  # fixture returns session_id string directly
    original_agents = agent_communication_service.agents
    agent_communication_service.agents = _PoppingDict(original_agents)
    try:
        result = agent_communication_service._handle_agent_response(
            session_id, enc_data=b""
        )
    finally:
        agent_communication_service.agents = original_agents

    assert result is None


def test_generate_sessionid_shape(agent_communication_service):
    valid = set(string.ascii_uppercase + string.digits)
    for _ in range(50):
        sid = agent_communication_service.generate_sessionid()
        assert len(sid) == 8  # noqa: PLR2004
        assert set(sid) <= valid


@pytest.mark.parametrize("language", ["powershell", "csharp", "python", "go"])
def test__handle_agent_staging_rejects_replayed_cert_with_substituted_key(
    agent_communication_service, session_local, language
):
    """A captured certificate must not validate against a different DH key.

    This is the MitM the transcript binding exists to stop: previously the
    signature covered the constant b"SIGNATURE", so a certificate observed in
    any handshake stayed valid forever and an attacker could swap in their own
    DH public key while replaying it verbatim.
    """
    agent_priv, agent_pub = _ed25519_keypair()

    # A legitimate certificate, captured from an earlier exchange over pub_a.
    pub_a = _client_pub()
    captured_cert = _bound_cert(agent_priv, agent_pub, pub_a)

    # Positive control: that same cert IS accepted in its own exchange (pub_a),
    # so the rejection below is specifically the substitution, not a dud cert.
    with session_local.begin() as db:
        ok = _stage(
            agent_communication_service,
            db,
            _sid("RPOK", language),
            language,
            STAGING_KEY,
            pub_a,
            captured_cert,
            agent_pub,
        )
    assert isinstance(ok, bytes)

    # Replayed against a DH public key the attacker controls (pub_b != pub_a).
    with session_local.begin() as db:
        result = _stage(
            agent_communication_service,
            db,
            _sid("RPLY", language),
            language,
            STAGING_KEY,
            _client_pub(),
            captured_cert,
            agent_pub,
        )

    assert isinstance(result, str)
    assert "Invalid agent certificate" in result
