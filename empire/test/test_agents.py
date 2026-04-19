import base64
import logging
import struct
import zlib
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from sqlalchemy.exc import IntegrityError

from empire.server.common.empire import MainMenu
from empire.server.utils import datetime_util

log = logging.getLogger(__name__)


# Copied from the agent.py file for Python agent
class compress:
    """
    Base clase for init of the package. This will handle
    the initial object creation for conducting basic functions.
    """

    CRC_HSIZE = 4
    COMP_RATIO = 9

    def __init__(self, verbose=False):
        """
        Populates init.
        """
        pass

    def comp_data(self, data, cvalue=COMP_RATIO):
        """
        Takes in a string and computes
        the comp obj.
        data = string wanting compression
        cvalue = 0-9 comp value (default 6)
        """
        return zlib.compress(data, cvalue)

    def crc32_data(self, data):
        """
        Takes in a string and computes crc32 value.
        data = string before compression
        returns:
        HEX bytes of data
        """
        return zlib.crc32(data) & 0xFFFFFFFF

    def build_header(self, data, crc):
        """
        Takes comp data, org crc32 value,
        and adds self header.
        data =  comp data
        crc = crc32 value
        """
        header = struct.pack("!I", crc)
        return header + data


def test_stale_expression(empire_config, session_local, models, agents):
    with session_local.begin() as db:
        agents = db.query(models.Agent).all()

        # assert one of the agents is stale via its hybrid property
        assert any(agent.stale for agent in agents)
        # assert any one of the agents is not stale via its hybrid property
        assert any(not agent.stale for agent in agents)
        # assert we can filter on stale via the hybrid expressions

        stale = (
            db.query(models.Agent).filter(models.Agent.stale == True).all()  # noqa: E712
        )
        assert all(agent.stale for agent in stale)

        # assert we can filter on stale via the hybrid expression
        not_stale = (
            db.query(models.Agent).filter(models.Agent.stale == False).all()  # noqa: E712
        )
        assert all(not agent.stale for agent in not_stale)


def test_large_internal_ip_works(session_local, host, models, agent):
    with session_local.begin() as db:
        db_agent = (
            db.query(models.Agent).filter(models.Agent.session_id == agent).first()
        )
        db_host = db.query(models.Host).filter(models.Host.id == host).first()
        db_agent.internal_ip = "192.168.1.75 fe90::51e7:5dc7:be5d:b22e 3600:1900:7bb0:90d0:4d3c:2cd6:3fe:883b 5600:1900:3aa0:80d1:18a4:4431:5023:eef7 6600:1500:1aa0:20d0:fd69:26ff:5c4c:8d27 2900:2700:4aa0:80d0::47 192.168.214.1 fe90::a24c:82de:578b:8626 192.168.245.1 fe00::f321:a1e:18d3:ab9"

        db.flush()

        db_host.internal_ip = db_agent.internal_ip

        db.flush()


def test_duplicate_host(session_local, models, host):
    with session_local.begin() as db:
        db_host = db.query(models.Host).filter(models.Host.id == host).first()
        host2 = models.Host(name=db_host.name, internal_ip=db_host.internal_ip)
        db.add(host2)

        with pytest.raises(IntegrityError):
            db.flush()


def test_duplicate_checkin_raises_exception(session_local, models, agent):
    with session_local.begin() as db:
        db_agent = (
            db.query(models.Agent).filter(models.Agent.session_id == agent).first()
        )
        timestamp = datetime.now(UTC)
        checkin = models.AgentCheckIn(
            agent_id=db_agent.session_id, checkin_time=timestamp
        )
        checkin2 = models.AgentCheckIn(
            agent_id=db_agent.session_id, checkin_time=timestamp
        )

        db.add(checkin)
        db.add(checkin2)

        with pytest.raises(IntegrityError):
            db.flush()


def test_can_ignore_duplicate_checkins(session_local, models, agent, main, monkeypatch):
    with session_local.begin() as db:
        db_agent = (
            db.query(models.Agent).filter(models.Agent.session_id == agent).first()
        )
        prev_checkin_count = len(db_agent.checkins.all())
        # Monkeypatch time to be 2 seconds in the future so the checkin
        # timestamp differs from the original checkin
        future_time = datetime_util.getutcnow() + timedelta(seconds=2)
        monkeypatch.setattr(datetime_util, "getutcnow", lambda: future_time)

        main.agentsv2.update_agent_lastseen(db, db_agent.session_id)
        main.agentsv2.update_agent_lastseen(db, db_agent.session_id)

    with session_local.begin() as db:
        db_agent = (
            db.query(models.Agent).filter(models.Agent.session_id == agent).first()
        )
        checkin_count = len(db_agent.checkins.all())

        assert checkin_count == prev_checkin_count + 1


def test_update_dir_list(session_local, models, agent, main: MainMenu):
    with session_local.begin() as db:
        message = {
            "directory_path": "C:\\",
            "directory_name": "C:\\",
            "items": [
                {
                    "path": "C:\\Users\\vinnybod\\Desktop\\test.txt",
                    "name": "test.txt",
                    "is_file": True,
                },
                {
                    "path": "C:\\Users\\vinnybod\\Desktop\\test2.txt",
                    "name": "test2.txt",
                    "is_file": True,
                },
            ],
        }
        main.agentcommsv2._update_dir_list(db, agent, message)

        file, _ = main.agentfilesv2.get_file_by_path(
            db, agent, "C:\\Users\\vinnybod\\Desktop\\test.txt"
        )

        assert file.path == "C:\\Users\\vinnybod\\Desktop\\test.txt"
        assert file.name == "test.txt"
        assert file.is_file is True
        assert file.parent_id is not None

        db.query(models.AgentFile).delete()


def test_update_dir_list_with_existing_joined_file(
    session_local, models, agent, main: MainMenu, empire_config
):
    with session_local.begin() as db:
        message = {
            "directory_path": "C:\\",
            "directory_name": "C:\\",
            "items": [
                {
                    "path": "C:\\Users\\vinnybod\\Desktop\\test.txt",
                    "name": "test.txt",
                    "is_file": True,
                },
                {
                    "path": "C:\\Users\\vinnybod\\Desktop\\test2.txt",
                    "name": "test2.txt",
                    "is_file": True,
                },
            ],
        }
        main.agentcommsv2._update_dir_list(db, agent, message)

        file, _ = main.agentfilesv2.get_file_by_path(
            db, agent, "C:\\Users\\vinnybod\\Desktop\\test.txt"
        )

        download_path = Path("empire/test/avatar.png")
        file.downloads.append(
            models.Download(
                location=str(download_path.absolute()),
                filename=download_path.name,
                size=download_path.stat().st_size,
            )
        )

        # This previously raised a Foreign Key Constraint error, but should succeed now.
        main.agentcommsv2._update_dir_list(db, agent, message)

        file2, _ = main.agentfilesv2.get_file_by_path(
            db, agent, "C:\\Users\\vinnybod\\Desktop\\test.txt"
        )

        if empire_config.database.use != "sqlite":
            # sqlite reuses ids and apparently doesn't cascade the delete to the
            # association table. This can result in files being linked to the wrong
            # download after refreshing a directory for sqlite.
            assert file.id != file2.id
            assert len(file2.downloads) == 0

        assert file.name == file2.name

        db.query(models.AgentFile).delete()


def test_skywalker_exploit_protection(caplog, agent, session_local, main: MainMenu):
    with session_local.begin() as db:
        # Malicious file path attempting directory traversal
        malicious_directory = (
            main.installPath + r"/downloads/..\\..\\..\\..\\..\\etc\\cron.d\\evil"
        )
        encodedPart = b"test"
        c = compress()
        start_crc32 = c.crc32_data(encodedPart)
        comp_data = c.comp_data(encodedPart)
        encodedPart = c.build_header(comp_data, start_crc32)
        encodedPart = base64.b64encode(encodedPart).decode("UTF-8")

        malicious_data = "|".join(
            [
                "0",
                malicious_directory,
                "6",
                encodedPart,
            ]
        )

        main.agentcommsv2._process_agent_packet(
            db, agent, "TASK_DOWNLOAD", "1", malicious_data
        )

        expected_message_part = "attempted skywalker exploit!"

    assert any(expected_message_part in message for message in caplog.messages)
