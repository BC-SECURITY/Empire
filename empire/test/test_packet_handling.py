import base64
import logging
import os
import struct

from empire.server.common import encryption, packets


class TestBuildTaskPacket:
    def test_header_fields(self):
        data = "test data"
        packet = packets.build_task_packet("TASK_SHELL", data, 42)
        task_type = struct.unpack("=H", packet[0:2])[0]
        total_packets = struct.unpack("=H", packet[2:4])[0]
        packet_num = struct.unpack("=H", packet[4:6])[0]
        result_id = struct.unpack("=H", packet[6:8])[0]
        length = struct.unpack("=L", packet[8:12])[0]

        assert task_type == packets.PACKET_NAMES["TASK_SHELL"]
        assert total_packets == 1
        assert packet_num == 1
        assert result_id == 42  # noqa: PLR2004
        assert length == len(data.encode("UTF-8"))

    def test_data_payload(self):
        data = "payload content"
        packet = packets.build_task_packet("TASK_SYSINFO", data, 1)
        assert packet[12:] == data.encode("UTF-8")


class TestParseResultPacket:
    def test_roundtrip_with_build_task_packet(self):
        data = base64.b64encode(b"result data").decode("UTF-8")
        packet = packets.build_task_packet("TASK_SHELL", data, 5)
        response_name, total, num, task_id, length, decoded_data, _remaining = (
            packets.parse_result_packet(packet)
        )

        assert response_name == "TASK_SHELL"
        assert total == 1
        assert num == 1
        assert task_id == 5  # noqa: PLR2004
        assert length == len(data.encode("UTF-8"))
        assert decoded_data == b"result data"

    def test_invalid_packet_returns_nones(self):
        assert packets.parse_result_packet(b"short") == (
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        )

    def test_with_offset(self):
        prefix = b"\x00" * 10
        data = base64.b64encode(b"hello").decode("UTF-8")
        packet = prefix + packets.build_task_packet("TASK_EXIT", data, 1)
        result = packets.parse_result_packet(packet, offset=10)
        assert result[0] == "TASK_EXIT"


class TestParseResultPackets:
    def test_single_packet(self):
        data = base64.b64encode(b"single").decode("UTF-8")
        packet = packets.build_task_packet("TASK_SYSINFO", data, 1)
        results = packets.parse_result_packets(packet)
        assert len(results) == 1
        assert results[0][0] == "TASK_SYSINFO"

    def test_multiple_concatenated_packets(self):
        data1 = base64.b64encode(b"first").decode("UTF-8")
        data2 = base64.b64encode(b"second").decode("UTF-8")
        pkt1 = packets.build_task_packet("TASK_SHELL", data1, 1)
        pkt2 = packets.build_task_packet("TASK_EXIT", data2, 2)
        results = packets.parse_result_packets(pkt1 + pkt2)
        assert len(results) == 2  # noqa: PLR2004
        assert results[0][0] == "TASK_SHELL"
        assert results[1][0] == "TASK_EXIT"


def _seal_routing_packet(staging_key: str, session_bytes: bytes) -> bytes:
    """Build a routing packet with raw session bytes.

    Mirrors build_routing_packet(), which UTF-8 encodes a str session id and so
    cannot express a session field that is not valid UTF-8.
    """
    data = session_bytes + struct.pack(
        "=BBHL",
        packets.LANGUAGE["POWERSHELL"],
        packets.META["STAGE0"],
        0,  # ADDITIONAL: NONE
        0,  # length: no trailing encrypted data
    )
    iv = os.urandom(12)
    return iv + encryption.AES256GCM(staging_key.encode("UTF-8")).seal(iv, data, b"")


class TestBuildAndParseRoutingPacket:
    def test_roundtrip(self):
        staging_key = "A" * 32
        session_id = "ABCD1234"
        enc_data = b"encrypted payload"

        packet = packets.build_routing_packet(
            staging_key,
            session_id,
            "powershell",
            meta="STAGE0",
            additional="NONE",
            encData=enc_data,
        )
        result = packets.parse_routing_packet(staging_key, packet)

        assert result is not None
        assert session_id in result
        language, meta, _additional, parsed_enc_data = result[session_id]
        assert language == "POWERSHELL"
        assert meta == "STAGE0"
        assert parsed_enc_data == enc_data

    def test_none_data_returns_none(self):
        assert packets.parse_routing_packet("A" * 32, None) is None

    def test_short_data_returns_none(self):
        assert packets.parse_routing_packet("A" * 32, b"short") is None

    def test_empty_enc_data(self):
        staging_key = "B" * 32
        session_id = "SESS0001"
        packet = packets.build_routing_packet(
            staging_key, session_id, "python", meta="TASKING_REQUEST"
        )
        result = packets.parse_routing_packet(staging_key, packet)
        assert result is not None
        assert result[session_id][0] == "PYTHON"
        assert result[session_id][1] == "TASKING_REQUEST"

    def test_wrong_key_returns_none(self):
        """Parsing with wrong staging key returns None (doesn't raise)."""
        packet = packets.build_routing_packet(
            "A" * 32, "ABCD1234", "powershell", meta="STAGE0", encData=b"payload"
        )
        result = packets.parse_routing_packet("B" * 32, packet)
        assert result is None

    def test_tampered_packet_returns_none(self):
        """Tampered routing packet returns None."""
        packet = packets.build_routing_packet(
            "A" * 32, "ABCD1234", "powershell", meta="STAGE0", encData=b"payload"
        )
        tampered = bytearray(packet)
        tampered[20] ^= 0xFF  # Flip a byte in the AEAD blob
        result = packets.parse_routing_packet("A" * 32, bytes(tampered))
        assert result is None

    def test_non_utf8_session_id_returns_none(self):
        """A packet that authenticates but carries undecodable session bytes is
        discarded, not raised out of the parser."""
        staging_key = "A" * 32
        packet = _seal_routing_packet(staging_key, b"\xff\xfe\x00\x01ABCD")
        assert packets.parse_routing_packet(staging_key, packet) is None

    def test_non_utf8_session_id_logs_warning(self, caplog):
        staging_key = "A" * 32
        packet = _seal_routing_packet(staging_key, b"\xff\xfe\x00\x01ABCD")
        with caplog.at_level(logging.WARNING, logger="empire.server.common.packets"):
            packets.parse_routing_packet(staging_key, packet)
        assert "session ID is not valid UTF-8" in caplog.text

    def test_multibyte_utf8_session_id_still_parses(self):
        """Only undecodable bytes are rejected — non-ASCII UTF-8 still parses."""
        staging_key = "A" * 32
        session_bytes = "éABCDEF".encode()  # 8 bytes: é is two of them
        result = packets.parse_routing_packet(
            staging_key, _seal_routing_packet(staging_key, session_bytes)
        )
        assert result is not None
        assert "éABCDEF" in result


class TestResolveId:
    def test_valid_id(self):
        assert packets.resolve_id(40) == "TASK_SHELL"

    def test_invalid_id_returns_error(self):
        assert packets.resolve_id(99999) == "ERROR"

    def test_string_id(self):
        assert packets.resolve_id("1") == "TASK_SYSINFO"

    def test_chdir_opcode(self):
        # Pin opcode 44 — three agent dispatchers (PS/Python/IronPython) hard-code this value.
        assert packets.PACKET_NAMES["TASK_CHDIR"] == 44  # noqa: PLR2004
        assert packets.resolve_id(44) == "TASK_CHDIR"


class TestChdirRoundtrip:
    def test_chdir_packet_roundtrip(self):
        data = base64.b64encode(b"/tmp").decode("UTF-8")
        packet = packets.build_task_packet("TASK_CHDIR", data, 7)
        response_name, _total, _num, task_id, _length, decoded, _rem = (
            packets.parse_result_packet(packet)
        )
        assert response_name == "TASK_CHDIR"
        assert task_id == 7  # noqa: PLR2004
        assert decoded == b"/tmp"
