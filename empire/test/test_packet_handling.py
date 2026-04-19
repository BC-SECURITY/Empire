import base64
import struct

from empire.server.common import packets


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


class TestResolveId:
    def test_valid_id(self):
        assert packets.resolve_id(40) == "TASK_SHELL"

    def test_invalid_id_returns_error(self):
        assert packets.resolve_id(99999) == "ERROR"

    def test_string_id(self):
        assert packets.resolve_id("1") == "TASK_SYSINFO"
