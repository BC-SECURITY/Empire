from os import urandom

from empire.server.common import packets


class TestRoutingPacketHandling:
    def TestBuildRoutingPacket(self):
        stagingKey = urandom(32)
        packet = packets.build_routing_packet(
            stagingKey, 1, 2, "NONE", "NONE", "HelloWorld!"
        )
        # Check if packet is of correct size.
        # Should be 44 + len(HelloWorld!) = 55
        assert len(packet) == 55  # noqa: PLR2004

    def TestParseRoutingPacket(self):
        stagingKey = urandom(32)
        packet = packets.build_routing_packet(
            stagingKey, 1, 2, "NONE", "NONE", "HelloWorld!"
        )
        results = packets.parse_result_packet(packet, 0)
        assert results[1][3] == "HelloWorld!"
