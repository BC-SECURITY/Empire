"""

Packet handling functionality for Empire.

Defines packet types, builds tasking packets and parses result packets.

Packet format:

AES-256-GCM = AES-256-GCM AEAD encrypted with the shared staging key
AESc = AES encrypted using the client's session key
HMACc = first 16 bytes of a SHA256 HMAC using the client's session key

    Routing Packet:
    +------+----------------------------+--------------------------+
    |  IV  | AES-256-GCM(RoutingData)   | AESc(client packet data) | ...
    +------+----------------------------+--------------------------+
    |  12  |             32             |          length          |
    +------+----------------------------+--------------------------+

        AES-256-GCM(RoutingData):
        +---------------------------+---------------------------+
        |   AES-GCM(Encrypted)      |        GCM Tag            |
        +---------------------------+---------------------------+
        |           16              |            16             |
        +---------------------------+---------------------------+

            AES-GCM(RoutingData):
            +-----------+------+------+-------+--------+
            | SessionID | Lang | Meta | Extra | Length |
            +-----------+------+------+-------+--------+
            |    8      |  1   |  1   |   2   |    4   |
            +-----------+------+------+-------+--------+

    SessionID = the sessionID that the packet is bound for
    Lang = indicates the language used
    Meta = indicates staging req/tasking req/result post/etc.
    Extra = reserved for future expansion


    AESc(client data)
    +--------+-----------------+-------+
    | AES IV | Enc Packet Data | HMACc |
    +--------+-----------------+-------+
    |   16   |   % 16 bytes    |  16   |
    +--------+-----------------+-------+

    Client data decrypted:
    +------+--------+--------------------+----------+---------+-----------+
    | Type | Length | total # of packets | packet # | task ID | task data |
    +------+--------+--------------------+--------------------+-----------+
    |  2   |   4    |         2          |    2     |    2    | <Length>  |
    +------+--------+--------------------+----------+---------+-----------+

    type = packet type
    total # of packets = number of total packets in the transmission
    Packet # = where the packet fits in the transmission
    Task ID = links the tasking to results for deconflict on server side


    Client *_SAVE packets have the sub format:

            [15 chars] - save prefix
            [5 chars]  - extension
            [X...]     - tasking data

"""

import base64
import logging
import os
import struct

from empire.server.core import protocol_constants as proto

from . import encryption

log = logging.getLogger(__name__)


# 0         -> error
# 1-99      -> standard functionality
# 100-199   -> dynamic functionality
# 200-299   -> SMB functionality

PACKET_NAMES = {
    # Agent Commands
    "ERROR": 0,
    "TASK_SYSINFO": 1,
    "TASK_EXIT": 2,
    # Comm Channel
    "TASK_SET_DELAY": 10,
    "TASK_GET_DELAY": 12,
    "TASK_SET_SERVERS": 13,
    "TASK_ADD_SERVERS": 14,
    "TASK_UPDATE_PROFILE": 20,
    "TASK_SET_KILLDATE": 30,
    "TASK_GET_KILLDATE": 31,
    "TASK_SET_WORKING_HOURS": 32,
    "TASK_GET_WORKING_HOURS": 33,
    # Empire Commands
    "TASK_SHELL": 40,
    "TASK_DOWNLOAD": 41,
    "TASK_UPLOAD": 42,
    "TASK_DIR_LIST": 43,
    "TASK_CHDIR": 44,
    "TASK_GETJOBS": 50,
    "TASK_STOPJOB": 51,
    "TASK_SOCKS": 60,
    "TASK_SOCKS_DATA": 61,
    "TASK_SMB_SERVER": 70,
    # Agent Module Commands
    "TASK_POWERSHELL_CMD_WAIT": 100,
    "TASK_POWERSHELL_CMD_WAIT_SAVE": 101,
    "TASK_POWERSHELL_CMD_JOB": 102,
    "TASK_PYTHON_CMD_WAIT": 110,
    "TASK_PYTHON_CMD_WAIT_SAVE": 111,
    "TASK_PYTHON_CMD_JOB": 112,
    "TASK_PYTHON_CMD_JOB_SAVE": 113,
    "TASK_CSHARP_CMD_WAIT": 120,
    "TASK_CSHARP_CMD_WAIT_SAVE": 121,
    "TASK_CSHARP_CMD_JOB": 122,
    "TASK_CSHARP_CMD_JOB_SAVE": 123,
    "TASK_BOF_CMD_WAIT": 130,
    "TASK_PE_CMD_WAIT": 140,
}

# build a lookup table for IDS
PACKET_IDS = {}
for name, ID in list(PACKET_NAMES.items()):
    PACKET_IDS[ID] = name

LANGUAGE = {
    "NONE": 0,
    "POWERSHELL": 1,
    "PYTHON": 2,
    "CSHARP": 3,
    "GO": 4,
    "IRONPYTHON": 5,
}
LANGUAGE_IDS = {}
for name, ID in list(LANGUAGE.items()):
    LANGUAGE_IDS[ID] = name

META = {
    "NONE": 0,
    "STAGE0": 1,
    "STAGE1": 2,
    "STAGE2": 3,
    "TASKING_REQUEST": 4,
    "RESULT_POST": 5,
    "SERVER_RESPONSE": 6,
}
META_IDS = {}
for name, ID in list(META.items()):
    META_IDS[ID] = name

ADDITIONAL = {"SHELLCODE": 1}
ADDITIONAL_IDS = {}
for name, ID in list(ADDITIONAL.items()):
    ADDITIONAL_IDS[ID] = name


def build_task_packet(taskName, data, resultID):
    """
    Build a task packet for an agent.

        [2 bytes] - type
        [2 bytes] - total # of packets
        [2 bytes] - packet #
        [2 bytes] - task/result ID
        [4 bytes] - length
        [X...]    - result data

        +------+--------------------+----------+---------+--------+-----------+
        | Type | total # of packets | packet # | task ID | Length | task data |
        +------+--------------------+--------------------+--------+-----------+
        |  2   |         2          |    2     |    2    |   4    | <Length>  |
        +------+--------------------+----------+---------+--------+-----------+
    """

    taskType = struct.pack("=H", PACKET_NAMES[taskName])
    totalPacket = struct.pack("=H", 1)
    packetNum = struct.pack("=H", 1)
    resultID = struct.pack("=H", resultID)
    length = struct.pack("=L", len(data.encode("UTF-8")))
    return taskType + totalPacket + packetNum + resultID + length + data.encode("UTF-8")


def parse_result_packet(packet, offset=0):
    """
    Parse a result packet-

        [2 bytes] - type
        [2 bytes] - total # of packets
        [2 bytes] - packet #
        [2 bytes] - task/result ID
        [4 bytes] - length
        [X...]    - result data

        +------+--------------------+----------+---------+--------+-----------+
        | Type | total # of packets | packet # | task ID | Length | task data |
        +------+--------------------+--------------------+--------+-----------+
        |  2   |         2          |    2     |    2    |   4    | <Length>  |
        +------+--------------------+----------+---------+--------+-----------+

    Returns a tuple with (responseName, length, data, remainingData)

    Returns a tuple with (responseName, totalPackets, packetNum, taskID, length, data, remainingData)
    """

    try:
        responseID = struct.unpack("=H", packet[0 + offset : 2 + offset])[0]
        totalPacket = struct.unpack("=H", packet[2 + offset : 4 + offset])[0]
        packetNum = struct.unpack("=H", packet[4 + offset : 6 + offset])[0]
        taskID = struct.unpack("=H", packet[6 + offset : 8 + offset])[0]
        length = struct.unpack("=L", packet[8 + offset : 12 + offset])[0]
        if length != "0":
            data = base64.b64decode(packet[12 + offset : 12 + offset + length])
        else:
            data = None
        remainingData = packet[12 + offset + length :]

        # todo: agent returns resultpacket in big endian instead of little for type 44 with outpipe in powershell.
        # This should be fixed and removed at some point.
        if responseID == proto.RESPONSE_ID_ENDIANNESS_FALLBACK:
            responseID = int.from_bytes(
                packet[0 + offset : 2 + offset], byteorder="big"
            )
            totalPacket = int.from_bytes(
                packet[2 + offset : 4 + offset], byteorder="big"
            )
            packetNum = int.from_bytes(packet[4 + offset : 6 + offset], byteorder="big")
            taskID = int.from_bytes(packet[6 + offset : 8 + offset], byteorder="big")
            length = int.from_bytes(packet[8 + offset : 12 + offset], byteorder="big")
        return (
            PACKET_IDS[responseID],
            totalPacket,
            packetNum,
            taskID,
            length,
            data,
            remainingData,
        )

    except Exception as e:
        message = f"parse_result_packet(): exception: {e}"
        log.error(message, exc_info=True)
        return (None, None, None, None, None, None, None)


def parse_result_packets(packets):
    """
    Parse a blob of one or more result packets
    """

    resultPackets = []

    # parse the first result packet
    (
        responseName,
        totalPacket,
        packetNum,
        taskID,
        length,
        data,
        remainingData,
    ) = parse_result_packet(packets)

    if responseName and responseName != "":
        resultPackets.append(
            (responseName, totalPacket, packetNum, taskID, length, data)
        )

    # iterate 12 (size of packet header) + length of the decoded
    offset = 12 + length
    while remainingData and remainingData != "":
        # parse any additional result packets
        # (responseName, length, data, remainingData) = parse_result_packet(packets, offset=offset)
        (
            responseName,
            totalPacket,
            packetNum,
            taskID,
            length,
            data,
            remainingData,
        ) = parse_result_packet(packets, offset=offset)
        if responseName and responseName != "":
            resultPackets.append(
                (responseName, totalPacket, packetNum, taskID, length, data)
            )
        offset += 12 + length

    return resultPackets


def parse_routing_packet(stagingKey, data):
    """
    Decodes the AES-256-GCM "routing packet" and parses raw agent data into:

        {sessionID : (language, meta, additional, [encData]), ...}


    Routing packet format:

        Routing Packet:
        +------+----------------------------+--------------------------+
        |  IV  | AES-256-GCM(RoutingData)   | AESc(client packet data) | ...
        +------+----------------------------+--------------------------+
        |  12  |             32             |          length          |
        +------+----------------------------+--------------------------+

            AES-256-GCM(RoutingData):
            +---------------------------+---------------------------+
            |   AES-GCM(Encrypted)      |        GCM Tag            |
            +---------------------------+---------------------------+
            |           16              |            16             |
            +---------------------------+---------------------------+

                AES-GCM(RoutingData):
                +-----------+------+------+-------+--------+
                | SessionID | Lang | Meta | Extra | Length |
                +-----------+------+------+-------+--------+
                |    8      |  1   |  1   |   2   |    4   |
                +-----------+------+------+-------+--------+
    """

    iv_length = 12
    aead_header_length = iv_length + 32  # Header covers AES-256-GCM (RoutingData)

    if not data:
        message = "parse_agent_data() data is None"
        log.warning(message)
        return None

    results = {}
    offset = 0

    # ensure we have at least the 44 bytes for a routing packet
    if len(data) < aead_header_length:
        message = f"parse_agent_data() data length incorrect: {len(data)}"
        log.warning(message)
        return None

    while True:
        if len(data) - offset < aead_header_length:
            break

        # 0-12
        iv = data[0 + offset : iv_length + offset]
        # routing data 13-35
        aead_data = data[iv_length + offset : aead_header_length + offset]
        key = stagingKey.encode("UTF-8")
        enc_handler = encryption.AES256GCM(key)
        try:
            routingPacket = enc_handler.open(iv, aead_data, b"")
        except encryption.TagInvalidException:
            log.warning(
                "parse_agent_data(): invalid AEAD tag, likely wrong staging key or non-agent traffic"
            )
            return None

        try:
            sessionID = routingPacket[0:8].decode("UTF-8")
        except UnicodeDecodeError:
            log.warning(
                "parse_agent_data(): session ID is not valid UTF-8, discarding packet"
            )
            return None

        # B == 1 byte unsigned char, H == 2 byte unsigned short, L == 4 byte unsigned long
        (language, meta, additional, length) = struct.unpack("=BBHL", routingPacket[8:])
        end = aead_header_length + offset + length
        if end > len(data):
            message = (
                f"parse_agent_data(): decoded length {length} exceeds available data"
            )
            log.warning(message)
            encData = None
        else:
            encData = data[(aead_header_length + offset) : end]

        results[sessionID] = (
            LANGUAGE_IDS.get(language, "NONE"),
            META_IDS.get(meta, "NONE"),
            ADDITIONAL_IDS.get(additional, "NONE"),
            encData,
        )

        # check if we're at the end of the packet processing
        remainingData = data[aead_header_length + offset + length :]
        if not remainingData:
            break

        offset += aead_header_length + length

    log.debug("successfully deconstructed a packet")
    return results


def build_routing_packet(  # noqa: PLR0913
    stagingKey, sessionID, language, meta="NONE", additional="NONE", encData=""
):
    """
    Takes the specified parameters for an "routing packet" and builds/returns
    an AES-256-GCM AEAD "routing packet".

    packet format:

        Routing Packet:
        +------+----------------------------+--------------------------+
        |  IV  | AES-256-GCM(RoutingData)   | AESc(client packet data) | ...
        +------+----------------------------+--------------------------+
        |  12  |             32             |          length          |
        +------+----------------------------+--------------------------+

            AES-256-GCM(RoutingData):
            +---------------------------+---------------------------+
            |   AES-GCM(Encrypted)      |        GCM Tag            |
            +---------------------------+---------------------------+
            |           16              |            16             |
            +---------------------------+---------------------------+

                AES-GCM(RoutingData):
                +-----------+------+------+-------+--------+
                | SessionID | Lang | Meta | Extra | Length |
                +-----------+------+------+-------+--------+
                |    8      |  1   |  1   |   2   |    4   |
                +-----------+------+------+-------+--------+

    """
    # binary pack all of the passed config values as unsigned numbers
    #   B == 1 byte unsigned char, H == 2 byte unsigned short, L == 4 byte unsigned long
    sessionID = sessionID.encode("UTF-8")
    data = sessionID + struct.pack(
        "=BBHL",
        LANGUAGE.get(language.upper(), 0),
        META.get(meta.upper(), 0),
        ADDITIONAL.get(additional.upper(), 0),
        len(encData),
    )
    iv = os.urandom(12)

    # Staging key is in string, needs to be in bytes
    stagingKey = stagingKey.encode("UTF-8")
    enc_handler = encryption.AES256GCM(stagingKey)

    # todo: remove in the future
    if isinstance(encData, str):
        encData = encData.encode("Latin-1")

    # Data is null as we don't need it
    encRoutingData = enc_handler.seal(iv, data, b"")

    log.debug("successfully built a routing packet")
    return iv + encRoutingData + encData


def resolve_id(PacketID):
    """
    Resolve a packet ID to its key.
    """
    try:
        return PACKET_IDS[int(PacketID)]
    except Exception:
        return PACKET_IDS[0]
