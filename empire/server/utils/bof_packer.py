import base64
import shlex
import struct
from binascii import hexlify


class Packer:
    def __init__(self):
        self.buffer = bytearray()

    @property
    def size(self) -> int:
        return len(self.buffer)

    def getbuffer(self) -> bytes:
        return struct.pack("<I", self.size) + bytes(self.buffer)

    def addbytes(self, b):
        if b is None:
            b = b""
        b = b.encode("utf-8") if isinstance(b, str) else bytes(b)

        self.buffer += struct.pack("<I", len(b))
        self.buffer += b

    def addstr(self, s):
        if s is None:
            s = ""
        raw = s if isinstance(s, bytes) else str(s).encode("utf-8")

        raw0 = raw + b"\x00"
        self.buffer += struct.pack("<I", len(raw0))
        self.buffer += raw0

    def addWstr(self, s):
        if s is None:
            s = ""

        raw0 = (str(s) + "\x00").encode("utf-16le")
        self.buffer += struct.pack("<I", len(raw0))
        self.buffer += raw0

    def addbool(self, b):
        self.buffer += struct.pack("<I", 1 if b else 0)

    def adduint32(self, n):
        self.buffer += struct.pack("<I", n & 0xFFFFFFFF)

    def addint(self, n):
        self.buffer += struct.pack("<i", int(n))

    def addshort(self, n):
        self.buffer += struct.pack("<H", int(n) & 0xFFFF)

    def bof_pack(self, fstring, args):
        if len(fstring) != len(args):
            raise ValueError(
                f"Format string length must match arguments: {len(fstring)} != {len(args)}"
            )

        for i, c in enumerate(fstring):
            if c == "b":
                self.addbytes(args[i])
            elif c == "i":
                self.addint(args[i])
            elif c == "s":
                self.addshort(args[i])
            elif c == "z":
                self.addstr(args[i])
            elif c == "Z":
                self.addWstr(args[i])
            else:
                raise ValueError(f"Invalid format character '{c}' in position {i}.")

        return self.getbuffer()

    def getbuffer_data(self) -> str:
        return base64.b64encode(hexlify(self.getbuffer())).decode("utf-8")


def process_arguments(format_string, arguments):
    arg_list = shlex.split(arguments)

    p = Packer()
    packed_data = p.bof_pack(format_string, arg_list)

    return base64.b64encode(hexlify(packed_data)).decode("utf-8")
