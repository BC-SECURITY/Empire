import base64
from binascii import hexlify
from struct import pack

import pytest

from empire.server.utils.bof_packer import Packer, process_arguments


class TestPackerMethods:
    """Tests for individual Packer methods."""

    def test_size_empty(self):
        """Test size property on empty packer."""
        p = Packer()
        assert p.size == 0

    def test_getbuffer_empty(self):
        """Test getbuffer with no data returns zero-length header."""
        p = Packer()
        assert p.getbuffer() == pack("<I", 0)

    def test_addbytes_with_bytes(self):
        """Test addbytes with raw bytes."""
        p = Packer()
        data = b"\xde\xad\xbe\xef"
        p.addbytes(data)
        expected = pack("<I", len(data)) + data
        assert bytes(p.buffer) == expected

    def test_addbytes_with_string(self):
        """Test addbytes encodes string to UTF-8."""
        p = Packer()
        p.addbytes("hello")
        encoded = b"hello"
        expected = pack("<I", len(encoded)) + encoded
        assert bytes(p.buffer) == expected

    def test_addbytes_with_none(self):
        """Test addbytes with None uses empty bytes."""
        p = Packer()
        p.addbytes(None)
        expected = pack("<I", 0)
        assert bytes(p.buffer) == expected

    def test_addstr(self):
        """Test addstr packs null-terminated UTF-8 string."""
        p = Packer()
        p.addstr("hello")
        raw0 = b"hello\x00"
        expected = pack("<I", len(raw0)) + raw0
        assert bytes(p.buffer) == expected

    def test_addstr_with_none(self):
        """Test addstr with None uses empty string."""
        p = Packer()
        p.addstr(None)
        raw0 = b"\x00"
        expected = pack("<I", len(raw0)) + raw0
        assert bytes(p.buffer) == expected

    def test_addstr_with_bytes(self):
        """Test addstr with bytes input uses them directly."""
        p = Packer()
        p.addstr(b"raw")
        raw0 = b"raw\x00"
        expected = pack("<I", len(raw0)) + raw0
        assert bytes(p.buffer) == expected

    def test_addWstr(self):
        """Test addWstr packs null-terminated UTF-16LE string."""
        p = Packer()
        p.addWstr("hi")
        raw0 = "hi\x00".encode("utf-16le")
        expected = pack("<I", len(raw0)) + raw0
        assert bytes(p.buffer) == expected

    def test_addWstr_with_none(self):
        """Test addWstr with None uses empty string."""
        p = Packer()
        p.addWstr(None)
        raw0 = "\x00".encode("utf-16le")
        expected = pack("<I", len(raw0)) + raw0
        assert bytes(p.buffer) == expected

    def test_addbool_true(self):
        """Test addbool packs True as 1."""
        p = Packer()
        p.addbool(True)
        assert bytes(p.buffer) == pack("<I", 1)

    def test_addbool_false(self):
        """Test addbool packs False as 0."""
        p = Packer()
        p.addbool(False)
        assert bytes(p.buffer) == pack("<I", 0)

    def test_adduint32(self):
        """Test adduint32 packs unsigned 32-bit integer."""
        p = Packer()
        p.adduint32(0xDEADBEEF)
        assert bytes(p.buffer) == pack("<I", 0xDEADBEEF)

    def test_adduint32_overflow_mask(self):
        """Test adduint32 masks values exceeding 32 bits."""
        p = Packer()
        p.adduint32(0x1FFFFFFFF)
        assert bytes(p.buffer) == pack("<I", 0xFFFFFFFF)

    def test_addint(self):
        """Test addint packs signed 32-bit integer."""
        p = Packer()
        p.addint(42)
        assert bytes(p.buffer) == pack("<i", 42)

    def test_addint_negative(self):
        """Test addint packs negative integer."""
        p = Packer()
        p.addint(-1)
        assert bytes(p.buffer) == pack("<i", -1)

    def test_addshort(self):
        """Test addshort packs unsigned 16-bit integer."""
        p = Packer()
        p.addshort(7)
        assert bytes(p.buffer) == pack("<H", 7)

    def test_addshort_overflow_mask(self):
        """Test addshort masks values exceeding 16 bits."""
        p = Packer()
        p.addshort(0x10001)
        assert bytes(p.buffer) == pack("<H", 1)


class TestBofPack:
    """Tests for Packer.bof_pack format string dispatch."""

    def test_bof_pack_bytes(self):
        """Test 'b' format packs raw bytes via addbytes."""
        p = Packer()
        data = b"\xde\xad\xbe\xef"
        result = p.bof_pack("b", [data])
        inner = pack("<I", len(data)) + data
        expected = pack("<I", len(inner)) + inner
        assert result == expected

    def test_bof_pack_int(self):
        """Test 'i' format packs signed 32-bit integer."""
        p = Packer()
        result = p.bof_pack("i", ["42"])
        inner = pack("<i", 42)
        expected = pack("<I", len(inner)) + inner
        assert result == expected

    def test_bof_pack_short(self):
        """Test 's' format packs unsigned 16-bit integer."""
        p = Packer()
        result = p.bof_pack("s", ["7"])
        inner = pack("<H", 7)
        expected = pack("<I", len(inner)) + inner
        assert result == expected

    def test_bof_pack_string(self):
        """Test 'z' format packs null-terminated UTF-8 string."""
        p = Packer()
        result = p.bof_pack("z", ["hello"])
        raw0 = b"hello\x00"
        inner = pack("<I", len(raw0)) + raw0
        expected = pack("<I", len(inner)) + inner
        assert result == expected

    def test_bof_pack_wide_string(self):
        """Test 'Z' format packs null-terminated UTF-16LE string."""
        p = Packer()
        result = p.bof_pack("Z", ["hi"])
        raw0 = "hi\x00".encode("utf-16le")
        inner = pack("<I", len(raw0)) + raw0
        expected = pack("<I", len(inner)) + inner
        assert result == expected

    def test_bof_pack_multiple_args(self):
        """Test bof_pack with multiple format characters."""
        p = Packer()
        result = p.bof_pack("iz", ["42", "hello"])
        buf = bytearray()
        buf += pack("<i", 42)
        raw0 = b"hello\x00"
        buf += pack("<I", len(raw0)) + raw0
        expected = pack("<I", len(buf)) + bytes(buf)
        assert result == expected

    def test_bof_pack_mismatched_length(self):
        """Test that mismatched format string and args raises ValueError."""
        p = Packer()
        with pytest.raises(ValueError, match="Format string length must match"):
            p.bof_pack("ii", ["1"])

    def test_bof_pack_invalid_format_char(self):
        """Test that an invalid format character raises ValueError."""
        p = Packer()
        with pytest.raises(ValueError, match="Invalid format character"):
            p.bof_pack("x", ["1"])

    def test_bof_pack_empty_format(self):
        """Test bof_pack with empty format string and no args."""
        p = Packer()
        result = p.bof_pack("", [])
        expected = pack("<I", 0)
        assert result == expected


class TestGetbufferData:
    """Tests for Packer.getbuffer_data base64+hex encoding."""

    def test_getbuffer_data_empty(self):
        """Test getbuffer_data with empty buffer."""
        p = Packer()
        raw = p.getbuffer()
        expected = base64.b64encode(hexlify(raw)).decode("utf-8")
        assert p.getbuffer_data() == expected

    def test_getbuffer_data_with_content(self):
        """Test getbuffer_data after adding data."""
        p = Packer()
        p.addint(42)
        raw = p.getbuffer()
        expected = base64.b64encode(hexlify(raw)).decode("utf-8")
        assert p.getbuffer_data() == expected


class TestProcessArguments:
    """Tests for the module-level process_arguments function."""

    def test_single_int(self):
        """Test process_arguments with a single integer argument."""
        result = process_arguments("i", "42")
        p = Packer()
        packed = p.bof_pack("i", ["42"])
        expected = base64.b64encode(hexlify(packed)).decode("utf-8")
        assert result == expected

    def test_quoted_string(self):
        """Test process_arguments correctly handles quoted strings via shlex."""
        result = process_arguments("z", '"hello world"')
        p = Packer()
        packed = p.bof_pack("z", ["hello world"])
        expected = base64.b64encode(hexlify(packed)).decode("utf-8")
        assert result == expected

    def test_multiple_args(self):
        """Test process_arguments with multiple space-separated arguments."""
        result = process_arguments("iz", "42 hello")
        p = Packer()
        packed = p.bof_pack("iz", ["42", "hello"])
        expected = base64.b64encode(hexlify(packed)).decode("utf-8")
        assert result == expected
