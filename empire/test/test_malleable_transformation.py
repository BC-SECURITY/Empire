import os

from empire.server.common.malleable.transformation import (
    Container,
    Terminator,
    Transform,
)


class TestBase64Transform:
    def test_roundtrip(self):
        t = Transform(type=Transform.BASE64)
        data = b"hello world"
        encoded = t.transform(data)
        assert encoded != data
        assert t.transform_r(encoded) == data


class TestAppendTransform:
    def test_roundtrip(self):
        t = Transform(type=Transform.APPEND, arg="SUFFIX")
        data = b"hello"
        transformed = t.transform(data)
        assert transformed.endswith(b"SUFFIX")
        assert t.transform_r(transformed) == data


class TestPrependTransform:
    def test_roundtrip(self):
        t = Transform(type=Transform.PREPEND, arg="PREFIX")
        data = b"hello"
        transformed = t.transform(data)
        assert transformed.startswith(b"PREFIX")
        assert t.transform_r(transformed) == data


class TestNetbiosTransform:
    def test_all_byte_values_roundtrip(self):
        t = Transform(type=Transform.NETBIOS)
        data = bytes(range(128))
        encoded = t.transform(data)
        assert len(encoded) == 2 * len(data)
        assert t.transform_r(encoded) == data


class TestNetbiosUTransform:
    def test_all_byte_values_roundtrip(self):
        t = Transform(type=Transform.NETBIOSU)
        data = bytes(range(128))
        assert t.transform_r(t.transform(data)) == data


class TestMaskTransform:
    def test_roundtrip(self):
        key = os.urandom(1)
        while ord(key) < 1 or ord(key) > 127:  # noqa: PLR2004
            key = os.urandom(1)
        t = Transform(type=Transform.MASK, arg=key)
        data = b"secret data"
        assert t.transform_r(t.transform(data)) == data

    def test_xor_with_known_key(self):
        t = Transform(type=Transform.MASK, arg=b"\x42")
        result = t.transform(b"\x00\x01\x02")
        assert result == bytes([0x42, 0x43, 0x40])


class TestContainerChains:
    def test_base64_prepend_roundtrip(self):
        c = Container()
        c.base64()
        c.prepend("HEADER:")
        data = b"payload"
        transformed = c.transform(data)
        assert transformed.startswith(b"HEADER:")
        assert c.transform_r(transformed) == data

    def test_empty_container_passthrough(self):
        c = Container()
        data = b"passthrough"
        assert c.transform(data) == data
        assert c.transform_r(data) == data

    def test_none_data_handled(self):
        c = Container()
        c.base64()
        assert c.transform(None) is not None


class TestCodeGeneration:
    def test_generate_python_base64(self):
        t = Transform(type=Transform.BASE64)
        assert "base64" in t.generate_python("data")

    def test_generate_powershell_base64(self):
        t = Transform(type=Transform.BASE64)
        assert "ToBase64String" in t.generate_powershell("$var")

    def test_generate_python_r_base64(self):
        t = Transform(type=Transform.BASE64)
        assert "b64decode" in t.generate_python_r("data")

    def test_container_generate_python(self):
        c = Container()
        c.base64()
        c.prepend("prefix")
        assert "base64" in c.generate_python("data")

    def test_container_generate_powershell(self):
        c = Container()
        c.base64()
        assert "ToBase64String" in c.generate_powershell("$x")


class TestSerialization:
    def test_transform_serialize_deserialize(self):
        t = Transform(type=Transform.BASE64)
        restored = Transform._deserialize(t._serialize())
        assert restored.type == Transform.BASE64

    def test_transform_append_serialize_deserialize(self):
        t = Transform(type=Transform.APPEND, arg="tail")
        restored = Transform._deserialize(t._serialize())
        assert restored.type == Transform.APPEND
        assert restored.arg == "tail"

    def test_container_serialize_deserialize(self):
        c = Container()
        c.base64()
        c.prepend("HDR")
        restored = Container._deserialize(c._serialize())
        assert len(restored.transforms) == 2  # noqa: PLR2004
        assert c.transform(b"test") == restored.transform(b"test")

    def test_terminator_serialize_deserialize(self):
        term = Terminator(type=Terminator.HEADER, arg="Cookie")
        restored = Terminator._deserialize(term._serialize())
        assert restored.type == Terminator.HEADER
        assert restored.arg == "Cookie"


class TestTerminators:
    def test_print_terminator(self):
        c = Container()
        c.print_()
        assert c.terminator.type == Terminator.PRINT

    def test_header_terminator(self):
        c = Container()
        c.header("Cookie")
        assert c.terminator.type == Terminator.HEADER
        assert c.terminator.arg == "Cookie"

    def test_parameter_terminator(self):
        c = Container()
        c.parameter("id")
        assert c.terminator.type == Terminator.PARAMETER
        assert c.terminator.arg == "id"

    def test_uriappend_terminator(self):
        c = Container()
        c.uriappend()
        assert c.terminator.type == Terminator.URIAPPEND
