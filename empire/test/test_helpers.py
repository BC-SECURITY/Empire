import base64
from datetime import datetime
from pathlib import Path

import pytest

from empire.server.common import helpers


@pytest.mark.slow
def test_dynamic_powershell(install_path):
    expected_len = 96863

    with (
        Path(install_path)
        / "data/module_source/situational_awareness/network/powerview.ps1"
    ).open() as file:
        script = file.read()
        new_script = helpers.generate_dynamic_powershell_script(
            script, "Find-LocalAdminAccess"
        )
    assert len(new_script) == expected_len


class TestValidateIP:
    def test_valid_ipv4(self):
        assert helpers.validate_ip("192.168.1.1") is True

    def test_valid_ipv6(self):
        assert helpers.validate_ip("::1") is True

    def test_invalid_string(self):
        assert helpers.validate_ip("not-an-ip") is False

    def test_empty_string(self):
        assert helpers.validate_ip("") is False


class TestValidateNTLM:
    def test_valid_ntlm(self):
        assert helpers.validate_ntlm("a" * 32) is True

    def test_too_short(self):
        assert helpers.validate_ntlm("aabb") is False

    def test_non_hex_chars(self):
        assert helpers.validate_ntlm("g" * 32) is False


class TestRandomString:
    def test_default_length(self):
        s = helpers.random_string()
        assert 6 <= len(s) <= 15  # noqa: PLR2004

    def test_explicit_length(self):
        s = helpers.random_string(length=10)
        assert len(s) == 10  # noqa: PLR2004

    def test_custom_charset(self):
        s = helpers.random_string(length=20, charset="abc")
        assert all(c in "abc" for c in s)


class TestChunks:
    def test_even_split(self):
        result = list(helpers.chunks("abcdef", 2))
        assert result == ["ab", "cd", "ef"]

    def test_uneven_split(self):
        result = list(helpers.chunks("abcde", 2))
        assert result == ["ab", "cd", "e"]

    def test_single_chunk(self):
        result = list(helpers.chunks("abc", 10))
        assert result == ["abc"]


class TestEncPowershell:
    def test_roundtrip(self):
        raw = "Get-Process"
        encoded = helpers.enc_powershell(raw)
        assert base64.b64decode(encoded).decode("UTF-16LE") == raw


class TestParsePowershellScript:
    def test_extracts_function_names(self):
        script = "function Get-Users{\n}\nfunction Set-Password{\n}"
        names = helpers.parse_powershell_script(script)
        assert "Get-Users" in names
        assert "Set-Password" in names

    def test_no_functions(self):
        script = "Write-Host 'hello'"
        assert helpers.parse_powershell_script(script) == []


class TestStripPowershellComments:
    def test_strips_block_comments(self):
        script = "line1\n<# block comment #>\nline2"
        result = helpers.strip_powershell_comments(script)
        assert "<#" not in result
        assert "line1" in result
        assert "line2" in result

    def test_strips_line_comments(self):
        script = "code\n# comment\nmore code"
        result = helpers.strip_powershell_comments(script)
        assert "# comment" not in result
        assert "code" in result

    def test_strips_verbose_debug(self):
        script = "code\nWrite-Verbose 'msg'\nWrite-Debug 'msg'\nmore"
        result = helpers.strip_powershell_comments(script)
        assert "Write-Verbose" not in result
        assert "Write-Debug" not in result

    def test_strips_empty_lines(self):
        script = "code\n\n\nmore"
        result = helpers.strip_powershell_comments(script)
        assert "\n\n" not in result


class TestStripPythonComments:
    def test_strips_comments(self):
        code = "code = 1\n# comment\ncode = 2"
        result = helpers.strip_python_comments(code)
        assert "# comment" not in result

    def test_strips_empty_lines(self):
        code = "code = 1\n\n\ncode = 2"
        result = helpers.strip_python_comments(code)
        assert "\n\n" not in result

    def test_preserves_code(self):
        script = "x = 1\ny = 2"
        result = helpers.strip_python_comments(script)
        assert "x = 1" in result
        assert "y = 2" in result


class TestGetFileSize:
    def test_bytes(self):
        result = helpers.get_file_size(b"x")
        assert "Bytes" in result

    def test_kb(self):
        result = helpers.get_file_size(b"x" * 2000)
        assert "KB" in result

    def test_mb(self):
        result = helpers.get_file_size(b"x" * (1024 * 1024 + 100))
        assert "MB" in result


class TestGetDatetime:
    def test_format(self):
        result = helpers.get_datetime()
        datetime.strptime(result, "%Y-%m-%d %H:%M:%S")


class TestGetFileDatetime:
    def test_format(self):
        result = helpers.get_file_datetime()
        datetime.strptime(result, "%Y-%m-%d_%H-%M-%S")


class TestUnique:
    def test_removes_duplicates(self):
        assert helpers.unique([1, 2, 2, 3, 3, 3]) == [1, 2, 3]

    def test_preserves_order(self):
        assert helpers.unique([3, 1, 2, 1, 3]) == [3, 1, 2]

    def test_empty_list(self):
        assert helpers.unique([]) == []

    def test_custom_idfun(self):
        result = helpers.unique(["A", "a", "B", "b"], idfun=str.lower)
        assert result == ["A", "B"]


class TestUniquifyTuples:
    def test_removes_duplicate_creds(self):
        tuples = [
            ("hash", "domain", "user", "pass", "host", "sid"),
            ("hash", "domain", "user", "pass", "host2", "sid2"),
        ]
        assert len(helpers.uniquify_tuples(tuples)) == 1

    def test_keeps_different_creds(self):
        tuples = [
            ("hash", "domain", "user1", "pass1", "host", "sid"),
            ("hash", "domain", "user2", "pass2", "host", "sid"),
        ]
        assert len(helpers.uniquify_tuples(tuples)) == 2  # noqa: PLR2004


class TestDecodeBase64:
    def test_valid_b64(self):
        original = b"hello world"
        encoded = base64.b64encode(original)
        assert helpers.decode_base64(encoded) == original

    def test_missing_padding(self):
        encoded = base64.b64encode(b"hello world").rstrip(b"=")
        assert helpers.decode_base64(encoded) == b"hello world"

    def test_string_input(self):
        encoded = base64.b64encode(b"test").decode("UTF-8")
        assert helpers.decode_base64(encoded) == b"test"


class TestEncodeBase64:
    def test_roundtrip(self):
        data = b"hello world"
        encoded = helpers.encode_base64(data)
        assert base64.decodebytes(encoded) == data


class TestParseCredentials:
    def test_mac_text_returned(self):
        data = b"button returned:OK, text returned:mypassword"
        result = helpers.parse_credentials(data)
        assert result is not None
        assert result[0][3] == b"mypassword"

    def test_unrecognized_format(self):
        assert helpers.parse_credentials(b"some random output") is None


class TestObfuscateCallHomeAddress:
    def test_contains_encoded_content(self):
        result = helpers.obfuscate_call_home_address("test")
        assert "$([Text.Encoding]::Unicode.GetString" in result
        encoded_part = result.split("'")[1]
        assert base64.b64decode(encoded_part).decode("UTF-16LE") == "test"


class TestPowershellLauncher:
    def test_builds_launcher(self):
        raw = "Get-Process"
        launcher_prefix = "powershell -noP -sta -w 1 -enc"
        result = helpers.powershell_launcher(raw, launcher_prefix)
        assert result.startswith(launcher_prefix)
        encoded_cmd = result.split(" ")[-1]
        assert base64.b64decode(encoded_cmd).decode("UTF-16LE") == raw
