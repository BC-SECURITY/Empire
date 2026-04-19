import pytest

from empire.server.utils.listener_util import (
    decimals_to_bytes,
    ensure_raw_bytes,
    generate_random_cipher,
    looks_like_decimal_blob,
    remove_lines_comments,
)


class TestRemoveLinesComments:
    def test_strips_comments(self):
        result = remove_lines_comments("line1\n# comment\nline2")
        assert "line1" in result
        assert "line2" in result
        assert "# comment" not in result

    def test_empty_input(self):
        assert remove_lines_comments("") == ""


class TestLooksLikeDecimalBlob:
    def test_space_separated_digits(self):
        assert looks_like_decimal_blob(b"237 30 211 45") is True

    def test_comma_separated_digits(self):
        assert looks_like_decimal_blob(b"1,2,3,4") is True

    def test_binary_data(self):
        assert looks_like_decimal_blob(b"\x80\x81\x82") is False

    def test_non_bytes_input(self):
        assert looks_like_decimal_blob("not bytes") is False

    def test_no_digits(self):
        assert looks_like_decimal_blob(b"   ") is False


class TestDecimalsToBytes:
    def test_space_separated(self):
        assert decimals_to_bytes("65 66 67") == b"ABC"

    def test_comma_separated(self):
        assert decimals_to_bytes("65,66,67") == b"ABC"

    def test_bytes_input(self):
        assert decimals_to_bytes(b"65 66 67") == b"ABC"

    def test_no_integers_raises(self):
        with pytest.raises(ValueError, match="No integers"):
            decimals_to_bytes("   ")

    def test_out_of_range_raises(self):
        with pytest.raises(ValueError, match="Out-of-range"):
            decimals_to_bytes("256 300")


class TestEnsureRawBytes:
    def test_decimal_blob_converted(self):
        assert ensure_raw_bytes(b"65 66 67") == b"ABC"

    def test_binary_passthrough(self):
        data = b"\x80\x81\x82"
        assert ensure_raw_bytes(data) == data


class TestGenerateRandomCipher:
    def test_contains_known_cipher(self):
        result = generate_random_cipher()
        parts = result.split(":")
        assert len(parts) == 2  # noqa: PLR2004
        assert parts[1] == "ECDHE-RSA-AES256-SHA"
