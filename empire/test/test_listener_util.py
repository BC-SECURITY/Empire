import ssl

import pytest

from empire.server.core.exceptions import ModuleExecutionException
from empire.server.utils.listener_util import (
    decimals_to_bytes,
    ensure_raw_bytes,
    generate_random_cipher,
    looks_like_decimal_blob,
    read_stager_artifact,
    remove_lines_comments,
    sanitize_log_value,
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
    def test_contains_both_fips_ciphers(self):
        fips_ciphers = {
            "ECDHE-RSA-AES256-GCM-SHA384",
            "ECDHE-RSA-AES128-GCM-SHA256",
        }
        result = generate_random_cipher()
        parts = set(result.split(":"))
        assert parts == fips_ciphers

    def test_order_is_randomized(self):
        results = {generate_random_cipher() for _ in range(50)}
        assert len(results) > 1  # order varies

    def test_cipher_usable_by_openssl(self):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.set_ciphers(generate_random_cipher())


class TestReadStagerArtifact:
    def test_returns_bytes_and_removes_the_artifact(self, tmp_path):
        artifact = tmp_path / "stager_abc.exe"
        artifact.write_bytes(b"MZ\x00\x01")

        assert read_stager_artifact(str(artifact)) == b"MZ\x00\x01"
        assert not artifact.exists()

    def test_unremovable_artifact_still_returns_its_bytes(self, tmp_path, monkeypatch):
        """The load-bearing half of the docstring: AV quarantine and a
        read-only tempdir both fail the unlink, and a compile that just
        succeeded must not be thrown away over it."""
        artifact = tmp_path / "stager_abc.exe"
        artifact.write_bytes(b"MZ\x00\x01")

        def _refuse(self, **kwargs):
            raise PermissionError("read-only tempdir")

        monkeypatch.setattr("pathlib.Path.unlink", _refuse)

        assert read_stager_artifact(str(artifact)) == b"MZ\x00\x01"
        assert artifact.exists()

    @pytest.mark.parametrize("path", ["", None])
    def test_empty_path_is_rejected_by_name(self, path):
        """generate_launcher() returns "" for an inactive listener and None for
        an empty launcher. Path("") is Path("."), so without the guard those
        surface as a bare IsADirectoryError/TypeError from inside a read."""
        with pytest.raises(ModuleExecutionException, match="returned no path"):
            read_stager_artifact(path)


class TestSanitizeLogValue:
    def test_escapes_newlines_so_a_value_cannot_forge_a_record(self):
        assert "\n" not in sanitize_log_value("go\r\n2026-01-01 INFO forged")

    def test_caps_length(self):
        capped = sanitize_log_value("A" * 5000, max_length=64)
        assert capped == repr("A" * 64 + "...")

    def test_keeps_ordinary_values_readable(self):
        assert sanitize_log_value("go") == "'go'"

    def test_missing_value_is_not_quoted(self):
        assert sanitize_log_value(None) == "None"
