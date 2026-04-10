from empire.server.utils.shellcode_compiler import _string_to_wchar_initializer


class TestStringToWcharInitializer:
    """Tests for the _string_to_wchar_initializer helper."""

    def test_basic_ascii(self):
        """Test simple ASCII string produces char literals."""
        result = _string_to_wchar_initializer("hello")
        assert result == "{'h','e','l','l','o',0}"

    def test_empty_string(self):
        """Test empty string produces only null terminator."""
        result = _string_to_wchar_initializer("")
        assert result == "{,0}"

    def test_single_char(self):
        """Test single character string."""
        result = _string_to_wchar_initializer("A")
        assert result == "{'A',0}"

    def test_single_quote_escaped(self):
        """Test single quote is emitted as hex literal."""
        result = _string_to_wchar_initializer("it's")
        assert result == "{'i','t',0x0027,'s',0}"

    def test_backslash_escaped(self):
        """Test backslash is emitted as hex literal."""
        result = _string_to_wchar_initializer("a\\b")
        assert result == "{'a',0x005c,'b',0}"

    def test_non_ascii_escaped(self):
        """Test non-ASCII characters (ord > 126) are emitted as hex."""
        result = _string_to_wchar_initializer("\x80")
        assert result == "{0x0080,0}"

    def test_control_char_escaped(self):
        """Test control characters (ord < 32) are emitted as hex."""
        result = _string_to_wchar_initializer("\t")
        assert result == "{0x0009,0}"

    def test_space_is_literal(self):
        """Test space (ord 32) is a valid printable and emitted as literal."""
        result = _string_to_wchar_initializer(" ")
        assert result == "{' ',0}"

    def test_tilde_is_literal(self):
        """Test tilde (ord 126) is the max printable and emitted as literal."""
        result = _string_to_wchar_initializer("~")
        assert result == "{'~',0}"

    def test_del_char_escaped(self):
        """Test DEL (ord 127) exceeds max printable and is emitted as hex."""
        result = _string_to_wchar_initializer("\x7f")
        assert result == "{0x007f,0}"

    def test_mixed_content(self):
        """Test string with mixed printable and special characters."""
        result = _string_to_wchar_initializer("a'b")
        assert result == "{'a',0x0027,'b',0}"

    def test_url_path(self):
        """Test realistic URL path input."""
        result = _string_to_wchar_initializer("/login/process.php")
        assert (
            result
            == "{'/','l','o','g','i','n','/','p','r','o','c','e','s','s','.','p','h','p',0}"
        )

    def test_digits_and_symbols(self):
        """Test digits and common symbols are treated as printable."""
        result = _string_to_wchar_initializer("8080")
        assert result == "{'8','0','8','0',0}"
