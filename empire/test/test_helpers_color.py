import click

from empire.server.common.helpers import color


def _expected(text, fg):
    return click.style(text, fg=fg, bold=True)


class TestColor:
    def test_explicit_colors(self):
        assert color("hello", "red") == _expected("hello", "red")
        assert color("hello", "green") == _expected("hello", "green")
        assert color("hello", "yellow") == _expected("hello", "yellow")
        assert color("hello", "blue") == _expected("hello", "blue")

    def test_prefix_auto_detection(self):
        assert color("[!] err") == _expected("[!] err", "red")
        assert color("[+] ok") == _expected("[+] ok", "green")
        assert color("[*] info") == _expected("[*] info", "blue")
        assert color("[>] prompt") == _expected("[>] prompt", "yellow")

    def test_no_matching_prefix(self):
        assert color("plain text") == "plain text"

    def test_case_insensitive(self):
        assert color("hello", "RED") == _expected("hello", "red")

    def test_unknown_color(self):
        assert color("hello", "purple") == click.style("hello", bold=True)
