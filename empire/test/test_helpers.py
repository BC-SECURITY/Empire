import base64
import hashlib
import logging
from datetime import datetime
from pathlib import Path

import pytest
import yaml

from empire.server.common import helpers


@pytest.mark.slow
def test_dynamic_powershell(install_path):
    # sha256 of the expected output. The dep-walk now emits functions in
    # deterministic order across Python invocations (was hash-randomized
    # via set iteration), which lets us lock the bytes here — this
    # catches any change to the algorithm, not just length drift.
    # Generated post-refactor, so it locks forward stability rather than
    # byte-equivalence with the pre-refactor (non-deterministic) output.
    # Update intentionally if the dependency-walk algorithm is changed.
    expected_sha256 = "f8e0138340d389f2e9047af983fe4d735bfccf4450337901c2a183ac31ecbc1e"
    expected_len = 96863

    # Open with explicit UTF-8 so the sha256 lock is stable across
    # platforms (Path.open() defaults to the system's locale encoding).
    with (
        Path(install_path)
        / "data/module_source/situational_awareness/network/powerview.ps1"
    ).open(encoding="utf-8") as file:
        script = file.read()
        new_script = helpers.generate_dynamic_powershell_script(
            script, "Find-LocalAdminAccess"
        )
    assert len(new_script) == expected_len
    assert hashlib.sha256(new_script.encode()).hexdigest() == expected_sha256


@pytest.fixture(scope="module")
def powerview_script(install_path):
    # Read the ~900KB script once for the module rather than per test.
    return (
        Path(install_path)
        / "data/module_source/situational_awareness/network/powerview.ps1"
    ).read_text(encoding="utf-8")


@pytest.mark.slow
@pytest.mark.parametrize(
    ("requested", "expected_body", "expected_alias"),
    [
        # Get-Proxy is now a Set-Alias to Get-WMIRegProxy.
        (
            "Get-Proxy",
            "function Get-WMIRegProxy {",
            "Set-Alias Get-Proxy Get-WMIRegProxy",
        ),
        # Invoke-FileFinder -> Find-InterestingDomainShareFile (a 31-char
        # target name that the old extraction truncated).
        (
            "Invoke-FileFinder",
            "function Find-InterestingDomainShareFile {",
            "Set-Alias Invoke-FileFinder Find-InterestingDomainShareFile",
        ),
        # Get-DomainDFSShare is a plain (correctly cased) definition.
        ("Get-DomainDFSShare", "function Get-DomainDFSShare {", None),
        # Invoke-DowngradeAccount was re-added to powerview.ps1.
        ("Invoke-DowngradeAccount", "function Invoke-DowngradeAccount {", None),
    ],
)
def test_real_powerview_modules_resolve(
    powerview_script, requested, expected_body, expected_alias
):
    """The real PowerView modules this fix rescues must emit a working script.

    These four entry points were each broken in a different way (alias,
    truncated alias target, casing, deleted function). Driving the actual
    900KB powerview.ps1 — not a synthetic stub — guards against the real
    script drifting (alias reworded, target renamed) in a way the unit tests
    above would not catch.
    """
    result = helpers.generate_dynamic_powershell_script(powerview_script, requested)
    assert expected_body in result
    if expected_alias:
        assert expected_alias in result
        # alias must follow its target definition to resolve at runtime
        assert result.index(expected_body) < result.index(expected_alias)


@pytest.mark.slow
def test_invoke_downgradeaccount_pulls_dependencies(powerview_script):
    # The re-added function calls Get-DomainObject / Set-DomainObject /
    # ConvertFrom-UACValue; the dep-walk must pull each into the payload.
    result = helpers.generate_dynamic_powershell_script(
        powerview_script, "Invoke-DowngradeAccount"
    )
    for dep in (
        "function Get-DomainObject {",
        "function Set-DomainObject {",
        "function ConvertFrom-UACValue {",
    ):
        assert dep in result


@pytest.mark.slow
def test_all_powerview_modules_generate_nonempty(install_path, powerview_script):
    """Every PowerView-backed module must resolve its entry function.

    A module whose script_end names a function the dynamic-script generator
    can't resolve (alias, casing mismatch, or a >30-char name the parser used
    to truncate) silently produces an empty payload — the Get-Proxy class of
    bug. This drives the real powerview.ps1 through every PowerView module's
    entry token and fails if any generates an essentially-empty script, so the
    whole class can't silently regress.
    """
    modules_root = Path(install_path) / "modules" / "powershell"
    powerview_modules = []
    for yaml_path in modules_root.rglob("*.yaml"):
        data = yaml.safe_load(yaml_path.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            continue
        if data.get("script_path") != "situational_awareness/network/powerview.ps1":
            continue
        script_end = data.get("script_end")
        if not script_end:
            continue
        # mirror module_service.finalize_module's entry-token extraction
        entry = script_end.lstrip().split(" ")[0]
        powerview_modules.append((yaml_path.name, entry))

    assert powerview_modules, "no PowerView modules discovered — check the path"

    # A resolved module emits thousands of chars; anything near-empty means the
    # entry function failed to resolve (the bug this guards against).
    min_resolved_len = 50
    empty = [
        (name, entry)
        for name, entry in powerview_modules
        if len(
            helpers.generate_dynamic_powershell_script(powerview_script, entry).strip()
        )
        < min_resolved_len
    ]
    assert not empty, f"PowerView modules generated empty/degraded scripts: {empty}"


class TestGenerateDynamicScriptResolution:
    """Entry-point resolution of the requested function name.

    PowerView ships backward-compat ``Set-Alias`` names (e.g.
    ``Get-Proxy`` -> ``Get-WMIRegProxy``) and Empire modules sometimes
    request a function by a case that differs from the definition. The
    dependency walker keys a case-sensitive dict on real ``function`` /
    ``filter`` definitions, so the requested name must be resolved to a
    real definition before the walk, or the lookup raises ``KeyError``.
    """

    def test_resolves_set_alias_to_target_function(self):
        script = (
            "\nfunction Get-WMIRegProxy {\n  'real proxy body'\n}\n"
            "Set-Alias Get-Proxy Get-WMIRegProxy\n"
        )
        result = helpers.generate_dynamic_powershell_script(script, "Get-Proxy")
        assert "real proxy body" in result
        # The alias is preserved so a script_end that invokes the
        # backward-compat name still resolves at agent runtime.
        assert "Set-Alias Get-Proxy Get-WMIRegProxy" in result

    def test_alias_emitted_after_target_definition(self):
        # The Set-Alias line must come *after* its target function so the
        # alias resolves to an already-defined command at runtime.
        script = (
            "\nfunction Get-WMIRegProxy {\n  'real proxy body'\n}\n"
            "Set-Alias Get-Proxy Get-WMIRegProxy\n"
        )
        result = helpers.generate_dynamic_powershell_script(script, "Get-Proxy")
        assert result.index("function Get-WMIRegProxy") < result.index(
            "Set-Alias Get-Proxy Get-WMIRegProxy"
        )

    def test_resolves_case_insensitive_function_name(self):
        script = "\nfunction Get-DomainDFSShare {\n  'dfs share body'\n}\n"
        result = helpers.generate_dynamic_powershell_script(
            script, "Get-DomainDFSshare"
        )
        assert "dfs share body" in result

    def test_resolves_long_function_name(self):
        # Names longer than 30 chars were silently truncated by the old
        # ``func_match[:40].split()[1]`` extraction (the ``\nfunction ``
        # prefix eats 10 chars), so the definition was stored under a
        # clipped key and could never be resolved or pulled in as a dep.
        long_name = "Find-InterestingDomainShareFile"
        script = f"\nfunction {long_name} {{\n  'long body'\n}}\n"
        result = helpers.generate_dynamic_powershell_script(script, long_name)
        assert "long body" in result

    def test_resolves_alias_to_long_target_name(self):
        long_name = "Find-InterestingDomainShareFile"
        script = (
            f"\nfunction {long_name} {{\n  'long body'\n}}\n"
            f"Set-Alias Invoke-FileFinder {long_name}\n"
        )
        result = helpers.generate_dynamic_powershell_script(script, "Invoke-FileFinder")
        assert "long body" in result
        assert f"Set-Alias Invoke-FileFinder {long_name}" in result

    def test_resolves_filter_definition(self):
        # _FUNCTION_PATTERN matches `filter` as well as `function`, so the
        # name extraction must work for both keywords.
        script = "\nfilter Get-FilterThing {\n  'filter body'\n}\n"
        result = helpers.generate_dynamic_powershell_script(script, "Get-FilterThing")
        assert "filter body" in result

    def test_only_requested_alias_is_emitted(self):
        # Two aliases share a target; requesting one must not leak the other
        # into the runtime payload.
        script = (
            "\nfunction Get-Target {\n  'target body'\n}\n"
            "Set-Alias Alias-One Get-Target\n"
            "Set-Alias Alias-Two Get-Target\n"
        )
        result = helpers.generate_dynamic_powershell_script(script, "Alias-One")
        assert "Set-Alias Alias-One Get-Target" in result
        assert "Alias-Two" not in result

    def test_alias_to_missing_target_is_dropped(self, caplog):
        # An alias whose target is not a real definition must be dropped, not
        # emitted as a dangling Set-Alias into the payload (which would fail on
        # the agent). The request then resolves to nothing and warns cleanly.
        script = (
            "\nfunction Real-Thing {\n  'real body'\n}\n"
            "Set-Alias Ghost-Cmd Missing-Target\n"
        )
        with caplog.at_level(logging.WARNING):
            result = helpers.generate_dynamic_powershell_script(script, "Ghost-Cmd")
        assert "Set-Alias" not in result
        assert "real body" not in result
        assert "Ghost-Cmd" in caplog.text

    def test_function_name_that_is_also_alias_emits_no_dangling_alias(self):
        # If a requested name is both a real definition AND an alias name,
        # resolve to the function and do NOT emit the Set-Alias (whose target
        # is not pulled into the payload — that would be a dangling alias).
        script = (
            "\nfunction Get-Thing {\n  'thing body'\n}\n"
            "\nfunction Other-Thing {\n  'other body'\n}\n"
            "Set-Alias Get-Thing Other-Thing\n"
        )
        result = helpers.generate_dynamic_powershell_script(script, "Get-Thing")
        assert "thing body" in result
        assert "Set-Alias" not in result

    def test_resolves_list_with_missing_name(self, caplog):
        # A list request resolves each valid name and skips a missing one
        # without aborting the rest of the batch.
        script = (
            "\nfunction Get-A {\n  'body a'\n}\n\nfunction Get-B {\n  'body b'\n}\n"
        )
        with caplog.at_level(logging.WARNING):
            result = helpers.generate_dynamic_powershell_script(
                script, ["Get-A", "Nope-Missing", "Get-B"]
            )
        assert "body a" in result
        assert "body b" in result
        assert "Nope-Missing" in caplog.text

    def test_missing_function_logs_warning_not_traceback(self, caplog):
        script = "\nfunction Real-Thing {\n  'real body'\n}\n"
        with caplog.at_level(logging.WARNING):
            result = helpers.generate_dynamic_powershell_script(
                script, "Nonexistent-Func"
            )
        assert "real body" not in result
        # The requested name is surfaced once, cleanly...
        assert "Nonexistent-Func" in caplog.text
        # ...and we no longer leak the two KeyError tracebacks.
        assert "Traceback" not in caplog.text
        assert "KeyError" not in caplog.text


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


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("10.0.0.5", "http://10.0.0.5"),
        ("https://c2.example", "https://c2.example"),
        ("HTTPS://C2.example", "https://C2.example"),
        ("[::1]", "http://[::1]"),
        ("münchen.de", "http://münchen.de"),
    ],
)
def test_normalize_http_host_accepts(raw, expected):
    assert helpers.normalize_http_host(raw) == expected


@pytest.mark.parametrize(
    "raw",
    [
        "",
        "10.0.0.5:8080",
        "http://c2.example:",
        "https://c2.example/stagers",
        "10.0.0.5?x=1",
        "10.0.0.5#f",
        "u:p@10.0.0.5",
        "ftp://10.0.0.5",
        "http://",
        ".",
        "[::1",
        "c2.exa\tmple",
        "10.0.0\n.5",
        "\x01http://c2.example",
    ],
)
def test_normalize_http_host_rejects(raw):
    assert helpers.normalize_http_host(raw) is None
