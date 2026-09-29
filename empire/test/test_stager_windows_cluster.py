"""Generation tests for a cluster of windows stagers: wmic (XSL), launcher_vbs,
war (JSP/zip), hta, and cmd_exec (msfvenom-wrapped). All embed a powershell
launcher into a device/format-specific payload.
"""

import contextlib
import io
import subprocess
import zipfile

import pytest

from empire.server.core.exceptions import StagerGenerationException
from empire.server.stagers.windows import cmd_exec
from empire.server.stagers.windows.cmd_exec import Stager as CmdExecStager
from empire.server.stagers.windows.hta import Stager as HtaStager
from empire.server.stagers.windows.launcher_vbs import Stager as LauncherVbsStager
from empire.server.stagers.windows.war import Stager as WarStager
from empire.server.stagers.windows.wmic import Stager as WmicStager

LISTENER = "new-listener-1"


# --------------------------------------------------------------------------- #
# wmic (XSL stylesheet)
# --------------------------------------------------------------------------- #
def test_wmic_powershell_builds_xsl(main):
    stager = WmicStager(main)
    stager.options["Listener"]["Value"] = LISTENER

    code = stager.generate()

    assert code.startswith('<?xml version="1.0"?>')
    assert "XSL/Transform" in code
    assert 'ActiveXObject("WScript.Shell").Run(' in code
    assert "-enc" in code
    assert code.endswith("</ms:script></stylesheet>")


def test_wmic_empty_launcher_raises(main, monkeypatch):
    monkeypatch.setattr(main.stagergenv2, "generate_launcher", lambda *a, **k: "")
    stager = WmicStager(main)
    stager.options["Listener"]["Value"] = LISTENER
    with pytest.raises(StagerGenerationException):
        stager.generate()


# --------------------------------------------------------------------------- #
# launcher_vbs
# --------------------------------------------------------------------------- #
def test_launcher_vbs_builds_vbs(main):
    stager = LauncherVbsStager(main)
    stager.options["Listener"]["Value"] = LISTENER

    code = stager.generate()

    assert 'WScript.CreateObject("WScript.Shell")' in code
    assert "objShell.Run command,0" in code
    assert "-enc" in code


def test_launcher_vbs_empty_launcher_raises(main, monkeypatch):
    monkeypatch.setattr(main.stagergenv2, "generate_launcher", lambda *a, **k: "")
    stager = LauncherVbsStager(main)
    stager.options["Listener"]["Value"] = LISTENER
    with pytest.raises(StagerGenerationException):
        stager.generate()


# --------------------------------------------------------------------------- #
# war (JSP packaged in a zip)
# --------------------------------------------------------------------------- #
def test_war_packages_jsp_with_launcher(main):
    stager = WarStager(main)
    stager.options["Listener"]["Value"] = LISTENER
    stager.options["AppName"]["Value"] = "myapp"

    result = stager.generate()

    zf = zipfile.ZipFile(io.BytesIO(result))
    jsp = zf.read("myapp.jsp").decode()
    web_xml = zf.read("WEB-INF/web.xml").decode()

    assert "Runtime.getRuntime().exec(" in jsp
    assert "-enc" in jsp
    assert "<servlet-name>myapp</servlet-name>" in web_xml


def test_war_app_name_defaults_to_listener(main):
    stager = WarStager(main)
    stager.options["Listener"]["Value"] = LISTENER
    stager.options["AppName"]["Value"] = ""

    result = stager.generate()

    zf = zipfile.ZipFile(io.BytesIO(result))
    assert f"{LISTENER}.jsp" in zf.namelist()


def test_war_empty_launcher_raises(main, monkeypatch):
    monkeypatch.setattr(main.stagergenv2, "generate_launcher", lambda *a, **k: "")
    stager = WarStager(main)
    stager.options["Listener"]["Value"] = LISTENER
    with pytest.raises(StagerGenerationException):
        stager.generate()


# --------------------------------------------------------------------------- #
# hta
# --------------------------------------------------------------------------- #
def test_hta_builds_html(main):
    stager = HtaStager(main)
    stager.options["Listener"]["Value"] = LISTENER

    code = stager.generate()

    assert code.startswith("<html><head><script>")
    assert "new ActiveXObject('WScript.Shell').Run(c)" in code
    assert "-enc" in code


def test_hta_empty_launcher_raises(main, monkeypatch):
    monkeypatch.setattr(main.stagergenv2, "generate_launcher", lambda *a, **k: "")
    stager = HtaStager(main)
    stager.options["Listener"]["Value"] = LISTENER
    with pytest.raises(StagerGenerationException):
        stager.generate()


# --------------------------------------------------------------------------- #
# cmd_exec (msfvenom-wrapped; subprocess stubbed)
# --------------------------------------------------------------------------- #
def test_cmd_exec_x64_builds_msfvenom_command(main, monkeypatch):
    captured = {}

    def fake_check_output(command, **kwargs):
        captured["command"] = command
        return b"SHELLCODE-BYTES"

    monkeypatch.setattr(cmd_exec.subprocess, "check_output", fake_check_output)

    stager = CmdExecStager(main)
    stager.options["Listener"]["Value"] = LISTENER
    stager.options["Arch"]["Value"] = "x64"
    stager.options["MSF_Format"]["Value"] = "exe"

    result = stager.generate()

    argv = captured["command"]
    assert result == b"SHELLCODE-BYTES"
    assert argv[:3] == ["msfvenom", "-p", "windows/x64/exec"]
    assert argv[argv.index("-f") + 1] == "exe"


def test_cmd_exec_x86_payload(main, monkeypatch):
    captured = {}
    monkeypatch.setattr(
        cmd_exec.subprocess,
        "check_output",
        lambda command, **k: captured.setdefault("command", command) or b"SC",
    )

    stager = CmdExecStager(main)
    stager.options["Listener"]["Value"] = LISTENER
    stager.options["Arch"]["Value"] = "x86"

    stager.generate()

    assert captured["command"][:3] == ["msfvenom", "-p", "windows/exec"]


def test_cmd_exec_empty_launcher_raises(main, monkeypatch):
    monkeypatch.setattr(main.stagergenv2, "generate_launcher", lambda *a, **k: "")
    stager = CmdExecStager(main)
    stager.options["Listener"]["Value"] = LISTENER
    with pytest.raises(StagerGenerationException):
        stager.generate()


def test_cmd_exec_msf_format_is_not_shell_interpreted(main, tmp_path, monkeypatch):
    """MSF_Format is an operator-supplied option; it must never reach a shell.

    subprocess is deliberately NOT stubbed here: the point is that no shell
    parses the command line at all. The marker assertion is host-independent --
    msfvenom does not need to be installed, because an unfixed `shell=True`
    splits on `;` before msfvenom's absence matters.

    The spy is what keeps this honest. generate() raises
    StagerGenerationException on several paths *before* the msfvenom call, and
    suppressing it means "no marker" would otherwise also be satisfied by never
    reaching the sink at all -- passing vacuously.
    """
    marker = tmp_path / "H2_PWNED"
    reached = []
    real_check_output = cmd_exec.subprocess.check_output

    def spy(command, **kwargs):
        reached.append(command)
        # On a host that does have msfvenom this really spawns it; cap it so a
        # wedged toolchain cannot hang the suite indefinitely.
        kwargs.setdefault("timeout", 60)
        return real_check_output(command, **kwargs)

    monkeypatch.setattr(cmd_exec.subprocess, "check_output", spy)

    stager = CmdExecStager(main)
    stager.options["Listener"]["Value"] = LISTENER
    stager.options["Arch"]["Value"] = "x64"
    stager.options["MSF_Format"]["Value"] = f"raw;touch {marker};"

    with contextlib.suppress(
        OSError,
        ValueError,
        subprocess.SubprocessError,
        StagerGenerationException,
    ):
        stager.generate()

    assert reached, "generate() never reached the msfvenom call; assertion is vacuous"
    assert not marker.exists()


def test_cmd_exec_passes_msf_format_as_a_single_argv_element(main, monkeypatch):
    captured = {}

    def fake_check_output(command, **kwargs):
        captured["command"] = command
        captured["kwargs"] = kwargs
        return b"SHELLCODE-BYTES"

    monkeypatch.setattr(cmd_exec.subprocess, "check_output", fake_check_output)

    tainted = "raw;touch /nonexistent/H2;"
    stager = CmdExecStager(main)
    stager.options["Listener"]["Value"] = LISTENER
    stager.options["Arch"]["Value"] = "x64"
    stager.options["MSF_Format"]["Value"] = tainted

    stager.generate()

    argv = captured["command"]
    assert isinstance(argv, list)
    assert not captured["kwargs"].get("shell")
    assert argv[argv.index("-f") + 1] == tainted
    assert len([element for element in argv if element.startswith("CMD=")]) == 1


@pytest.mark.parametrize(
    ("failure", "message"),
    [
        (FileNotFoundError(2, "No such file or directory", "msfvenom"), "not on the"),
        (subprocess.CalledProcessError(1, ["msfvenom"]), "exited with code 1"),
    ],
)
def test_cmd_exec_toolchain_failure_raises_a_stager_error(
    main, monkeypatch, failure, message
):
    """A missing or failing msfvenom must be a stager error, not a bare 500.

    Argv spawning raises FileNotFoundError where the old ``shell=True`` call let
    /bin/sh exit 127, and stager_service converts only StagerGenerationException.
    """

    def raise_failure(command, **kwargs):
        raise failure

    monkeypatch.setattr(cmd_exec.subprocess, "check_output", raise_failure)

    stager = CmdExecStager(main)
    stager.options["Listener"]["Value"] = LISTENER
    stager.options["Arch"]["Value"] = "x64"

    with pytest.raises(StagerGenerationException, match=message):
        stager.generate()


def test_cmd_exec_unsupported_arch_raises_a_stager_error(main):
    """Arch is Strict at the API, but the branch must still not fall through.

    Without the else, msf_payload stays unbound and the caller gets an
    UnboundLocalError, which stager_service does not convert.
    """
    stager = CmdExecStager(main)

    with pytest.raises(StagerGenerationException, match="Unsupported Arch"):
        stager.generate_shellcode("exe", "arm64", "launcher")


def test_cmd_exec_nul_in_msf_format_raises_a_stager_error(main):
    """A NUL byte in MSF_Format breaks the spawn before msfvenom is reached.

    argv spawning raises ValueError("embedded null byte"), which is neither
    FileNotFoundError nor CalledProcessError -- without the broadened handler
    it escapes as a bare 500 from a non-admin operator option.
    """
    stager = CmdExecStager(main)

    with pytest.raises(StagerGenerationException, match="Could not run msfvenom"):
        stager.generate_shellcode("raw\x00", "x64", "launcher")
