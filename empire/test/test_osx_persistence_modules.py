"""Generation tests for the Python custom_generate modules: a compile sweep
over all of them, and end-to-end runs of the emitted code for the three macOS
persistence modules that emitted Python 2 code
(https://github.com/BC-SECURITY/Empire/issues/828 and its follow-on findings).
"""

import base64
import io
import os
import plistlib
import re
import shutil
import struct
import sys
import tempfile
from pathlib import Path

import macholib.MachO
import pytest

from empire.server.common import helpers
from empire.server.core.config import config_manager
from empire.server.core.exceptions import ModuleValidationException
from empire.server.utils import module_util
from empire.server.utils.string_util import slugify

LISTENER = "new-listener-1"
MODULES_DIR = Path(__file__).parent.parent / "server" / "modules" / "python"
MISC = Path(__file__).parent.parent / "server" / "data" / "misc"

# Bytes with no Python 2.7 framework marker, so the server-side guard stays quiet.
STUB_MACHO = b"\xcf\xfa\xed\xfe" + b"\x00" * 60
EXECUTABLE = 0o755
READABLE = 0o644

# Characters a hand-written XML plist mangled; plistlib must round-trip them.
HOSTILE_LAUNCHER = """import os;x='<a&b>' + "q\\"q" + '\\\\'"""

LAUNCH_AGENT = "python_persistence_osx_launchagent"
USERLAND = "python_persistence_osx_launchagentuserlandpersistence"
HIJACKER = "python_persistence_osx_createhijacker"
SHELLCODE = "python_management_osx_shellcodeinject64"

# A bytes object formatted into emitted source renders as "b'...'" and the
# agent-side base64 decode then produces garbage.
BYTES_IN_SOURCE = re.compile(r"""["']b['"]""")

# Modules whose default options cannot generate without a prerequisite file.
# Anything else raising ModuleValidationException on defaults is a regression.
EXPECTED_PREREQ_SKIPS = {SHELLCODE}


def _mode(path):
    return path.stat().st_mode & 0o777


def _module_ids():
    # Every custom_generate module is a .py beside its YAML; the loader derives
    # the id the same way and _generate asserts the module actually loaded.
    return [
        slugify(p.relative_to(MODULES_DIR.parent).with_suffix("").as_posix())
        for p in sorted(MODULES_DIR.rglob("*.py"))
    ]


def _generate(main, module_id, overrides=None):
    """Generate a module's agent code through the real server with default options."""
    module = main.modulesv2.get_by_id(module_id)
    assert module is not None, f"module {module_id} not loaded"
    params = {opt.name: opt.value for opt in module.options}
    if "Listener" in params:
        params["Listener"] = LISTENER
    params.update(overrides or {})
    cls = main.modulesv2._load_custom_generate_class(module)
    # Positional, because @auto_get_source-decorated modules index args[3:5].
    code = cls.generate(main, module, params, False, "")
    if isinstance(code, tuple):
        code = code[0]
    assert isinstance(code, str), f"{module_id} returned {type(code)}"
    return code


def _agent_view(code):
    """What the agent actually compiles: execute_module strips comments first."""
    return helpers.strip_python_comments(code)


def _run_agent_code(code, expect=None):
    """Execute emitted module code the way agent.py does: print captured.

    With `expect`, the code must raise that exception type.
    """
    buf = io.StringIO()
    g = {"print": lambda *a, **k: print(*a, **k, file=buf)}
    # Restrictive umask so the emitted os.chmod calls are what set the modes
    # the tests assert on; without it 0o644 is just the default for new files.
    old_umask = os.umask(0o077)
    try:
        if expect is None:
            exec(compile(_agent_view(code), "<module>", "exec"), g)
        else:
            with pytest.raises(expect):
                exec(compile(_agent_view(code), "<module>", "exec"), g)
    finally:
        os.umask(old_umask)
    return buf.getvalue()


@pytest.fixture
def stub_binaries(main, monkeypatch):
    monkeypatch.setattr(
        main.stagergenv2, "generate_macho", lambda launcher_code: STUB_MACHO
    )
    monkeypatch.setattr(
        main.stagergenv2,
        "generate_dylib",
        lambda launcher_code, arch, hijacker: STUB_MACHO,
    )
    monkeypatch.setattr(
        main.stagergenv2, "generate_appbundle", lambda *a, **k: b"PK\x03\x04"
    )


not_root = pytest.mark.skipif(
    os.geteuid() == 0, reason="module writes to system paths when run as root"
)


# --------------------------------------------------------------------------- #
# Guard helper and compile sweep
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    ("binary", "fragment"),
    [
        (
            b"\xcf\xfa\xed\xfe/System/Library/Frameworks/Python.framework/Versions/2.7/Python",
            "Python 2.7",
        ),
        ("", "could not be patched"),
        (None, "could not be patched"),
    ],
)
def test_ensure_python3_macho_template_rejects(binary, fragment):
    with pytest.raises(ModuleValidationException) as exc:
        module_util.ensure_python3_macho_template(binary, "machotemplate")
    assert fragment in str(exc.value)
    assert "machotemplate" in str(exc.value)


def test_ensure_python3_macho_template_accepts_other_bytes():
    module_util.ensure_python3_macho_template(STUB_MACHO, "machotemplate")


@pytest.mark.parametrize("module_id", _module_ids())
def test_python_custom_generate_modules_compile(main, stub_binaries, module_id):
    try:
        code = _generate(main, module_id)
    except ModuleValidationException as e:
        if module_id in EXPECTED_PREREQ_SKIPS:
            pytest.skip(
                f"{module_id} needs a prerequisite this test cannot supply: {e}"
            )
        raise
    assert module_id not in EXPECTED_PREREQ_SKIPS, (
        "allowlisted module now generates; remove it"
    )
    compile(_agent_view(code), module_id, "exec")
    assert not BYTES_IN_SOURCE.search(code), "bytes object formatted into source"


def test_shellcodeinject64_rejects_missing_or_directory_path(main, tmp_path):
    for bad in ("", str(tmp_path)):
        with pytest.raises(ModuleValidationException):
            _generate(main, SHELLCODE, {"Shellcode": bad})


def test_shellcodeinject64_generates_from_real_file(main, tmp_path, monkeypatch):
    # Shellcode is confined to the downloads root, so point that at a scratch dir.
    monkeypatch.setattr(config_manager.empire_config.directories, "downloads", tmp_path)
    shellcode = tmp_path / "sc.bin"
    shellcode.write_bytes(b"\x90\x90\xcc")
    code = _generate(main, SHELLCODE, {"Shellcode": str(shellcode), "PID": "4242"})
    compile(_agent_view(code), SHELLCODE, "exec")
    assert base64.b64encode(b"\x90\x90\xcc").decode() in code
    assert "4242" in code


# --------------------------------------------------------------------------- #
# LaunchAgent
# --------------------------------------------------------------------------- #
@not_root
def test_launch_agent_installs_daemon_and_plist(
    main, stub_binaries, tmp_path, monkeypatch
):
    monkeypatch.setenv("HOME", str(tmp_path))
    code = _generate(main, LAUNCH_AGENT, {"DaemonName": "com.test.it's.daemon"})
    # The 828 fix: no shell, no /tmp staging.
    assert "subprocess" not in code
    assert "shell=True" not in code
    assert "/tmp/" not in code

    out = _run_agent_code(code)

    daemon = (
        tmp_path / "Library" / "Application Support" / "com.test.it's.daemon" / "daemon"
    )
    plist_path = tmp_path / "Library" / "LaunchAgents" / "com.test.it's.daemon.plist"
    assert daemon.read_bytes() == STUB_MACHO
    assert _mode(daemon) == EXECUTABLE
    assert _mode(plist_path) == READABLE
    plist = plistlib.loads(plist_path.read_bytes())
    assert plist["Label"] == "com.test.it's.daemon"
    assert plist["ProgramArguments"] == [str(daemon)]
    assert plist["RunAtLoad"] is True
    assert plist["KeepAlive"] is True
    assert "Persistence has been installed" in out


def test_launch_agent_refuses_py27_template(main):
    with pytest.raises(ModuleValidationException) as exc:
        _generate(main, LAUNCH_AGENT)
    assert "Python 2.7" in str(exc.value)


# --------------------------------------------------------------------------- #
# LaunchAgentUserLandPersistence
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    ("plist_name", "expected_file", "expected_label"),
    [
        ("com.test.userland.plist", "com.test.userland.plist", "com.test.userland"),
        ("com.test.nosuffix", "com.test.nosuffix.plist", "com.test.nosuffix"),
    ],
)
def test_userland_plist_uses_agent_interpreter(
    main, tmp_path, monkeypatch, plist_name, expected_file, expected_label
):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setattr(
        main.stagergenv2, "generate_launcher", lambda *a, **k: HOSTILE_LAUNCHER
    )
    code = _generate(main, USERLAND, {"PLISTName": plist_name})

    out = _run_agent_code(code)

    plist_path = tmp_path / "Library" / "LaunchAgents" / expected_file
    assert _mode(plist_path) == READABLE
    plist = plistlib.loads(plist_path.read_bytes())
    assert plist["ProgramArguments"] == [sys.executable, "-c", HOSTILE_LAUNCHER]
    assert plist["Label"] == expected_label
    assert plist["RunAtLoad"] is True
    assert "Persistence has been installed" in out


def test_userland_falls_back_to_which_when_executable_is_not_python(
    main, tmp_path, monkeypatch
):
    monkeypatch.setenv("HOME", str(tmp_path))
    code = _generate(main, USERLAND)
    # The emitted script imports the real modules, so patch their attributes.
    monkeypatch.setattr(sys, "executable", "/Applications/Host.app/Contents/MacOS/Host")
    monkeypatch.setattr(shutil, "which", lambda name: "/opt/py/bin/python3")

    _run_agent_code(code)

    plist_path = tmp_path / "Library" / "LaunchAgents" / "com.proxy.initialize.plist"
    plist = plistlib.loads(plist_path.read_bytes())
    assert plist["ProgramArguments"][0] == "/opt/py/bin/python3"


def test_userland_aborts_without_interpreter(main, tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    code = _generate(main, USERLAND)
    monkeypatch.setattr(sys, "executable", "")
    monkeypatch.setattr(shutil, "which", lambda name: None)

    _run_agent_code(code, expect=RuntimeError)

    assert not (tmp_path / "Library" / "LaunchAgents").exists()


# --------------------------------------------------------------------------- #
# CreateHijacker: real Mach-O patching against the shipped templates
# --------------------------------------------------------------------------- #
LC_ID_DYLIB = 0xD
LC_REEXPORT_DYLIB = 0x8000001F


def _dylib_commands(path):
    """Return {cmd: (file_offset, dylib_command, name_bytes)} for the first header."""
    header = macholib.MachO.MachO(str(path)).headers[0]
    out = {}
    offset = header.offset + header.mach_header._size_
    for lc, cmd, data in header.commands:
        if type(cmd).__name__ == "dylib_command":
            out[lc.cmd] = (offset, cmd, data)
        offset += lc.cmdsize
    return out


def _rewrite_id_versions(path, current, compat):
    offset, _cmd, _data = _dylib_commands(path)[LC_ID_DYLIB]
    with Path(path).open("r+b") as f:
        # load_command header (8) + lc_str name offset (4) + timestamp (4)
        f.seek(offset + 8 + 4 + 4)
        f.write(struct.pack("<LL", current, compat))


def _hijacker_template_without_marker(name="template64.dylib"):
    data = (MISC / "hijackers" / name).read_bytes()
    marker = module_util.PY27_FRAMEWORK_MARKER
    assert marker in data
    return data.replace(marker, b"X" * len(marker))


@pytest.fixture
def agent_tmp(tmp_path, monkeypatch):
    """Where the emitted script's mkstemp lands; must be empty after every run."""
    path = tmp_path / "tmp"
    path.mkdir()
    monkeypatch.setattr(tempfile, "tempdir", str(path))
    return path


@pytest.fixture
def hijacker_params(main, tmp_path, monkeypatch, agent_tmp):
    """Option overrides for a 64-bit hijack of a copied launcher template."""
    target = tmp_path / "target" / "templateLauncher64.dylib"
    target.parent.mkdir()
    shutil.copy2(MISC / "templateLauncher64.dylib", target)
    # Both templates ship as 1.0.0, so give the target distinct versions.
    _rewrite_id_versions(target, 0x00020003, 0x00010004)
    monkeypatch.setattr(
        main.stagergenv2,
        "generate_dylib",
        lambda launcher_code, arch, hijacker: _hijacker_template_without_marker(),
    )
    return {
        "Arch": "x64",
        "LegitimateDylibPath": str(target),
        "VulnerableRPATH": str(tmp_path / "planted" / "templateLauncher64.dylib"),
    }


def _assert_hijack_failed(main, params, agent_tmp, message):
    out = _run_agent_code(_generate(main, HIJACKER, params), expect=RuntimeError)
    assert "[!] CreateHijacker FAILED" in out
    assert message in out
    assert not Path(params["VulnerableRPATH"]).is_file()
    assert list(agent_tmp.iterdir()) == [], "attacker temp file was not removed"


def test_create_hijacker_patches_dylib_end_to_end(main, hijacker_params, agent_tmp):
    code = _generate(main, HIJACKER, hijacker_params)
    # The old script hard-coded "/tmp/" + uuid; operator paths may legitimately
    # live under /tmp (pytest's tmp_path does), so check the literal only.
    assert '"/tmp/"' not in code
    assert "mkstemp" in code

    out = _run_agent_code(code)

    planted = Path(hijacker_params["VulnerableRPATH"])
    assert planted.exists(), out
    assert _mode(planted) == EXECUTABLE
    assert list(agent_tmp.iterdir()) == [], "attacker temp file was not removed"

    cmds = _dylib_commands(planted)
    _off, id_cmd, _name = cmds[LC_ID_DYLIB]
    # macholib renders packed versions as major.minor.rev
    assert str(id_cmd.current_version) == "2.0.3"
    assert str(id_cmd.compatibility_version) == "1.0.4"
    _off, _reexport, name = cmds[LC_REEXPORT_DYLIB]
    assert name.rstrip(b"\x00") == hijacker_params["LegitimateDylibPath"].encode()
    assert "Hijacker configured" in out


def test_create_hijacker_rejects_overlong_target_path(
    main, hijacker_params, agent_tmp, tmp_path
):
    long_dir = tmp_path / ("x" * 200)
    long_dir.mkdir()
    long_target = long_dir / "templateLauncher64.dylib"
    shutil.copy2(MISC / "templateLauncher64.dylib", long_target)
    hijacker_params["LegitimateDylibPath"] = str(long_target)

    _assert_hijack_failed(main, hijacker_params, agent_tmp, "too long")


def test_create_hijacker_missing_target_cleans_up(
    main, hijacker_params, agent_tmp, tmp_path
):
    hijacker_params["LegitimateDylibPath"] = str(tmp_path / "does-not-exist.dylib")

    _assert_hijack_failed(main, hijacker_params, agent_tmp, "not found")


def test_create_hijacker_architecture_mismatch(
    main, hijacker_params, agent_tmp, monkeypatch
):
    monkeypatch.setattr(
        main.stagergenv2,
        "generate_dylib",
        lambda launcher_code, arch, hijacker: _hijacker_template_without_marker(
            "template.dylib"
        ),
    )
    hijacker_params["Arch"] = "x86"

    _assert_hijack_failed(main, hijacker_params, agent_tmp, "Architecture mismatch")


def test_create_hijacker_rejects_directory_rpath(
    main, hijacker_params, agent_tmp, tmp_path
):
    (tmp_path / "planted").mkdir()
    hijacker_params["VulnerableRPATH"] = str(tmp_path / "planted")

    _assert_hijack_failed(main, hijacker_params, agent_tmp, "must be a full file path")
    assert list((tmp_path / "planted").iterdir()) == []


@pytest.mark.parametrize(
    ("arch", "template"), [("x86", "template.dylib"), ("x64", "template64.dylib")]
)
def test_create_hijacker_refuses_py27_template(main, arch, template):
    overrides = {
        "Arch": arch,
        "LegitimateDylibPath": "/x/y.dylib",
        "VulnerableRPATH": "/x/z.dylib",
    }
    with pytest.raises(ModuleValidationException) as exc:
        _generate(main, HIJACKER, overrides)
    assert "Python 2.7" in str(exc.value)
    assert template in str(exc.value)
