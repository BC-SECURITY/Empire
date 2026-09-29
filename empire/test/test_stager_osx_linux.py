"""Generation tests for the osx/application, osx/dylib, linux/bash, and
linux/pyinstaller stagers.

osx/application, osx/dylib and linux/pyinstaller delegate the final packaging to
generate_appbundle / generate_dylib / the pyinstaller toolchain (env-gated);
those are stubbed so the tests cover the launcher preprocessing and guards.
linux/bash is a pure text generator.
"""

import subprocess
from pathlib import Path

import pytest

from empire.server.core.exceptions import StagerGenerationException
from empire.server.stagers.linux import pyinstaller
from empire.server.stagers.linux.bash import Stager as LinuxBashStager
from empire.server.stagers.linux.pyinstaller import Stager as PyInstallerStager
from empire.server.stagers.osx.application import Stager as OsxAppStager
from empire.server.stagers.osx.dylib import Stager as OsxDylibStager

LISTENER = "new-listener-1"


# --------------------------------------------------------------------------- #
# linux/bash
# --------------------------------------------------------------------------- #
def test_linux_bash_builds_self_deleting_script(main):
    stager = LinuxBashStager(main)
    stager.options["Listener"]["Value"] = LISTENER

    code = stager.generate()

    assert code.startswith("#!/bin/bash\n")
    assert 'rm -f "$0"' in code
    assert code.endswith("exit\n")
    # A python launcher is embedded between the shebang and the self-delete.
    assert len(code.splitlines()) >= 4  # noqa: PLR2004


def test_linux_bash_empty_launcher_raises(main, monkeypatch):
    monkeypatch.setattr(main.stagergenv2, "generate_launcher", lambda *a, **k: "")
    stager = LinuxBashStager(main)
    stager.options["Listener"]["Value"] = LISTENER
    with pytest.raises(StagerGenerationException):
        stager.generate()


# --------------------------------------------------------------------------- #
# osx/application
# --------------------------------------------------------------------------- #
def test_osx_application_preprocesses_launcher_and_packages(main, monkeypatch):
    captured = {}

    def fake_appbundle(**kwargs):
        captured.update(kwargs)
        return b"APP-BUNDLE-ZIP"

    monkeypatch.setattr(main.stagergenv2, "generate_appbundle", fake_appbundle)

    stager = OsxAppStager(main)
    stager.options["Listener"]["Value"] = LISTENER
    stager.options["Architecture"]["Value"] = "x64"

    result = stager.generate()

    assert result == b"APP-BUNDLE-ZIP"
    # The python "echo ... | python3 &" wrapper is stripped before packaging.
    assert captured["launcher_code"]
    assert "echo " not in captured["launcher_code"]
    assert "| python3 &" not in captured["launcher_code"]
    assert captured["arch"] == "x64"


def test_osx_application_empty_launcher_raises(main, monkeypatch):
    monkeypatch.setattr(main.stagergenv2, "generate_launcher", lambda *a, **k: "")
    stager = OsxAppStager(main)
    stager.options["Listener"]["Value"] = LISTENER
    with pytest.raises(StagerGenerationException):
        stager.generate()


# --------------------------------------------------------------------------- #
# osx/dylib
# --------------------------------------------------------------------------- #
def test_osx_dylib_preprocesses_launcher_and_builds(main, monkeypatch):
    captured = {}

    def fake_dylib(**kwargs):
        captured.update(kwargs)
        return b"DYLIB-BYTES"

    monkeypatch.setattr(main.stagergenv2, "generate_dylib", fake_dylib)

    stager = OsxDylibStager(main)
    stager.options["Listener"]["Value"] = LISTENER
    stager.options["Architecture"]["Value"] = "x64"
    stager.options["Hijacker"]["Value"] = False

    result = stager.generate()

    assert result == b"DYLIB-BYTES"
    assert captured["arch"] == "x64"
    assert "echo " not in captured["launcher_code"]


def test_osx_dylib_missing_arch_raises(main):
    stager = OsxDylibStager(main)
    stager.options["Listener"]["Value"] = LISTENER
    stager.options["Architecture"]["Value"] = ""
    with pytest.raises(StagerGenerationException, match="valid architecture"):
        stager.generate()


def test_osx_dylib_empty_launcher_raises(main, monkeypatch):
    monkeypatch.setattr(main.stagergenv2, "generate_launcher", lambda *a, **k: "")
    stager = OsxDylibStager(main)
    stager.options["Listener"]["Value"] = LISTENER
    stager.options["Architecture"]["Value"] = "x64"
    with pytest.raises(StagerGenerationException):
        stager.generate()


# --------------------------------------------------------------------------- #
# linux/pyinstaller
# --------------------------------------------------------------------------- #
@pytest.fixture
def fake_pyinstaller(monkeypatch):
    """Stand in for the pyinstaller toolchain, which is not installed on CI.

    The fake reads --distpath and --onefile out of the argv it is handed and
    drops a binary where the real pyinstaller would, so generate() still runs
    end to end and returns real bytes. The captured argv is the assertion
    surface for the confinement tests.
    """
    captured = {}

    # setattr on pyinstaller.shutil patches the real module, so this must answer
    # only for the binary the stager looks up and delegate to the real lookup
    # for anything else reached during generate() -- returning None for those
    # would tell every other caller its toolchain is missing.
    real_which = pyinstaller.shutil.which

    def fake_which(name, *a, **k):
        if name == "pyinstaller":
            return "/usr/bin/pyinstaller"
        return real_which(name, *a, **k)

    monkeypatch.setattr(pyinstaller.shutil, "which", fake_which)

    def fake_run(argv, **kwargs):
        captured["argv"] = argv
        dist_path = Path(argv[argv.index("--distpath") + 1])
        work_path = Path(argv[argv.index("--workpath") + 1])
        source = Path(argv[argv.index("--onefile") + 1])
        # Real pyinstaller creates its work directory; reproducing that is what
        # lets these tests see a collision between it and the artifact.
        work_path.mkdir(parents=True, exist_ok=True)
        dist_path.mkdir(parents=True, exist_ok=True)
        # Real pyinstaller names the onefile artifact after the source stem.
        (dist_path / source.stem).write_bytes(b"FAKE-BINARY")
        return subprocess.CompletedProcess(argv, 0)

    monkeypatch.setattr(pyinstaller.subprocess, "run", fake_run)
    return captured


@pytest.mark.parametrize("shape", ["absolute", "traversal"])
def test_pyinstaller_never_writes_to_the_operator_supplied_path(
    main, fake_pyinstaller, tmp_path, shape
):
    """BinaryFile is a scratch path, not a delivery destination.

    No traversal is needed to exploit the unfixed sink -- BinaryFile is not
    relative to anything, so a plain absolute path is the load-bearing case.
    Both target directories must already exist: write_text() does not create
    parents, so a PoC pointing through a missing directory fails with
    FileNotFoundError even against the unfixed sink and yields a tautological
    guard.
    """
    outside = tmp_path / "outside"
    outside.mkdir()
    intended = tmp_path / "intended"
    intended.mkdir()

    if shape == "absolute":
        binary_file = outside / "ARBITRARY"
        written = outside / "ARBITRARY.py"
    else:
        binary_file = intended / ".." / "ESCAPED"
        written = tmp_path / "ESCAPED.py"

    stager = PyInstallerStager(main)
    stager.options["Listener"]["Value"] = LISTENER
    stager.options["BinaryFile"]["Value"] = str(binary_file)

    result = stager.generate()

    assert result == b"FAKE-BINARY"
    assert not written.exists()
    assert not written.with_suffix(".spec").exists()


def test_pyinstaller_builds_in_a_temp_dir_and_keeps_the_basename(
    main, fake_pyinstaller, tmp_path
):
    outside = tmp_path / "outside"
    outside.mkdir()

    stager = PyInstallerStager(main)
    stager.options["Listener"]["Value"] = LISTENER
    stager.options["BinaryFile"]["Value"] = str(outside / "ARBITRARY")

    stager.generate()

    argv = fake_pyinstaller["argv"]
    build_dir = Path(argv[argv.index("--distpath") + 1])
    spec_path = Path(argv[argv.index("--specpath") + 1])
    work_path = Path(argv[argv.index("--workpath") + 1])

    assert spec_path == build_dir
    assert build_dir != outside
    assert outside not in build_dir.parents
    # Siblings under one temp root: nested would collide (see the test below).
    assert build_dir not in work_path.parents
    assert work_path.parent == build_dir.parent
    # The operator's chosen name still names the artifact; only the directory
    # component -- the part that was purely a server-side side effect -- is dropped.
    assert Path(argv[-1]).name == "ARBITRARY.py"
    assert Path(argv[-1]).parent == build_dir


@pytest.mark.parametrize("basename", ["build", "dist", "work"])
def test_pyinstaller_binary_name_cannot_collide_with_the_build_dirs(
    main, fake_pyinstaller, basename
):
    """The operator's BinaryFile name must not be able to claim a build directory.

    pyinstaller creates --workpath as a directory. While it lived under
    --distpath, a BinaryFile of "/tmp/build" made the work directory and the
    artifact the same path, and generate() died on IsADirectoryError -- an
    uncaught 500, since stager_service only converts StagerGenerationException.
    """
    stager = PyInstallerStager(main)
    stager.options["Listener"]["Value"] = LISTENER
    stager.options["BinaryFile"]["Value"] = f"/tmp/{basename}"

    assert stager.generate() == b"FAKE-BINARY"


@pytest.mark.parametrize(
    "binary_name", ["agent.bin", "launcher.elf", "empire.py", "empire.spec"]
)
def test_pyinstaller_keeps_a_dotted_binary_name(main, fake_pyinstaller, binary_name):
    """A BinaryFile with an extension must still name the artifact that is read.

    The source path is built by appending ".py", not substituting it: with
    with_suffix() a BinaryFile of "agent.bin" builds "agent.py", pyinstaller
    emits "agent", and the read misses -- FileNotFoundError, an uncaught 500.
    "empire.py" is the nastier shape: source and artifact collapse onto one
    path and the operator is handed the plaintext launcher source as the ELF.
    """
    stager = PyInstallerStager(main)
    stager.options["Listener"]["Value"] = LISTENER
    stager.options["BinaryFile"]["Value"] = binary_name

    assert stager.generate() == b"FAKE-BINARY"

    argv = fake_pyinstaller["argv"]
    assert Path(argv[-1]).name == f"{binary_name}.py"


@pytest.mark.parametrize(
    "binary_file", ["", ".", "..", "/", "some/dir/..", "agent\x00.bin"]
)
def test_pyinstaller_rejects_a_binary_file_without_a_name(
    main, fake_pyinstaller, binary_file
):
    """Every clause of safe_filename() is load-bearing here.

    Without the empty-name clause, "." and "/" leave binary_path pointing at the
    dist directory itself; without the ".." clause it points at dist's parent.
    Either way the read below dies with IsADirectoryError, which stager_service
    does not convert. A NUL byte instead reaches write_text() and raises
    ValueError -- the same uncaught 500 one step later.
    """
    stager = PyInstallerStager(main)
    stager.options["Listener"]["Value"] = LISTENER
    stager.options["BinaryFile"]["Value"] = binary_file

    with pytest.raises(StagerGenerationException, match="must include a file name"):
        stager.generate()


def test_pyinstaller_unwritable_binary_name_raises_a_stager_error(
    main, fake_pyinstaller
):
    """A BinaryFile past NAME_MAX fails the source write, not the build.

    safe_filename() cannot catch this one -- the name is well formed, the
    filesystem just will not take it -- so the write needs its own conversion
    or the OSError escapes as an opaque 500.
    """
    stager = PyInstallerStager(main)
    stager.options["Listener"]["Value"] = LISTENER
    stager.options["BinaryFile"]["Value"] = "A" * 300

    with pytest.raises(StagerGenerationException, match="Could not write"):
        stager.generate()


def test_pyinstaller_build_failure_raises_a_stager_error(
    main, fake_pyinstaller, monkeypatch
):
    """A failed build must not fall through to read_bytes().

    The temp directory deletes the .py, .spec and work tree on the way out, so
    a bare FileNotFoundError here is a 500 with neither a message nor any
    evidence left to look at.
    """
    monkeypatch.setattr(
        pyinstaller.subprocess,
        "run",
        lambda argv, **kwargs: subprocess.CompletedProcess(argv, 1),
    )

    stager = PyInstallerStager(main)
    stager.options["Listener"]["Value"] = LISTENER

    with pytest.raises(StagerGenerationException, match="pyinstaller exited"):
        stager.generate()
