import base64
import logging
import subprocess
import tempfile
import zlib
from pathlib import Path

from empire.server.common.helpers import random_string
from empire.server.core.config.config_manager import empire_config
from empire.server.core.config.data_manager import (
    CompilerSyncError,
    sync_empire_compiler,
)
from empire.server.core.exceptions import ModuleExecutionException

log = logging.getLogger(__name__)

_COMPILER_UNAVAILABLE_MSG = (
    "Empire Compiler is not available. It could not be downloaded or extracted "
    "at startup (see the server log for the cause). Set GITHUB_TOKEN in the "
    "environment, configure empire_compiler.directory to a local build, or "
    "re-run './ps-empire setup' once GitHub is reachable, then restart."
)


class DotnetCompiler:
    def __init__(self, install_path):
        self.install_path = install_path
        # Don't hard-crash startup: C# compilation is opt-in, so a cold cache
        # on an offline or throttled host degrades to a clear error at the
        # first compile request instead of taking down the whole server.
        self.compiler_dir: Path | None = None
        try:
            compiler_root = sync_empire_compiler(empire_config.empire_compiler)
        except CompilerSyncError:
            log.exception(_COMPILER_UNAVAILABLE_MSG)
            return
        if compiler_root is None:
            log.error(_COMPILER_UNAVAILABLE_MSG)
            return
        self.compiler_dir = compiler_root / "EmpireCompiler"

    def require_available(self) -> None:
        """Raise the operator-facing error if startup left no compiler behind.

        Deliberately no re-sync here (issue 1319 floated one): a compile
        request should not do network I/O, and the operator is told to run
        setup and restart instead.
        """
        if self.compiler_dir is None:
            raise ModuleExecutionException(_COMPILER_UNAVAILABLE_MSG)

    def embedded_resources_dir(self) -> Path:
        """Where stager launchers are written for the compiler to embed."""
        self.require_available()
        return self.compiler_dir / "Data" / "EmbeddedResources" / "common"

    def compile_task(
        self,
        compiler_yaml,
        task_name,
        dot_net_version="net40",
        confuse=False,
        merge_references=False,
    ) -> Path:
        self.require_available()

        random_task_name = f"{task_name}_{random_string(6)}.exe"

        with tempfile.NamedTemporaryFile(delete=False) as temp_file:
            output_path = temp_file.name
            args = [
                "./EmpireCompiler",
                "--output",
                output_path,
                "--dotnet-version",
                dot_net_version,
                "--yaml",
                base64.b64encode(compiler_yaml.encode("UTF-8")).decode("UTF-8"),
            ]

            if confuse:
                args.extend(["--confuse"])

            if merge_references:
                args.extend(["--merge-references"])

            log.debug(
                f"Compiler args: merge_references={merge_references}, args={args}"
            )

            result = subprocess.run(
                args,
                capture_output=True,
                text=True,
                check=False,
                cwd=self.compiler_dir,
            )

            if result.stderr:
                log.warning(f"Compiler stderr: {result.stderr.strip()}")

            if result.returncode != 0:
                log.error(
                    "EmpireCompiler failed (rc=%d)\nstdout: %s\nstderr: %s",
                    result.returncode,
                    result.stdout,
                    result.stderr,
                )
                detail = (
                    result.stderr.strip()
                    or result.stdout.strip()
                    or "<no output — likely killed by signal, check OOM/AV/cgroup limits>"
                )
                raise ModuleExecutionException(
                    f"EmpireCompiler execution failed (rc={result.returncode}): {detail}"
                )

            if "Final Task Path:" not in result.stdout.strip():
                log.error(result.stdout)
                raise ModuleExecutionException("Module compile failed")

            exe_location = Path(output_path)
            exe_location = exe_location.rename(exe_location.with_name(random_task_name))
            compiled_location = exe_location.with_suffix(".compiled")

            data_bytes = exe_location.read_bytes()
            encoded_data = zlib.compress(data_bytes, level=-1)[2:-4]
            compiled_location.write_bytes(encoded_data)

            return compiled_location

    def compile_stager(
        self, compiler_yaml, task_name, dot_net_version="net40", confuse=False
    ) -> Path:
        self.require_available()

        random_task_name = f"{task_name}_{random_string(4)}.exe"

        with tempfile.NamedTemporaryFile(delete=False) as temp_file:
            output_path = temp_file.name
            args = [
                "./EmpireCompiler",
                "--output",
                output_path,
                "--dotnet-version",
                dot_net_version,
                "--yaml",
                base64.b64encode(compiler_yaml.encode("UTF-8")).decode("UTF-8"),
            ]

            if confuse:
                args.extend(["--confuse"])

            result = subprocess.run(
                args,
                capture_output=True,
                text=True,
                check=False,
                cwd=self.compiler_dir,
            )

            if result.returncode != 0:
                log.error(
                    "EmpireCompiler failed (rc=%d)\nstdout: %s\nstderr: %s",
                    result.returncode,
                    result.stdout,
                    result.stderr,
                )
                detail = (
                    result.stderr.strip()
                    or result.stdout.strip()
                    or "<no output — likely killed by signal, check OOM/AV/cgroup limits>"
                )
                raise ModuleExecutionException(
                    f"EmpireCompiler execution failed (rc={result.returncode}): {detail}"
                )

            if "Final Task Path:" not in result.stdout.strip():
                log.error(result.stdout)
                raise ModuleExecutionException("Stager compile failed")

        exe_location = Path(output_path)
        return exe_location.rename(exe_location.with_name(random_task_name))
