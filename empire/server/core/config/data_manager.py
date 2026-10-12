import logging
import os
import platform
import pwd
import shutil
import subprocess
import tarfile
import tempfile
import time
from pathlib import Path

import requests
import urllib3
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from empire.server.core.config import config_manager, paths
from empire.server.core.config.config_manager import (
    EmpireCompilerConfig,
    PluginRegistryConfig,
    StarkillerConfig,
)
from empire.server.utils.file_util import run_as_user
from empire.server.utils.git_util import GitOperationException, clone_git_repo

log = logging.getLogger(__name__)

_FIX_DIRECTORY_HINT = (
    "Fix `starkiller.directory` in config.user.yaml, or unset it to clone from GitHub."
)


def resolve_starkiller_dist(starkiller_dir: Path) -> Path | None:
    """Find the servable build under a Starkiller root, or None if there isn't
    one.

    Both layouts are legitimate. A git checkout keeps its build in `dist/`; a
    packaged build flattens that away -- the nixpkgs derivation does
    `cp -r dist/** $out`, and the level above `$out` is `/nix/store`, so that
    package has no `dist/` parent it could name. Accepting both also means
    pointing at `dist/` itself works, which is the likeliest operator mistake.

    `dist/` wins when both match: a built checkout also carries an index.html at
    its root, but that one is Vite's entry template (`src="/src/main.js"`), not a
    build -- serving it yields a blank UI. That template is also why an
    index.html alone isn't proof of a build; `package.json` discriminates, since
    every source checkout has one and no build output does.

    Keying on index.html rather than on `dist/` merely existing keeps an
    interrupted `npm run build` -- or an unrelated project's `dist/` of wheels --
    from being mounted.
    """
    if (starkiller_dir / "dist" / "index.html").is_file():
        return starkiller_dir / "dist"
    if (starkiller_dir / "index.html").is_file() and not (
        starkiller_dir / "package.json"
    ).is_file():
        return starkiller_dir
    return None


def _starkiller_layout_hint(starkiller_dir: Path) -> str:
    """Operator-facing advice for a directory that exists but holds no build.
    Only meaningful when `resolve_starkiller_dist` has already returned None.
    """
    if (starkiller_dir / "package.json").is_file():
        return (
            "That looks like a Starkiller source checkout that has not been "
            "built -- run the build first, then point `starkiller.directory` "
            "at the checkout or at its dist/ output."
        )
    if (starkiller_dir / "dist").is_dir():
        # Saying "point at a directory containing dist/" here would be a dead
        # end -- they did. The dist/ is the incomplete thing.
        return (
            "There is a dist/ there, but it has no index.html, so the build is "
            "incomplete -- re-run the Starkiller build."
        )
    return (
        "`starkiller.directory` must point at a built Starkiller: either a "
        "directory containing dist/, or the build output itself (an index.html "
        "beside its assets)."
    )


def starkiller_directory_problem(starkiller_dir: Path) -> str | None:
    """Why `starkiller_dir` can't be served, or None when it holds a build.

    Single source for the diagnosis so the server's boot warning and
    `setup`/`update`'s validation can't drift apart on the wording.
    """
    if not starkiller_dir.is_dir():
        if str(starkiller_dir).startswith("~"):
            # Expansion left the `~` in place, so there is no home to resolve
            # (unset $HOME, an unmapped uid, no such user). Diagnosed after
            # `is_dir` so a literal `~name` directory that really exists is
            # still servable, and separately from the "not a directory" case
            # because the path it names may well exist -- what failed is the
            # expansion, and no amount of checking the spelling reveals that.
            return (
                f"configured directory '{starkiller_dir}' begins with `~`, but "
                f"this process has no resolvable home directory, so it could "
                f"not be expanded. Use a literal absolute path. "
                f"{_FIX_DIRECTORY_HINT}"
            )
        return (
            f"configured directory '{starkiller_dir}' is not a directory "
            f"(or does not exist). {_FIX_DIRECTORY_HINT}"
        )
    if resolve_starkiller_dist(starkiller_dir) is None:
        return (
            f"configured directory '{starkiller_dir}' contains no Starkiller "
            f"build. {_starkiller_layout_hint(starkiller_dir)} "
            f"{_FIX_DIRECTORY_HINT}"
        )
    return None


def _starkiller_override_dir(starkiller_config: StarkillerConfig) -> Path | None:
    """The configured `directory`, expanded, or None when there is no override.

    `os.path.expanduser` rather than `Path.expanduser`: the latter raises
    `RuntimeError` for a `~user` with no resolvable home (an unmapped uid in a
    container, a typo'd username), which would abort `setup`/`update` on a
    traceback instead of reporting the path as bad.
    """
    if not starkiller_config.directory:
        return None
    return Path(os.path.expanduser(starkiller_config.directory))  # noqa: PTH111


def sync_starkiller(starkiller_config: StarkillerConfig) -> Path:
    local_dir = _starkiller_override_dir(starkiller_config)
    if local_dir is not None:
        # Never fall back to a clone: this override exists for air-gapped and
        # distro-packaged installs, where a silent GitHub fetch would serve
        # upstream Starkiller in place of the operator's vetted build.
        if local_dir.is_dir():
            log.info(f"Starkiller: using local directory {local_dir}")
        else:
            log.error(
                f"Starkiller: {starkiller_directory_problem(local_dir)} "
                "Not falling back to a clone."
            )
        return local_dir

    starkiller_dir = config_manager.DATA_DIR / "starkiller" / starkiller_config.ref

    if not Path(starkiller_dir).exists():
        log.info("Starkiller: directory not found. Cloning Starkiller")
        clone_git_repo(starkiller_config.repo, starkiller_config.ref, starkiller_dir)

    return starkiller_dir


def _resolve_compiler_platform():
    """Return (os, arch) strings used in compiler asset names, or (None, None)."""
    os_ = platform.system()
    arch = platform.machine()

    if os_ == "Darwin":
        os_ = "osx"
    elif os_ == "Linux":
        os_ = "linux"
    else:
        log.error(f"Empire Compiler: unsupported OS '{os_}'")
        return None, None

    if arch == "x86_64":
        arch = "x64"
    elif arch in ["aarch64", "arm64"]:
        arch = "arm64"
    else:
        log.error(f"Empire Compiler: unsupported architecture '{arch}'")
        return None, None

    return os_, arch


class CompilerSyncError(Exception):
    """`sync_empire_compiler` could not install the compiler.

    The message is operator-facing and names the cause and what to do; the
    library error that triggered it is `__cause__`. Every failure the sync can
    hit once it starts talking to GitHub or touching disk is wrapped in this,
    so the three callers that must not die on a failed sync (the server's
    DotnetCompiler, `setup`, `update`) catch one name and print the message.
    """


class CompilerArchiveError(CompilerSyncError):
    """The release archive unpacked cleanly but does not contain the compiler.

    A bad or mislaid release asset, not a transient failure: downloading it
    again would fetch the same archive.
    """


# Library errors a sync wraps. The urllib3 base class is here because a
# connection dropped *while streaming the body* surfaces from
# `resp.raw.read()` as a urllib3 ProtocolError, which requests only wraps on
# its own iterators.
_SYNC_LIBRARY_ERRORS = (
    requests.RequestException,
    urllib3.exceptions.HTTPError,
    tarfile.TarError,
    OSError,
)
_GITHUB_API_HEADERS = {"Accept": "application/vnd.github+json"}
_USER_AGENT = "Empire-Server (+https://github.com/BC-SECURITY/Empire)"
# Whole download-and-extract attempts; see `_download_compiler` for what is
# and is not retried.
_DOWNLOAD_ATTEMPTS = 3
_STREAM_ERRORS = (urllib3.exceptions.HTTPError, tarfile.ReadError)
# Relative to an installed compiler root. Installs made by `_download_compiler`
# are renamed into place only once this file exists, so for them its presence
# means "complete". For directories left by the pre-atomic code it is a
# best-effort marker: the binary is not the last archive entry.
_COMPILER_BINARY = Path("EmpireCompiler") / "EmpireCompiler"


def _github_session() -> requests.Session:
    """A session for both the release lookup and the asset download.

    GitHub rate-limits anonymous API traffic per source IP, and CI runners
    share IP ranges, so the token matters for the release lookup. It also goes
    on the first hop of the asset download, which is harmless (`requests`
    drops `Authorization` on the cross-host redirect to the asset CDN) but
    buys nothing measurable there: the download is protected by the retries,
    not by auth. Retries cover dropped connections, timeouts before the
    response headers arrive, 429 (honouring a bounded Retry-After) and 5xx
    with exponential backoff; any other 4xx is returned as-is so a real 404
    fails once, not five times.
    """
    session = requests.Session()
    session.headers["User-Agent"] = _USER_AGENT
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if token:
        session.headers["Authorization"] = f"Bearer {token}"
    retry = Retry(
        total=4,
        backoff_factor=1,
        status_forcelist=(429, 500, 502, 503, 504),
        allowed_methods=frozenset({"GET"}),
        raise_on_status=False,
        respect_retry_after_header=True,
        # GitHub's secondary limits can ask for minutes; the server is booting.
        retry_after_max=60,
    )
    session.mount("https://", HTTPAdapter(max_retries=retry))
    return session


def _resolve_compiler_download_url(
    compiler_config: EmpireCompilerConfig,
    platform_str: str,
    session: requests.Session | None = None,
) -> str | None:
    """Resolve the download URL for the compiler archive.

    Queries the GitHub Releases API using ``repo`` and ``ref`` over
    ``session`` (a fresh `_github_session()` when not supplied).
    """
    if not compiler_config.repo or not compiler_config.ref:
        log.error("Empire Compiler: 'repo' and 'ref' must be configured")
        return None

    api_url = f"https://api.github.com/repos/{compiler_config.repo}/releases/tags/{compiler_config.ref}"
    log.info(f"Empire Compiler: querying GitHub release {api_url}")
    if session is None:
        session = _github_session()
    resp = session.get(api_url, timeout=30, headers=_GITHUB_API_HEADERS)
    if not resp.ok:
        log.error(
            f"Empire Compiler: failed to fetch release info ({resp.status_code}): {resp.text}"
        )
        return None

    assets = resp.json().get("assets", [])
    for asset in assets:
        name = asset.get("name", "")
        if platform_str in name and name.endswith(".tgz"):
            return asset["browser_download_url"]

    log.error(
        f"Empire Compiler: no matching asset for platform '{platform_str}' in release {compiler_config.ref}"
    )
    return None


def _configure_compiler(
    compiler_config: EmpireCompilerConfig, extracted_folder: Path
) -> Path:
    """Write the ConfuserEx project file if it doesn't already exist."""
    confuser_proj_dir = extracted_folder / "EmpireCompiler"
    confuser_base_dir = confuser_proj_dir / "Data" / "Temp"
    confuser_output_dir = confuser_base_dir / "confused_out"
    confuser_project_file = confuser_base_dir / "empire.crproj"

    if not confuser_project_file.exists():
        # `confuser_proj` names a file that ships inside the package, so a
        # relative value is relative to the install root -- never the CWD.
        # REPO_ROOT is the repo root from a checkout and site-packages from a
        # wheel, which is also where an existing install's `empire/server/...`
        # config value resolves correctly.
        confuser_template_path = Path(compiler_config.confuser_proj)
        if not confuser_template_path.is_absolute():
            confuser_template_path = paths.REPO_ROOT / confuser_template_path
        confuser_template = confuser_template_path.read_text()
        confuser_project_file.parent.mkdir(parents=True, exist_ok=True)
        confuser_project_file.write_text(
            confuser_template.format(
                confuser_base_dir=confuser_base_dir,
                confuser_output_dir=confuser_output_dir,
                confuser_module_path="confused.exe",
                confuser_proj_dir=confuser_proj_dir,
            ),
            encoding="utf-8",
        )

    return extracted_folder


def _is_complete_install(root: Path) -> bool:
    return (root / _COMPILER_BINARY).is_file()


def _cached_compiler_names(compiler_dir: Path) -> list[str]:
    if not compiler_dir.exists():
        return []
    return sorted(
        d.name
        for d in compiler_dir.iterdir()
        if d.is_dir() and not d.name.startswith(".")
    )


def _find_install(compiler_dir: Path, expected_suffix: str) -> Path | None:
    """The cached directory for this platform+ref, complete or not."""
    for name in _cached_compiler_names(compiler_dir):
        if expected_suffix in name:
            return compiler_dir / name
    return None


def _remove_incomplete_install(root: Path) -> None:
    """Drop what an interrupted extract left behind (the pre-atomic code
    streamed straight into the final path). Serving it would fail obscurely
    at first compile; leaving it in place would let the download step mistake
    it for a finished install, so a failed removal is an error, not a warning.
    """
    log.warning(
        f"Empire Compiler: removing incomplete install {root.name} "
        f"(no {_COMPILER_BINARY}); it will be downloaded again"
    )
    shutil.rmtree(root)


def _cached_compiler_refs(compiler_dir: Path, platform_str: str) -> list[str]:
    """Refs of the complete installs for this platform, in the form
    `empire_compiler.ref` needs (the cache scan matches `{platform}-{ref}`).
    """
    prefix = f"EmpireCompiler-{platform_str}-"
    return [
        name.removeprefix(prefix)
        for name in _cached_compiler_names(compiler_dir)
        if name.startswith(prefix) and _is_complete_install(compiler_dir / name)
    ]


def _describe_sync_failure(error: BaseException, compiler_dir: Path) -> str:
    """Operator-facing cause for a failed sync, so the advice fits it."""
    if isinstance(error, tarfile.TarError):
        return f"the release archive is corrupt or truncated ({error})"
    if isinstance(error, requests.RequestException | urllib3.exceptions.HTTPError):
        return (
            f"network error fetching the release ({error}); re-run "
            "'./ps-empire setup' once GitHub is reachable"
        )
    return (
        f"could not update {compiler_dir} ({error}); check permissions and free space"
    )


def _extract_compiler_stream(resp, scratch: Path, name: str) -> Path:
    with tarfile.open(fileobj=resp.raw, mode="r|gz") as tar:
        # filter="data" guards against path traversal in the downloaded archive.
        tar.extractall(scratch, filter="data")
    extracted = scratch / name
    if not _is_complete_install(extracted):
        raise CompilerArchiveError(
            f"the release asset {name}.tgz does not contain "
            f"{name}/{_COMPILER_BINARY.as_posix()}; check the release on GitHub"
        )
    return extracted


def _download_compiler_once(
    session: requests.Session, url: str, compiler_dir: Path, name: str
) -> Path | None:
    target = compiler_dir / name
    with session.get(url, stream=True, timeout=(30, 300)) as resp:
        if not resp.ok:
            log.error(f"Empire Compiler: download failed ({resp.status_code}): {url}")
            return None
        scratch_root = compiler_dir / ".partial"
        scratch_root.mkdir(parents=True, exist_ok=True)
        scratch = Path(tempfile.mkdtemp(dir=scratch_root))
        try:
            extracted = _extract_compiler_stream(resp, scratch, name)
            # Another process may have installed it while we streamed.
            if _is_complete_install(target):
                log.info(
                    f"Empire Compiler: {name} was installed by another process; using it"
                )
            else:
                extracted.rename(target)
        finally:
            shutil.rmtree(scratch, ignore_errors=True)
    return target


def _download_compiler(
    session: requests.Session, url: str, compiler_dir: Path, name: str
) -> Path | None:
    """Fetch and unpack the release archive into ``compiler_dir / name``.

    The archive streams into a scratch directory under ``.partial/`` and is
    renamed into place only once the binary is present, so a crash or a
    dropped connection never leaves a half-populated directory that the cache
    scan could mistake for an install. Returns None on any non-OK final status
    (a 4xx, or a 429/5xx after the session's own retries are spent).

    Only failures a second download might fix are retried here: a mid-body
    drop (urllib3 raises it from `resp.raw.read()`) or a truncated / corrupt
    gzip stream. Connect-level and status failures were already retried
    inside the session, so they are not retried again; neither are a wrong
    archive, a path-traversal entry, or a disk error.
    """
    for attempt in range(1, _DOWNLOAD_ATTEMPTS + 1):
        try:
            return _download_compiler_once(session, url, compiler_dir, name)
        except _STREAM_ERRORS as e:
            if attempt == _DOWNLOAD_ATTEMPTS:
                raise
            delay = 2**attempt
            log.warning(
                f"Empire Compiler: download attempt {attempt}/{_DOWNLOAD_ATTEMPTS} "
                f"failed ({e}); retrying in {delay}s"
            )
            time.sleep(delay)
    return None  # pragma: no cover - the loop always returns or raises


def _sync_compiler_release(
    compiler_config: EmpireCompilerConfig, platform_str: str, compiler_dir: Path
) -> Path | None:
    expected_suffix = f"{platform_str}-{compiler_config.ref}"
    # Check for an existing directory matching this platform *and* version
    # before hitting the GitHub API, so cached compilers don't require
    # network access.
    found = _find_install(compiler_dir, expected_suffix)
    if found is not None and _is_complete_install(found):
        log.info(f"Empire Compiler: using cached {found.name}")
        return _configure_compiler(compiler_config, found)
    if found is not None:
        _remove_incomplete_install(found)

    with _github_session() as session:
        url = _resolve_compiler_download_url(compiler_config, platform_str, session)
        if url is None:
            return None
        name = url.split("/")[-1].removesuffix(".tgz")
        log.info(f"Empire Compiler: directory not found. Downloading {url}")
        target = _download_compiler(session, url, compiler_dir, name)
    if target is None:
        return None
    return _configure_compiler(compiler_config, target)


def sync_empire_compiler(compiler_config: EmpireCompilerConfig):
    """Install the configured compiler release if it is not cached.

    Returns the compiler root, or None when nothing could be resolved
    (unsupported platform, missing repo/ref, a non-OK GitHub status, no
    matching asset). Raises CompilerSyncError for everything else.
    """
    # Allow a local directory override so developers can test without
    # publishing a GitHub release. A stale path falls back to downloading the
    # published release, which is safe because this override is a developer
    # convenience rather than a deployment mechanism.
    if compiler_config.directory:
        local_dir = Path(compiler_config.directory)
        if local_dir.exists():
            log.info(f"Empire Compiler: using local directory {local_dir}")
            return _configure_compiler(compiler_config, local_dir)
        log.warning(
            f"Empire Compiler: configured directory '{compiler_config.directory}' does not exist, falling back to download"
        )

    os_, arch = _resolve_compiler_platform()
    if os_ is None:
        return None

    platform_str = f"{os_}-{arch}"
    compiler_dir = config_manager.DATA_DIR / "empire-compiler"
    try:
        return _sync_compiler_release(compiler_config, platform_str, compiler_dir)
    except _SYNC_LIBRARY_ERRORS as e:
        # Deliberately no fallback to another cached version: a compiler that
        # doesn't match the configured ref can silently miscompile against the
        # module YAML. Tell the operator which refs would work instead.
        refs = _cached_compiler_refs(compiler_dir, platform_str)
        hint = (
            f" Cached for this platform: set empire_compiler.ref to one of: "
            f"{', '.join(refs)}."
            if refs
            else ""
        )
        raise CompilerSyncError(
            f"{_describe_sync_failure(e, compiler_dir)}.{hint}"
        ) from e


def _banner(msg: str) -> None:
    """User-facing status line for the `update` subcommand.

    The `update` entry point does not initialise the server logger, so `log.*`
    output is suppressed. Print directly so operators can see what's being
    checked.
    """
    print(f"\x1b[1;34m[*] {msg}\x1b[0m", flush=True)


def _warn(msg: str) -> None:
    print(f"\x1b[1;33m[!] {msg}\x1b[0m", flush=True)


def _error(msg: str) -> None:
    print(f"\x1b[1;31m[x] {msg}\x1b[0m", flush=True)


def _confirm(prompt: str, *, assume_yes: bool) -> bool:
    if assume_yes:
        log.info(f"{prompt} [auto-yes]")
        return True
    try:
        answer = input(f"{prompt} [y/N]: ")
    except EOFError:
        # Non-interactive without -y is ambiguous: the caller intends to
        # update, but we'd silently skip migrations and the aggregator would
        # report success. Exit non-zero so CI / scripted callers notice
        # rather than relying on operators to spot a missed prompt in logs.
        _error(
            "No interactive TTY and -y not provided; refusing to silently "
            "skip migration. Re-run with -y to auto-confirm."
        )
        raise SystemExit(2) from None
    return answer.strip().lower() in ("y", "yes")


def _git_fast_forward(target: Path, ref: str, label: str) -> bool:
    """Fetch + checkout + fast-forward pull at `target`. Returns success.

    Used by `update_starkiller` / `update_plugin_registry` Case A. The loop
    raises out of the shared try/except as soon as a step fails, so the
    user-facing error names the failing command (via `e.cmd`) instead of a
    generic "git update failed".
    """
    _banner(f"{label}: checking for updates at {target} (ref: {ref})")
    # `config.yaml` documents Starkiller's `ref` as branch/tag/commit. Tags
    # and SHAs land on detached HEAD after checkout, where `git pull --ff-only`
    # errors with "You are not currently on a branch". Probe with
    # `branch --show-current` (empty stdout on detached HEAD) and skip the
    # pull in that case — there's nothing to fast-forward when HEAD is
    # already pinned to a fixed commit.
    for step, cmd in (
        ("fetch", ["git", "fetch", "--tags"]),
        ("checkout", ["git", "checkout", ref]),
    ):
        try:
            run_as_user(cmd, cwd=target)
        except subprocess.CalledProcessError as e:
            _error(
                f"{label}: git {step} failed at {target} "
                f"(cmd: {' '.join(str(c) for c in e.cmd)}, rc: {e.returncode}). "
                "Resolve manually or remove the directory to force a re-clone."
            )
            return False

    try:
        branch = run_as_user(
            ["git", "branch", "--show-current"], cwd=target, capture_output=True
        ).strip()
    except subprocess.CalledProcessError:
        branch = ""
    if not branch:
        _banner(f"{label}: pinned to '{ref}' (detached HEAD); skipping pull")
        return True

    try:
        run_as_user(["git", "pull", "--ff-only"], cwd=target)
    except subprocess.CalledProcessError as e:
        _error(
            f"{label}: git pull failed at {target} "
            f"(cmd: {' '.join(str(c) for c in e.cmd)}, rc: {e.returncode}). "
            "Resolve manually or remove the directory to force a re-clone."
        )
        return False
    return True


def overwrite_base_config() -> bool:
    """Copy the shipped `config.yaml` over the user's active base config.

    Customizations belong in `config.user.yaml` under the config dir, which the
    layered loader (`config_manager.EmpireConfig.settings_customise_sources`)
    merges on top of the base — so treating the base as team-owned defaults
    lets us ship new refs (compiler, starkiller, registries) without trying
    to reconcile them against the user's edits.

    `DEFAULT_CONFIG` rather than a path rebuilt from the repo root: the guard
    below only means anything if `src` is the same file the seeding code
    reads, and nothing would enforce that across two derivations.
    """
    src = config_manager.DEFAULT_CONFIG
    dst = config_manager.CONFIG_PATH
    if not src.exists():
        _error(f"Config: shipped template missing at {src}; skipping overwrite")
        return False
    if src.resolve() == dst.resolve():
        _banner(f"Config: {dst} already points at the shipped template; skipping copy")
        return True
    try:
        # Same helper the import-time seeding uses, so the "copyfile, not
        # copy" reasoning lives in exactly one place.
        config_manager.seed_config(src, dst)
    except OSError as e:
        # PermissionError (e.g. dst is root-owned from a prior sudo install) and
        # any other OSError — surface it and let the rest of run_update proceed.
        _error(
            f"Config: could not overwrite {dst} from {src} ({e}). "
            f"Fix permissions (e.g. `sudo chown $USER {dst}`) and re-run "
            "'./ps-empire update'."
        )
        return False
    _banner(f"Config: overwrote {dst} from {src}")
    return True


def _detect_release_channel(repo_root: Path) -> str | None:
    """Return the `checkout-latest-tag.sh` channel arg matching the origin remote.

    `Empire-Sponsors` -> `sponsors`, `Empire-Kali` -> `kali`, otherwise None
    (mainline Empire — script picks the latest non-prerelease semver tag).
    Returning None on a *failed* read (vs. an unknown URL) would silently
    downgrade sponsors/kali installs to mainline tags, so warn loudly in that
    case to leave a greppable breadcrumb.
    """
    try:
        url = run_as_user(
            ["git", "remote", "get-url", "origin"],
            cwd=repo_root,
            capture_output=True,
        )
    except subprocess.CalledProcessError as e:
        _warn(
            f"Empire: could not read 'origin' remote at {repo_root} "
            f"(cmd: {' '.join(str(c) for c in e.cmd)}, rc: {e.returncode}); "
            "treating as mainline. If this is a sponsors/kali install, restore "
            "the 'origin' remote and re-run './ps-empire update'."
        )
        return None
    if not url:
        _warn(
            f"Empire: 'origin' remote at {repo_root} returned an empty URL; "
            "treating as mainline. If this is a sponsors/kali install, restore "
            "the remote and re-run './ps-empire update'."
        )
        return None
    if "Empire-Sponsors" in url:
        return "sponsors"
    if "Empire-Kali" in url:
        return "kali"
    return None


def update_empire_source(repo_root: Path) -> bool:
    """Move the Empire checkout to the latest release tag.

    Mirrors the documented install path (`setup/checkout-latest-tag.sh`), so
    users who installed at a tag stay on a stable release. For dev branches
    (`sponsors-main`, `7.0-dev`, etc.) we skip and let the user manage source
    updates themselves — `git pull` from a detached HEAD fails outright, and
    silently fast-forwarding a tracking branch isn't what most users want.
    """
    if not (repo_root / ".git").exists():
        _banner(f"Empire: {repo_root} is not a git checkout, skipping")
        return True

    _banner(f"Empire: checking for updates at {repo_root}")
    # `git branch --show-current` returns the branch name on a branch and
    # empty stdout on detached HEAD, exiting 0 either way.
    try:
        run_as_user(["git", "fetch", "--tags"], cwd=repo_root)
        branch = run_as_user(
            ["git", "branch", "--show-current"],
            cwd=repo_root,
            capture_output=True,
        )
    except subprocess.CalledProcessError as e:
        _error(
            f"Empire: `{' '.join(str(c) for c in e.cmd)}` failed at {repo_root} "
            f"(rc: {e.returncode}). Resolve manually and re-run './ps-empire update'."
        )
        return False

    if branch:
        _warn(
            f"Empire: HEAD is on branch '{branch}'; this is a development "
            "branch — manage source updates manually with git. Skipping the "
            "source step (config and downstream refreshes will still run)."
        )
        return True

    script = repo_root / "setup" / "checkout-latest-tag.sh"
    if not script.exists():
        _error(f"Empire: {script} not found; cannot move to latest release tag")
        return False

    cmd = ["bash", str(script)]
    channel = _detect_release_channel(repo_root)
    if channel:
        cmd.append(channel)
    try:
        run_as_user(cmd, cwd=repo_root)
    except subprocess.CalledProcessError as e:
        _error(
            f"Empire: checkout-latest-tag.sh failed (rc: {e.returncode}). "
            "Resolve manually and re-run './ps-empire update'."
        )
        return False
    return True


def update_starkiller(
    starkiller_config: StarkillerConfig, *, assume_yes: bool = False
) -> bool:
    local_dir = _starkiller_override_dir(starkiller_config)
    if local_dir is not None:
        # Nothing to fetch, but still check the override resolves: `update` is
        # what operators run after editing config, and reporting success for a
        # path that `setup` would reject hands them a green "Update complete"
        # over a server that will boot with no UI.
        _banner(
            f"Starkiller: using local directory override {local_dir}; nothing to update"
        )
        return _starkiller_directory_ok(starkiller_config)

    starkiller_root = config_manager.DATA_DIR / "starkiller"
    target = starkiller_root / starkiller_config.ref

    if target.exists() and (target / ".git").exists():
        return _git_fast_forward(target, starkiller_config.ref, "Starkiller")

    cached = (
        [p.name for p in starkiller_root.iterdir() if p.is_dir()]
        if starkiller_root.exists()
        else []
    )
    if cached:
        _banner(
            f"Starkiller: cached refs {cached}; config ref is '{starkiller_config.ref}'"
        )
        if not _confirm(
            f"Download Starkiller '{starkiller_config.ref}' and migrate?",
            assume_yes=assume_yes,
        ):
            _banner("Starkiller: migration skipped")
            return True

    _banner(f"Starkiller: cloning '{starkiller_config.ref}' (first run)")
    try:
        sync_starkiller(starkiller_config)
    except GitOperationException as e:
        _error(f"Starkiller: clone failed ({e}).")
        return False
    return True


def update_empire_compiler(
    compiler_config: EmpireCompilerConfig, *, assume_yes: bool = False
) -> bool:
    if compiler_config.directory:
        _banner(
            f"Empire Compiler: using local directory override {compiler_config.directory}; nothing to update"
        )
        return True

    os_, arch = _resolve_compiler_platform()
    if os_ is None:
        return False

    platform_str = f"{os_}-{arch}"
    compiler_dir = config_manager.DATA_DIR / "empire-compiler"
    expected_suffix = f"{platform_str}-{compiler_config.ref}"

    # Same test as the server's sync: a directory on the right ref but without
    # the binary is an interrupted extract, which this command exists to repair
    # (the sync itself removes it, inside the error handling below).
    found = _find_install(compiler_dir, expected_suffix)
    if found is not None and _is_complete_install(found):
        _banner(
            f"Empire Compiler: already on '{compiler_config.ref}' ({found.name}); up to date"
        )
        return True
    if found is not None:
        _warn(
            f"Empire Compiler: {found.name} is incomplete (no {_COMPILER_BINARY}); it will be replaced"
        )
    cached_names = [
        name
        for name in _cached_compiler_names(compiler_dir)
        if compiler_dir / name != found
    ]

    if cached_names:
        _banner(
            f"Empire Compiler: cached {cached_names}; config ref is '{compiler_config.ref}'"
        )
        if not _confirm(
            f"Download Empire Compiler '{compiler_config.ref}' and migrate?",
            assume_yes=assume_yes,
        ):
            _banner("Empire Compiler: migration skipped")
            return True

    _banner(f"Empire Compiler: downloading '{compiler_config.ref}'")
    # sync_empire_compiler returns None (without raising) for unsupported
    # OS/arch, missing repo/ref config, a non-OK GitHub API or asset-download
    # status (rate limit, 404), and no asset matching the resolved platform —
    # and raises CompilerSyncError, whose message is operator-facing, for
    # network/disk/extract failures. Without this check the aggregator
    # prints "[*] Update complete." and the user hits the actual error
    # several layers downstream. Funnel both cases through a single error
    # path to keep the return count under PLR0911's threshold.
    error_detail: str | None = None
    try:
        result = sync_empire_compiler(compiler_config)
    except CompilerSyncError as e:
        error_detail = str(e)
    else:
        if result is None:
            error_detail = (
                "sync returned no path (unsupported platform, missing asset, "
                "or API failure). Check the server log for the underlying cause."
            )
    if error_detail:
        _error(f"Empire Compiler: {error_detail}")
        return False
    return True


def update_plugin_registry(
    registry_config: PluginRegistryConfig, *, assume_yes: bool = False
) -> bool:
    if not registry_config.git_url:
        return True

    ref = registry_config.ref or "main"
    base_dir = config_manager.DATA_DIR / "plugin-registries" / registry_config.name
    target = base_dir / ref

    if target.exists() and (target / ".git").exists():
        return _git_fast_forward(
            target, ref, f"Plugin Registry '{registry_config.name}'"
        )

    cached = (
        [p.name for p in base_dir.iterdir() if p.is_dir()] if base_dir.exists() else []
    )
    if cached:
        _banner(
            f"Plugin Registry '{registry_config.name}': cached refs {cached}; config ref is '{ref}'"
        )
        if not _confirm(
            f"Download plugin registry '{registry_config.name}' at '{ref}' and migrate?",
            assume_yes=assume_yes,
        ):
            _banner(f"Plugin Registry '{registry_config.name}': migration skipped")
            return True

    _banner(f"Plugin Registry '{registry_config.name}': cloning '{ref}' (first run)")
    try:
        sync_plugin_registry(registry_config)
    except GitOperationException as e:
        _error(f"Plugin Registry '{registry_config.name}': clone failed ({e}).")
        return False
    return True


def _ownership_check_paths() -> list[Path]:
    """Paths the pre-flight should stat for foreign ownership.

    Includes the obvious roots plus the immediate children of `DATA_DIR`
    that contain `.git/` clones (Starkiller, plugin registries) — those are
    where prior `sudo` installs left root-owned trees that trip git's
    "dubious ownership" check, even when `DATA_DIR` itself is user-owned.
    """
    paths = [
        config_manager.CONFIG_DIR,
        config_manager.CONFIG_PATH,
        config_manager.DATA_DIR,
    ]
    for subdir_name in ("starkiller", "plugin-registries", "empire-compiler"):
        subdir = config_manager.DATA_DIR / subdir_name
        if not subdir.exists():
            continue
        paths.append(subdir)
        try:
            paths.extend(p for p in subdir.iterdir() if p.is_dir())
        except OSError:
            # Can't enumerate children — the parent itself will surface the
            # ownership problem if there is one.
            continue
    return paths


def _foreign_owned_paths() -> tuple[list[Path], list[Path]]:
    """Return (foreign-owned, unstat-able) lists.

    Foreign-owned paths exist and are owned by another uid (typically root,
    left behind by a prior `sudo` invocation of `install`/`setup`/`update`
    before this PR moved `setup`/`update` off sudo). Unstat-able paths
    couldn't be checked at all (broken filesystem, EACCES on stat); they're
    returned separately so the caller can warn rather than silently treating
    them as clean. A single `stat` (not `exists` + `stat`) is used so that
    `PermissionError` lands in `unstat` instead of being swallowed by
    `Path.exists`'s built-in OSError → False fallback.
    """
    current_uid = os.getuid()
    foreign: list[Path] = []
    unstat: list[Path] = []
    for p in _ownership_check_paths():
        try:
            st = p.stat()
        except FileNotFoundError:
            continue
        except OSError:
            unstat.append(p)
            continue
        if st.st_uid != current_uid:
            foreign.append(p)
    return foreign, unstat


def _current_username() -> str:
    """Resolve the current user's name for the chown remediation hint.

    Prefers `$USER` (set in normal login shells); falls back to the passwd
    database; finally falls back to the numeric uid for slim containers /
    distroless / deleted-account cases where neither is available.
    """
    user = os.environ.get("USER")
    if user:
        return user
    try:
        return pwd.getpwuid(os.getuid()).pw_name
    except KeyError:
        return str(os.getuid())


def check_no_foreign_ownership() -> bool:
    """Pre-flight for `setup` / `update`: bail with a single actionable banner
    if any of the user's Empire dirs are owned by another user. Without this,
    the calling subcommand fails partway through — the config copy hits `EPERM`,
    and `git fetch` inside root-owned clones hits "dubious ownership" — and
    the user is left to piece together the remediation from per-step errors.
    """
    foreign, unstat = _foreign_owned_paths()
    for p in unstat:
        _warn(f"Could not stat {p}; ownership unknown — continuing.")
    if not foreign:
        return True

    _error(
        "Detected files owned by another user (likely root from a prior "
        "`sudo` invocation of install/setup/update). `./ps-empire setup` and "
        "`update` no longer run under sudo, so they cannot write to "
        "root-owned paths."
    )
    for p in foreign:
        print(f"    {p}", flush=True)
    _error(
        f"Fix once with:\n"
        f"    sudo chown -R {_current_username()} {config_manager.CONFIG_DIR} "
        f"{config_manager.DATA_DIR}\n"
        "Then re-run the command that triggered this."
    )
    return False


def update_database(*, assume_yes: bool) -> bool:
    """Back up the database (if possible) then apply any pending Alembic
    migrations.

    Run as part of `./ps-empire update` so users don't have to start the
    server, watch it crash on a schema mismatch, and chase the recovery
    advice manually. Idempotent: a no-op when the schema is already at
    head.

    Returns True on success (including the no-op case), False if the user
    declines to migrate or the migration itself fails. Backup failures do
    not block the migration — the operator is warned and the upgrade
    proceeds, since the alternative (refusing to migrate) would leave the
    server unbootable on environments where mysqldump isn't installed.
    """
    _banner("Database: checking for pending migrations")
    # Lazy import: empire.server.core.db.base has heavy module-level side
    # effects (creates the SQLAlchemy engine, runs Base.metadata.create_all).
    # Defer until the update flow actually needs the DB so a `--help` or a
    # pre-flight failure doesn't pay that cost.
    try:
        from empire.server.core.db import base as db_base
    except Exception:
        _error(
            "Database: failed to import the DB module; cannot check "
            "migrations. See traceback above."
        )
        log.exception("Database: import failed")
        return False

    try:
        current, head = db_base.pending_migrations()
    except Exception:
        _error(
            "Database: failed to read Alembic revision state. Check that "
            "the database is reachable and the alembic package is installed."
        )
        log.exception("Database: revision check failed")
        return False

    if current == head:
        _banner(f"Database: schema up to date at revision {current}")
        return True

    label = f"untracked → '{head}'" if current is None else f"'{current}' → '{head}'"
    _banner(f"Database: pending migrations ({label})")

    if not _confirm(
        "Back up the database and apply migrations?",
        assume_yes=assume_yes,
    ):
        _warn("Database: skipping migrations at user request.")
        return False

    backup_path = db_base.backup_db()
    if backup_path is None:
        _warn(
            "Database: backup did not produce a file (see log for cause). "
            "Proceeding with migration anyway — restore manually from an "
            f"earlier backup in {config_manager.DATA_DIR / 'backups'} if needed."
        )
    else:
        _banner(f"Database: backed up to {backup_path}")

    try:
        db_base.stamp_and_migrate()
    except Exception:
        restore_hint = backup_path or config_manager.DATA_DIR / "backups"
        _error(
            f"Database: migration failed. The database may be in a partial "
            f"state — restore from {restore_hint} before retrying."
        )
        log.exception("Database: migration failed")
        return False

    _banner("Database: migrations complete.")
    return True


def run_update(args, *, repo_root: Path) -> bool:
    """Entry point for `./ps-empire update`. Moves the Empire checkout to the
    latest release tag, overwrites the base `config.yaml` from the shipped
    template, then refreshes Starkiller / Empire-Compiler / plugin registries
    according to the (possibly just-overwritten) active config.

    Returns True if every step succeeded, False otherwise — caller should
    map this to a process exit code so CI / scripted callers can detect a
    failed update.
    """
    if not check_no_foreign_ownership():
        return False

    assume_yes = getattr(args, "yes", False)

    source_ok = update_empire_source(repo_root)
    if not source_ok:
        _warn(
            "Continuing with the update despite source step failure; the "
            "config overwrite and downstream refreshes will use the existing "
            "local template."
        )

    config_ok = overwrite_base_config()
    if config_ok:
        # Reload so the update_* helpers operate on whatever refs the new
        # base config (merged with the user's config.user.yaml) resolves to.
        config_manager.empire_config = config_manager.EmpireConfig()

    results = [
        ("Empire source", source_ok),
        ("Config", config_ok),
        # Run migrations after source/config but before the downstream
        # refreshes so that (a) any new migration scripts pulled in by the
        # source step are on disk, and (b) the user sees the DB step's
        # prompt up-front rather than after sitting through Starkiller /
        # Compiler downloads.
        ("Database", update_database(assume_yes=assume_yes)),
        (
            "Starkiller",
            update_starkiller(
                config_manager.empire_config.starkiller, assume_yes=assume_yes
            ),
        ),
        (
            "Empire Compiler",
            update_empire_compiler(
                config_manager.empire_config.empire_compiler, assume_yes=assume_yes
            ),
        ),
    ]
    for registry in config_manager.empire_config.plugin_marketplace.registries:
        results.append(
            (
                f"Plugin Registry '{registry.name}'",
                update_plugin_registry(registry, assume_yes=assume_yes),
            )
        )

    failed = [label for label, ok in results if not ok]
    if failed:
        _warn(
            f"Update finished with {len(failed)} failure(s): {', '.join(failed)}. "
            "Review the errors above and re-run './ps-empire update' after "
            "resolving them."
        )
        return False

    print(
        "\x1b[1;32m[*] Update complete. Restart the server for changes to take effect.\x1b[0m",
        flush=True,
    )
    return True


def _starkiller_directory_ok(starkiller_config: StarkillerConfig) -> bool:
    """Validate a configured `directory` for `setup` / `update`.

    `sync_starkiller` returns an override unvalidated -- it never falls back to
    a clone -- so this is where a bad one has to fail. `_error` rather than
    `log.error` because these entry points run without the server logger's
    formatting.

    Resolves the build, not just the directory: a directory that exists but
    holds no build still boots to a blank UI, and `is_dir()` alone would print a
    green banner over that.

    A relative override warns instead of failing: it is a legal value (the field
    is typed `str` precisely so relative paths survive verbatim), but nothing
    anchors it, so `setup` and the server each resolve it against whichever
    directory they happened to be launched from.

    A disabled Starkiller passes regardless. The sync still runs, `enabled` or
    not, so the build stays ready for whenever the operator flips it back on --
    but failing a whole install over a UI they switched off is not acceptable.
    """
    starkiller_dir = _starkiller_override_dir(starkiller_config)
    if not starkiller_config.enabled or starkiller_dir is None:
        return True
    # An unexpanded `~` is not relative in any sense the operator can act on;
    # the CWD advice would contradict the diagnosis that follows it.
    if not starkiller_dir.is_absolute() and not str(starkiller_dir).startswith("~"):
        _warn(
            f"Starkiller: configured directory '{starkiller_dir}' is relative, so "
            f"it resolves against the current working directory ({Path.cwd()}). "
            "The server is normally launched from somewhere else (systemd unit, "
            "console script, container), where the same value names a different "
            "path -- use an absolute path."
        )
    problem = starkiller_directory_problem(starkiller_dir)
    if problem:
        _error(f"Starkiller: {problem}")
        return False
    return True


def run_setup(args) -> dict[str, bool] | None:
    """Entry point for `./ps-empire setup`. Runs the install-time syncs
    (`sync_starkiller` / `sync_empire_compiler` / `sync_plugin_registry`)
    with banner-style error handling, returning a per-step result dict.

    Symmetric with `run_update`: the same defect class (silent sync
    failures) was fixed there for the `update` subcommand in PR #1276;
    this is its install-time counterpart. Without it, a `setup` run with
    e.g. a blocked GitHub egress prints nothing about the failure and
    crashes the next server boot when `DotnetCompiler.__init__` divides
    `None` by a string.

    Aggregate-then-exit semantics (matching `run_update`): every sync
    runs even after earlier ones fail, so a fresh-install operator sees
    the full list of red banners in one pass. The typical root cause —
    firewall blocking GitHub, missing SSH key for the sponsors repos,
    DNS broken in the install container — breaks several syncs at once,
    and listing them together is more useful than iterative fail-fast.

    Returns:
      - `None` if the foreign-ownership pre-flight failed (caller must
        exit non-zero without doing further work).
      - dict mapping step labels (`"Starkiller"`, `"Empire Compiler"`,
        `"Plugin Registry '<name>'"`) to bool success otherwise.

    The caller (`empire.py`) inspects the dict to gate
    `_auto_install_plugins` on every plugin-registry step succeeding —
    auto-install reads the registry data those syncs populate, so
    running it after a partial sync silently produces an incomplete
    install.
    """
    if not check_no_foreign_ownership():
        return None

    results: dict[str, bool] = {}

    _banner("Starkiller: syncing")
    starkiller_config = config_manager.empire_config.starkiller
    try:
        sync_starkiller(starkiller_config)
    except GitOperationException as e:
        _error(f"Starkiller: clone failed ({e}).")
        results["Starkiller"] = False
    else:
        results["Starkiller"] = _starkiller_directory_ok(starkiller_config)

    _banner("Empire Compiler: syncing")
    # Mirrors the failure model in update_empire_compiler:
    # sync_empire_compiler returns None (without raising) for unsupported
    # OS/arch, missing repo/ref config, a non-OK GitHub API or asset-download
    # status, or no asset matching the resolved platform — and raises
    # CompilerSyncError, whose message is operator-facing, for network / disk /
    # extract failures. Funnel both into a single error path so the banner is
    # uniform regardless of which surface failed.
    error_detail: str | None = None
    try:
        result = sync_empire_compiler(config_manager.empire_config.empire_compiler)
    except CompilerSyncError as e:
        error_detail = str(e)
    else:
        if result is None:
            error_detail = (
                "sync returned no path (unsupported platform, missing asset, "
                "or API failure). Check the server log for the underlying cause."
            )
    if error_detail:
        _error(f"Empire Compiler: {error_detail}")
        results["Empire Compiler"] = False
    else:
        results["Empire Compiler"] = True

    for registry in config_manager.empire_config.plugin_marketplace.registries:
        label = f"Plugin Registry '{registry.name}'"
        _banner(f"{label}: syncing")
        try:
            sync_plugin_registry(registry)
            results[label] = True
        except GitOperationException as e:
            _error(f"{label}: clone failed ({e}).")
            results[label] = False

    failed = [label for label, ok in results.items() if not ok]
    if failed:
        _warn(
            f"Setup finished with {len(failed)} failure(s): {', '.join(failed)}. "
            "Resolve the errors above and re-run './ps-empire setup'."
        )

    return results


def sync_plugin_registry(registry_config: PluginRegistryConfig):
    base_dir = config_manager.DATA_DIR / "plugin-registries" / registry_config.name
    base_dir.mkdir(parents=True, exist_ok=True)

    # If a local location is provided, prefer it as-is (no copy) for speed
    if registry_config.location:
        return registry_config.location

    # Clone a git-based registry into a persistent offline directory
    if registry_config.git_url:
        ref = registry_config.ref or "main"
        target_dir = base_dir / ref

        if not target_dir.exists():
            log.info(
                f"Plugin Registry: directory not found for {registry_config.name}. Cloning {registry_config.git_url} ({ref})"
            )
            clone_git_repo(registry_config.git_url, ref, target_dir)

        return target_dir / (registry_config.file or "registry.yaml")

    # Fallback: download from URL and cache to disk for offline use
    if registry_config.url:
        registry_file = base_dir / "registry.yaml"
        log.info(
            f"Plugin Registry: downloading {registry_config.name} from {registry_config.url}"
        )
        resp = requests.get(registry_config.url, timeout=30)
        if resp.ok:
            registry_file.write_text(resp.text)
            return registry_file
        log.error(
            f"Failed to download plugin registry {registry_config.name} from {registry_config.url}"
        )
        return None

    return None
