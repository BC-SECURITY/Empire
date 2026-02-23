import logging
import platform
import tarfile
from pathlib import Path

import requests

from empire.server.core.config import config_manager
from empire.server.core.config.config_manager import (
    EmpireCompilerConfig,
    PluginRegistryConfig,
    StarkillerConfig,
)
from empire.server.utils.git_util import clone_git_repo

log = logging.getLogger(__name__)


def sync_starkiller(starkiller_config: StarkillerConfig):
    starkiller_dir = config_manager.DATA_DIR / "starkiller" / starkiller_config.ref

    if not Path(starkiller_dir).exists():
        log.info("Starkiller: directory not found. Cloning Starkiller")
        clone_git_repo(starkiller_config.repo, starkiller_config.ref, starkiller_dir)

    return starkiller_dir


def sync_empire_compiler(compiler_config: EmpireCompilerConfig):
    os_ = platform.system()
    arch = platform.machine()

    if os_ == "Darwin":
        os_ = "osx"
    elif os_ == "Linux":
        os_ = "linux"
    else:
        log.error(f"Empire Compiler: unsupported OS '{os_}'")
        return None

    if arch == "x86_64":
        arch = "x64"
    elif arch in ["aarch64", "arm64"]:
        arch = "arm64"
    else:
        log.error(f"Empire Compiler: unsupported architecture '{arch}'")
        return None

    name = (
        compiler_config.archive.split("/")[-1]
        .removesuffix(".tgz")
        .replace("{{platform}}", f"{os_}-{arch}")
    )
    compiler_dir = config_manager.DATA_DIR / "empire-compiler"

    if not Path(compiler_dir / name).exists():
        log.info("Empire Compiler: directory not found. Cloning Empire Compiler")

        url = compiler_config.archive.replace("{{platform}}", f"{os_}-{arch}")
        log.info(f"Empire Compiler: fetching and unarchiving {url}")
        with (
            requests.get(url, stream=True) as resp,
            tarfile.open(fileobj=resp.raw, mode="r|gz") as tar,
        ):
            tar.extractall(compiler_dir)
    # The release version changes but folder structure should stay the same
    extracted_folder = next(d for d in compiler_dir.iterdir() if d.is_dir())
    confuser_proj_dir = str(extracted_folder) + "/EmpireCompiler"
    confuser_project_name = "empire.crproj"
    confuser_base_dir = f"{confuser_proj_dir}/Data/Temp"
    confuser_output_dir = f"{confuser_proj_dir}/Data/Temp/confused_out"
    confuser_module_path = "confused.exe"

    confuser_template = Path(compiler_config.confuser_proj).read_text()
    confuser_template = confuser_template.format(
        confuser_base_dir=confuser_base_dir,
        confuser_output_dir=confuser_output_dir,
        confuser_module_path=confuser_module_path,
        confuser_proj_dir=confuser_proj_dir,
    )
    if not Path(confuser_base_dir + "/" + confuser_project_name).exists():
        with Path(confuser_base_dir + "/" + confuser_project_name).open(
            "w", encoding="utf-8"
        ) as f:
            f.write(confuser_template)

    return compiler_dir / name


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
