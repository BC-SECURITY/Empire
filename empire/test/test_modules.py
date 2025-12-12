import logging
import re
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import MagicMock, Mock

import pytest
import yaml
from _pytest.logging import LogCaptureHandler

from empire.server.core.exceptions import (
    ModuleValidationException,
)
from empire.server.core.module_service import ModuleService


def convert_options_to_params(options):
    params = {}
    for option in options:
        params[option.name] = option.value
    return params


def fake_obfuscate(psScript, obfuscation_command):
    return psScript


@contextmanager
def catch_logs(level: int, logger: logging.Logger) -> LogCaptureHandler:
    """Context manager that sets the level for capturing of logs.

    After the end of the 'with' statement the level is restored to its original value.

    :param level: The level.
    :param logger: The logger to update.
    """
    handler = LogCaptureHandler()
    orig_level = logger.level
    logger.setLevel(level)
    logger.addHandler(handler)
    try:
        yield handler
    finally:
        logger.setLevel(orig_level)
        logger.removeHandler(handler)


@pytest.fixture
def main_menu_mock(models, install_path):
    main_menu = Mock()
    main_menu.install_path = Path(install_path)
    main_menu.installPath = install_path

    main_menu.obfuscationv2 = Mock()
    obf_conf_mock = MagicMock()
    main_menu.obfuscationv2.get_obfuscation_config = Mock(
        side_effect=lambda x, y: obf_conf_mock
    )
    main_menu.obfuscationv2.get_obfuscation_config = Mock(
        return_value=models.ObfuscationConfig(
            language="python", command="", enabled=False
        )
    )
    main_menu.obfuscationv2.obfuscate = Mock(side_effect=fake_obfuscate)
    main_menu.obfuscationv2.obfuscate_keywords = Mock(side_effect=lambda x: x)
    main_menu.pluginsv2.get_by_id = Mock(
        side_effect=lambda x: Mock(enabled=False) if x == "csharpserver" else None
    )

    return main_menu


@pytest.fixture
def module_service(main_menu_mock):
    module_service = ModuleService(main_menu_mock)
    main_menu_mock.modulesv2 = module_service

    return module_service


@pytest.mark.slow
def test_load_modules(main_menu_mock, models, session_local):
    """
    This is just meant to be a small smoke test to ensure that the modules
    that come with Empire can be loaded properly at startup and a script can
    be generated with the default values.
    """
    # https://github.com/pytest-dev/pytest/issues/3697
    # caplog not working for some reason.
    with catch_logs(
        level=logging.INFO, logger=logging.getLogger(ModuleService.__module__)
    ) as handler:
        module_service = ModuleService(main_menu_mock)

        module_service.dotnet_compiler.compile_task = Mock(
            return_value=Path("/tmp/compiled_task.exe")
        )

        messages = [x.message for x in handler.records if x.levelno >= logging.WARNING]

    if messages:
        pytest.fail(f"warning messages encountered during testing: {messages}")

    min_modules = 300
    assert len(module_service.modules) > min_modules

    with session_local.begin() as db:
        assert len(db.query(models.Module).all()) > min_modules

        for key, module in module_service.modules.items():
            if not module.advanced.custom_generate:
                try:
                    err = None
                    resp = module_service._generate_script(
                        db, module, convert_options_to_params(module.options), None
                    )

                    if isinstance(resp, tuple):
                        resp, err = resp

                    if err != "csharpserver plugin not running":
                        # fail if a module fails to generate a script.
                        assert resp.data is not None, (
                            f"No generated script for module {key}"
                        )
                        assert len(resp.data) > 0, (
                            f"No generated script for module {key}"
                        )

                except ModuleValidationException as e:
                    # not gonna bother mocking out the csharp server right now.
                    if str(e) == "csharpserver plugin not running":
                        pass


def test_execute_custom_generate(
    module_service, session_local, agent, models, install_path
):
    with session_local.begin() as db:
        file_path = (
            Path(install_path).parent / "test/data/modules/test_custom_module.yaml"
        )
        root_path = Path(install_path).parent
        module_service._load_module(
            db, yaml.safe_load(file_path.read_text()), root_path, file_path
        )

        db_agent = (
            db.query(models.Agent).filter(models.Agent.session_id == agent).first()
        )
        execute, err = module_service.execute_module(
            db,
            db_agent,
            "test_data_modules_test_custom_module",
            {"Agent": agent},
            ignore_admin_check=True,
            ignore_language_version_check=True,
        )

        assert err is None
        assert execute.data == "This is the module code."


@contextmanager
def patch_module_source(module_service):
    old_source = module_service.module_source_path
    module_service.module_source_path = Path("empire/test/data/module_source")

    yield

    module_service.module_source_path = old_source


def test_auto_get_source(
    empire_config, module_service, session_local, agent, models, install_path
):
    with session_local.begin() as db, patch_module_source(module_service):
        source_path = Path(
            "empire/test/data/module_source/custom_module_auto_get_source.py"
        )
        file_path = (
            Path(install_path).parent
            / "test/data/modules/test_custom_module_auto_get_source.yaml"
        )
        root_path = Path(install_path).parent
        module_service._load_module(
            db, yaml.safe_load(file_path.read_text()), root_path, file_path
        )

        db_agent = (
            db.query(models.Agent).filter(models.Agent.session_id == agent).first()
        )
        execute, err = module_service.execute_module(
            db,
            db_agent,
            "test_data_modules_test_custom_module_auto_get_source",
            {"Agent": agent},
            ignore_admin_check=True,
            ignore_language_version_check=True,
        )

        assert err is None
        assert execute.data.strip() == source_path.read_text().strip()


def test_auto_finalize(
    empire_config, module_service, session_local, agent, models, install_path
):
    with session_local.begin() as db:
        file_path = (
            Path(install_path).parent
            / "test/data/modules/test_custom_module_auto_finalize.yaml"
        )
        root_path = Path(install_path).parent
        module_service._load_module(
            db, yaml.safe_load(file_path.read_text()), root_path, file_path
        )

        db_agent = (
            db.query(models.Agent).filter(models.Agent.session_id == agent).first()
        )
        execute, err = module_service.execute_module(
            db,
            db_agent,
            "test_data_modules_test_custom_module_auto_finalize",
            {"Agent": agent},
            ignore_admin_check=True,
            ignore_language_version_check=True,
        )

        assert err is None
        assert execute.data.strip() == "ScriptScriptEnd"


def test_ttps(install_path):
    module_dir = Path(install_path) / "modules"
    tactic_pattern = re.compile(r"TA\d{4}")
    technique_pattern = re.compile(r"T\d{4}(\.\d{3})?")

    for path in module_dir.rglob("*.y*ml"):
        try:
            mod = yaml.safe_load(path.read_text())

            for tactic in mod.get("tactics", []):
                assert tactic_pattern.match(tactic), (
                    f"Invalid tactic {tactic} in {path}"
                )
            for technique in mod.get("techniques", []):
                assert technique_pattern.match(technique), (
                    f"Invalid technique {technique} in {path}"
                )

        except Exception as e:
            pytest.fail(f"Error loading {path}: {e}")
