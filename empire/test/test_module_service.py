from pathlib import Path
from unittest.mock import Mock

import pytest

from empire.server.core.exceptions import ModuleValidationException
from empire.server.core.module_models import EmpireModuleOption
from empire.server.core.module_service import ModuleService


@pytest.fixture(scope="module")
def main_menu_mock(models, install_path):
    main_menu = Mock()
    main_menu.installPath = install_path
    main_menu.install_path = Path(install_path)
    main_menu.listeners.activeListeners = {}
    main_menu.listeners.listeners = {}
    main_menu.obfuscationv2 = Mock()
    main_menu.obfuscationv2.get_obfuscation_config = Mock(
        return_value=models.ObfuscationConfig(
            language="python", command="", enabled=False
        )
    )
    main_menu.obfuscationv2.obfuscate_keywords = Mock(side_effect=lambda x: x)

    return main_menu


@pytest.fixture(scope="module")
def module_service(main_menu_mock):
    module_service = ModuleService(main_menu=main_menu_mock)

    module_service.dotnet_compiler.compile_task = Mock(
        return_value=Path("/tmp/compiled_task.exe")
    )

    return module_service


@pytest.fixture
def agent_mock():
    agent_mock = Mock()
    agent_mock.session_id = "ABC123"
    return agent_mock


def test_execute_module_with_script_in_yaml_modified_python_agent(
    module_service, agent_mock
):
    agent_mock.language = "python"
    params = {
        "Agent": agent_mock.session_id,
        "Text": "Hello World",
    }
    module_id = "python_trollsploit_osx_say"
    res, err = module_service.execute_module(
        None, agent_mock, module_id, params, True, True, "Modified Script: {{ Text }}"
    )

    assert err is None
    script = res.data

    assert script == "Modified Script: Hello World"


def test_execute_module_with_script_in_path_powershell_agent(
    module_service, agent_mock
):
    agent_mock.language = "powershell"
    params = {
        "Agent": agent_mock.session_id,
        "BooSource": "Hello World",
    }
    module_id = "powershell_code_execution_invoke_boolang"
    res, err = module_service.execute_module(
        None, agent_mock, module_id, params, True, True, None
    )

    assert err is None
    script = res.data

    assert script.startswith("function Invoke-Boolang")


def test_execute_module_with_script_in_path_modified_powershell(
    module_service, agent_mock
):
    agent_mock.language = "powershell"
    params = {
        "Agent": agent_mock.session_id,
        "BooSource": "Hello World",
    }
    module_id = "powershell_code_execution_invoke_boolang"
    res, err = module_service.execute_module(
        None, agent_mock, module_id, params, True, True, "Modified Script: "
    )

    assert err is None
    script = res.data

    assert script.startswith(
        'Modified Script:  Invoke-Boolang -BooSource "Hello World"'
    )


def test_execute_module_custom_generate_no_obfuscation_config_powershell_agent(
    main_menu_mock, module_service, agent_mock
):
    agent_mock.language = "python"
    params = {"Agent": agent_mock.session_id}
    module_id = "python_collection_osx_search_email"

    main_menu_mock.obfuscationv2.get_obfuscation_config = Mock(
        side_effect=lambda x, y: None
    )
    res, err = module_service.execute_module(
        None, agent_mock, module_id, params, True, True, None
    )

    assert err is None
    script = res.data

    assert script == 'cmd = "find /Users/ -name *.emlx 2>/dev/null"\nrun_command(cmd)'


def test_execute_module_task_command_python_agent(module_service, agent_mock):
    agent_mock.language = "python"
    params = {
        "Agent": agent_mock.session_id,
        "Text": "Hello World",
    }
    module_id = "python_trollsploit_osx_say"
    res, err = module_service.execute_module(
        None, agent_mock, module_id, params, True, True, None
    )

    assert err is None

    script = res.data
    assert script == "run_command('say -v alex Hello World')"

    task_command = res.command
    assert task_command == "TASK_PYTHON_CMD_WAIT"


def test_execute_module_task_command_ironpython_agent(module_service, agent_mock):
    agent_mock.language = "ironpython"
    params = {
        "Agent": agent_mock.session_id,
        "Text": "Hello World",
    }
    module_id = "python_trollsploit_osx_say"
    res, err = module_service.execute_module(
        None, agent_mock, module_id, params, True, True, None
    )

    assert err is None
    task_command = res.command
    assert task_command == "TASK_PYTHON_CMD_WAIT"


def test_execute_module_task_command_csharp_agent_with_missing_csharp_module(
    module_service, agent_mock
):
    agent_mock.language = "csharp"
    params = {
        "Agent": agent_mock.session_id,
        "Text": "Hello World",
    }
    module_id = "csharp_execution_some_module"
    res, err = module_service.execute_module(
        None, agent_mock, module_id, params, True, True, None
    )

    assert err == "Module not found for id csharp_execution_some_module"


def test_execute_module_task_command_csharp_agent_with_csharp_module(
    module_service, agent_mock
):
    agent_mock.language = "csharp"
    params = {
        "Agent": agent_mock.session_id,
        "Command": "triage",
    }
    module_id = "csharp_credentials_rubeus"
    res, err = module_service.execute_module(
        None, agent_mock, module_id, params, True, True, None
    )

    assert err is None
    task_command = res.command
    assert task_command == "TASK_CSHARP_CMD_JOB"


@pytest.mark.parametrize(
    ("background_param", "expected_command"),
    [
        ("false", "TASK_CSHARP_CMD_WAIT"),
        ("true", "TASK_CSHARP_CMD_JOB"),
    ],
)
def test_execute_module_background_param_override(
    module_service, agent_mock, background_param, expected_command
):
    """Test that a runtime Background option overrides the module's YAML background setting."""
    agent_mock.language = "csharp"
    module_id = "csharp_credentials_rubeus"

    module = module_service.get_by_id(module_id)
    assert module.background is True, "Rubeus should have background=true in YAML"

    # Add a Background option to the module so validation passes it through
    original_options = module.options
    background_option = EmpireModuleOption(
        name="Background",
        description="Run as background job",
        required=False,
        value="true",
        type="bool",
        suggested_values=["true", "false"],
        strict=True,
    )
    module.options = [*original_options, background_option]

    try:
        params = {
            "Agent": agent_mock.session_id,
            "Command": "triage",
            "Background": background_param,
        }
        res, err = module_service.execute_module(
            None, agent_mock, module_id, params, True, True, None
        )

        assert err is None
        assert res.command == expected_command
    finally:
        module.options = original_options


def test_execute_module_bof_custom_generate(module_service, agent_mock):
    agent_mock.language = "csharp"
    params = {
        "Agent": agent_mock.session_id,
        "Architecture": "x64",
        "Domain": ".",
    }
    module_id = "bof_situational_awareness_adcs_enum"
    res, err = module_service.execute_module(
        None, agent_mock, module_id, params, True, True, None
    )

    assert err is None
    task_command = res.command
    assert task_command == "TASK_CSHARP_CMD_WAIT"


def test_execute_module_bof(module_service, agent_mock):
    agent_mock.language = "csharp"
    params = {
        "Agent": agent_mock.session_id,
        "Architecture": "x64",
        "Server": ".",
    }
    module_id = "bof_situational_awareness_tasklist"
    res, err = module_service.execute_module(
        None, agent_mock, module_id, params, True, True, None
    )

    assert err is None
    task_command = res.command
    assert task_command == "TASK_CSHARP_CMD_WAIT"


def test_execute_bof_module_missing_architecture(module_service, agent_mock):
    agent_mock.language = "csharp"
    params = {
        "Agent": agent_mock.session_id,
        "Architecture": "",
        "Server": ".",
    }
    module_id = "bof_situational_awareness_tasklist"

    with pytest.raises(ModuleValidationException) as excinfo:
        module_service.execute_module(
            None, agent_mock, module_id, params, True, True, None
        )

    assert "required option missing: Architecture" in str(excinfo.value)


def test_execute_csharp_module(module_service, agent_mock):
    agent_mock.language = "csharp"
    params = {
        "Agent": agent_mock.session_id,
        "Password": "password",
        "Port": "5900",
        "Username": "Empire",
    }
    module_id = "csharp_management_vnc"

    res, err = module_service.execute_module(
        None, agent_mock, module_id, params, True, True, None
    )

    assert err is None
    task_command = res.command
    assert task_command == "TASK_CSHARP_CMD_WAIT"


def test_execute_bof_module_missing_option(module_service, agent_mock):
    agent_mock.language = "csharp"
    params = {
        "Agent": agent_mock.session_id,
        "Password": "password",
        "Port": "",
        "Username": "Empire",
    }
    module_id = "csharp_management_vnc"

    with pytest.raises(ModuleValidationException) as excinfo:
        module_service.execute_module(
            None, agent_mock, module_id, params, True, True, None
        )

    assert "required option missing: Port" in str(excinfo.value)


def test_execute_module_task_command_powershell_agent(module_service, agent_mock):
    agent_mock.language = "powershell"
    params = {
        "Agent": agent_mock.session_id,
        "BooSource": "Hello World",
    }
    module_id = "powershell_code_execution_invoke_boolang"
    res, err = module_service.execute_module(
        None, agent_mock, module_id, params, True, True, None
    )

    assert err is None
    task_command = res.command
    assert task_command == "TASK_POWERSHELL_CMD_JOB"


def test_execute_module_task_command_unsupported_agent_language(
    module_service, agent_mock
):
    agent_mock.language = "unsupported_language"
    params = {
        "Agent": agent_mock.session_id,
        "BooSource": "Hello World",
    }
    module_id = "powershell_code_execution_invoke_boolang"

    with pytest.raises(ModuleValidationException) as excinfo:
        module_service.execute_module(
            None, agent_mock, module_id, params, True, True, None
        )

    assert "Unsupported agent language 'unsupported_language'" in str(excinfo.value)


def test_execute_module_with_non_ascii_characters(module_service, agent_mock):
    agent_mock.language = "python"
    params = {
        "Agent": agent_mock.session_id,
        "Text": "こんにちは世界",
    }
    module_id = "python_trollsploit_osx_say"

    res, err = module_service.execute_module(
        None, agent_mock, module_id, params, True, True, None
    )

    assert err is None
    assert res.data


def test_execute_disabled_module(module_service, agent_mock):
    agent_mock.language = "python"
    params = {
        "Agent": agent_mock.session_id,
        "Text": "Hello World",
    }
    module_id = "python_trollsploit_osx_say"

    module = module_service.get_by_id(module_id)
    module.enabled = False

    res, err = module_service.execute_module(
        None, agent_mock, module_id, params, True, True, None
    )

    module.enabled = True

    assert res is None
    assert err == "Cannot execute disabled module"


def test_execute_module_validation_error(module_service, agent_mock):
    agent_mock.language = "python"
    params = {
        "InvalidParam": "invalid_value",
    }
    module_id = "python_trollsploit_osx_say"

    with pytest.raises(ModuleValidationException) as excinfo:
        module_service.execute_module(
            None, agent_mock, module_id, params, True, True, None
        )

    assert "required option missing: Agent" in str(excinfo.value)


def test_execute_module_with_empty_params(module_service, agent_mock):
    agent_mock.language = "python"
    params = {}
    module_id = "python_trollsploit_osx_say"

    with pytest.raises(ModuleValidationException) as excinfo:
        module_service.execute_module(
            None, agent_mock, module_id, params, True, True, None
        )

    assert "required option missing: Agent" in str(excinfo.value)


@pytest.mark.parametrize(
    ("agent_language", "module_language", "should_raise"),
    [
        # Valid combinations
        ("go", "bof", False),
        ("go", "powershell", False),
        ("go", "csharp", False),
        ("ironpython", "bof", False),
        ("ironpython", "powershell", False),
        ("ironpython", "csharp", False),
        ("ironpython", "python", False),
        ("powershell", "bof", False),
        ("powershell", "powershell", False),
        ("powershell", "csharp", False),
        ("csharp", "bof", False),
        ("csharp", "powershell", False),
        ("csharp", "csharp", False),
        ("python", "python", False),
        # Invalid combinations
        ("go", "python", True),
        ("go", "ironpython", True),
        ("powershell", "python", True),
        ("powershell", "ironpython", True),
        ("csharp", "python", True),
        ("csharp", "ironpython", True),
        ("python", "powershell", True),
        ("python", "csharp", True),
        ("python", "bof", True),
    ],
)
def test_validate_agent_module_language_compatibility(
    module_service, agent_mock, agent_language, module_language, should_raise
):
    agent_mock.language = agent_language
    agent_mock.language_version = "5.1"

    module_mock = Mock()
    module_mock.language = module_language
    module_mock.min_language_version = "5.0"
    module_mock.needs_admin = False
    module_mock.options = {}

    params = {"Agent": agent_mock.session_id}

    if should_raise:
        with pytest.raises(ModuleValidationException) as excinfo:
            module_service._validate_module_params(
                None, module_mock, agent_mock, params
            )
        assert (
            f"agent language '{agent_language}' cannot run module language '{module_language}'"
            in str(excinfo.value)
        )
    else:
        options, err = module_service._validate_module_params(
            None, module_mock, agent_mock, params
        )
        assert err is None
        assert options is not None


@pytest.mark.parametrize(
    ("needs_admin", "high_integrity", "ignore_admin_check", "should_raise"),
    [
        (
            True,
            False,
            False,
            True,
        ),  # Needs admin, no high integrity, no ignore -> should raise
        (
            True,
            False,
            True,
            False,
        ),  # Needs admin, no high integrity, but ignored -> should not raise
        (
            True,
            True,
            False,
            False,
        ),  # Needs admin, has high integrity -> should not raise
        (False, False, False, False),  # Does not need admin -> should not raise
    ],
)
def test_validate_module_admin_check(
    module_service,
    agent_mock,
    needs_admin,
    high_integrity,
    ignore_admin_check,
    should_raise,
):
    agent_mock.language = "powershell"
    agent_mock.language_version = "5.1"
    agent_mock.high_integrity = high_integrity

    module_mock = Mock()
    module_mock.language = "powershell"
    module_mock.min_language_version = "5.0"
    module_mock.needs_admin = needs_admin
    module_mock.options = {}

    params = {"Agent": agent_mock.session_id}

    if needs_admin and not high_integrity and not ignore_admin_check:
        with pytest.raises(ModuleValidationException) as excinfo:
            module_service._validate_module_params(
                None,
                module_mock,
                agent_mock,
                params,
                ignore_admin_check=ignore_admin_check,
            )
        assert "module needs to run in an elevated context" in str(excinfo.value)
    else:
        options, err = module_service._validate_module_params(
            None, module_mock, agent_mock, params, ignore_admin_check=ignore_admin_check
        )
        assert err is None
        assert options is not None


@pytest.mark.parametrize(
    (
        "agent_language",
        "module_language",
        "agent_version",
        "module_version",
        "ignore_version_check",
        "should_raise",
    ),
    [
        ("powershell", "powershell", "4.0", "5.0", False, True),  # Version too low
        ("powershell", "powershell", "5.0", "5.0", False, False),  # Matching versions
        (
            "powershell",
            "powershell",
            "6.0",
            "5.0",
            False,
            False,
        ),  # Agent version higher than required
        (
            "powershell",
            "powershell",
            "4.0",
            "5.0",
            True,
            False,
        ),  # Ignoring version check
        ("csharp", "csharp", "3.0", "3.5", False, True),  # C# version too low
        ("csharp", "csharp", "3.5", "3.5", False, False),  # C# version matches
        ("csharp", "csharp", "4.0", "3.5", False, False),  # C# agent version higher
    ],
)
def test_validate_module_version_check(
    module_service,
    agent_mock,
    agent_language,
    module_language,
    agent_version,
    module_version,
    ignore_version_check,
    should_raise,
):
    agent_mock.language = agent_language
    agent_mock.language_version = agent_version

    module_mock = Mock()
    module_mock.language = module_language
    module_mock.min_language_version = module_version
    module_mock.needs_admin = False
    module_mock.options = {}

    params = {"Agent": agent_mock.session_id}

    if should_raise:
        with pytest.raises(ModuleValidationException) as excinfo:
            module_service._validate_module_params(
                None,
                module_mock,
                agent_mock,
                params,
                ignore_language_version_check=ignore_version_check,
            )
        assert (
            f"module requires language version {module_version} but agent running language version {agent_version}"
            in str(excinfo.value)
        )
    else:
        options, err = module_service._validate_module_params(
            None,
            module_mock,
            agent_mock,
            params,
            ignore_language_version_check=ignore_version_check,
        )
        assert err is None
        assert options is not None
