from unittest.mock import MagicMock

from empire.server.utils.option_util import (
    evaluate_dependencies,
    safe_cast,
    validate_options,
)


def test_validate_options_required_strict_success():
    instance_options = {
        "enabled": {
            "Description": "Enable/Disable the module",
            "Required": True,
            "Value": "True",
            "SuggestedValues": ["True", "False"],
            "Strict": True,
        },
    }

    options = {
        "enabled": "True",
    }

    cleaned_options, _err = validate_options(instance_options, options, None, None)

    assert cleaned_options == options


def test_validate_options_required_strict_failure():
    instance_options = {
        "enabled": {
            "Description": "Enable/Disable the module",
            "Required": True,
            "Value": "True",
            "SuggestedValues": ["True", "False"],
            "Strict": True,
        },
    }

    options = {
        "enabled": "Wrong",
    }

    cleaned_options, err = validate_options(instance_options, options, None, None)

    assert cleaned_options is None
    assert err == "enabled must be set to one of the suggested values."


def test_validate_options_required_empty_failure_doesnt_use_default():
    instance_options = {
        "Command": {
            "Description": "Command to run",
            "Required": True,
            "Value": "DEFAULT_VALUE",
            "SuggestedValues": [],
            "Strict": False,
        }
    }

    options = {
        "Command": "",
    }

    cleaned_options, err = validate_options(instance_options, options, None, None)

    assert cleaned_options is None
    assert err == "required option missing: Command"


def test_validate_options_required_missing_uses_default():
    instance_options = {
        "Command": {
            "Description": "Command to run",
            "Required": True,
            "Value": "DEFAULT_VALUE",
            "SuggestedValues": [],
            "Strict": False,
        }
    }

    options = {}

    cleaned_options, _err = validate_options(instance_options, options, None, None)

    assert cleaned_options == {"Command": "DEFAULT_VALUE"}


def test_validate_options_casts_string_to_int_success():
    # Not going to bother testing every combo here since its already tested independently
    instance_options = {
        "Port": {
            "Description": "Port to listen on",
            "Required": True,
            "Value": "DEFAULT_VALUE",
            "SuggestedValues": [],
            "Strict": False,
            "Type": "int",
        }
    }

    options = {
        "Port": "123",
    }

    cleaned_options, _err = validate_options(instance_options, options, None, None)

    assert cleaned_options == {"Port": 123}


def test_validate_options_missing_optional_field_no_default():
    instance_options = {
        "Command": {
            "Description": "Command to run",
            "Required": False,
            "Value": "",
            "SuggestedValues": [],
            "Strict": False,
        }
    }

    options = {}

    cleaned_options, _err = validate_options(instance_options, options, None, None)

    assert cleaned_options == {"Command": ""}


def test_validate_options_strict_required_no_default():
    instance_options = {
        "Command": {
            "Description": "Command to run",
            "Required": True,
            "Value": "",
            "SuggestedValues": ["True", "False"],
            "Strict": True,
        }
    }

    options = {}

    _cleaned_options, err = validate_options(instance_options, options, None, None)

    assert err == "required option missing: Command"


def test_validate_options_missing_optional_field_with_default():
    instance_options = {
        "Command": {
            "Description": "Command to run",
            "Required": False,
            "Value": "Test",
            "SuggestedValues": [],
            "Strict": False,
        }
    }

    options = {}

    cleaned_options, _err = validate_options(instance_options, options, None, None)

    assert cleaned_options == {"Command": "Test"}


def test_validate_options_missing_optional_field_with_default_and_strict():
    instance_options = {
        "Command": {
            "Description": "Command to run",
            "Required": False,
            "Value": "Test",
            "SuggestedValues": ["Test"],
            "Strict": True,
        }
    }

    options = {}

    cleaned_options, _err = validate_options(instance_options, options, None, None)

    assert cleaned_options == {"Command": "Test"}


def test_validate_options_with_uneditable_field():
    instance_options = {
        "UneditableField": {
            "Description": "Uneditable Field",
            "Required": False,
            "Value": "DEFAULT_VALUE",
            "Editable": False,
        }
    }

    options = {"UneditableField": "Test"}

    cleaned_options, _err = validate_options(instance_options, options, None, None)

    assert cleaned_options == {}


def test_validate_options_with_file_not_found(session_local):
    instance_options = {
        "File": {
            "Description": "A File",
            "Required": True,
            "Strict": False,
            "Type": "file",
            "DependsOn": None,
        }
    }

    options = {
        "File": "9999",
    }

    download_service_mock = MagicMock()
    download_service_mock.get_by_id.return_value = None

    with session_local.begin() as db:
        cleaned_options, err = validate_options(
            instance_options, options, db, download_service_mock
        )

        assert cleaned_options is None
        assert err == "File not found for 'File' id 9999"


def test_validate_options_with_file(session_local, models):
    instance_options = {
        "File": {
            "Description": "A File",
            "Required": True,
            "Strict": False,
            "Type": "file",
            "DependsOn": None,
        }
    }

    options = {
        "File": "9999",
    }

    download = models.Download(id=9999, filename="test_file", location="/tmp/test_file")
    download_service_mock = MagicMock()
    download_service_mock.get_by_id.return_value = download

    with session_local.begin() as db:
        cleaned_options, _err = validate_options(
            instance_options, options, db, download_service_mock
        )

        assert cleaned_options["File"] == download


def test_safe_cast_string():
    assert safe_cast("abc", str) == "abc"


def test_safe_cast_int_from_string():
    assert safe_cast("1", int) == 1


def test_safe_cast_int_from_int():
    assert safe_cast(1, int) == 1


def test_safe_cast_float_from_float():
    assert safe_cast(1.0, float) == 1.0


def test_safe_cast_float_from_int():
    assert safe_cast(1, float) == 1.0


def test_safe_cast_float_from_string():
    assert safe_cast("1", float) == 1.0


def test_safe_cast_float_from_string_2():
    assert safe_cast("1.0", float) == 1.0


def test_safe_cast_boolean_from_string_true():
    assert safe_cast("True", bool) is True
    assert safe_cast("TRUE", bool) is True
    assert safe_cast("true", bool) is True


def test_safe_cast_boolean_from_string_false():
    assert safe_cast("False", bool) is False
    assert safe_cast("false", bool) is False
    assert safe_cast("FALSE", bool) is False


def test_evaluate_dependencies_no_depends_on():
    option = {"name": "Option1", "Value": "Test"}
    params = {"Option1": "Test"}
    assert evaluate_dependencies(option, params) is True


def test_evaluate_dependencies_single_dependency_met():
    option = {
        "name": "Option1",
        "Value": "Test",
        "depends_on": [{"name": "Option2", "values": ["True"]}],
    }
    params = {"Option1": "Test", "Option2": "True"}
    assert evaluate_dependencies(option, params) is True


def test_evaluate_dependencies_single_dependency_not_met():
    option = {
        "name": "Option1",
        "Value": "Test",
        "depends_on": [{"name": "Option2", "values": ["True"]}],
    }
    params = {"Option1": "Test", "Option2": "False"}
    assert evaluate_dependencies(option, params) is False


def test_evaluate_dependencies_multiple_dependencies_met():
    option = {
        "name": "Option1",
        "Value": "Test",
        "depends_on": [
            {"name": "Option2", "values": ["True"]},
            {"name": "Option3", "values": ["Enabled"]},
        ],
    }
    params = {"Option1": "Test", "Option2": "True", "Option3": "Enabled"}
    assert evaluate_dependencies(option, params) is True


def test_evaluate_dependencies_multiple_dependencies_not_met():
    option = {
        "name": "Option1",
        "Value": "Test",
        "depends_on": [
            {"name": "Option2", "values": ["True"]},
            {"name": "Option3", "values": ["Enabled"]},
        ],
    }
    params = {"Option1": "Test", "Option2": "False", "Option3": "Enabled"}
    assert evaluate_dependencies(option, params) is False


def test_evaluate_dependencies_dependency_not_present_in_params():
    option = {
        "name": "Option1",
        "Value": "Test",
        "depends_on": [{"name": "Option2", "values": ["True"]}],
    }
    params = {"Option1": "Test"}
    assert evaluate_dependencies(option, params) is False


def test_validate_options_internal_option_skipped():
    instance_options = {
        "internal_option": {
            "Description": "An internal option",
            "Required": True,
            "Value": "Test",
            "Internal": True,
        },
    }
    options = {"internal_option": "Test"}
    cleaned_options, err = validate_options(instance_options, options, None, None)

    assert "internal_option" not in cleaned_options
    assert err is None


def test_validate_options_type_cast_failure():
    instance_options = {
        "Port": {
            "Description": "Port to listen on",
            "Required": True,
            "Type": "int",
        }
    }
    options = {"Port": "NotANumber"}
    cleaned_options, err = validate_options(instance_options, options, None, None)

    assert cleaned_options is None
    assert (
        err
        == "incorrect type for option Port. Expected <class 'int'> but got <class 'str'>"
    )


def test_validate_options_dependency_not_met():
    instance_options = {
        "DependentOption": {
            "Description": "An option with dependencies",
            "Required": True,
            "depends_on": [{"name": "AnotherOption", "values": ["True"]}],
        }
    }
    options = {"AnotherOption": "False"}
    cleaned_options, err = validate_options(instance_options, options, None, None)

    assert "DependentOption" not in cleaned_options
    assert err is None


def test_validate_options_dependency_met(session_local):
    instance_options = {
        "DependentOption": {
            "Description": "An option with dependencies",
            "Required": True,
            "depends_on": [{"name": "AnotherOption", "values": ["True"]}],
            "Value": "SomeValue",
        }
    }
    options = {"AnotherOption": "True"}

    with session_local.begin() as db:
        cleaned_options, err = validate_options(instance_options, options, db, None)

        assert "DependentOption" in cleaned_options
        assert err is None


def test_validate_options_with_name_in_code():
    instance_options = {
        "OriginalName": {
            "Description": "An option with NameInCode",
            "Required": True,
            "Value": "SomeValue",
            "NameInCode": "CodeName",
        }
    }
    options = {"OriginalName": "SomeValue"}
    cleaned_options, err = validate_options(instance_options, options, None, None)

    assert cleaned_options == {"CodeName": "SomeValue"}
    assert err is None


def test_validate_options_file_with_correct_script_type(session_local, models):
    instance_options = {
        "ScriptType": {
            "Description": "Type of script to execute",
            "Required": True,
            "Internal": True,
            "Value": "File",
            "SuggestedValues": ["File", "URL"],
            "Strict": True,
        },
        "File": {
            "Description": "A PowerShell script to load",
            "Required": False,
            "Value": "",
            "Type": "file",
            "DependsOn": [{"name": "ScriptType", "values": ["File"]}],
        },
        "ScriptUrl": {
            "Description": "URL to download a Python script from.",
            "Required": False,
            "Value": "https://test.com/",
            "DependsOn": [{"name": "ScriptType", "values": ["URL"]}],
        },
    }

    options = {
        "ScriptType": "File",
        "File": "9999",
        "ScriptUrl": "https://test.com/",
    }

    download = models.Download(
        id=9999, filename="test_file.ps1", location="/tmp/test_file.ps1"
    )
    download_service_mock = MagicMock()
    download_service_mock.get_by_id.return_value = download

    with session_local.begin() as db:
        cleaned_options, err = validate_options(
            instance_options, options, db, download_service_mock
        )

        assert "File" in cleaned_options
        assert cleaned_options["File"] == download
        assert err is None


def test_validate_options_file_skipped_with_url_script_type():
    instance_options = {
        "ScriptType": {
            "Description": "Type of script to execute",
            "Required": True,
            "Value": "URL",
            "Internal": True,
            "SuggestedValues": ["File", "URL"],
            "Strict": True,
        },
        "File": {
            "Description": "A PowerShell script to load",
            "Required": False,
            "Value": "",
            "Type": "file",
            "DependsOn": [{"name": "ScriptType", "values": ["File"]}],
        },
        "ScriptUrl": {
            "Description": "URL to download a Python script from.",
            "Required": False,
            "Value": "https://test.com/",
            "DependsOn": [{"name": "ScriptType", "values": ["URL"]}],
        },
    }

    options = {
        "ScriptType": "URL",
        "File": "",
        "ScriptUrl": "https://test.com/",
    }

    cleaned_options, err = validate_options(instance_options, options, None, None)

    assert cleaned_options["File"] == ""
    assert cleaned_options["ScriptUrl"] == "https://test.com/"
    assert err is None


def test_validate_options_file_missing_with_file_script_type():
    instance_options = {
        "ScriptType": {
            "Description": "Type of script to execute",
            "Required": True,
            "Internal": True,
            "Value": "File",
            "SuggestedValues": ["File", "URL"],
            "Strict": True,
        },
        "File": {
            "Description": "A PowerShell script to load",
            "Required": False,
            "Value": "",
            "Type": "file",
            "DependsOn": [{"name": "ScriptType", "values": ["File"]}],
        },
        "ScriptUrl": {
            "Description": "URL to download a Python script from.",
            "Required": False,
            "Value": "https://test.com/",
            "DependsOn": [{"name": "ScriptType", "values": ["URL"]}],
        },
    }

    options = {
        "ScriptType": "File",
        "File": "",
        "ScriptUrl": "https://test.com/",
    }

    cleaned_options, err = validate_options(instance_options, options, None, None)

    assert cleaned_options is None
    assert err == "required option missing: File"


def test_validation_options_file_not_required():
    instance_options = {
        "File": {
            "Description": "A file",
            "Required": False,
            "Value": "",
            "Type": "file",
        }
    }

    options = {"File": ""}
    cleaned_options, _err = validate_options(instance_options, options, None, None)

    assert cleaned_options == {"File": ""}
