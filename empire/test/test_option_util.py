from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from empire.server.core.config import config_manager
from empire.server.core.exceptions import ModuleValidationException
from empire.server.core.module_models import EmpireModuleOption
from empire.server.core.option_types import (
    _TYPE_STR_TO_PY,
    _TYPE_STR_TO_VALUETYPE,
    _VALUETYPE_TO_PYTYPE,
    _VALUETYPE_TO_TAG,
    ValueType,
    to_value_type,
)
from empire.server.utils.option_util import (
    coerce_legacy_value,
    confine_to_downloads,
    evaluate_dependencies,
    is_option_required,
    safe_cast,
    validate_options,
)


def test_option_type_tables_are_self_consistent():
    # The `option_types` tables are a single source of truth: `_TYPE_STR_TO_PY`
    # is derived from `_TYPE_STR_TO_VALUETYPE`, so their key sets must match,
    # and `_VALUETYPE_TO_PYTYPE` must realize every `ValueType` member (else the
    # derivation would KeyError at import).
    assert set(_TYPE_STR_TO_PY) == set(_TYPE_STR_TO_VALUETYPE)
    assert set(_VALUETYPE_TO_PYTYPE) == set(ValueType)


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


def test_validate_options_required_bool_with_default_is_noop():
    # `Required` is a presence check, not a value check. A boolean always
    # carries a value, so `Required: True` on a bool with a default can never
    # fail validation — it is effectively a no-op. See the note on
    # `EmpireModuleOption.required`.
    instance_options = {
        "Debug": {
            "Description": "Enable debug output",
            "Required": True,
            "Value": "False",
            "SuggestedValues": [],
            "Strict": False,
            "Type": "bool",
        }
    }

    cleaned_options, err = validate_options(instance_options, {}, None, None)

    assert err is None
    assert cleaned_options == {"Debug": False}


def test_validate_options_required_bool_empty_string_param_is_rejected():
    # The single path where `Required` is observable for a bool: a client that
    # explicitly sends an empty string (which a toggle UI never does). The empty
    # value trips the presence check before it can be cast to a bool.
    instance_options = {
        "Debug": {
            "Description": "Enable debug output",
            "Required": True,
            "Value": "False",
            "SuggestedValues": [],
            "Strict": False,
            "Type": "bool",
        }
    }

    cleaned_options, err = validate_options(instance_options, {"Debug": ""}, None, None)

    assert cleaned_options is None
    assert err == "required option missing: Debug"


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


def test_safe_cast_boolean_from_bool():
    assert safe_cast(True, bool) is True
    assert safe_cast(False, bool) is False


def test_safe_cast_boolean_silent_coercion_edges():
    # Pin the documented "truthy-string" contract so a future refactor of the
    # bool branch doesn't silently flip these. Only `"true"` (any case) and
    # `"1"` map to True; everything else — including `None`, `0`, `"yes"`,
    # `"on"`, and the literal string `"2"` — maps to False (or None in the
    # case of None, where str(None).lower() == "none" is not in the truthy set).
    assert safe_cast(None, bool) is False
    assert safe_cast(0, bool) is False
    assert safe_cast(1, bool) is True
    assert safe_cast("1", bool) is True
    assert safe_cast("2", bool) is False
    assert safe_cast("yes", bool) is False
    assert safe_cast("on", bool) is False
    assert safe_cast("", bool) is False


def test_coerce_legacy_value():
    # Native primitives stringify for the legacy generate-path string builders.
    assert coerce_legacy_value(True) == "True"
    assert coerce_legacy_value(False) == "False"
    assert coerce_legacy_value(100) == "100"
    assert coerce_legacy_value(1.5) == "1.5"
    # Strings, None, and non-primitives (e.g. file-download objects) pass through
    # unchanged so the `.lower()` / `get_base64_file()` consumers still work.
    assert coerce_legacy_value("already a string") == "already a string"
    assert coerce_legacy_value("") == ""
    assert coerce_legacy_value(None) is None
    sentinel = object()
    assert coerce_legacy_value(sentinel) is sentinel


def test_safe_cast_non_bool_returns_none_on_typeerror():
    # Pin the post-PR safe_cast contract: TypeError from `expected_option_type(option)`
    # surfaces as None (caller `_safe_cast_option` translates this into
    # "incorrect type for option X"). Regression target: `int(None)` and
    # `int([])` previously raised; widening the catch was intentional but
    # narrowly scoped to the type-call path.
    assert safe_cast(None, int) is None
    assert safe_cast([1, 2], int) is None
    assert safe_cast({"a": 1}, int) is None
    # ValueError path still returns None.
    assert safe_cast("not-a-number", int) is None


def test_validate_options_strict_with_legacy_string_suggested_values():
    # "Hybrid YAML" shape (`strict: true` + `suggested_values: ['True','False']`
    # + bool type). validate_options no longer stringifies native primitives, so
    # a *direct* caller passing native `True` is now rejected by the strict
    # membership check (`True not in ["True", "False"]`). This direct-call path
    # is unreachable via the HTTP API, where `coerced_dict` stringifies every
    # option value to "True"/"False" before validation — the stringly path below
    # is the real API contract and still passes.
    instance_options = {
        "Debug": {
            "Description": "Debug toggle (legacy hybrid shape).",
            "Required": False,
            "Value": "False",
            "SuggestedValues": ["True", "False"],
            "Strict": True,
            "Type": "bool",
        },
    }

    # Native bool no longer matches the stringly suggested values (direct call).
    _, err = validate_options(instance_options, {"Debug": True}, None, None)
    assert err is not None

    # Stringly param (the API contract) passes the strict check, then
    # `_safe_cast_option` casts it to native bool because Type == "bool".
    cleaned, err = validate_options(instance_options, {"Debug": "True"}, None, None)
    assert err is None
    assert cleaned == {"Debug": True}


def test_evaluate_dependencies_no_depends_on():
    option = {"name": "Option1", "Value": "Test"}
    params = {"Option1": "Test"}
    assert evaluate_dependencies(option, params) is True


def test_evaluate_dependencies_single_dependency_met():
    option = {
        "name": "Option1",
        "Value": "Test",
        "DependsOn": [{"name": "Option2", "values": ["True"]}],
    }
    params = {"Option1": "Test", "Option2": "True"}
    assert evaluate_dependencies(option, params) is True


def test_evaluate_dependencies_single_dependency_not_met():
    option = {
        "name": "Option1",
        "Value": "Test",
        "DependsOn": [{"name": "Option2", "values": ["True"]}],
    }
    params = {"Option1": "Test", "Option2": "False"}
    assert evaluate_dependencies(option, params) is False


def test_evaluate_dependencies_multiple_dependencies_met():
    option = {
        "name": "Option1",
        "Value": "Test",
        "DependsOn": [
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
        "DependsOn": [
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
        "DependsOn": [{"name": "Option2", "values": ["True"]}],
    }
    params = {"Option1": "Test"}
    assert evaluate_dependencies(option, params) is False


def test_is_option_required_tolerates_valueless_depends_on():
    """A depends_on entry without a "values" key imposes no value constraint and
    must not crash.

    Regression guard: is_option_required used to index ``dependency["values"]``
    unconditionally, so a valueless depends_on (e.g. ``- name: Obfuscate`` with
    no values) raised ``KeyError`` at validation time. It now gates on values
    only when they are listed.
    """
    # Valueless dependency, dependent option present -> required (no crash).
    option_meta = {"Required": False, "DependsOn": [{"name": "Obfuscate"}]}
    assert is_option_required(option_meta, {"Obfuscate": "True"}) is True

    # Mixed with a valued dependency: required only when the valued one matches.
    mixed = {
        "Required": False,
        "DependsOn": [
            {"name": "Language", "values": ["powershell"]},
            {"name": "Obfuscate"},
        ],
    }
    assert (
        is_option_required(mixed, {"Language": "powershell", "Obfuscate": "True"})
        is True
    )
    assert (
        is_option_required(mixed, {"Language": "csharp", "Obfuscate": "True"}) is False
    )


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
            "DependsOn": [{"name": "AnotherOption", "values": ["True"]}],
        }
    }
    options = {"AnotherOption": "False"}
    cleaned_options, err = validate_options(instance_options, options, None, None)

    assert cleaned_options["DependentOption"] == ""
    assert err is None


def test_validate_options_dependency_with_stringly_values():
    # `depends_on` values in YAML are stringly (`values: ["True"]`), and
    # `evaluate_dependencies` compares them verbatim. validate_options no longer
    # stringifies native primitives, so the parent value must already be a string
    # for the dependency to match. Via the HTTP API this always holds:
    # `coerced_dict` coerces a POSTed native `true` to "True" before validation.
    instance_options = {
        "Obfuscate": {
            "Description": "Obfuscate the script",
            "Required": False,
            "Value": "False",
            "Type": "bool",
        },
        "ObfuscateCommand": {
            "Description": "Obfuscation command",
            "Required": False,
            "Value": "Token\\All\\1",
            "DependsOn": [{"name": "Obfuscate", "values": ["True"]}],
        },
    }

    # The API contract: stringly "True" matches the stringly depends_on value,
    # the dependency is met, and the user's ObfuscateCommand is kept.
    cleaned_options, err = validate_options(
        instance_options,
        {"Obfuscate": "True", "ObfuscateCommand": "MyCustomObfuscation"},
        None,
        None,
    )
    assert err is None
    assert cleaned_options["ObfuscateCommand"] == "MyCustomObfuscation"
    # safe_cast re-emerges the parent as a native bool in the returned options.
    assert cleaned_options["Obfuscate"] is True

    # A *direct* caller passing native `True` no longer matches the stringly
    # depends_on value (`True not in ["True"]`), so the dependency is treated as
    # unmet and ObfuscateCommand falls back to its default. This path is
    # unreachable via the API (coerced_dict stringifies first).
    cleaned_options, err = validate_options(
        instance_options,
        {"Obfuscate": True, "ObfuscateCommand": "MyCustomObfuscation"},
        None,
        None,
    )
    assert err is None
    assert cleaned_options["ObfuscateCommand"] == "Token\\All\\1"


def test_validate_options_gated_default_is_native_typed():
    # Regression pin: when an option's `depends_on` is unmet, validate_options
    # returns its default value. That default must be cast to the option's
    # native type (matching the validated branch) — otherwise a gated bool
    # option's stringly "False" default reaches generate() as a truthy string
    # and a native `if params["X"]:` check silently inverts (e.g. obfuscation
    # turning on for non-PowerShell launchers). String/int defaults must round-
    # trip to their native types too.
    instance_options = {
        "Language": {
            "Description": "",
            "Required": True,
            "Value": "powershell",
            "SuggestedValues": ["powershell", "csharp"],
            "Strict": True,
            "Type": "string",
        },
        "Obfuscate": {
            "Description": "",
            "Required": False,
            "Value": "False",  # stringly default, as loaded from YAML
            "Type": "bool",
            "DependsOn": [{"name": "Language", "values": ["powershell"]}],
        },
        "Threads": {
            "Description": "",
            "Required": False,
            "Value": "5",
            "Type": "int",
            "DependsOn": [{"name": "Language", "values": ["powershell"]}],
        },
    }
    # Language=csharp -> both gated options' dependency is unmet -> defaults.
    cleaned, err = validate_options(
        instance_options, {"Language": "csharp"}, None, None
    )
    assert err is None
    # Native bool, not the truthy string "False".
    assert cleaned["Obfuscate"] is False
    # Native int, cast from the stringly default "5".
    assert cleaned["Threads"] == int(instance_options["Threads"]["Value"])
    assert isinstance(cleaned["Threads"], int)


def test_validate_options_dependency_met(session_local):
    instance_options = {
        "DependentOption": {
            "Description": "An option with dependencies",
            "Required": True,
            "DependsOn": [{"name": "AnotherOption", "values": ["True"]}],
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


def test_to_value_type_explicit_bool_with_string_value():
    """Explicit type='bool' should return BOOLEAN even when value is a string."""
    assert to_value_type("False", "bool") == ValueType.boolean
    assert to_value_type("True", "bool") == ValueType.boolean
    assert to_value_type("true", "boolean") == ValueType.boolean


def test_to_value_type_explicit_int_with_string_value():
    assert to_value_type("8080", "int") == ValueType.integer
    assert to_value_type("42", "integer") == ValueType.integer


def test_to_value_type_explicit_float_with_string_value():
    assert to_value_type("3.14", "float") == ValueType.float


def test_to_value_type_explicit_string():
    assert to_value_type("hello", "string") == ValueType.string
    assert to_value_type("hello", "str") == ValueType.string


def test_to_value_type_explicit_file():
    assert to_value_type("somefile", "file") == ValueType.file


def test_to_value_type_infer_from_value():
    """When type is empty, infer from the Python type of value."""
    assert to_value_type(True) == ValueType.boolean
    assert to_value_type(False) == ValueType.boolean
    assert to_value_type(42) == ValueType.integer
    assert to_value_type(3.14) == ValueType.float
    assert to_value_type("hello") == ValueType.string


def test_module_option_infers_bool_type():
    opt = EmpireModuleOption(name="Debug", value=False)
    assert opt.type == "bool"
    assert opt.value == "False"


def test_module_option_infers_bool_type_true():
    opt = EmpireModuleOption(name="Debug", value=True)
    assert opt.type == "bool"
    assert opt.value == "True"


def test_module_option_infers_int_type():
    opt = EmpireModuleOption(name="Port", value=8080)
    assert opt.type == "int"
    assert opt.value == "8080"


def test_module_option_infers_float_type():
    opt = EmpireModuleOption(name="Rate", value=3.14)
    assert opt.type == "float"
    assert opt.value == "3.14"


def test_module_option_string_no_type_inference():
    opt = EmpireModuleOption(name="Command", value="whoami")
    assert opt.type is None
    assert opt.value == "whoami"


def test_module_option_explicit_type_takes_precedence():
    opt = EmpireModuleOption(name="Port", value=8080, type="string")
    assert opt.type == "string"
    assert opt.value == "8080"


def test_module_option_default_empty_string():
    opt = EmpireModuleOption(name="Command")
    assert opt.value == ""
    assert opt.type is None


def test_module_option_suggested_values_coerced_to_strings():
    opt = EmpireModuleOption(name="Port", suggested_values=[80, 443, 8080])
    assert opt.suggested_values == ["80", "443", "8080"]


def test_validate_options_does_not_mutate_caller_params():
    # Guards `params.copy()`: validate_options writes into its local params
    # (the `Value` default backfill at the `not in params` branch), so it must
    # rebind to a fresh copy and never touch the caller's dict.
    instance_options = {
        "Command": {
            "Description": "",
            "Required": False,
            "Value": "DEFAULT_VALUE",
            "SuggestedValues": [],
            "Strict": False,
            "Type": None,
        },
        "Debug": {
            "Description": "",
            "Required": False,
            "Value": "False",
            "SuggestedValues": [],
            "Strict": False,
            "Type": "bool",
        },
    }
    caller_params = {"Debug": True}
    _, err = validate_options(instance_options, caller_params, MagicMock(), MagicMock())
    assert err is None
    # No default backfilled in, native bool not stringified — on the caller's dict.
    assert caller_params == {"Debug": True}


def test_valuetype_to_tag_round_trips_through_alias_table():
    # _VALUETYPE_TO_TAG is the inference write-back path. It can't be a key-set
    # equality check: `string` is omitted (inferred strings stay untyped) and
    # `file` is omitted (never inferred from a raw scalar). Pin the exact
    # taggable set and that every written tag re-resolves to its own type — this
    # catches a new ValueType that should auto-tag but was left out of the map.
    assert set(_VALUETYPE_TO_TAG) == {
        ValueType.boolean,
        ValueType.integer,
        ValueType.float,
    }
    for vtype, tag in _VALUETYPE_TO_TAG.items():
        assert _TYPE_STR_TO_VALUETYPE[tag] == vtype


def test_to_value_type_unknown_type_falls_through_to_inference():
    # A typo'd `type:` tag is not an error: to_value_type falls through to
    # inference on the Python type of value (documented behavior) instead of
    # raising, so it renders as its inferred type.
    assert to_value_type("hello", "stirng") == ValueType.string
    assert to_value_type(True, "boool") == ValueType.boolean


def test_safe_cast_unknown_type_returns_none_without_swallowing_real_errors():
    # `_parse_type` returns None for a typo'd `type:` tag like 'stirng'.
    # safe_cast now short-circuits on None so the caller can distinguish
    # "server-config bug" from "bad client value" without the catch widening
    # masking the TypeError that NoneType(value) would otherwise raise.
    assert safe_cast("anything", None) is None


def test_empire_module_option_rejects_unknown_type_tag():
    # Typos in `type:` previously silently degraded to STRING and produced
    # a misleading "Expected None but got <class 'str'>" error at task
    # dispatch time. The field validator now rejects unknown tags at
    # model-load (mirrors `check_credential_parser`).
    with pytest.raises(ValueError, match="unknown option type"):
        EmpireModuleOption(name="Debug", value="True", type="stirng")


def test_empire_module_option_accepts_known_type_tags():
    # All canonical aliases in `_TYPE_STR_TO_PY` must construct cleanly.
    # Verify the validator's "known set" stays aligned with the underlying
    # dispatch table.
    for tag in ("str", "string", "int", "integer", "bool", "boolean", "float", "file"):
        # Capitalized form also accepted (validator lowercases for the check).
        opt = EmpireModuleOption(name="Debug", value="x", type=tag.upper())
        assert opt.type == tag.upper()


class TestConfineToDownloads:
    """The shared guard behind ``ExtFile``, ``File`` and ``Shellcode``."""

    @pytest.fixture
    def downloads(self, tmp_path, monkeypatch):
        root = tmp_path / "downloads"
        root.mkdir()
        monkeypatch.setattr(config_manager.empire_config.directories, "downloads", root)
        return root

    def test_contained_path_is_returned_resolved(self, downloads):
        # Resolved, not echoed back: containment was decided about the resolved
        # form, so a caller that reads the raw value could read a different file
        # than the one that was checked.
        assert confine_to_downloads(
            str(downloads / "a" / ".." / "b.ps1"), "ExtFile"
        ) == (downloads / "b.ps1")

    @pytest.mark.parametrize(
        "value",
        ["/etc/shadow", "../outside.ps1", "a\x00b"],
        ids=["absolute", "traversal", "nul"],
    )
    def test_escaping_value_is_rejected(self, downloads, value):
        with pytest.raises(ModuleValidationException) as exc:
            confine_to_downloads(value, "ExtFile")
        assert "ExtFile" in str(exc.value)

    def test_the_root_is_read_per_call_not_captured_at_import(
        self, downloads, tmp_path
    ):
        """``run_update`` rebinds the process-global config; the guard must follow.

        ``data_manager.run_update`` does ``config_manager.empire_config =
        EmpireConfig()`` after rewriting the base config. A module that did
        ``from ...config_manager import empire_config`` at import time keeps the
        pre-update object, so after an update that moves ``directories.downloads``
        the guard rejects paths under the *new* root and keeps accepting paths
        under the *old* one -- the precise inversion this pins.

        The rebind is simulated by replacing the whole ``empire_config`` object,
        not by mutating ``directories.downloads`` on it: mutating in place is
        satisfied by an import-time capture too, so it would pass either way.
        """
        moved = tmp_path / "moved-downloads"
        moved.mkdir()
        rebound = SimpleNamespace(directories=SimpleNamespace(downloads=moved))

        stale = downloads / "old.ps1"
        with patch.object(config_manager, "empire_config", rebound):
            assert confine_to_downloads(str(moved / "new.ps1"), "ExtFile") == (
                moved / "new.ps1"
            )
            with pytest.raises(ModuleValidationException):
                confine_to_downloads(str(stale), "ExtFile")
