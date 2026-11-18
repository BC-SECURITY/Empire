import logging
import typing
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session

from empire.server.core.config import config_manager
from empire.server.core.db import models
from empire.server.core.exceptions import ModuleValidationException
from empire.server.core.module_models import EmpireModuleOption
from empire.server.core.option_types import py_type_for_tag
from empire.server.utils.file_util import is_path_within

log = logging.getLogger(__name__)

LISTENER_OPTION_NAMES = {"listener", "listenername", "listener_name"}


def confine_to_downloads(value: str, option_name: str) -> Path:
    """Return ``value`` as a Path, rejecting anything outside the downloads root.

    Module options that name a *server-side* file are operator-supplied and end
    up in a read sink whose bytes come back in the task's ``input``, so an
    unconfined one is an arbitrary file read for any enabled operator. The
    downloads directory is the boundary because it is the one place operators
    can write through the API: upload the payload, then pass back the
    ``location`` the Download DTO hands out.

    Read through ``config_manager`` rather than a module-level
    ``from ... import empire_config``: ``run_update`` rebinds that global
    (``data_manager.py``), and a captured reference would leave the guard
    comparing against the pre-update downloads root.

    Returns the *resolved* path, for the same reason ``resolve_under_root``
    does: containment was decided about the resolved form, so handing the
    caller the raw value back would let the path that was checked and the path
    that is read diverge.
    """
    downloads = config_manager.empire_config.directories.downloads
    if not is_path_within(Path(value), downloads):
        log.warning(
            "Blocked %s outside the downloads directory: %r", option_name, value
        )
        raise ModuleValidationException(f"{option_name} must be inside {downloads}")
    return Path(value).resolve()


def get_listener_defaults(db: Session) -> tuple[str | None, list[str] | None]:
    """Return (first_active_listener_name, all_active_listener_names) ordered by id.

    Returns (None, None) on DB error so callers can fall back to template defaults.
    Returns (None, []) when the DB is healthy but no listeners are active.
    """
    try:
        active = (
            db.scalars(
                select(models.Listener)
                .where(models.Listener.enabled.is_(True))
                .order_by(models.Listener.id)
            )
        ).all()
        names = [listener.name for listener in active]
        return (names[0] if names else None), names
    except Exception:
        log.error(
            "Failed to query active listeners for default pre-fill", exc_info=True
        )
        return None, None


def safe_cast(option: typing.Any, expected_option_type: type) -> typing.Any | None:
    """Coerce `option` into `expected_option_type`, returning None on failure.

    `bool` is special-cased: a native bool passes through, any other value is
    truthy-string tested. `expected_option_type is None` (an unknown YAML
    `type:` tag) short-circuits to None so callers can distinguish it from
    "valid type, bad value" — only reachable for non-module callers, since
    `EmpireModuleOption` rejects unknown tags at load time.
    """
    if expected_option_type is None:
        return None
    if expected_option_type is bool:
        if isinstance(option, bool):
            return option
        return str(option).lower() in ("true", "1")
    try:
        return expected_option_type(option)
    except (ValueError, TypeError) as e:  # TypeError tolerates int(None) etc.
        log.debug("safe_cast: %s(%r) failed: %s", expected_option_type, option, e)
        return None


def coerce_legacy_value(value: typing.Any) -> typing.Any:
    """Stringify a native ``bool``/``int``/``float`` option value to its legacy
    string form for generate-path consumers that build command text — switch
    detection (`value.lower() == "true"`), `str.replace` substitution, and `+`
    concatenation all assume strings.

    Strings, ``None``, and non-primitive values (e.g. file-download objects)
    pass through unchanged. This is the per-value form of the removed
    ``normalize_legacy_params`` dict-level shim: apply it only at the point a
    typed value must become text, so native reads elsewhere (`if params["X"]:`)
    keep their real types.
    """
    return str(value) if isinstance(value, bool | int | float) else value


def convert_module_options(options: list[EmpireModuleOption]) -> dict:
    """
    Since modules options are typed classes vs listeners/stagers/etc which are dicts, this function
    converts the options to dicts so they can use the same validation logic in validate_options.
    """
    converted_options = {}

    for option in options:
        if option.internal:
            continue

        converted_options[option.name] = {
            "Description": option.description,
            "Required": option.required,
            "Value": option.value,
            "SuggestedValues": option.suggested_values,
            "Strict": option.strict,
            "Type": option.type,
            "NameInCode": option.name_in_code,
            "Internal": option.internal,
            "DependsOn": option.depends_on,
        }

    return converted_options


def validate_options(  # noqa: PLR0912
    instance_options: dict, params: dict, db: Session, download_service
) -> tuple[dict | None, str | None]:
    """
    Compares the options passed in (params) to the options defined in the
    class (instance). If any options are invalid, returns a Tuple of
    (None, error_message). If all options are valid, returns a Tuple of
    (options, None).

    Will also attempt to cast the options to the correct type using safe_cast.
    Options of type "file" are not validated.
    If an option has "Editable" set to False, it will be skipped (Only applies to
    plugins for now).
    """
    options = {}
    # Copy so the default-injection below (`params[instance_key] = ...`) never
    # mutates the caller's dict.
    params = params.copy()

    for instance_key, option_meta in instance_options.items():
        if option_meta.get("Internal", False):
            continue

        if not evaluate_dependencies(option_meta, params):
            # Dependencies not met: include with default value but skip validation.
            # Cast the default to the option's native type so a gated bool/int
            # option matches the validated branch — otherwise a bool option's
            # stringly "False" default reaches generate() as a truthy string and
            # a native `if params["X"]:` check silently inverts.
            default_value = option_meta.get("Value", "")
            casted, _ = _safe_cast_option(instance_key, default_value, option_meta)
            if casted is not None:
                default_value = casted
            if option_meta.get("NameInCode"):
                options[option_meta["NameInCode"]] = default_value
            else:
                options[instance_key] = default_value
            continue

        if option_meta.get("Editable", True) is False:
            continue

        if instance_key not in params and option_meta["Value"] not in ["", None]:
            params[instance_key] = option_meta["Value"]

        if is_option_required(option_meta, params) and (
            instance_key not in params
            or params[instance_key] == ""
            or params[instance_key] is None
        ):
            return None, f"required option missing: {instance_key}"

        if _lower_default(option_meta.get("Type")) == "file":
            if params.get(instance_key):
                db_download = download_service.get_by_id(db, params[instance_key])
                if not db_download:
                    return (
                        None,
                        f"File not found for '{instance_key}' id {params[instance_key]}",
                    )

                options[instance_key] = db_download
            else:
                options[instance_key] = ""
            continue

        if (
            option_meta.get("Strict")
            and option_meta.get("SuggestedValues") is not None
            and params.get(instance_key, "") not in option_meta.get("SuggestedValues")
        ):
            return (
                None,
                f"{instance_key} must be set to one of the suggested values.",
            )

        casted, err = _safe_cast_option(
            instance_key, params.get(instance_key, ""), option_meta
        )
        if err:
            return None, err

        if option_meta.get("NameInCode"):
            options[option_meta["NameInCode"]] = casted
        else:
            options[instance_key] = casted

    return options, None


def is_option_required(option_meta: dict, params: dict) -> bool:
    """
    Check if an option should be validated based on its `depends_on` configuration.
    This will return True if the option's dependencies are met.
    """
    dependencies = option_meta.get("DependsOn", [])

    if not dependencies:
        # If there are no dependencies, treat the option as required based on the 'Required' field
        return option_meta.get("Required", False)

    # If there are dependencies, check if all are satisfied
    for dependency in dependencies:
        dependent_option = dependency["name"]
        required_values = dependency.get("values")

        # A dependency with no "values" list imposes no value constraint, so it
        # is treated as satisfied; gate on a specific value only when one is
        # listed. (Presence of the dependent option is enforced separately by
        # validate_options, which calls evaluate_dependencies first.)
        if required_values is not None and (
            params.get(dependent_option) not in required_values
        ):
            return (
                False  # If any dependency is not satisfied, the option is not required
            )

    # If all dependencies are satisfied, return True
    return True


def evaluate_dependencies(option, params):
    """
    Evaluate the depends_on conditions for a given option.
    :param option: The option being validated.
    :param params: The current parameters provided by the user.
    :return: Boolean indicating if the dependencies are met.
    """
    if "DependsOn" not in option or not option["DependsOn"]:
        return True

    for dependency in option["DependsOn"]:
        dependent_option = dependency["name"]
        if dependent_option not in params:
            return False
        if (
            "values" in dependency
            and params[dependent_option] not in dependency["values"]
        ):
            return False

    return True


def set_options(instance, options: dict):
    """
    Sets the options for the listener/stager instance.
    """
    for option_name, option_value in options.items():
        instance.options[option_name]["Value"] = option_value


def _lower_default(x):
    return "" if x is None else x.lower()


def get_file_options(db, download_service, options, params):
    files = {}

    for option_name, _option_meta in filter(
        lambda x: _lower_default(x[1].get("Type")) == "file", options.items()
    ):
        db_download = download_service.get_by_id(db, params[option_name])
        if not db_download:
            return (
                None,
                f"File not found for '{option_name}' id {params[option_name]}",
            )

        files[option_name] = db_download

    return files, None


def _parse_type(type_str: str = "", value: str = ""):
    if not type_str:
        return type(value)
    return py_type_for_tag(type_str)


def _safe_cast_option(
    param_name, param_value, option_meta
) -> tuple[typing.Any, str | None]:
    option_type = type(param_value)
    if option_meta.get("Type") is not None and isinstance(
        option_meta.get("Type"), type
    ):
        expected_option_type = option_meta.get("Type")
    else:
        expected_option_type = _parse_type(
            option_meta.get("Type"), option_meta.get("Value")
        )
    casted = safe_cast(param_value, expected_option_type)
    if casted is None:
        return (
            None,
            f"incorrect type for option {param_name}. Expected {expected_option_type} but got {option_type}",
        )
    return casted, None
