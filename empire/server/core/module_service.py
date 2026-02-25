import base64
import fnmatch
import importlib.util
import json
import logging
import shutil
import typing
import warnings
from pathlib import Path

import yaml

try:
    from yaml import CSafeDumper as Dumper
    from yaml import CSafeLoader as Loader
except ImportError:
    from yaml import Dumper, Loader

from packaging.version import parse
from pydantic import BaseModel
from sqlalchemy.orm import Session

from empire.server.api.v2.module.module_dto import (
    ModuleBulkUpdateRequest,
    ModuleUpdateRequest,
)
from empire.server.common import helpers
from empire.server.core.config.config_manager import DATA_DIR
from empire.server.core.db import models
from empire.server.core.db.base import SessionLocal
from empire.server.core.exceptions import (
    ModuleExecutionException,
    ModuleValidationException,
)
from empire.server.core.module_models import (
    EmpireModule,
    EmpireModuleOption,
    LanguageEnum,
)
from empire.server.utils import data_util
from empire.server.utils.bof_packer import process_arguments
from empire.server.utils.option_util import convert_module_options, validate_options
from empire.server.utils.string_util import slugify

if typing.TYPE_CHECKING:
    from empire.server.common.empire import MainMenu
    from empire.server.core.download_service import DownloadService
    from empire.server.core.obfuscation_service import ObfuscationService

log = logging.getLogger(__name__)


class ModuleExecutionRequest(BaseModel):
    command: str
    data: str
    files: list[Path] = []


class ModuleService:
    def __init__(self, main_menu: "MainMenu"):
        self.main_menu = main_menu
        self.obfuscation_service: ObfuscationService = main_menu.obfuscationv2
        self.download_service: DownloadService = main_menu.downloadsv2
        self.dotnet_compiler = main_menu.dotnet_compiler

        self.module_source_path = main_menu.install_path / "data/module_source"
        self._obfuscated_module_source_path = DATA_DIR / "obfuscated_module_source"

        self.modules = {}

        with SessionLocal.begin() as db:
            self.load_modules(db)

    def get_all(self, hide_disabled: bool = False):
        if hide_disabled:
            return {k: v for k, v in self.modules.items() if v.enabled}
        return self.modules

    def get_by_id(self, uid: str):
        return self.modules.get(uid)

    def update_module(
        self, db: Session, module: EmpireModule, module_req: ModuleUpdateRequest
    ):
        db_module: models.Module = (
            db.query(models.Module).filter(models.Module.id == module.id).first()
        )
        db_module.enabled = module_req.enabled

        self.modules.get(module.id).enabled = module_req.enabled

    def update_modules(self, db: Session, module_req: ModuleBulkUpdateRequest):
        db_modules: list[models.Module] = (
            db.query(models.Module)
            .filter(models.Module.id.in_(module_req.modules))
            .all()
        )

        for db_module in db_modules:
            db_module.enabled = module_req.enabled

        for db_module in db_modules:
            self.modules.get(db_module.id).enabled = module_req.enabled

    def execute_module(  # noqa: PLR0913 PLR0912 PLR0915
        self,
        db: Session,
        agent: models.Agent,
        module_id: str,
        params: dict,
        ignore_language_version_check: bool = False,
        ignore_admin_check: bool = False,
        modified_input: str | None = None,
    ) -> tuple[ModuleExecutionRequest | None, str | None]:
        """
        Execute the module. Note this doesn't actually add the task to the queue,
        it only generates the module data needed for a task to be created.
        :param module_id: str
        :param params: the execution parameters
        :param user_id: the user executing the module
        :return: tuple with the response and an error message (if applicable)
        """
        module = self.get_by_id(module_id)

        if not module:
            return None, f"Module not found for id {module_id}"
        if not module.enabled:
            return None, "Cannot execute disabled module"

        if modified_input:
            module = self._create_modified_module(module, modified_input)

        cleaned_options, err = self._validate_module_params(
            db, module, agent, params, ignore_language_version_check, ignore_admin_check
        )

        if err:
            raise ModuleValidationException(err)

        module_data = self._generate_script(
            db,
            module,
            cleaned_options,
            agent.language,
        )
        if isinstance(module_data, tuple):
            warnings.warn(
                "Returning a tuple on errors from module generation is deprecated. Raise exceptions instead."
                "https://bc-security.gitbook.io/empire-wiki/module-development/powershell-modules#custom-generate",
                DeprecationWarning,
                stacklevel=5,
            )
            (module_data, err) = module_data
        else:
            # Not all modules return a tuple. If they just return a single value,
            # we don't want to throw an unpacking error.
            err = None

        # Should standardize on the return type.
        if not module_data or module_data == "":
            # This should probably be a ModuleExecutionException, but
            # for backwards compatability with 5.x, it needs to raise a 400
            raise ModuleValidationException(err or "module produced an empty script")

        if type(module_data) is not ModuleExecutionRequest:
            module_data = ModuleExecutionRequest(command="", data=module_data)

        if not module_data.data.isascii():
            # This previously returned 'None, 'module source contains non-ascii characters'
            # Was changed in 4.3 to print a warning.
            log.warning(f"Module source for {module_id} contains non-ascii characters")

        if module.language == LanguageEnum.powershell:
            module_data.data = helpers.strip_powershell_comments(module_data.data)

        if module.language == LanguageEnum.python:
            module_data.data = helpers.strip_python_comments(module_data.data)

        extension = module.output_extension.rjust(5) if module.output_extension else ""

        effective_background = cleaned_options.pop("Background", module.background)

        if agent.language in ("ironpython", "python"):
            if module.language == "python":
                if effective_background:
                    module_data.command = "TASK_PYTHON_CMD_JOB"
                else:
                    command, data = self._handle_save_file_command(
                        "TASK_PYTHON", module.name, extension, module_data.data
                    )
                    module_data.command = command
                    module_data.data = data
            elif module.language == "powershell":
                if effective_background:
                    module_data.command = "TASK_POWERSHELL_CMD_JOB"
                else:
                    command, data = self._handle_save_file_command(
                        "TASK_POWERSHELL", module.name, extension, module_data.data
                    )
                    module_data.command = command
                    module_data.data = data
            elif module.language in ("csharp", "bof"):
                if effective_background:
                    module_data.command = "TASK_CSHARP_CMD_JOB"
                else:
                    module_data.command = "TASK_CSHARP_CMD_WAIT"
            else:
                log.error(
                    f"Unsupported module language {module.language} for agent {agent.language}"
                )

        elif agent.language == "csharp":
            if module.language in ("csharp", "bof"):
                if effective_background:
                    module_data.command = "TASK_CSHARP_CMD_JOB"
                else:
                    module_data.command = "TASK_CSHARP_CMD_WAIT"
            elif module.language == "powershell":
                module_data.command = "TASK_POWERSHELL_CMD_JOB"
            else:
                log.error(
                    f"Unsupported module language {module.language} for agent {agent.language}"
                )

        elif agent.language == "powershell":
            if module.language == "powershell":
                if effective_background:
                    module_data.command = "TASK_POWERSHELL_CMD_JOB"
                else:
                    command, data = self._handle_save_file_command(
                        "TASK_POWERSHELL", module.name, extension, module_data.data
                    )
                    module_data.command = command
                    module_data.data = data
            elif module.language in ("csharp", "bof"):
                if effective_background:
                    module_data.command = "TASK_CSHARP_CMD_JOB"
                else:
                    module_data.command = "TASK_CSHARP_CMD_WAIT"
            else:
                log.error(
                    f"Unsupported module language {module.language} for agent {agent.language}"
                )
        elif agent.language == "go":
            if module.language == "powershell":
                if effective_background:
                    module_data.command = "TASK_POWERSHELL_CMD_JOB"
                else:
                    command, data = self._handle_save_file_command(
                        "TASK_POWERSHELL", module.name, extension, module_data.data
                    )
                    module_data.command = command
                    module_data.data = data
            elif module.language == "csharp":
                if effective_background:
                    module_data.command = "TASK_CSHARP_CMD_JOB"
                else:
                    module_data.command = "TASK_CSHARP_CMD_WAIT"
            elif module.language == "bof":
                module_data.command = "TASK_BOF_CMD_WAIT"
            elif module.language == "pe":
                module_data.command = "TASK_PE_CMD_WAIT"
            else:
                log.error(
                    f"Unsupported module language {module.language} for agent {agent.language}"
                )
        else:
            log.error(f"Unsupported agent language {agent.language}")
            return None, f"Unsupported agent language: {agent.language}"

        return module_data, None

    @staticmethod
    def _handle_save_file_command(cmd_type, module_name, extension, module_data):
        if extension:
            save_file_prefix = module_name.split("/")[-1][:15]
            module_data = save_file_prefix.rjust(15) + extension + module_data
            return f"{cmd_type}_CMD_WAIT_SAVE", module_data
        return f"{cmd_type}_CMD_WAIT", module_data

    def _validate_module_params(  # noqa: PLR0913
        self,
        db: Session,
        module: EmpireModule,
        agent: models.Agent,
        params: dict[str, str],
        ignore_language_version_check: bool = False,
        ignore_admin_check: bool = False,
    ) -> tuple[dict[str, str] | None, str | None]:
        """
        Given a module and execution params, validate the input and return back a clean Dict for execution.
        :param module: EmpireModule
        :param params: the execution parameters set by the user
        :return: tuple with options and the error message (if applicable)
        """

        # Define valid agent/module language compatibility
        valid_language_mapping = {
            "go": {"bof", "powershell", "csharp"},
            "ironpython": {"bof", "powershell", "csharp", "python"},
            "powershell": {"bof", "powershell", "csharp"},
            "csharp": {"bof", "powershell", "csharp"},
            "python": {"python"},
        }

        # Ensure the agent's language is supported
        if agent.language not in valid_language_mapping:
            raise ModuleValidationException(
                f"Unsupported agent language '{agent.language}'."
            )

        # Ensure the module language is compatible with the agent's language
        if module.language not in valid_language_mapping.get(agent.language, {}):
            raise ModuleValidationException(
                f"agent language '{agent.language}' cannot run module language '{module.language}'."
            )

        converted_options = convert_module_options(module.options)

        options, err = validate_options(
            converted_options, params, db, self.download_service
        )

        if err:
            return None, err

        if not ignore_language_version_check and module.language == agent.language:
            module_version = parse(module.min_language_version or "0")
            agent_version = parse(agent.language_version or "0")

            # check if the agent/module PowerShell versions are compatible
            if module_version > agent_version:
                raise ModuleValidationException(
                    f"module requires language version {module.min_language_version} but agent running language version {agent.language_version}",
                )

        if module.needs_admin and not ignore_admin_check and not agent.high_integrity:
            raise ModuleValidationException(
                "module needs to run in an elevated context"
            )

        return options, None

    def _generate_script(  # noqa: PLR0911
        self,
        db: Session,
        module: EmpireModule,
        params: dict,
        agent_language: str,
        obfuscation_config: models.ObfuscationConfig = None,
    ) -> tuple[ModuleExecutionRequest | None, str | None]:
        """
        Generate the script to execute
        :param module: the execution parameters (already validated)
        :param params: the execution parameters
        :param obfuscation_config: the obfuscation config. If not provided, will look up from the db.
        :return: tuple containing the generated script and an error if it exists
        """
        if not obfuscation_config:
            obfuscation_config = self.obfuscation_service.get_obfuscation_config(
                db, module.language
            )
        if not obfuscation_config:
            obfuscation_enabled = False
            obfuscation_command = None
        else:
            obfuscation_enabled = obfuscation_config.enabled
            obfuscation_command = obfuscation_config.command

        if module.advanced.custom_generate:
            # In a future release we could refactor the modules to accept an obuscation_config,
            #  but there's little benefit to doing so at this point. So I'm saving myself the pain.
            try:
                return module.advanced.generate_class.generate(
                    self.main_menu,
                    module,
                    params,
                    obfuscation_enabled,
                    obfuscation_command,
                )
            except (ModuleValidationException, ModuleExecutionException) as e:
                raise e
            except Exception as e:
                log.error(f"Error generating script: {e}", exc_info=True)
                return None, "Error generating script."
        elif module.language == LanguageEnum.powershell:
            resp = self._generate_script_powershell(module, params, obfuscation_config)
            return ModuleExecutionRequest(command="", data=resp), None
        # We don't have obfuscation for other languages yet, but when we do,
        # we can pass it in here.
        elif module.language == LanguageEnum.python:
            resp = self._generate_script_python(module, params, obfuscation_config)
            return ModuleExecutionRequest(command="", data=resp), None
        elif module.language == LanguageEnum.csharp:
            return self.generate_script_csharp(module, params, obfuscation_config), None
        elif module.language == LanguageEnum.bof:
            if agent_language == "go":
                resp = self.generate_go_bof(module, params)
                return ModuleExecutionRequest(command="", data=resp), None
            if not obfuscation_config:
                obfuscation_config = self.obfuscation_service.get_obfuscation_config(
                    db, LanguageEnum.csharp
                )
            return self.generate_script_bof(module, params, obfuscation_enabled), None

        return None, "Unsupported language"

    def generate_script_bof(
        self,
        module: EmpireModule,
        params: dict,
        obfuscate: bool = False,
    ) -> ModuleExecutionRequest:
        bof_module = self.modules["csharp_code_execution_runcoff"]

        if params["Architecture"] == "x86":
            script_path = self.module_source_path / module.bof.x86
        else:
            script_path = self.module_source_path / module.bof.x64

        bof_data = script_path.read_bytes()
        b64_bof_data = base64.b64encode(bof_data).decode("utf-8")

        script_file = self.dotnet_compiler.compile_task(
            bof_module.compiler_yaml,
            bof_module.name,
            dot_net_version="net40",
            confuse=obfuscate,
        )

        filtered_params = {
            key: (
                value if value != "" else " "
            )  # Replace empty values with a blank space
            for key, value in params.items()
            if key.lower()
            not in [
                "agent",
                "dotnetversion",
                "architecture",
                "entrypoint",
            ]
        }

        formatted_args = " ".join(
            f'"{value}"' if " " in value else value
            for value in filtered_params.values()
        )

        params_dict = {}
        params_dict["Entrypoint"] = (
            module.bof.entry_point if module.bof.entry_point else "go"
        )
        params_dict["File"] = b64_bof_data
        params_dict["HexData"] = process_arguments(
            module.bof.format_string, formatted_args
        )

        final_base64_json = base64.b64encode(
            json.dumps(params_dict).encode("utf-8")
        ).decode("utf-8")

        return ModuleExecutionRequest(
            command="",
            data=f"{script_file}|,{final_base64_json}",
            files=[script_file],
        )

    def generate_go_bof(
        self,
        module: EmpireModule,
        params: dict,
        skip_params=False,
    ) -> str:
        if params["Architecture"] == "x86":
            script_path = self.module_source_path / module.bof.x86
        else:
            script_path = self.module_source_path / module.bof.x64

        bof_data = script_path.read_bytes()
        b64_bof_data = base64.b64encode(bof_data).decode("utf-8")

        filtered_params = {
            key: (
                value if value != "" else " "
            )  # Replace empty values with a blank space
            for key, value in params.items()
            if key.lower()
            not in [
                "agent",
                "dotnetversion",
                "architecture",
                "entrypoint",
            ]
        }

        formatted_args = " ".join(
            f'"{value}"' if " " in value else value
            for value in filtered_params.values()
        )

        if not skip_params:
            params_dict = {}
            params_dict["File"] = b64_bof_data
            params_dict["HexData"] = process_arguments(
                module.bof.format_string, formatted_args
            )
        else:
            params_dict = params

        final_base64_json = base64.b64encode(
            json.dumps(params_dict).encode("utf-8")
        ).decode("utf-8")

        return f"{final_base64_json}"

    def generate_go_pe(
        self,
        module: EmpireModule,
        params: dict[str, str],
        skip_params=False,
    ) -> str:
        """
        Generates a base64-encoded JSON structure for a PE file and its arguments.

        :param module: EmpireModule object containing PE file paths and format info.
        :param params: Dictionary of parameters, including architecture and arguments.
        :param skip_params: If True, bypasses argument formatting and uses params as is.
        :return: Base64-encoded JSON string.
        """
        # Determine the file path based on architecture
        if params["Architecture"] == "x86":
            script_path = self.module_source_path / module.pe.x86
        else:
            script_path = self.module_source_path / module.pe.x64

        # Read the PE file and encode it in base64
        pe_data = script_path.read_bytes()
        b64_pe_data = base64.b64encode(pe_data).decode("utf-8")

        # Filter and prepare arguments
        filtered_params = {
            key: (
                value if value != "" else " "
            )  # Replace empty values with a blank space
            for key, value in params.items()
            if key.lower()
            not in [
                "agent",
                "dotnetversion",
                "architecture",
                "entrypoint",
            ]
        }

        # Create a list of arguments
        formatted_args = [
            f'"{value}"' if " " in value else value
            for value in filtered_params.values()
        ]

        if not skip_params:
            params_dict = {"File": b64_pe_data, "Args": formatted_args}
        else:
            params_dict = params

        return base64.b64encode(json.dumps(params_dict).encode("utf-8")).decode("utf-8")

    def _generate_script_python(
        self,
        module: EmpireModule,
        params: dict,
        obfuscation_config: models.ObfuscationConfig,
    ) -> str:
        obfuscate = (
            obfuscation_config.enabled if obfuscation_config is not None else False
        )

        if module.script_path:
            script_path = self.module_source_path / module.script_path
            script = script_path.read_text()
        else:
            script = module.script

        for key, value in params.items():
            if key.lower() != "agent":
                script = script.replace("{{ " + key + " }}", value).replace(
                    "{{" + key + "}}", value
                )

        if obfuscate:
            script = self.obfuscation_service.python_obfuscate(script)

        return script

    def _generate_script_powershell(
        self,
        module: EmpireModule,
        params: dict,
        obfuscation_config: models.ObfuscationConfig,
    ) -> str:
        obfuscate = (
            obfuscation_config.enabled if obfuscation_config is not None else False
        )
        obfuscate_command = (
            obfuscation_config.command if obfuscation_config is not None else ""
        )

        if module.script_path:
            script, err = self.get_module_source(
                module_name=module.script_path,
                obfuscate=obfuscate,
                obfuscate_command=obfuscate_command,
            )

            if err:
                raise ModuleValidationException(err)
        elif obfuscate:
            script = self.obfuscation_service.obfuscate(
                module.script, obfuscate_command
            )
        else:
            script = module.script

        script_end = f" {module.script_end} "
        option_strings = []

        # This is where the code goes for all the modules that do not have a custom generate function.
        for key, value in params.items():
            if key.lower() not in ["agent", "outputfunction"] and value and value != "":
                if value.lower() == "true":
                    # if we're just adding a switch
                    # wannabe mustache templating.
                    # If we want to get more advanced, we can import a library for it.
                    this_option = module.advanced.option_format_string_boolean.replace(
                        "{{ KEY }}", str(key)
                    ).replace("{{KEY}}", str(key))
                    option_strings.append(f"{this_option}")
                elif value.lower() == "false":
                    # Have to add a continue for false statements, else it adds -option 'False'
                    continue
                else:
                    this_option = (
                        module.advanced.option_format_string.replace(
                            "{{ KEY }}", str(key)
                        )
                        .replace("{{KEY}}", str(key))
                        .replace("{{ VALUE }}", str(value))
                        .replace("{{VALUE}}", str(value))
                    )
                    option_strings.append(f"{this_option}")

        script_end = (
            script_end.replace("{{ PARAMS }}", " ".join(option_strings))
            .replace("{{PARAMS}}", " ".join(option_strings))
            .replace(
                "{{ OUTPUT_FUNCTION }}", params.get("OutputFunction", "Out-String")
            )
            .replace("{{OUTPUT_FUNCTION}}", params.get("OutputFunction", "Out-String"))
        )

        # obfuscate the invoke command and append to script
        return self.finalize_module(
            script=script,
            script_end=script_end,
            obfuscate=obfuscate,
            obfuscation_command=obfuscate_command,
        )

    def generate_script_csharp(
        self,
        module: EmpireModule,
        params: dict,
        obfuscation_config: models.ObfuscationConfig,
    ) -> ModuleExecutionRequest:
        try:
            obfuscate = (
                obfuscation_config.enabled if obfuscation_config is not None else False
            )
            script_file = self.dotnet_compiler.compile_task(
                module.compiler_yaml,
                module.name,
                dot_net_version=params["DotNetVersion"].lower(),
                confuse=obfuscate,
            )
            filtered_params = {}
            for key, value in params.items():
                if (
                    key.lower() not in ["agent", "dotnetversion"]
                    and value
                    and value != ""
                ):
                    if key.lower() == "file":
                        base64_assembly = value.get_base64_file()
                        filtered_params[key] = base64_assembly
                    else:
                        filtered_params[key] = value

            param_json = json.dumps(filtered_params)
            base64_json = base64.b64encode(param_json.encode("utf-8")).decode("utf-8")
            return ModuleExecutionRequest(
                command="",
                data=f"{script_file}|,{base64_json}",
                files=[script_file],
            )
        except (ModuleValidationException, ModuleExecutionException) as e:
            raise e
        except Exception as e:
            log.error(f"dotnet compile error: {e}")
            raise ModuleExecutionException("dotnet compile error") from e

    def _create_modified_module(self, module: EmpireModule, modified_input: str):
        """
        Return a copy of the original module with the input modified.
        """
        modified_module = module.model_copy(deep=True)
        modified_module.script = modified_input
        modified_module.script_path = None

        if modified_module.language == LanguageEnum.csharp:
            compiler_dict = yaml.load(modified_module.compiler_yaml, Loader=Loader)
            compiler_dict[0]["Code"] = modified_input
            modified_module.compiler_yaml = yaml.dump(compiler_dict, Dumper=Dumper)

        return modified_module

    def load_modules(self, db: Session):
        root_path = Path(self.main_menu.installPath) / "modules"
        log.info(f"v2: Loading modules from: {root_path}")

        for file_path in root_path.rglob("*.y*ml"):
            filename = file_path.name
            if fnmatch.fnmatch(filename, "*template.yaml"):
                continue

            # instantiate the module and save it to the internal cache
            try:
                yaml2 = yaml.load(file_path.read_text(), Loader=Loader)
                yaml_module = {k: v for k, v in yaml2.items() if v is not None}
                self._load_module(db, yaml_module, root_path, file_path)
            except Exception as e:
                log.error(f"Error loading module {filename}: {e}")

    def _load_module(  # noqa: PLR0912
        self, db: Session, yaml_module, root_path: Path, file_path: Path
    ):
        module_name = file_path.relative_to(root_path).with_suffix("").as_posix()
        yaml_module["techniques"].extend(
            self._get_interpreter_technique(yaml_module["language"])
        )

        if yaml_module["language"] == "csharp":
            yaml_module["id"] = slugify(module_name)

            # TODO: Remove this from EmpireCompiler so we dont need to build all the extra unused fields
            dict_yaml = yaml_module.get("csharp", {}).copy()
            dict_yaml.update(
                {
                    "Name": yaml_module.get("name", ""),
                    "Language": yaml_module.get("language", ""),
                    "TokenTask": False,
                }
            )

            dict_yaml["ReferenceSourceLibraries"] = [
                {
                    "Name": ref_lib.get("Name", ""),
                    "Description": ref_lib.get("Description", ""),
                    "Location": ref_lib.get("Location", ""),
                    "Language": ref_lib.get("Language", "CSharp"),
                    "CompatibleDotNetVersions": ref_lib.get(
                        "CompatibleDotNetVersions", []
                    ),
                    "ReferenceAssemblies": ref_lib.get("ReferenceAssemblies", []),
                    "EmbeddedResources": ref_lib.get("EmbeddedResources", []),
                }
                for ref_lib in dict_yaml.get("ReferenceSourceLibraries", [])
            ]

            compiler_yaml = yaml.dump(
                [dict_yaml],
                sort_keys=False,
                default_flow_style=False,
                allow_unicode=True,
                Dumper=Dumper,
            )

            my_model = EmpireModule(**yaml_module)
            my_model.compiler_yaml = compiler_yaml

            my_model.options.append(
                EmpireModuleOption(
                    name="DotNetVersion",
                    value=my_model.csharp.CompatibleDotNetVersions[0],
                    description=".NET version to compile against",
                    required=True,
                    suggested_values=my_model.csharp.CompatibleDotNetVersions,
                    strict=True,
                )
            )
        else:
            yaml_module["id"] = slugify(module_name)
            my_model = EmpireModule(**yaml_module)

        if my_model.advanced.custom_generate:
            if not file_path.with_suffix(".py").exists():
                raise Exception("No File to use for custom generate.")
            spec = importlib.util.spec_from_file_location(
                module_name + ".py", file_path.with_suffix(".py")
            )
            imp_mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(imp_mod)
            my_model.advanced.generate_class = imp_mod.Module()
        elif my_model.script_path:
            script_path = self.module_source_path / my_model.script_path
            if not script_path.exists():
                raise Exception(
                    f"File provided in script_path does not exist: {module_name}"
                )
        elif my_model.script:
            pass
        elif my_model.language == LanguageEnum.bof:
            if not (self.module_source_path / my_model.bof.x86).exists():
                raise Exception(f"x86 bof file provided does not exist: {module_name}")
            if not (self.module_source_path / my_model.bof.x64).exists():
                raise Exception(f"x64 bof file provided does not exist: {module_name}")
        elif my_model.language == LanguageEnum.csharp:
            pass
        else:
            raise Exception(
                "Must provide a valid script, script_path, or custom generate function"
            )

        mod = db.query(models.Module).filter(models.Module.id == my_model.id).first()

        if not mod:
            mod = models.Module(
                id=my_model.id,
                name=module_name,
                enabled=True,
                tactic=my_model.tactics,
                technique=my_model.techniques,
                software=my_model.software,
            )
            db.add(mod)

        self.modules[slugify(module_name)] = my_model
        self.modules[slugify(module_name)].enabled = mod.enabled

    def _get_interpreter_technique(self, language):
        if language == LanguageEnum.powershell:
            return ["T1059.001"]
        if language == LanguageEnum.csharp:
            return ["T1620"]
        if language == LanguageEnum.python:
            return ["T1059.006"]
        if language == LanguageEnum.ironpython:
            return ["T1059.006", "T1620"]
        if language == LanguageEnum.bof:
            return ["T1620"]
        return []

    def get_module_script(self, module_id: str):
        mod: EmpireModule = self.modules.get(module_id)

        if not mod:
            return None

        if mod.script_path:
            script_path = self.module_source_path / mod.script_path
            script = script_path.read_text()
        else:
            script = mod.script

        return script

    def get_module_source(
        self, module_name: str, obfuscate: bool = False, obfuscate_command: str = ""
    ) -> tuple[str | None, str | None]:
        """
        Get the obfuscated/unobfuscated module source code.
        """
        try:
            if obfuscate:
                module_path = self._obfuscated_module_source_path / module_name
                # If pre-obfuscated module exists then return code
                if module_path.exists():
                    return module_path.read_text(), None

                # If pre-obfuscated module does not exist then generate obfuscated code and return it
                module_path = self.module_source_path / module_name
                module_code = module_path.read_text()
                obfuscated_module_code = self.obfuscation_service.obfuscate(
                    module_code, obfuscate_command
                )
                return obfuscated_module_code, None

            # Use regular/unobfuscated code
            module_path = self.module_source_path / module_name
            module_code = module_path.read_text()
            return module_code, None
        except Exception:
            return (
                None,
                f"[!] Could not read module source path at: {self.module_source_path}",
            )

    def preobfuscate_modules(self, language: str, reobfuscate=False):
        """
        Preobfuscate PowerShell module_source files
        """
        if not data_util.is_powershell_installed():
            err = "PowerShell is not installed and is required to use obfuscation, please install it first."
            log.error(err)
            return err

        with SessionLocal.begin() as db:
            db_obf_config = self.obfuscation_service.get_obfuscation_config(
                db, language
            )
            files = self._get_module_source_files()

            for file in files:
                if reobfuscate or not self.is_obfuscated(file):
                    message = f"Obfuscating {file.name}..."
                    log.info(message)
                else:
                    log.warning(
                        f"{file.name} was already obfuscated. Not reobfuscating."
                    )
                self.obfuscate_module(file, db_obf_config.command, reobfuscate)
            return None

    # this is still written in a way that its only used for PowerShell
    # to make it work for other languages, we probably want to just pass in the db_obf_config
    # and delegate to language specific functions
    def obfuscate_module(
        self, module_source: Path, obfuscation_command="", force_reobfuscation=False
    ):
        if self.is_obfuscated(module_source) and not force_reobfuscation:
            return None

        try:
            module_code = module_source.read_text()
        except Exception:
            log.error(f"Could not read module source path at: {module_source}")
            return ""

        # Get the random function name generated at install and patch the stager with the proper function name
        module_code = self.obfuscation_service.obfuscate_keywords(module_code)

        # obfuscate and write to obfuscated source path
        obfuscated_code = self.obfuscation_service.obfuscate(
            module_code, obfuscation_command
        )

        relative_path = module_source.relative_to(self.module_source_path)
        obfuscated_source = self._obfuscated_module_source_path / relative_path

        try:
            obfuscated_source.parent.mkdir(parents=True, exist_ok=True)
            obfuscated_source.write_text(obfuscated_code)
        except Exception:
            log.error(
                f"Could not write obfuscated module source path at: {obfuscated_source}"
            )
            return ""

    def is_obfuscated(self, module_source: Path):
        # Get the file path of the module_source, but only relative to the module_source directory
        # Then append to the obfuscated_module_source directory
        relative_path = module_source.relative_to(self.module_source_path)
        return (self._obfuscated_module_source_path / relative_path).exists()

    def _get_module_source_files(self) -> list[Path]:
        paths = []
        pattern = "*.ps1"
        for root, _dirs, files in self.module_source_path.walk():
            for filename in fnmatch.filter(files, pattern):
                paths.append(root / filename)

        return paths

    def remove_preobfuscated_modules(self, _language: str):
        shutil.rmtree(self._obfuscated_module_source_path, ignore_errors=True)

    def finalize_module(
        self,
        script: str,
        script_end: str,
        obfuscate: bool = False,
        obfuscation_command: str = "",
    ) -> str:
        """
        Combine script and script end with obfuscation if needed.
        """
        if "PowerSploit File: PowerView.ps1" in script:
            module_name = script_end.lstrip().split(" ")[0]
            script = helpers.generate_dynamic_powershell_script(script, module_name)

        script += script_end
        if obfuscate:
            script = self.obfuscation_service.obfuscate(script, obfuscation_command)
        return self.obfuscation_service.obfuscate_keywords(script)

    def delete_all_modules(self, db: Session):
        for module in list(self.modules.values()):
            db_module: models.Module = (
                db.query(models.Module).filter(models.Module.id == module.id).first()
            )
            if db_module:
                db.delete(db_module)
            del self.modules[module.id]
        db.flush()


def auto_get_source(func):
    def wrapper(*args, **kwargs):
        main_menu = args[0]
        module = args[1]
        obfuscate = args[3]
        obfuscation_command = args[4]

        script, err = main_menu.modulesv2.get_module_source(
            module_name=module.script_path,
            obfuscate=obfuscate,
            obfuscate_command=obfuscation_command,
        )

        if err:
            raise ModuleValidationException(err)

        return func(*args, script=script, **kwargs)

    return wrapper


def auto_finalize(func):
    def wrapper(*args, **kwargs):
        script, script_end = func(*args, **kwargs)

        main_menu = args[0]
        obfuscate = args[3]
        obfuscation_command = args[4]

        return main_menu.modulesv2.finalize_module(
            script=script,
            script_end=script_end,
            obfuscate=obfuscate,
            obfuscation_command=obfuscation_command,
        )

    return wrapper
