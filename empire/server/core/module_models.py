from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, field_validator


class LanguageEnum(StrEnum):
    python = "python"
    powershell = "powershell"
    csharp = "csharp"
    ironpython = "ironpython"
    bof = "bof"


class EmpireModuleAdvanced(BaseModel):
    option_format_string: str = '-{{ KEY }} "{{ VALUE }}"'
    option_format_string_boolean: str = "-{{ KEY }}"
    custom_generate: bool = False
    generate_class: Any = None


class EmpireModuleOption(BaseModel):
    name: str
    name_in_code: str | None = None
    description: str = ""
    required: bool = False
    value: str = ""
    suggested_values: list[str] = []
    strict: bool = False
    type: str | None = None
    internal: bool = False
    depends_on: list[dict[str, str | list[str]]] | None = None

    # Ensure the functionality of pydantic v1 coercing values to strings
    # https://github.com/pydantic/pydantic/issues/5606
    @field_validator("value", mode="plain")
    @classmethod
    def check_value(cls, v):
        return str(v)

    # @classmethod
    @field_validator("suggested_values", mode="plain")
    @classmethod
    def check_suggested_values(cls, v):
        return [str(value) for value in v]


class EmpireAuthor(BaseModel):
    name: str | None = ""
    handle: str | None = ""
    link: str | None = ""


class BofModuleOption(BaseModel):
    x86: str | None = None
    x64: str | None = None
    entry_point: str | None = None
    format_string: str | None = None


class CSharpOption(BaseModel):
    UnsafeCompile: bool = False
    CompatibleDotNetVersions: list[str] = []
    Code: str = ""
    ReferenceSourceLibraries: list[dict] | None = []
    ReferenceAssemblies: list[dict] | None = []
    EmbeddedResources: list[dict] | None = []


class EmpireModule(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str
    name: str
    authors: list[EmpireAuthor] = []
    description: str = ""
    software: str = ""
    techniques: list[str] = []
    tactics: list[str] = []
    background: bool = False
    output_extension: str | None = None
    needs_admin: bool = False
    opsec_safe: bool = False
    language: LanguageEnum
    min_language_version: str | None = None
    comments: list[str] = []
    options: list[EmpireModuleOption] = []
    script: str | None = None
    script_path: str | None = None
    bof: BofModuleOption | None = None
    script_end: str = " {{ PARAMS }}"
    enabled: bool = True
    advanced: EmpireModuleAdvanced = EmpireModuleAdvanced()
    compiler_yaml: str | None = None
    csharp: CSharpOption | None = None
