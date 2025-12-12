from datetime import datetime

from pydantic import BaseModel, ConfigDict

from empire.server.api.v2.shared_dto import (
    Author,
    CustomOptionSchema,
    DownloadDescription,
    coerced_dict,
    domain_to_dto_download_description,
    to_value_type,
)
from empire.server.core.db import models


def domain_to_dto_template(stager, uid: str):
    options = {
        x[0]: {
            "description": x[1]["Description"],
            "required": x[1]["Required"],
            "value": x[1]["Value"],
            "strict": x[1]["Strict"],
            "suggested_values": x[1]["SuggestedValues"],
            "value_type": to_value_type(x[1]["Value"], x[1].get("Type")),
            "depends_on": x[1]["Depends_on"] if x[1]["Depends_on"] is not None else [],
            "internal": x[1]["Internal"] if x[1]["Internal"] is not None else False,
        }
        for x in stager.options.items()
    }

    authors = [
        {
            "name": x["Name"],
            "handle": x["Handle"],
            "link": x["Link"],
        }
        for x in stager.info.get("Authors") or []
    ]

    return StagerTemplate(
        id=uid,
        name=stager.info.get("Name"),
        authors=authors,
        description=stager.info.get("Description"),
        comments=stager.info.get("Comments"),
        options=options,
    )


def domain_to_dto_stager(stager: models.Stager):
    return Stager(
        id=stager.id,
        name=stager.name,
        template=stager.module,
        one_liner=stager.one_liner,
        downloads=[domain_to_dto_download_description(x) for x in stager.downloads],
        options=stager.options,
        user_id=stager.user_id,
        created_at=stager.created_at,
        updated_at=stager.updated_at,
    )


class StagerTemplate(BaseModel):
    id: str
    name: str
    authors: list[Author]
    description: str
    comments: list[str]
    options: dict[str, CustomOptionSchema]
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "id": "multi_launcher",
                "name": "Launcher",
                "authors": ["@harmj0y"],
                "description": "Generates a one-liner stage0 launcher for Empire.",
                "comments": [""],
                "options": {
                    "Listener": {
                        "description": "Listener to generate stager for.",
                        "required": True,
                        "value": "",
                        "suggested_values": [],
                        "strict": False,
                        "depends_on:": [],
                        "internal": False,
                    },
                    "Language": {
                        "description": "Language of the stager to generate.",
                        "required": True,
                        "value": "powershell",
                        "suggested_values": ["powershell", "python"],
                        "strict": True,
                        "depends_on:": [],
                        "internal": False,
                    },
                    "StagerRetries": {
                        "description": "Times for the stager to retry connecting.",
                        "required": False,
                        "value": "0",
                        "suggested_values": [],
                        "strict": False,
                        "depends_on:": [],
                        "internal": False,
                    },
                    "OutFile": {
                        "description": "Filename that should be used for the generated output.",
                        "required": False,
                        "value": "",
                        "suggested_values": [],
                        "strict": False,
                        "depends_on:": [],
                        "internal": False,
                    },
                    "Base64": {
                        "description": "Switch. Base64 encode the output.",
                        "required": True,
                        "value": "True",
                        "suggested_values": ["True", "False"],
                        "strict": True,
                        "depends_on:": [],
                        "internal": False,
                    },
                    "Obfuscate": {
                        "description": "Switch. Obfuscate the launcher powershell code, uses the ObfuscateCommand for obfuscation types. For powershell only.",
                        "required": False,
                        "value": "False",
                        "suggested_values": ["True", "False"],
                        "strict": True,
                        "depends_on:": [],
                        "internal": False,
                    },
                    "ObfuscateCommand": {
                        "description": "The Invoke-Obfuscation command to use. Only used if Obfuscate switch is True. For powershell only.",
                        "required": False,
                        "value": "Token\\All\\1",
                        "suggested_values": [],
                        "strict": False,
                        "depends_on:": [],
                        "internal": False,
                    },
                    "SafeChecks": {
                        "description": "Switch. Checks for LittleSnitch or a SandBox, exit the staging process if True. Defaults to True.",
                        "required": True,
                        "value": "True",
                        "suggested_values": ["True", "False"],
                        "strict": True,
                        "depends_on:": [],
                        "internal": False,
                    },
                    "UserAgent": {
                        "description": "User-agent string to use for the staging request (default, none, or other).",
                        "required": False,
                        "value": "default",
                        "suggested_values": [],
                        "strict": False,
                        "depends_on:": [],
                        "internal": False,
                    },
                    "Proxy": {
                        "description": "Proxy to use for request (default, none, or other).",
                        "required": False,
                        "value": "default",
                        "suggested_values": [],
                        "strict": False,
                        "depends_on:": [],
                        "internal": False,
                    },
                    "ProxyCreds": {
                        "description": "Proxy credentials ([domain\\]username:password) to use for request (default, none, or other).",
                        "required": False,
                        "value": "default",
                        "suggested_values": [],
                        "strict": False,
                        "depends_on:": [],
                        "internal": False,
                    },
                    "Bypasses": {
                        "description": "Bypasses as a space separated list to be prepended to the launcher",
                        "required": False,
                        "value": "",
                        "suggested_values": [],
                        "strict": False,
                        "depends_on:": [],
                        "internal": False,
                    },
                },
            }
        }
    )


class StagerTemplates(BaseModel):
    records: list[StagerTemplate]


class Stager(BaseModel):
    id: int
    name: str
    template: str
    one_liner: bool
    downloads: list[DownloadDescription]
    options: coerced_dict
    user_id: int
    # optional because if its not saved yet, it will be None
    created_at: datetime | None = None
    updated_at: datetime | None = None


class Stagers(BaseModel):
    records: list[Stager]


class StagerPostRequest(BaseModel):
    name: str
    template: str
    options: coerced_dict
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "name": "MyStager",
                "template": "multi_launcher",
                "options": {
                    "Listener": "",
                    "Language": "powershell",
                    "StagerRetries": "0",
                    "OutFile": "",
                    "Base64": "True",
                    "Obfuscate": "False",
                    "ObfuscateCommand": "Token\\All\\1",
                    "SafeChecks": "True",
                    "UserAgent": "default",
                    "Proxy": "default",
                    "ProxyCreds": "default",
                    "Bypasses": "",
                },
            }
        }
    )


class StagerUpdateRequest(BaseModel):
    name: str
    options: coerced_dict

    def __iter__(self):
        return iter(self.__root__)

    def __getitem__(self, item):
        return self.__root__[item]
