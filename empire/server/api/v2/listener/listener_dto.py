from datetime import datetime

from pydantic import BaseModel, ConfigDict

from empire.server.api.v2.agent.agent_task_dto import ModulePostRequest
from empire.server.api.v2.shared_dto import (
    Author,
    CustomOptionSchema,
    coerced_dict,
    to_value_type,
)
from empire.server.api.v2.tag.tag_dto import Tag, domain_to_dto_tag


def domain_to_dto_template(listener, uid: str):
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
        for x in listener.options.items()
    }

    authors = [
        {
            "name": x["Name"],
            "handle": x["Handle"],
            "link": x["Link"],
        }
        for x in listener.info.get("Authors") or []
    ]

    return ListenerTemplate(
        id=uid,
        name=listener.info.get("Name"),
        authors=authors,
        description=listener.info.get("Description"),
        category=listener.info.get("Category"),
        comments=listener.info.get("Comments"),
        software=listener.info.get("Software"),
        techniques=listener.info.get("Techniques"),
        tactics=listener.info.get("Tactics"),
        options=options,
    )


def domain_to_dto_listener(listener):
    options = {x[0]: x[1]["Value"] for x in listener.options.items()}

    return Listener(
        id=listener.id,
        name=listener.name,
        template=listener.module,
        enabled=listener.enabled,
        host_address=listener.host_address,
        options=options,
        created_at=listener.created_at,
        tags=[domain_to_dto_tag(x) for x in listener.tags],
    )


class ListenerTemplate(BaseModel):
    id: str
    name: str
    authors: list[Author]
    description: str
    category: str
    comments: list[str]
    tactics: list[str]
    techniques: list[str]
    software: str | None = None
    options: dict[str, CustomOptionSchema]
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "id": "http",
                "name": "HTTP[S]",
                "authors": [
                    {
                        "handle": "@harmj0y",
                        "link": "",
                        "name": "",
                    }
                ],
                "description": "Starts a http[s] listener that uses a GET/POST approach.",
                "category": "client_server",
                "comments": [],
                "tactics": [],
                "techniques": [],
                "software": "",
                "options": {
                    "Name": {
                        "description": "Name for the listener.",
                        "required": True,
                        "value": "http",
                        "suggested_values": [],
                        "strict": False,
                        "depends_on:": [],
                        "internal": False,
                    },
                    "Host": {
                        "description": "Hostname/IP for staging.",
                        "required": True,
                        "value": "http://192.168.0.20",
                        "suggested_values": [],
                        "strict": False,
                        "depends_on:": [],
                        "internal": False,
                    },
                    "BindIP": {
                        "description": "The IP to bind to on the control server.",
                        "required": True,
                        "value": "0.0.0.0",
                        "suggested_values": ["0.0.0.0"],
                        "strict": False,
                        "depends_on:": [],
                        "internal": False,
                    },
                    "Port": {
                        "description": "Port for the listener.",
                        "required": True,
                        "value": "",
                        "suggested_values": ["1335", "1336"],
                        "strict": False,
                        "depends_on:": [],
                        "internal": False,
                    },
                    "Launcher": {
                        "description": "Launcher string.",
                        "required": True,
                        "value": "powershell -noP -sta -w 1 -enc ",
                        "suggested_values": [],
                        "strict": False,
                        "depends_on:": [],
                        "internal": False,
                    },
                    "StagingKey": {
                        "description": "Staging key for initial agent negotiation.",
                        "required": True,
                        "value": "}q)jFnDKw&px/7QBhE9Y<6~[Z1>{+Ps@",
                        "suggested_values": [],
                        "strict": False,
                        "depends_on:": [],
                        "internal": False,
                    },
                    "DefaultDelay": {
                        "description": "Agent delay/reach back interval (in seconds).",
                        "required": True,
                        "value": "5",
                        "suggested_values": [],
                        "strict": False,
                        "depends_on:": [],
                        "internal": False,
                    },
                    "DefaultJitter": {
                        "description": "Jitter in agent reachback interval (0.0-1.0).",
                        "required": True,
                        "value": "0.0",
                        "suggested_values": [],
                        "strict": False,
                        "depends_on:": [],
                        "internal": False,
                    },
                    "DefaultLostLimit": {
                        "description": "Number of missed checkins before exiting",
                        "required": True,
                        "value": "60",
                        "suggested_values": [],
                        "strict": False,
                        "depends_on:": [],
                        "internal": False,
                    },
                    "DefaultProfile": {
                        "description": "Default communication profile for the agent.",
                        "required": True,
                        "value": "/admin/get.php,/news.php,/login/process.php|Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko",
                        "suggested_values": [],
                        "strict": False,
                        "depends_on:": [],
                        "internal": False,
                    },
                    "CertPath": {
                        "description": "Certificate path for https listeners.",
                        "required": False,
                        "value": "",
                        "suggested_values": [],
                        "strict": False,
                        "depends_on:": [],
                        "internal": False,
                    },
                    "KillDate": {
                        "description": "Date for the listener to exit (MM/dd/yyyy).",
                        "required": False,
                        "value": "",
                        "suggested_values": [],
                        "strict": False,
                        "depends_on:": [],
                        "internal": False,
                    },
                    "WorkingHours": {
                        "description": "Hours for the agent to operate (09:00-17:00).",
                        "required": False,
                        "value": "",
                        "suggested_values": [],
                        "strict": False,
                        "depends_on:": [],
                        "internal": False,
                    },
                    "Headers": {
                        "description": "Headers for the control server.",
                        "required": True,
                        "value": "Server:Microsoft-IIS/7.5",
                        "suggested_values": [],
                        "strict": False,
                        "depends_on:": [],
                        "internal": False,
                    },
                    "Cookie": {
                        "description": "Custom Cookie Name",
                        "required": False,
                        "value": "xNQsvLdAysjkonT",
                        "suggested_values": [],
                        "strict": False,
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
                },
            }
        }
    )


class ListenerTemplates(BaseModel):
    records: list[ListenerTemplate]


class Listener(BaseModel):
    id: int
    name: str
    enabled: bool
    template: str
    options: coerced_dict
    created_at: datetime
    host_address: str
    tags: list[Tag]


class Listeners(BaseModel):
    records: list[Listener]


class AutorunConfig(BaseModel):
    records: list[ModulePostRequest]


class ListenerPostRequest(BaseModel):
    name: str
    template: str
    options: coerced_dict
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "name": "MyListener",
                "template": "http",
                "tactics": [""],
                "techniques": [""],
                "software": "",
                "options": {
                    "Name": "MyListener",  # TODO VR Name should not be an option
                    "Host": "http://localhost",
                    "BindIP": "0.0.0.0",
                    "Port": "1336",
                    "Launcher": "powershell -noP -sta -w 1 -enc ",
                    "StagingKey": "2c103f2c4ed1e59c0b4e2e01821770fa",
                    "DefaultDelay": 5,
                    "DefaultJitter": 0.0,
                    "DefaultLostLimit": 60,
                    "DefaultProfile": "/admin/get.php,/news.php,/login/process.php|Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko",
                    "CertPath": "",
                    "KillDate": "",
                    "WorkingHours": "",
                    "Headers": "Server:Microsoft-IIS/7.5",
                    "Cookie": "",
                    "UserAgent": "default",
                    "Proxy": "default",
                    "ProxyCreds": "default",
                },
            }
        }
    )


class ListenerUpdateRequest(BaseModel):
    name: str
    enabled: bool
    options: coerced_dict

    def __iter__(self):
        return iter(self.__root__)

    def __getitem__(self, item):
        return self.__root__[item]
