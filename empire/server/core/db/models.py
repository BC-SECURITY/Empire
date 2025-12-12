import base64
import enum
import os
from pathlib import Path

import sqlalchemy
from fastapi.encoders import jsonable_encoder
from pydantic import BaseModel
from sqlalchemy import (
    JSON,
    Boolean,
    Column,
    Enum,
    Float,
    ForeignKey,
    ForeignKeyConstraint,
    Integer,
    Sequence,
    String,
    Table,
    Text,
    func,
    select,
    text,
)
from sqlalchemy.dialects import mysql
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.ext.hybrid import hybrid_property
from sqlalchemy.orm import Mapped, declarative_base, deferred, relationship
from sqlalchemy_utc import UtcDateTime, utcnow

from empire.server.core.config.config_manager import (
    PluginAutoExecuteConfig,
    empire_config,
)
from empire.server.core.module_models import EmpireAuthor
from empire.server.utils.datetime_util import is_stale

Base = declarative_base()

database_config = empire_config.database
use = os.environ.get("DATABASE_USE", database_config.use)
database_config.use = use
database_config = database_config[use.lower()]


def get_database_config():
    return use, database_config


agent_task_download_assc = Table(
    "agent_task_download_assc",
    Base.metadata,
    Column("agent_task_id", Integer),
    Column("agent_id", String(255)),
    Column("download_id", Integer, ForeignKey("downloads.id")),
    ForeignKeyConstraint(
        ("agent_task_id", "agent_id"), ("agent_tasks.id", "agent_tasks.agent_id")
    ),
)

plugin_task_download_assc = Table(
    "plugin_task_download_assc",
    Base.metadata,
    Column("plugin_task_id", Integer, ForeignKey("plugin_tasks.id")),
    Column("download_id", Integer, ForeignKey("downloads.id")),
    ForeignKeyConstraint(("plugin_task_id",), ("plugin_tasks.id",)),
)

agent_file_download_assc = Table(
    "agent_file_download_assc",
    Base.metadata,
    Column("agent_file_id", Integer, ForeignKey("agent_files.id", ondelete="CASCADE")),
    Column("download_id", Integer, ForeignKey("downloads.id")),
)

stager_download_assc = Table(
    "stager_download_assc",
    Base.metadata,
    Column("stager_id", Integer, ForeignKey("stagers.id")),
    Column("download_id", Integer, ForeignKey("downloads.id")),
)

# this doesn't actually join to anything atm, but is used for the filtering in api/v2/downloads
upload_download_assc = Table(
    "upload_download_assc",
    Base.metadata,
    Column("download_id", Integer, ForeignKey("downloads.id")),
)

listener_tag_assc = Table(
    "listener_tag_assc",
    Base.metadata,
    Column("listener_id", Integer, ForeignKey("listeners.id")),
    Column("tag_id", Integer, ForeignKey("tags.id")),
)

agent_tag_assc = Table(
    "agent_tag_assc",
    Base.metadata,
    Column("agent_id", String(255), ForeignKey("agents.session_id")),
    Column("tag_id", Integer, ForeignKey("tags.id")),
)

agent_task_tag_assc = Table(
    "agent_task_tag_assc",
    Base.metadata,
    Column("agent_task_id", Integer),
    Column("agent_id", String(255)),
    Column("tag_id", Integer, ForeignKey("tags.id")),
    ForeignKeyConstraint(
        ("agent_task_id", "agent_id"), ("agent_tasks.id", "agent_tasks.agent_id")
    ),
)

plugin_task_tag_assc = Table(
    "plugin_task_tag_assc",
    Base.metadata,
    Column("plugin_task_id", Integer, ForeignKey("plugin_tasks.id")),
    Column("tag_id", Integer, ForeignKey("tags.id")),
)

credential_tag_assc = Table(
    "credential_tag_assc",
    Base.metadata,
    Column("credential_id", Integer, ForeignKey("credentials.id")),
    Column("tag_id", Integer, ForeignKey("tags.id")),
)

download_tag_assc = Table(
    "download_tag_assc",
    Base.metadata,
    Column("download_id", Integer, ForeignKey("downloads.id")),
    Column("tag_id", Integer, ForeignKey("tags.id")),
)


# https://roman.pt/posts/pydantic-in-sqlalchemy-fields/
class PydanticType(sqlalchemy.types.TypeDecorator):
    """Pydantic type.
    SAVING:
    - Uses SQLAlchemy JSON type under the hood.
    - Acceps the pydantic model and converts it to a dict on save.
    - SQLAlchemy engine JSON-encodes the dict to a string.
    RETRIEVING:
    - Pulls the string from the database.
    - SQLAlchemy engine JSON-decodes the string to a dict.
    - Uses the dict to create a pydantic model.
    """

    # If you work with PostgreSQL, you can consider using
    # sqlalchemy.dialects.postgresql.JSONB instead of a
    # generic sa.types.JSON
    #
    # Ref: https://www.postgresql.org/docs/13/datatype-json.html
    impl = sqlalchemy.types.JSON

    def __init__(self, pydantic_type):
        super().__init__()
        self.pydantic_type = pydantic_type

    def load_dialect_impl(self, dialect):
        # Use JSONB for PostgreSQL and JSON for other databases.
        if dialect.name == "postgresql":
            return dialect.type_descriptor(JSONB())
        return dialect.type_descriptor(sqlalchemy.JSON())

    def process_bind_param(self, value, dialect):
        return jsonable_encoder(value) if value else None

    def process_result_value(self, value, dialect):
        if self.pydantic_type and value:
            return self.pydantic_type.model_validate(value)

        return None


class PluginInfo(BaseModel):
    id: str | None = None  # Get's set after the class is loaded from the yaml file
    name: str
    authors: list[EmpireAuthor] = []
    readme: str | None = ""
    software: str | None = ""
    techniques: list[str] | None = []
    tactics: list[str] | None = []
    auto_start: bool = True
    auto_execute: PluginAutoExecuteConfig | None = None
    main: str
    python_deps: list[str] | None = []


class User(Base):
    __tablename__ = "users"
    id = Column(Integer, Sequence("user_id_seq"), primary_key=True)
    username = Column(String(255), nullable=False)
    hashed_password = Column(String(255), nullable=False)
    api_token = Column(String(50))
    enabled = Column(Boolean, nullable=False)
    admin = Column(Boolean, nullable=False)
    notes = Column(Text)
    created_at = Column(UtcDateTime, default=utcnow(), nullable=False)
    updated_at = Column(
        UtcDateTime, default=utcnow(), onupdate=utcnow(), nullable=False
    )
    avatar = relationship("Download")
    avatar_id = Column(Integer, ForeignKey("downloads.id"), nullable=True)

    def __repr__(self):
        return f"<User(username='{self.username}')>"


class Listener(Base):
    __tablename__ = "listeners"
    id = Column(Integer, Sequence("listener_id_seq"), primary_key=True)
    name = Column(String(255), nullable=False, unique=True)
    module = Column(String(255), nullable=False)
    listener_type = Column(String(255), nullable=True)
    listener_category = Column(String(255), nullable=False)
    enabled = Column(Boolean, nullable=False)
    host_address = Column(String(255), nullable=True)
    options = Column(JSON)
    created_at = Column(UtcDateTime, nullable=False, default=utcnow())
    tags = relationship("Tag", secondary=listener_tag_assc)
    autorun_tasks = Column(JSON, nullable=True)

    def __repr__(self):
        return f"<Listener(name='{self.name}')>"


class Host(Base):
    __tablename__ = "hosts"
    id = Column(Integer, Sequence("host_id_seq"), primary_key=True)
    name = Column(Text, nullable=False)
    internal_ip = Column(Text)

    # unique check handled differently in mysql and sqlite
    # In base.py, a unique constraint is added for sqlite
    # and a generated column is added for mysql


class AgentCheckIn(Base):
    """
    Agents check in periodically. Every time they do, a new AgentCheckIn is created.
    This is used to calculate the stale status of an agent and is used to
    """

    __tablename__ = "agent_checkins"
    agent_id = Column(
        String(255),
        ForeignKey("agents.session_id", ondelete="CASCADE"),
        nullable=False,
        primary_key=True,
    )
    checkin_time = Column(
        UtcDateTime, nullable=False, default=utcnow(), index=True, primary_key=True
    )


class Agent(Base):
    __tablename__ = "agents"
    session_id = Column(String(255), primary_key=True, nullable=False)
    name = Column(String(255), nullable=False)
    host_id = Column(Integer, ForeignKey("hosts.id"), nullable=True)
    host = relationship(Host, lazy="joined")
    listener = Column(String(255), nullable=False)
    language = Column(String(255))
    language_version = Column(String(255))
    delay = Column(Integer)
    jitter = Column(Float)
    external_ip = Column(String(255))
    internal_ip = Column(Text)
    username = Column(Text)
    high_integrity = Column(Boolean)
    process_name = Column(Text)
    process_id = Column(Integer)
    hostname = Column(String(255))
    os_details = Column(String(255))
    session_key = Column(String(255))
    nonce = Column(String(255))
    firstseen_time = Column(UtcDateTime, default=utcnow())
    checkins: Mapped[list[AgentCheckIn]] = relationship(
        "AgentCheckIn",
        order_by="desc(AgentCheckIn.checkin_time)",
        lazy="dynamic",
        cascade="all, delete",
    )
    parent = Column(String(255))
    children = Column(String(255))
    servers = Column(String(255))
    profile = Column(Text)
    functions = Column(String(255))
    kill_date = Column(String(255))
    working_hours = Column(String(255))
    lost_limit = Column(Integer)
    notes = Column(Text)
    architecture = Column(String(255))
    archived = Column(Boolean, nullable=False)
    socks = Column(Boolean)
    socks_port = Column(Integer)
    tags = relationship("Tag", secondary=agent_tag_assc)

    @hybrid_property
    def lastseen_time(self):
        return self.checkins[0].checkin_time

    #  https://stackoverflow.com/questions/72096054/sqlalchemy-limit-the-joinedloaded-results
    @lastseen_time.inplace.expression
    @classmethod
    def _lastseen_time_expression(cls):
        return (
            select(AgentCheckIn.checkin_time)
            .filter(AgentCheckIn.agent_id == cls.session_id)
            .order_by(AgentCheckIn.checkin_time.desc())
            .limit(1)
            .label("lastseen_time")
        )

    @hybrid_property
    def stale(self):
        return is_stale(self.lastseen_time, self.delay, self.jitter)

    @stale.inplace.expression
    @classmethod
    def _stale_expression(cls):
        if get_database_config()[0] == "sqlite":
            threshold = 30 + cls.delay + cls.delay * cls.jitter
            seconds_elapsed = (
                func.julianday(utcnow()) - func.julianday(cls.lastseen_time)
            ) * 86400.0
            return seconds_elapsed > threshold

        diff = func.timestampdiff(
            text("SECOND"), cls.lastseen_time, func.utc_timestamp()
        )
        threshold = 30 + cls.delay + cls.delay * cls.jitter
        return diff > threshold

    def __repr__(self):
        return f"<Agent(name='{self.name}')>"

    def __getitem__(self, key):
        return self.__dict__[key]

    def __setitem__(self, key, value):
        self.__dict__[key] = value


class AgentFile(Base):
    __tablename__ = "agent_files"
    id = Column(Integer, primary_key=True)
    session_id = Column(String(50))
    name = Column(Text, nullable=False)
    path = Column(Text, nullable=False)
    is_file = Column(Boolean, nullable=False)
    parent_id = Column(
        Integer, ForeignKey("agent_files.id", ondelete="CASCADE"), nullable=True
    )
    downloads = relationship("Download", secondary=agent_file_download_assc)


class HostProcess(Base):
    __tablename__ = "host_processes"
    host_id = Column(Integer, ForeignKey("hosts.id"), primary_key=True)
    process_id = Column(Integer, primary_key=True)
    process_name = Column(Text)
    architecture = Column(String(255))
    user = Column(String(255))
    stale = Column(Boolean, default=False)
    agent = relationship(
        Agent,
        lazy="joined",
        primaryjoin="and_(Agent.process_id==foreign(HostProcess.process_id), Agent.host_id==foreign(HostProcess.host_id), Agent.archived == False)",
    )


class Config(Base):
    __tablename__ = "config"
    staging_key = Column(String(255), primary_key=True)
    jwt_secret_key = Column(Text, nullable=False)
    ip_filtering = Column(Boolean, nullable=False)

    def __repr__(self):
        return f"<Config(staging_key='{self.staging_key}')>"

    def __getitem__(self, key):
        return self.__dict__[key]

    def __setitem__(self, key, value):
        self.__dict__[key] = value


class Credential(Base):
    __tablename__ = "credentials"
    id = Column(Integer, Sequence("credential_id_seq"), primary_key=True)
    credtype = Column(String(255))
    domain = Column(Text)
    username = Column(Text)
    password = Column(Text)
    host = Column(Text)
    os = Column(String(255))
    sid = Column(String(255))
    notes = Column(Text)
    created_at = Column(UtcDateTime, default=utcnow(), nullable=False)
    updated_at = Column(
        UtcDateTime, default=utcnow(), onupdate=utcnow(), nullable=False
    )
    tags = relationship("Tag", secondary=credential_tag_assc)

    def __repr__(self):
        return f"<Credential(id='{self.id}')>"

    def __getitem__(self, key):
        return self.__dict__[key]

    def __setitem__(self, key, value):
        self.__dict__[key] = value


class Download(Base):
    __tablename__ = "downloads"
    id = Column(Integer, Sequence("download_seq"), primary_key=True)
    location = Column(Text, nullable=False)
    filename = Column(Text, nullable=True)
    size = Column(Integer, nullable=True)
    created_at = Column(UtcDateTime, default=utcnow(), nullable=False)
    updated_at = Column(
        UtcDateTime, default=utcnow(), onupdate=utcnow(), nullable=False
    )
    tags = relationship("Tag", secondary=download_tag_assc)

    def get_base64_file(self):
        return base64.b64encode(self.get_bytes_file()).decode("utf-8")

    def get_bytes_file(self):
        return Path(self.location).read_bytes()


class AgentTaskStatus(str, enum.Enum):
    queued = "queued"
    pulled = "pulled"
    completed = "completed"
    error = "error"
    continuous = "continuous"


class AgentTask(Base):
    __tablename__ = "agent_tasks"
    id = Column(Integer, primary_key=True)
    agent_id = Column(
        String(255),
        ForeignKey("agents.session_id", ondelete="CASCADE"),
        primary_key=True,
    )
    agent = relationship(Agent, lazy="joined", innerjoin=True)
    input = Column(Text)
    input_full = deferred(Column(Text().with_variant(mysql.LONGTEXT, "mysql")))
    output = deferred(
        Column(Text().with_variant(mysql.LONGTEXT, "mysql"), nullable=True)
    )
    # In most cases, this isn't needed and will match output.
    #  However, with the filter feature, we want to store
    # a copy of the original output if it gets modified by a filter.
    original_output = deferred(
        Column(Text().with_variant(mysql.LONGTEXT, "mysql"), nullable=True)
    )
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    user = relationship(User)
    created_at = Column(UtcDateTime, default=utcnow(), nullable=False)
    updated_at = Column(
        UtcDateTime, default=utcnow(), onupdate=utcnow(), nullable=False
    )
    module_name = Column(Text)
    task_name = Column(Text)
    status = Column(Enum(AgentTaskStatus), index=True)
    downloads = relationship("Download", secondary=agent_task_download_assc)
    tags = relationship("Tag", secondary=agent_task_tag_assc)

    def __repr__(self):
        return f"<AgentTask(id='{self.id}')>"

    def __getitem__(self, key):
        return self.__dict__[key]

    def __setitem__(self, key, value):
        self.__dict__[key] = value


class Plugin(Base):
    __tablename__ = "plugins"
    id = Column(String(255), primary_key=True)
    name = Column(String(255), nullable=False)
    enabled = Column(Boolean, nullable=False)
    settings = Column(JSON)
    settings_initialized = Column(Boolean, nullable=False, default=False)
    internal_state = Column(JSON)
    info = Column(PydanticType(PluginInfo), nullable=False)
    load_error = Column(Text, nullable=True)
    installed_version = Column(String(255), nullable=False, default="unknown")


class PluginTaskStatus(str, enum.Enum):
    queued = "queued"
    started = "started"
    completed = "completed"
    error = "error"
    continuous = "continuous"


class PluginTask(Base):
    __tablename__ = "plugin_tasks"
    id = Column(Integer, primary_key=True, autoincrement=True)
    plugin_id = Column(String(255), ForeignKey("plugins.id"), nullable=False)
    input = Column(Text)
    input_full = deferred(Column(Text().with_variant(mysql.LONGTEXT, "mysql")))
    output = deferred(
        Column(Text().with_variant(mysql.LONGTEXT, "mysql"), nullable=True)
    )
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    user = relationship(User)
    created_at = Column(UtcDateTime, default=utcnow(), nullable=False)
    updated_at = Column(
        UtcDateTime, default=utcnow(), onupdate=utcnow(), nullable=False
    )
    task_name = Column(Text)
    status = Column(Enum(PluginTaskStatus), index=True)
    downloads = relationship("Download", secondary=plugin_task_download_assc)
    tags = relationship("Tag", secondary=plugin_task_tag_assc)

    def __repr__(self):
        return f"<PluginTask(id='{self.id}')>"


class PluginRegistry(Base):
    __tablename__ = "plugin_registry"
    name = Column(String(255), nullable=False, primary_key=True)
    location = Column(Text, nullable=True)
    url = Column(Text, nullable=True)
    data = Column(JSON, nullable=False)


class Keyword(Base):
    __tablename__ = "keywords"
    id = Column(Integer, Sequence("keyword_seq"), primary_key=True)
    keyword = Column(String(255), unique=True)
    replacement = Column(String(255))
    created_at = Column(UtcDateTime, nullable=False, default=utcnow())
    updated_at = Column(
        UtcDateTime, default=utcnow(), onupdate=utcnow(), nullable=False
    )

    def __repr__(self):
        return f"<KeywordReplacement(id='{self.id}')>"


class Module(Base):
    __tablename__ = "modules"
    id = Column(String(255), primary_key=True)
    name = Column(String(255), nullable=False)
    enabled = Column(Boolean, nullable=False)
    technique = Column(JSON)
    tactic = Column(JSON)
    software = Column(JSON)


class Profile(Base):
    __tablename__ = "profiles"
    id = Column(Integer, Sequence("profile_seq"), primary_key=True)
    name = Column(String(255), unique=True)
    file_path = Column(String(255))
    category = Column(String(255))
    data = Column(Text, nullable=False)
    created_at = Column(UtcDateTime, nullable=False, default=utcnow())
    updated_at = Column(
        UtcDateTime, default=utcnow(), onupdate=utcnow(), nullable=False
    )


class Bypass(Base):
    __tablename__ = "bypasses"
    id = Column(Integer, Sequence("bypass_seq"), primary_key=True)
    name = Column(String(255), unique=True)
    authors = Column(JSON)
    code = Column(Text)
    language = Column(String(255))
    is_default = Column(Boolean, default=False, nullable=False)
    created_at = Column(UtcDateTime, nullable=False, default=utcnow())
    updated_at = Column(
        UtcDateTime, default=utcnow(), onupdate=utcnow(), nullable=False
    )


class Stager(Base):
    __tablename__ = "stagers"
    id = Column(Integer, Sequence("stager_seq"), primary_key=True)
    name = Column(String(255), unique=True)
    module = Column(String(255))
    options = Column(JSON)
    downloads = relationship("Download", secondary=stager_download_assc)
    one_liner = Column(Boolean)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    created_at = Column(UtcDateTime, nullable=False, default=utcnow())
    updated_at = Column(
        UtcDateTime, default=utcnow(), onupdate=utcnow(), nullable=False
    )


class ObfuscationConfig(Base):
    __tablename__ = "obfuscation_config"
    language = Column(String(255), primary_key=True)
    command = Column(Text)
    module = Column(String(255))
    enabled = Column(Boolean)
    preobfuscatable = Column(Boolean)


class Tag(Base):
    __tablename__ = "tags"
    id = Column(Integer, Sequence("tag_seq"), primary_key=True)
    name = Column(String(255), nullable=False)
    value = Column(String(255), nullable=False)
    color = Column(String(12), nullable=True)
    created_at = Column(UtcDateTime, nullable=False, default=utcnow())
    updated_at = Column(
        UtcDateTime, nullable=False, onupdate=utcnow(), default=utcnow()
    )


class IpList(str, enum.Enum):
    allow = "allow"
    deny = "deny"


class IP(Base):
    __tablename__ = "ips"
    id = Column(Integer, Sequence("ip_seq"), primary_key=True)
    ip_address = Column(String(255), nullable=False)
    list = Column(Enum(IpList), nullable=False)
    description = Column(Text, nullable=True)
    created_at = Column(UtcDateTime, nullable=False, default=utcnow())
    updated_at = Column(
        UtcDateTime, nullable=False, onupdate=utcnow(), default=utcnow()
    )
