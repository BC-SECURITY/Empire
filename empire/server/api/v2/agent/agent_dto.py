from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel

from empire.server.api.v2.tag.tag_dto import Tag, domain_to_dto_tag
from empire.server.core.db import models


def domain_to_dto_agent(agent: models.Agent):
    return Agent(
        session_id=agent.session_id,
        name=agent.name,
        # the way agents connect, we only get the listener name. Ideally we should
        # be getting the id so we can store it by id on the db.
        # Future change would be to add id to the dto and change
        # listener to listener_name
        # listener_id=agent.listener,
        listener=agent.listener,
        host_id=agent.host_id,
        hostname=agent.hostname,
        language=agent.language,
        language_version=agent.language_version,
        delay=agent.delay,
        jitter=agent.jitter,
        external_ip=agent.external_ip,
        internal_ip=agent.internal_ip,
        username=agent.username,
        high_integrity=agent.high_integrity,
        process_id=agent.process_id,
        process_name=agent.process_name,
        os_details=agent.os_details,
        nonce=agent.nonce,
        checkin_time=agent.firstseen_time,
        lastseen_time=agent.lastseen_time,
        parent=agent.parent,
        children=agent.children,
        servers=agent.servers,
        profile=agent.profile,
        kill_date=agent.kill_date,
        working_hours=agent.working_hours,
        lost_limit=agent.lost_limit,
        notes=agent.notes,
        architecture=agent.architecture,
        stale=agent.stale,
        archived=agent.archived,
        tags=[domain_to_dto_tag(x) for x in agent.tags],
    )


def domain_to_dto_agent_checkin(agent_checkin: models.AgentCheckIn):
    return AgentCheckIn(
        agent_id=agent_checkin.agent_id,
        checkin_time=agent_checkin.checkin_time,
    )


def domain_to_dto_agent_checkin_agg(agent_checkin_agg):
    return AgentCheckInAggregate(
        count=agent_checkin_agg["count"], checkin_time=agent_checkin_agg["checkin_time"]
    )


class Agent(BaseModel):
    session_id: str
    name: str
    # listener_id: int
    listener: str
    host_id: int | None = None
    hostname: str | None = None
    language: str | None = None
    language_version: str | None = None
    delay: int
    jitter: float
    external_ip: str | None = None
    internal_ip: str | None = None
    username: str | None = None
    high_integrity: bool | None = None
    process_id: int | None = None
    process_name: str | None = None
    os_details: str | None = None
    nonce: str
    checkin_time: datetime
    lastseen_time: datetime
    parent: str | None = None
    children: str | None = None
    servers: str | None = None
    profile: str | None = None
    functions: str | None = None
    kill_date: str | None = None
    working_hours: str | None = None
    lost_limit: int
    notes: str | None = None
    architecture: str | None = None
    archived: bool
    stale: bool
    tags: list[Tag]


class Agents(BaseModel):
    records: list[Agent]


class AgentCheckIn(BaseModel):
    agent_id: str
    checkin_time: datetime


class AgentCheckIns(BaseModel):
    records: list[AgentCheckIn]
    limit: int
    page: int
    total_pages: int
    total: int


class AgentCheckInAggregate(BaseModel):
    count: int
    checkin_time: datetime  # will be truncated depending on the group_by


class AgentCheckInsAggregate(BaseModel):
    records: list[AgentCheckInAggregate]
    start_date: datetime | None = None
    end_date: datetime | None = None
    bucket_size: str


class AggregateBucket(StrEnum):
    second = "second"
    minute = "minute"
    hour = "hour"
    day = "day"


class AgentUpdateRequest(BaseModel):
    name: str
    notes: str | None = None
