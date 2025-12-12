import logging
import sqlite3
import sys
from pathlib import Path
from urllib.parse import quote_plus

from sqlalchemy import Index, UniqueConstraint, create_engine, event, text
from sqlalchemy.engine import Engine
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import close_all_sessions, sessionmaker

from empire.server.core.db import models
from empire.server.core.db.defaults import (
    get_default_config,
    get_default_ips,
    get_default_keyword_obfuscation,
    get_default_obfuscation_config,
    get_default_user,
)
from empire.server.core.db.models import Base, get_database_config

log = logging.getLogger(__name__)


# https://stackoverflow.com/a/13719230
@event.listens_for(Engine, "connect")
def set_sqlite_pragma(dbapi_connection, connection_record):
    if type(dbapi_connection) is sqlite3.Connection:  # play well with other DB backends
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA journal_mode=WAL;")
        cursor.close()


def try_create_engine(engine_url: str, *args, **kwargs) -> Engine:
    engine = create_engine(engine_url, *args, **kwargs)
    try:
        with engine.connect():
            pass
    except OperationalError as e:
        log.error(e, exc_info=True)
        log.error(f"Failed connecting to database using {engine_url}")
        log.error("Perhaps the MySQL service is not running.")
        log.error("Try executing: sudo systemctl start mysql")
        sys.exit(1)

    return engine


use, database_config = get_database_config()


def reset_db():
    close_all_sessions()

    if use == "mysql":
        cmd = f"DROP DATABASE IF EXISTS {database_config.database_name}"
        reset_engine = try_create_engine(mysql_url, echo=False)
        with reset_engine.connect() as connection:
            connection.execute(text(cmd))

    if use == "sqlite":
        Path(database_config.location).unlink(missing_ok=True)


if use == "mysql":
    url = database_config.url
    database_name = database_config.database_name
    encoded_username = (
        quote_plus(database_config.username) if database_config.username else ""
    )
    encoded_password = (
        quote_plus(database_config.password) if database_config.password else ""
    )

    if encoded_username and encoded_password:
        userinfo = f"{encoded_username}:{encoded_password}"
    elif encoded_username:
        userinfo = encoded_username
    else:
        userinfo = ""
    auth = f"{userinfo}@" if userinfo else ""

    mysql_url = f"mysql+pymysql://{auth}{url}"
    engine = try_create_engine(mysql_url, echo=False)
    with engine.connect() as connection:
        connection.execute(text(f"CREATE DATABASE IF NOT EXISTS {database_name}"))
    engine = try_create_engine(f"{mysql_url}/{database_name}", echo=False)
else:
    location = database_config.location
    engine = try_create_engine(
        f"sqlite:///{location}",
        connect_args={
            "check_same_thread": False,
        },
        echo=False,
    )

    models.Host.__table_args__ = (
        UniqueConstraint(
            models.Host.name, models.Host.internal_ip, name="host_unique_idx"
        ),
    )

SessionLocal = sessionmaker(bind=engine)
Base.metadata.create_all(engine)


def startup_db():
    try:
        with SessionLocal.begin() as db:
            if use == "mysql":
                database_name = database_config.database_name

                result = db.execute(
                    text(
                        f"""
                    SELECT * FROM information_schema.COLUMNS
                    WHERE TABLE_SCHEMA = '{database_name}'
                    AND table_name = 'hosts'
                    AND column_name = 'unique_check'
                    """
                    )
                ).fetchone()
                if not result:
                    db.execute(
                        text(
                            """
                        ALTER TABLE hosts
                        ADD COLUMN unique_check VARCHAR(255) GENERATED ALWAYS AS (MD5(CONCAT(name, internal_ip))) UNIQUE;
                        """
                        )
                    )

                    # index agent_id and checkin_time together
                    # won't work for sqlite.
                    Index(
                        "agent_checkin_idx",
                        models.AgentCheckIn.agent_id,
                        models.AgentCheckIn.checkin_time.desc(),
                    )

            # When Empire starts up for the first time, it will create the database and create
            # these default records.
            if len(db.query(models.User).all()) == 0:
                log.info("Setting up database.")
                log.info("Adding default user.")
                db.add(get_default_user())

            if len(db.query(models.Config).all()) == 0:
                log.info("Adding database config.")
                db.add(get_default_config())

            if len(db.query(models.Keyword).all()) == 0:
                log.info("Adding default keyword obfuscation functions.")
                keywords = get_default_keyword_obfuscation()

                for keyword in keywords:
                    db.add(keyword)

            if len(db.query(models.ObfuscationConfig).all()) == 0:
                log.info("Adding default obfuscation config.")
                obf_configs = get_default_obfuscation_config()

                for config in obf_configs:
                    db.add(config)

            if len(db.query(models.IP).all()) == 0:
                ips = get_default_ips()

                for ip in ips:
                    db.add(ip)

            # Checking that schema matches the db.
            # Some errors don't manifest until query time.
            for model in models.Base.__subclasses__():
                db.query(model).first()

    except Exception as e:
        log.error(e, exc_info=True)
        log.error("Failed to setup database.")
        log.error(
            "If you have recently updated Empire, please run 'server --clean' to reset the database."
        )
        sys.exit(1)
