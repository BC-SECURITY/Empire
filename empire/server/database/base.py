import os

from sqlalchemy import create_engine
from sqlalchemy.orm import scoped_session, sessionmaker

from empire.server.common.config import empire_config
from empire.server.database import models
from empire.server.database.defaults import (
    get_default_config,
    get_default_keyword_obfuscation,
    get_default_user,
)
from empire.server.database.models import Base

database_config = empire_config.database

if database_config.type == "mysql":
    url = database_config.url
    username = database_config.username
    password = database_config.password
    engine = create_engine(
        f"mysql+pymysql://{username}:{password}@{url}/empire", echo=False
    )
else:
    location = database_config.location
    engine = create_engine(f"sqlite:///{location}?check_same_thread=false", echo=False)

Session = scoped_session(sessionmaker(bind=engine))


Base.metadata.create_all(engine)


def reset_db():
    Base.metadata.drop_all(engine)
    if database_config.type == "sqlite":
        os.unlink(database_config.location)


def color(string, color=None):
    """
    Change text color for the Linux terminal.
    Note: this is duplicate code copied from helpers.py because it cannot be imported into this file due to a circular
    reference. There are plans to refactor these circular references out, but this is the near term solution.
    """
    attr = []
    # bold
    attr.append("1")

    if color:
        if color.lower() == "red":
            attr.append("31")
        elif color.lower() == "green":
            attr.append("32")
        elif color.lower() == "yellow":
            attr.append("33")
        elif color.lower() == "blue":
            attr.append("34")
        return "\x1b[%sm%s\x1b[0m" % (";".join(attr), string)

    else:
        if string.strip().startswith("[!]"):
            attr.append("31")
            return "\x1b[%sm%s\x1b[0m" % (";".join(attr), string)
        elif string.strip().startswith("[+]"):
            attr.append("32")
            return "\x1b[%sm%s\x1b[0m" % (";".join(attr), string)
        elif string.strip().startswith("[*]"):
            attr.append("34")
            return "\x1b[%sm%s\x1b[0m" % (";".join(attr), string)
        elif string.strip().startswith("[>]"):
            attr.append("33")
            return "\x1b[%sm%s\x1b[0m" % (";".join(attr), string)
        else:
            return string


# When Empire starts up for the first time, it will create the database and create
# these default records.
if len(Session().query(models.User).all()) == 0:
    print(color("[*] Setting up database."))
    print(color("[*] Adding default user."))
    Session().add(get_default_user())
    Session().commit()
    Session.remove()

if len(Session().query(models.Config).all()) == 0:
    print(color("[*] Adding database config."))
    Session().add(get_default_config())
    Session().commit()
    Session.remove()

if len(Session().query(models.Keyword).all()) == 0:
    print(color("[*] Adding default keyword obfuscation functions."))
    functions = get_default_keyword_obfuscation()

    for function in functions:
        Session().add(function)
    Session().commit()
    Session.remove()
