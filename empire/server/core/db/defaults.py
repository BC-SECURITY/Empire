import logging
import os
import random
import secrets
import string

import bcrypt

from empire.server.core.config.config_manager import empire_config
from empire.server.core.db import models

database_config = empire_config.database.defaults

log = logging.getLogger(__name__)


def get_default_hashed_password():
    pwd_bytes = database_config.password.encode("utf-8")
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(pwd_bytes, salt).decode("utf-8")


def get_default_user():
    return models.User(
        username=database_config.username,
        hashed_password=get_default_hashed_password(),
        enabled=True,
        admin=True,
    )


def get_default_config():
    return models.Config(
        staging_key=get_staging_key(),
        jwt_secret_key=secrets.token_hex(16),
        ip_filtering=True,
    )


def get_default_keyword_obfuscation():
    keyword_obfuscation_list = database_config.keyword_obfuscation
    obfuscated_keywords = []
    for value in keyword_obfuscation_list:
        obfuscated_keywords.append(
            models.Keyword(
                keyword=value,
                replacement="".join(
                    random.choice(string.ascii_uppercase + string.digits)
                    for _ in range(5)
                ),
            )
        )
    return obfuscated_keywords


def get_default_obfuscation_config():
    obfuscation_config_list = database_config.obfuscation
    obfuscation_configs = []

    for config in obfuscation_config_list:
        obfuscation_configs.append(
            models.ObfuscationConfig(
                language=config.language,
                command=config.command,
                module=config.module,
                enabled=config.enabled,
                preobfuscatable=config.preobfuscatable,
            )
        )

    return obfuscation_configs


def get_default_ips():
    allows = database_config.ip_allow_list
    denies = database_config.ip_deny_list
    ips = []

    for ip in allows:
        ips.append(models.IP(ip_address=ip, list="allow"))

    for ip in denies:
        ips.append(models.IP(ip_address=ip, list="deny"))

    return ips


def get_staging_key():
    expected_length = 32

    # Staging Key is set up via environmental variable or config.yaml.
    staging_key = os.getenv("STAGING_KEY") or database_config.staging_key
    valid_chars = string.ascii_letters + string.digits

    if not staging_key:
        log.info("Generating random staging key")
        return "".join(random.choices(valid_chars, k=expected_length))

    log.info("Using preset staging key")

    # Validate provided staging key
    if not all(c in valid_chars for c in staging_key):
        log.error("Invalid staging key: contains unsupported characters")
        raise ValueError(
            "Staging key must only contain letters (A-Z, a-z) and numbers (0-9)"
        )

    if len(staging_key) != expected_length:
        log.error("Invalid staging key: must be exactly 32 characters long")
        raise ValueError("Staging key must be exactly 32 characters long")

    log.info(f"Using configured staging key: {staging_key}")
    return staging_key
