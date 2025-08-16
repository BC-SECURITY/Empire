import logging
import sys
from unittest.mock import MagicMock

from empire.test.conftest import SERVER_CONFIG_LOC, load_test_config


def test_simple_log_format(monkeypatch):
    logging.getLogger().handlers.clear()
    sys.argv = ["", "server", "--config", SERVER_CONFIG_LOC]

    monkeypatch.setattr("empire.server.server.empire", MagicMock())

    from empire import arguments
    from empire.server.utils.log_util import (
        SIMPLE_LOG_FORMAT,
        ColorFormatter,
        setup_logging,
    )

    args = arguments.parse_args()  # Force reparse of args between runs
    setup_logging(args)

    stream_handler = next(
        filter(
            lambda h: type(h) == logging.StreamHandler,  # noqa: E721
            logging.getLogger().handlers,
        )
    )

    assert isinstance(stream_handler.formatter, ColorFormatter)
    assert stream_handler.formatter._fmt == SIMPLE_LOG_FORMAT


def test_extended_log_format(monkeypatch):
    logging.getLogger().handlers.clear()
    sys.argv = ["", "server", "--config", SERVER_CONFIG_LOC]

    from empire import arguments
    from empire.server.core.config.config_manager import EmpireConfig
    from empire.server.utils.log_util import LOG_FORMAT, ColorFormatter, setup_logging

    test_config = load_test_config()
    test_config["logging"]["simple_console"] = False
    modified_config = EmpireConfig(test_config)

    args = arguments.parse_args()  # Force reparse of args between runs
    setup_logging(args, override_config=modified_config)

    stream_handler = next(
        filter(
            lambda h: type(h) == logging.StreamHandler,  # noqa: E721
            logging.getLogger().handlers,
        )
    )

    assert isinstance(stream_handler.formatter, ColorFormatter)
    assert stream_handler.formatter._fmt == LOG_FORMAT


def test_log_level_by_config(monkeypatch):
    logging.getLogger().handlers.clear()
    sys.argv = ["", "server", "--config", SERVER_CONFIG_LOC]

    from empire import arguments
    from empire.server.core.config.config_manager import EmpireConfig
    from empire.server.utils.log_util import setup_logging

    test_config = load_test_config()
    test_config["logging"]["level"] = "WaRNiNG"  # case-insensitive
    modified_config = EmpireConfig(test_config)

    args = arguments.parse_args()  # Force reparse of args between runs
    setup_logging(args, override_config=modified_config)

    stream_handler = next(
        filter(
            lambda h: type(h) == logging.StreamHandler,  # noqa: E721
            logging.getLogger().handlers,
        )
    )

    assert stream_handler.level == logging.WARNING


def test_log_level_by_arg():
    logging.getLogger().handlers.clear()
    sys.argv = [
        "",
        "server",
        "--config",
        SERVER_CONFIG_LOC,
        "--log-level",
        "ERROR",
    ]

    from empire import arguments
    from empire.server.utils.log_util import setup_logging

    config_mock = MagicMock()
    test_config = load_test_config()
    test_config["logging"]["level"] = "WaRNiNG"  # Should be overwritten by arg
    config_mock.yaml = test_config

    args = arguments.parse_args()  # Force reparse of args between runs
    setup_logging(args)

    stream_handler = next(
        filter(
            lambda h: type(h) == logging.StreamHandler,  # noqa: E721
            logging.getLogger().handlers,
        )
    )

    assert stream_handler.level == logging.ERROR


def test_log_level_by_debug_arg():
    logging.getLogger().handlers.clear()
    sys.argv = ["", "server", "--config", SERVER_CONFIG_LOC, "--debug"]

    from empire import arguments
    from empire.server.utils.log_util import setup_logging

    config_mock = MagicMock()
    test_config = load_test_config()
    test_config["logging"]["level"] = "WaRNiNG"  # Should be overwritten by arg
    config_mock.yaml = test_config

    args = arguments.parse_args()  # Force reparse of args between runs
    setup_logging(args)

    assert logging.getLogger().level == logging.DEBUG
