import logging
import sys
from logging.handlers import RotatingFileHandler
from unittest.mock import MagicMock

import pytest
from pydantic import ValidationError

from empire.test.conftest import DEFAULT_ARGV, SERVER_CONFIG_LOC, load_test_config

DEFAULT_MAX_BYTES = 10 * 1024 * 1024
DEFAULT_BACKUP_COUNT = 5
# Small cap so the rotation tests write past it in a few dozen records.
ROTATION_CAP = 1024


@pytest.fixture(autouse=True)
def log_dir(monkeypatch, tmp_path):
    """Keep log files out of the shared data dir and restore the root logger after each test."""
    from empire.server.core.config import config_manager

    monkeypatch.setattr(config_manager, "DATA_DIR", tmp_path)
    # An operator's environment must not flip the config these tests build.
    for name in (
        "FILE_LOGGING",
        "MAX_BYTES",
        "BACKUP_COUNT",
        "LEVEL",
        "SIMPLE_CONSOLE",
    ):
        monkeypatch.delenv(f"EMPIRE_LOGGING__{name}", raising=False)
    root = logging.getLogger()
    saved_handlers, saved_level = root.handlers[:], root.level
    yield tmp_path
    for handler in root.handlers:
        if handler not in saved_handlers:
            handler.close()
    root.handlers[:] = saved_handlers
    root.setLevel(saved_level)


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

    args = arguments.parent_parser.parse_args()  # Force reparse of args between runs
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

    args = arguments.parent_parser.parse_args()  # Force reparse of args between runs
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

    args = arguments.parent_parser.parse_args()  # Force reparse of args between runs
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

    args = arguments.parent_parser.parse_args()  # Force reparse of args between runs
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

    args = arguments.parent_parser.parse_args()  # Force reparse of args between runs
    setup_logging(args)

    assert logging.getLogger().level == logging.DEBUG


def _config(**logging_overrides):
    from empire.server.core.config.config_manager import EmpireConfig

    test_config = load_test_config()
    test_config["logging"].update(logging_overrides)
    return EmpireConfig(test_config)


def _setup_logging(config=None):
    """Run setup_logging against the test config and return the root logger."""
    logging.getLogger().handlers.clear()
    sys.argv = list(DEFAULT_ARGV)

    from empire import arguments
    from empire.server.utils.log_util import setup_logging

    args = arguments.parent_parser.parse_args()  # Force reparse of args between runs
    setup_logging(args, override_config=config)
    return logging.getLogger()


def _handlers(logger, cls):
    return [h for h in logger.handlers if type(h) is cls]


def test_logging_config_defaults():
    from empire.server.core.config.config_manager import LoggingConfig

    config = LoggingConfig()

    assert config.file_logging is True
    assert config.max_bytes == DEFAULT_MAX_BYTES
    assert config.backup_count == DEFAULT_BACKUP_COUNT


@pytest.mark.parametrize("field", ["max_bytes", "backup_count"])
def test_logging_config_rejects_negative_limits(field):
    from empire.server.core.config.config_manager import LoggingConfig

    with pytest.raises(ValidationError):
        LoggingConfig(**{field: -1})


def test_logging_file_logging_env_var_overrides_yaml(monkeypatch):
    monkeypatch.setenv("EMPIRE_LOGGING__FILE_LOGGING", "false")

    config = _config(file_logging=True)

    assert config.logging.file_logging is False


def test_root_file_handler_rotates_with_defaults():
    from empire.server.utils.log_util import LOG_FORMAT

    config = _config()
    root = _setup_logging(config)

    (handler,) = [h for h in root.handlers if isinstance(h, logging.FileHandler)]
    assert type(handler) is RotatingFileHandler
    assert handler.maxBytes == config.logging.max_bytes
    assert handler.backupCount == config.logging.backup_count
    assert handler.formatter._fmt == LOG_FORMAT
    assert handler.baseFilename.endswith("empire_server.log")


def test_root_file_handler_honors_custom_limits():
    max_bytes = 1024
    backup_count = 2
    root = _setup_logging(_config(max_bytes=max_bytes, backup_count=backup_count))

    (handler,) = _handlers(root, RotatingFileHandler)
    assert handler.maxBytes == max_bytes
    assert handler.backupCount == backup_count


def _write_past_cap(log_dir, max_bytes, backup_count, records=50):
    """Log past the cap; return the log file names and whether the stream was reopened."""
    root = _setup_logging(_config(max_bytes=max_bytes, backup_count=backup_count))
    (handler,) = _handlers(root, RotatingFileHandler)
    stream = handler.stream
    log = logging.getLogger("empire.test.rotation")
    for _ in range(records):
        log.warning("x" * 100)
    names = sorted(p.name for p in (log_dir / "logs").iterdir())
    return names, handler.stream is not stream


def test_root_log_rotates_on_disk(log_dir):
    names, _ = _write_past_cap(log_dir, ROTATION_CAP, backup_count=2)

    assert names == ["empire_server.log", "empire_server.log.1", "empire_server.log.2"]
    for name in names:
        assert (log_dir / "logs" / name).stat().st_size <= ROTATION_CAP


@pytest.mark.parametrize(
    ("max_bytes", "backup_count"), [(0, DEFAULT_BACKUP_COUNT), (ROTATION_CAP, 0)]
)
def test_root_log_unbounded_when_rotation_disabled(log_dir, max_bytes, backup_count):
    names, reopened = _write_past_cap(log_dir, max_bytes, backup_count)

    assert names == ["empire_server.log"]
    # With a cap but no backups the stdlib would reopen the file on every record.
    assert not reopened
    assert (log_dir / "logs" / "empire_server.log").stat().st_size > ROTATION_CAP


def test_file_logging_off_attaches_no_file_handler_and_no_log_dir(log_dir):
    root = _setup_logging(_config(file_logging=False))

    assert [h for h in root.handlers if isinstance(h, logging.FileHandler)] == []
    assert len(_handlers(root, logging.StreamHandler)) == 1
    assert not (log_dir / "logs").exists()


def test_listener_logger_with_file_logging_on(monkeypatch):
    from empire.server.utils import log_util

    # Non-default limits, so a listener that ignored the config would fail.
    config = _config(file_logging=True, max_bytes=ROTATION_CAP, backup_count=2)
    monkeypatch.setattr(log_util, "empire_config", config)
    # Start from a fresh logger even if an earlier test configured this name.
    for handler in logging.getLogger("empire.listener.test_on").handlers:
        handler.close()
    logging.getLogger("empire.listener.test_on").handlers.clear()

    log = log_util.get_listener_logger("empire.listener", "test_on")
    try:
        # A second call must hit the early return and not stack handlers.
        log_util.get_listener_logger("empire.listener", "test_on")
        assert log.propagate is False
        file_handler, stream_handler = log.handlers
        assert type(file_handler) is RotatingFileHandler
        assert file_handler.level == logging.DEBUG
        assert file_handler.maxBytes == config.logging.max_bytes
        assert file_handler.backupCount == config.logging.backup_count
        assert file_handler.baseFilename.endswith("listener_test_on.log")
        assert type(stream_handler) is logging.StreamHandler
        assert stream_handler.level == logging.WARNING
    finally:
        for handler in log.handlers:
            handler.close()
        log.handlers.clear()
        log.propagate = True


def test_listener_logger_with_file_logging_off_keeps_warning_console_only(
    monkeypatch, caplog, capsys, log_dir
):
    from empire.server.utils import log_util

    monkeypatch.setattr(log_util, "empire_config", _config(file_logging=False))

    log = log_util.get_listener_logger("empire.listener", "test_off")
    try:
        # A second call must hit the early return and not stack handlers.
        log_util.get_listener_logger("empire.listener", "test_off")
        (stream_handler,) = log.handlers
        assert type(stream_handler) is logging.StreamHandler
        assert stream_handler.level == logging.WARNING
        assert log.propagate is False
        assert not (log_dir / "logs").exists()

        with caplog.at_level(logging.DEBUG):
            log.info("listener info line")
            log.warning("listener warning line")

        # Nothing reaches the root (server console), and only the warning
        # reaches the listener's own console handler.
        assert [r for r in caplog.records if r.name == log.name] == []
        err = capsys.readouterr().err
        assert "listener warning line" in err
        assert "listener info line" not in err
    finally:
        for handler in log.handlers:
            handler.close()
        log.handlers.clear()
        log.propagate = True
