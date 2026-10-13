import logging
from logging.handlers import RotatingFileHandler

from empire.server.core.config import config_manager
from empire.server.core.config.config_manager import LoggingConfig, empire_config

LOG_FORMAT = "%(asctime)s [%(filename)s:%(lineno)d] [%(levelname)s]: %(message)s "
SIMPLE_LOG_FORMAT = "[%(levelname)s]: %(message)s "


class ColorFormatter(logging.Formatter):
    def __init__(self, fmt=None, datefmt=None, style="%", validate=True):
        grey = "\x1b[38;1m"
        blue = "\x1b[34;1m"
        yellow = "\x1b[33;1m"
        red = "\x1b[31;1m"
        reset = "\x1b[0m"

        self.FORMATS = {
            logging.DEBUG: grey + fmt + reset,
            logging.INFO: blue + fmt + reset,
            logging.WARNING: yellow + fmt + reset,
            logging.ERROR: red + fmt + reset,
            logging.CRITICAL: red + fmt + reset,
        }
        super().__init__(fmt, datefmt, style, validate)

    def format(self, record):
        log_fmt = self.FORMATS.get(record.levelno)
        formatter = logging.Formatter(log_fmt)
        return formatter.format(record)


def get_log_dir():
    log_dir = config_manager.DATA_DIR / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    return log_dir


def _file_handler(
    file_name: str, logging_config: LoggingConfig
) -> RotatingFileHandler | None:
    """Rotating handler for ``<data-dir>/logs/<file_name>``, or None if file logging is off."""
    if not logging_config.file_logging:
        return None
    # The stdlib only checks maxBytes before rolling over, so a cap with no backups
    # would reopen the file on every record past the cap. Either zero means unbounded.
    max_bytes = logging_config.max_bytes if logging_config.backup_count else 0
    # get_log_dir() creates the directory, so only call it when we will write to it.
    handler = RotatingFileHandler(
        get_log_dir() / file_name,
        maxBytes=max_bytes,
        backupCount=logging_config.backup_count,
    )
    handler.setFormatter(logging.Formatter(LOG_FORMAT))
    return handler


def get_listener_logger(log_name_prefix: str, listener_name: str):
    log = logging.getLogger(f"{log_name_prefix}.{listener_name}")

    # return if already initialized
    if log.handlers:
        return log

    log.propagate = False

    # With file logging off the listener keeps only its WARNING console handler:
    # propagating would put per-request INFO lines, including raw session
    # cookies, on the server console.
    listener_log_file_handler = _file_handler(
        f"listener_{listener_name}.log", empire_config.logging
    )
    if listener_log_file_handler is not None:
        listener_log_file_handler.setLevel(logging.DEBUG)
        log.addHandler(listener_log_file_handler)

    listener_stream_handler = logging.StreamHandler()
    listener_stream_handler.setLevel(logging.WARNING)
    simple_console = empire_config.logging.simple_console
    stream_format = SIMPLE_LOG_FORMAT if simple_console else LOG_FORMAT
    listener_stream_handler.setFormatter(ColorFormatter(stream_format))
    log.addHandler(listener_stream_handler)

    return log


def setup_logging(args, override_config=None):
    config = override_config or empire_config
    if args.log_level:
        log_level = logging.getLevelName(args.log_level.upper())
    else:
        log_level = logging.getLevelName(config.logging.level.upper())

    root_logger = logging.getLogger()
    # If this isn't set to DEBUG, then we won't see debug messages from the listeners.
    root_logger.setLevel(logging.DEBUG)

    root_logger_file_handler = _file_handler("empire_server.log", config.logging)
    if root_logger_file_handler is not None:
        root_logger.addHandler(root_logger_file_handler)

    simple_console = config.logging.simple_console
    stream_format = SIMPLE_LOG_FORMAT if simple_console else LOG_FORMAT
    root_logger_stream_handler = logging.StreamHandler()
    root_logger_stream_handler.setFormatter(ColorFormatter(stream_format))
    root_logger_stream_handler.setLevel(log_level)
    root_logger.addHandler(root_logger_stream_handler)
