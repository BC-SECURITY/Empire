from pathlib import Path

from empire.server.common import helpers
from empire.server.core.config import config_manager
from empire.server.core.exceptions import ModuleValidationException
from empire.server.utils.file_util import resolve_under_root


def handle_validate_message(
    msg: str = "", print_to_server: bool = True
) -> tuple[bool, str]:
    """
    Given a reason for a module execution error, print to server and return the message as a tuple back to
    the modules.py handler to send to the client
    :param msg: the msg to print
    :param print_to_server: whether the msg should print to the server
    :return: tuple of None, str
    """
    if print_to_server:
        print(helpers.color(msg))
    return False, msg


def write_module_outfile(out_file: str, script: str) -> Path:
    """Write ``script`` to an operator-named ``OutFile`` under a server-owned root.

    ``OutFile`` is a delivery destination the operator goes and collects from, so an
    escaping value is rejected outright rather than quietly rewritten -- an operator
    who is silently redirected has no way to find what they asked for.

    The containment check runs before the ``mkdir``, not just before the write --
    creating the directory tree is itself a filesystem side effect on operator input.

    Returns the resolved path so the caller can name it in its success notice; after
    confinement that notice is the operator's only pointer to where the file landed.
    """
    # Resolve the singleton per call: config/data_manager.py rebinds
    # config_manager.empire_config, and this module is cached in sys.modules, so a
    # name bound at import time would freeze a stale config.
    root = config_manager.empire_config.directories.downloads / "generated-modules"
    out_path = resolve_under_root(root, out_file)
    if out_path is None:
        raise ModuleValidationException(
            f"OutFile must name a file under {root}: give a path relative to it, "
            f"or an absolute path already inside it."
        )

    try:
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(script)
    except OSError as e:
        # Confined but unwritable (a component already taken by a regular file,
        # EACCES, ENOSPC). ModuleValidationException is the only channel that
        # reaches the operator as a 4xx; anything else is an opaque 500. Never echo
        # the errno text -- it reaches the caller and is a filesystem-probe oracle.
        raise ModuleValidationException(f"Could not write OutFile under {root}.") from e

    return out_path
