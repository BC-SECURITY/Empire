import logging
import os
import shutil
import subprocess

log = logging.getLogger(__name__)


def remove_dir_contents(path: str) -> None:
    """
    Removes all files and directories in a directory.
    Keeps the .keep and .gitignore that reserve the directory.
    """
    for root, dirs, files in os.walk(path):
        for f in files:
            if f.endswith(".keep") or f.endswith(".gitignore"):
                continue
            os.unlink(os.path.join(root, f))
        for d in dirs:
            shutil.rmtree(os.path.join(root, d))


def remove_file(path: str) -> None:
    """
    Removes a file. If the file doesn't exist, nothing happens.
    """
    if os.path.exists(path):
        os.remove(path)


def run_command(command,  cwd=None):
    """
    Runs a command as current user.

    Args:
        command (list): The command to run, specified as a list of strings.
    """
    try:
        subprocess.run(command, check=True, cwd=cwd)

        log.debug("Command executed successfully: %s", " ".join(map(str, command)))

    except subprocess.CalledProcessError as e:
        # Log the error details
        log.error("Failed to execute command: %s", e, exc_info=True)
        log.error("Try running the command manually: %s", " ".join(command))
