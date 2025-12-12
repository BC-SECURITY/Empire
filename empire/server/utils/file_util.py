import logging
import os
import subprocess

log = logging.getLogger(__name__)


def run_as_user(  # noqa: PLR0913
    command, user=None, cwd=None, capture_output=False, check=True, text=True
):
    """
    Runs a command as a specified user or the user who invoked sudo.
    If no user is specified and the script is not run with sudo, it runs as the current user.

    Args:
        command (list): The command to run, specified as a list of strings.
        user (str, optional): The username to run the command as. Defaults to None.
        cwd (str, optional): The working directory for the command. Defaults to None.
        capture_output (bool, optional): Whether to capture and return the command's output. Defaults to False.

    Returns:
        str or None: The output of the command if capture_output is True, otherwise None.
    """
    try:
        if user is None:
            user = os.getenv("SUDO_USER")

        # Avoid sudo if target user is root or empty (typical in containers)
        if user in (None, "", "root"):
            command_with_user = command
        else:
            # Preserve env (-E) so SSH_AUTH_SOCK / GIT_SSH_COMMAND are available
            command_with_user = ["sudo", "-E", "-u", user, *command]

        result = subprocess.run(
            command_with_user,
            check=check,
            cwd=cwd,
            text=text,
            capture_output=capture_output,
        )

        log.debug("Command executed successfully: %s", " ".join(map(str, command)))

        if capture_output:
            return result.stdout.strip()
        return None

    except subprocess.CalledProcessError as e:
        log.error("Failed to execute command: %s", e, exc_info=True)
        log.error(
            "Try running the command manually: %s", " ".join([str(c) for c in command])
        )
        if e.stdout:
            log.error("Command output: %s", e.stdout)
        if e.stderr:
            log.error("Command error output: %s", e.stderr)
        raise
