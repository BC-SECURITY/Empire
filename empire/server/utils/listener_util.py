import logging
import secrets
from pathlib import Path
from textwrap import dedent

from flask import request

from empire.server.common import helpers
from empire.server.core.exceptions import ModuleExecutionException
from empire.server.utils.file_util import remove_stager_artifact

log = logging.getLogger(__name__)

BYTE_MAX = 255

# Attacker-controlled strings reach the instance log before anything has
# validated them. Cap them so an unauthenticated peer cannot write an
# arbitrarily long record (the instance log has no rotation) and strip the
# control characters that would otherwise forge additional log lines.
LOG_VALUE_MAX_LENGTH = 64


def sanitize_log_value(value, max_length=LOG_VALUE_MAX_LENGTH):
    """Render an untrusted request value safe to splice into a log line.

    Query strings and URL paths arrive percent-decoded, so a bare `%0a` in
    either forges a new record in a plain-text log. `!r` escapes the control
    characters and the length cap bounds what one request can append.
    """
    if value is None:
        return "None"
    text = str(value)
    if len(text) > max_length:
        text = text[:max_length] + "..."
    return repr(text)


def read_stager_artifact(path):
    """Read a freshly compiled stager and drop the temp file the compiler left behind.

    Cleanup is best-effort on purpose: the bytes are already in hand, and a
    compile that just succeeded must not be thrown away because the artifact
    could not be removed -- AV quarantine and a read-only tempdir both produce
    exactly that, and the caller cannot tell the difference from a build that
    produced nothing.

    An empty path is rejected explicitly. `stager_generation_service`'s
    `generate_launcher()` returns "" when the named listener exists in the DB
    but is not active and None when the launcher came back empty; `Path("")`
    is `Path(".")`, so without this guard those cases surface as a bare
    `IsADirectoryError`/`TypeError` from the middle of a read.
    """
    if not path:
        msg = (
            "read_stager_artifact(): the stager producer returned no path "
            "(listener inactive, or the build produced nothing)"
        )
        log.error(msg)
        raise ModuleExecutionException(msg)

    artifact = Path(path)
    data = artifact.read_bytes()
    remove_stager_artifact(artifact)
    return data


def register_default_response_error_handler(app, listener, status_code):
    """Serve the listener's default response for anything that escapes a view.

    Flask's stock 500 page is the loudest tell a listener has: any peer that
    can provoke a traceback learns the box is not what the profile claims.
    Compiled-stager requests raise for ordinary reasons (no EmpireCompiler
    downloaded, no Go toolchain), so this cannot be handled by validating
    input.

    The repr plus the innermost frame, not a full traceback: an
    unauthenticated peer picks how often this fires and the instance log has
    no rotation, but a bare repr would leave a bug in view code with no file
    and no line anywhere in the logs -- this handler suppresses the only
    traceback Flask would otherwise have produced.

    `listener` is passed rather than its log so the handler reads
    `instance_log` at call time; `start_server()` rebinds it after the app is
    built, and tests swap it per case. The name is read live for the same
    reason: the value in scope at `start_server()` is a deep copy of the
    options taken at boot, so an operator renaming a running listener would
    leave every error record filed under the old name while the INFO records
    beside it use the new one.
    """

    @app.errorhandler(Exception)
    def handle_unexpected_error(e):
        # Errors raised outside a view (before_request/after_request) arrive
        # wrapped in a synthetic InternalServerError whose repr names nothing
        # useful; unwrap to the real cause.
        cause = getattr(e, "original_exception", None) or e
        location = ""
        tb = cause.__traceback__
        if tb:
            # Walk to the innermost frame directly. traceback.extract_tb()
            # would build a FrameSummary for the whole stack and hit linecache
            # for each one -- per-frame stat() and source reads on a path an
            # unauthenticated peer can fire at will.
            while tb.tb_next:
                tb = tb.tb_next
            location = f" at {tb.tb_frame.f_code.co_filename}:{tb.tb_lineno}"
        listener.instance_log.error(
            f"{listener.options['Name']['Value']}: error serving "
            f"{sanitize_log_value(request.path, 256)}: {cause!r}{location}"
        )
        return app.response_class(listener.default_response(), status_code)


def remove_lines_comments(lines):
    """
    Remove lines comments.
    """
    code = ""
    for line in lines.split("\n"):
        _line = line.strip()
        # skip commented line
        if not _line.startswith("#"):
            code += _line
    return code


def looks_like_decimal_blob(b: bytes) -> bool:
    """
    Heuristic: returns True if b decodes as ASCII and contains only digits and
    common separators (space, comma, brackets, newlines, minus).
    """
    if not isinstance(b, bytes):
        return False
    try:
        s = bytes(b).decode("ascii")
    except UnicodeDecodeError:
        return False
    if not any(ch.isdigit() for ch in s):  # must contain at least one digit
        return False
    allowed = set("0123456789- \t\r\n,;[]()")
    return all(ch in allowed for ch in s)


def decimals_to_bytes(x):
    """Convert '237 30 211 ...' (bytes or str) into real bytes."""
    if isinstance(x, bytes):
        x = bytes(x).decode("ascii")
    # normalize separators
    for c in ",;[]()\t\r\n":
        x = x.replace(c, " ")
    vals = [int(tok) for tok in x.split() if tok]
    if not vals:
        raise ValueError("No integers found")
    if any(v < 0 or v > BYTE_MAX for v in vals):
        bad = [v for v in vals if v < 0 or v > BYTE_MAX][:5]
        raise ValueError(f"Out-of-range byte(s): {bad} (expected 0..255)")
    return bytes(vals)


def ensure_raw_bytes(x):
    """
    Helper function for malleable listener where encoding may not be consistent.
    If x looks like a decimal blob, convert it to raw bytes.
    """
    return decimals_to_bytes(x) if looks_like_decimal_blob(x) else bytes(x)


def python_extract_stager(staging_key):
    """
    Download the stager and extract the IV for Python agent.
    """
    stager = dedent(
        """
    exec(data);
    """
    )
    return helpers.strip_python_comments(stager)


def generate_random_cipher():
    """
    Return FIPS-approved TLS 1.2 cipher suites (AEAD + forward secrecy)
    in randomized order for JA3 evasion. Both suites are included so
    OpenSSL can negotiate even if one is unavailable on the platform.
    """
    ciphers = [
        "ECDHE-RSA-AES256-GCM-SHA384",
        "ECDHE-RSA-AES128-GCM-SHA256",
    ]
    shuffled = secrets.SystemRandom().sample(ciphers, len(ciphers))
    return ":".join(shuffled)
