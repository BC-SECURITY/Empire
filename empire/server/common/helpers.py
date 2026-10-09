"""

Misc. helper functions used in Empire.

Includes:

    validate_ip() - validate an IP
    validate_ntlm() - checks if the passed string is an NTLM hash
    random_string() - returns a random string of the specified number of characters
    chunks() - used to split a string into chunks
    strip_python_comments() - strips Python newlines and comments
    enc_powershell() - encodes a PowerShell command into a form usable by powershell.exe -enc ...
    powershell_launcher() - builds a command line powershell.exe launcher
    parse_powershell_script() - parses a raw PowerShell file and return the function names
    strip_powershell_comments() - strips PowerShell newlines and comments
    get_powerview_psreflect_overhead() - extracts some of the psreflect overhead for PowerView
    get_dependent_functions() - extracts function dependenies from a PowerShell script
    find_all_dependent_functions() - takes a PowerShell script and a set of functions, and returns all dependencies
    generate_dynamic_powershell_script() - takes a PowerShell script and set of functions and returns a minimized script
    get_config() - pulls config information from the database output of normal menu execution
    get_listener_options() - gets listener options outside of normal menu execution
    get_datetime() - returns the current date time in a standard format
    get_file_datetime() - returns the current date time in a format savable to a file
    get_file_size() - returns a string representing file size
    lhost() - returns the local IP
    color() - used for colorizing output in the Linux terminal
    unique() - uniquifies a list, order preserving
    uniquify_tuples() - uniquifies Mimikatz tuples based on the password
    decode_base64() - tries to base64 decode a string
    encode_base64() - tries to base64 encode a string
    complete_path() - helper to tab-complete file paths
    dict_factory() - helper that returns the SQLite query results as a dictionary
    KThread() - a subclass of threading.Thread, with a kill() method
"""

import base64
import binascii
import functools
import ipaddress
import logging
import re
import secrets
import socket
import string
import sys
import threading
from datetime import datetime
from urllib.parse import urlsplit

import click

log = logging.getLogger(__name__)


###############################################################
#
# Global Variables
#
################################################################

globentropy = secrets.randbelow(datetime.today().day) + 1
globDebug = False


###############################################################
#
# Validation methods
#
###############################################################


def validate_ip(IP):
    """
    Validate an IP.
    """
    try:
        ipaddress.ip_address(IP)
    except Exception:
        return False
    else:
        return True


# A DNS/IDN name or IPv4 address, or the inside of a bracketed IPv6 literal.
_HTTP_HOSTNAME_RE = re.compile(r"[\w.-]+|[0-9a-f:.]+")


def normalize_http_host(raw: str) -> str | None:
    """Return ``scheme://host`` for a bare host or an http(s) URL, else None.

    Rejects userinfo, a port, a path, a query, or a fragment, and any
    whitespace or control character. The returned base is rebuilt from the
    parsed scheme and netloc, so the value that was validated is the value the
    caller emits: urlsplit silently drops tab, newline, and leading control
    characters, so validating the parsed host but emitting the raw string would
    let those through. Non-ASCII letters are kept so an IDN host still works.
    """
    if "://" not in raw:
        raw = "http://" + raw
    # Every whitespace character except the ASCII space is non-printable, so
    # this pair rejects the characters urlsplit would otherwise strip.
    if " " in raw or not raw.isprintable():
        return None
    try:
        parts = urlsplit(raw)
    except ValueError:  # e.g. an unclosed IPv6 bracket
        return None
    hostname = parts.hostname or ""
    # Comparing netloc to the bare hostname rejects userinfo, a port, and a
    # trailing ':' in one check; urlsplit lowercases hostname, so lower netloc.
    expected_netloc = f"[{hostname}]" if ":" in hostname else hostname
    if (
        parts.scheme not in ("http", "https")
        or parts.netloc.lower() != expected_netloc
        or parts.path
        or parts.query
        or parts.fragment
        or _HTTP_HOSTNAME_RE.fullmatch(hostname) is None
        or hostname.strip(".") == ""
    ):
        return None
    return f"{parts.scheme}://{parts.netloc}"


def validate_ntlm(data):
    """
    Checks if the passed string is an NTLM hash.
    """
    allowed = re.compile("^[0-9a-f]{32}", re.IGNORECASE)
    return bool(allowed.match(data))


####################################################################################
#
# Randomizers/obfuscators
#
####################################################################################
def random_string(length=-1, charset=string.ascii_letters):
    """
    Returns a random string of "length" characters.
    If no length is specified, resulting string is in between 6 and 15 characters.
    A character set can be specified, defaulting to just alpha letters.
    """
    if length == -1:
        length = secrets.choice(range(6, 16))
    return "".join(secrets.choice(charset) for _ in range(length))


def obfuscate_call_home_address(data):
    """
    Poowershell script to base64 encode variable contents and execute on command as if clear text in powershell
    """
    tmp = "$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('"
    tmp += (enc_powershell(data)).decode("UTF-8") + "')))"
    return tmp


def chunks(s, n):
    """
    Generator to split a string s into chunks of size n.
    Used by macro modules.
    """
    for i in range(0, len(s), n):
        yield s[i : i + n]


####################################################################################
#
# Python-specific helpers
#
####################################################################################


def strip_python_comments(data):
    """
    *** DECEMBER 2017 - DEPRECATED, PLEASE DO NOT USE ***

    Strip block comments, line comments, empty lines, verbose statements, docstring,
    and debug statements from a Python source file.
    """
    log.warning("strip_python_comments is deprecated and should not be used")

    # remove docstrings
    data = re.sub(r'"(?<!= )""".*?"""', "", data, flags=re.DOTALL)
    data = re.sub(r"(?<!= )'''.*?'''", "", data, flags=re.DOTALL)

    # remove comments
    lines = data.split("\n")
    strippedLines = [
        line
        for line in lines
        if ((not line.strip().startswith("#")) and (line.strip() != ""))
    ]
    return "\n".join(strippedLines)


####################################################################################
#
# PowerShell-specific helpers
#
####################################################################################


def enc_powershell(raw):
    """
    Encode a PowerShell command into a form usable by powershell.exe -enc ...
    """
    return base64.b64encode(raw.encode("UTF-16LE"))
    # tmp = raw
    # tmp = bytes("".join([str(char) + "\x00" for char in raw]), "UTF-16LE")
    # tmp = base64.b64encode(tmp)


def powershell_launcher(raw, modifiable_launcher):
    """
    Build a one line PowerShell launcher with an -enc command.
    """
    # encode the data into a form usable by -enc
    encCMD = enc_powershell(raw)

    return modifiable_launcher + " " + encCMD.decode("UTF-8")


def parse_powershell_script(data):
    """
    Parse a raw PowerShell file and return the function names.
    """
    p = re.compile("function(.*){")
    return [x.strip() for x in p.findall(data)]


def strip_powershell_comments(data):
    """
    Strip block comments, line comments, empty lines, verbose statements,
    and debug statements from a PowerShell source file.
    """

    # strip block comments
    strippedCode = re.sub(re.compile("<#.*?#>", re.DOTALL), "\n", data)

    # strip blank lines, lines starting with #, and verbose/debug statements
    return "\n".join(
        [
            line
            for line in strippedCode.split("\n")
            if (
                (line.strip() != "")
                and (not line.strip().startswith("#"))
                and (not line.strip().lower().startswith("write-verbose "))
                and (not line.strip().lower().startswith("write-debug "))
            )
        ]
    )


####################################################################################
#
# PowerView dynamic generation helpers
#
####################################################################################


def get_powerview_psreflect_overhead(script):
    """
    Helper to extract some of the psreflect overhead for PowerView/PowerUp.
    """

    if "PowerUp" in script[0:100]:
        pattern = re.compile(r"\n\$Module =.*\[\'kernel32\'\]", re.DOTALL)
    else:
        # otherwise extracting from PowerView
        pattern = re.compile(r"\n\$Mod =.*\[\'wtsapi32\'\]", re.DOTALL)

    try:
        return strip_powershell_comments(pattern.findall(script)[0])
    except Exception:
        log.exception("Error extracting psreflect overhead from script!")
        return ""


_PSREFLECT_NAMESPACE_PATTERN = re.compile(
    r"\$Netapi32|\$Advapi32|\$Kernel32|\$Wtsapi32", re.IGNORECASE
)


def get_dependent_functions(code, functionNames, deps_pattern):
    """
    Helper that takes a chunk of PowerShell code and a set of function
    names and returns the unique function names referenced within the
    script block, in deterministic insertion order.

    ``deps_pattern`` is a precompiled alternation regex of all known
    function names (built once by ``_build_function_map``); a single
    findall pass over it replaces what used to be one ``re.search``
    per candidate name (~600 per call on PowerView).

    Returns a list (not a set) so that downstream concatenation order
    is stable across Python invocations; sets iterate in hash-
    randomized order (CPython randomizes the string-hash seed per
    process by default) and would make the generated script's byte
    sequence change between runs.
    """
    # Case-insensitive alternation: matches preserve original casing,
    # so normalize to the canonical case from functionNames. dict.fromkeys
    # dedupes while preserving first-match order.
    canonical = {n.lower(): n for n in functionNames}
    dependentFunctions = list(
        dict.fromkeys(
            canonical[m.lower()]
            for m in deps_pattern.findall(code)
            if m.lower() in canonical
        )
    )

    if _PSREFLECT_NAMESPACE_PATTERN.search(code):
        for psreflect_fn in (
            "New-InMemoryModule",
            "func",
            "Add-Win32Type",
            "psenum",
            "struct",
        ):
            if psreflect_fn not in dependentFunctions:
                dependentFunctions.append(psreflect_fn)

    return dependentFunctions


def find_all_dependent_functions(
    functions, functionsToProcess, deps_pattern, resultFunctions=None
):
    """
    Takes a dictionary of "[functionName] -> functionCode" and a set of functions
    to process, and recursively returns all nested functions that may be required.

    Used to map the dependent functions for nested script dependencies like in
    PowerView.

    ``deps_pattern`` is a precompiled alternation regex of all known
    function names (see ``_build_function_map``); it lets
    ``get_dependent_functions`` scan each code chunk in a single pass
    instead of running one regex per candidate name.
    """
    resultFunctions = [] if resultFunctions is None else resultFunctions
    if isinstance(functionsToProcess, str):
        functionsToProcess = [functionsToProcess]

    while len(functionsToProcess) != 0:
        # pop the next function to process off the stack
        requiredFunction = functionsToProcess.pop()

        if requiredFunction not in resultFunctions:
            resultFunctions.append(requiredFunction)

        # get the dependencies for the function we're currently processing
        try:
            functionDependencies = get_dependent_functions(
                functions[requiredFunction], functions.keys(), deps_pattern
            )
        except Exception:
            functionDependencies = []
            log.exception(
                f"Error in retrieving dependencies for function {requiredFunction} !"
            )

        for functionDependency in functionDependencies:
            if (
                functionDependency not in resultFunctions
                and functionDependency not in functionsToProcess
            ):
                # for each function dependency, if we haven't already seen it
                #   add it to the stack for processing
                functionsToProcess.append(functionDependency)
                resultFunctions.append(functionDependency)

        resultFunctions = find_all_dependent_functions(
            functions, functionsToProcess, deps_pattern, resultFunctions
        )

    return resultFunctions


_FUNCTION_PATTERN = re.compile(r"\n(?:function|filter).*?{.*?\n}\n", re.DOTALL)
_BLOCK_COMMENT_PATTERN = re.compile("<#.*?#>", re.DOTALL)
# PowerView keeps backward-compatible names as ``Set-Alias`` lines
# (e.g. ``Set-Alias Get-Proxy Get-WMIRegProxy``). These aren't function
# definitions, so the requested-name resolver below maps them onto the
# real target before the dependency walk.
_ALIAS_PATTERN = re.compile(r"^Set-Alias\s+(\S+)\s+(\S+)", re.MULTILINE)


@functools.lru_cache(maxsize=128)
def _build_function_map(
    script: str,
) -> tuple[str, dict[str, str], "re.Pattern[str]", dict[str, str], dict[str, str]]:
    """Strip block comments and parse the script into a name->code map.

    Returns ``(cleaned_script, name_to_code, deps_pattern, canonical,
    alias_map)`` where ``deps_pattern`` is a single precompiled regex of
    all known function names — used by ``get_dependent_functions`` to
    avoid the N-per-call recompile/research that dominated profiling
    (each call on PowerView ran ~600 regex searches per dep-walk step);
    ``canonical`` maps each lower-cased definition name onto its real
    key (for case-insensitive resolution); and ``alias_map`` maps each
    lower-cased ``Set-Alias`` name onto the real function it points at
    (e.g. ``get-proxy`` -> ``Get-WMIRegProxy``).

    Cached by ``functools.lru_cache(maxsize=128)`` keyed on the script
    string itself — most callers (notably the PowerView modules) pass
    identical 25k-line scripts, so without caching the regex parse
    runs N times for N modules. The bound prevents unbounded memory
    growth in long-running production servers, and the string-equality
    key avoids the (theoretical) hash-collision risk of hashing-based
    caches.
    """
    cleaned = _BLOCK_COMMENT_PATTERN.sub("", script)
    functions = {}
    for func_match in _FUNCTION_PATTERN.findall(cleaned):
        # ``split(None, 2)`` -> ['function', name, rest]; capped at two
        # splits so it stops at the name boundary without scanning the
        # whole body. The old ``[:40]`` slice truncated names longer
        # than 30 chars (the leading "\nfunction " eats 10), storing
        # them under a clipped key that could never be resolved.
        name = func_match.split(None, 2)[1]
        functions[name] = func_match

    if functions:
        # Sort by length desc so longer names match before shorter
        # prefixes (e.g. "Get-User2" before "Get-User").
        names = sorted(functions.keys(), key=len, reverse=True)
        alternation = "|".join(re.escape(n) for n in names)
        deps_pattern = re.compile(
            rf"[^A-Za-z']({alternation})[^A-Za-z']", re.IGNORECASE
        )
    else:
        deps_pattern = re.compile(r"$^")  # never matches

    # ``canonical`` maps every lower-cased definition name onto its real
    # key — used both to validate alias targets and to resolve a
    # case-mismatched requested name (see ``_resolve_function_name``).
    # Map backward-compat alias names onto their real target function;
    # only keep aliases whose target is an actual definition so the
    # dependency walk always lands on a real name_to_code key.
    canonical = {name.lower(): name for name in functions}
    alias_map = {}
    for alias, target in _ALIAS_PATTERN.findall(cleaned):
        real = canonical.get(target.lower())
        if real:
            alias_map[alias.lower()] = real

    return cleaned, functions, deps_pattern, canonical, alias_map


def _resolve_function_name(
    name: str,
    functions: dict[str, str],
    canonical: dict[str, str],
    alias_map: dict[str, str],
) -> tuple[str | None, bool]:
    """Map a requested function name onto a real definition key.

    Modules name the function to extract via the first token of their
    ``script_end``. That token may not match a ``function`` definition
    verbatim: it can differ only in case (the dep-walk dict is
    case-sensitive) or be a PowerView ``Set-Alias`` backward-compat name.

    Returns ``(real_key, via_alias)`` — ``real_key`` is the resolved
    ``name_to_code`` key (or ``None`` if nothing matches), and
    ``via_alias`` is True only when resolution went through ``alias_map``
    (a real function/case match takes precedence). The caller uses
    ``via_alias`` to decide whether to preserve the ``Set-Alias`` line.
    """
    if name in functions:
        return name, False
    lower = name.lower()
    real = canonical.get(lower)
    if real:
        return real, False
    alias_target = alias_map.get(lower)
    return alias_target, alias_target is not None


@functools.lru_cache(maxsize=512)
def _generate_dynamic_powershell_script_cached(
    script: str, function_names: tuple[str, ...]
) -> str:
    """Inner cached implementation of ``generate_dynamic_powershell_script``.

    Cached by ``(script, function_names)`` keys with a bounded LRU.
    Direct callers should use the public function below; this exists
    only to give lru_cache a hashable signature.
    """
    psreflect_functions = [
        "New-InMemoryModule",
        "func",
        "Add-Win32Type",
        "psenum",
        "struct",
    ]

    script, functions, deps_pattern, canonical, alias_map = _build_function_map(script)

    # recursively enumerate all possible function dependencies and
    #   start building the new result script
    function_dependencies = []
    alias_lines = []

    for functionName in function_names:
        resolved, via_alias = _resolve_function_name(
            functionName, functions, canonical, alias_map
        )
        if resolved is None:
            log.warning(
                "Requested function %s was not found in the script; skipping.",
                functionName,
            )
            continue

        if via_alias:
            # Preserve the alias so a script_end that invokes the
            # backward-compat name still resolves at agent runtime.
            alias_lines.append(f"Set-Alias {functionName} {resolved}")

        function_dependencies += find_all_dependent_functions(
            functions, resolved, deps_pattern
        )
        function_dependencies = unique(function_dependencies)

    new_script = ""
    for function_dependency in function_dependencies:
        try:
            new_script += functions[function_dependency] + "\n"
        except Exception:
            log.exception(f"Key error with function {function_dependency} !")

    # if any psreflect methods are needed, add in the overhead at the end
    if any(el in set(psreflect_functions) for el in function_dependencies):
        new_script += get_powerview_psreflect_overhead(script)

    # Emit any preserved aliases after their target definitions so the
    # alias resolves to an already-defined function at runtime.
    for alias_line in alias_lines:
        new_script += alias_line + "\n"

    return strip_powershell_comments(new_script) + "\n"


def generate_dynamic_powershell_script(script, function_names):
    """
    Takes a PowerShell script and a function name (or array of function names,
    generates a dictionary of "[functionNames] -> functionCode", and recursively
    maps all dependent functions for the specified function name.

    A script is returned with only the code necessary for the given
    functionName, stripped of comments and whitespace.

    Note: in practice this is only called with PowerView as the input
    script (see ``module_service.finalize_module`` and
    ``new_gpo_immediate_task``). The PSReflect-overhead detection and
    the hardcoded {New-InMemoryModule, func, Add-Win32Type, psenum,
    struct} fallback set in ``get_dependent_functions`` are PowerView-
    specific assumptions; a future caller passing a non-PowerView
    script would still work but wouldn't get the PSReflect handling.

    Output is memoized via a bounded LRU keyed on the (script,
    function_names) pair — the PowerView modules generate the same
    25k-line script through this function many times, and each call
    costs ~1s of regex + dependency-walk + comment stripping for an
    identical result.
    """
    if not isinstance(function_names, list):
        function_names = [function_names]
    return _generate_dynamic_powershell_script_cached(script, tuple(function_names))


###############################################################
#
# Miscellaneous methods (formatting, sorting, etc.)
#
###############################################################


def get_datetime():
    """
    Return the local current date/time
    """
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def get_file_datetime():
    """
    Return the current date/time in a format workable for a file name.
    """
    return datetime.now().strftime("%Y-%m-%d_%H-%M-%S")


def get_file_size(file):
    """
    Returns a string with the file size and highest rating.
    """
    byte_size = sys.getsizeof(file)
    kb_size = byte_size // 1024
    if kb_size == 0:
        return f"{byte_size} Bytes"
    mb_size = kb_size // 1024
    if mb_size == 0:
        return f"{kb_size} KB"
    gb_size = mb_size // 1024
    if gb_size == 0:
        return f"{mb_size} MB"
    return f"{gb_size} GB"


def lhost():
    """
    Return the local IP.
    """
    try:
        # Create a socket and connect to a remote server
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
    except Exception:
        ip = "127.0.0.1"
    return ip


def color(string, color=None):
    """
    Change text color for the Linux terminal.
    """
    color_map = {"red": "red", "green": "green", "yellow": "yellow", "blue": "blue"}
    prefix_map = {"[!]": "red", "[+]": "green", "[*]": "blue", "[>]": "yellow"}

    fg = None
    if color:
        fg = color_map.get(color.lower())
    else:
        stripped = string.strip()
        for prefix, prefix_color in prefix_map.items():
            if stripped.startswith(prefix):
                fg = prefix_color
                break
        else:
            return string

    return click.style(string, fg=fg, bold=True)


def unique(seq, idfun=None):
    """
    Uniquifies a list, order preserving.

    from http://www.peterbe.com/plog/uniqifiers-benchmark
    """
    if idfun is None:

        def idfun(x):
            return x

    seen = {}
    result = []
    for item in seq:
        marker = idfun(item)
        # in old Python versions:
        # if seen.has_key(marker)
        # but in new ones:
        if marker in seen:
            continue
        seen[marker] = 1
        result.append(item)
    return result


def uniquify_tuples(tuples):
    """
    Uniquifies Mimikatz tuples based on the password.

    cred format- (credType, domain, username, password, hostname, sid)
    """
    seen = set()
    return [
        item
        for item in tuples
        if f"{item[0]}{item[1]}{item[2]}{item[3]}" not in seen
        and not seen.add(f"{item[0]}{item[1]}{item[2]}{item[3]}")
    ]


def decode_base64(data):
    """
    Try to decode a base64 string.
    From http://stackoverflow.com/questions/2941995/python-ignore-incorrect-padding-error-when-base64-decoding
    """
    missing_padding = 4 - len(data) % 4
    if isinstance(data, str):
        data = data.encode("UTF-8")

    if missing_padding:
        data += b"=" * missing_padding

    try:
        return base64.decodebytes(data)
    except binascii.Error:
        # if there's a decoding error, just return the data
        return data


def encode_base64(data):
    """
    Encode data as a base64 string.
    """
    return base64.encodebytes(data).strip()


class KThread(threading.Thread):
    """
    A subclass of threading.Thread, with a kill() method.
    From https://web.archive.org/web/20130503082442/http://mail.python.org/pipermail/python-list/2004-May/281943.html
    """

    def __init__(self, *args, **keywords):
        threading.Thread.__init__(self, *args, **keywords)
        self.killed = False

    def start(self):
        """Start the thread."""
        self.__run_backup = self.run
        self.run = self.__run  # Force the Thread toinstall our trace.
        threading.Thread.start(self)

    def __run(self):
        """Hacked run function, which installs the trace."""
        sys.settrace(self.globaltrace)
        self.__run_backup()
        self.run = self.__run_backup

    def globaltrace(self, frame, why, arg):
        if why == "call":
            return self.localtrace
        return None

    def localtrace(self, frame, why, arg):
        if self.killed and why == "line":
            raise SystemExit()
        return self.localtrace

    def kill(self):
        self.killed = True
