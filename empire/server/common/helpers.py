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
    parse_credentials() - enumerate module output, looking for any parseable credential sections
    parse_mimikatz() - parses the output of Invoke-Mimikatz
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
import ipaddress
import logging
import random
import re
import socket
import string
import sys
import threading
from datetime import datetime

import click

from empire.server.utils.math_util import old_div

log = logging.getLogger(__name__)


###############################################################
#
# Global Variables
#
################################################################

globentropy = random.randint(1, datetime.today().day)
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
        return True
    except Exception:
        return False


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
        length = random.randrange(6, 16)
    return "".join(random.choice(charset) for x in range(length))


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
        log.error("Error extracting psreflect overhead from script!")
        return ""


def get_dependent_functions(code, functionNames):
    """
    Helper that takes a chunk of PowerShell code and a set of function
    names and returns the unique set of function names within the script block.
    """

    dependentFunctions = set()
    for functionName in functionNames:
        # find all function names that aren't followed by another alpha character
        if re.search("[^A-Za-z']+" + functionName + "[^A-Za-z']+", code, re.IGNORECASE):
            # if "'AbuseFunction' \"%s" % (functionName) not in code:
            # TODO: fix superflous functions from being added to PowerUp Invoke-AllChecks code...
            dependentFunctions.add(functionName)

    if re.search(r"\$Netapi32|\$Advapi32|\$Kernel32|\$Wtsapi32", code, re.IGNORECASE):
        dependentFunctions |= {
            "New-InMemoryModule",
            "func",
            "Add-Win32Type",
            "psenum",
            "struct",
        }

    return dependentFunctions


def find_all_dependent_functions(functions, functionsToProcess, resultFunctions=None):
    """
    Takes a dictionary of "[functionName] -> functionCode" and a set of functions
    to process, and recursively returns all nested functions that may be required.

    Used to map the dependent functions for nested script dependencies like in
    PowerView.
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
                functions[requiredFunction], functions.keys()
            )
        except Exception:
            functionDependencies = []
            log.error(
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
            functions, functionsToProcess, resultFunctions
        )

    return resultFunctions


def generate_dynamic_powershell_script(script, function_names):
    """
    Takes a PowerShell script and a function name (or array of function names,
    generates a dictionary of "[functionNames] -> functionCode", and recursively
    maps all dependent functions for the specified function name.

    A script is returned with only the code necessary for the given
    functionName, stripped of comments and whitespace.

    Note: for PowerView, it will also dynamically detect if psreflect
    overhead is needed and add it to the result script.
    """

    new_script = ""
    psreflect_functions = [
        "New-InMemoryModule",
        "func",
        "Add-Win32Type",
        "psenum",
        "struct",
    ]

    if not isinstance(function_names, list):
        function_names = [function_names]

    # build a mapping of functionNames -> stripped function code
    functions = {}
    pattern = re.compile(r"\n(?:function|filter).*?{.*?\n}\n", re.DOTALL)

    script = re.sub(re.compile("<#.*?#>", re.DOTALL), "", script)
    for func_match in pattern.findall(script):
        name = func_match[:40].split()[1]
        functions[name] = func_match

    # recursively enumerate all possible function dependencies and
    #   start building the new result script
    function_dependencies = []

    for functionName in function_names:
        function_dependencies += find_all_dependent_functions(
            functions, functionName, []
        )
        function_dependencies = unique(function_dependencies)

    for function_dependency in function_dependencies:
        try:
            new_script += functions[function_dependency] + "\n"
        except Exception:
            log.error(f"Key error with function {function_dependency} !")

    # if any psreflect methods are needed, add in the overhead at the end
    if any(el in set(psreflect_functions) for el in function_dependencies):
        new_script += get_powerview_psreflect_overhead(script)

    new_script = strip_powershell_comments(new_script)

    return new_script + "\n"


###############################################################
#
# Parsers
#
###############################################################


def parse_credentials(data):
    """
    Enumerate module output, looking for any parseable credential sections.
    """
    if isinstance(data, str):
        data = data.encode("UTF-8")
    parts = data.split(b"\n")

    # tag for Invoke-Mimikatz output
    if parts[0].startswith(b"Hostname:"):
        return parse_mimikatz(data)

    # powershell/collection/prompt output
    if parts[0].startswith(b"[+] Prompted credentials:"):
        parts = parts[0].split(b"->")
        if len(parts) == 2:  # noqa: PLR2004
            username = parts[1].split(b":", 1)[0].strip()
            password = parts[1].split(b":", 1)[1].strip()

            if "\\" in username:
                domain = username.split("\\")[0].strip()
                username = username.split("\\")[1].strip()
            else:
                domain = ""

            return [("plaintext", domain, username, password, "", "")]

        log.error("Error in parsing prompted credential output.")
        return None

    # python/collection/prompt (Mac OS)
    if b"text returned:" in parts[0]:
        parts2 = parts[0].split(b"text returned:")
        if len(parts2) >= 2:  # noqa: PLR2004
            password = parts2[-1]
            return [("plaintext", "", "", password, "", "")]
        return None

    return None


def parse_mimikatz(data):  # noqa: PLR0912 PLR0915
    """
    Parse the output from Invoke-Mimikatz to return credential sets.
    """

    # cred format:
    #   credType, domain, username, password, hostname, sid
    creds = []

    # regexes for "sekurlsa::logonpasswords" Mimikatz output
    regexes = [
        "(?s)(?<=msv :).*?(?=tspkg :)",
        "(?s)(?<=tspkg :).*?(?=wdigest :)",
        "(?s)(?<=wdigest :).*?(?=kerberos :)",
        "(?s)(?<=kerberos :).*?(?=ssp :)",
        "(?s)(?<=ssp :).*?(?=credman :)",
        "(?s)(?<=credman :).*?(?=Authentication Id :)",
        "(?s)(?<=credman :).*?(?=mimikatz)",
    ]

    hostDomain = ""
    domainSid = ""
    hostName = ""
    if isinstance(data, str):
        data = data.encode("UTF-8")
    lines = data.split(b"\n")
    for line in lines[0:2]:
        if line.startswith(b"Hostname:"):
            try:
                domain = line.split(b":")[1].strip()
                temp = domain.split(b"/")[0].strip()
                domainSid = domain.split(b"/")[1].strip()

                hostName = temp.split(b".")[0]
                hostDomain = b".".join(temp.split(".")[1:])
            except Exception:
                pass

    for regex in regexes:
        p = re.compile(regex)
        for match in p.findall(data.decode("UTF-8")):
            lines2 = match.split("\n")
            username, domain, password = "", "", ""

            for line in lines2:
                try:
                    if "Username" in line:
                        username = line.split(":", 1)[1].strip()
                    elif "Domain" in line:
                        domain = line.split(":", 1)[1].strip()
                    elif "NTLM" in line or "Password" in line:
                        password = line.split(":", 1)[1].strip()
                except Exception:
                    pass

            if password not in ("", "(null)"):
                sid = ""

                # substitute the FQDN in if it matches
                if hostDomain.startswith(domain.lower()):
                    domain = hostDomain
                    sid = domainSid

                credType = "hash" if validate_ntlm(password) else "plaintext"

                # ignore machine account plaintexts
                if not (credType == "plaintext" and username.endswith("$")):
                    creds.append((credType, domain, username, password, hostName, sid))

    if not creds and len(lines) >= 13:  # noqa: PLR2004
        # check if we have lsadump output to check for krbtgt
        #   happens on domain controller hashdumps
        for x in range(8, 13):
            if lines[x].startswith(b"Domain :"):
                domain, sid, krbtgtHash = b"", b"", b""

                try:
                    domainParts = lines[x].split(b":")[1]
                    domain = domainParts.split(b"/")[0].strip()
                    sid = domainParts.split(b"/")[1].strip()

                    # substitute the FQDN in if it matches
                    if hostDomain.startswith(domain.decode("UTF-8").lower()):
                        domain = hostDomain
                        sid = domainSid

                    for x in range(0, len(lines)):  # noqa: PLW2901
                        if lines[x].startswith(b"User : krbtgt"):
                            krbtgtHash = lines[x + 2].split(b":")[1].strip()
                            break

                    if krbtgtHash != b"":
                        creds.append(
                            (
                                "hash",
                                domain.decode("UTF-8"),
                                "krbtgt",
                                krbtgtHash.decode("UTF-8"),
                                hostName.decode("UTF-8"),
                                sid.decode("UTF-8"),
                            )
                        )
                except Exception:
                    pass

    # check if we get lsadump::dcsync output
    if not creds and b"** SAM ACCOUNT **" in lines:
        domain, user, userHash, dcName, sid = "", "", "", "", ""
        for line in lines:
            if line.strip().endswith(b"will be the domain"):
                domain = line.split(b"'")[1]
            elif line.strip().endswith(b"will be the DC server"):
                dcName = line.split(b"'")[1].split(b".")[0]
            elif line.strip().startswith(b"SAM Username"):
                user = line.split(b":")[1].strip()
            elif line.strip().startswith(b"Object Security ID"):
                parts = line.split(b":")[1].strip().split(b"-")
                sid = b"-".join(parts[0:-1])
            elif line.strip().startswith(b"Hash NTLM:"):
                userHash = line.split(b":")[1].strip()

        if domain != "" and userHash != "":
            creds.append(
                (
                    "hash",
                    domain.decode("UTF-8"),
                    user.decode("UTF-8"),
                    userHash.decode("UTF-8"),
                    dcName.decode("UTF-8"),
                    sid.decode("UTF-8"),
                )
            )

    return uniquify_tuples(creds)


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
    kb_size = old_div(byte_size, 1024)
    if kb_size == 0:
        return f"{byte_size} Bytes"
    mb_size = old_div(kb_size, 1024)
    if mb_size == 0:
        return f"{kb_size} KB"
    gb_size = old_div(mb_size, 1024) % (mb_size)
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
