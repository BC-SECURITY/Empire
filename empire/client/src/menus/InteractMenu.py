import logging
import pathlib
import subprocess
import textwrap
import time

from prompt_toolkit import HTML
from prompt_toolkit.completion import Completion

from empire.client.src.EmpireCliState import state
from empire.client.src.menus.Menu import Menu
from empire.client.src.Shortcut import Shortcut
from empire.client.src.ShortcutHandler import shortcut_handler
from empire.client.src.utils import print_util, table_util
from empire.client.src.utils.autocomplete_util import (
    current_files,
    filtered_search_list,
    position_util,
)
from empire.client.src.utils.cli_util import command, register_cli_commands
from empire.client.src.utils.data_util import get_data_from_file

log = logging.getLogger(__name__)


@register_cli_commands
class InteractMenu(Menu):
    def __init__(self):
        super().__init__(display_name="", selected="")
        self.agent_options = {}
        self.agent_language = ""
        self.session_id = ""

    def autocomplete(self):
        return (
            self._cmd_registry
            + super().autocomplete()
            + shortcut_handler.get_names(self.agent_language)
        )

    def get_completions(self, document, complete_event, cmd_line, word_before_cursor):
        if cmd_line[0] in ["interact"] and position_util(
            cmd_line, 2, word_before_cursor
        ):
            active_agents = [
                a["name"]
                for a in filter(lambda a: a["stale"] is not True, state.agents.values())
            ]
            for agent in filtered_search_list(word_before_cursor, active_agents):
                yield Completion(agent, start_position=-len(word_before_cursor))
        elif cmd_line[0] in ["display"] and position_util(
            cmd_line, 2, word_before_cursor
        ):
            for property_name in filtered_search_list(
                word_before_cursor, self.agent_options
            ):
                yield Completion(property_name, start_position=-len(word_before_cursor))
        elif cmd_line[0] in shortcut_handler.get_names(self.agent_language):
            position = len(cmd_line)
            shortcut = shortcut_handler.get(self.agent_language, cmd_line[0])
            params = shortcut.get_dynamic_param_names()
            if position - 1 < len(params):
                if params[position - 1].lower() == "listener":
                    for listener in filtered_search_list(
                        word_before_cursor, state.listeners.keys()
                    ):
                        yield Completion(
                            listener, start_position=-len(word_before_cursor)
                        )
                if params[position - 1].lower() == "agent":
                    for agent in filtered_search_list(
                        word_before_cursor, state.agents.keys()
                    ):
                        yield Completion(agent, start_position=-len(word_before_cursor))

                if params[position - 1].lower() == "file":
                    for files in filtered_search_list(
                        word_before_cursor,
                        current_files(state.directory["downloads"]),
                    ):
                        yield Completion(
                            files,
                            display=files.split("/")[-1],
                            start_position=-len(word_before_cursor),
                        )
            elif (
                position - 1 >= len(params)
                and position > 1
                and params[position - 2].lower() == "file"
                and len(cmd_line) > 1
                and cmd_line[1] == "-p"
            ):
                file = state.search_files()
                if file:
                    yield Completion(file, start_position=-len(word_before_cursor))

        elif cmd_line[0] in ["view"]:
            tasks = state.get_agent_tasks(self.session_id, 100)
            tasks = {str(x["id"]): x for x in tasks["records"]}

            for task_id in filtered_search_list(word_before_cursor, tasks.keys()):
                full = tasks[task_id]
                help_text = print_util.truncate(
                    f"{full.get('input', '')[:30]}, {full.get('username', '')}",
                    width=75,
                )
                yield Completion(
                    task_id,
                    display=HTML(f"{full['id']} <purple>({help_text})</purple>"),
                    start_position=-len(word_before_cursor),
                )
        elif cmd_line[0] in ["upload", "script_import"]:
            if len(cmd_line) > 1 and cmd_line[1] == "-p":
                file = state.search_files()
                if file:
                    yield Completion(file, start_position=-len(word_before_cursor))
            else:
                for files in filtered_search_list(
                    word_before_cursor, current_files(state.directory["downloads"])
                ):
                    yield Completion(
                        files,
                        display=files.split("/")[-1],
                        start_position=-len(word_before_cursor),
                    )

        yield from super().get_completions(
            document, complete_event, cmd_line, word_before_cursor
        )

    def on_enter(self, **kwargs) -> bool:
        if "selected" not in kwargs:
            return False
        else:
            self.use(kwargs["selected"])
            self.display_cached_results()
            return True

    def get_prompt(self) -> str:
        joined = "/".join([self.display_name, self.name]).strip("/")
        return f"(Empire: <ansired>{joined}</ansired>) > "

    def display_cached_results(self) -> None:
        """
        Print the task results for the all the results that have been received for this agent.
        """
        task_results = state.cached_agent_results.get(self.session_id, {})
        for key, value in task_results.items():
            log.info("Task " + str(key) + " results received")
            print(value)

        state.cached_agent_results.get(self.session_id, {}).clear()

    def use(self, agent_name: str) -> None:
        """
        Use the selected agent

        Usage: use <agent_name>
        """
        state.get_agents()
        if agent_name in state.agents:
            self.name = agent_name
            self.selected = agent_name
            self.session_id = state.agents[agent_name]["session_id"]
            self.agent_options = state.agents[agent_name]  # todo rename agent_options
            self.agent_language = self.agent_options["language"]

    @command
    def shell(self, shell_cmd: str, literal: bool = False) -> None:
        """
        Tasks the specified agent to execute a shell command.

        Usage: shell [--literal / -l] <shell_cmd>

        Options:
            --literal -l    Interpret the shell command literally. This will ensure that aliased
                            commands such as whoami or ps do not execute the built-in agent aliases.
        """
        literal = bool(literal)  # docopt parses into 0/1
        response = state.agent_shell(self.session_id, shell_cmd, literal)
        if "status" in response:
            log.info(
                "Tasked " + self.session_id + " to run Task " + str(response["id"])
            )

    @command
    def sysinfo(self) -> None:
        """
        Tasks the specified agent update sysinfo.

        Usage: sysinfo
        """
        response = state.sysinfo(self.session_id)
        if "status" in response:
            log.info(
                "Tasked " + self.session_id + " to run Task " + str(response["id"])
            )

    @command
    def script_import(self, local_script_location: str) -> None:
        """
        Uploads a PowerShell script to the server and runs it in memory on the agent. Use '-p' for a file selection dialog.

        Usage: script_import <local_script_location>
        """
        try:
            filename = local_script_location.split("/")[-1]
            data = get_data_from_file(local_script_location)
        except Exception:
            log.error("Invalid filename or file does not exist")
            return

        if data:
            response = state.agent_script_import(self.session_id, filename, data)
            if "id" in response:
                log.info(
                    "Tasked " + self.selected + " to run Task " + str(response["id"])
                )
            elif "detail" in response:
                log.error(response["detail"])

        else:
            log.error("Invalid file path")

    @command
    def script_command(self, script_cmd: str) -> None:
        """
        Execute a function in the currently imported PowerShell script.

        Usage: shell_command <script_cmd>
        """
        response = state.agent_script_command(self.session_id, script_cmd)
        if "id" in response:
            log.info(
                "[*] Tasked " + self.session_id + " to run Task " + str(response["id"])
            )

        elif "detail" in response:
            log.error("[!] Error: " + response["detail"])

    @command
    def upload(self, local_file_directory: str, remote_file_directory: str) -> None:
        """
        Tasks specified agent to upload a file. Use '-p' for a file selection dialog.

        Usage: upload <local_file_directory> [<remote_file_directory>]
        """
        # Get file and upload to server
        filename = local_file_directory.split("/")[-1]
        data = get_data_from_file(local_file_directory)

        if not remote_file_directory:
            remote_file_directory = filename

        if data:
            response = state.upload_file(filename, data)

            if "id" in response:
                log.info(f"Uploaded {filename} to server")

                # If successful upload then pass to agent
                response = state.agent_upload_file(
                    self.session_id, response["id"], file_path=remote_file_directory
                )
                if "id" in response:
                    log.info("Tasked " + self.selected + " to upload file " + filename)
                elif "detail" in response:
                    log.error(response["detail"])

            elif "detail" in response:
                log.error(response["detail"])
        else:
            log.error("Invalid file path")

    @command
    def download(self, file_name: str) -> None:
        """
        Tasks specified agent to download a file,

        Usage: download <file_name>
        """
        response = state.agent_download_file(self.session_id, file_name)
        if response.status_code == 201:
            log.info("[*] Tasked " + self.selected + " to run Download " + file_name)
        elif "detail" in response:
            log.error(response["detail"])

    @command
    def sleep(self, delay: int, jitter: int) -> None:
        """
        Tasks specified agent to update delay (s) and jitter (0.0 - 1.0),

        Usage: sleep <delay> <jitter>
        """
        response = state.agent_sleep(self.session_id, delay, jitter)
        log.info(f"Tasked agent to sleep delay/jitter {delay}/{jitter}")
        if "id" in response:
            log.info(
                "[*] Tasked " + self.session_id + " to run Task " + str(response["id"])
            )

        elif "detail" in response:
            try:
                log.error(response["detail"][0]["msg"])
            except Exception:
                log.error(response["detail"])

    @command
    def info(self) -> None:
        """
        Display agent info.

        Usage: info
        """
        agent_list = []
        for key, value in self.agent_options.items():
            if isinstance(value, int):
                value = str(value)
            if value is None:
                value = ""
            if key not in ["taskings", "results"]:
                temp = [key, "\n".join(textwrap.wrap(str(value), width=45))]
                agent_list.append(temp)

        table_util.print_table(agent_list, "Agent Options")

    @command
    def help(self):
        """
        Display the help menu for the current menu

        Usage: help
        """
        help_list = []
        for name in self._cmd_registry:
            try:
                description = print_util.text_wrap(
                    getattr(self, name).__doc__.split("\n")[1].lstrip(), width=35
                )
                usage = print_util.text_wrap(
                    getattr(self, name).__doc__.split("\n")[3].lstrip()[7:], width=35
                )
                help_list.append([name, description, usage])
            except Exception:
                continue

        for name, shortcut in shortcut_handler.shortcuts[self.agent_language].items():
            try:
                description = shortcut.get_help_description()
                usage = shortcut.get_usage_string()
                help_list.append([name, description, usage])
            except Exception:
                continue
        help_list.insert(0, ["Name", "Description", "Usage"])
        table_util.print_table(help_list, "Help Options")

    @command
    def update_comms(self, listener_name: str) -> None:
        """
        Update the listener for an agent.

        Usage: update_comms <listener_name>
        """
        response = state.update_agent_comms(self.session_id, listener_name)

        if "id" in response:
            log.info("Updated agent " + self.selected + " listener " + listener_name)
        elif "detail" in response:
            log.error(response["detail"])

    @command
    def kill_date(self, kill_date: str) -> None:
        """
        Set an agent's kill_date (01/01/2020)

        Usage: kill_date <kill_date>
        """
        response = state.update_agent_kill_date(self.session_id, kill_date)

        if "id" in response:
            log.info("Updated agent " + self.selected + " kill_date to " + kill_date)
        elif "detail" in response:
            log.error(response["detail"])

    @command
    def working_hours(self, working_hours: str) -> None:
        """
        Set an agent's working hours (9:00-17:00)

        Usage: working_hours <working_hours>
        """
        response = state.update_agent_working_hours(self.session_id, working_hours)

        if "id" in response:
            log.info(
                "Updated agent " + self.selected + " working_hours to " + working_hours
            )
        elif "detail" in response:
            log.error(response["detail"])

    @command
    def proxy(self, agent_name: str) -> None:
        """
        Proxy management menu for configuring agent proxies

        Usage: proxy
        """
        pass

    @command
    def display(self, property_name: str):
        """
        Display an agent property

        Usage: display <property_name>
        """
        if property_name in self.agent_options:
            print(f"{property_name} is {self.agent_options[property_name]}")

    @command
    def history(self, number_tasks: int):
        """
        Display last number of task results received.

        Usage: history [<number_tasks>]
        """
        if not number_tasks:
            number_tasks = 5

        response = state.get_agent_tasks(self.session_id, str(number_tasks))

        if "records" in response:
            tasks = response["records"]
            for task in tasks:
                if task.get("output"):
                    log.info(f'Task {task["id"]} results received')
                    for line in task.get("output", "").split("\n"):
                        print(print_util.color(line))
                else:
                    log.error(f'Task {task["id"]} No tasking results received')
        elif "detail" in response:
            log.error(response["detail"])

    @command
    def view(self, task_id: str):
        """
        View specific task and result

        Usage: view <task_id>
        """
        task = state.get_agent_task(self.session_id, task_id)
        record_list = []
        record_list.append([print_util.color("ID", "blue"), task["id"]])
        record_list.append([print_util.color("Module", "blue"), task["module_name"]])
        record_list.append([print_util.color("Status", "blue"), task["status"]])
        record_list.append([print_util.color("Input", "blue"), task["input"]])

        table_util.print_table(
            record_list,
            "View Task",
            colored_header=False,
            borders=False,
            end_space=False,
        )
        print(print_util.color(" Output", "blue"))
        if task["output"]:
            for line in task["output"].split("\n"):
                print(print_util.color(line))

    def execute_shortcut(self, command_name: str, params: list[str]):
        shortcut: Shortcut = shortcut_handler.get(self.agent_language, command_name)

        if not shortcut:
            return None

        if shortcut.shell:
            self.shell(shortcut.shell)
            return

        if len(params) != len(shortcut.get_dynamic_param_names()):
            return None  # todo log message

        if shortcut.module not in state.modules:
            log.error(f"No module named {shortcut.name} found on the server.")
            return None

        module_options = dict.copy(state.modules[shortcut.module]["options"])
        post_body = {}
        post_body["options"] = {}

        for i, shortcut_param in enumerate(shortcut.get_dynamic_params()):
            if shortcut_param.name in module_options:
                post_body["options"][shortcut_param.name] = params[i]

        # TODO Still haven't figured out other data types. Right now everything is a string.
        #  Which I think is how it is in the old cli
        for key in module_options:
            if key in shortcut.get_dynamic_param_names():
                # Grab filename, send to server, and save a copy off in the downloads folder
                if key in ["File"]:
                    if pathlib.Path(post_body.get("options")["File"]).is_file():
                        try:
                            file_directory = post_body.get("options")["File"]
                            filename = file_directory.split("/")[-1]
                            data = get_data_from_file(file_directory)
                        except Exception:
                            log.error("Invalid filename or file does not exist")
                            return
                        response = state.upload_file(filename, data)
                        if "id" in response:
                            log.info("File uploaded to server successfully")
                            post_body.get("options")["File"] = response["id"]
                        elif "detail" in response:
                            if response["detail"].startswith("[!]"):
                                msg = response["detail"]
                            else:
                                msg = f"[!] Error: {response['detail']}"
                            print(print_util.color(msg))

                        # Save copy off to downloads folder so last value points to the correct file
                        with open(
                            f"{state.directory['downloads']}{filename}", "wb+"
                        ) as f:
                            f.write(data)
                else:
                    continue
            elif key in shortcut.get_static_param_names():
                post_body["options"][key] = str(shortcut.get_param(key).value)
            else:
                post_body["options"][key] = str(module_options[key]["value"])

        post_body["module_id"] = shortcut.module
        response = state.execute_module(self.session_id, post_body)

        if "id" in response:
            log.info(
                "[*] Tasked " + self.selected + " to run Task " + str(response["id"])
            )
        elif "detail" in response:
            log.error(response["detail"])

    @command
    def vnc_client(self, address: str, port: str, password: str) -> None:
        """
        Launch a VNC client to a remote server

        Usage: vnc_client <address> <port> <password>
        """
        vnc_cmd = [
            "python3",
            state.install_path + "/src/utils/vnc_util.py",
            address,
            port,
            password,
        ]
        self.vnc_proc = subprocess.Popen(
            vnc_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )

    @command
    def vnc(self) -> None:
        """
        Launch a VNC server on the agent and spawn a VNC client

        Usage: vnc
        """
        module_options = dict.copy(state.modules["csharp_vnc_vncserver"]["options"])
        post_body = {}
        post_body["options"] = {}

        for key in module_options:
            post_body["options"][key] = str(module_options[key]["value"])

        post_body["module_id"] = "csharp_vnc_vncserver"
        response = state.execute_module(self.session_id, post_body)

        if "id" in response:
            log.info("Tasked " + self.selected + " to run Task " + str(response["id"]))
        elif "detail" in response:
            log.error(response["detail"])
            return

        log.info("Starting VNC server...")
        time.sleep(5)

        vnc_cmd = [
            "python3",
            state.install_path + "/src/utils/vnc_util.py",
            self.agent_options["internal_ip"],
            module_options["Port"]["value"],
            module_options["Password"]["value"],
        ]
        self.vnc_proc = subprocess.Popen(
            vnc_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )

    @command
    def socks(self, port: int) -> None:
        """
        Create a socks proxy on the agent using in-band comms. (Default port: 1080)

        Usage: socks [<port>]
        """
        if not port:
            port = 1080

        log.info(f"SOCKS server port set to {port}")

        response = state.create_socks(self.session_id, port)
        if "id" in response:
            print(
                print_util.color(
                    "[*] Tasked " + self.selected + " to start SOCKS server"
                )
            )

        elif "detail" in response:
            print(print_util.color("[!] Error: " + response["detail"]))
            return

    @command
    def jobs(self) -> None:
        """
        View list of active jobs

        Usage: jobs
        """
        response = state.view_jobs(self.session_id)
        if "id" in response:
            print(
                print_util.color(
                    "[*] Tasked " + self.selected + " to retrieve active jobs"
                )
            )

        elif "detail" in response:
            print(print_util.color("[!] Error: " + response["detail"]))
            return

    @command
    def kill_job(self, task_id: int) -> None:
        """
        Kill an active jobs

        Usage: kill_job <task_id>
        """
        response = state.kill_job(self.session_id, task_id)
        if "id" in response:
            print(
                print_util.color(
                    "[*] Tasked " + self.selected + f" to kill task {task_id!s}"
                )
            )

        elif "detail" in response:
            print(print_util.color("[!] Error: " + response["detail"]))
            return


interact_menu = InteractMenu()
