import logging
import threading
import time

from empire.client.src.EmpireCliState import state
from empire.client.src.menus.Menu import Menu
from empire.client.src.utils import print_util
from empire.client.src.utils.cli_util import register_cli_commands

log = logging.getLogger(__name__)


@register_cli_commands
class ShellMenu(Menu):
    def __init__(self):
        super().__init__(display_name="", selected="")
        self.stop_threads = False

    def autocomplete(self):
        return self._cmd_registry + super().autocomplete()

    def get_completions(self, document, complete_event, cmd_line, word_before_cursor):
        yield from super().get_completions(
            document, complete_event, cmd_line, word_before_cursor
        )

    def on_enter(self, **kwargs) -> bool:
        if "selected" not in kwargs:
            return False
        else:
            self.use(kwargs["selected"])
            self.stop_threads = False
            log.info("Exit Shell Menu with Ctrl+C")
            return True

    def on_leave(self):
        self.stop_threads = True

    def get_prompt(self) -> str:
        return f"<ansiblue>({self.selected})</ansiblue> <ansired>{self.display_name}</ansired> > "

    def use(self, agent_name: str) -> None:
        """
        Use shell

        Usage: shell
        """
        self.selected = agent_name
        self.session_id = state.agents[self.selected]["session_id"]
        self.language = state.agents[self.selected]["language"]
        shell_return = threading.Thread(
            target=self.update_directory, args=[self.session_id]
        )
        shell_return.daemon = True
        shell_return.start()

    def update_directory(self, session_id: str):
        """
        Update current directory
        """
        if self.language == "powershell":
            task_id: int = state.agent_shell(session_id, r"(Resolve-Path .\).Path")[
                "id"
            ]
        elif self.language == "python":
            task_id: int = state.agent_shell(session_id, "echo $PWD")["id"]
        elif self.language == "ironpython":
            task_id: int = state.agent_shell(session_id, "cd .")["id"]
        elif self.language == "csharp":
            task_id: int = state.agent_shell(session_id, r"(Resolve-Path .\).Path")[
                "id"
            ]
            pass

        count = 0
        result = None
        while result is None and count < 30:
            result = state.cached_agent_results.get(session_id, {}).get(task_id)
            count += 1
            time.sleep(1)

        if result:
            temp_name = result.split("\r")[0]
            del state.cached_agent_results.get(session_id, {})[task_id]
            self.display_name = temp_name
            self.get_prompt()

    def shell(self, agent_name: str, shell_cmd: str):
        """
        Tasks an the specified agent_name to execute a shell command.

        Usage:  <shell_cmd>
        """
        response = state.agent_shell(state.agents[agent_name]["session_id"], shell_cmd)
        if shell_cmd.split()[0].lower() in ["cd", "set-location"]:
            shell_return = threading.Thread(
                target=self.update_directory, args=[state.agents[agent_name]["session_id"]]
            )
            shell_return.daemon = True
            shell_return.start()
        else:
            shell_return = threading.Thread(
                target=self.tasking_id_returns, args=[response["id"]]
            )
            shell_return.daemon = True
            shell_return.start()

    def tasking_id_returns(self, task_id: int):
        """
        Polls for the tasks that have been queued.
        Once found, will remove from the cache and display.
        """
        count = 0
        result = None
        while result is None and count < 30 and not self.stop_threads:
            # this may not work 100% of the time since there is a mix of agent session_id and names still.
            result = state.cached_agent_results.get(self.session_id, {}).get(task_id)
            count += 1
            time.sleep(1)

        if result:
            del state.cached_agent_results.get(self.session_id, {})[task_id]

        print(print_util.color(result))


shell_menu = ShellMenu()
