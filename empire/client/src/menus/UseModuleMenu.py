import logging
import pathlib

from prompt_toolkit.completion import Completion

from empire.client.src.EmpireCliState import state
from empire.client.src.menus.UseMenu import UseMenu
from empire.client.src.MenuState import menu_state
from empire.client.src.utils.autocomplete_util import (
    filtered_search_list,
    position_util,
)
from empire.client.src.utils.cli_util import command, register_cli_commands
from empire.client.src.utils.data_util import get_data_from_file

log = logging.getLogger(__name__)


@register_cli_commands
class UseModuleMenu(UseMenu):
    def __init__(self):
        super().__init__(
            display_name="usemodule", selected="", record=None, record_options=None
        )
        self.stop_threads = False

    def autocomplete(self):
        return self._cmd_registry + super().autocomplete()

    def get_completions(self, document, complete_event, cmd_line, word_before_cursor):
        if cmd_line[0] == "usemodule" and position_util(
            cmd_line, 2, word_before_cursor
        ):
            for module in filtered_search_list(
                word_before_cursor, state.modules.keys()
            ):
                yield Completion(module, start_position=-len(word_before_cursor))

        yield from super().get_completions(
            document, complete_event, cmd_line, word_before_cursor
        )

    def on_enter(self, **kwargs) -> bool:
        if "selected" not in kwargs:
            return False
        else:
            state.get_bypasses()
            self.use(kwargs["selected"])
            self.stop_threads = False

            if "agent" in kwargs and "Agent" in self.record_options:
                self.set("Agent", kwargs["agent"])
            self.info()
            self.options()
            state.get_credentials()
            return True

    def on_leave(self):
        self.stop_threads = True

    def use(self, module: str) -> None:
        """
        Use the selected module

        Usage: use <module>
        """
        if module in state.modules:
            self.selected = module
            self.record = state.modules[module]
            self.record_options = state.modules[module]["options"]

    @command
    def execute(self):
        """
        Execute the selected module

        Usage: execute
        """
        # Find file then upload to server
        if (
            "File" in self.record_options
            # if a full path upload to server, else use file from download directory
            and pathlib.Path(self.record_options["File"]["value"]).is_file()
        ):
            try:
                file_directory = self.record_options["File"]["value"]
                filename = file_directory.split("/")[-1]
                data = get_data_from_file(file_directory)
            except Exception:
                log.error("Invalid filename or file does not exist")
                return
            response = state.upload_file(filename, data)
            if "id" in response:
                log.info("File uploaded to server successfully")
                self.record_options["File"]["value"] = response["id"]

            elif "detail" in response:
                if response["detail"].startswith("[!]"):
                    log.info(response["detail"])
                else:
                    log.error(response["detail"])

            # Save copy off to downloads folder so last value points to the correct file
            with open(f"{state.directory['downloads']}{filename}", "wb+") as f:
                f.write(data)

        post_body = {"options": {}}

        for key in self.record_options:
            post_body["options"][key] = self.record_options[key]["value"]

        post_body["module_id"] = self.record["id"]

        try:
            if self.record_options["Agent"]["value"] == "":
                log.error("Agent not set")
                return
            response = state.execute_module(
                state.agents[self.record_options["Agent"]["value"]]["session_id"], post_body
            )
            if "status" in response:
                if "Agent" in post_body["options"]:
                    log.info(
                        "Tasked "
                        + self.record_options["Agent"]["value"]
                        + " to run Task "
                        + str(response["id"])
                    )
                    menu_state.pop()

            elif "detail" in response:
                if response["detail"].startswith("[!]"):
                    log.info(response["detail"])
                else:
                    log.error(response["detail"])
        except Exception as e:
            log.error(e)

    @command
    def generate(self):
        """
        Execute the selected module

        Usage: generate
        """
        self.execute()


use_module_menu = UseModuleMenu()
