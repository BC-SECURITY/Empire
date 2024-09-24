"""
Parse arguments.
Life saver comment on separating the parser.
https://stackoverflow.com/a/30217387
"""

import argparse

parent_parser = argparse.ArgumentParser()
subparsers = parent_parser.add_subparsers(dest="subparser_name")

server_parser = subparsers.add_parser("server", help="Launch Empire Server")
api_export_parser = subparsers.add_parser("api_export", help="Export the OpenAPI spec")
client_parser = subparsers.add_parser("client", help="Launch Empire CLI")
sync_starkiller_parser = subparsers.add_parser(
    "sync-starkiller", help="Sync Starkiller submodule with the config"
)
install_parser = subparsers.add_parser("install", help="Install the Empire framework")
install_parser.add_argument(
    "-y",
    action="store_true",
    help="Automatically say yes to all prompts during installation",
)

# Client Args
client_parser.add_argument(
    "-l",
    "--log-level",
    dest="log_level",
    type=str.upper,
    choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
    help="Set the logging level",
)
client_parser.add_argument(
    "-r",
    "--resource",
    type=str,
    help="Run the Empire commands in the specified resource file after startup.",
)
client_parser.add_argument(
    "--config",
    type=str,
    nargs=1,
    help="Specify a config.yaml different from the config.yaml in the empire/client directory.",
)
client_parser.add_argument(
    "--reset",
    action="store_true",
    help="Resets Empire's client to defaults and deletes any app data accumulated over previous runs.",
)

# Server Args
general_group = server_parser.add_argument_group("General Options")
general_group.add_argument(
    "-l",
    "--log-level",
    dest="log_level",
    type=str.upper,
    choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
    help="Set the logging level",
)
general_group.add_argument(
    "-d",
    "--debug",
    help="Set the logging level to DEBUG",
    action="store_const",
    dest="log_level",
    const="DEBUG",
    default=None,
)
general_group.add_argument(
    "--reset",
    action="store_true",
    help="Resets Empire's database and deletes any app data accumulated over previous runs.",
)
general_group.add_argument(
    "-v", "--version", action="store_true", help="Display current Empire version."
)
general_group.add_argument(
    "--config",
    type=str,
    nargs=1,
    help="Specify a config.yaml different from the config.yaml in the empire/server directory.",
)
general_group.add_argument(
    "--secure-api",
    action="store_true",
    help="Use https for the API. Uses .key and .pem file from empire/server/data."
    "Note that Starkiller will not work with self-signed certs due to browsers blocking the requests.",
)

rest_group = server_parser.add_argument_group("RESTful API Options")
rest_group.add_argument(
    "--restip",
    nargs=1,
    help="IP to bind the Empire RESTful API on. Defaults to 0.0.0.0",
)
rest_group.add_argument(
    "--restport",
    type=int,
    nargs=1,
    help="Port to run the Empire RESTful API on. Defaults to 1337",
)

args = parent_parser.parse_args()

if parent_parser.parse_args().subparser_name is None:
    parent_parser.print_help()
