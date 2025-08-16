#! /usr/bin/env python3

import sys

from empire import arguments
from empire.server.core.config import config_manager
from empire.server.core.config.data_manager import sync_empire_compiler, sync_starkiller

if __name__ == "__main__":
    args = arguments.parse_args()

    if args.subparser_name == "server":
        from empire.server import server

        server.run(args)
    if args.subparser_name == "setup":
        sync_starkiller(config_manager.empire_config.starkiller)
        sync_empire_compiler(config_manager.empire_config.empire_compiler)

    sys.exit(0)
