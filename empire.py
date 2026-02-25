#! /usr/bin/env python3

import logging
import sys

from empire import arguments
from empire.server.common import empire
from empire.server.core.config import config_manager
from empire.server.core.config.data_manager import (
    sync_empire_compiler,
    sync_plugin_registry,
    sync_starkiller,
)
from empire.server.core.db import base
from empire.server.core.db.base import SessionLocal
from empire.server.core.exceptions import PluginValidationException
from empire.server.server import run

log = logging.getLogger(__name__)

if __name__ == "__main__":
    args = arguments.args

    if args.subparser_name == "server":
        run(args)
    if args.subparser_name == "setup":
        sync_starkiller(config_manager.empire_config.starkiller)
        sync_empire_compiler(config_manager.empire_config.empire_compiler)
        for registry in config_manager.empire_config.plugin_marketplace.registries:
            sync_plugin_registry(registry)

        auto_install = config_manager.empire_config.plugin_marketplace.auto_install
        if auto_install:
            base.startup_db()
            main = empire.MainMenu(args=args)

            with SessionLocal.begin() as db:
                for entry in auto_install:
                    try:
                        main.pluginregistriesv2.install_plugin(
                            db, entry.name, entry.version, entry.registry
                        )
                        log.info(
                            f"Auto-install: plugin '{entry.name}' v{entry.version} installed"
                        )
                    except PluginValidationException as e:
                        log.info(f"Auto-install: skipping '{entry.name}': {e}")
                    except Exception:
                        log.error(
                            f"Auto-install: failed to install '{entry.name}'",
                            exc_info=True,
                        )

            main.shutdown()

    sys.exit(0)
