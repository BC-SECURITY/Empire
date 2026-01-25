# Migration

This is an exhaustive list of changes that have been made to the plugin system between major Empire versions.

## 4->5 Migration

Not a lot has changed for plugins in Empire 5.0. We've just added a few guard rails for better stability between Empire versions.

The plugin interface is a guarantee that certain functionality will not be changed outside of major Empire version updates (ie 4->5). So which functions are guaranteed? Any of the functions on the `core/*_service` classes not prefixed with a `_`.

Does this mean you can't use `util` functions or modify state in other parts of the empire code? No. In most cases you will be fine to do so. We as maintainers just can't keep track of any and every thing a plugin may be doing and guarantee that it won't break in a minor/patch update. This is no different than the way things were pre 5.0.

* Make sure `self.info` is a dict and not a tuple. A lot of plugins had a trailing comma that caused it to be interpreted as a tuple.
* Update `Author` to `Authors` and follow the new format (Link, Handle, Name)
* The execute plugin endpoint no longer automatically changes the state of the `self.options` dict inside the plugin. Instead, it sends validated parameters to the plugin as a dict and the plugin itself should decide whether it makes sense to modify the internal state or not.
* `plugin_socketio_message` was moved from `MainMenu` to `plugin_service`.
* Example conversion for a 5.0 plugin can be seen in [ChiselServer-Plugin](https://github.com/BC-SECURITY/ChiselServer-Plugin/compare/5.0)

## 5->6 Migration

* self.info is now an object of type `PluginInfo` instead of a dict
  * `self.info["Name"]` is now `self.info.name`
* plugins now require a `plugin.yaml` file (added in 5.9)
* all `self.info` fields are now in the `plugin.yaml` file
* `.plugin` files are no longer supported and won't be loaded
* The `Plugin` class is now called `BasePlugin`
* Plugin constructors now take a `PluginInfo` object as the second positional argument
* Removed `Category` from `PluginInfo` which was not used
* Plugin execute function must take `**kwargs`
* Plugin name is now based on the name in the `plugin.yaml` file instead of the filename
* `mainMenu` is now `main_menu`
* BasePlugin moved from common to core
* Sending socketio messages can now be done via `self.send_socketio_message` which will automatically use the correct plugin id
* `onLoad` renamed to `on_load` and receives a `db` object
* Plugins can now be turned on and off via the API without needing to use the `execute` function
  * Plugins have an `enabled` boolean attribute that is set in the database and on the plugin object
* Lifecycle functions -
  * `on_load` - When the plugin is loaded into memory
  * `on_unload` - When the plugin is unloaded from memory
  * `on_start` - When the plugin is started
  * `on_stop` - When the plugin is stopped
* `register` function was removed
* `install_path` is automatically set on `BasePlugin` constructor
* Plugins have an internal state that can be defined in a similar way to execution and module options
  * Internal state persists through database restarts
* `options` is now `execution_options`
* New config options -
  * `auto_start` - Automatically start the plugin when Empire starts
    * If using `auto_start`, the default settings should be valid
  * `auto_execute` - Automatically execute the plugin when Empire starts
* Execution can be disabled by setting `self.execution_enabled = False`
* `PluginTask` should now use the id of the plugin instead of the name
