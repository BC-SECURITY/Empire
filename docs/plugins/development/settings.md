# Settings

Plugins can have state that persists through server restarts. There are different types of state.

## Settings

There are values that are defined in the same format as execution options. These options can be modified by the user and are persisted in the database.

"Settings" supports one extra option that execution options don't. "Editable" is a boolean that determines if the user can modify the value. If "Editable" is set to False, the value can be seen via the API, but not modified.

When getting the settings from within the plugin, use `self.current_settings(db)`, which will return the current settings values from the database.

```python
@override
def on_start(self, db):
    settings = self.current_settings(db)
    print(settings)
```

To set settings values, use `self.set_settings(db, settings)` where `settings` is a dict of the values you want to set, or `self.state_settings_option(db, key, value)` to set a single value.

```python
@override
def on_start(self, db):
    self.set_settings(db, {"key": "value"})
    self.set_settings_option(db, "key", "value")
```

### `on_settings_change`

When settings are updated, the `on_settings_change` function is called. This allows your plugin to react to changes in settings without needing to be restarted or continuously check the database.

```python
@override
def on_settings_change(self, db, settings):
    print(settings)
```

## Internal State

Internal state is state that is defined by the plugin and is not exposed via the API, but is persisted in the database. It can be accessed via `self.internal_state(db)`, and can be set via `self.set_internal_state(db, state)` or `self.set_internal_state_option(db, key, value)`.
