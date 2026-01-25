# Lifecycle Hooks

## on\_load

The `on_load` function is called when the plugin is loaded into memory.

```python
@override
def on_load(self, db):
    print("Plugin loaded")
```

## on\_unload

The `on_unload` function is called when the plugin is unloaded from memory.

```python
@override
def on_unload(self, db):
    print("Plugin unloaded")
```

## on\_start

The `on_start` function is called when the plugin is started.

```python
@override
def on_start(self, db):
    print("Plugin started")
```

## on\_stop

The `on_stop` function is called when the plugin is stopped.

```python
@override
def on_stop(self, db):
    print("Plugin stopped")
```
