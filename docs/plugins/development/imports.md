# Imports

Add a `__init__.py` file to your plugin directory to make it a package.

If you want to import other python files in your plugin, you can do so by importing them relative to your entrypoint.

For example, if you have a file called `example_helpers.py` in the same directory as your plugin, you can import it like so:

```python
from . import example_helpers
```
