# Development

## Getting Started

The hello world plugin is an example plugin that can be found in the `empire/server/plugins/example` directory.

```
empire/server/plugins/example
├── __init__.py
├── example.py
└── plugin.yaml
```

## plugin.yaml

```yaml
name: example
authors:
  - name: Author 1
    handle: '@author1'
    link: https://twitter.com/author1
# Software and tools that from the MITRE ATT&CK framework (https://attack.mitre.org/software/)
software:
# Techniques that from the MITRE ATT&CK framework (https://attack.mitre.org/techniques/enterprise/)
techniques:
  - TXXXX
  - TXXXX
# The entry point for the plugin. The file that contains the `Plugin` class.
main: example.py
# Extra dependencies that the plugin requires.
# Empire will not automatically install these dependencies, but
# will check if they are installed before running the plugin.
# Starkiller may tell the user to install these dependencies when it is installed via the marketplace.
python_deps:
  - requests>=2.25.1
  - pyyaml
```

The `example.py` file contains the plugin class. The class must be named `Plugin` and must inherit from `empire.server.common.plugins.BasePlugin`.

```python
class Plugin(BasePlugin):
    ...
```
