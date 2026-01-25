# Python Modules

Python modules are not much different from PowerShell modules in terms of the yaml schema. The differences for Python come in with the `script`, `script_path`, `script_end`, and option formatters.

A python script doesn't have an `option_format_string`. Instead, options are injected into the script directly using mustache templating. An example of this is the python module [say](https://github.com/BC-SECURITY/Empire/blob/master/empire/server/modules/python/trollsploit/osx/say.yaml).

```yaml
options:
  - name: Agent
    description: Agent to run module on.
    required: true
    value: ''
  - name: Text
    description:
    required: true
    value: 'The text to speak.'
  - name: Voice
    description: The voice to use.
    required: true
    value: 'alex'
script: run_command('say -v {{ Voice }} {{ Text }}')
```

Python modules also support the `advanced.custom_generate` method of generating the script. Python modules can be used with `script` OR `script_path` and will ignore `script_end`, `option_format_string`, and `option_format_string_boolean`.
