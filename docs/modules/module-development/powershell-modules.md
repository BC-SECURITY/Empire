# PowerShell Modules

The [powershell\_template.yaml](https://github.com/BC-SECURITY/Empire/blob/master/empire/server/modules/powershell_template.py) will help guide through the fields needed for writing a simple module. Of course, not every module will fit the simplest case. There are advanced options that we will discuss below.

The property `options` is a list of the options that can be set for the module at execution time. All modules must contain an option called **Agent**. Additional options go in the options list after the **Agent** argument. If the argument is required for execution, set `required: true`, and if a default value is warranted, set `value`. The [prompt module](https://github.com/BC-SECURITY/Empire/blob/master/empire/server/modules/powershell/collection/prompt.yaml) has an example of this.

When Empire boots up, it loads all module yamls found in the modules directory. If there are any missing fields or misconfigurations, the module won't load and a warning will print to the console.

## Defining the script

**script:** For most scripts, simply pasting the script into the yaml is good enough.

```yaml
script: |
  Function Invoke-Template {

  }
```

**script\_path:** For longer scripts, or scripts that are shared between multiple modules, it is recommended to put the text file into the `empire/server/data/module_source` directory and reference it like so:

```yaml
script_path: 'empire/server/data/module_source/credentials/Invoke-Mimikatz.ps1'
```

The above example comes from the [logonpasswords module.](https://github.com/BC-SECURITY/Empire/blob/master/empire/server/modules/powershell/credentials/mimikatz/logonpasswords.yaml)

**script\_end:** In most cases the `script_end` will simply be a call to to the powershell function with a mustache template variable called `$PARAMS`. `{{ PARAMS }}` is where Empire will insert the formatted options.

```yaml
script_end: Invoke-Function {{ PARAMS }}
```

There are functions that require the script\_end to be customized a bit further. For example: the one found in [Invoke-Kerberoast](https://github.com/BC-SECURITY/Empire/blob/master/empire/server/modules/powershell/credentials/invoke_kerberoast.yaml)

```yaml
script_end: Invoke-Kerberoast {{ PARAMS }} | fl | {{ OUTPUT_FUNCTION }} | %{$_ + "`n"};"`nInvoke-Kerberoast completed!
```

## Advanced

### **Custom Generate**

**custom\_generate:** For complex modules that require custom code that accesses Empire logic, such as lateral movement modules dynamically generating a listener launcher, a custom "generate" function can be used. To tell Empire to utilize the custom generate function, set `advanced.custom_generate: true`

```yaml
advanced:
  custom_generate: true
```

The python file should share the same name as the yaml file. For example `Invoke-Assembly.yaml` and `Invoke-Assembly.py` The generate function is a static function that gets passed 5 parameters:

* main\_menu: The main\_menu object that gives the module access to listeners, stagers, and just about everything else it might need
* module: The module, loaded from the yaml. In case we need to check properties like `opsec_safe`, `background`, etc.
* params: The execution parameters. At this point, Empire has already validated the parameters provided are the correct parameters for this module, and that the required parameters are there.
* obfuscate: Whether to obfuscate the code
* obfuscation\_command: The command to use to obfuscate the code

It returns the generated code to be run by the agent as a string.

The generate function **should** treat these parameters as read only, to not cause side effects.

```python
class Module(object):
    @staticmethod
    def generate(
        main_menu: MainMenu,
        module: EmpireModule,
        params: dict,
        obfuscate: bool = False,
        obfuscation_command: str = "",
    ):
```

Examples of modules that use this custom generate function:

* [bypassuac\_eventvwr](https://github.com/BC-SECURITY/Empire/blob/master/empire/server/modules/powershell/privesc/bypassuac_eventvwr.py)
* [invoke\_assembly](https://github.com/BC-SECURITY/Empire/blob/master/empire/server/modules/powershell/code_execution/invoke_assembly.py)
* [seatbelt](https://github.com/BC-SECURITY/Empire/blob/master/empire/server/modules/powershell/situational_awareness/host/seatbelt.py)

#### Error Handling

If an error occurs during the execution of the generate function and it goes unchecked, the client will receive a 500 error.

There are two Exceptions that can be raised by the generate function: **ModuleValidationException**: This exception should be raised if the module fails validation. This will return a 400 error to the client with the error message. **ModuleExecutionException**: This exception should be raised if the module fails execution. This will return a 500 error to the client with the error message.

```python
raise ModuleValidationException("Error Message")
raise ModuleExecutionException("Error Message")
```

**Deprecated**

Previously, it was recommended that the generate function return a tuple of the script and the error. `handle_error_message` was provided as a helper function to handle this tuple.

This is no longer recommended, but is still supported. Please migrate away from the tuple return type to raising exceptions. The tuple return type will be removed in a future major release.

#### Functions

`get_module_source` is used pull the script from the yaml file defined in **script\_path**. Once the script has been loaded, it will determine if obfuscation is enabled and obfuscate it.

`finialize_module` will combine the `script` and `script_end` into a single script and then will apply obfuscation, if it is enabled.

#### Decorators

`@auto_get_source` is a decorator that will automatically call `get_module_source` and pass the script to the decorated function. To use this decorator, the function must have a `script` kwarg and the `script_path` must be set in the yaml config.

```python
@staticmethod
@auto_get_source
def generate(
    main_menu: MainMenu,
    module: EmpireModule,
    params: dict,
    obfuscate: bool = False,
    obfuscation_command: str = "",
    script: str = "",
):
    # do stuff
    ...

# The above is the equivalent of:
@staticmethod
def generate(
    main_menu: MainMenu,
    module: EmpireModule,
    params: dict,
    obfuscate: bool = False,
    obfuscation_command: str = "",
):
    # read in the common module source code
    script, err = main_menu.modulesv2.get_module_source(
        module_name=module.script_path,
        obfuscate=obfuscate,
        obfuscate_command=obfuscation_command,
    )

    if err:
        return handle_error_message(err)

    # do stuff
    ...
```

`@auto_finalize` is a decorator that will automatically call `finalize_module` on the returned script from the decorated function.

To use this decorator, the function must not utilize the deprecated tuple return type or the `handle_error_message` function. First migrate the function to raise exceptions before using this decorator.

```python
@staticmethod
@auto_finalize
def generate(
    main_menu: MainMenu,
    module: EmpireModule,
    params: dict,
    obfuscate: bool = False,
    obfuscation_command: str = "",
):
    # Do stuff

    return script, script_end

# The above is the equivalent of:
@staticmethod
def generate(
    main_menu: MainMenu,
    module: EmpireModule,
    params: dict,
    obfuscate: bool = False,
    obfuscation_command: str = "",
):
    # Do stuff

    script, script_end = main_menu.modulesv2.finalize_module(
        script=script,
        script_end=script_end,
        obfuscate=obfuscate,
        obfuscate_command=obfuscation_command,
    )

    return script
```

### String Formatting

**option\_format\_string:** This tells Empire how to format all of the options before injecting them into the `script_end`. In most cases, the default option format string will be fine: `-{{ KEY }} "{{ VALUE }}"`.

**option\_format\_string\_boolean:** This tells Empire how to format boolean parameters when `True`. In most cases, the default format string will be fine: `-{{ KEY }}`.

[Rubeus](https://github.com/BC-SECURITY/Empire/blob/master/empire/server/modules/powershell/credentials/rubeus.yaml) is an example of a module that overwrites the option\_format\_string, since it only has one parameter `Command` and deviates from the default:

```yaml
options:
  - name: Agent
    description: Agent to run module on.
    required: true
    value: ''
  - name: Command
    description: Use available Rubeus commands as a one-liner.
    required: false
    value: ''
script_path: 'empire/server/data/module_source/credentials/Invoke-Rubeus.ps1'
script_end: "Invoke-Rubeus -Command \"{{ PARAMS }}\""
advanced:
  option_format_string: "{{ VALUE }}"
  option_format_string_boolean: ""
```

**name\_in\_code**: There may be times when you want the display name for an option in Starkiller to be different from how it looks in the module's code. For this, you can use `name_in_code` such as in the [sharpsecdump module](https://github.com/BC-SECURITY/Empire/blob/master/empire/server/modules/powershell/credentials/sharpsecdump.yaml)

```yaml
  - name: Username
    name_in_code: u
    description: Username to use, if you want to use alternate credentials to run. Must
      use with -p and -d flags, Misc)
    required: false
    value: ''
  - name: Password
    name_in_code: p
    description: Plaintext password to use, if you want to use alternate credentials
      to run. Must use with -u and -d flags
    required: false
    value: ''
```

**suggested\_values**: A list of suggested values can be provided for an option. These values will be available in Starkiller as autocomplete values.

**strict**: If true, the option validator will check that the value chosen matches a value from the suggested values list.

**type**: If a type is defined, the API will automatically validate the option value against the type. The following types are supported:

* bool
* int
* float
* str
* file

A 'file' option type should be an integer that corresponds to the `download` id of a file already on the empire server. The API will automatically validate that the file exists. If a `custom_generate` function is used, the whole database object for the file will be passed to the function.

{% hint style="info" %}
Note: Starkiller will automatically give file options with a dropdown or upload. If you are using the REST API directly, you will need to supply the file download ID.
{% endhint %}

**OUTPUT\_FUNCTION**: Some PowerShell modules have an option named `OutputFunction` that converts the output to json, xml, etc. The `OutputFunction` option can be inserted anywher in the `script` and `script_end` by using `{{ OUTPUT_FUNCTION }}`.

* An example of this in a yaml can be seen in [sherlock](https://github.com/BC-SECURITY/Empire/blob/master/empire/server/modules/powershell/privesc/sherlock.yaml).
* If a module uses a `custom_generate` function, it needs to perform this substitution on its own.
