# Empire Modules

Modules are driven by a yaml configuration per module. In most cases, only a yaml is needed to create a module.

{% embed url="https://youtu.be/ZS3Rdld_Ebo" %}

## Basic Structure
Each module is defined by a set of metadata (like authors, description, and tactics) and options. These options define what values can be set when the module is executed.

```yaml
name: ExampleModule
authors:
  - name: John Doe
    handle: '@johndoe'
description: A sample module demonstrating Empire module structure.
tactics: []
techniques:
  - T1234
background: true
output_extension: ps1
needs_admin: false
opsec_safe: true
language: powershell
min_language_version: '2'
comments: []
options:
  - name: SampleOption
    description: An example option.
    required: true
    value: 'default_value'
    strict: true
```

## Special Options

Empire reserves certain option names that receive special handling during module execution. These are filtered out of the parameters passed to the module's script and instead control how the task is dispatched or processed.

### Agent
**Required on all modules.** Identifies which agent should execute the module. This is automatically populated by Empire and should not be included in the module's script logic.

### Background
Allows the operator to override the module-level `background` field at runtime. When a module defines `background: true` in its YAML metadata, it will run as a background job by default. Adding a `Background` option lets operators choose per-execution whether to run in the foreground or background.

```yaml
options:
  - name: Background
    description: Run as a background job (non-blocking). Can be killed via the jobs/kill_job endpoint.
    required: false
    value: 'true'
    type: bool
    suggested_values:
      - 'true'
      - 'false'
    strict: true
```

If the `Background` option is not defined on the module, the module-level `background` field is used as-is.

### OutputFunction
PowerShell-specific. Controls how module output is formatted. Substituted into the script via the `{{ OUTPUT_FUNCTION }}` placeholder. Defaults to `Out-String`. See [PowerShell Modules](powershell-modules.md) for details.

## Advanced Options
Empire modules support advanced configuration for dynamic dependencies between options. For example, one option may depend on the value of another option. This is handled using the `depends_on` field.

### Dynamic Option Dependencies
The `depends_on` field allows an option to be displayed or required based on the value of another option. In this example, the `CredID` option only appears if the `Credentials` option is set to `CredID`.

```yaml
options:
  - name: Credentials
    description: Manually enter credentials or credential ID.
    required: true
    value: 'Manual'
    strict: true
    internal: true
    suggested_values:
      - Manual
      - CredID
  - name: CredID
    description: Use CredID from the store.
    required: false
    value: ''
    depends_on:
      - name: Credentials
        values: ['CredID']
```

## Internal Options
The internal field is used to manage dynamic options in Empire modules, such as top-tier switches that control which options are displayed to the user. These options are internal to Empire’s logic and are not used during the execution of the module itself. Instead, they help control the visibility and behavior of other options.

For example, an internal option can act as a switch to determine whether certain options appear based on the user’s selection.

```yaml
- name: Credentials
  description: Manually enter credentials or credential ID.
  required: true
  value: 'Manual'
  strict: true
  internal: true
  suggested_values:
    - Manual
    - CredID
```

In this example, Credentials is an internal option that controls whether CredID or Password is shown to the user, depending on its value. This logic helps ensure the correct options are visible and modifiable based on the selected configurations.

```yaml
options:
  - name: Credentials
    description: Manually enter credentials or credential ID.
    required: true
    value: 'Manual'
    strict: true
    internal: true
    suggested_values:
      - Manual
      - CredID
  - name: CredID
    description: CredID from the store to use.
    required: false
    value: ''
    depends_on:
      - name: Credentials
        values: ['CredID']
  - name: Password
    description: Password for manual credentials entry.
    required: false
    value: ''
    depends_on:
      - name: Credentials
        values: ['Manual']
```
