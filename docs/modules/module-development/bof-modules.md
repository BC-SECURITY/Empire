# BOF Modules

BOF modules are configured similarly to PowerShell modules with a few key differences:

* The `script`, `script_path`, and `script_end` fields are no longer used.
* `bof.x86` and `bof.x64` refer to the path of the beacon object file for each architecture (x86 and x64).
* `bof.entry_point` is an optional field to define the object file's entry point.
* An `Architecture` field is required.
* `format_string` is used to define how data should be passed.

### Format String

| Type  | Description                                    | Unpack With (C)     |
| ----- | ---------------------------------------------- | ------------------- |
| **b** | Binary data                                    | `BeaconDataExtract` |
| **i** | 4-byte integer                                 | `BeaconDataInt`     |
| **s** | 2-byte short integer                           | `BeaconDataShort`   |
| **z** | Zero-terminated + encoded string               | `BeaconDataExtract` |
| **Z** | Zero-terminated wide-char string (`wchar_t *`) | `BeaconDataExtract` |

## Example BOF

```yaml
options:
  - name: Architecture
    description: Architecture of the beacon_funcs.o to generate with (x64 or x86).
    required: true
    value: x64
    strict: true
    suggested_values:
      - x64
      - x86
  - name: Filepath
    description: Filepath to search for permissions.
    required: true
    value: 'C:\\windows\\system32\\cmd.exe'
    format: Z
bof:
  x86: bof/situational_awareness/cacls.x86.o
  x64: bof/situational_awareness/cacls.x64.o
  entry_point: ''
  format_string: Z
```

BOF modules also support the `advanced.custom_generate` method of generating the script.
