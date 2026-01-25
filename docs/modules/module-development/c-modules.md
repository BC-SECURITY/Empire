# C# Modules

Empire originally adopted Covenant's YAML format for C# modules but has since forked this into Empire-Compiler, which has gradually evolved away from the original Covenant implementation. These modules are defined in YAML files that specify metadata, options, and the C# code to be executed through the .NET Roslyn compiler.

## Module Structure

A typical C# module YAML has the following structure:

```yaml
name: ModuleName
authors:
  - name: Author Name
    handle: AuthorHandle
    link: https://twitter.com/AuthorHandle
description: Module description
software: ''
tactics: [TA0002, TA0005]
techniques: [T1620]
background: false
output_extension: ''
needs_admin: false
opsec_safe: true
language: csharp
min_language_version: ''
options:
  - name: OptionName
    description: Option description
    required: true
    value: 'Default value'
    strict: false
    suggested_values: []
csharp:
  UnsafeCompile: false
  CompatibleDotNetVersions:
    - Net35
    - Net40
  Code: |
    using System;
    using System.IO;

    public static class Program
    {
        public static void Main(string[] args)
        {
            // Module implementation
        }
    }
  ReferenceSourceLibraries:
    - Name: LibraryName
      Description: Library description
      Location: LibraryPath
      Language: CSharp
      CompatibleDotNetVersions:
        - Net35
        - Net40
      ReferenceAssemblies:
        - Name: Assembly.dll
          Location: net35\Assembly.dll
          DotNetVersion: Net35
        - Name: AnotherAssembly.dll
          Location: net40\AnotherAssembly.dll
          DotNetVersion: Net40
      EmbeddedResources: []
  ReferenceAssemblies: []
  EmbeddedResources: []
```

Every section except for the 'csharp' section are the same as the other module languages.

The csharp section is what was derived from the Covenant yamls. The `csharp` section contains the actual C# code and compilation settings, including whether to allow unsafe code, which .NET Framework versions are compatible, and references to external libraries and resources.

## Advanced Generation

**custom\_generate:** For complex modules that require custom code that accesses Empire logic, such as lateral movement modules dynamically generating a listener launcher, a custom "generate" function can be used. To tell Empire to utilize the custom generate function, set `advanced.custom_generate: true`

Additional information about custom\__generate can be found under the_ [_PowerShell Modules custom\_generate_](https://bc-security.gitbook.io/empire-wiki/module-development/PowerShell-Modules#advanced)_._
