# Module Configuration

Each module defines:

* **Options**: Required and optional parameters exposed to the operator.
* **Language**: The runtime environment the agent must support (PowerShell, Python, C#, etc.).
* **Opsec notes**: Guidance on how noisy the module may be or what artifacts it leaves behind.
* **Background execution**: Whether the module runs synchronously or can be queued for later execution.

Reading the module description and options carefully helps avoid failed tasks and reduces unnecessary network or disk activity.

#### Dynamic Options

Some modules populate or reveal option values dynamically based on other option selections. When you open a module, Empire evaluates these relationships so the UI only shows the options that are relevant to the current configuration. This keeps the option list shorter and helps avoid invalid combinations.

For detailed, YAML-backed examples of dynamic options (including `depends_on`, `suggested_values`, and `internal`), see the module development documentation in Module Development.
