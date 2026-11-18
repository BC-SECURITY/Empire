# Empire Agents Overview
This page provides an in-depth overview of the different agents available within Empire, including their capabilities, features, and usage scenarios.

## Shell Commands & Working Directory

As of Empire 7.0, the PowerShell, Python, and IronPython agents no longer intercept a built-in set of `shell` aliases (`ls`, `cd`, `pwd`, `ps`, `ipconfig`, etc.). A `shell <cmd>` task always passes the command straight to the underlying system shell, matching the C# and Go agents' existing behavior. Two structured replacements cover what the aliases used to provide:

- **Structured output**: the `situational_awareness/host/{processes,ipconfig,route,dir_list}` modules (PowerShell; `processes` also has a Python variant) return the same information as JSON instead of raw shell text.
- **Persistent working directory**: `POST /api/v2/agents/{id}/tasks/chdir` issues `TASK_CHDIR`, which changes the agent's working directory for all subsequent shell tasks until another `chdir` is issued.

## File Uploads

As of Empire 7.0, `POST /api/v2/agents/{id}/tasks/upload` no longer caps uploads at 1MB. Files up to 512KB are sent as a single task; anything larger is split into 512KB chunks and dispatched one per checkin, with the agent appending each chunk to the destination file as it arrives. A large upload therefore completes over several checkins instead of failing outright.

Chunking is automatic and applies to every agent language — the request shape is unchanged and there is no chunk-size option to set.

## IronPython Agent
IronPython brings the Python language to the .NET framework. The IronPython agent leverages this to execute Python scripts using .NET, bypassing restrictions on native Python interpreters. Additional documentation on the agent can be found [here](./python/README.md).

### Features
- Executes in a .NET context, allowing for unique evasion techniques.
- Can interface with .NET libraries directly from Python code.
- Runs Python, C#, and PowerShell taskings.

## Python Agent
The Python agent offers cross-platform capabilities for targeting non-Windows systems, such as Linux and macOS. Additional documentation on the agent can be found [here](./python/README.md).

### Features
- Cross-platform for Linux and macOS.

## Go Agent
The Go agent (`Gopire`) is designed for use in environments where Go is advantageous for performance and portability. It is lightweight and suitable for Windows systems. **Currently, the Go agent only supports Windows.** Future updates may include cross-platform support.

### Features
- **Currently only Windows compatible.**
- Written in Go, providing performance and portability benefits.
- Can run taskings such as C#, PowerShell, and shell commands.
- Reflectively loaded to evade detection.
- Supports the HTTP, HTTP Malleable, and Port Forward listeners.

Additional documentation on the agent can be found [here](./go/README.md).

## C Agent
The C agent (`Cpire`) is an experimental native agent modeled after the Go agent. It compiles into a native binary: Windows (statically linked, via MinGW) is the supported target and Linux builds are experimental. **Currently, the C agent supports the HTTP listener only.**

The C agent is only available in the [Sponsors](https://github.com/sponsors/BC-SECURITY) version of Empire.

### Features
- Windows (supported) and Linux (experimental) targets.
- Native compiled binary; no runtime dependencies on Windows.
- Runs PowerShell, C#, BOF, and shell taskings.
- Full DH key exchange staging with transcript-bound Ed25519 certificate verification.
- File download/upload and directory listing.
- Agent controls: delay/jitter, kill date, working hours, lost-limit enforcement; exits when the server no longer knows its session.

Additional documentation on the agent can be found [here](./c/README.md).

## PowerShell Agent
The PowerShell agent is the original agent for Empire.

### Features:
- Reflectively loads into memory.
- Can run C# and PowerShell taskings.

## C# Agent
The C# agent leverages [Sharpire](https://github.com/BC-SECURITY/Sharpire) as the implant.

### Features
- Can run C# and PowerShell taskings.
