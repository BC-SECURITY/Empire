# Agents

This page provides an in-depth overview of the different agents available within Empire, including their capabilities, features, and usage scenarios.

## IronPython Agent

IronPython brings the Python language to the .NET framework. The IronPython agent leverages this to execute Python scripts using .NET, bypassing restrictions on native Python interpreters. Additional documentation on the agent can be found [here](python/).

### Features

* Executes in a .NET context, allowing for unique evasion techniques.
* Can interface with .NET libraries directly from Python code.
* Runs Python, C#, and PowerShell taskings.

## Python Agent

The Python agent offers cross-platform capabilities for targeting non-Windows systems, such as Linux and macOS. Additional documentation on the agent can be found [here](python/).

### Features

* Cross-platform for Linux and macOS.

## Go Agent

The Go agent (`Gopire`) is designed for use in environments where Go is advantageous for performance and portability. It is lightweight and suitable for Windows systems. **Currently, the Go agent only supports Windows and the HTTP listener.** Future updates may include cross-platform support.

### Features

* **Currently only Windows compatible.**
* Written in Go, providing performance and portability benefits.
* Can run taskings such as C#, PowerShell, and shell commands.
* Reflectively loaded to evade detection.
* **Supports only the HTTP listener.**

Additional documentation on the agent can be found [here](go/).

## PowerShell Agent

The PowerShell agent is the original agent for Empire.

### Features:

* Reflectively loads into memory.
* Can run C# and PowerShell taskings.

## C# Agent

The C# agent leverages [Sharpire](https://github.com/BC-SECURITY/Sharpire) as the implant.

### Features

* Can run C# and PowerShell taskings.
