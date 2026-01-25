# Go

The Go agent (`Gopire`) is a lightweight and portable agent for Empire, designed for environments where performance and portability are critical. It supports tasking execution and communication with the Empire server in a secure and covert manner. **Currently, the Go agent only supports Windows and the HTTP listener**.

## Prerequisites

To compile the Go agent, the following are required:

* Go 1.17+

## Compilation and Setup

The Go agent is currently limited to Windows environments. To compile outside the Empire server:

```bash
GOOS=windows GOARCH=amd64 go build -o gopire_stager.exe main.go
```

## Features

* Windows-only support: The Go agent currently only targets Windows environments.
* Evasion Techniques: Reflectively loaded and does not leave a significant trace on disk.
* Task Execution: Executes commands and taskings sent from the Empire server.
* Encryption: Secure communications using AES encryption.
* Profiles: Supports different communication profiles to evade network detection.
* HTTP Listener Support: Only supports the HTTP listener for communication with the Empire server.
