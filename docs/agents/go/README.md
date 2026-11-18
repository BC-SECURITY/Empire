# Go Agent Overview

The Go agent (`Gopire`) is a lightweight and portable agent for Empire, designed for environments where performance and portability are critical. It supports tasking execution and communication with the Empire server in a secure and covert manner. **Currently, the Go agent only supports Windows, and the HTTP and HTTP[S] MALLEABLE listeners**.

## Prerequisites

To compile the Go agent, the following are required:

- Go 1.17+

## Compilation and Setup

The Go agent is currently limited to Windows environments. To compile outside the Empire server:

```bash
GOOS=windows GOARCH=amd64 go build -o gopire_stager.exe main.go
```

## Features
- Windows-only support: The Go agent currently only targets Windows environments.
- Evasion Techniques: Reflectively loaded and does not leave a significant trace on disk.
- Task Execution: Executes commands and taskings sent from the Empire server.
- Backgrounded Jobs: Long-running PowerShell tasks can run as backgrounded jobs, which can be stopped early via the `TASK_STOPJOB` task.
- Encryption: Secure communications using AES-256-GCM and AES-CBC encryption.
- Profiles: Supports different communication profiles to evade network detection.
- Listener Support: the HTTP and HTTP[S] MALLEABLE listeners.
- Polling: tasking polls are GETs carrying the base64 routing packet in the listener's session cookie (the `Cookie` option); results are POSTed. On a malleable listener the profile's `get` section carries polls and `post` carries results.
- Lost limit: a 401 on a tasking poll (the server no longer knows the session) ends the agent; a 401 on a results POST is ignored and the next poll catches it. The lost limit counts consecutive failed polls — transport errors, the 120 s request timeout, non-200s, and 200s that are neither the listener's idle answer nor tasking that decrypts — and `0` disables it. Two failures are invisible to the agent and do not count: the `http` listener answers a routing packet it rejects (bad key, malformed packet) with its default page, and a malleable profile whose output terminator is a header or parameter reads a stripped header as idle.
