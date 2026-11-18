# C Agent Overview

The C agent (`Cpire`) is a native agent for Empire, modeled after the Go agent (Gopire). Windows (MinGW cross-compilation) is the supported target and produces a statically linked, standalone `.exe`. Linux builds are experimental: the binary links OpenSSL and libcurl dynamically, so the target needs the OpenSSL 3 (`libssl3`) and `libcurl4` runtimes and a glibc at least as new as the build host's. **Currently, the C agent supports the HTTP listener only.**

The C agent is only available in the [Sponsors](https://github.com/sponsors/BC-SECURITY) version of Empire.

Developer pages: [Agent Loop](agent-loop.md), [Comms & Routing](comms.md), [Template & Compiler](template.md).

## Prerequisites

To compile the C agent, the following are required:

- A C compiler (GCC or MinGW for cross-compilation)
- For Windows targets: `x86_64-w64-mingw32-gcc` (MinGW-w64 toolchain) and OpenSSL built for MinGW in `/opt/openssl-mingw64`
- For Linux targets: `libssl-dev` and `libcurl4-openssl-dev`

The Docker image provides all of these. `setup/install.sh` installs the Linux libraries and offers MinGW with OpenSSL for MinGW — answer `y`, or run it with `-y`; without MinGW every Windows build fails with `C compiler not found`.

## Compilation and Setup

The C agent is compiled server-side by the `CCompiler` class when you generate a `multi/c_exe` stager. The options are `Listener`, `TargetOS` (`windows` or `linux`), and `CC` / `CFLAGS` overrides; defaults, the compiler and flag allowlists, and the build steps are in [Template & Compiler](template.md#the-multic_exe-stager). The server saves the finished binary under its `downloads/generated-stagers/` directory — `multi/c_exe` has no `OutFile` option, so retrieve it from the stager's download. A build that fails surfaces as the stager-generation error `C build failed: <compiler output>`; a disallowed compiler as `Compiler '…' is not in the allowlist`. The build directory, including the rendered source and compiler intermediates that carry the listener's keys, is removed either way.

### Listener Option Validation

Every listener value the agent embeds is pasted into a C string literal, so stager generation rejects values that would break the build or inject C: the `Cookie` option must be an RFC 6265 cookie-name token, and no other embedded option may contain a quote, a backslash or a control character. The error names the listener option to fix. A listener whose `Cookie` contains a space or `;` cannot build a C agent until it is renamed; the default `session` and any ordinary name are unaffected. Details in [Template & Compiler](template.md#maintemplatec).

### Manual Compilation (Outside Empire)

The flags mirror `CCompiler._link_libraries`:

```bash
# Windows target (cross-compile from Linux)
x86_64-w64-mingw32-gcc -o cpire.exe main.c agent/*.c comms/*.c crypto/*.c tasks/*.c common/*.c profile/*.c \
  -I. -Iagent -Icomms -Icrypto -Itasks -Icommon -Iprofile \
  -I/opt/openssl-mingw64/include -L/opt/openssl-mingw64/lib64 \
  -lssl -lcrypto -lws2_32 -lwinhttp -lcrypt32 -lole32 -loleaut32 -ladvapi32 -static

# Linux target
gcc -o cpire main.c agent/*.c comms/*.c crypto/*.c tasks/*.c common/*.c profile/*.c \
  -I. -Iagent -Icomms -Icrypto -Itasks -Icommon -Iprofile \
  -lcrypto -lcurl -lpthread
```

Add `-DCPIRE_DEBUG` for a build that logs to a file; see [Debug builds](agent-loop.md#debug-builds).

## Features

- **Windows (supported) and Linux (experimental) targets**; no runtime dependencies on Windows.
- **Full staging**: DH key exchange with transcript-bound Ed25519 certificate verification, HKDF-SHA256 session and AES/HMAC keys, AES-CBC encrypt-then-HMAC payloads, and AES-256-GCM routing packets.
- **Encrypted comms**: HTTP/HTTPS via WinHTTP (Windows) or libcurl (Linux). TLS certificate validation is disabled on both.
- **Task execution**: Shell commands, PowerShell, C#/.NET assembly loading, and BOF (Beacon Object File) execution.
- **File operations**: File download (chunked), upload, and JSON directory listing.
- **Agent controls**: Delay/jitter, kill date, working hours, and lost-limit enforcement.
- **OPSEC**: No debug output in production builds.

## Communication

Tasking polls are `GET` requests to a random task URI from the listener's `DefaultProfile`, with the base64 routing packet in the cookie named by the listener's `Cookie` option; results are `POST`ed — the same shape as the Python and PowerShell agents.

### Lost limit and exit

A poll counts as a healthy check-in only if the listener answered with its default page (nothing to do) or with tasking that decrypted. Everything else is a missed check-in, and the agent exits when the number of consecutive missed check-ins reaches the lost limit (`DefaultLostLimit`; `0` disables it). Three things follow for an operator:

- A `401` on a tasking poll ends the agent at once. The listener sends it when it still accepts the staging key but no longer has the session, typically after the agent was archived and the server restarted. Behind `hop.php` the agent instead exits at the lost limit.
- A body-rewriting proxy or block page in front of the listener ends an idle agent after lost-limit polls.
- A staging-key mismatch is invisible: the listener answers a packet it rejects with its default page, so the agent reads it as idle until its kill date.

The full decision table is in [Agent Loop](agent-loop.md#what-one-poll-means).

### Working hours

`WorkingHours` is `HH:MM-HH:MM` in the target's local time. Outside the window the agent sleeps a minute at a time without polling. A window whose end is before its start wraps midnight (`22:00-06:00`), equal start and end means all day, and an empty or unparsable value never blocks.

## Supported Tasks

| Task ID | Name | Description |
|---------|------|-------------|
| 1 | SYSINFO | Collect system information |
| 2 | EXIT | Terminate the agent |
| 10/12 | SET/GET_DELAY | Set or query delay and jitter |
| 30/31 | SET/GET_KILLDATE | Set or query kill date |
| 32/33 | SET/GET_WORKING_HOURS | Set or query working hours |
| 40 | SHELL | Execute a shell command |
| 41 | DOWNLOAD | Download a file from target (chunked) |
| 42 | UPLOAD | Upload a file to target |
| 43 | DIR_LIST | List directory contents (JSON) |
| 100 | POWERSHELL | Execute PowerShell script (wait for output) |
| 101 | POWERSHELL_CMD_WAIT | Execute PowerShell with save-file prefix |
| 102 | POWERSHELL_CMD_JOB | Execute PowerShell (background) |
| 120 | CSHARP_CMD_WAIT | Load and execute .NET assembly |
| 121 | CSHARP_CMD_WAIT (save) | Load .NET assembly with save-file prefix |
| 122 | CSHARP_CMD_JOB | Load .NET assembly (background) |
| 123 | CSHARP_CMD_JOB (save) | Load .NET assembly background with save-file |
| 130 | BOF_CMD_WAIT | Execute Beacon Object File |

## Security

Server-side compilation validates the compiler and its flags against allowlists and rejects listener values that are unsafe inside a C string literal. On a normal shutdown (kill date, lost limit, 401) the agent zeros all key material with `OPENSSL_cleanse` before freeing it; the `EXIT` task terminates the process immediately.
