# Template & Compiler

A C agent is built on the server for each stager request: `main.template.c` is
rendered with the listener's values, compiled together with the rest of the
cpire sources, and the resulting binary is returned to the operator. Nothing is
compiled on the target.

## `main.template.c`

The template is a short `main()`: it declares one `static const char *` per
template variable, parses the numeric ones with fallbacks (`DELAY` → 5 s,
`JITTER` → 0, `LOST_LIMIT` → 0), fills a `cpire_config`, and runs
`cpire_agent_create` → `cpire_run_agent` → `cpire_agent_destroy`.

| Template variable | Comes from | Notes |
|-------------------|------------|-------|
| `HOST` | listener `Host` | scheme and host; the port only when it is not the scheme default |
| `PROFILE` | listener `DefaultProfile` | pipe-separated task URIs, User-Agent and extra headers (see [Comms & Routing](comms.md#comms-context)) |
| `SESSION_COOKIE` | listener `Cookie` | cookie name carrying tasking polls |
| `DELAY`, `JITTER`, `LOST_LIMIT` | listener `DefaultDelay`, `DefaultJitter`, `DefaultLostLimit` | `LOST_LIMIT` `0` disables the lost limit |
| `KILL_DATE`, `WORKING_HOURS` | listener `KillDate`, `WorkingHours` | `MM/DD/YYYY`, `HH:MM-HH:MM` |
| `SESSION_ID` | fixed `00000000` | placeholder; the server assigns the real ID at stage 1 |
| `STAGING_KEY`, `DEFAULT_RESPONSE` | listener `StagingKey`, the listener's default page | base64 |
| `AGENT_PRIVATE_CERT_KEY`, `AGENT_PUBLIC_CERT_KEY`, `SERVER_PUBLIC_CERT_KEY` | the server's staging certificates | base64 |

Every value is pasted into a C string literal, so the server validates them
before rendering (`_validate_c_template_vars` in
`empire/server/core/stager_generation_service.py`): `SESSION_COOKIE` must match
the RFC 6265 cookie-name token class (letters, digits and `` !#$%&'*+-.^_`|~ ``),
and no other value may contain `"`, `\` or a control character. A violation
fails stager generation with an error that names the listener option to fix,
for example:

```
Listener 'http' option Cookie (SESSION_COOKIE) must be a cookie name: letters, digits and !#$%&'*+-.^_`|~ only.
```

## The `multi/c_exe` stager

| Option | Description | Default |
|--------|-------------|---------|
| `Listener` | Listener to build for (required) | – |
| `TargetOS` | `windows` or `linux` | `windows` |
| `CC` | Compiler override | `CC` env var, else `x86_64-w64-mingw32-gcc` (Windows) / `gcc` (Linux) |
| `CFLAGS` | Extra compiler flags | `CFLAGS` env var |
| `StagerRetries` | Unused by the C agent | `0` |

`generate()` calls `StagerGenerationService.generate_c_stageless`, reads the
binary, and removes the build directory — compiler intermediates such as `main.i`
carry the listener keys, so the whole `mkdtemp()` directory goes, not just the
binary. The stager framework then saves the bytes under the server's
`downloads/generated-stagers/` directory.

## `CCompiler` (`empire/server/core/c.py`)

`compile_stager(template_vars, task_name, cc, cflags, target_os)`:

1. **Validate the toolchain.** `CC` (option or environment) must be in
   `ALLOWED_COMPILERS` (`gcc`, `cc`, `clang`, `musl-gcc`,
   `x86_64-w64-mingw32-gcc`, `i686-w64-mingw32-gcc`, `aarch64-linux-gnu-gcc`)
   and must resolve on `PATH`. `CFLAGS` may not contain `DANGEROUS_CFLAGS` —
   flags that run code or read arbitrary files at compile time (`-fplugin`,
   `-include`, `-imacros`, `-Xlinker`, `--script`, `-specs`, `-wrapper`,
   `@file`).
2. **Render** `main.template.c` to `main.c` in a fresh `mkdtemp()` directory
   (UTF-8).
3. **Build** with one compiler invocation: `CFLAGS`, then for Windows
   `-I /opt/openssl-mingw64/include`, include directories for every cpire
   header, all `*.c` under `data/agent/cpire/` except the template, and the
   platform libraries *after* the sources (GNU ld resolves left to right):
   - Windows: `-L /opt/openssl-mingw64/lib64 -lssl -lcrypto -lws2_32 -lwinhttp
     -lcrypt32 -lole32 -loleaut32 -ladvapi32 -static` — a standalone `.exe`.
   - Linux: `-lcrypto -lcurl -lpthread` — dynamically linked; the target needs
     the OpenSSL 3 and libcurl runtimes and a glibc at least as new as the
     build host's.
   A compiler failure raises `C build failed: <stderr>`; an empty output raises
   `C build produced no output or empty file`.
4. **Clean up.** `main.c` is always removed and a failed or empty build removes
   the whole directory; on success `c_exe` reads the binary and removes the
   directory with whatever else the compiler left in it.

`CCompiler` never passes `-DCPIRE_DEBUG`; add it through `CFLAGS` for a build
that logs (see [Debug builds](agent-loop.md#debug-builds)).

## Building and testing without a Windows host

The server's Linux test suite covers the C agent without running it:

- `empire/test/test_c_compiler.py` — argument building, link order and cleanup
  with a fake compiler, plus `test_build_compiles`, which compiles the agent for
  both targets (slow; needs `gcc`, `libssl-dev`, `libcurl4-openssl-dev` and
  `x86_64-w64-mingw32-gcc` with OpenSSL for MinGW in `/opt/openssl-mingw64`).
- `empire/test/test_cpire_polling.py` — builds `empire/test/data/cpire/poll_driver.c`
  against the real cpire sources with the native `gcc` and drives them with
  synthesized responses: poll classification and the poll-step table, the
  GET-with-cookie request shape, result POSTs, working-hours windows, the WinHTTP
  reader's failure paths (through the shims in `winhttp_read.h`) and one full
  poll iteration.
- `empire/test/test_stager_multi_c_exe.py` — the stager's build-directory
  cleanup.

CI installs the Linux dependencies, and the install-script tests check that
`setup/install.sh` leaves MinGW and the libcurl headers in place.
