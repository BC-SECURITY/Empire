# Upgrading to 7.1

Empire 7.1 hardens the staging handshake. The change is wire-breaking for agents but, unlike [7.0](upgrading-to-7.md), it does **not** touch the database or password hashing — so there is no forced reset. The main required action is to **re-stage every agent** after upgrading. 7.1 also carries a handful of smaller breaking changes, listed under [Other breaking changes](#other-breaking-changes).

Bring your checkout to 7.1 with `./ps-empire update` (see [Update](README.md#update)). Existing listeners, operator accounts, credentials, and downloads carry over unchanged.

## Re-stage all agents

The Stage 1 key exchange changed in three ways, none of which is backward-compatible:

* **Transcript-bound certificates.** The Ed25519 handshake certificate used to sign the constant string `"SIGNATURE"`, so a certificate captured from any exchange stayed valid forever and could be replayed against a substituted DH public key. Both sides now sign the exchange transcript instead — the agent signs its own DH public key, and the server signs the session ID, a nonce, and its DH public key.
* **Server authentication for C#.** The C# (Sharpire) agent previously received no server certificate and never authenticated the server. The server now sends a transcript-bound certificate on the C# staging branch, and the agent verifies it before deriving the session key — matching PowerShell, Python, and Go.
* **AES/HMAC key separation.** The AES-CBC payload layer now derives independent cipher and MAC keys from the shared key via HKDF-SHA256 (`empire-enc` / `empire-mac`) instead of using one key for both.

An agent staged before 7.1 cannot complete Stage 1 against a 7.1 server — there is no compatibility shim. Re-stage everything after upgrading. See [Staging](../agents/staging.md) for the current process.

## Agent support

The server and the in-tree PowerShell, Python, IronPython, and Go (Gopire) agents are updated by `./ps-empire update`.

* **C# (Sharpire)** ships inside Empire-Compiler. 7.1 pins Empire-Compiler v2.0.3, which carries the 7.1 handshake; the server downloads it on first start, so re-staging is the only action needed.
* **cpire (native C agent)** has not yet been updated for the 7.1 handshake and cannot stage against a 7.1 server.

## Other breaking changes

These ship in 7.1 alongside the handshake change:

* **`linux/pyinstaller` stager:** `BinaryFile` is now a bare file name defaulting to `empire` (any directory component is ignored), and the built binary is no longer left on the server.
* **http / http_malleable listeners:** an error that escapes a view now returns the listener's default response instead of a Werkzeug 500 page.
* **`http_hop` listener:** `OutFolder` is relative to `downloads/http_hop` and defaults to `redirectors`; hop listeners stored with an absolute path outside it no longer start.
* **API operation ids:** OpenAPI operation ids are now `{tag}_{route name}` (e.g. `agents_read_agent`), which also renames the three generated `Body_*` request schemas. Regenerate any API client.
* **API tags:** agent-task and plugin-task routes are tagged only with their primary resource (no `tasks` tag group), and `/api/v2/obfuscation` routes moved from the `keywords` tag to `obfuscation`.
* **File-path module options:** `ExtFile`, `File`, and `Shellcode` must name a path inside the server's downloads directory; saved workflows pointing elsewhere are rejected until the file is uploaded through the API.

No database reset or password-hash migration ships with 7.1. If you are coming from a pre-7.0 database, follow [Upgrading to 7.0](upgrading-to-7.md) first (it does require a fresh database), then this guide.
