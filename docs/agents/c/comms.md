# Comms & Routing

`comms/comms.c` talks HTTP to the listener, `comms/routing.c` builds and parses
Empire routing packets, and `crypto/` holds staging and the payload ciphers. The
C agent speaks the same wire protocol as the Python and PowerShell agents against
the `http` listener; it does not support malleable profiles.

## Comms context

`cpire_comms_init(server, profile, staging_key, staging_key_len)` parses the
listener's pipe-split `DefaultProfile` — `task URIs|User-Agent|Header:Value|…` —
into the task-URI list, the `User-Agent` and any extra headers, and keeps the
staging key for routing packets. `cpire_comms_set_session_cookie` stores the
listener's `Cookie` option; an unset name falls back to `session`.

## Requests

| Call | Request | Carries |
|------|---------|---------|
| `cpire_perform_dh_key_exchange` (stage 1) | `POST <Host>/index.jsp` | the stage-1 routing packet; the only fixed URI |
| `cpire_stage2_sysinfo` (stage 2) | `POST` a random task URI | the meta-`3` routing packet |
| `cpire_poll_tasking` | `GET` a random task URI | `Cookie: <name>=<base64 routing packet>` |
| `cpire_post_response` | `POST` a random task URI | the result routing packet as the body |

Polling by GET is what lets the listener signal an unknown session: the `http`
listener sends its `401` only on the GET path, and it looks for the routing
packet under the cookie name it is configured with.

Every request returns a `cpire_http_response` (`status_code`, `data`, `size`,
`headers`). A transport failure comes back with status `0` and no data (`NULL`
only when a handle or buffer could not be allocated); both are classified as a
missed check-in. The caller frees it with `cpire_http_response_free`.

## Backends

- **Windows — WinHTTP.** The session uses the system default proxy
  (`WINHTTP_ACCESS_TYPE_DEFAULT_PROXY`). HTTPS requests ignore every certificate
  error (unknown CA, wrong usage, CN mismatch, expired). The response reader
  lives in `comms/winhttp_read.h`, header-only with the WinHTTP calls behind
  macros so the Linux test driver can compile it against scripted shims. On any
  header-query, read or allocation failure it frees the partial body and leaves
  the response with status `0` and no data, so a truncated read is a failed
  request rather than a short `200` taken for tasking.
- **Linux — libcurl.** `CURLOPT_SSL_VERIFYPEER` and `CURLOPT_SSL_VERIFYHOST` are
  off, matching Windows. libcurl is initialised once per process.

## Routing packets

`routing.c` implements the format from `empire/server/common/packets.py`:

```
+---------+--------------------------------+--------------------------+
|  Nonce  |  AES-256-GCM(RoutingData)      | AESc(client packet data) |
+---------+--------------------------------+--------------------------+
|    12   |                32              |          length          |
+---------+--------------------------------+--------------------------+

RoutingData (16 bytes, sealed with the staging key, empty AAD; 16-byte GCM tag):
+-----------+------+------+-------+--------+
| SessionID | Lang | Meta | Extra | Length |
+-----------+------+------+-------+--------+
|    8      |  1   |  1   |   2   |    4   |
+-----------+------+------+-------+--------+
```

The C agent's language byte is `6`. Meta is `3` for the stage-2 check-in, `4`
for a tasking request (no payload) and `5` for results.
`cpire_build_routing_packet` and `cpire_parse_routing_packet` are the only two
entry points; the payload after the header is AES-CBC encrypt-then-HMAC under
the session key.

## Staging

The sequence is Empire's standard one, described in [Staging](../staging.md).
`cpire_run_agent` drives it with two calls: `cpire_perform_dh_key_exchange`
(`crypto/dh.c`) verifies the server's transcript-bound Ed25519 certificate with
the embedded server public key, derives the session key from the DH secret with
HKDF-SHA256, and splits it into AES and HMAC keys (`cpire_hkdf_sha256`, labels
`empire-enc` / `empire-mac`); `cpire_perform_stage2_sysinfo` then POSTs the
encrypted system information in a meta-`3` packet and the task loop begins.
