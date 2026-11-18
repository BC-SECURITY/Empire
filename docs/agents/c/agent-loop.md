# Agent Loop

`agent/agent.c` owns the agent's lifetime after the binary starts: staging, the
tasking loop, and task dispatch. The task handlers themselves are listed in the
[overview](README.md#supported-tasks).

The C agent's source is only in the Sponsors version of Empire, under
`empire/server/data/agent/cpire/`.

## `cpire_config` and `cpire_agent`

`main.template.c` fills a `cpire_config` from the template variables (see
[Template & Compiler](template.md)) and hands it to `cpire_agent_create`, which
base64-decodes the staging key, the default page (`DEFAULT_RESPONSE`) and the
three certificate keys, parses the profile and builds the comms context with the
listener's session cookie name. `cpire_agent` carries that decoded state plus
what staging adds: the session ID, the session key and the server nonce.
`cpire_agent_destroy` zeroes every key with `OPENSSL_cleanse` before freeing it.

## `cpire_run_agent`

```
key exchange (stage 1)  ->  sysinfo check-in (stage 2)  ->  task loop
```

Returns `-1` if either staging step fails and `0` when the task loop ends (kill
date, lost limit, or a 401). An `EXIT` task terminates the process from inside
the loop instead. The binary exits either way; there is no retry. Staging is
described in [Comms & Routing](comms.md#staging).

## The task loop

Each iteration of `cpire_task_loop`:

1. **Kill date.** `KillDate` is `MM/DD/YYYY`; once it is in the past the loop
   returns.
2. **Working hours.** Outside the `WorkingHours` window the agent sleeps 60
   seconds and re-checks without polling (`cpire_outside_window`; semantics in
   the [overview](README.md#working-hours)).
3. **Sleep** `delay` seconds, ± `delay × jitter`.
4. **Poll.** Build a tasking-request routing packet (language `6`, meta `4`, no
   payload) and GET a task URI with it in the listener's session cookie
   (`cpire_poll_tasking`).
5. **Decide** with `cpire_poll_once`, below. It returns `0` when the agent should
   exit.

### What one poll means

`cpire_poll_once` classifies the HTTP response, processes tasking if there is
any, and updates the missed check-in count. The three steps are separate,
non-static functions so the Linux test driver can feed them synthesized
responses.

`cpire_classify_poll` (in `comms/comms.c`):

| Response | Result |
|----------|--------|
| no usable response (transport error, read failure) | `MISSED` |
| `401` | `UNKNOWN_SESSION` — the server still accepts the staging key but no longer has this session (the agent was archived and the server restarted) |
| any other non-200 | `MISSED` — on the GET path a `404` with the default page means "no routing packet in the cookie" |
| `200` with an empty body | `MISSED` — Empire never answers a tasking GET with an empty body; `hop.php` relays a failed upstream (including a 401) as one |
| `200` with exactly the listener's default page | `IDLE` |
| `200` with anything else | `TASKING` |

`cpire_process_routing_response` parses the routing packet with the staging key,
decrypts and verifies the AES-CBC/HMAC payload with the session key and
dispatches each task packet. It returns `1` when the blob parsed and decrypted
and `0` otherwise. A blob that decrypts but holds no parseable task packet still
counts as processed — the HMAC proves the server sent it — and a debug build
logs it.

`cpire_poll_step` turns the two results into a decision. The *lost limit* is the
threshold (`DefaultLostLimit`, field `lost_limit`); *missed check-ins* is the
count of consecutive failed polls:

| Result | Missed check-ins | Keep polling? |
|--------|------------------|---------------|
| `IDLE` | reset to 0 | yes |
| `TASKING`, processed | reset to 0 | yes |
| `TASKING`, not processed | +1 | unless the limit is reached |
| `MISSED` | +1 | unless the limit is reached |
| `UNKNOWN_SESSION` | unchanged | **no** — exit now |

"The limit is reached" means `lost_limit > 0 && missed >= lost_limit`; a lost
limit of `0` never stops the agent. The Python agent differs on both tasking
rows: it resets its count only on the default page, and a 200 carrying tasking
leaves the count unchanged whether or not it decodes.

One failure is invisible to this table, for the C agent as for every other: the
`http` listener answers a routing packet it rejects (bad key, malformed packet)
with its default page and `200`, which reads as `IDLE`.

## Results

Task handlers call `cpire_post_task_result`, which builds a result routing packet
(meta `5`) and POSTs it through `cpire_send_result`, a thin wrapper over
`cpire_post_response` (see [Comms & Routing](comms.md#requests)). A failed
result POST is logged in debug builds and otherwise ignored: Empire answers an
unknown session on a POST with `404`, never `401`, so the next tasking poll is
where the agent learns it is orphaned.

## Debug builds

`cpire_log` is a no-op unless the agent is compiled with `-DCPIRE_DEBUG`, which
the server's `CCompiler` never sets (pass it through `CFLAGS`). A debug build
appends to `cpire_debug.log` in the process's working directory — nothing goes
to the console, and the file is an on-disk artefact. It logs staging, every poll
as `poll=<idle|tasking|unknown-session|missed> status=… size=… processed=…
missed=…`, each failure branch of routing-packet processing, and result POSTs
that did not get a non-empty `200`.
