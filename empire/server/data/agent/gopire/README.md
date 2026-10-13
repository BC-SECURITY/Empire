# Gopire

## Comms

Tasking polls are GETs with the base64 routing packet in the listener's session
cookie (`Cookie` option, default `session`); results are POSTed. Malleable
builds use the profile's `get` section for polls and `post` for results. A 401
on a tasking poll ends the agent; other failed polls — transport errors, the
120 s request timeout, non-200s, 200s that do not decrypt — count toward the
lost limit (`0` disables it). The `http` listener answers a rejected packet
with its default page, which the agent cannot tell from idle. The
`comms` package carries the Go unit tests; `agent` is Windows-only and is
type-checked with `GOOS=windows go vet ./...` (see `empire/test/test_gopire_unit.py`).
