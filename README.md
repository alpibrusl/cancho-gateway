# lexsys-gateway

An HTTP/1.1 reverse proxy written in [lex-sys](https://github.com/alpibrusl/lex-sys): no `Ffi`, no `unsafe`, and a
checkable authority report. **The gateway you can audit:** `lex-sys authority` bounds where the program can connect
(`net_out(...)`) and says it never touches files or foreign code, so a parsing bug cannot turn it into a way to reach
arbitrary hosts. **The bound is exact for a single upstream and a shared prefix for several**: a lex-sys program has one
`Net` and so one bound (measured, `docs/design.md` section 2; an earlier version of this README promised an exact set).
Strict, bounded request parsing (`std.http`) is the defence against request smuggling.

The model is [`lexsys-cache`](https://github.com/alpibrusl/lexsys-cache): one thread, one poller, memory sized at start,
every input bounded with its own refusal, and measurements against the incumbent (nginx, HAProxy) fixed before the code.

**Status: design stage. Nothing is built.** The plan and its tasks are in the epic issue. The first deliverable is
`docs/design.md`: scope, the authority row, the gates, written before any code.

## Intended scope (v1)

A route table to a fixed set of upstreams; header sanitising (hop-by-hop headers, `Forwarded`, request id); per-route
size and time limits; per-key rate limiting from the clock; API-key and HMAC/JWT verification (lex-sys has `std.hmac`,
ed25519, RSA and ECDSA); upstream connection reuse; health checks; an access log. HTTP/1.1 over plain TCP.

Not in v1: TLS (it needs foreign code today and would make the authority report unbounded: terminate it in front, as
Caddy does for the services this is meant to sit before), HTTP/2 and gRPC, caching, response rewriting, dynamic upstream
discovery, clustering. WebSockets (the OCPP use case) are a later stage built on lex-sys's WebSocket spike.

## Why a repository of its own

It is a server with its own authority row (the network and the clock, no files), and in this toolbox one program carries
one authority row. It is not `lexsys-web` (an application framework that serves routes and validates bodies, with
middleware listed as not yet) and it is not `lexsys-hooks` (outbound webhook delivery).
