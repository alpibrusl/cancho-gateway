# cancho-gateway

An HTTP/1.1 reverse proxy written in [cancho](https://github.com/alpibrusl/cancho): no `Ffi`, no `unsafe`, and a
checkable authority report. **The gateway you can audit, with an honest limit:** `cancho authority` proves it touches no
files and no foreign code and is bounded (CI-gated against `authority.toml`). It does **not** prove which upstreams it
reaches: a cancho program has one network bound shared by listening and connecting, so a proxy's report is `net_in("")`
and `net_out("")` (measured, `docs/design.md` section 2). The upstream set is compiled in from a deployment file and
enforced by exact match before every connect, and tested; the compiler does not vouch for it. Strict, bounded request
parsing (`std.http`) is the defence against request smuggling.

**Site:** <https://alpibrusl.github.io/cancho-gateway/> (the overview and [the evidence](https://alpibrusl.github.io/cancho-gateway/evidence.html)); it is `docs/index.html` and `docs/evidence.html`, its figures drawn by `scripts/figures.py` from `bench/results/`, its images by `scripts/site_assets.py` from `docs/logo.jpg`.

The model is [`cancho-cache`](https://github.com/alpibrusl/cancho-cache): one thread, one poller, memory sized at start,
every input bounded with its own refusal, and measurements against the incumbent (nginx, HAProxy) fixed before the code.

**Status: a working gateway slice, not a finished one.** It accepts, frames and routes requests, forwards them to a compiled-in upstream
and relays the response, with deadlines, backpressure and problem+json refusals, all tested end to end (`docs/proxy.md`). It keeps upstream
connections alive in a bounded pool (`docs/pool.md`), stops sending requests to an upstream that keeps failing (`docs/health.md`), applies a
header policy (`Via`, `X-Forwarded-Host/Proto`, a request id, untrusted forwarding claims removed: `docs/headers.md`), terminates **TLS 1.3** on a second port with cancho's pure-cancho TLS server (`tls_listen`; `docs/tls.md`: certificates reloaded on `SIGHUP`, ECDSA P-256 certificates only, not independently reviewed), writes one JSON
access-log line per request to stdout (`docs/observability.md`) and echoes the request id in every response and error. It has been benchmarked
against nginx, HAProxy, Envoy, Caddy, Traefik and Kong, and **is slower than HAProxy on most cells and than nginx on POST bodies** (`docs/bench.md`, sections 8 and 10; the two runs disagree about nginx on the other cells), all of it over plain HTTP: **over TLS it serves 1 request in 170 of the plain rate** (section 11).
It has **no client-side keep-alive and no active health checks**, no `X-Forwarded-For` of its own (the compiler gives no peer address). It has **per-route API-key authentication** (`auth = "api-key"`; `docs/auth.md`): the binary holds only a SHA-256 digest and a name for each key, never a key; the credential comes from `Authorization: Bearer` or one header of the route's choosing, is removed before the upstream sees the request, and a refusal is a `401` with `WWW-Authenticate` or a `403`; **no key change without a restart, no client certificates**, and a key is only as private as the transport (a plain listener needs `auth_allow_plain`). A route can instead (or also) take **JWT bearer tokens** (`auth = "jwt"`; `docs/jwt.md`): `EdDSA` (Ed25519) only, never chosen from the token, verified with a public key compiled into the binary, `exp` required, `aud`, `iss` and a bounded leeway per route, one `401` for every invalid token with the cause in the log; **no HS256, no JWKS, no revocation**, and a token costs about 5 ms to verify on a single-threaded loop, so a flood of well-formed tokens is expensive. It has **per-route rate limiting** (`rate_limit = "100/s"`, a token bucket; `docs/ratelimit.md`) whose key is the whole route, a request header or an `X-Forwarded-For` element: **never a client address, which the compiler does not give**, so a single abusive client with no distinguishing header cannot be told from the rest, and a header an attacker chooses can be rotated. It does have an optional **admin port** (`admin_listen`: `/metrics` as JSON or Prometheus text, `/healthz`, `/readyz`; `docs/observability.md` section 7) that **binds every interface and has no authentication**: firewall it. The plan and its tasks are in the epic issue; the design
is `docs/design.md`.

## Intended scope (v1)

A route table to a fixed set of upstreams; header sanitising (hop-by-hop headers, `Forwarded`, request id); per-route
size and time limits; per-route rate limiting from the clock (built: `docs/ratelimit.md`); API-key verification (built: `docs/auth.md`) and EdDSA JWT verification (built: `docs/jwt.md`; HMAC, RSA and ECDSA tokens are not: cancho has the
primitives, but HMAC needs a secret the binary must not hold); upstream connection reuse; health checks; an access log. HTTP/1.1, over plain TCP or TLS 1.3 from the client side.

Not in v1: HTTP/2 and gRPC, TLS to the upstreams, client certificates, caching, response rewriting, dynamic upstream
discovery, clustering. WebSocket compression and OCPP message validation are not done (below).

**WebSocket, built 2026-10-08 (slice 1).** A route with `websocket = true` (and `subprotocols`, `origins`) admits an RFC 6455 opening handshake after the
checks of `docs/websocket.md` section 4, forwards it on a fresh connection without extensions, checks the upstream's `101` (including the
`Sec-WebSocket-Accept` value), and then carries the connection as a **byte tunnel**: the same back-pressure buffers, an idle timeout, a maximum lifetime,
a bound on concurrent tunnels, over plain TCP or the TLS listener (`wss`). The use case is OCPP-J (`ocpp1.6`, `ocpp2.0.1`) between EV chargers and a back office.

**WebSocket frames, built 2026-10-12 (slice 2).** The tunnel now reads frames in both directions with a parser that holds no message (`docs/websocket-frames.md`): RFC 6455 section 5
is enforced (reserved bits and opcodes, control frames, masking in the right direction, minimal lengths, fragmentation order), a message longer than the route's `ws_max_message_bytes`
(default 1 MiB, counted over its fragments) and invalid UTF-8 in a text message are refused, and a violation never reaches the other side. The gateway now sends **Close frames** of its own at
frame boundaries (1001 for a timer, 1002/1007/1009 for the client's fault, 1011 to a client whose upstream broke the rules), waits a bounded time for the echo (`ws_close_ms`) and passes a
peer's Close through. An optional **keepalive** (`ws_ping_ms`, `ws_pong_ms`) Pings a silent charger and closes it when the Pong does not come, so a charger whose NAT mapping died frees its slot in
seconds instead of at the idle timeout; the upstream never sees the gateway's Ping or its Pong. **Not done:** `permessage-deflate` (stripped), OCPP-J message validation, per-message rate limits,
TLS to the upstream, and more than 127 concurrent tunnels (the slot table's size).

**TLS, built 2026-10-08 (slice 1), reload and TLS-only the same day (slice 2).** This file used to say TLS "needs foreign code and would make the authority report unbounded". That
reason stopped holding when cancho shipped a TLS 1.3 server written in cancho (`packages/tls`; cancho's own notes say it has not been
independently reviewed). The gateway now uses it: `tls_listen = <port>` in the deployment adds a second, TLS listener beside `listen`,
the certificates are read at start from a directory compiled into the binary, and the authority report gains exactly two filesystem paths
(`fs_read("/dev/urandom")` and the directory) and no `fs_read("")`. `kill -HUP` reads every certificate again (a refused or unreadable replacement leaves the old one serving, is counted in
the metrics and written to standard error; connections already open keep working), `SIGINT` and `SIGTERM` stop the process with status 0, and `listen` may be left out for a deployment that serves TLS only
(at least one of `listen` and `tls_listen`). The report gains `signals("HUP,INT,TERM")` for that. **Not done:** a change of an identity's names, or of the set of identities, without a restart; and draining requests in flight at a stop. **The cost of TLS, measured in the benchmark harness on 2026-10-12, is high:** the gateway has no client keep-alive, so every HTTPS request is a full handshake
(5.9 ms of CPU), and it serves about 157 HTTPS requests a second from a core against 26,991 plain, 1 in 170; the default `tls_rate` of 50 a second caps it lower still (`docs/tls.md` section 12, `docs/bench.md` section 11). The design,
the gates and what was measured are `docs/tls.md`.

## Why a repository of its own

It is a server with its own authority row (the network and the clock; the only files it reads are the TLS certificates and 32 bytes of `/dev/urandom`, two named paths), and in this toolbox one program carries
one authority row. It is not `cancho-web` (an application framework that serves routes and validates bodies, with
middleware listed as not yet) and it is not `cancho-hooks` (outbound webhook delivery).
