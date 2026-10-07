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
header policy (`Via`, `X-Forwarded-Host/Proto`, a request id, untrusted forwarding claims removed: `docs/headers.md`), writes one JSON
access-log line per request to stdout (`docs/observability.md`) and echoes the request id in every response and error. It has been benchmarked
against nginx, HAProxy, Envoy, Caddy, Traefik and Kong, and **is slower than HAProxy on most cells and than nginx on POST bodies** (`docs/bench.md`, sections 8 and 10; the two runs disagree about nginx on the other cells).
It has **no client-side keep-alive, no active health checks, no authentication and no rate limiting**, no TLS (see below: cancho has a TLS server now, the gateway does not use it yet) and no `X-Forwarded-For` of its own (the compiler gives no peer address). It does have an optional **admin port** (`admin_listen`: `/metrics` as JSON or Prometheus text, `/healthz`, `/readyz`; `docs/observability.md` section 7) that **binds every interface and has no authentication**: firewall it. The plan and its tasks are in the epic issue; the design
is `docs/design.md`.

## Intended scope (v1)

A route table to a fixed set of upstreams; header sanitising (hop-by-hop headers, `Forwarded`, request id); per-route
size and time limits; per-key rate limiting from the clock; API-key and HMAC/JWT verification (cancho has `std.hmac`,
ed25519, RSA and ECDSA); upstream connection reuse; health checks; an access log. HTTP/1.1 over plain TCP.

Not in v1: TLS in the gateway (terminate it in front, as Caddy does for the services this is meant to sit before; see the note below),
HTTP/2 and gRPC, caching, response rewriting, dynamic upstream
discovery, clustering. WebSockets (the OCPP use case) are a later stage built on cancho's WebSocket spike.

**TLS, corrected 2026-10-07.** This file used to say TLS "needs foreign code and would make the authority report unbounded". That
reason no longer holds: cancho has a TLS 1.3 server written in cancho, no foreign code (`packages/tls`, cancho #338 and #339; the example
`examples/tls_echo`, #346; cancho's own notes say it has not been independently reviewed). **Using it here is not built.** It is a design
decision for #16, because it changes what this program may do: the authority report would gain reading one certificate directory
and 32 bytes of `/dev/urandom` (the gateway has no file access today; cancho's open PR #364 would let the report name those two paths instead of `fs_read("")`), the engine takes about 350 KiB (cancho's figure) plus
per-connection state, and every handshake costs a signature. The design is `docs/tls.md` (written before any code; nothing in it is built). Until it is, terminate TLS in front.

## Why a repository of its own

It is a server with its own authority row (the network and the clock, no files), and in this toolbox one program carries
one authority row. It is not `cancho-web` (an application framework that serves routes and validates bodies, with
middleware listed as not yet) and it is not `cancho-hooks` (outbound webhook delivery).
