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
header policy (`Via`, `X-Forwarded-Host/Proto`, a request id, untrusted forwarding claims removed: `docs/headers.md`), terminates **TLS 1.3** on a second port with cancho's pure-cancho TLS server (`tls_listen`; `docs/tls.md`: no reload yet, ECDSA P-256 certificates only, not independently reviewed), writes one JSON
access-log line per request to stdout (`docs/observability.md`) and echoes the request id in every response and error. It has been benchmarked
against nginx, HAProxy, Envoy, Caddy, Traefik and Kong, and **is slower than HAProxy on most cells and than nginx on POST bodies** (`docs/bench.md`, sections 8 and 10; the two runs disagree about nginx on the other cells).
It has **no client-side keep-alive, no active health checks, no authentication and no rate limiting**, no `X-Forwarded-For` of its own (the compiler gives no peer address). It does have an optional **admin port** (`admin_listen`: `/metrics` as JSON or Prometheus text, `/healthz`, `/readyz`; `docs/observability.md` section 7) that **binds every interface and has no authentication**: firewall it. The plan and its tasks are in the epic issue; the design
is `docs/design.md`.

## Intended scope (v1)

A route table to a fixed set of upstreams; header sanitising (hop-by-hop headers, `Forwarded`, request id); per-route
size and time limits; per-key rate limiting from the clock; API-key and HMAC/JWT verification (cancho has `std.hmac`,
ed25519, RSA and ECDSA); upstream connection reuse; health checks; an access log. HTTP/1.1, over plain TCP or TLS 1.3 from the client side.

Not in v1: HTTP/2 and gRPC, TLS to the upstreams, client certificates, caching, response rewriting, dynamic upstream
discovery, clustering. WebSockets (the OCPP use case) are a later stage built on cancho's WebSocket spike.

**TLS, built 2026-10-08.** This file used to say TLS "needs foreign code and would make the authority report unbounded". That
reason stopped holding when cancho shipped a TLS 1.3 server written in cancho (`packages/tls`; cancho's own notes say it has not been
independently reviewed). The gateway now uses it: `tls_listen = <port>` in the deployment adds a second, TLS listener beside `listen`,
the certificates are read at start from a directory compiled into the binary, and the authority report gains exactly two filesystem paths
(`fs_read("/dev/urandom")` and the directory) and no `fs_read("")`. **Not done:** reloading a renewed certificate without a restart
(`SIGHUP`, the next slice), a TLS-only deployment (`listen` is still required), and the cost measured in the benchmark harness. The design,
the gates and what was measured are `docs/tls.md`.

## Why a repository of its own

It is a server with its own authority row (the network and the clock; the only files it reads are the TLS certificates and 32 bytes of `/dev/urandom`, two named paths), and in this toolbox one program carries
one authority row. It is not `cancho-web` (an application framework that serves routes and validates bodies, with
middleware listed as not yet) and it is not `cancho-hooks` (outbound webhook delivery).
