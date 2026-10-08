# WebSocket proxying (task #15), first slice

Status: **design, written before the code (2026-10-08); the gates in section 12 are fixed here and must be able to fail.** Sections 1 to 12 are the decision. Section 13 is filled in after the build
(what was built, what was measured, the mutants) and says where the build found the design false; a claim found false is corrected in place and marked *(corrected)*. Claims about cancho are about the pinned
compiler (`cancho.toml`, `2fcf4cd`).

The use case is OCPP-J: EV chargers connect to a back office over a WebSocket (`ws`, or `wss` in production) and speak a subprotocol, `ocpp1.6` or `ocpp2.0.1`, for hours or weeks. The gateway sits in front of the
back office: it is where the strict parsing, the upstream set, the access log, the metrics and TLS already are. This slice makes the gateway carry the connection. It does **not** understand OCPP and does **not**
read WebSocket frames.

## 1. Scope

**Built in this slice**

- A route flag `websocket = true`, with `subprotocols` (the protocols the route serves) and `origins` (the browser origins it admits).
- The opening handshake of RFC 6455 section 4, checked at the gateway on the way in (section 4) and on the way back (section 6), with a rule tag for every refusal.
- After a validated `101` from the upstream the connection is a **byte tunnel in both directions**: the existing back-pressure buffers, an idle timeout, a maximum lifetime, byte counters. The gateway never
  parses, masks, unmasks, fragments or originates a frame.
- `wss`: the client side can be the TLS listener (`docs/tls.md`); the tunnel is plaintext to the upstream and ciphertext to the client, as every other session is.
- Access log line, metrics, a bound on concurrent tunnels, new refusal tags, generator keys, tests, mutants.

**Not in this slice, said once**

| not done | why |
|---|---|
| interpreting frames: ping/pong policy, close handshake, message size limits, fragmentation limits, UTF-8 validation | a byte tunnel is the smallest thing that carries OCPP; each of these is a later decision with its own gate (section 10 says what its absence costs) |
| `permessage-deflate` and every other extension | stripped from the request (section 5), so none is negotiated; an upstream that answers with one is refused (`ws.upstream-extensions`) |
| a gateway-originated ping, or any idle keepalive | **none in slice 1** (section 8). The idle timeout is the only liveness rule |
| TLS to the upstream (`wss` upstream) | the upstream side is plain, as everywhere else in the gateway (`docs/tls.md` section 2) |
| routing a connection by its `Sec-WebSocket-Protocol` | the route is chosen by `Host`, path and method as for any request |
| HTTP/2 WebSocket (RFC 8441), `CONNECT` | the gateway speaks HTTP/1.1 and refuses `CONNECT` (`framing.method-unsupported`) |
| thousands of tunnels | the slot table is 256 slots, a tunnel holds two (section 9). The honest ceiling of this slice is **127 tunnels at the very most**. A deployment of ten thousand chargers needs a different budget, which is a separate task |
| the charger's address in the log or in an upstream header | there is no peer address (`docs/headers.md` section 1); an OCPP back office usually identifies the charger by the path (`/ocpp/CP001`), which the log has |

## 2. What cancho gives and does not give (measured)

- **No WebSocket package, and no SHA-1 or base64 in `std`.** `ls std packages` at the pinned commit: `std/crypto.cho` has SHA-256, SHA-384 and SHA-512 only; the packages are `agent-wire`, `http-request`, `http-response`, `http-server`, `net-connect`,
  `net-sockets`, `tls`, `x509`. cancho's own `docs/websocket-spike.md` section 10 row 1 says the same ("no SHA-1 and no base64 in `std`") and records that `examples/ocpp_ws/{sha1,b64}.cho` carry them, differentially tested
  (2,096 comparisons against `hashlib` and `base64`, 0 differences, spike section 8).
- **What the gateway does about it:** it carries copies of those two files (`src/sha1.cho`, `src/b64.cho`; module names changed, bodies not) and one module of its own, `src/websocket.cho`. SHA-1 is used for one
  thing, the `Sec-WebSocket-Accept` value, which is a check that the server read the key, **not** a security primitive (RFC 6455 section 1.3, 10.8). The gateway's own differential against `hashlib` is a gate (section 12, gate 2).
- **No new effect.** Nothing in this slice needs a capability the gateway does not already hold; section 12 gate 9 holds the authority report to that.
- **Unknown, to be measured:** whether `std.http.parse` at this commit accepts a request head carrying `Upgrade` and `Sec-WebSocket-*` headers without comment. The code reads as if it does (it treats `Upgrade` as an ordinary header and the
  gateway strips it today as hop-by-hop, `src/forward.cho`); gate 1 measures it.

## 3. Deployment keys

Per route (all optional; `subprotocols` and `origins` are refused without `websocket = true`, rule `config.websocket`):

| key | type | default | meaning |
|---|---|---|---|
| `websocket` | bool | `false` | the route accepts WebSocket upgrades. A request without `Upgrade` is an ordinary request on the same route |
| `subprotocols` | list of up to 8 tokens | `[]` | the subprotocols the route serves (`"ocpp1.6"`, `"ocpp2.0.1"`). Each is an RFC 9110 token of at most 64 bytes, no repeats. An empty list means the route serves **no** subprotocol (section 4, row 11) |
| `origins` | list of up to 16 strings | `[]` | the `Origin` values a request may carry (section 4, row 12), each `scheme://host[:port]` exactly as a browser writes it (lowercase scheme and host, no path, no trailing slash) |

A route with `websocket = true` whose `methods` exclude `GET` is refused (`config.websocket`): an upgrade is a `GET`.

Deployment-wide (refused without at least one `websocket` route, `config.websocket`, as the `tls_*` keys are without `tls_listen`):

| key | default | range | meaning |
|---|---|---|---|
| `ws_idle_timeout_ms` | 600000 | 100 to 86400000 | a tunnel in which no byte moved in either direction for this long is closed (section 7) |
| `ws_max_lifetime_ms` | 86400000 | 100 to 2592000000 | a tunnel older than this is closed, whatever it is doing. There is no "unlimited": 30 days is the largest |
| `ws_max_tunnels` | 64 | 1 to 127 | the most upgrades in progress or open at once; one more is refused `ws.limit` (section 9) |

The 600 s default is two OCPP heartbeats at the usual 300 s interval. It is a guess about OCPP deployments, not a measurement; the operator sets it from the heartbeat interval the back office hands out.

## 4. The request: what is checked, in this order

The checks run when the head is complete and the route is known, and only on a route with `websocket = true` and a request that **asks for an upgrade**: one with an `Upgrade` header or a `Connection` header listing `upgrade`.
Everything else on that route is an ordinary request. A request that asks for an upgrade on a route **without** `websocket` is an ordinary request too, with the `Upgrade` and the `Connection` headers removed as hop-by-hop
(RFC 9110 section 7.8 lets a server ignore `Upgrade`); the upstream never sees an upgrade the operator did not enable.

The stance is the gateway's: one reading or a refusal. Where RFC 6455 allows a spelling the gateway could tolerate, it takes the conservative one and says so.

| # | check | refusal |
|---|---|---|
| 1 | method is `GET` | `ws.method` 400 |
| 2 | HTTP/1.1 (RFC 6455 4.2.1 item 1: "HTTP/1.1 or higher"; the gateway does not speak higher) | `ws.http-version` 400 |
| 3 | exactly one `Upgrade` header, whose value is the single token `websocket`, any case. A list (`websocket, h2c`), a second header, another protocol: refused | `ws.upgrade` 400 |
| 4 | exactly one `Connection` header, whose tokens are `upgrade` and optionally `keep-alive`, any case. Any other token is refused, **because a `Connection` header names headers to remove (RFC 9110 7.6.1) and a token `sec-websocket-key` or `origin` would remove the check's own input** | `ws.upgrade` 400 |
| 5 | no `Content-Length` header of any value (`0` included) and no `Transfer-Encoding` header | `ws.body` 400 |
| 6 | nothing after the head in what was read (no pipelined bytes). RFC 6455 4.1: the client waits for the response before sending more | `ws.early-data` 400 |
| 7 | exactly one `Sec-WebSocket-Version` whose value is `13`. Anything else: `426` with `Sec-WebSocket-Version: 13` in the response (RFC 6455 4.4) | `ws.version` 426 |
| 8 | exactly one `Sec-WebSocket-Key`, 24 bytes, canonical base64 of 16 bytes: 22 base64 characters whose last carries no stray low bits (`A`, `Q`, `g` or `w`), then `==`. A lenient decoder would accept non-canonical padding; the gateway does not | `ws.key` 400 |
| 9 | no more than one `Sec-WebSocket-Protocol` header, a comma-separated list of tokens, each at most 64 bytes, no empty items, at most 16 | `ws.subprotocol` 400 |
| 10 | no more than one `Origin` header | `ws.origin` 403 |
| 11 | subprotocols: if the route lists any, the client must offer at least one of them; if the route lists none, the client must offer none. Comparison is exact and case-sensitive (RFC 6455 section 11.5 registry names are lowercase; 4.2.2 item 5.ii compares case-sensitively) | `ws.subprotocol` 400 |
| 12 | origin: a request with **no** `Origin` header is not from a browser and is admitted. A request **with** one must equal, byte for byte, an entry of the route's `origins`; an empty list admits none. There is no wildcard | `ws.origin` 403 |
| 13 | tunnels in progress or open are fewer than `ws_max_tunnels` | `ws.limit` 503 |

Why rows 11 and 12 are shaped as they are. A browser always sends `Origin` on a WebSocket request, and a script on any web page can ask the browser to open a socket to your back office with the user's cookies and network position
(cross-site WebSocket hijacking, RFC 6455 section 10.2). Refusing an unlisted `Origin` is the whole defence at this layer, and a charger (which is not a browser and sends none) is unaffected. The default, an empty list, admits no
browser at all. The subprotocol rule is the other half of an OCPP route: a charger that offers `ocpp1.6` to a route that serves `ocpp2.0.1` is refused at the edge, with a tag, instead of reaching a back office that would close it with
a code.

Row 13 is checked last so that a refused request does not count against the bound; the count is taken when the check passes and released when the session ends, so a refusal later (the upstream's) frees it.

## 5. What the upstream is sent

The ordinary rewrite (`docs/headers.md`: hop-by-hop headers removed, forwarding claims handled, `Via`, `X-Forwarded-*`, `X-Request-Id`) with these differences:

- `Connection: Upgrade` and `Upgrade: websocket` are written by the gateway, after the client's headers and after the headers of `docs/headers.md` section 2; the client's own `Connection` and `Upgrade` are removed as before. `Connection: close` is **not** written
  (it contradicts `Upgrade`).
- `Sec-WebSocket-Key`, `Sec-WebSocket-Version`, `Sec-WebSocket-Protocol` and `Origin` are copied as received (they passed section 4). The key is forwarded unchanged: the upstream's accept value is checked against it (section 6).
- **`Sec-WebSocket-Extensions` is removed.** No extension is offered, so none can be negotiated, so a byte tunnel never carries frames whose meaning the gateway has not read. (`permessage-deflate` would work through a byte tunnel, but would make the
  frame size limits of a later slice meaningless; that is a decision for that slice.)
- The upstream connection is a **fresh** one, never taken from the pool and never retried (section 10).

## 6. The upstream's answer

A non-`101` answer to an upgrade request (a `401`, a `404`, a `200` page, a `5xx`) is an ordinary response: parsed by `gateway.response`, rewritten and relayed as today, the connection closed after it. This is what lets a
back office refuse a charger it does not know with the status it chooses.

A `101` is parsed by the same strict response parser (`101` is accepted **only** for a session that asked for an upgrade; anywhere else it is still `response.status`) and then checked:

| check | refusal (all 502, and counted against the upstream as a failure as a response the parser refuses is) |
|---|---|
| exactly one `Upgrade: websocket` (any case) and a `Connection` header listing `upgrade`; no `Content-Length` and no `Transfer-Encoding` (a `101` has no body, and a header that says otherwise is a framing disagreement) | `ws.upstream-upgrade` |
| exactly one `Sec-WebSocket-Accept` equal, byte for byte, to base64(SHA-1(key + the RFC 6455 GUID)) for the key the client sent. **Validated: yes.** It costs one SHA-1 of 60 bytes per upgrade and it is the only evidence that the upstream is a WebSocket server that read this request, not a server that answered `101` to anything (RFC 6455 4.2.2 item 5.4; a proxy that skips it will tunnel to a confused upstream and call it a success) | `ws.upstream-accept` |
| `Sec-WebSocket-Protocol`: at most one header, one token. If the route lists subprotocols, it must be present and be one the client offered **and** the route lists. If the route lists none, it must be absent | `ws.upstream-subprotocol` |
| no `Sec-WebSocket-Extensions` (none was offered, RFC 6455 4.2.2 item 5.5: an unsolicited extension fails the connection) | `ws.upstream-extensions` |

Then the client is sent `HTTP/1.1 101 Switching Protocols` with `Upgrade: websocket`, `Connection: Upgrade`, the accept value, the chosen subprotocol, `Via`, `X-Request-Id`, and no other upstream header (an upstream's `Set-Cookie`
on a `101` is dropped: the head is rebuilt from the checked fields only). Bytes the upstream sent after its head in the same read belong to the tunnel and are passed on (a server may speak first).

## 7. The tunnel

**State.** The client slot's phase becomes 6 (tunnel); the upstream slot is marked as a tunnel half. The two slots keep pointing at each other. Per direction: client to upstream moves bytes from the client's read buffer
(16 KiB, after TLS if any) into the upstream's write queue (32 KiB); upstream to client moves the upstream's read buffer into the client's write queue. A direction reads from its source only while its sink has room, exactly as a request body
and a response body do today (`docs/proxy.md` section 2), so a client that stops reading stops the upstream's reads, and the kernel's buffers and the sender's own TCP window take the rest. Nothing is dropped and nothing grows.

**Interest.** Level-triggered, as everywhere: a slot is watched for write only if bytes are queued for it and for read only if its sink has room. A tunnel at rest costs no CPU; `docs/proxy.md`'s no-spin test is repeated for it (gate 5).

**Timers.** Both are the client slot's existing deadline words, reset at the 101:

- *idle*: `now + ws_idle_timeout_ms`, reset every time a byte moves in either direction. Expiry closes both connections; the log line says `rule: "ws.idle-timeout"`.
- *lifetime*: `101 time + ws_max_lifetime_ms`, never reset. Expiry closes both; the log says `rule: "ws.lifetime"`.

The gateway **does not send a WebSocket Close frame** when it closes on a timer. It cannot do so safely: it does not parse frames, so it cannot know whether the byte it would write lands in the middle of a frame the upstream is
sending. The peer sees a TCP close without a close handshake (WebSocket close code 1006 on its side, "abnormal closure"). That is the price of a byte tunnel and it is stated here rather than discovered.

**Ends.**

| who ended it | what the gateway does | log outcome |
|---|---|---|
| the client closed its side (FIN) | bytes already read are forwarded, then both connections close. cancho has no half-close, so an upstream that was still sending is cut | `ok` |
| the upstream closed its side | bytes already read are written to the client, then both close | `ok` |
| a read or write failed (reset, broken pipe) | both close at once | `aborted` |
| `ws.idle-timeout`, `ws.lifetime` | both close at once | `aborted`, with the tag in `rule` |

Whether a peer closed after a proper WebSocket close handshake is not known to the gateway; `ok` means a peer ended the connection by closing it, not that the application protocol ended cleanly.

**Admission of bytes before the 101.** The client is not read between the end of its head and the 101 (row 6 refuses what came with the head). Bytes it sends in that window wait in the kernel and are forwarded after the 101;
they cannot reach the upstream earlier.

## 8. Idle ping policy: none in slice 1

The gateway sends nothing on its own. An idle tunnel is closed by `ws_idle_timeout_ms`. Charger-side liveness is the charger's: OCPP's `Heartbeat` (or any message) is traffic that resets the idle timer, and a
WebSocket ping from either end is traffic too. What this means in practice: with the default 600 s, a charger that heartbeats every 300 s survives; a charger that is silent longer is closed, and reconnects. A gateway-originated ping
(which would keep a NAT binding alive and detect a dead peer sooner) needs frame awareness and is a later slice.

## 9. Capacity

A tunnel is two slots (256 in the table), and 16 KiB + 32 KiB of buffers on each: 96 KiB. With the table as it is (`docs/proxy.md` section 3), **at most 127 sessions of any kind** exist, and `ws_max_tunnels` is bounded by that.
A deployment that sets it near 127 leaves no room for ordinary requests on the same gateway; the default 64 leaves 63 sessions, and a deployment with long-lived tunnels and short requests should put them on separate
gateways or accept that bound. The count of tunnels in progress and open is `sessions with an upgrade flag`, taken from the slot table by a scan, so it cannot drift from the table.

This slice does not raise the table. A deployment of ten thousand chargers (the spike in cancho's `docs/websocket-spike.md` held 9,999 in 79.8 MB on a dedicated server) needs the slot count to become a deployment key, which changes the memory budget of the whole gateway (`docs/tls.md`
section 4 already lists 23 MiB of TLS state at 256 slots) and is measured separately. **Unknown:** the CPU and memory of the tunnel path at hundreds of tunnels; gate 5 measures the 127 case only.

## 10. Interaction with the pool, the circuit and the retry

- **Pool.** The upstream connection of an upgrade is fresh (`dial` is told not to take an idle connection) and, when the session ends, **closed, never pooled**: a connection that carried a `101` is no longer an HTTP connection.
- **Retry.** An upgrade is never sent again: its `st[16]` retry flag is cleared (a `GET` without a body is otherwise retried once if a pooled connection turns out dead; here there is no pooled connection to be dead).
- **Circuit.** The upgrade counts like any request: a connect failure, a timeout, a `101` the checks refuse (`ws.upstream-*`) are failures of the upstream; a `101` that passes is a success and closes the circuit. A request refused by
  the gateway before dialling (every row of section 4) uses no trial of a half-open circuit, as other local refusals do not (`docs/health.md`). A tunnel that ends later does not count as anything: its length is not the upstream's fault.
- **Deadlines before the 101** are the ordinary ones: `connect_timeout_ms`, `upstream_timeout_ms` (the wait for the `101`), `total_timeout_ms`. At the 101 the total deadline is replaced by the lifetime and the phase deadline by the idle timer.

## 11. Observability

**Access log.** One line when the tunnel ends (not when it opens), in the existing key order, with the same fields: `status` 101, `rule` empty or `ws.idle-timeout` / `ws.lifetime`, `outcome` as in section 7, `ms` the whole
tunnel, `upstream_ms` the wait for the 101, `bytes_in` the bytes forwarded to the upstream, `bytes_out` the bytes queued for the client (the 101 head included). A new key, **`"upgrade":"websocket"`**, goes **last** (after `tls`), and is
written only on an upgrade, so a deployment without a WebSocket route writes the lines it always wrote and the key list the tests pin does not change for it. A refused upgrade is a refusal like any other: its line has the tag, the
refusal's status, and no `upgrade` key. **Consequence:** an open tunnel has no log line yet; `ws.tunnels_active` in the metrics is how an operator sees it. A line at open is a later decision (it would double the lines).

**Metrics.** Counter `ws_tunnels_total` (101s relayed); gauge `ws_tunnels_active` (the scan of section 9); `refusals_total{rule="ws.*"}` carries every tag of section 13, including the two closing tags (they are not refusals of a request but
the bound that keeps `refusals_total`'s label set closed is the same: tags the code owns). JSON gains `"ws":{"tunnels_total":…,"tunnels_active":…}` between `tls` and `log`; Prometheus gains the two families. Per-route
`bytes_in`/`bytes_out` and the duration histogram include tunnels when they end. The worst-case answer bound (`metrics.worst_case`) and its test are updated.

## 12. Smuggling, and the gates

**What a tunnel changes about smuggling.** After a `101` the gateway stops framing: whatever follows is opaque. The danger is therefore any disagreement about **where the HTTP message ends and the opaque stream begins**.

- *Request side.* An upgrade request with a body (`Content-Length`, any value including `0`; `Transfer-Encoding`; both) is refused (`ws.body`) rather than framed: if the gateway forwarded a body and the upstream treated the connection as upgraded
  at the head, the body would be read as frames; if the reverse, the frames would be a body. With no body there is no disagreement to have. The existing combinations (`Content-Length` with `Transfer-Encoding`, two lengths, a
  `Connection` naming a framing header) are refused earlier by `framing.*` and `forward.connection-token`, unchanged.
- *Pipelined bytes.* Bytes after the head are refused (`ws.early-data`); a client that pipelines a request behind an upgrade is attacking a parser that may treat it as a second request.
- *Response side.* A `101` with `Content-Length` or `Transfer-Encoding` is refused (`ws.upstream-upgrade`). A `101` the session did not ask for is refused (`response.status`, as it is today). A non-`101` final answer closes the connection after the
  body as every response does, so a response cannot turn a connection into a tunnel.
- *Header spelling.* `Upgrade`, `Connection` and `Sec-WebSocket-*` are matched on the parsed header name, which the parser has already restricted to token characters with no whitespace before the colon and no folding
  (`docs/framing.md`); duplicates are refused, not merged; a `Connection` token list that names a header the check reads is refused (section 4 row 4).
- *Keys that are not what they look like.* A key of 24 characters that decodes to a different number of bytes, or with non-canonical padding, is refused (row 8).

**Refusal tags** (every one has a status, a rule tag, a row in the access log and in `refusals_total`; all use `application/problem+json` as every refusal does):

| tag | status | | tag | status |
|---|---|---|---|---|
| `ws.method` | 400 | | `ws.upstream-upgrade` | 502 |
| `ws.http-version` | 400 | | `ws.upstream-accept` | 502 |
| `ws.upgrade` | 400 | | `ws.upstream-subprotocol` | 502 |
| `ws.body` | 400 | | `ws.upstream-extensions` | 502 |
| `ws.early-data` | 400 | | `ws.idle-timeout` | closing, no response |
| `ws.version` | 426 | | `ws.lifetime` | closing, no response |
| `ws.key` | 400 | | `ws.limit` | 503 |
| `ws.subprotocol` | 400 | | `ws.origin` | 403 |
| `config.websocket` | the generator's, exit 2 | | | |

**Gates, fixed before the code; each must be able to fail (gate 8 shows it).**

1. **End to end, plain** (`tests/websocket_test.py`): a Python RFC 6455 client and a Python RFC 6455 upstream (both written for the test, from the RFC, not from the gateway), through a built gateway: text, binary (1 byte, 125, 126, 65535, 65536 bytes), ping with
   payload answered by a pong with the same payload, a close handshake with a code and a reason, subprotocol selection of `ocpp1.6` and `ocpp2.0.1` on two routes. Also: the access log line of a finished tunnel has `status` 101, `"upgrade":"websocket"`
   last, the byte counts equal to what the test sent and received, and a non-upgrade line has no `upgrade` key.
2. **The accept value against `hashlib`:** the RFC 6455 example key, and 300 random keys, each through the gateway: the upstream computes the accept with `hashlib` and `base64`, the gateway with its own SHA-1 and base64 and compares; every handshake succeeds
   only if the two agree. A mutant that changes one constant of SHA-1 or the GUID must fail it. Unit tests in cancho (`tests/websocket_test.cho`) carry the SHA-1 vectors of FIPS 180-4 and the RFC's example.
3. **Refusals, one test for each tag** of section 12 with the status and tag asserted and, for every refusal made **before** the dial, **the upstream's connection count unchanged** (the upstream never saw it): the section 4 table row by row, including the smuggling-style corpus: `Content-Length: 0`, `Content-Length: 5` with 5 bytes, `Transfer-Encoding: chunked`,
   both, `Upgrade` twice, `Upgrade: websocket, h2c`, `Connection: upgrade, sec-websocket-key`, `Connection` twice, `Upgrade` with a space before the colon, with obs-fold, in odd case, a request line of `GET http://host/ HTTP/1.1`, HTTP/1.0, bytes pipelined behind the head, a key of 23, 25 and 24 non-base64
   characters, a key of non-canonical padding, two keys, version 8 and `13, 8` and none, an origin not listed, two origins, `Origin: null`, a subprotocol not listed, none offered to a route that lists some, one offered to a route that lists none, a subprotocol list with an empty item. Upstream-side: an upstream whose `101` has a wrong
   accept, no accept, two accepts, no `Upgrade`, `Content-Length`, `Transfer-Encoding`, an unoffered subprotocol, a subprotocol where none is served, no subprotocol where one is required, an extension; and a `101` to a plain request; and a `200`/`401`/`404` to an upgrade (relayed with its status).
4. **Tunnel integrity under back-pressure:** a 1 MiB message in each direction, and a 1 MiB message echoed while the client does not read for a second; 8 MiB sent by the upstream to a client that reads late; all byte-for-byte (SHA-256); the gateway's resident memory
   does not grow past the slabs it allocated at start (bounded, measured); `ws.idle` timer does not fire while data is draining slowly.
5. **Deadlines and no spin:** an idle tunnel is closed at `ws_idle_timeout_ms` (within a bound, with `ws.idle-timeout` in the log); traffic every half interval keeps it open past three intervals; a busy tunnel is closed at `ws_max_lifetime_ms` with
   `ws.lifetime`; a tunnel at rest and one with a non-reading peer use under 0.05 s of CPU in a second; a tunnel ended by the client or the upstream leaves no descriptor and no slot (`sessions_active` and `ws.tunnels_active` return to their start); 120 tunnels
   at once all carry bytes, the 121st past `ws_max_tunnels` is refused `ws.limit`, and ordinary requests are served meanwhile.
6. **`wss`:** gates 1, 3 (a representative subset), 4 (1 MiB both ways) and the lifetime test over `tls_listen` with certificates made as in `tests/tls_test.py`; the log line carries both `"tls":true` and `"upgrade":"websocket"`.
7. **Generator:** every refusal of section 3 has a rule tag and a line (`tests/generate_test.py`, counts updated); `deploy/examples/ocpp.toml` generates, builds and is the deployment of the example on the site.
8. **Mutants** of the new code, each killed by a named test or argued: each check of section 4 removed, the accept not compared, the accept compared on a prefix, a key check loosened, the origin list ignored, the subprotocol mask ignored (client side, upstream side), the extensions header not removed, the tunnel's two directions
   (one not pumped; the sink's room not respected; the idle timer not reset; the lifetime not applied), the limit not applied, the pool taking the tunnel's connection back, the `ws` flag lost at the dial, the log's `upgrade` key missing, the gauge not decremented. The table of results is recorded in section 13.
9. **The authority report does not change** except for the pure-function list (no new effect); the 2,000-line gate; the existing suites pass unchanged (`proxy_test.py`, `admin_test.py`, `tls_test.py`, `cancho test`).

## 13. As built

*(filled in after the build)*
