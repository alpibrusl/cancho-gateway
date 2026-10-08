# WebSocket proxying (task #15), first slice

Status: **slice 1 built (2026-10-08).** Sections 1 to 12 are the decision, written before the code; the gates in section 12 were fixed then and must be able to fail. Section 13 is what was built, what was measured and the mutants, and says where
the build found the design false; a claim found false is corrected in place and marked *(corrected)*. Claims about cancho are about the pinned
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
- **Unknown, to be measured** *(measured, section 13: it accepts)*: whether `std.http.parse` at this commit accepts a request head carrying `Upgrade` and `Sec-WebSocket-*` headers without comment. The code reads as if it does (it treats `Upgrade` as an ordinary header and the
  gateway strips it today as hop-by-hop, `src/forward.cho`); gate 1 measures it.

## 3. Deployment keys

Per route (all optional; `subprotocols` and `origins` are refused without `websocket = true`, rule `config.websocket`):

| key | type | default | meaning |
|---|---|---|---|
| `websocket` | bool | `false` | the route accepts WebSocket upgrades. A request without `Upgrade` is an ordinary request on the same route |
| `subprotocols` | list of up to 8 tokens | `[]` | the subprotocols the route serves (`"ocpp1.6"`, `"ocpp2.0.1"`). Each is an RFC 9110 token of at most 64 bytes, no repeats. An empty list means the route serves **no** subprotocol (section 4, row 9) |
| `origins` | list of up to 16 strings | `[]` | the `Origin` values a request may carry (section 4, row 10), each `scheme://host[:port]` exactly as a browser writes it (lowercase scheme and host, no path, no trailing slash) |

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
| 9 | subprotocols: at most one `Sec-WebSocket-Protocol` header, a comma-separated list of tokens, each at most 64 bytes, no empty items, at most 16. Then: if the route lists any, the client must offer at least one of them; if the route lists none, the client must offer none. Comparison is exact and case-sensitive (RFC 6455 section 11.5 registry names are lowercase; 4.2.2 item 5.ii compares case-sensitively) | `ws.subprotocol` 400 |
| 10 | origin: at most one `Origin` header. A request with **no** `Origin` header is not from a browser and is admitted. A request **with** one must equal, byte for byte, an entry of the route's `origins`; an empty list admits none. There is no wildcard | `ws.origin` 403 |
| 11 | tunnels in progress or open are fewer than `ws_max_tunnels` | `ws.limit` 503 |

Why rows 9 and 10 are shaped as they are. *(Corrected: the design listed the format and the match of each as four rows, 9 to 12, and the limit as 13; the code checks each pair together, so the rows are merged and the order of the two pairs is subprotocol then origin.)* A browser always sends `Origin` on a WebSocket request, and a script on any web page can ask the browser to open a socket to your back office with the user's cookies and network position
(cross-site WebSocket hijacking, RFC 6455 section 10.2). Refusing an unlisted `Origin` is the whole defence at this layer, and a charger (which is not a browser and sends none) is unaffected. The default, an empty list, admits no
browser at all. The subprotocol rule is the other half of an OCPP route: a charger that offers `ocpp1.6` to a route that serves `ocpp2.0.1` is refused at the edge, with a tag, instead of reaching a back office that would close it with
a code.

Row 11 is checked last so that a refused request does not count against the bound; the count is taken when the check passes and released when the session ends, so a refusal later (the upstream's) frees it.

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
section 4 already lists 23 MiB of TLS state at 256 slots) and is measured separately. **Unknown** *(measured at 120 in section 13)*: the CPU and memory of the tunnel path at hundreds of tunnels.

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

1. **End to end, plain** (`tests/websocket_test.py`): a Python RFC 6455 client and a Python RFC 6455 upstream (both written for the test, from the RFC, not from the gateway), through a built gateway (and, where the `websockets` library is installed, that library as a client and as an upstream: an implementation that is not ours): text, binary (1 byte, 125, 126, 65535, 65536 bytes), ping with
   payload answered by a pong with the same payload, a close handshake with a code and a reason, subprotocol selection of `ocpp1.6` and `ocpp2.0.1` on two routes. Also: the access log line of a finished tunnel has `status` 101, `"upgrade":"websocket"`
   last, the byte counts equal to what the test sent and received, and a non-upgrade line has no `upgrade` key.
2. **The accept value against `hashlib`:** the RFC 6455 example key, and 300 random keys, each through the gateway: the upstream computes the accept with `hashlib` and `base64`, the gateway with its own SHA-1 and base64 and compares; every handshake succeeds
   only if the two agree. A mutant that changes one constant of SHA-1 or the GUID must fail it. Unit tests in cancho (`tests/websocket_test.cho`) carry the SHA-1 vectors of FIPS 180-4 and the RFC's example.
3. **Refusals, one test for each tag** of section 12 with the status and tag asserted and, for every refusal made **before** the dial, **the upstream's connection count unchanged** (the upstream never saw it): the section 4 table row by row, including the smuggling-style corpus: `Content-Length: 0`, `Content-Length: 5` with 5 bytes, `Transfer-Encoding: chunked`,
   both, `Upgrade` twice, `Upgrade: websocket, h2c`, `Connection: upgrade, sec-websocket-key`, `Connection` twice, `Upgrade` with a space before the colon, with obs-fold, in odd case, a request line of `GET http://host/ HTTP/1.1`, HTTP/1.0, bytes pipelined behind the head, a key of 23, 25 and 24 non-base64
   characters, a key of non-canonical padding, two keys, version 8 and `13, 8` and none, an origin not listed, two origins, `Origin: null`, a subprotocol not listed, none offered to a route that lists some, one offered to a route that lists none, a subprotocol list with an empty item. Upstream-side: an upstream whose `101` has a wrong
   accept, no accept, two accepts, no `Upgrade`, `Content-Length`, `Transfer-Encoding`, an unoffered subprotocol, a subprotocol where none is served, no subprotocol where one is required, an extension; and a `101` to a plain request; and a `200`/`401`/`404` to an upgrade (relayed with its status).
4. **Tunnel integrity under back-pressure:** a 1 MiB message in each direction, and a 1 MiB message echoed while the client does not read for a second; 8 MiB sent by the upstream to a client that reads late; all byte-for-byte (SHA-256); the gateway's resident memory
   does not grow past the slabs it allocated at start (bounded, measured); `ws.idle` timer does not fire while data is draining slowly. *(Corrected in section 13: 32 MiB toward the upstream as well, because 8 MiB was absorbed by the kernel's buffers; the last clause was not tested.)*
5. **Deadlines and no spin:** an idle tunnel is closed at `ws_idle_timeout_ms` (within a bound, with `ws.idle-timeout` in the log); traffic every half interval keeps it open past three intervals; a busy tunnel is closed at `ws_max_lifetime_ms` with
   `ws.lifetime`; a tunnel at rest and one with a non-reading peer use under 0.05 s of CPU in a second; a tunnel ended by the client or the upstream leaves no descriptor and no slot (`sessions_active` and `ws.tunnels_active` return to their start); 120 tunnels
   at once all carry bytes, the 121st past `ws_max_tunnels` is refused `ws.limit`, and ordinary requests are served meanwhile.
6. **`wss`:** gates 1, 3 (a representative subset), 4 (1 MiB both ways) and the lifetime test over `tls_listen` with certificates made as in `tests/tls_test.py`; the log line carries both `"tls":true` and `"upgrade":"websocket"`.
7. **Generator:** every refusal of section 3 has a rule tag and a line (`tests/generate_test.py`, counts updated); `deploy/examples/ocpp.toml` generates, builds and is the deployment of the example on the site.
8. **Mutants** of the new code, each killed by a named test or argued: each check of section 4 removed, the accept not compared, the accept compared on a prefix, a key check loosened, the origin list ignored, the subprotocol mask ignored (client side, upstream side), the extensions header not removed, the tunnel's two directions
   (one not pumped; the sink's room not respected; the idle timer not reset; the lifetime not applied), the limit not applied, the pool taking the tunnel's connection back, the `ws` flag lost at the dial, the log's `upgrade` key missing, the gauge not decremented. The table of results is recorded in section 13.
9. **The authority report does not change** except for the pure-function list (no new effect); the 2,000-line gate; the existing suites pass unchanged (`proxy_test.py`, `admin_test.py`, `tls_test.py`, `cancho test`).

## 13. As built

Built 2026-10-08, on a branch of its own; everything below was run on the development machine against the pinned compiler (`2fcf4cd`).

**What exists.**

- *Deployment keys* (`scripts/generate.py`, one tag, `config.websocket`): per route `websocket`, `subprotocols`, `origins`; deployment-wide `ws_idle_timeout_ms`, `ws_max_lifetime_ms`, `ws_max_tunnels`. The route table has three more columns (8 to 10); `generated/deploy.cho` has `ws_idle_ms`, `ws_lifetime_ms`, `ws_max_tunnels`.
- *`src/websocket.cho`* (468 lines, pure, no effect): `asks_upgrade`, `judge` (section 4), `accept_for`, `check_response` (section 6), `upgrade_response` (the head the client is sent), the rule tags and statuses. `src/sha1.cho` and `src/b64.cho` are cancho's spike files with the module name changed.
- *The proxy* (`src/proxy.cho`, 1,334 to 1,550 lines, still the largest file): the block in `head_ready`, `upgrade_answered`, `tunnel_down`, `tunnel_up`, a dispatch at the top of `pump_response` and `pump_request`, a tunnel branch in `settle`, `step`, `read_client`, `read_upstream` and `sweep`, and the TLS turn. A tunnel is client phase 6 and upstream state 16 = 2. `src/shared.cho`: client stride 40 to 48 (fields 40 `ws_mode`, 41 `ws_mask`; 32 to 39 stay TLS's), meta area 256 to 288 bytes (the accept value at 252), `tunnels` (the scan of section 9). `src/forward.cho`: `rewrite_upgrade`. `src/response.cho`: `parse_upgrade`. `src/problem.cho`: 403 and 426 (with `Sec-WebSocket-Version: 13`). `src/accesslog.cho`: the `upgrade` key. `src/metrics.cho`: `ws_tunnels_total`, `ws_tunnels_active`, and the worst-case bound.
- *Tests:* `tests/websocket_test.cho` (23 cancho tests: every row of sections 4 and 6 case by case, the accept value against the RFC's example and SHA-1's vectors), `tests/websocket_test.py` (52 end-to-end tests, below), `tests/websocket_mutants.py` (the mutant runner), 35 `config.websocket` refusal cases and 6 accepted deployments in `tests/generate_test.py`, 1 test of `forward.rewrite_upgrade` and 1 of the log line in the existing cancho tests. `deploy/examples/ocpp.toml` with `scripts/demo_ws_upstream.py` and `scripts/demo_ws_client.py` is example 8 on `docs/examples.html`; its output there is from a real run.

**Where the build found the design wrong, or the gate weaker than it read.**

| design | built | why |
|---|---|---|
| section 4 rows 9 to 12 (format and match of the subprotocol and of the origin as four rows), limit as row 13 | two rows (9 subprotocol, 10 origin) and the limit as row 11 | the code checks each pair together, subprotocol before origin; corrected in the table |
| gate 4: "8 MiB sent by the upstream to a client that reads late" only | 8 MiB toward the client **and 32 MiB toward the upstream** | the first version of the upstream-direction test sent 8 MiB and `send` returned at once: the kernel's buffers on loopback absorbed it, so nothing pushed back. 32 MiB blocked the sender for more than a second, which the test asserts |
| gate 4: "the idle timer does not fire while data drains slowly" | **not tested** | a slow reader is tested for integrity and bounded memory, not for the timer; the timer is reset when bytes move into a queue, and a reader that drains slowly keeps the queue moving, which is an argument, not a measurement |
| section 2, "unknown": `std.http.parse` and `Upgrade` | **measured: it accepts** a head with `Upgrade`, `Connection: Upgrade` and `Sec-WebSocket-*` as ordinary headers | every test of `judge` parses its request with it |
| section 9, "unknown": CPU and memory at hundreds of tunnels | **measured at 120** (below); not beyond | the gateway admits up to 127 (the table is 256 slots); 120 is what the test sets |
| section 12, gate 3 "one test for each tag" | one test checks 34 refusals before the dial, one 10 upstream-side modes plus a subprotocol where none is served, a corpus of 17 smuggling-shaped upgrades, and the cancho tests hold the rest case by case | the upstream-never-heard-of-it assertion is on the connection count, which is the same for all of them |
| the 426 | `application/problem+json` with the version in a header (`Sec-WebSocket-Version: 13`) | RFC 6455 4.4; `problem.response` writes the header for this one status |

Two defects the first runs of the tests found **in the tests**, not in the gateway: an upstream path (`/plain101`) that the test's own upstream answered as plain HTTP, and the idle/lifetime test whose first version could not tell a tunnel closed at the idle time from one closed at the lifetime (the lifetime is now 4 s against an idle time of 1 s).

**Gates.**

| gate | status | where |
|---|---|---|
| 1 end to end, plain | **met** | `websocket_test.py`: text, binary at 0, 1, 125, 126, 127, 65535, 65536 and 70000 bytes, ping and pong with a payload, a close handshake with a code, a fragmented message, `ocpp1.6` and `ocpp2.0.1` selected on two routes, a route with no subprotocol, a server that speaks first, a frame sent before the 101. The log line of a finished tunnel: `status` 101, `"upgrade":"websocket"` last, `bytes_in` equal to the bytes the client sent, `bytes_out` equal to the 101 head plus the bytes it received, no `tls` key; an ordinary request on the same gateway writes the line it always wrote |
| 2 the accept value against `hashlib` | **met** | the RFC example key and 300 random keys through the gateway (the gateway compares its own SHA-1 and base64 with the upstream's `hashlib`); the cancho tests carry the SHA-1 vectors of the empty message, `abc` and the 448-bit message of FIPS 180-4; mutants r11 to r14 |
| 3 refusals, the corpus | **met** | section 12's tag table, each tag asserted with its status; a refusal before the dial leaves the upstream's connection count unchanged; the smuggling corpus; every upstream-side refusal; a `401` relayed with its body; a `101` to a plain request refused (`response.status`) |
| 4 integrity and back-pressure | **met, with the corrections above** | 1 MiB each way, six 600 KB messages echoed to a reader that reads nothing for a second, 8 MiB to a client with a 4 KiB receive buffer that reads after 1.5 s (the gateway's resident memory grew by under 4 MiB while it waited: asserted), 32 MiB to an upstream that reads after 1.5 s; all byte for byte; 3 MiB of random bytes that are not frames delivered exactly (the gateway does not judge them) |
| 5 deadlines, no spin, limits | **met** | idle close at the idle time (measured 1.0 s for a 1 s setting), traffic from either side alone keeps a tunnel open, a busy tunnel closed at the lifetime (4.2 s for 4 s), an upstream's 101 pending counts against the limit, 120 tunnels at once with the 121st refused `ws.limit` and an ordinary request served, ten tunnels at rest and a stuck one use under 0.05 s of CPU in a second, descriptors and slots return to their start, 500 hostile upgrade requests leave the gateway answering |
| 6 `wss` | **met** | frames of every kind, the scheme the upstream sees (`https`), 1 MiB each way, 8 MiB to a late reader, refusals, the idle and lifetime closes, a client that vanishes without `close_notify`; the line carries `"tls":true` then `"upgrade":"websocket"` |
| 7 generator | **met** | 35 `config.websocket` refusals and 6 accepted deployments (117 refusal cases in all); `deploy/examples/ocpp.toml` generates, builds and ran |
| 8 mutants | **75 single edits: 72 killed, 3 survive, each argued** | below |
| 9 authority and the suites | **met** | the labels did not change (`args, clock, conn_accept, conn_read, conn_write, dir_read, file_read, heap, io_write, net_in(""), net_out(""), poll`; `gateway-tls` adds the same two `fs_read` paths); the manifests were re-recorded because the list of pure functions and the operator counts grew (1,326 to 1,380 functions); no source file over 2,000 lines; `proxy_test.py` 75 tests, `admin_test.py` 16, `tls_test.py` 18, `cancho test` 88, all passing with no change to them but the new `ws` object in the metrics' key list |

**Counts, verbatim from the last full run.** `websocket_test.py`: `52 tests, 0 failures` (with the `websockets` library installed; without it `52 tests, 0 failures, 2 skipped`). `proxy_test.py`: `75 tests, 0 failures`. `admin_test.py`: `16 tests, 0 failures`. `tls_test.py`: `18 tests, 0 failures`. `generate_test.py`: `7 prefix cases, 117 refusal cases, 11 accepted, 0 failures`. `cancho test`: 10 suites, 88 tests, 0 failed (websocket 23, forward 20, accesslog 12, metrics 11). `route_test.py 12 400`: `12 tables, 4800 requests (1356 routed, 3444 refused), 0 failures`; `--fixed`: `18 fixed cases, 0 failures`. `smuggling/run.py --gateway`: `60 cases, 0 disagreements`; `--chunked`: `39 chunked cases x 6 deliveries = 234 runs, 0 failures`.

**Measured, informally** (one machine, `tests`' Python endpoints on the same machine, the gateway's CPU from `/proc` in 10 ms ticks, so only totals over many runs mean anything; this is **not** the benchmark harness and compares nothing to another proxy). *Memory:* 2.2 MiB resident at start; 4.6 MiB with 120 tunnels open (about 20 KiB each: the slabs are allocated at start and touched as used); unchanged after they close. *CPU:* 0.0000 s a second for 120 idle tunnels over 3 s. *Throughput:* moving 320 MiB from the upstream to the client in 8 MiB frames cost the gateway 0.44 s of CPU (1.4 ms a MiB; 423 MiB/s wall median per 8 MiB), against 0.41 s (1.3 ms a MiB; 680 MiB/s) for relaying 320 MiB of plain HTTP response bodies on the same gateway: **the tunnel costs about what a response relay costs**. An 8 MiB message echoed both ways: 0.82 s of CPU for 640 MiB moved (1.3 ms a MiB). *Latency:* a 64-byte echo, 2,000 messages on one tunnel: p50 140 us and p99 278 us through the gateway, against p50 70 us and p99 175 us straight to the upstream: **the gateway adds about 70 us at the median**, one hop on loopback. The cost of the new column read on a request that is not an upgrade (one more scan of the route table per request) is **not measured**; the benchmark harness has not been run for this slice.

**Mutants** (`python3 tests/websocket_mutants.py`: copy the tree, apply one edit, run the tests that should notice it, then the whole suite if they do not). **75 edits: 72 killed, 3 survive.** Three of the 75 were first written wrongly (the old text occurred twice, or had been reformatted by `cancho fmt`): they were corrected and rerun, and are in the table as killed.

| id | the single edit | result |
|---|---|---|
| w01 | the method is not checked | killed by `rule_1_refuses_a_method_other_than_GET` (unit) |
| w02 | HTTP/1.0 is admitted | killed by `rule_2_refuses_HTTP_1_0` (unit) |
| w03 | two Upgrade headers are admitted | killed by `rule_3_refuses_an_Upgrade_that_is_not_exactly_websocket_once` (unit) |
| w04 | any Upgrade protocol is admitted | killed by `rule_3_refuses_an_Upgrade_that_is_not_exactly_websocket_once` (unit) |
| w05 | any other Connection token is admitted | killed by `rule_3_refuses_an_Upgrade_that_is_not_exactly_websocket_once` (unit) |
| w06 | two Connection headers are admitted | killed by `rule_3_refuses_an_Upgrade_that_is_not_exactly_websocket_once` (unit) |
| w07 | a Content-Length (even 0) is admitted | killed by `rule_4_refuses_a_body_or_a_header_that_says_there_is_one` (unit) |
| w08 | a Transfer-Encoding is admitted | killed by `rule_4_refuses_a_body_or_a_header_that_says_there_is_one` (unit) |
| w09 | bytes pipelined behind the head are admitted | killed by `rule_5_refuses_bytes_after_the_head` (unit) |
| w10 | any version is admitted | killed by `rule_6_refuses_a_version_other_than_13` (unit) |
| w11 | two version headers are admitted | killed by `rule_6_refuses_a_version_other_than_13` (unit) |
| w12 | a non-canonical key is admitted | killed by `rule_7_refuses_a_key_that_is_not_16_bytes_in_canonical_base64` (unit) |
| w13 | a key without its padding is admitted | killed by `rule_7_refuses_a_key_that_is_not_16_bytes_in_canonical_base64` (unit) |
| w14 | a key of the wrong length is admitted | killed by `rule_7_refuses_a_key_that_is_not_16_bytes_in_canonical_base64` (unit) |
| w15 | a client that offers none of the route's subprotocols is admitted | killed by `rule_8_refuses_a_subprotocol_the_route_does_not_serve_or_a_list_that_is_not_one` (unit) |
| w16 | a subprotocol is admitted on a route that serves none | killed by `rule_8_refuses_a_subprotocol_the_route_does_not_serve_or_a_list_that_is_not_one` (unit) |
| w17 | a list of 17 subprotocols is admitted | killed by `rule_8_refuses_a_subprotocol_the_route_does_not_serve_or_a_list_that_is_not_one` (unit) |
| w18 | every Origin is admitted | killed by `rule_9_admits_no_browser_origin_that_is_not_listed_and_any_request_without_one` (unit) |
| w19 | two Origin headers are admitted | killed by `rule_9_admits_no_browser_origin_that_is_not_listed_and_any_request_without_one` (unit) |
| w20 | the offered mask names the first subprotocol only | killed by `a_good_handshake_is_admitted_and_answers_the_offered_subprotocols` (unit) |
| r01 | the accept value is not compared | killed by `rule_12_refuses_an_accept_value_that_is_not_exactly_the_one_called_for` (unit) |
| r02 | the accept value is compared on a prefix | killed by `rule_12_refuses_an_accept_value_that_is_not_exactly_the_one_called_for` (unit) |
| r03 | two accept headers are admitted | killed by `rule_12_refuses_an_accept_value_that_is_not_exactly_the_one_called_for` (unit) |
| r04 | a 101 without Upgrade: websocket is admitted | killed by `rule_11_refuses_a_101_that_is_not_a_websocket_upgrade_or_has_a_body_header` (unit) |
| r05 | a 101 without Connection: Upgrade is admitted | killed by `rule_11_refuses_a_101_that_is_not_a_websocket_upgrade_or_has_a_body_header` (unit) |
| r06 | a 101 with a body header is admitted | killed by `rule_11_refuses_a_101_that_is_not_a_websocket_upgrade_or_has_a_body_header` (unit) |
| r07 | a subprotocol the client did not offer is admitted | killed by `rule_13_refuses_a_subprotocol_that_was_not_offered_or_not_served` (unit) |
| r08 | no subprotocol is admitted where the route requires one | **survived**, argued below |
| r09 | a subprotocol is admitted where the route serves none | killed by `rule_13_refuses_a_subprotocol_that_was_not_offered_or_not_served` (unit) |
| r10 | an unsolicited extension is admitted | killed by `rule_14_refuses_an_extension_nobody_asked_for` (unit) |
| r11 | the GUID is wrong | killed by `the_accept_value_of_the_rfc_example_and_of_known_digests` (unit) |
| r12 | a SHA-1 round constant is wrong | killed by `the_accept_value_of_the_rfc_example_and_of_known_digests` (unit) |
| r13 | SHA-1's majority function is wrong | killed by `the_accept_value_of_the_rfc_example_and_of_known_digests` (unit) |
| r14 | the base64 alphabet is wrong | killed by `the_accept_value_of_the_rfc_example_and_of_known_digests` (unit) |
| r15 | the 101 head carries a field nobody checked | killed by `the_head_the_client_is_sent_carries_only_what_was_checked` (unit) |
| f01 | Sec-WebSocket-Extensions is forwarded | killed by `an_upgrade_is_forwarded_with_its_own_connection_headers_and_without_extensions` (unit) |
| f02 | the upstream is not told it is an upgrade | killed by `an_upgrade_is_forwarded_with_its_own_connection_headers_and_without_extensions` (unit) |
| f03 | a 101 is accepted for every request | killed by `a_101_is_a_refusal_unless_the_request_asked_for_an_upgrade` (unit) |
| f04 | a 426 does not name the version | killed by `an_upstream_that_reads_late_receives_thirty_two_mebibytes_intact` (e2e) |
| f05 | the log's upgrade value is wrong | killed by `an_upgrade_carries_its_field_last_and_the_worst_line_with_both_still_fits` (unit) |
| f06 | the route's websocket column is read from the wrong place | killed by `handshake_selects_the_subprotocol_and_the_head_has_only_checked_fields` (e2e) |
| p01 | no route is a websocket route | killed by `handshake_selects_the_subprotocol_and_the_head_has_only_checked_fields` (e2e) |
| p02 | the limit is off by one | killed by `the_limit_refuses_the_fourth_and_frees_with_a_close` (e2e) |
| p03 | the limit is not applied | killed by `a_hundred_and_twenty_tunnels_at_once_and_the_next_is_refused` (e2e) |
| p04 | an upgrade may take a pooled connection | killed by `a_tunnel_connection_is_never_pooled` (e2e) |
| p05 | a 101 is never accepted | killed by `handshake_selects_the_subprotocol_and_the_head_has_only_checked_fields` (e2e) |
| p06 | the upstream's 101 is not checked | killed by `the_upstreams_refusals_of_the_upgrade_each_have_their_tag` (e2e) |
| p07 | a bad 101 is not a failure of the upstream | killed by `the_circuit_counts_a_bad_101_and_closes_on_a_good_one` (e2e) |
| p08 | a good 101 is not a success of the upstream | killed by `the_circuit_counts_a_bad_101_and_closes_on_a_good_one` (e2e) |
| p09 | the idle timer is not reset by the upstream's bytes | killed by `traffic_from_the_upstream_alone_keeps_a_tunnel_open` (e2e) |
| p10 | the idle timer is not reset by the client's bytes | killed by `traffic_from_the_client_alone_keeps_a_tunnel_open` (e2e) |
| p11 | the lifetime is not applied | killed by `a_busy_tunnel_is_closed_at_the_lifetime` (e2e) |
| p12 | the sweep does not close at the lifetime | killed by `a_busy_tunnel_is_closed_at_the_lifetime` (e2e) |
| p13 | the sweep does not close an idle tunnel | killed by `an_idle_tunnel_is_closed_at_the_idle_time` (e2e) |
| p14 | the client's queue room is not respected (downstream) | killed by `a_client_that_reads_late_gets_eight_mebibytes_intact_with_the_queues_bounded` (e2e) |
| p15 | the upstream's queue room is not respected (upstream) | killed by `an_upstream_that_reads_late_receives_thirty_two_mebibytes_intact` (e2e) |
| p16 | a client that closed leaves the tunnel up | killed by `the_client_closing_ends_the_upstream_connection_and_frees_the_slots` (e2e) |
| p17 | an upstream that closed leaves the tunnel up | killed by `the_upstream_closing_ends_the_client_side` (e2e) |
| p19 | a tunnel's client is never read | killed by `text_binary_ping_and_close_frames_go_both_ways` (e2e) |
| p20 | a write to a lost upstream is answered as if it were an HTTP exchange | **survived**, argued below |
| p21 | the offered mask is lost | killed by `handshake_selects_the_subprotocol_and_the_head_has_only_checked_fields` (e2e) |
| p22 | the upstream is sent the ordinary rewrite | killed by `the_upstream_is_sent_the_checked_request_and_no_extensions` (e2e) |
| p23 | the tunnel counter does not count | killed by `metrics_count_the_tunnel_and_return_to_zero` (e2e) |
| p24 | the client stays in the request phase (not a tunnel) | killed by `text_binary_ping_and_close_frames_go_both_ways` (e2e) |
| p25 | the log line has no upgrade key | killed by `the_access_log_line_of_a_tunnel` (e2e) |
| p26 | the accept value overlaps the path in the meta area | killed by `a_long_path_is_logged_whole_beside_the_accept_value` (e2e) |
| p27 | the active gauge is not filled | killed by `metrics_count_the_tunnel_and_return_to_zero` (e2e) |
| p28 | an upgrade in progress holds no place | killed by `upgrades_still_waiting_for_their_101_hold_a_place` (e2e) |
| p29 | read_client does not call tunnel_up (pump_request dispatches there too: expected equivalent) | **survived**, argued below |
| p30 | the TLS turn does not read a tunnel's client again | killed by `a_wss_handshake_and_every_frame_type` (e2e) |
| p31 | a tunnel's client is not watched for reading | killed by `text_binary_ping_and_close_frames_go_both_ways` (e2e) |
| g01 | a websocket route may exclude GET | killed by `FAIL refusal config.websocket at line 9: exit 0` (generator) |
| g02 | an origin with a trailing slash is accepted | killed by `FAIL refusal config.websocket at line 9: exit 0` (generator) |
| g03 | ws_* keys are accepted without a websocket route | killed by `FAIL refusal config.websocket at line 2: exit 0` (generator) |
| g04 | more tunnels than the table holds | killed by `FAIL refusal config.websocket at line 2: exit 0` (generator) |

**The three that survive, and why:**

- **r08**, the check that a route which serves subprotocols refuses a `101` with none. It survives because the answer does not change: without the guard `value_of` reads header index −1, which lands on slots 14 and 15 of the response table (unused, so zero), an empty slice that matches no subprotocol, and the next check refuses with the same tag. The guard exists so that the answer does not depend on two unused slots staying zero; the behaviour it protects is covered by r09 and the `noproto` upstream mode.
- **p20**, `upstream_lost` treating a tunnel like a finished request when a write to the upstream fails. It survives because the fall-through reaches `refuse`, which, because the client's response has begun (the `101` was queued), just ends the session: the same end by a longer road.
- **p29**, `read_client` not calling `tunnel_up` itself. It survives because `pump_request` dispatches a phase 6 client to `tunnel_up` at its top: the call at the site is redundant, kept so that the data path reads straight.

**Not done, and not known.**

- **No frame is read**, so there is no ping or pong policy, no close handshake of the gateway's own, no message-size limit (a peer can send a 4 GiB frame and the tunnel carries it), no fragment limit, no UTF-8 check, no per-message anything. Each is a later slice with its own gate; section 8 and section 7 say what their absence costs.
- **No Close frame on a timer** (section 7), no gateway-originated keepalive, no `permessage-deflate` (stripped).
- **More than 127 tunnels**: the slot table; a deployment of thousands of chargers needs the slot count as a deployment key and a new memory budget. Measured only at 120.
- **The log line at open**: a tunnel that has not ended has no line; `ws_tunnels_active` is the only trace.
- **TLS to the upstream**, **a peer address** (no `conn_peer`: the charger's identity is the path), **RFC 8441** (WebSocket over HTTP/2).
- **A client that closes while its `101` is pending** is noticed when the `101` arrives, or at the upstream deadline, as a client whose whole request has been sent is today; the upgrade holds its place until then (a bound, not a leak: `ws_max_tunnels` counts it).
- **The cost of the new column read on an ordinary request** is not measured (the benchmark harness was not run for this slice).
- **A browser** was not used: the `Origin` rules are tested with the header, not with a real page. The `websockets` library (17.2) was run as a client and as an upstream (`Interop`, skipped without it); no other third-party implementation was.
