# The proxy core (task #5), first slice

Status: **a working reverse proxy, with deliberate gaps.** (Upstream keep-alive and the pool arrived in `docs/pool.md`; the first slice below opened one connection per request.) One thread, one poller, memory sized at start. Built: accept, head
framing and routing (tasks #3, #4), a fresh upstream connection per request, request body forwarding (Content-Length and
chunked), response relay, backpressure both ways, deadlines, refusals as `application/problem+json`. **Not built:** keep-alive
on either side and the upstream pool (#6), (the header policy of #7 is built: `docs/headers.md`), authentication (#8), rate limits
(#9), the metrics endpoint (#10; the access log is built), WebSockets (#15). Section 6 lists what is untested.

## 1. The flow of one request

1. **accept** (non-blocking) into a slot; a header deadline starts.
2. **read the head** into the slot's buffer; `framing.judge` (more, a refusal, or accepted).
3. **route** (`route.select`), refuse if the declared `Content-Length` exceeds the route's `max_body`, and note the upstream
   the route chose.
4. **dial** (`tcp_connect_start`) the upstream, after `egress.allowed` re-checks the address against the compiled-in set (which
   is also what keeps the compiler's bound trap unreachable, design section 2.1).
5. **forward**: `forward.rewrite` writes the head into the upstream's queue (hop-by-hop headers and any header named by
   `Connection` removed; `Connection: close` added), then the body, framed (`Content-Length` counted, chunked by
   `chunked.advance`), as the upstream takes it.
6. **relay** the upstream's bytes to the client unchanged until the upstream closes; then the session ends and the client's
   connection closes.

A slot is a client or an upstream connection; the two ends of a request point at each other. Per slot: a 16 KiB read buffer, a
32 KiB write queue, and sixteen state ints (layout in `src/proxy.cho`).

## 2. Backpressure and the loop

Readiness is **level-triggered**, so a session that is waiting must be watched for nothing: `settle` recomputes each slot's
interest (write if bytes are queued, read only if the phase wants input and there is room) and a slot with neither is watched
for neither. A client's request is read only while the upstream's queue has room; an upstream's response is read only while the
client's queue has room. Nothing is dropped and nothing grows.

## 3. Limits, deadlines, refusals

Slots: 256, a session holds two, so about 127 concurrent sessions. Memory: 256 x (16 + 32) KiB = 12 MiB of slabs, allocated at
start; the table of connection tickets (`std.conns`) grows with concurrency up to 256 entries.

Deadlines come from the deployment (`header_timeout_ms` 10000, `connect_timeout_ms` 5000, `upstream_timeout_ms` 30000,
`total_timeout_ms` 60000, each 100 to 600000, checked by the generator). **`total_timeout_ms` bounds the whole request including
the response**: a download longer than it is cut, not refused.

| rule | status | when |
|---|---|---|
| `timeout.header` | 408 | the head did not arrive in time |
| `timeout.connect` | 504 | the upstream did not accept in time |
| `timeout.upstream` | 504 | it accepted but did not start answering in time |
| `timeout.total` | 504 | the whole request ran out of time (if the response has begun, the session just ends) |
| `proxy.connect` | 502 | refused or failed |
| `proxy.upstream-closed` | 502 | it closed without answering |
| `proxy.egress` | 502 | the address is not in the compiled-in set (cannot happen with a generated table) |
| `proxy.head` | 502 | the head could not be rebuilt for the upstream |
| `limit.connections` | 503 | no slot for the upstream half |
| `forward.*`, `framing.*`, `route.*`, `limit.body` | per `docs/framing.md`, `docs/routes.md` | |

**Where this differs from design section 4:** a client that arrives when the table is full is **closed without a response**
(there is no slot to answer in); `limit.connections` 503 is only sent when the upstream half cannot be opened.

**A refused client is kept open for a moment.** cancho has no half-close (`shutdown`), and closing a socket with unread request
bytes in it sends a reset that can destroy the response before the client has read it (RFC 9112 9.6). So after a refusal is
written the gateway reads and discards the client's input until it has been silent for 500 ms, or for at most three seconds.

## 4. Measured: `python3 tests/proxy_test.py` (25 tests, about 20 s)

The built gateway, real sockets, a scripted upstream. Every test can fail (section 5).

- **Correct bytes:** a 600 KB Content-Length body and a 12-chunk chunked body echo back identical (hash); a request trickled one
  byte at a time; a 6 MiB response to a client that starts reading late, byte-identical; **six concurrent 12 MiB downloads
  through a 4 KB receive window**, each started late, byte-identical (this is what fills the gateway's own queues).
- **Refusals:** eleven malformed or forbidden requests answered with the right status and rule; none reaches the upstream; a
  chunked body over the route's limit is answered 413 after part of it was already forwarded.
- **Timeouts:** twenty slowloris clients do not delay others (five requests in under a second) and each gets 408; a stalled
  upstream is answered 504 in 1.2 to 3.5 s and its connection is closed; a request that never completes is answered 504 by the
  total deadline; a refused connection is 502; an upstream that closes without answering is 502.
- **Abuse:** an upstream that cuts its response gives the client the bytes it sent and a close; a client that leaves mid-body or
  mid-response leaves **no upstream connection and no file descriptor behind**; 300 simultaneous connections do not stop it;
  300 hostile connections (random and mutated bytes) leave it answering.
- **No spin:** with ten stalled upstream sessions, an upload blocked by a non-reading upstream and a download blocked by a
  non-reading client, the gateway uses under 0.05 s of CPU in 0.8 s.
- **No leaks:** after 900 warm-up requests, 4,500 more (good, with a body, and refused) leave the descriptor count unchanged and
  resident memory within 512 KB.
- **One connection per request:** seven requests make exactly seven upstream connections (so nothing is retried).

## 5. Mutants, and what the first tests missed

Each killed by the test named: the peer not closed with the session (`client_leaves_mid_body`); deadlines never firing (three
tests); no framing of a chunked body (`chunked_body_over_limit`); a body over `max_body` forwarded (`refusals`); a refusal not
lingering (`a_refusal_survives_unread_request_bytes`: the client's `sendall` is reset); a blocked session keeping its read
interest (`blocked_sessions_do_not_spin`: **0.8 s of CPU in 0.8 s**).

**Survivors and what they showed:**
- *The response queue's room not respected* survived the first large-response tests, and a 3 MiB concurrent test. It was only
  killed by six concurrent 12 MiB downloads through a 4 KB window (the gateway then **traps**: the queue overruns its slab). The
  kernel's socket buffers had been absorbing the whole response, so the gateway's queue never filled.
- *The peer not closed with the session* survives in `client_leaves_mid_response`: an upstream that is still sending raises an
  event that finds its client gone and closes itself, so the cleanup is lazy and the mutant is equivalent there. It is killed
  where there is no such event (`client_leaves_mid_body`).

**What testing found in the code itself:** (1) the first smoke test hung because the listener was blocking (`accept` blocked the
loop); the process sat in `inet_csk_accept`. (2) The 413 for an oversized chunked upload reached the client followed by a **reset**,
which the lingering close now prevents. (3) `route.select` once divided by a method's bit before testing it (task #4).

## 6. Not tested, not built

- **Upstream host names.** `tcp_connect_start` given a name resolves it inside the builtin with `getaddrinfo`, which **blocks the
  loop** (`cancho/examples/tls_nb/resolve_demo.cho`). Every test uses IP literals. The generator still accepts names.
- HTTP/1.0 clients through the proxy, `Expect: 100-continue`, `HEAD` responses, and an upstream that sends `1xx` responses.
- The response is relayed **unverified**. Because the upstream is told `Connection: close`, a lying `Content-Length` cannot
  desynchronise a later request; the client sees what the upstream sent.
- The header policy is `docs/headers.md` (`Via`, `X-Forwarded-Host/Proto`, `X-Request-Id`, untrusted forwarding claims removed). **No `X-Forwarded-For`
  of its own: the gateway cannot know the client's address.** The request id is in every response and error, and one access-log line per request goes to stdout (`docs/observability.md`). No metrics endpoint yet (#10, second slice).
- No keep-alive: every request costs a TCP connection on each side. #14 will say what that costs against nginx and HAProxy; this
  slice has **not** been benchmarked.
- A single upstream address per route; no health checks or retries (#6).
