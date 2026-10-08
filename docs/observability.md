# The access log and metrics (task #10)

Status: **10a built (section 9); 10b (sections 6, 7 and gates 8 to 12) designed, being built.** The design was written before the code and the gates in section 8 were fixed then. It is built in two slices, each its
own PR: **10a** (sections 2 to 5: the access log, and the request id completed) and **10b** (sections 6 and 7: counters, the histogram, the admin
listener). Claims below are about the pinned compiler (`cancho.toml`); where a later commit finds one false, it is corrected here, in place.

## 1. What the probes found (before any design)

| assumed by the issue | found | consequence |
|---|---|---|
| a bounded line per request to stdout, "no file effects" | **stdout is written through libc's buffer** (`write_bytes`, then `flush_out`, which answers whether everything arrived: `docs/bulk-io.md`, `docs/checked-output.md`); a `write` to a pipe nobody reads **blocks the whole loop** | the log is queued in memory by the session code (no effect needed there) and written once per loop turn by `run`, which holds the `Io`. The authority row does not change (`io_write` is already in the ceiling). A consumer that stops reading stalls the proxy: a documented property of a log that is never silently dropped on the way to stdout (section 3) |
| a client address in the line | **none**: an accepted connection carries no peer address (`conn_peer` is not built; `docs/headers.md` section 1) | the line has no `client` field. It says so rather than writing a wrong one |
| a timestamp | `clock_ms` is **monotonic from an arbitrary origin** (right for timeouts, wrong for a log); `clock_unix_ms` is the wall clock and can jump | `t` is the wall clock at start plus the monotonic time since, so it never jumps backwards inside a run, and is stamped once per run (`t0_unix_ms - t0_mono_ms`) |
| an admin listener "on a separate bounded listener" | **`tcp_listen` binds every address the host has**; its flags argument is `SO_REUSEPORT` only (`docs/native-sockets.md`, `docs/listen.md` section 6: "who may reach a bound port is the perimeter's decision") | the admin port is reachable from wherever the proxy port is, unless the operator's firewall says otherwise. Section 7 says what that means and what the deployment must do; a loopback-only flag is a request to cancho, with the same askers as `conn_peer` |
| a request id in the response and in the error body | the head the id came from is gone when the response is rewritten | one 64-byte id string per session, kept for the whole session (section 4); this completes what `docs/headers.md` section 2 deferred |

## 2. The line

One JSON object per request, one line, written when the request ends, in this key order:

```json
{"t":1791363042117,"id":"19b3c2a1f00-1f90-0000002a","method":"GET","path":"/users/7","route":"api","upstream":"api","status":200,"rule":"","outcome":"ok","ms":12,"upstream_ms":9,"bytes_in":0,"bytes_out":1834}
```

| key | meaning |
|---|---|
| `t` | start of the request (accept), milliseconds since 1970 (section 1) |
| `id` | the request id: the one the upstream was sent and the client was given (section 4) |
| `method` | the request method, if the head got far enough to have one; else `""` |
| `path` | the request target **up to `?`**, at most 128 bytes, escaped (below). **No query string, no headers, no body, ever**: a secret in a query is not the log's to keep |
| `route` | the route's `name` (generator: required to match `[a-z][a-z0-9_-]{0,31}`; default `route<N>`); `""` if no route was selected |
| `upstream` | the upstream's name; `""` if none was chosen |
| `status` | what the client was sent: the response's status, or the refusal's. `0` if the client left before any status was written |
| `rule` | the rule tag of a refusal the gateway made (`framing.*`, `route.*`, `limit.*`, `proxy.*`, `timeout.*`, `response.*`); `""` otherwise |
| `outcome` | `ok` (the response was relayed whole), `refused` (the gateway answered, `rule` says why), `aborted` (the client or the upstream went away, or the total deadline cut a response that had begun) |
| `ms` | accept to the end of the request |
| `upstream_ms` | from the request being routed to the first byte of the upstream's response; `0` if there was none |
| `bytes_in`, `bytes_out` | request-body bytes forwarded to the upstream, response bytes (head and body) queued for the client; over TLS these are plaintext bytes |
| `tls` | `true`, **only** on a connection that spoke TLS on `tls_listen` (`docs/tls.md`); absent otherwise, so a deployment without `tls_listen` writes the lines it always wrote. It comes after `bytes_out` |
| `upgrade` | `"websocket"`, **only** on a request that became a WebSocket tunnel (`docs/websocket.md` section 11), and then the last key, after `tls`. The line is written when the tunnel **ends**; `status` is 101, `bytes_in` and `bytes_out` count the tunnel's bytes, `rule` is empty or `ws.idle-timeout` / `ws.lifetime`, `outcome` is `ok` if a peer closed it and `aborted` otherwise |

**Escaping, so that a hostile request cannot make a line unparseable or longer than its bound:** in every string, `"` and `\` are backslash-escaped, every
byte below 0x20 and 0x7f and every byte from 0x80 up is written as `\u00XX` (the byte read as Latin-1: always valid JSON, never invalid UTF-8). The path is cut at 128 input bytes **and** its escaped form at 256 output bytes (never in the middle of an escape), after which `"path_truncated":true` follows. A line is at most
**768 bytes** by construction: the fixed keys and numbers, an id of at most 64 bytes, a method cut at 16, route and upstream names of at most 32 and a rule tag of at most 40, and the path's 256; the test
sends the worst bytes and measures.

## 3. The queue, and what happens when stdout is slow

The session code never writes. When a request ends it appends its line to a **bounded queue in memory** (256 KiB, sized at start like everything else); the loop drains it
to stdout once per turn (`write_bytes`, then one `flush_out`), so a burst of requests is one write, not one per line.

- **Full queue** (the loop has not drained it: stdout blocked, or a very large burst): the line is **dropped and counted** (`log_dropped`). The next line that fits is
  preceded by `{"t":…,"log_dropped":N}`, so the gap is visible in the log itself and in the counters (10b). The proxy never waits for the log *inside* the session code.
- **A blocked stdout stalls the loop** at the drain: every proxied request waits. This is libc's blocking `write`, which the pinned compiler cannot make non-blocking. It is the
  right trade for an audit trail that must not be lost on the way out, and the wrong one for a consumer that can hang. The runbook says so: log to a file, `journald`, or a
  reader that does not stop; a measured test (section 8, gate 5) pins what a full pipe does.
- `flush_out` answers whether everything arrived; a failure (a closed pipe, a full disk) is counted (`log_write_failures`) and, as the gateway can no longer log, **ends the
  process with status 6** after the in-flight sessions are given up (a gateway that serves traffic it cannot account for is the thing an auditable gateway must not be). Whether to
  continue instead is a flag in the deployment (`log_failure = "exit" | "continue"`, default `exit`).

## 4. The request id, completed

Every accepted connection gets an id at accept (the generated form of `docs/headers.md` section 3); if its route trusts forwarding headers and the client sent one valid id, that
becomes the id at routing time. The id's bytes live in a per-slot area (64 bytes) for the whole session, so that:

- the **access log** has it, whatever happened;
- the **response** carries it: `X-Request-Id: <id>` is written into every response head the gateway relays (a header of that name from the upstream is removed first, so the client
  never sees two), and into every refusal;
- a **`problem+json`** body has `"request_id":"<id>"` (the member `docs/design.md` section 8 promised), so a client or an agent can quote it;
- a **retry** carries the same one (unchanged from `docs/headers.md`).

## 5. What 10a changes in the code

- `generator`: route `name` validated and compiled into the table (a seventh column).
- `proxy`: the slot's state grows from 24 to 32 ints and each slot gets a 128-byte area (the id, the rule tag); each client session records its start, routed and first-byte times, byte counts and
  final status; `session_end` builds the line into the queue; `run` takes the `Io` and drains the queue each turn.
- `forward`/`problem`: the id in the response and the error body.
- **No new effect:** `io_write` is in the ceiling already, and the authority report's capability rows must come out identical (gate 7).

## 6. Counters and the histogram (10b)

Kept in one block of integers sized at start from the compiled-in counts (`routes x 32 + upstreams x 24 + 96 rules x 2` ints, about 1 KiB for a small deployment), updated by `log_end` (the one place a request ends: an addition per request, no allocation):

| metric | labels | kind |
|---|---|---|
| `requests_total` | `route`, `class` (`none` for status 0, then `1xx`..`5xx`) | counter |
| `refusals_total` | `rule` | counter |
| `request_duration_ms` | `route` | histogram: buckets 1, 2, 5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000, 10000, +Inf (**14**, not the 15 first written here), `_sum`, `_count` |
| `upstream_wait_ms` | `upstream` | the same buckets: the wait for the response head, as the log's `upstream_ms` |
| `bytes_in_total`, `bytes_out_total` | `route` | counters, as the log's `bytes_in`, `bytes_out` |
| `upstream_responses_total`, `upstream_retries_total`, `upstream_failures_total` | `upstream` | counters: requests whose response head arrived; requests sent again on a fresh connection; failures as the circuit counts them (counted even when the circuit is off) |
| `sessions_active`, `pool_idle`, `circuit_open` | (`upstream` for the last two) | gauges, read when scraped |
| `log_dropped_total`, `log_write_failures_total` | | counters |
| `tls_handshakes_total`, `tls_handshake_failures_total` | | counters (`docs/tls.md` section 10): handshakes that finished; TLS connections ended before theirs did. A failure is also counted in `refusals_total` under the engine's `tls-*` tag (or `tls.handshake-timeout`). The JSON has them as `"tls":{"handshakes":N,"failures":N}`, between `refusals` and `log` |
| `ws_tunnels_total`, `ws_tunnels_active` | | WebSocket upgrades relayed as tunnels (counter) and tunnels open now (gauge; `docs/websocket.md` section 11). The JSON has them as `"ws":{"tunnels_total":N,"tunnels_active":N}`, between `tls` and `log` |

**Labels are bounded by construction.** A route, an upstream and a class are compiled in. A rule is one of the tags the code can emit, but the tags live in several modules and there is no single table, so the rule counters sit in a small table filled as tags are first seen (at most 96 entries of 40 bytes; a tag past the 96th is counted under `other`, which cannot happen while the code has about 60). A client cannot make a label: it can only reach a tag the code already has. The table is searched linearly (96 comparisons) on a refusal, which is not the hot path.

**A request with no route** (refused before routing: framing, route selection) counts under no route's `requests_total` (it has none) and under its `rule` in `refusals_total`; `requests_total` per route therefore sums to the requests that were routed, and the gate says so.

## 7. The admin listener (10b)

`admin_listen = <port>` in the deployment (default **0: off**; refused if equal to `listen`). A different port, not a path on the proxy's: the proxy's port is the public one. Read only: a `GET` with no body, a 2 KiB head, at most **8** connections at a time (a ninth is closed at once), each closed after one response, a 2 s deadline for the whole exchange.

| path | answer |
|---|---|
| `GET /metrics` | the section 6 metrics as JSON, keys in a fixed order; `?format=prometheus` for the Prometheus text exposition (`# HELP`, `# TYPE`, cumulative `le` buckets) |
| `GET /healthz` | `200 {"alive":true}`: the loop is turning, since it is answering |
| `GET /readyz` | `200 {"ready":true}`, or `503 {"ready":false,"why":["upstream api: circuit open","log: a write failed in the last 10 s"]}`: the reasons are data. Ready means no circuit is open and the log is not failing |

Anything else is a problem+json refusal with its own rule, and the refusal's `request_id` is `admin`: `admin.method` (405: not `GET`), `admin.path` (404), `admin.body` (400: a `Content-Length` or `Transfer-Encoding` header), `admin.head` (431: no complete head in 2 KiB), `admin.version` (505: `HTTP/` but not 1.0 or 1.1), `admin.request` (400: a request line that is not `METHOD target HTTP/x.y`, or a `/metrics` query other than none, `format=json` or `format=prometheus`), `admin.busy` (503: the response buffer stayed taken for the whole deadline), `admin.size` (500: the answer did not fit the buffer, which the unit test says cannot happen). An admin connection has no access-log line (it is not a proxied request) and counts in none of the metrics.

**How it runs, in the same loop.** The admin listener is a second listener on the same poller; its connections take slots of the same table (kind 4), so the table's bound covers them. The metrics response is built into one buffer, sized at start to the worst case the formatter can produce for this deployment (`metrics.worst_case()`, computed from the compiled-in names, and about 25 KiB for a small one; allocated only if the admin port is on), and **only one connection owns that buffer at a time**: a connection with a complete head waits, unwatched, until the buffer is free. Serving one at a time is invisible at this size (a scrape is a few milliseconds) and keeps the memory bound independent of the connection count.

**The exposure, stated first because the compiler forces it:** the admin port binds every interface (section 1). What it reveals is topology and volume (route and upstream names, counters), no request data and no secret. That is still not for the internet. The deployment's production profile (the operator bundle, a later task) must firewall it or run the gateway where the admin port is not routed; a loopback-only bind is the clean fix and is a request to cancho (`tcp_listen` flag, bit 2). Until then the README says the admin port is "as public as its firewall lets it be".

## 8. Gates, fixed before the code

1. **The line, byte for byte** (unit tests on the pure builder): every key for an ok request, a refusal, an abort; the escaping of every byte value 0..255 in the path; the 128-byte path cut;
   the 768-byte bound with the worst input; no query string.
2. **End to end** (`tests/proxy_test.py`, the gateway's stdout captured): one line per request and no more; every line is valid JSON; `id` equals the `X-Request-Id` the upstream saw and the
   one in the response; `route`, `upstream`, `status`, `rule`, `outcome` right for a 200, a 404 (no route), a 405, a 413, a 502 (dead upstream), a 504 (silent upstream), a client that leaves
   mid-request; `bytes_out` equals the bytes the client received; a trusted route's kept id is the one logged.
3. **Hostile requests**: the crafted corpus of `docs/headers.md` gate 3, plus a 128-byte path of `"`, `\`, controls, DEL and high bytes, a 16 KiB path, an `X-Request-Id` of 65 bytes: every line
   parses, stays within 768 bytes, and contains no byte below 0x20 other than the final newline.
4. **A request id in every refusal body** and the response header on a relayed response; an upstream's own `X-Request-Id` is not passed on.
5. **A full pipe**: stdout is a pipe that is not read; the measured behaviour (the loop stalls at the drain once the queue and the pipe are full; no line is written out of order; after the reader
   resumes, every line that was queued arrives and the dropped ones are announced by `log_dropped`) is written here.
6. **Mutants** of the new code, all killed or explained (each field, the escaping, the cut, the queue's full case and its announcement, the id echo, the strip of the upstream's id).
7. **No new effect:** `scripts/authority.py --check` passes with the capability rows unchanged; the 2,000-line gate; the cost measured against the previous build in the same rounds (the log's price per
   request is a number in this document, not a claim).
8. (10b) **Counters equal an independent count:** the log's own lines over a scripted run (every status class, a refusal of each kind, a retry, an upstream failure), parsed and summed by route, class and rule, against `/metrics`; the histogram's `_count` equals its bucket total, and the cumulative Prometheus buckets are non-decreasing and end at `_count`; the Prometheus text parses (every sample line is `name{labels} value`, every family has a `# TYPE`).
9. (10b) **The admin port is what section 7 says:** off by default (nothing listens); refuses `POST`, a body, a 2 KiB head, an unknown path, an HTTP/1.0-or-other version it cannot serve, and a ninth connection; `/readyz` says why for each cause (an open circuit, a failing log) and is `200` when neither; a slow reader of the metrics does not stall the proxy port, and two scrapes at once are both answered; the generator refuses `admin_listen` equal to `listen` or out of range.
10. (10b) **The formatter cannot overrun its buffer:** a unit test fills every counter with the largest values the formatter accepts and checks that the output of both formats fits `metrics.worst_case()`, byte for byte on small known cases.
11. (10b) **Mutants** of the new code, all killed or explained (class boundaries, each bucket bound, the sum, the retry and failure counts, the rule table's lookup and its overflow, the readiness causes, the 8-connection cap, the one-owner buffer, each refusal's status).
12. (10b) **No new capability and a measured cost:** `scripts/authority.py --check` unchanged (the second listener is `net_in("")` and `conn_accept`, both already in the row); the 2,000-line gate; the counters' price per request against the build before, in the same rounds.

## 10. What 10b built, and what checked it

**Built.** `src/metrics.cho` (the counters, the histograms, the JSON and Prometheus text, the readiness body, the response framing and the size bound), `src/admin.cho` (what an admin request asks for), and in `src/proxy.cho` the admin
sessions (kind 4 of the slot table), the second listener (matched in place as a `Listening`, so a gateway without one runs the same loop), the record in `log_end`, the failure count in `health_fail` and the release of the metrics buffer in `drop_session`.
The deployment key is `admin_listen` (0, off, by default; the generator refuses a value equal to `listen`). Nothing else in the gateway changed; the proxy path is the same code.

**Where building corrected the design above** (each is corrected in sections 6 and 7 where it was wrong):
- The histogram has **14** buckets, not 15; `upstream_requests_total` became `upstream_responses_total` (it counts requests whose response head arrived; "requests" would have counted ones that never reached an upstream).
- Rule counters live in a small table filled as tags are first seen, since the tags are spread over several modules and there is no single list to index (section 6).
- Two more refusal tags, `admin.request` and `admin.size`; and an admin refusal's `request_id` is the literal `admin`.
- **The size bound.** The first `worst_case()` was a generous constant per route and upstream, about 50% above the largest answer; a mutant that halved a term survived it. The bound is now the exact line count and length per family
  (the comment in `metrics.worst_case` gives the arithmetic) and the unit tests require both `answer <= bound` and `bound <= answer + answer / 10`, on two deployments: the example (names of 3 to 10 bytes) and one whose names are 32 bytes
  (`tests/fixtures/long`, generated and checked in), because a name is counted in 24 lines of a route and 21 of an upstream and the short names hide a wrong multiplier.
- **Readiness.** An upstream whose circuit period has run out is **not** reported open: a trial is then allowed, and a gateway that reported itself not ready would be sent no traffic to take the trial with (a load balancer would never put it back).
- A unit test of the largest answer allocated more than a region holds (about 64 KiB) and trapped; it is the test's allocation, not the gateway's (the gateway's buffer is a heap box), and each buffer now has its own region.

**What checked it.**
- **Unit tests:** `tests/metrics_test.cho` (11: every bucket edge, the class boundaries, counting by route, class and bucket, a request with no route, the rule table filling and then counting `other`, a long tag, upstream failures, the JSON byte for byte at its start and its parts, the Prometheus text with cumulative buckets, the readiness causes, the framing, saturation), `tests/admin_test.cho` (7: the four things it serves, each refusal, headers in any case, versions and malformed lines, where a head ends), and `tests/metrics_bound_test.cho` (2, run on both deployments).
- **End to end:** `tests/admin_test.py`, 16 tests against the built gateway, now a CI step. The one that matters most: **the counters equal an independent count** made from the gateway's own access-log lines over a varied run (every status class, every refusal kind, a dead upstream, a body over the limit): per route and class, bytes in and out, the duration histogram's buckets, sum and count, and the refusals by rule all agree exactly. Others: one request moves exactly the counters it should; a retried request is counted as a retry; a dead upstream's failures are counted; the Prometheus text parses and its histograms are cumulative and end at `_count`; every refusal of section 7 (a `POST`, a body header, a 3 KB head, an unknown path, a version, a malformed line, a head that never ends and is dropped at 2 s); a ninth connection is closed and a freed slot is reused; six scrapes at once are all answered; an unread scrape does not stall the proxy; `/readyz` says why for an open circuit and for a failing log, and is `200` again after the circuit closes; a 125-route deployment's 230 KB answer fits its buffer and arrives whole; the admin port is open only when asked (the listening sockets of the process are read from `/proc`).
- **Mutants:** 42 single edits of the new code (bucket bounds and edges, the class range, the sum, the byte counts, the retry and failure counts, the rule table's lookup and cap, the `other` slot, the readiness causes, the framing, saturation, the size bound's terms, each admin refusal, the 8-connection cap, the buffer's release, the deadline, the watch). **40 killed, 2 survive, both argued:**
  (1) *the metrics buffer given to two connections at once.* The protection matters only when an answer is written in more than one piece, which needs an answer larger than the kernel will take in one write; a 230 KB answer through a client with a 1 KiB receive buffer was taken whole by the loopback socket, so it cannot be provoked here (the largest answer a deployment can give is about 0.5 MB). The rule stays, untested, and this paragraph is where that is said.
  (2) *the phase-0 branch of `admin_settle` wants nothing instead of input.* Nothing calls `admin_settle` in phase 0 (the connection is watched for input when it is accepted); the branch is correct and unreachable.
  A first round of the size-bound mutants left one standing (a name multiplier); the long-names deployment was added for it.
- **No new capability:** `scripts/authority.py --check` against the regenerated manifest; the capability row is unchanged (the second listener is `net_in("")` and `conn_accept`, already there); only the pure-function lists and counts moved. The 2,000-line gate holds (`proxy.cho` is 1,865 lines now; the admin tests moved out of `proxy_test.py` into their own file, which was at 1,969).
- **Cost of the counters** (the admin port off, so this is the record in `log_end` and the failure count, not the listener), against the build just before it, five interleaved rounds on one core, paired per round (`bench/results/2026-10-07-metrics.json`): **C1 1.02 (0.96 to 1.18), C4 0.97 (0.93 to 1.08)**. The median on C4 is 3.5% below 1 and the range includes 1: no cost the noise does not hide, and no gain either. The earlier build's own rounds differ from each other by up to 10%.

**Not done.** A loopback-only bind (the compiler offers none: the admin port is on every interface, and has no authentication); alerting; per-upstream or per-rule histograms; the metrics in the agent-facing `introspect` (#18); a metric for the circuit's state changes beyond the gauge.
