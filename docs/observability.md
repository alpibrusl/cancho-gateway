# The access log and metrics (task #10)

Status: **10a built (section 9); 10b (sections 6 and 7) not yet.** The design was written before the code and the gates in section 8 were fixed then. It is built in two slices, each its
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
| `bytes_in`, `bytes_out` | request-body bytes forwarded to the upstream, response bytes (head and body) queued for the client |

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

Kept in a fixed block sized at start, updated by `session_end` (an addition per request, no allocation):

| metric | labels | kind |
|---|---|---|
| `requests_total` | `route`, `class` (`1xx`..`5xx`, `none` for status 0) | counter |
| `refusals_total` | `rule` (every tag in the tag tables, ~60) | counter |
| `request_duration_ms` | `route` | histogram, buckets 1, 2, 5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000, 10000, +Inf, with `_sum` and `_count` |
| `upstream_wait_ms` | `upstream` | the same buckets |
| `bytes_in_total`, `bytes_out_total` | `route` | counters |
| `upstream_requests_total`, `upstream_retries_total`, `upstream_failures_total` | `upstream` | counters |
| `sessions_active`, `pool_idle`, `circuit_open` | (`upstream` for the last two) | gauges |
| `log_dropped_total`, `log_write_failures_total` | | counters |

Bounded by construction: at most 256 routes x 5 classes, ~60 rules, 256 upstreams, 15 buckets; a client cannot create a label (a label is a route, an upstream, a rule or a class, all compiled in).

## 7. The admin listener (10b)

`admin_listen = <port>` in the deployment (default **off**; refused if equal to `listen`; a different port, not a path on the proxy's: the proxy's port is the public one). It serves, read only, with no
request body accepted and a 2 KiB head limit, at most 8 connections at a time, each closed after one response (a 2 s deadline):

| path | answer |
|---|---|
| `GET /metrics` | the section 6 metrics as JSON (byte-stable key order); `?format=prometheus` for the Prometheus text exposition |
| `GET /healthz` | `200 {"alive":true}` if the loop is turning (it is answering) |
| `GET /readyz` | `200` if at least one upstream's circuit is closed and the log is not failing, else `503 {"ready":false,"why":["upstream api: circuit open", ...]}`: the *why* is data |

**The exposure, stated first because the compiler forces it:** the admin port binds every interface (section 1). What it reveals is topology and volume (route and upstream names, counters), no
request data and no secret. That is still not for the internet. The deployment's production profile (the operator bundle, a later task) must firewall it or run the gateway where the admin
port is not routed; a loopback-only bind is the clean fix and is a request to cancho (`tcp_listen` flag, bit 2). Until then the README says the admin port is "as public as its firewall lets it be".

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
8. (10b) **Counters equal an independent count** over a scripted run (the log's own lines, parsed, summed by route, class and rule, against `/metrics`); the histogram's `_count` equals the sum of its buckets;
   the admin port refuses a body, a long head, a ninth connection; `/readyz` says why for each cause.

## 9. What 10a built, and what checked it

- **`src/accesslog.cho`** (the pure line builder) and `out.put_json` (the escaper): 10 unit tests, including every byte value 0..255 coming out as printable ASCII that is valid JSON, the
  path cuts at 128 input and 256 output bytes, and the worst line. **Measured:** the worst line (every field at its cap, 16-digit counters, a path of 128 control bytes) is **676 bytes**;
  the bound is 768 (section 2 first said 640 before it was measured; corrected).
- **The proxy**: 32 state ints and a 256-byte meta area per slot; `session_begin` at accept (the connection's own id), the route and its upstream recorded as soon as they are known (so a 413
  names them), `log_end` building the line when the client's session ends, `run` writing the queue once per turn and exiting with status 6 when the write fails (`log_failure`, default `exit`).
  The request id in the response (`X-Request-Id`, an upstream's own removed) and in every refusal (header and `"request_id"` member).
- **End to end** (`tests/proxy_test.py`, now 75 tests with the gateway's stdout captured): one line per request and every field, `bytes_out` equal to the bytes the client received, `bytes_in`, the four
  refusal kinds with their rules and the id in the body, a timeout, a client that leaves with a half head and one that leaves mid-response, a trusted route's kept id logged and echoed, the upstream's
  own id not passed on, the upstream's own status, `upstream_ms` as the wait for the first byte (a 0.3 s upstream), hostile paths (quotes, backslashes, controls, DEL, high bytes, 16 KiB, a 65-byte id)
  all parsing within the bound, forty concurrent requests giving forty lines, `/dev/full` as stdout stopping the gateway with status 6, and `log_failure = "continue"` keeping it serving.
- **A full pipe, measured (gate 5):** stdout a pipe nobody reads: **320 to 336 requests** were answered before the loop blocked in its write (the 64 KiB pipe plus the 4 KiB stdio buffer, about 200 bytes
  a line); the next request waited. When the reader started, every line arrived, in order, none twice, none dropped (the loop had waited, not dropped), and the gateway served again.
- **The full queue (a build whose queue is 1,600 bytes, because the real one is 256 KiB and a turn would need over a thousand lines to fill it, which a 128-event turn cannot produce):** a hundred clients
  leaving together dropped lines, the count was announced in the log, and `lines + announced == requests` exactly. At the real size the drop path is **defensive and unreachable in practice**; the
  test is what keeps it honest.
- **Mutants:** 32 of the new code (each field, the escaping, each cap, the truncation marker, the flags, every byte count, the first-byte time, the status, the method and path, the route known early, the
  kept id, the queue reset, the announcement reset, the wall offset, the exit status, the inverted `log_failure`, the sequence): **31 killed**. One survives as **equivalent**: the guard that writes a
  client's line once (`flag 4`): every path that could write it twice frees the slot first, so no reachable input shows the difference; it stays as an invariant, not as tested behaviour. Two survived
  the first tests and were killed by new ones (the status always 200: a test with an upstream 404; the first-byte time: a 0.3 s upstream). A dead branch (writing the *peer's* line in `drop_session`,
  reachable only when the client was already gone) was removed instead of tested.
- **Cost, measured:** `cancho` against the build before this change (`4bac430`), 5 interleaved rounds, one core, stdout to a file: **C1 0.95 (0.86 to 0.97), C4 0.97 (0.93 to 1.03)**. The log costs about
  3 to 5% of throughput on these cells.
- **The authority report is unchanged** in its capability row (`args, clock, conn_accept, conn_read, conn_write, heap, io_write, net_in(""), net_out(""), poll`): only the pure-function list and counts moved.
- **Corrections to the design found while building:** a closed stdout raises `SIGPIPE` before `flush_out` can answer (`docs/checked-output.md`), so for a closed pipe the process dies rather than exits
  with 6 (not tested here; `/dev/full` is the tested failure); the readiness probe a test starts with is itself a connection and gets a line (`"aborted"`, no method), which is accurate: the gateway
  logs every connection it accepts, including one that never sends a byte.

**Not done in 10a:** counters, the histogram, the admin listener (10b); the client address (no peer address in the compiler).
