# TLS in the gateway (task #16, the decision made)

Status: **slice 1 built (2026-10-08): the listener, the handshake bounds, the data path, the report, the tests; `docs/tls.md` section 10 says what was built, what was measured and where it differs from the
design above it. Slice 2 built (2026-10-08): certificate reload on `SIGHUP`, a clean stop on `SIGINT` and `SIGTERM`, and an optional `listen` (a TLS-only deployment): section 11. Not built: the cost cell in the benchmark harness (gate 9).** Sections 1 to 9 were written before the code, and where the code found one false it is corrected
in place and marked *(corrected)*. It replaces the
"TLS is out of v1" record in `docs/design.md` section 7, whose stated reason (TLS needs foreign code and would make the authority report unbounded) stopped
being true when cancho shipped a TLS 1.3 server written in cancho (`packages/tls`, cancho #338 and #339; `examples/tls_echo`, #346; the byte-fed HTTP
server and `examples/https_hello`, #360). Claims below are about cancho at the commit named in section 1; where a later commit finds one false, it is
corrected here, in place.

## 1. What exists, and what it is not

| piece | what it gives | where it is stated | caveat |
|---|---|---|---|
| `packages/tls` server | TLS 1.3 only; suites AES-128-GCM, ChaCha20-Poly1305, AES-256-GCM; groups X25519, P-256, P-384; **one certificate type, ECDSA P-256**; up to 16 identities chosen by SNI; ALPN list; HelloRetryRequest; `replace_identity` while running | cancho `docs/tls-server.md` sections 2 and 10 | not independently reviewed (cancho says so, #209); no client certificates, no resumption, no TLS 1.2, no 0-RTT |
| the engine's interface | slots, bytes in and bytes out: `serve`, `feed`, `recv`, `send`, `take`, `event`, `finish`, `drop`, `server_name`, `alpn`, `suite`, `group` | `tls-server.md` section 5.1 | the engine never reads a file and holds no capability |
| `examples/tls_echo`, `examples/https_hello` | a complete non-blocking terminator on one `Poller`: handshake bounds, a rate limit, `SIGHUP` reload, `close_notify` on stop | `tls-server.md` section 11, `http-server.md` section 11.6 | `https_hello` uses cancho's `http.server`, which the gateway does not (the gateway has its own framing and proxy state machine); what carries over is the *terminator* half |
| `narrow(fs, "a", "b")` (cancho #364, **merged**) | one `Fs` narrowed into several literal paths, so a program that reads `/dev/urandom` and one certificate directory reports exactly those two paths instead of `fs_read("")` | #364's description; `examples/tls_echo_fixed` | *(corrected)* the gateway's pin moved to `2fcf4cd`, the commit that has it (`cancho.toml`) |
| measured cost | TLS 1.3 serves 3.6 times (aarch64) to 4.2 times (x86-64) fewer requests a second from one core than the same server plain (23.4 against 5.6 microseconds of CPU a request on CI's x86-64 runner, 99-byte answers); a full handshake is 3.0 ms (Apple M4) to 5.5 ms (CI x86-64) of CPU | `http-server.md` section 11.7, `tls-server.md` section 11.4 | cancho's server, cancho's request path; the gateway's own cost is a number this task must produce (gate 9) |

## 2. What the gateway wants, and what it will not do

**Wanted:** HTTPS on the client side, so that the gateway can be the public edge for a few internal services instead of sitting behind Caddy; the same strict parsing,
the same refusals, the same request id and log line over TLS as over plain TCP; and an authority report that says exactly what the extra capability is.

**Not in this task, and why:**

| not done | why |
|---|---|
| TLS to the upstreams | the upstream set is fixed, internal and (today) plain; client-side TLS in cancho (`packages/tls` client) would be a second, separate decision, and it would add a trust store (a file read) |
| client certificates (mTLS) | the engine does not have them (`tls-server.md` section 2.2) |
| HTTP/2 | the gateway speaks HTTP/1.1; ALPN offers `http/1.1` only and refuses a client that offers nothing else (`no_application_protocol`) |
| TLS 1.2 | the engine has no TLS 1.2 server |
| session tickets, OCSP stapling | the engine has neither |
| choosing the route by SNI | routes select on the `Host` header, as today. A client whose SNI and `Host` differ is routed by `Host`; the log records both (section 6) |
| an ACME client | the operator's job: a deploy hook copies the files in and sends `SIGHUP` (cancho's own convention, `tls-server.md` section 11.2) |

## 3. The decisions

1. **One more listener, not a mode of the first.** `tls_listen = <port>` in the deployment (default 0: none). The plain `listen` port stays as it is (it may be
   behind another terminator, as the examples show); a deployment may have both, and every route serves both. `tls_listen` must differ from `listen` and from
   `admin_listen`. Where the gateway should *refuse* plain HTTP on a route (`require_tls`) is not in this task: a front that wants it listens on `tls_listen` only,
   which needs `listen` to be optional (see question 3).
2. **The upstream side does not change.** Only a client connection has TLS state; an upstream connection is the plain one it is today.
3. **Where the TLS state sits.** The engine's slot `k` is the table's slot `k` (cancho's own examples do exactly this): no second numbering. A client slot on the TLS
   port gets, besides its `bufs[k]` (plaintext request, as today) and `pends[k]` (plaintext response, as today), two ciphertext buffers `cin[k]` (bytes read from the
   socket, not yet fed) and `cout[k]` (bytes the engine has produced, not yet written). Their sizes are the engine's own bounds (a TLS record is at most 16,384 bytes of
   plaintext plus 5 bytes of header and up to 255 of expansion); the numbers are fixed in the code and listed in section 7. Allocated only if `tls_listen` is set.
4. **The data path** (only the two socket calls of a client slot change):
   - **read:** socket -> `cin[k]` -> `tls.feed` -> `tls.recv` into `bufs[k]` at the current offset, asking for no more than `bufs[k]` has room for, so a full request buffer stops
     `recv`, which stops `feed`, which stops the socket read: the same back-pressure rule as plain, and the same bound.
   - **write:** `pends[k]` -> `tls.send` -> `tls.take` into `cout[k]` -> socket; `pends[k]` is released only as `send` takes it.
   - the framing, routing, header policy, pool, circuit and log code see plaintext only and are not changed.
5. **A new client phase, "handshaking",** before phase 0 (reading the head): the slot is watched for reading; bytes go to `feed`; when `tls.event` says established the phase becomes 0 and the
   header timeout starts then (a client that is slow in the handshake is not slow in the head). Bounds, from `tls_echo` and fixed here: at most `tls_handshakes` (default 32) in progress, at
   most `tls_rate` (default 50 *(corrected from 100)*) started a second, `tls_handshake_ms` (default 10,000) to finish. A connection over the bound is delayed (left unwatched, so its ClientHello waits in the
   kernel and costs nothing), not refused: the common case of "too many handshakes" is a burst of honest clients; the attacker's case is bounded by the same two numbers.
6. **The end of a session.** When a client session ends in the gateway (a response relayed, a refusal sent), the engine's `finish` is called so that `close_notify` is queued, and the slot
   closes once it is written or after the flush deadline. A peer that closes without `close_notify` mid-request is an aborted request exactly as a plain reset is (the request is
   Content-Length or chunk framed, so a truncation cannot make an incomplete request look complete; this is a gate, section 8).
7. **Certificates.** `tls_dir = "<absolute path>"` is a **literal compiled into the binary** (the generator emits it, as it does the upstream addresses), and `tls_identities = ["a", "b"]` names up to 16
   subdirectories of it, each with `chain.pem`, `key.pem` and `names`, the first the default (`tls_echo`'s layout, so cancho's deploy-hook examples apply unchanged). The binary reads them at start with
   `narrow(fs, "/dev/urandom", tls_dir)`, opens the directory once, and every later read goes through that handle (`examples/tls_echo_fixed` does exactly this). The authority report therefore gains
   `dir_read`, `file_read`, `fs_read("/dev/urandom")` and `fs_read("<tls_dir>")` and **no `fs_read("")`**. Symbolic links in that directory are refused (certbot's `live/` is links: the deploy hook copies the
   files in). **This depends on cancho #364.** If the compiler the gateway is pinned to does not have it, the first slice waits for it rather than ship an `fs_read("")` (section 9, question 1).
8. **Reload** (`SIGHUP`, `tls.replace_identity`; connections already started keep the certificate they were sent) is a second slice, **built: section 11**. *(Until then a renewed certificate meant a restart.)*
   It adds `signals("HUP,INT,TERM")` to the report, which is why it was a separate, reviewed step.
9. **The scheme is a fact of the connection.** `X-Forwarded-Proto` on an untrusted route is `https` for a TLS-port client and `http` for a plain one (`docs/headers.md` section 2 said `http` because there was no TLS);
   a trusted route passes the front's value through, unchanged. The access log gains `"tls":true` *(corrected: only on a TLS connection, and last, so that a deployment without `tls_listen` writes the lines it always wrote and the key list the tests pin is unchanged)* (the version, suite and SNI are in the engine; they go in the log only if a gate asks, because the
   line has a byte bound, `docs/observability.md` section 2). Metrics gain two counters, handshakes finished and TLS connections ended before theirs did *(corrected: not `tls_handshakes_total{result}`, a label the cardinality rule would have to bound)*, and the refusal tags of the engine appear in `refusals_total`
   (they are `tls-server-*` tags, all of them from a set the engine owns, so the rule table's bound holds; the gateway adds `tls.handshake-timeout`).
10. **Edition.** `narrow`, `dir_read` and the signal capability need edition 6 or 7 (`tls_echo` is edition 6). The gateway's modules are edition 5; the ones that touch the new capabilities move, the rest stay (an edition
    is per file, `docs/editions.md`). Each moved file is a reviewed diff, and the existing tests are the check that nothing else changed.

## 4. What it does to the budgets

| | today | with `tls_listen` |
|---|---|---|
| sessions (table slots) | 256 slots, about 127 sessions (two slots each) | the same; engine slots equal table slots (256) |
| memory | 4 MiB of buffers, `bufs` 16 KiB and `pends` 32 KiB a slot, and the log queue | plus per slot `cin` (17 KiB) and `cout` (34 KiB), plus the engine: about 40 KiB a connection slot (cancho's figure, `http-server.md` section 11.2), 274 KiB for 16 identities and 75 KiB of key-parser work. Allocated only when `tls_listen` is set, and indexed by table slot (the engine's slot is the table's): **about 23 MiB more at 256 slots**, which is more than ten times the whole gateway's 1.9 MiB today. That is the honest price of the simple numbering. Only client slots use TLS state, and in steady state about half the table is clients (a session holds a client slot and an upstream slot), so a dense index from client slot to TLS state could halve it to about 12 MiB, at the price of an indirection in the data path and of its own admission bound (the accept check today lets up to 254 clients in before any has dialled an upstream): question 5 |
| CPU | 1 core | a full handshake is 3 to 5.5 ms of that core (cancho's figures; ours is gate 9), so 100 handshakes a second is a third to a half of it: `tls_rate` exists for that; each request costs about 4 times as much as plain on cancho's own server |
| authority report | `args, clock, conn_accept, conn_read, conn_write, heap, io_write, net_in(""), net_out(""), poll` | plus `dir_read`, `file_read`, `fs_read("/dev/urandom")`, `fs_read("<tls_dir>")` (slice 1) and `signals("HUP,INT,TERM")`, `signals_read` (slice 2, built; in the plain row too, section 11.7). `authority.toml`'s ceiling is changed deliberately, in the same PR, with the reason |

## 5. What the TLS slice needs from cancho that it does not have

| need | state | what we do |
|---|---|---|
| `narrow` into several paths | cancho #364, open | wait; pin to the commit that has it (question 1) |
| the peer's address | not built (`conn_peer`) | none: the log has no client address over TLS either; `docs/headers.md` section 1 is unchanged |
| a half-close | none | `close_notify` then close; the lingering after a refusal (`docs/proxy.md`) stays |
| how a project depends on `packages/tls` | the examples are built from a lock file pinning a store (`examples/*/server.lock`); the gateway has a project file (`cancho.toml`) | **open** (question 2): read cancho's package-system notes and settle it before slice 1; the deployment generator may have to emit the lock |

## 6. What it does not weaken

- **Smuggling and framing:** the corpus runs through TLS and must give the verdicts it gives plain (gate 2). The gateway sees the same plaintext either way, so a difference would be a bug in the glue.
- **SNI and Host:** a client that sends SNI `a.example` and `Host: b.example` is routed by `Host`. This is the same trust the plain port gives `Host`. *(Corrected: the log does not record the SNI in slice 1; the line's byte bound has no room for it without a decision about the bound, and nothing needs it yet.)* Whether a deployment should refuse a mismatch is a later `tls_*` key, not a default.
- **The upstream set:** unchanged and still enforced in code before every connect; a TLS client cannot change it.
- **No secret in a log or a metric:** the key is held by the engine and overwritten when an identity is replaced or the engine ends (cancho's guarantee, `tls-server.md` section 4); the gateway's buffers hold plaintext of the request and response, as today, and ciphertext in `cin` and `cout`.

## 7. The numbers to fix before the code

| | value | why |
|---|---|---|
| `cin` per slot | 16,384 + 5 + 256 = 16,645, rounded to 17,408 | one record of ciphertext at the engine's largest |
| `cout` per slot | 34,816 (two records) | the engine writes a record at a time; two lets one be written while the next is made |
| `tls_handshakes` | 32 | `tls_echo`'s default |
| `tls_rate` | ~~100~~ **50** a second *(corrected: measured 12 ms a handshake, section 10)* | `tls_echo`'s default was 100; the operator sets it from the machine's own handshake figure |
| `tls_handshake_ms` | 10,000 | `tls_echo`'s default |
| identities | at most 16 | the engine's bound |
| ALPN offered | `http/1.1` | the gateway speaks nothing else |

## 8. Gates, fixed before the code

1. **Interop** (a script in `tests/tls/`, run in CI): `openssl s_client`, curl and Python's `ssl` through the gateway to the recording upstream: a GET, a POST with a 3 MB body and a 6 MB response (both directions through the buffers' bounds), 100 keep-alive-less requests, SNI selecting the second identity and the default for an unknown one, ALPN `http/1.1` accepted and `h2` alone refused. Each checks the response byte for byte and the access-log line (`"tls":true`).
2. **The smuggling corpus over TLS:** `tests/smuggling/run.py --gateway`, `--prefixes`, `--chunked` and `--fuzz`, each run a second time with the client side wrapped in TLS: every verdict equal to the plain run's. *(Corrected: those four drivers run `build/framing_probe`, the framing module alone, not a socket, so there is no client side to wrap. The gate became: every case of the corpus, and every chunked case, sent to a built gateway in the clear and over TLS, the same verdict from both. `tls_test.py`, 99 cases.)*
3. **Bounds:** `tls_handshakes` held by silent peers delays an honest one rather than refusing it; a peer that connects and sends nothing is dropped at `tls_handshake_ms` and does not delay the others; `tls_rate` holds under a burst of 200 handshakes; a client that handshakes and then stops reading its response does not grow the gateway's memory beyond the slot's buffers and is ended at its deadline.
4. **Hostile TLS:** cancho's liar-client vectors (`tests/vectors/tls/liar_client.txt`, 110 connections) replayed against the gateway's TLS port: the gateway stays up, every refusal is a `tls-server-*` tag in `refusals_total`, no file descriptor or slot leaks (the churn test of `tests/proxy_test.py`, over TLS).
5. **A truncated request:** a TLS peer that closes the TCP connection without `close_notify` after half a request body gives an aborted request in the log and nothing at the upstream beyond what was forwarded as the plain case forwards (the plain `client_leaves_mid_body` test, over TLS).
6. **The report:** `scripts/authority.py --check` against the recorded manifest with exactly the labels of section 4 and no `fs_read("")`; a mutant that widens the narrowing to the whole filesystem must fail it.
7. **The 2,000-line gate** and the existing end-to-end tests (75 in `tests/proxy_test.py`, 16 in `tests/admin_test.py`) passing unchanged on a build with `tls_listen` unset, and (where they apply) over TLS.
8. **Mutants** of the new code, all killed or explained: the data path's back-pressure (feed without room, send without release), the handshake bounds (each), the phase change at establishment, `close_notify` at the end, the scheme header, the log field, the narrowing.
9. **Cost, measured in the benchmark harness** against the plain gateway in the same rounds: C1 and C4 over TLS (the harness gets a TLS-capable load tool) and a handshake-rate cell; the result is a number in this document, with the machine's drift stated, not a claim.

## 9. Questions that decide the first slice

1. **cancho #364.** The design wants the report to name two paths. The PR is open. If it is merged, the gateway moves its pin to that commit (a deliberate change, `cancho.toml`). If it is not, the choice is to wait, or to build with `fs_read("")` and say so in the report, the page and the runbook; this document's position is **wait**, because "what can this program touch" is the gateway's headline and `fs_read("")` is the whole disk.
2. **How the gateway depends on `packages/tls`.** Unknown at the time of writing; to be read from cancho's package-system documentation before any code. If the answer needs a lock file, the generator emits or checks it.
3. **Should `listen` become optional,** so that a deployment can be TLS-only? Probably yes (a TLS-only edge is the natural deployment), at the price of a generator rule ("at least one of `listen`, `tls_listen`") and a second `Listener` handled like the admin one. Decided in the slice that adds the listener.
4. **Slices.** (1) the TLS listener, handshake, data path, bounds, interop, the report; (2) reload by `SIGHUP`; (3) the cost cell and the runbook text; each its own PR.
5. **Index the TLS state by slot, or by client?** By slot is one numbering and the simplest data path (cancho's examples do it); by client halves the memory (about 23 MiB to about 12 MiB at 256 slots) and costs an indirection table. This document's position: **by slot first**, measured, and the indirection only if the memory figure is what stops a deployment.

*(Answered: 1. #364 merged; the pin is `2fcf4cd`. 2. A `[dependencies.tls]` table in `cancho.toml`, a full commit and the store's path in cancho's repository; `cancho build` fetches 13 files into `build/deps` and re-checks every hash; no lock file, nothing for the generator to emit. 3. Not in slice 1; **yes in slice 2**: `listen` is optional, at least one of `listen` and `tls_listen` is required (section 11.6). 4. Slice 1 is this one. 5. By slot, as proposed; the figure is in section 10.)*

## 10. As built (slice 1)

**What exists.** `tls_listen`, `tls_dir`, `tls_identities`, `tls_handshakes`, `tls_rate`, `tls_handshake_ms` in the deployment file (the generator refuses the bad ones, one tag, `config.tls`); `generated/tlsfiles.cho` (the only code that holds the filesystem: it narrows to the
two literal paths, reads 32 bytes of entropy, opens the directory once, and everything after reads through that handle); `src/tlsids.cho` (cancho's `examples/tls_echo/identity.cho`, read, unchanged apart from the module name); `src/tlsio.cho` (the glue: `read`, `write`, `drain`, `promote`, `end`,
`admit`, `start`; no HTTP byte is known to it); and the proxy's own changes, which are the two socket calls of a client slot (`client_read`, `client_write` in `shared.cho`), the handshake queue and the TLS turn of the loop (`tls_turn`), and the sweep's rule that a connection that has not finished
its handshake is dropped without an answer, since there is no HTTP to answer with.

**What differs from the design, and why.**

| design | built | why |
|---|---|---|
| `proxy.cho` grows | `proxy.cho` split: `shared.cho` (constants, `Core`, the per-slot metadata, the log line, the client's bytes, the end of a session) and `adminloop.cho` (the admin listener's connections) | it was 2,028 lines with the glue's call sites; the ceiling is 2,000. The split moved text and renamed calls (`shared.x`); nothing else in it changed, and the 75 + 16 existing tests are the check |
| TLS state absent unless `tls_listen` | always present: one slot's engine and one slot's buffers when off (about 60 KiB), the full ones when on | this compiler cannot bind a payload wider than one leaf when matching a `res enum` through a reference (`matching through a reference cannot bind a payload wider than one leaf`), so `Core` holds a `Tls` struct, not an `Off | On(Tls)` enum. The mode field of each slot says whether it is in use |
| handshakes queued in arrival order | queued oldest first by accept time | the first version took the lowest slot number first and **starved** a connection in a high slot for as long as new ones kept taking the low slots: 19 of 250 connections in a burst test waited out their 4 s and were dropped. `tls_test.py` has the burst; a mutant that restores lowest-slot-first fails it |
| a queued connection is bounded by `tls_handshake_ms` | bounded by `total_timeout_ms` while it waits, and by `tls_handshake_ms` from when its handshake starts | bounding the wait by the handshake's deadline refused the honest peer that a bound is meant to delay (the first version did; a mutant that restores it fails the burst test with 110 clients at once, the last of which waits 2.2 s) |
| edition 6 for the modules that touch the new capabilities | `gateway.cho` (its `Split` has a `signals` field in edition 6, released unread *(slice 2 claims it, section 11)*), `tlsio.cho`, `tlsids.cho`, `tlsfiles.cho`; the rest stay edition 5 *(corrected in slice 2: `proxy.cho` is edition 6 too, section 11.7)* | as designed |
| `X-Forwarded-Proto`, log field, metrics | as designed, with the corrections marked in section 3 | |
| the report | `gateway`: the old row plus `dir_read`, `file_read` (the code is in every build; a deployment without `tls_listen` releases the capability unread and reports no `fs_read`). `gateway-tls` (derived for `deploy/examples/tls.toml`): the same plus exactly `fs_read("/dev/urandom")` and `fs_read("/etc/cancho-gateway/tls")` | `scripts/authority.py` derives both and fails on any other `fs_read`, and on `fs_write`, `file_write`, `dir_write` and `ffi` as before |
| the default `tls_rate` is 100 a second | **50** | a handshake measured 12 ms of this gateway's CPU on the development machine (below), against cancho's 3 to 5.5 ms; 100 a second would be more than a core. The operator sets it from their machine's figure |

**Gates.**

| gate | status | where |
|---|---|---|
| 1 interop | **met** | `tests/tls_test.py`: Python `ssl`, `openssl s_client`, curl; a GET, a 3 MB POST echoed and a 6 MB response (byte for byte), 100 requests on separate connections, SNI picking the second identity and the default for an unknown name, ALPN `http/1.1` accepted and `h2` alone refused, TLS 1.2 refused; the log line has `"tls":true` and the upstream saw `X-Forwarded-Proto: https`. *(Not done: the log line's byte-for-byte check for every one of these; each checks the status, outcome and flag.)* |
| 2 smuggling corpus | **met, as corrected above** | 60 framing cases and 39 chunked cases, the same verdict in the clear and over TLS |
| 3 bounds | **met** | four silent peers at `tls_handshakes = 4` delay an honest one until they are dropped at `tls_handshake_ms`, and are counted as `tls.handshake-timeout`; 250 handshakes at `tls_rate = 50` take at least 3 s and are all served; a client that handshakes and stops reading is ended at its deadline with the gateway's RSS growing by under 4 MiB; a response longer than the kernel's buffers is delivered whole to a client that reads late (the session waits for the ciphertext still queued) |
| 4 hostile TLS | **met, with the gap below** | the 91 cases of cancho's liar-client vectors that carry client bytes (`tests/vectors/tls/client_bytes.txt`, the client's writes only, taken from cancho `2fcf4cd`) replayed; the gateway stays up, every refusal is a `tls-*` tag in `refusals_total`, and the table is empty afterwards (`sessions_active` at most 1, the scrape's own client). *Gap:* the vectors' later flights are encrypted to the recording's server keys, so after the first flight they are noise to this server; cases decided on the ClientHello are exercised exactly, the rest are exercised as hostile bytes, not as the attack they were written to be |
| 5 truncated request | **met** | a TLS peer that ends the TCP connection mid-body gives `"outcome":"aborted"` with `"tls":true` |
| 6 the report | **met** | `scripts/authority.py --check` (CI) and `tests/authority_test.py`: a build whose directory is widened to `/etc` is refused by the ceiling, one narrowed to `/` is refused by the compiler (nested paths) |
| 7 the 2,000-line gate, the existing tests | **met** | the largest source file is `proxy.cho`, 1,334 lines; 75 + 16 tests pass with `tls_listen` unset (`example.toml`) |
| 8 mutants | **21 single edits of the new code: 16 killed, 5 survive, each argued** | below |
| 9 cost in the benchmark harness | **not done** | the harness has no TLS-capable load tool; the informal numbers below are one machine, one connection, Python endpoints |

**Mutants.** Killed: feed's "more may be waiting" flag removed (a 3 MB POST stalls, 504); the loop's no-sleep after progress removed (the same); the header clock not started at establishment; establishment declared before the engine says so; `close_notify` not sent; the scheme
always `http`; the log field off; the concurrency bound removed; the rate bound removed; the handshake deadline never applied; the queue bounded by the handshake deadline; lowest slot first; the session ended with ciphertext still queued; the handshake not counted; the engine's refusal tag lost; the timeout tag lost. **Survive:**
(1) `send` taking nothing answered `Wrote(0)` instead of `Again` (the proxy treats both as no progress: equivalent). (2) `drain` returning "done" when the socket is full: the next `write` then hands the engine plaintext it queues, bounded by the engine's own output queue and by `cout`; the memory bound the gate measures (RSS) holds either way. (3) `eof` not told to the engine for a peer that left: the proxy drops the session on `End` either way and `tls.drop` wipes the slot. (4) the 20 ms wake while a handshake waits for its turn removed: a queued handshake then starts at the next turn, at most 250 ms later; latency only. (5) a read watch kept while ciphertext is held that the engine cannot take: CPU
(a busy turn), not correctness; it needs a state (the engine's output full while the plaintext buffer has room) that no test reaches.

**Measured (informal; not gate 9).** One machine, one core of it, Python endpoints and upstream, the gateway's CPU from `/proc`. *A full handshake: 12.0 ms of the gateway's CPU* (200 handshakes started at 50 a second). *Bulk, one connection, 100 MB through the gateway: 162 MB/s over TLS (0.44 s of gateway CPU) against 378 MB/s plain (0.14 s)*; the TLS path is
about three times the plain one's CPU for the bytes moved. *Memory:* 1.8 MiB resident plain, 2.4 MiB with `tls_listen` and no connection, 13.9 MiB with 100 established TLS connections, about 110 KiB each; the 23 MiB of section 4 is the figure with all 256 slots touched. The per-request cost against plain, and the handshake rate in the benchmark harness, are gate 9.

**What it does not do, again.** *(Corrected by slice 2: reload and a TLS-only deployment are built, section 11.)* TLS to the upstreams, client certificates, HTTP/2, the SNI in the log, a peer address, a change of an identity's names or of the set of identities without a restart. The runbook line: copy the new files in (each file whole, the pair complete), then `kill -HUP <pid>`.

## 11. Slice 2: reload on `SIGHUP`, a clean stop, and an optional `listen`

Written before the code (the claims in 11.1 to 11.7 are the design; 11.8 and after say what was built and measured, and where it differs).

**11.1 The claim.** `main` narrows the `signals` field of `Split` (released unread in slice 1) to `"HUP,INT,TERM"` and `signals_watch` takes it once, before any socket is served and before any thread (the gateway has none; cancho refuses a watch while a spawned thread is live,
`signals.md` section 3). The `SignalWatch` is registered on the loop's `Poller` under its own token (`slot_limit() + 3`, beside the admin and TLS listeners' tokens), so a signal wakes `poller_wait` instead of waiting out its 250 ms nap; the registration is level-triggered, so the loop
reads it with `signals_pending` every time the token is reported, which also clears it. The claim is in **every** build, plain deployments included: one program has one authority row, and without it `SIGINT` and `SIGTERM` would end the process by the kernel's default (status 130 or 143, the access-log
queue's last turn lost). A deployment without `tls_listen` has nothing to reload: `SIGHUP` is read and ignored. (Its default action would end the process, which is a worse thing for an operator's `kill -HUP` than a no-op.) If the claim fails (`EBUSY`, `EMFILE`) the process exits with status 7, before it has
served anything.

**11.2 Stop.** The first `SIGINT` or `SIGTERM` ends the loop at the end of the turn it was read in: the access-log lines of that turn are written, every connection that is up gets its TLS `close_notify` (best effort, as at the end of any session: `tlsio.end_all`), the sockets close, the
`SignalWatch` is closed (so a **second** signal during the exit is the kernel's default and ends the process at once, which is what an operator who is impatient means), and the exit status is **0**. `gateway: stopping` is written to standard error. There is **no drain**: a request in flight is cut, as it
is when the process is killed today. A drain needs the listeners to stop accepting, and a `Listener` cannot be unwatched, only closed (`tls-server.md` section 11.2 says why for cancho's own servers), so it is a larger change and not in this slice.

**11.3 Reload.** On `SIGHUP`, `tlsio.reload` reads every identity again, in order, by `tlsids.load(heap, dir, name, engine, id, now)` with `id >= 0`, which is `tls.replace_identity`: the engine checks the chain parses, the key parses, and the pair match (`tls-server-key-mismatch`) and swaps both only if all
is well; names are not read again (`replace_identity` keeps the names the identity was added with), so a change of names, or a new identity, is a restart. A failure of any kind (a file that cannot be read, a chain or key the engine refuses) **leaves that identity's old certificate serving**, is **counted**
(11.5) and **logged to standard error**, one line an identity: `gateway: tls reload <identity> ok`, `gateway: tls reload <identity> refused <tls-server-tag>`, or `gateway: tls reload <identity> unreadable <file> errno=<n>`. The identity's subdirectory name is the operator's own (the generator restricts it to
letters, digits and `. _ -`), the tag is from the engine's closed set, and no key material is ever written: nothing a log line holds is a secret. Standard error and not standard output, because standard output is the access log, whose lines are one JSON object each, in a fixed key order that a log pipeline
parses; a reload line there would be a line it does not understand. An identity that reloads fine while another does not is still replaced (they are independent: a deploy hook that renewed one of two certificates should not need the other to be renewed too).

**11.4 What the directory handle costs, and what a connection keeps.** A reload reads files, so the directory handle that `start` opened must live as long as the process: `tlsio.start` now returns `(Tls, DirOpened, status)`, `main` holds the handle in `serve` and closes it after the loop, and `proxy.run` is
passed a reference to it (`&DirOpened`). The narrowing is **unchanged**: `generated/tlsfiles.cho` is still the only code that holds the filesystem capability, it narrows to the same two literal paths, and everything after it reads *beneath the handle* (`dir_read`, `file_read`), which cannot name a path outside
the directory. The report keeps exactly the two `fs_read` paths and no `fs_read("")`, which `scripts/authority.py` and `tests/authority_test.py` fail on. **In-flight connections:** an established connection has derived its keys and keeps working to its end; a connection whose ClientHello has been answered keeps the
certificate it was sent (cancho's own statement, `tls-server.md` section 11.2); a connection that arrives or finishes its hello after the reload gets the new certificate. Nothing is closed by a reload.

**11.5 Metrics.** `tls.reloads` and `tls.reload_failures` in the JSON (after `handshakes` and `failures`; `tls` is still one object and the top-level key list is unchanged), `tls_reloads_total` and `tls_reload_failures_total` in the Prometheus text; **per identity**, not per signal, so a reload of two identities of which one
is refused moves each counter by one. No label (the cardinality rule of `docs/observability.md`); the failing identity's name and tag are in the log line. The worst-case scrape bound grows by the 419 bytes the two families add (`metrics_bound_test.cho`, whose rule-table offset moves from 196 to 198 because the table
has two more cells).

**11.6 `listen` is optional.** `listen` may be absent: **at least one of `listen` and `tls_listen` is required**, and a deployment with neither is refused by the generator with the tag `config.listeners`. `listen = 0` is still refused (`config.listen`); the way to say "no plain listener" is to leave the key out. `admin_listen` must
differ from `listen` only when there is one (`config.admin`), and `tls_listen` from `listen` and `admin_listen` (`config.tls`), as before. The generated `listen_port()` answers `0` for a TLS-only deployment and `gateway.cho` binds the plain port only when it is not 0 (the same shape as the admin and TLS listeners; `proxy.run` takes the plain
listener as a `Listening` like the other two, matched where it is used), so every accessor still compiles and nothing but the bind and the poller registration changes. The request id's port field, which names the port a request came in on, is the TLS port when there is no plain one. Every route is served on whichever listeners
exist: a front that wants the gateway to *refuse* plain HTTP simply has no `listen`.

**11.7 The report.** Both rows, `gateway` and `gateway-tls`, gain `signals("HUP,INT,TERM")` and `signals_read`: a **deliberate widening** of `authority.toml`, with the reason in the file, and the manifests re-recorded (`python3 scripts/authority.py`). It is exactly those three signals (the compiler refuses any other name, and the
report prints the set, so a program that claimed one more would be refused by the ceiling: `tests/authority_test.py` makes that edit and shows the refusal). `err_write`, for the reload's standard-error line, was already within the ceiling and is now derived. Nothing else changes: still no `fs_write`, `file_write`, `dir_write` or
`ffi`, still exactly two `fs_read` paths in the TLS row and none in the plain row. `proxy.cho` moves from edition 5 to edition 6 (it names `SignalWatch` and calls `signals_pending` and `poller_add_signals`); the diff to it is the signal turn, the plain listener as a `Listening`, and `end_all` at the end of the loop.

**11.8 Gates.** (a) The tests of `tests/tls_test.py`: `SIGHUP` after a certificate is replaced on disk, a new connection gets the new certificate (compared as DER, and it verifies against the new chain and not the old), a connection that was open before keeps working with the certificate it was sent; four
kinds of bad replacement (a key that is not a key, a pair that does not match, a missing file, an empty chain), each leaving the old certificate serving, counted in both formats, and named on standard error; `SIGTERM` and `SIGINT` each stop the gateway with status 0 and an open TLS connection gets `close_notify`;
a TLS-only deployment listens on the TLS and admin ports and no other. (b) `tests/proxy_test.py`: `SIGHUP` on a plain deployment is ignored, `SIGTERM` and `SIGINT` stop it with status 0. (c) `tests/generate_test.py`: one case for each new refusal and acceptance. (d) `tests/authority_test.py` as in 11.7. (e) Mutants of the new code (11.9).

**11.9 As built, and where it differs from the design.** Everything in 11.1 to 11.7 was built as written. What the code found: (1) the directory handle could not simply be stored in `Tls` (a `res struct` that must exist, `bare`, in a deployment with no directory), so `start` returns it beside the state as a `DirOpened`, `serve` in `gateway.cho` owns
it and lends `proxy.run` a `&DirOpened` that the signal turn matches in place (a `Failed` for a deployment without TLS, where `SIGHUP` is a no-op). (2) `serve` could not declare `dir_read`/`file_read`: the compiler discharges them by the handle the function holds, and a row that names an effect it does not perform is refused ("a row is exact").
(3) The measure of "exactly two `fs_read` paths" is unchanged and still checked in `scripts/authority.py` (it fails on any other count, and on `fs_read("")`). (4) The plain listener's `listener_nonblocking` moved from `main` into `proxy.run`, beside the other two listeners', because the plain listener may now not exist.
(5) A stop is a loop exit, so the lines of the turn are written and `end_all` sends `close_notify` to every connection that is up; the exit status is `0`, and a test shows a TLS client that was connected when `SIGTERM` arrived reads a clean end of stream, not a reset. (6) `err_write` is new in the derived report (it was in the ceiling already). The tests: `tests/tls_test.py` 22 (18 before),
`tests/proxy_test.py` 77 (75), `tests/admin_test.py` 16 (the key list and the Prometheus names gain the reload counters), `tests/generate_test.py` 90 refusal cases (82) and 7 accepted (5) and two checks of what a TLS-only deployment compiles, `tests/authority_test.py` 5 checks (3).

**Mutants of slice 2.** 28 single edits of the new code, each applied to a copy of the tree and run against the tests that should notice it: **27 killed, 1 survives**, argued below. (The first version of mutant S1, "SIGHUP ignored", was written as `sg.has(mask, 0)`, which is true of every mask (all of no bits are present), so it survived, and it was
a bad mutant, not a gap: it reloads on every signal. Rewritten as a test of `SIGUSR1` instead, it is killed.)

| | the edit | killed by |
|---|---|---|
| R1 | reload reads only the first identity | reload counters (+1 where +2) |
| R2 | a refused replacement counted as replaced | the failure counter |
| R3 | an unreadable file reported as `refused` | the stderr line of the missing-key case |
| R4 | the reload line is not written | the stderr line |
| R5 | identity number off by one | counters and the certificate served |
| **R6** | **reload with the clock at 0 instead of the wall clock** | **survives**: the engine's `replace_identity` uses its time argument as a clock for the handshakes it starts, not to judge the certificate (a certificate whose `notBefore` is after 1970 was accepted at time 0). Equivalent until the engine starts to judge validity at load, and then the reload test with a not-yet-valid certificate is the one to add |
| R7 | add an identity (id -1) instead of replacing | the new certificate is not the one served |
| S1 | `SIGHUP` not recognised | no reload |
| S2 | `SIGINT`, `SIGTERM` not recognised | the process does not stop (3 s wait) |
| S3 | `SIGHUP` also stops the gateway | the plain deployment must survive `SIGHUP` |
| S4 | a stop answers status 1 | exit status 0 |
| S5 | the signal's token equals the TLS listener's | the signal is never read; no reload |
| S6 | the claim is not registered on the poller | no reload (the signal is blocked, never seen) |
| S7 | `end_all` not called | an open TLS connection gets a reset, not `close_notify` |
| S8 | `end_all` skips every slot | the same |
| S9 | no `gateway: stopping` line | the exact stderr line is asserted |
| C1 | the two reload counters swapped | counters |
| C2 | Prometheus prints the failures as the reloads | the Prometheus test |
| C3 | JSON key renamed | `admin_test.py`'s key list |
| C4 | the scrape bound not grown for the two new families | `cancho test` (`metrics_bound`) |
| L1 | the plain port bound even when `listen` is absent | the TLS-only deployment's listening ports |
| L2 | the request id's port is 0 with no plain listener | the request id test |
| L3 | the plain listener left blocking | the plain listener's test |
| L4 | the plain listener never polled | the plain listener's test |
| G1 | a deployment with no listener accepted | `config.listeners` cases |
| G2 | `admin_listen == listen` compared when there is no `listen` | the TLS-only deployments without an admin port |
| G3 | `listen = 0` accepted | the `config.listen` cases |
| G4 | `--explain` says a plain listener exists | the TLS-only compile check |

**Not done in slice 2:** a drain on stop (requests in flight are cut); the names of an identity, or the set of identities, read again (a restart); a reload of an identity's chain that is not valid yet (R6); the cost cell (gate 9). The runbook line for a renewal: copy the new `chain.pem` and `key.pem` into the identity's directory (each file replaced whole; the pair complete before the signal, because the engine refuses a pair that does not match and the old one keeps serving), then `kill -HUP <pid>`, then look at the
`tls_reload_failures_total` counter or at standard error.
