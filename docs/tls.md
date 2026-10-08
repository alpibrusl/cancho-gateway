# TLS in the gateway (task #16, the decision made)

Status: **slice 1 built (2026-10-08): the listener, the handshake bounds, the data path, the report, the tests; `docs/tls.md` section 10 says what was built, what was measured and where it differs from the
design above it. Not built: reload (slice 2), a TLS-only deployment, the cost cell in the benchmark harness (gate 9).** Sections 1 to 9 were written before the code, and where the code found one false it is corrected
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
   most `tls_rate` (default 100) started a second, `tls_handshake_ms` (default 10,000) to finish. A connection over the bound is delayed (left unwatched, so its ClientHello waits in the
   kernel and costs nothing), not refused: the common case of "too many handshakes" is a burst of honest clients; the attacker's case is bounded by the same two numbers.
6. **The end of a session.** When a client session ends in the gateway (a response relayed, a refusal sent), the engine's `finish` is called so that `close_notify` is queued, and the slot
   closes once it is written or after the flush deadline. A peer that closes without `close_notify` mid-request is an aborted request exactly as a plain reset is (the request is
   Content-Length or chunk framed, so a truncation cannot make an incomplete request look complete; this is a gate, section 8).
7. **Certificates.** `tls_dir = "<absolute path>"` is a **literal compiled into the binary** (the generator emits it, as it does the upstream addresses), and `tls_identities = ["a", "b"]` names up to 16
   subdirectories of it, each with `chain.pem`, `key.pem` and `names`, the first the default (`tls_echo`'s layout, so cancho's deploy-hook examples apply unchanged). The binary reads them at start with
   `narrow(fs, "/dev/urandom", tls_dir)`, opens the directory once, and every later read goes through that handle (`examples/tls_echo_fixed` does exactly this). The authority report therefore gains
   `dir_read`, `file_read`, `fs_read("/dev/urandom")` and `fs_read("<tls_dir>")` and **no `fs_read("")`**. Symbolic links in that directory are refused (certbot's `live/` is links: the deploy hook copies the
   files in). **This depends on cancho #364.** If the compiler the gateway is pinned to does not have it, the first slice waits for it rather than ship an `fs_read("")` (section 9, question 1).
8. **Reload** (`SIGHUP`, `tls.replace_identity`; connections already started keep the certificate they were sent) is a second slice. Until it is built a renewed certificate means a restart, and the runbook says so.
   It adds `signals("HUP,INT,TERM")` to the report, which is why it is a separate, reviewed step.
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
| authority report | `args, clock, conn_accept, conn_read, conn_write, heap, io_write, net_in(""), net_out(""), poll` | plus `dir_read`, `file_read`, `fs_read("/dev/urandom")`, `fs_read("<tls_dir>")` (slice 1) and `signals("HUP,INT,TERM")`, `signals_read` (slice 2). `authority.toml`'s ceiling is changed deliberately, in the same PR, with the reason |

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
| `tls_rate` | 100 a second | `tls_echo`'s default; the operator sets it from the machine's own handshake figure |
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

*(Answered: 1. #364 merged; the pin is `2fcf4cd`. 2. A `[dependencies.tls]` table in `cancho.toml`, a full commit and the store's path in cancho's repository; `cancho build` fetches 13 files into `build/deps` and re-checks every hash; no lock file, nothing for the generator to emit. 3. Not yet: `listen` is still required, so a TLS-only deployment is the next small change. 4. Slice 1 is this one. 5. By slot, as proposed; the figure is in section 10.)*

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
| edition 6 for the modules that touch the new capabilities | `gateway.cho` (its `Split` has a `signals` field in edition 6, released unread), `tlsio.cho`, `tlsids.cho`, `tlsfiles.cho`; the rest stay edition 5 | as designed |
| `X-Forwarded-Proto`, log field, metrics | as designed, with the corrections marked in section 3 | |
| the report | `gateway`: the old row plus `dir_read`, `file_read` (the code is in every build; a deployment without `tls_listen` releases the capability unread and reports no `fs_read`). `gateway-tls` (derived for `deploy/examples/tls.toml`): the same plus exactly `fs_read("/dev/urandom")` and `fs_read("/etc/cancho-gateway/tls")` | `scripts/authority.py` derives both and fails on any other `fs_read`, and on `fs_write`, `file_write`, `dir_write` and `ffi` as before |
| the default `tls_rate` is 100 a second | **50** | a handshake measured 12 ms of this gateway's CPU on the development machine (below), against cancho's 3 to 5.5 ms; 100 a second would be more than a core. The operator sets it from their machine's figure |

**Gates.**

| gate | status | where |
|---|---|---|
| 1 interop | **met** | `tests/tls_test.py`: Python `ssl`, `openssl s_client`, curl; a GET, a 3 MB POST echoed and a 6 MB response (byte for byte), 100 requests on separate connections, SNI picking the second identity and the default for an unknown name, ALPN `http/1.1` accepted and `h2` alone refused, TLS 1.2 refused; the log line has `"tls":true` and the upstream saw `X-Forwarded-Proto: https`. *(Not done: the log line's byte-for-byte check for every one of these; each checks the status, outcome and flag.)* |
| 2 smuggling corpus | **met, as corrected above** | 60 framing cases and 39 chunked cases, the same verdict in the clear and over TLS |
| 3 bounds | **met** | four silent peers at `tls_handshakes = 4` delay an honest one until they are dropped at `tls_handshake_ms`, and are counted as `tls.handshake-timeout`; 250 handshakes at `tls_rate = 50` take at least 3 s and are all served; a client that handshakes and stops reading is ended at its deadline with the gateway's RSS growing by under 4 MiB; a response longer than the kernel's buffers is delivered whole to a client that reads late (the session waits for the ciphertext still queued) |
| 4 hostile TLS | **met, with the gap below** | the 91 cases of cancho's liar-client vectors that carry client bytes (`tests/vectors/tls/client_bytes.txt`, the client's writes only, taken from cancho `2fcf4cd`) replayed; the gateway stays up, every refusal is a `tls-*` tag in `refusals_total`, and the table is empty afterwards (`sessions_active` 0). *Gap:* the vectors' later flights are encrypted to the recording's server keys, so after the first flight they are noise to this server; cases decided on the ClientHello are exercised exactly, the rest are exercised as hostile bytes, not as the attack they were written to be |
| 5 truncated request | **met** | a TLS peer that ends the TCP connection mid-body gives `"outcome":"aborted"` with `"tls":true` |
| 6 the report | **met** | `scripts/authority.py --check` (CI) and `tests/authority_test.py`: a build whose directory is widened to `/etc` is refused by the ceiling, one narrowed to `/` is refused by the compiler (nested paths) |
| 7 the 2,000-line gate, the existing tests | **met** | `proxy.cho` 1,334 lines, the largest 1,334; 75 + 16 tests pass with `tls_listen` unset (`example.toml`) |
| 8 mutants | **21 single edits of the new code: 16 killed, 5 survive, each argued** | below |
| 9 cost in the benchmark harness | **not done** | the harness has no TLS-capable load tool; the informal numbers below are one machine, one connection, Python endpoints |

**Mutants.** Killed: feed's "more may be waiting" flag removed (a 3 MB POST stalls, 504); the loop's no-sleep after progress removed (the same); the header clock not started at establishment; establishment declared before the engine says so; `close_notify` not sent; the scheme
always `http`; the log field off; the concurrency bound removed; the rate bound removed; the handshake deadline never applied; the queue bounded by the handshake deadline; lowest slot first; the session ended with ciphertext still queued; the handshake not counted; the engine's refusal tag lost; the timeout tag lost. **Survive:**
(1) `send` taking nothing answered `Wrote(0)` instead of `Again` (the proxy treats both as no progress: equivalent). (2) `drain` returning "done" when the socket is full: the next `write` then hands the engine plaintext it queues, bounded by the engine's own output queue and by `cout`; the memory bound the gate measures (RSS) holds either way. (3) `eof` not told to the engine for a peer that left: the proxy drops the session on `End` either way and `tls.drop` wipes the slot. (4) the 20 ms wake while a handshake waits for its turn removed: a queued handshake then starts at the next turn, at most 250 ms later; latency only. (5) a read watch kept while ciphertext is held that the engine cannot take: CPU
(a busy turn), not correctness; it needs a state (the engine's output full while the plaintext buffer has room) that no test reaches.

**Measured (informal; not gate 9).** One machine, one core of it, Python endpoints and upstream, the gateway's CPU from `/proc`. *A full handshake: 12.0 ms of the gateway's CPU* (200 handshakes started at 50 a second). *Bulk, one connection, 100 MB through the gateway: 162 MB/s over TLS (0.44 s of gateway CPU) against 378 MB/s plain (0.14 s)*; the TLS path is
about three times the plain one's CPU for the bytes moved. *Memory:* 1.8 MiB resident plain, 2.4 MiB with `tls_listen` and no connection, 13.9 MiB with 100 established TLS connections, about 110 KiB each; the 23 MiB of section 4 is the figure with all 256 slots touched. The per-request cost against plain, and the handshake rate in the benchmark harness, are gate 9.

**What it does not do, again.** Reload (a renewed certificate means a restart), a TLS-only deployment, TLS to the upstreams, client certificates, HTTP/2, the SNI in the log, a peer address. The runbook line: copy the new files in, restart.
