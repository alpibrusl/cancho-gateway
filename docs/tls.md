# TLS in the gateway (task #16, the decision made)

Status: **design, written before the code; the gates in section 8 are fixed here and must be able to fail.** Nothing in this document is built. It replaces the
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
| `narrow(fs, "a", "b")` (cancho #364, **open, not merged**) | one `Fs` narrowed into several literal paths, so a program that reads `/dev/urandom` and one certificate directory reports exactly those two paths instead of `fs_read("")` | #364's description; `examples/tls_echo_fixed` | not in the compiler the gateway is pinned to (`a4572ea`) |
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
   a trusted route passes the front's value through, unchanged. The access log gains `"tls":true|false` (the version, suite and SNI are in the engine; they go in the log only if a gate asks, because the
   line has a byte bound, `docs/observability.md` section 2). Metrics gain a counter of handshakes by outcome (`tls_handshakes_total{result}`) and the refusal tags of the engine appear in `refusals_total`
   (they are `tls-server-*` tags, all of them from a set the engine owns, so the rule table's bound holds).
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
- **SNI and Host:** a client that sends SNI `a.example` and `Host: b.example` is routed by `Host`. This is the same trust the plain port gives `Host`. The log records the SNI (a bounded, validated field) beside the host the request used, so a mismatch is visible; whether a deployment should refuse a mismatch is a later `tls_*` key, not a default.
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
2. **The smuggling corpus over TLS:** `tests/smuggling/run.py --gateway`, `--prefixes`, `--chunked` and `--fuzz`, each run a second time with the client side wrapped in TLS: every verdict equal to the plain run's.
3. **Bounds:** `tls_handshakes` held by silent peers delays an honest one rather than refusing it; a peer that connects and sends nothing is dropped at `tls_handshake_ms` and does not delay the others; `tls_rate` holds under a burst of 200 handshakes; a client that handshakes and then stops reading its response does not grow the gateway's memory beyond the slot's buffers and is ended at its deadline.
4. **Hostile TLS:** cancho's liar-client vectors (`tests/vectors/tls/liar_client.txt`, 110 connections) replayed against the gateway's TLS port: the gateway stays up, every refusal is a `tls-server-*` tag in `refusals_total`, no file descriptor or slot leaks (the churn test of `tests/proxy_test.py`, over TLS).
5. **A truncated request:** a TLS peer that closes the TCP connection without `close_notify` after half a request body gives an aborted request in the log and nothing at the upstream beyond what was forwarded as the plain case forwards (the plain `client_leaves_mid_body` test, over TLS).
6. **The report:** `scripts/authority.py --check` against the recorded manifest with exactly the labels of section 4 and no `fs_read("")`; a mutant that widens the narrowing to the whole filesystem must fail it.
7. **The 2,000-line gate** and the existing 90 end-to-end tests passing unchanged on a build with `tls_listen` unset, and (where they apply) over TLS.
8. **Mutants** of the new code, all killed or explained: the data path's back-pressure (feed without room, send without release), the handshake bounds (each), the phase change at establishment, `close_notify` at the end, the scheme header, the log field, the narrowing.
9. **Cost, measured in the benchmark harness** against the plain gateway in the same rounds: C1 and C4 over TLS (the harness gets a TLS-capable load tool) and a handshake-rate cell; the result is a number in this document, with the machine's drift stated, not a claim.

## 9. Questions that decide the first slice

1. **cancho #364.** The design wants the report to name two paths. The PR is open. If it is merged, the gateway moves its pin to that commit (a deliberate change, `cancho.toml`). If it is not, the choice is to wait, or to build with `fs_read("")` and say so in the report, the page and the runbook; this document's position is **wait**, because "what can this program touch" is the gateway's headline and `fs_read("")` is the whole disk.
2. **How the gateway depends on `packages/tls`.** Unknown at the time of writing; to be read from cancho's package-system documentation before any code. If the answer needs a lock file, the generator emits or checks it.
3. **Should `listen` become optional,** so that a deployment can be TLS-only? Probably yes (a TLS-only edge is the natural deployment), at the price of a generator rule ("at least one of `listen`, `tls_listen`") and a second `Listener` handled like the admin one. Decided in the slice that adds the listener.
4. **Slices.** (1) the TLS listener, handshake, data path, bounds, interop, the report; (2) reload by `SIGHUP`; (3) the cost cell and the runbook text; each its own PR.
5. **Index the TLS state by slot, or by client?** By slot is one numbering and the simplest data path (cancho's examples do it); by client halves the memory (about 23 MiB to about 12 MiB at 256 slots) and costs an indirection table. This document's position: **by slot first**, measured, and the indirection only if the memory figure is what stops a deployment.
