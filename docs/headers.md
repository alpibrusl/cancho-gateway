# The header policy (task #7)

Status: **design, written before the code; the gates in section 6 are fixed here and must be able to fail.** Numbers and
claims below are about the pinned compiler (`lex-sys.toml`); where a later commit finds one false, it is corrected here, in
place.

What the gateway does to the headers it forwards today (`docs/proxy.md`): it removes the hop-by-hop headers and anything the
`Connection` header names, rebuilds the request line as HTTP/1.1, and adds `Connection: close` when the upstream must not keep
the connection. Nothing says who the client was, that a proxy was in the path, or which request this is. This task adds those
three things, and decides what to believe about them when a client claims them.

## 1. What the probes found (before any design)

Two facilities the issue assumed do not exist in the pinned compiler, and the design is built around the fact, not around the
assumption.

| assumed | found | consequence |
|---|---|---|
| the client's address, for `X-Forwarded-For` and `Forwarded: for=` | **not available.** `Accepted` carries no peer address; `docs/native-sockets.md` (the "Peer address on `accept`" row) records `conn_peer(&Conn, &![byte]) -> int` as a later, additive builtin "with no asker until an access log exists". It is not in `std.conns` or the builtins at the pinned commit (`grep conn_peer` over `std/` and `builtin.rs`: no match) | the gateway **cannot say who the client was**. It does not write a `for=` or an `X-Forwarded-For` of its own, and says so (section 2). #7, #9 (rate limiting by client address) and #10 (the access log) are now three askers for `conn_peer`; it is a request to lex-sys, not something to emulate |
| randomness for request ids | **no random-bytes effect.** The TLS engine is seeded by a program that read `/dev/urandom` through a file capability (`docs/tls-hooks.md`); the gateway deliberately has none (no `fs_*`, design section 3) | request ids are **unique, not unpredictable**: a start stamp, the listen port and a counter (section 3). They are correlation ids and nothing may treat them as secrets |
| the clock | present (`clock`); the loop already reads `clock_ms` each turn | the start stamp |

## 2. The policy, in one table

`trust_forwarded` is a per-route key (default `false`) in the deployment file: "the party in front of this gateway is mine and
its forwarding headers are true". The realistic case is a TLS-terminating front (Caddy, nginx) that sets them; the gateway has no
TLS (design section 7).

| header | `trust_forwarded = false` (default) | `trust_forwarded = true` |
|---|---|---|
| `Forwarded`, `X-Forwarded-For`, `X-Forwarded-Port`, `X-Real-IP` (request) | **removed**, whatever the client sent | passed through untouched |
| `X-Forwarded-Host`, `X-Forwarded-Proto` (request) | inbound removed; `X-Forwarded-Host: <the Host header as received>` and `X-Forwarded-Proto: http` added | passed through untouched; none added |
| `X-Request-Id` (request) | inbound removed; a generated one added | one inbound header whose value is 1 to 64 bytes of `[A-Za-z0-9._-]` is **kept**; any other (invalid value, empty, or more than one header) is removed and a generated one added |
| `Via` (request) | inbound kept (an intermediary appends, RFC 9110 7.6.3); `Via: 1.1 lexsys-gateway` appended | the same |
| `Via` (response) | upstream's kept; `Via: 1.1 lexsys-gateway` appended | the same |
| hop-by-hop, and headers named by `Connection` | removed, both directions (unchanged) | unchanged |
| `Proxy-Authorization` | removed (hop-by-hop, unchanged) | unchanged |
| every other header | copied, in order, name and value as received | the same |

The added headers go after the client's, before `Connection: close`, in this order: `Via`, `X-Forwarded-Host`,
`X-Forwarded-Proto`, `X-Request-Id`. A route that leaves `trust_forwarded` off never lets a client choose what the upstream
believes about forwarding: that is the property the gates test.

**What the gateway does not do, and why.**

- **No `X-Forwarded-For` / `Forwarded: for=` of its own** (section 1). With `trust_forwarded = false` the upstream is told that a proxy
  was in the path (`Via`), what host the client asked for and that the hop was HTTP, and nothing about the client's address, which is
  honest: the gateway does not know it. A deployment that needs the address behind it puts a front that knows it in front and sets
  `trust_forwarded = true`. When `conn_peer` exists, the untrusted rows gain `X-Forwarded-For: <peer>` and `Forwarded: for=<peer>`, and the
  trusted row appends the peer to an existing `X-Forwarded-For`; the table is the contract for that change too.
- **No request id in the response yet.** The id a client sent is in the request head, which is gone by the time the response is
  rewritten (its buffer is reused), and keeping a 64-byte string per session for it is the same cost the access log (#10) needs for the same
  reason; the two are done together there, and `problem+json` carries it from #18. Until then the id is in the upstream's view of the request only.
- **No credentials of its own to leak.** In v1 the gateway holds none: it takes no keys and presents none upstream. The rule
  that stays true when #8 adds some: **a credential the gateway itself checks is removed before the request is forwarded**
  (the header #8's policy consumes is dropped in `forward.rewrite`, with a test that the upstream never sees it). `Proxy-Authorization` is
  removed already. A client's own `Authorization` is the upstream's business and is forwarded unless a route's auth policy consumes it.

## 3. The request id

`X-Request-Id: <stamp>-<port>-<seq>`, each part lowercase hex: `stamp` the gateway's `clock_ms` at start, `port` the listen port,
`seq` a counter that starts at 1 and counts requests in this process (eight digits at least). Example: `19b3c2a1f00-1f90-0000002a`. Unique within a
deployment because the three together are, across restarts because the stamp differs, across gateways on one host because the
ports differ; **not** unique across two gateways with the same port and the same start millisecond (a collision a person would
have to arrange). The id is assigned once per client request when it is routed and kept in the session, so **a request sent again on a
fresh connection (design section 6) carries the same id** both times.

## 4. Injection

Every byte written into a head comes from one of three places, and each is safe by construction:

1. **A client's header** copied as received: `framing.judge` has already refused CR, LF, NUL and other control bytes in names and
   values, obs-fold, and whitespace before the colon; nothing is re-encoded.
2. **The gateway's literals** (`Via: 1.1 lexsys-gateway`, `X-Forwarded-Proto: http`).
3. **Hex digits it formats** (the id) and **the Host header** (case 1, already validated).

A kept `X-Request-Id` is restricted to `[A-Za-z0-9._-]` precisely so that a trusted-but-wrong front cannot smuggle a delimiter, a
quote or a comma into a log line later (#10).

## 5. What it costs

Four headers add about 130 bytes to a head, plus the Host header's length again for `X-Forwarded-Host`. The head limit (16 KiB) and the
upstream queue (32 KiB) leave room; a head that still does not fit is refused as before (`forward.head-room`, 431). Measured with the benchmark
harness, not assumed: the second run's C1 is the baseline.

## 6. Gates, fixed before the code

1. **Table-driven unit tests** (`tests/forward_test.ls`): every row of the table in section 2, for both settings of the flag, byte for byte.
2. **End-to-end** (`tests/proxy_test.py`), through a real gateway to a recording upstream: a client that claims `X-Forwarded-For`,
   `Forwarded`, `X-Real-IP`, `X-Forwarded-Host/Proto/Port` and `X-Request-Id` is not believed on a default route, and is passed on a trusted one; the same
   request sent again on a fresh connection carries the same id; two requests carry different ids; the id matches the format of section 3; every
   byte of every header the upstream saw is printable ASCII and no header the client did not send appears except the four.
3. **Injection corpus**: crafted values (CR/LF and NUL in every header position and in the target, `%0d%0a` in the path and query, a
   `Host` with commas, quotes and spaces, an `X-Request-Id` of 65 bytes, with a comma, a space, a quote, a NUL, empty, duplicated) against both settings: none
   adds a header line the upstream did not get from the gateway's own code (counted by parsing the upstream's recording).
4. **Differential against nginx** (`tests/headers/differential.py`): a table of cases sent to nginx and to the gateway in front of the same recording
   upstream, the two views compared header by header after removing what each is *supposed* to add. Where they must agree, they must (order, case,
   duplicates, values, a header with an empty value). Where they differ, the case is in an `EXPECTED` table with the reason (the RFC clause), and a
   difference not in the table fails. The cases nginx handles differently on purpose (it does not remove `Keep-Alive`, `TE`, `Upgrade`, `Trailer` or
   a header named by `Connection`; the gateway does, RFC 9110 7.6.1) are the table's content, not its failures.
5. **Mutants** of the new code, all killed or explained: the trust flag ignored (each direction), an inbound forwarding header not removed,
   `Via` not added or added twice, the id not stable across a retry, the id validity check loosened (65 bytes, a delimiter, an empty value, a
   duplicate accepted), `X-Forwarded-Host` taken from the request target instead of `Host`.
6. The authority report must not change (no new effect); the 2,000-line gate; `route_ref.py`'s differential over generated tables now includes the new column.
