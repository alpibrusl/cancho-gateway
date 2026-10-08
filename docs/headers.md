# The header policy (task #7)

Status: **design, written before the code; the gates in section 6 are fixed here and must be able to fail.** Numbers and
claims below are about the pinned compiler (`cancho.toml`); where a later commit finds one false, it is corrected here, in
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
| the client's address, for `X-Forwarded-For` and `Forwarded: for=` | **not available.** `Accepted` carries no peer address; `docs/native-sockets.md` (the "Peer address on `accept`" row) records `conn_peer(&Conn, &![byte]) -> int` as a later, additive builtin "with no asker until an access log exists". It is not in `std.conns` or the builtins at the pinned commit (`grep conn_peer` over `std/` and `builtin.rs`: no match) | the gateway **cannot say who the client was**. It does not write a `for=` or an `X-Forwarded-For` of its own, and says so (section 2). #7, #9 (rate limiting by client address) and #10 (the access log) are now three askers for `conn_peer`; it is a request to cancho, not something to emulate |
| randomness for request ids | **no random-bytes effect.** The TLS engine is seeded by a program that read `/dev/urandom` through a file capability (`docs/tls-hooks.md`); the TLS engine is seeded from it once, at start, and the gateway deliberately has no random-bytes capability beyond that (design section 3) | request ids are **unique, not unpredictable**: a start stamp, the listen port and a counter (section 3). They are correlation ids and nothing may treat them as secrets |
| the clock | present (`clock`); the loop already reads `clock_ms` each turn | the start stamp |

## 2. The policy, in one table

`trust_forwarded` is a per-route key (default `false`) in the deployment file: "the party in front of this gateway is mine and
its forwarding headers are true". The realistic case is a TLS-terminating front (Caddy, nginx) that sets them. The gateway can terminate TLS
itself on `tls_listen` (`docs/tls.md`); a client that did is forwarded as `https`.

| header | `trust_forwarded = false` (default) | `trust_forwarded = true` |
|---|---|---|
| `Forwarded`, `X-Forwarded-For`, `X-Forwarded-Port`, `X-Real-IP` (request) | **removed**, whatever the client sent | passed through untouched |
| `X-Forwarded-Host`, `X-Forwarded-Proto` (request) | inbound removed; `X-Forwarded-Host: <the Host header as received>` and `X-Forwarded-Proto: https` (the client spoke TLS on `tls_listen`) or `http` added | passed through untouched; none added |
| `X-Request-Id` (request) | inbound removed; a generated one added | one inbound header whose value is 1 to 64 bytes of `[A-Za-z0-9._-]` is **kept**; any other (invalid value, empty, or more than one header) is removed and a generated one added |
| `Via` (request) | inbound kept (an intermediary appends, RFC 9110 7.6.3); `Via: 1.1 cancho-gateway` appended | the same |
| `Via` (response) | upstream's kept; `Via: 1.1 cancho-gateway` appended | the same |
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
- **The request id in the response and in `problem+json`: built with the access log (`docs/observability.md` section 4).** It was deferred here because the head the id came
  from is gone when the response is rewritten; the per-session id area the log needs solves both, so the two were done together in #10's first slice. A response now carries
  `X-Request-Id` (an upstream's own is removed first), and a refusal carries it in the header and as `"request_id"` in the body.
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
2. **The gateway's literals** (`Via: 1.1 cancho-gateway`, `X-Forwarded-Proto: http` or `https`).
3. **Hex digits it formats** (the id) and **the Host header** (case 1, already validated).

A kept `X-Request-Id` is restricted to `[A-Za-z0-9._-]` precisely so that a trusted-but-wrong front cannot smuggle a delimiter, a
quote or a comma into a log line later (#10).

## 5. What it costs

Four headers add about 130 bytes to a head, plus the Host header's length again for `X-Forwarded-Host`. The head limit (16 KiB) and the
upstream queue (32 KiB) leave room; a head that still does not fit is refused as before (`forward.head-room`, 431). **Measured** with the benchmark
harness against the build just before this change (5 interleaved rounds, one core): C1 `cancho` ÷ before 1.05 (0.89 to 1.07 over the rounds), C4 1.03
(0.95 to 1.09): **no cost that the noise does not hide**, and no gain either; a ratio above 1 here is the machine, not the headers.

## 6. Gates, fixed before the code

1. **Table-driven unit tests** (`tests/forward_test.cho`): every row of the table in section 2, for both settings of the flag, byte for byte.
2. **End-to-end** (`tests/proxy_test.py`), through a real gateway to a recording upstream: a client that claims `X-Forwarded-For`,
   `Forwarded`, `X-Real-IP`, `X-Forwarded-Host/Proto/Port` and `X-Request-Id` is not believed on a default route, and is passed on a trusted one; the same
   request sent again on a fresh connection carries the same id; two requests carry different ids; the id matches the format of section 3; no header the client did
   not send appears except the four, and no control byte reaches the upstream other than CRLF as the delimiter. (First written as "every byte printable ASCII"; corrected
   in the test's first run: a value may carry obs-text, 0x80 and up, which RFC 9110 allows and the gateway passes as received, as nginx does.)
3. **Injection corpus**: crafted values (CR/LF and NUL in every header position and in the target, `%0d%0a` in the path and query, a
   `Host` with commas, quotes and spaces, an `X-Request-Id` of 65 bytes, with a comma, a space, a quote, a NUL, empty, duplicated) against both settings: none
   adds a header line the upstream did not get from the gateway's own code (counted by parsing the upstream's recording).
4. **Differential against nginx** (`tests/headers/differential.py`): a table of cases sent to nginx 1.24 and to the gateway in front of the same recording
   upstream, on a default route and on a trusted one, the two views compared header by header after removing what the gateway is *supposed* to add
   (unless the case sent a header of that name). Where they must agree, they must (order, case, duplicates, values, an empty value, a long value, obs-text, the
   request line with a query and escapes). Where they differ, the case is in an `EXPECTED` table with the reason, and a difference not in the table fails, and so
   does a listed one that has stopped differing (the table cannot go stale). **Corrected in place after the first run:** the design assumed nginx forwards
   `Keep-Alive`, `TE` and `Upgrade` and drops an empty-valued header. Measured: nginx 1.24 removes the first three and forwards an empty value, exactly as the
   gateway does; the real differences are `Proxy-Authorization`, `Trailer`, `Proxy-Connection` and a header named by `Connection` (nginx forwards them, the
   gateway removes them), the gateway's own `Via`, and the untrusted-route policy.
5. **Mutants** of the new code, all killed or explained: the trust flag ignored (each direction), an inbound forwarding header not removed,
   `Via` not added or added twice, the id not stable across a retry, the id validity check loosened (65 bytes, a delimiter, an empty value, a
   duplicate accepted), `X-Forwarded-Host` taken from the request target instead of `Host`.
6. The authority report must not change (no new effect); the 2,000-line gate; `route_ref.py`'s differential over generated tables now includes the new column.

## 7. What was built and what checked it

- **The deployment key** `trust_forwarded` (per route, default `false`): the generator refuses a non-boolean (`config.route`), the table has a sixth
  column, `route.trust_forwarded(index)` reads it, and the reference differential (`tests/route_ref.py`) compares it over 4,800 generated requests
  and the 18 fixed cases (`deploy/example.toml` trusts the `api` route, as a deployment behind a TLS-terminating front would).
- **`forward.rewrite`** applies the table of section 2; `forward.rewrite_response` appends `Via`. The request id is numbered when the request is routed
  (state slot 23 holds `2 * sequence + trust`), so a retry carries the same id; `out.put_hex` formats it.
- **Unit tests** (`tests/forward_test.cho`, 16): every row of the table for both settings, the id's format at its extremes, the nine invalid-id cases, the
  64-byte boundary, an id named by `Connection`, `Via` after the client's.
- **End to end** (`tests/proxy_test.py`, 61 tests with the 7 new): claims not believed on a default route and passed on a trusted one, bad ids replaced, ids
  unique and counting up, the port in the id, `Via` in the response, a crafted-values corpus (nine values in five header positions on both routes), and the
  retry keeping its id while other requests are routed (a 0.4 s dead pooled connection).
- **Differential against nginx 1.24** (`tests/headers/differential.py`, in CI): 114 comparisons, 36 differences, every one listed with its reason. Its first run
  found four of the design's assumptions about nginx false (section 6, gate 4); the table was corrected to the measurement.
- **Mutants:** 29 of the new code (the trust flag ignored each way, each forwarding header left in, `Via` missing or doubled, `X-Forwarded-Host` from the target,
  each id-validity rule loosened, the id not stable across a retry, the flag lost or always set, the sequence not advancing, the port left out, the route
  table's column ignored, a wrong hex digit, the response's `Via` missing): **all killed**; one (the retry reading the counter instead of the session's number) survived the
  first end-to-end tests, because with one request at a time the two are equal, and is killed by the 0.4 s test above.
- The authority report did not change except for the pure-function list and counts (no new effect); the 2,000-line gate holds.

**Not done, and why:** no `X-Forwarded-For` or `Forwarded: for=` of the gateway's own (no peer address: section 1); the credential rule for #8 is recorded, and tested when #8 has a
credential to strip.
