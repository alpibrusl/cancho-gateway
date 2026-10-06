# Upstream keep-alive and the connection pool (task #6, first part)

Status: **upstream connections are kept alive, pooled, bounded and expired; a dead pooled connection is detected and, for a safe
request, retried once.** Not built: the optional active health check, and keep-alive on the **client** side (section 6); passive
health is in `docs/health.md`. Everything here is measured by `tests/response/run.py` and `tests/proxy_test.py`.

## 1. What changed

The first slice (`docs/proxy.md`) opened a connection per request and read the response until the upstream closed it. To reuse a
connection the gateway must know **where a response ends**, so it now reads the response head and frames the body.

- `src/response.ls`: a strict response-head parser (section 2).
- `forward.rewrite_response`: the head the client gets, hop-by-hop headers removed, `Connection: close` added (the client's
  connection still closes after each response).
- `forward.rewrite`: the request line is now sent as `HTTP/1.1` whatever the client spoke, and carries no `Connection` header
  (keep-alive is the default), unless pooling is off (`pool_idle_max = 0`), when it carries `Connection: close` as before.
- `src/proxy.ls`: response framing, the pool, retry.
- Deployment keys: `pool_idle_max` (idle connections kept per upstream, 0 to 64, default 4; **0 turns pooling off**) and
  `idle_timeout_ms` (100 to 600000, default 5000).

## 2. Reading a response (measured: `python3 tests/response/run.py`)

Strict, in the spirit of `docs/framing.md`: one reading of the framing, or a 502.

| rule (all 502) | when |
|---|---|
| `response.status-line` | not `HTTP/1.x SP DDD SP reason CRLF` (the SP before an empty reason is required) |
| `response.version` | a well-formed version that is not 1.0 or 1.1 |
| `response.status` | below 100, or 101 (`Upgrade` is not spoken) |
| `response.header` | malformed, a control byte in a value, more than 64 headers |
| `response.fold` | obs-fold |
| `response.length` | a bad, signed, empty, listed or **repeated** `Content-Length` (even if the values agree) |
| `response.two-lengths` | `Content-Length` with `Transfer-Encoding` |
| `response.transfer-encoding` | anything but one `chunked` |
| `response.head-too-large` | over 16,384 bytes |

Body framing follows RFC 9112 6.3: none for `HEAD`, `1xx`, `204`, `304`; chunked; `Content-Length`; otherwise until close. A `1xx`
is passed to the client as it came and the final response awaited. A connection is reusable if the response is HTTP/1.1 without
`Connection: close` (or HTTP/1.0 with `keep-alive`), its body is not close-delimited, **nothing is left unread on it**, the upstream
did not hang up, and **the request's own body was fully sent**.

**Measured:** 55 cases with sources (all pass); 789 split-delivery prefixes (every proper prefix of an accepted head is "more");
1,500 seeded mutations, 48 accepted, each accepted head self-contained, **no trap**. Eight mutants killed: `Content-Length` with
`Transfer-Encoding` allowed, a repeated `Content-Length` allowed, a 204 or a `HEAD` response framed by its `Content-Length`, a
close-delimited body treated as reusable, obs-fold allowed, HTTP/1.0 reusable without `keep-alive`, a head limit one too high (this
last survived until I added the exact-limit boundary cases).

## 3. The pool

- **Keyed by upstream**, not by route. A finished, reusable connection goes idle (watched for reading only, so any hang-up or
  unsolicited byte closes it at once) if the upstream has fewer than `pool_idle_max` idle; otherwise it is closed. Idle connections
  expire after `idle_timeout_ms`. A client arriving when the slot table is full evicts the oldest idle connection first.
- **Retry.** A pooled connection can die in the instant between the gateway choosing it and the upstream noticing, so a request on a
  reused connection that gets a hang-up **before any response byte** is sent again **once, on a fresh connection**, but only if it
  has **no body and an idempotent method** (`GET`, `HEAD`, `DELETE`, `OPTIONS`). Anything else is answered 502
  `proxy.upstream-closed` and **never sent twice** (a `POST` is tested to reach the upstream exactly once). The head is kept in the
  client's buffer for a request that may be retried.
- A connection that fails on a *fresh* attempt is not retried.

## 4. Measured: `python3 tests/proxy_test.py` (40 tests, about 40 s; 15 new)

Ten requests in a row use **one** upstream connection; a 50 KB `Content-Length` echo, a chunked echo and a plain `GET` share one;
after a chunked, a 204, a `HEAD` (the gateway does not wait for the 100 body bytes it advertises), a `1xx` then 200, the same
connection serves the next request; HTTP/1.0, `Connection: close` and close-delimited responses are **not** reused; a connection
with unread bytes after its response is closed, not reused; hop-by-hop response headers do not reach the client; a response with
two lengths is 502; a dead pooled connection is retried for a `GET` and not for a `POST`; **a connection the upstream hung up on
while idle is dropped before it can be reused**, so even a `POST` finds a good one; ten concurrent requests keep exactly four idle
connections and all expire after the timeout; an early `413` while the client is still uploading reaches the client, and its
connection is not reused; 2,400 requests leave the descriptor count unchanged and memory within 512 KB, on fewer than twenty
upstream connections; with `pool_idle_max = 0` every request opens its own connection and tells the upstream to close.

## 5. Mutants, survivors, and what the tests found

Eleven mutants of the new logic, each killed: the pool never keeping a connection; the pool bound ignored; idle connections never
expiring; every request retryable; nothing retried; leftover bytes not preventing reuse; a hung-up idle connection not noticed; a `HEAD`
read as having a body (the test then **hangs** until its timeout); a chunked response read as close-delimited; an unfinished request's
connection reused; an early response not lingered on.

**Survivors, then fixed in the tests:** *an unfinished request's connection reused* survived my first test, because the fake upstream
closed the connection soon after anyway, so the next client got a fresh one either way; it is killed by an upstream that keeps the
connection open and an assertion that the next request is not delayed. *An early response not lingered on* survived because Linux keeps
data already received when a reset arrives, so a client that only reads the status cannot see the reset; it is killed by a client that
is **still sending** when the gateway closes (`ECONNRESET` on its `send`).

**Bugs the tests found in my code:** (1) a client that waits for the connection to close (rather than stopping at `Content-Length`) hung
**until the total deadline** after a close-delimited or already-flushed response: the end of a session only closed the client if bytes
were still queued for it. (2) A response that arrived before the request body was complete would have closed the client with the upload
unread, which resets the connection (fixed with the same lingering close refusals use). (3) My test routes `/ka-chunked` did not match the
route prefix `/ka`: a prefix matches on a segment boundary (`docs/routes.md`), so they went to the other upstream; the tests use `/ka/...`.

## 6. Not done, not tested

- **No keep-alive on the client side.** The client's connection closes after every response (`Connection: close` is added to it), so the
  pool saves the gateway's connects to upstreams but not clients' connects to the gateway.
- **Health** is in `docs/health.md` (a passive circuit); there is still no active health check.
- **The window between choosing a pooled connection and the upstream noticing it died** is closed only for the retryable requests above;
  a `POST` that hits it is a 502. The idle watch makes the window small; it is not measured.
- A `Transfer-Encoding: chunked` response sent to an **HTTP/1.0 client** is passed as chunked, which a 1.0 client cannot read. Untested.
- Upstream responses with **chunk extensions or trailers are cut off** (the session ends), as request bodies with them are refused; not
  tested against a real server that sends them.
- Upstream host names (a blocking resolver), `Expect: 100-continue` end to end, and anything about speed are untested.
