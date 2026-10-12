# Authentication (task #8)

Status: **design, written before the code.** Sections 1 to 11 are the design; section 12 is filled in when it is built and measured. The gates in section 10 are fixed here and must
be able to fail. A claim found false later is corrected in place and marked *(corrected)*. Claims about cancho are about the pinned compiler (`cancho.toml`, `2fcf4cd`).

`docs/headers.md` section 2 recorded the rule this task has to keep: **a credential the gateway itself checks is removed before the request is forwarded.** `docs/ratelimit.md`
section 3.3 recorded the reason for one more feature: a header key can be rotated by the client, an authenticated identity cannot. This document is the policy for the first slice:
**API-key authentication per route.** Its first job is to say what the binary may contain, because the requirement that decides every other choice is that **the binary must not
contain a usable secret.**

## 1. What cancho gives and does not give (measured, before any design)

| wanted | found | consequence |
|---|---|---|
| a SHA-256 | **`std.crypto.sha256(message, digest)`** (and the streaming `sha256_init/update/final`), FIPS 180-4, in the standard library the TLS package already uses (`import std.crypto` is in `packages/tls/server.cho`); pure, no effect | the gateway stores the digest of each key and hashes the presented credential. No hash is copied into the repository (`src/sha1.cho` and `src/b64.cho` were copied because `std` has neither; this does not need that) |
| a constant-time comparison | **none.** `grep -rniE "constant.time\|ct_eq" std/` finds constant-time scalar arithmetic and range checks (`bigmod`, `ecdh`, `ecdsa_sign`), but no exported equality for byte slices; `bytes.equal` returns at the first difference | the comparison is written here (section 4), as an OR of XORs over the whole digest, for every key, with no early exit. What that does and does not promise is section 4.3 |
| HMAC | `std.hmac` (`sha256`, `sha384`) exists | not used in this slice; it is the verifier of the next one (section 11) |
| base64 decoding | none (`src/b64.cho` encodes only) | not needed: keys are compared as the text the client sent (section 3) |
| randomness, to make keys | none in the gateway, by design (`docs/headers.md` section 1) | keys are made **outside** the gateway, by `scripts/mkkey.py` (section 5), from the operating system's generator. The gateway never makes, stores or shows a key |
| the client's address | not available (`docs/headers.md` section 1) | a failed attempt cannot be tied to an address in the log. An attacker who guesses keys is limited only by what section 8 says |
| a clock, for expiry | present (`clock`) | not needed by API keys; it is the trap of the next slice (section 11) |

## 2. Scope

**Built in this task:** per route, API-key authentication; the credential read from `Authorization: Bearer <key>` **or** from one configured header (one source per route, section 3);
the gateway holds only a SHA-256 digest of each key and a short name for it; a refusal as `application/problem+json` with `WWW-Authenticate` (401) or without (403); the identity name in the
access log; the identity usable as the rate-limit key (`rate_key = "auth"`); per-route counters of failures by kind; a deployment rule that keeps keys off a plain listener unless the operator says
a TLS-terminating front is in front; generator rules, tests, mutants.

**Not in this task, said once**

| not done | why |
|---|---|
| JWT / HMAC-signed tokens | a verifier with a secret in the binary, a clock and a claims policy is a task of its own; the design for it is section 11 |
| rotating keys without a restart | the digests are compiled in (that is the requirement). Rotation by overlap needs only a restart (section 7); a `SIGHUP` could re-read a key file but that would add a file read to the authority row, so it is not built (section 11) |
| mutual TLS (client certificates) | the TLS engine does not ask for or verify client certificates (`docs/tls.md`) |
| `Basic`, `Digest`, OAuth introspection, cookies, sessions | not asked for; each is a different credential with a different threat |
| a key in the query string | **refused by omission**: credentials in URLs end up in logs, in `Referer` and in browser history. The access log already records the path without its query (`docs/observability.md` section 2), but upstreams, proxies in front and browsers do not |
| authenticating the admin listener | it is a separate listener, reachable by the perimeter's decision (`docs/observability.md` section 7); this slice protects routes |
| per-key rate limits that differ between keys | `rate_key = "auth"` gives every identity its own bucket of the route's rate; different rates per key are not offered |
| per-key allowed methods or paths | the unit of authorisation is the route: a key is allowed on a route or not (section 6) |
| key expiry or revocation at run time | a key is in the binary until the binary is replaced |

## 3. The credential

A route chooses **one** place the credential is read from. Two sources on one route would let a client send a good key in one and a bad one in the other, and the gateway and the upstream could
read different ones; "and/or" is therefore resolved per route, not per request.

| `auth_header` | the credential is | scheme |
|---|---|---|
| `Authorization` (the default) | the token of `Authorization: Bearer <token>` | `Bearer` (RFC 6750 syntax, RFC 9110 11.6) |
| any other header name (for example `X-Api-Key`) | the whole value of that header | none |

**Exact parsing** (`src/auth.cho`; the same function for both sources; the rule tag is what the client gets, each one a test):

1. **Exactly one header** of that name (name compared without regard to case). None: `auth.missing`. Two or more, even identical: `auth.malformed`. The gateway never picks one: the upstream might pick the other.
2. The value, with leading and trailing blanks (SP, HT) removed, is the **field**. For `Authorization` it must be the scheme `Bearer` (any case, RFC 9110 11.1), **exactly one space** and the credential. Anything else
   (another scheme, no space, two spaces, a tab, nothing after the scheme) is `auth.malformed`: a request carrying `Basic ...` is told so, not treated as anonymous.
3. The **credential** is 1 to **256 bytes** of `[A-Za-z0-9._~+/=-]` (the `token68` syntax of RFC 9110 11.2). An empty credential, one longer than 256, or one with any other byte (a space inside it, a comma, a quote,
   a control byte, a byte above 0x7f) is `auth.malformed`. The limit is on the credential, not the head: the head is bounded by `limit.head` before this runs.
4. **Case**: the header name and the scheme are case-insensitive; **the credential is case-sensitive** and hashed exactly as sent. No normalisation, trimming of the inside, decoding or Unicode handling happens to it.
5. A header present but empty is not missing: it is `auth.malformed` (the client tried and sent nothing).

`scripts/mkkey.py` makes keys of the form `ck_` followed by 43 characters of URL-safe base64 (256 bits), all inside the credential alphabet.

**Removal before forwarding.** The credential header is **removed from the request the upstream gets** (`forward.rewrite`), whichever source it came from, so that a key checked here is never in an upstream's logs, its error pages
or its debugging output. `auth_forward = true` on a route keeps it, for an upstream that also checks the same credential (for example an application that reads the bearer token for its own purposes); the default is the conservative one.
Only the header the route reads is removed: a client's `Authorization` on a route that reads `X-Api-Key` is the upstream's business and is forwarded as before (`docs/headers.md` section 2). A header named by `Connection`
is removed by the existing rule whatever its name.

## 4. The key table and the comparison

### 4.1 What is compiled in

The deployment file lists keys by **name** and **SHA-256 digest** (64 lowercase hexadecimal digits); the generator writes them into `generated/routes.cho` (`keys_blob()`, one `name<TAB>digest` line per key, in file order).
There is no key and no way to recover one from the binary other than guessing it: a key made by `scripts/mkkey.py` has 256 bits of entropy, so the digest is not a way in. **A key chosen by a person (a word, a short string)
is not protected by being hashed**: an unsalted fast hash of a guessable value is an invitation to anyone who obtains the binary or the deployment file. The tool makes the keys; the doc says not to write them.

At most **64 keys** per deployment (`MAX_KEYS`; the generator refuses the 65th). A route allows all of them or a named subset (section 6).

### 4.2 The comparison

`auth.lookup(credential)`:

1. `digest = sha256(credential)` and its 64-digit lowercase hexadecimal text `hex`. The presented credential is at most 256 bytes, so this is at most 5 blocks.
2. For **every** key (all of them, never stopping at a match; the count is a compiled constant at most 64): `diff = OR over the 64 digits of (hex[i] XOR stored[i])`; `eq = (255 - diff) / 255` (1 if `diff` is 0, else 0:
   an arithmetic, not a branch, on `diff`); `found = found + (index + 1) * eq`.
3. The answer is `found`: 0 for no key, else the matching key's index plus 1. Two keys with the same digest cannot exist (the generator refuses it), so at most one term is non-zero.

**Cost**: one hash of at most 256 bytes and 64 x 64 byte comparisons per authenticated request, whether the key is right, wrong, short or long. No allocation larger than the 32-byte digest and the 64-byte text.

### 4.3 What constant time is claimed, and what is not

- The loops run over fixed counts (64 digits, the compiled number of keys) and there is **no early exit and no branch on a byte of the digest or on whether a key matched** before the answer is complete. That is the
  property the code has and the tests and mutants check.
- It is a property of the **source**. The compiler is not shown to emit code whose timing is independent of the data (nothing in cancho promises it for this code, as it does for `std.ecdh`'s scalar arithmetic, and the
  gateway is a single-threaded loop whose latency also depends on everything else). The claim is therefore "no data-dependent early exit in the program as written", not "proved constant time on this CPU".
- **Why that is enough here.** The comparison is between *digests*. What the attacker controls is the credential; what the comparison could leak is how many leading digest digits of their credential equal a stored digest. Making
  those digits agree is a pre-image problem on SHA-256: a timing difference reveals nothing the attacker can use to improve a guess of the key. The constant-time shape is defence in depth, and it is also why the digest
  is compared and not the key. What it protects against is the leak that a direct comparison of a stored key would give.
- The time of the **hash** depends on the length of what was sent (the number of 64-byte blocks, 1 to 5). The length is the attacker's own and it is bounded; it reveals nothing about any key.
- The response is the same for an unknown credential and a wrong one (they are the same case: no digest matches), byte for byte but for the request id, which the end-to-end test checks. A **valid key on a route that does not allow it**
  is `auth.forbidden` (403), which does tell the holder that the key is valid. See section 6.

## 5. Making keys

    $ python3 scripts/mkkey.py alice
    [[api_key]]
    name = "alice"
    sha256 = "b1946ac92492d2347c6235b4d2611184..."

and, on standard error, the key (`ck_...`), once. The key is made from `secrets.token_bytes(32)`. **The script never writes a file**, and its standard output (the part meant to be appended to a deployment file) holds the digest
only; the key goes to standard error so that `mkkey.py alice >> deploy.toml` cannot put it in the file. To hash a key that already exists, `mkkey.py alice --stdin` reads it from standard input (never from the command line,
which `ps` shows) and prints the same table. Nothing is logged by the script.

## 6. Deployment keys and the generator

    auth_allow_plain = false             # top level; see 7.3

    [[api_key]]
    name = "alice"                       # [a-z0-9][a-z0-9._-]{0,31}: what the access log calls the caller
    sha256 = "..."                       # 64 lowercase hex digits

    [[route]]
    name = "api"
    path_prefix = "/api"
    upstream = "api"
    auth = "api-key"                     # the only kind in this slice
    auth_header = "Authorization"        # default; any other token (<= 64 bytes) is read as the whole header value
    auth_keys = ["alice", "bob"]         # default: every [[api_key]]
    auth_forward = false                 # default: the credential header is removed before the upstream sees the request
    rate_limit = "100/s"
    rate_key = "auth"                    # one bucket per identity

Refusals, all `config.auth` with the key and the line of the file, each with one test in `tests/generate_test.py`:

| # | rule |
|---|---|
| 1 | an `[[api_key]]` name that is not `[a-z0-9][a-z0-9._-]{0,31}`, or a missing one |
| 2 | two `[[api_key]]` with the same name |
| 3 | an `sha256` that is not exactly 64 lowercase hexadecimal digits (an uppercase digit is refused, not folded: nothing is guessed) |
| 4 | two keys with the same `sha256` (one credential, two identities: ambiguous) |
| 5 | more than 64 `[[api_key]]` |
| 6 | `auth` is anything but `"api-key"` |
| 7 | `auth_header`, `auth_keys` or `auth_forward` on a route without `auth` |
| 8 | `auth_header` is not a token of 1 to 64 bytes, or names a header the gateway removes or owns (the hop-by-hop ones, `Content-Length`, `Transfer-Encoding`, `Host`) or a forwarding claim (`Forwarded`, `X-Forwarded-*`, `X-Real-IP`, `X-Request-Id`), which are removed or replaced and so could never carry a key |
| 9 | `auth_keys` is not a non-empty list of distinct declared key names |
| 10 | `auth_forward` is not a boolean |
| 11 | a route with `auth` and no `[[api_key]]` at all (a route nobody can enter) |
| 12 | `[[api_key]]` and no route with `auth` (keys that protect nothing; the digest is data in the binary for no reason) |
| 13 | a route with `auth` while the deployment has a plain `listen` and `auth_allow_plain` is not `true` (section 7.3) |
| 14 | `auth_allow_plain` that is not a boolean, or set without a plain `listen` and an `auth` route |
| 15 | `rate_key = "auth"` on a route without `auth` (`config.ratelimit`: there is no identity to key on) |

**Per-route key sets and `403`.** A key may be valid and not allowed on a route (`auth_keys`). That is `auth.forbidden`, **403**, not 401: the client did authenticate, and re-sending the same credential will not help. It
tells the holder of a valid key that the key is valid; it tells nobody else anything, since an invalid credential never reaches that test. An unknown key and a wrong key are one case and get one answer (section 4.3).

## 7. Where in the pipeline, and what the deployment must look like

### 7.1 The order

`head_ready` (`src/proxy.cho`), the new step in bold:

1. framing (`framing.judge`), routing (`route.select`): refusals as before; none authenticates;
2. **authentication: the route's credential is read, parsed, hashed and compared; `auth.missing`, `auth.malformed`, `auth.invalid` (401) or `auth.forbidden` (403)**;
3. WebSocket: `websocket.judge`, then the tunnel cap;
4. the body (`limit.body`);
5. the rate limit (`docs/ratelimit.md` section 7), with `rate_key = "auth"` reading the identity step 2 found;
6. the circuit's admission, and everything after: the dial, the pool, the retry.

So an **unauthenticated flood is cheap and spends nothing**: it costs one hash and the comparison, consumes no token of any bucket (a request refused at step 2 never reaches step 5, so it cannot drain
a legitimate identity's budget, nor fill the rate table with junk keys), never touches an upstream, and holds a slot only as any refusal does (`docs/ratelimit.md` section 3.2). It is also before the WebSocket
checks: an unauthenticated client learns nothing about the route's subprotocols or origins and takes no tunnel place (the WebSocket state is only set after step 2).

- **WebSocket**: authentication happens on the **upgrade request**, which is an ordinary `GET` with the credential in a header; the same code. Browsers cannot set `Authorization` on a WebSocket; a route for browsers uses a
  custom header only if the client is not a browser, otherwise an application-level token in the first message is the application's business. The frames of an open tunnel are not authenticated again.
- **TLS and plain**: `head_ready` sees plaintext whichever listener the bytes came from; the same code. Over TLS the credential is protected on the wire; on the plain listener it is not (7.3).
- **Retries** after a dead pooled connection do not authenticate again; the request was admitted once.
- The refusal goes through `refuse` like every other: the upstream half, if any, closed, the client lingered, the response `Connection: close` with the request's id in the header and the body.

### 7.2 The refusal

    HTTP/1.1 401 Unauthorized
    Content-Type: application/problem+json
    Content-Length: 112
    WWW-Authenticate: Bearer realm="cancho-gateway"
    X-Request-Id: 19b3c2a1f00-1f90-0000002a
    Connection: close

    {"type":"about:blank","title":"Unauthorized","status":401,"rule":"auth.missing","request_id":"19b3c2a1f00-1f90-0000002a"}

| rule | status | when | `WWW-Authenticate` |
|---|---|---|---|
| `auth.missing` | 401 | the route's header is absent | `Bearer realm="cancho-gateway"` |
| `auth.malformed` | 401 | the header twice, empty, another scheme, a credential that is empty, over 256 bytes or outside the alphabet | the same, plus `, error="invalid_request"` |
| `auth.invalid` | 401 | well formed, and no key's digest matches | the same, plus `, error="invalid_token"` |
| `auth.forbidden` | 403 | a key matches and the route does not allow it | none (RFC 9110 15.5.4: a 403 does not invite a new credential) |

For a route that reads a header other than `Authorization` the challenge names it instead of pretending to be `Bearer`: `ApiKey realm="cancho-gateway", header="x-api-key"` (`ApiKey` is not a registered scheme; it says what
to send, which is the point of the header). The `error` parameters follow in the same way. `WWW-Authenticate` goes between `Content-Length` and `X-Request-Id` (after `Retry-After` if there were one, which a 401 never has);
no other response changes by a byte (`tests/problem_test.cho` pins every existing one). The body never says which of the checks failed beyond the rule tag, never echoes the credential, and has the same
shape as every refusal.

### 7.3 Keys on a plain listener

A key sent over plain HTTP crosses the network readable by anyone on the path. The gateway cannot know whether a TLS-terminating front is in front of its plain port (no peer address, `docs/headers.md` section 1), so the
deployment has to say:

- a deployment with a route that has `auth` **and** a plain `listen` is refused (`config.auth`, rule 13) unless the top level sets **`auth_allow_plain = true`**, meaning "the plain port is reachable only through a TLS-terminating front
  or on a trusted network". The flag is a decision in the file, in the diff, and `--explain` prints it;
- with `tls_listen` alone, or with `tls_listen` and a plain `listen` that a front terminates, nothing else is needed;
- the gateway does not look at the scheme of each request: a route cannot be made "TLS only" in a deployment that also serves plain. That would be a per-request refusal (`auth.insecure`) that does not protect the key (it has already
  crossed the wire when the refusal is made). It is not offered.

## 8. Threats, and what is not protected

| threat | what happens |
|---|---|
| a key on the wire | protected only by TLS (`tls_listen`, or a front that terminates it). On a plain listener a key is sent in clear. Section 7.3 makes the operator say so |
| the key in an upstream's log | **prevented by default**: the credential header is removed (`auth_forward = false`). With `auth_forward = true` it is the upstream's to protect |
| the key in a URL | not accepted from the query string at all |
| the key in the gateway's own log | never: the access log has no headers and no query; the problem body never echoes the credential; the log carries the **name**, not the key or its digest |
| the binary or the deployment file is stolen | holds digests of 256-bit keys: not usable as credentials. Not true of a key a person chose (section 4.1) |
| **replay** | a captured credential works until the key is removed from the binary. There is no nonce, no signature over the request and no expiry: that is what an API key is. Over TLS capture needs the endpoint; the exposure is a leak at the client or at an upstream that logs it |
| **brute force by guessing** | 256-bit keys are not guessable. A key a person chose is: the gateway has no per-address limit (no peer address), so an online guess is limited only by what the gateway can answer, and an attacker who knows a key's digest can guess offline. Use `mkkey.py` |
| an unauthenticated flood | cheap (7.1) and spends no token, but not free: one hash per request, and a slot while the refusal lingers |
| timing of the comparison | section 4.3 |
| one valid key being used by someone else | inherent to a shared secret; the log's `identity` shows which key, and `rate_key = "auth"` bounds what any one holder can spend |
| `403` tells the holder of a valid key that it is valid | accepted: it is the holder's own key |
| a client that sends the credential twice | refused as `auth.malformed`; never guessed (the gateway and the upstream could read different ones) |
| the upstream also trusting a header like `X-User` that the client sets | the gateway does **not** inject the identity into the request in this slice, so there is nothing for an upstream to trust and nothing for a client to forge. See 11 |
| **the authenticated identity in the rate limiter** | `rate_key = "auth"` (section 9): a client cannot rotate it, unlike `header:X-Api-Key` (`docs/ratelimit.md` section 3.3) |

## 9. `rate_key = "auth"`

Built, because it is small: the key of the bucket is the **name** of the authenticated key (1 to 32 bytes), found in step 2 and held in the client's slot. `ratelimit.admit` is unchanged; the proxy passes the name where it
passed the header value. The generator requires `auth` on the route (rule 15). The decisions:

- Every identity has its own bucket of the route's rate and burst, so one caller cannot spend another's budget, and **a caller cannot make a new bucket by changing a string**: there are at most 64 identities.
- A request that did not authenticate never gets here, so there is no "absent" bucket for this key and an attacker cannot fill the table with junk identities (`docs/ratelimit.md` section 3.3, last row: for `auth` the
  table holds at most 64 keys per route and `rate_buckets` of 4 is enough for four identities; the default 1,024 is far more than needed and can be lowered).
- The name is the key, not the digest: the table lives in memory in the process and is never output; the name is the thing the log shows too.

## 10. Gates, fixed before the code

Each must be able to fail, with a mutant shown failing it (section 12 records them).

1. **The comparison and the parsing, a unit test** (`tests/auth_test.cho`, `[[test]] auth` in `cancho.toml`): the digest of known keys against `hashlib`; every row of the parsing table in section 3, including the empty
   header, a tab, two spaces, `Bearer` alone, another scheme in any case, 256 and 257 bytes, every byte value outside the alphabet, two headers; a key that matches the first, the last and a middle entry; a digest that
   differs in the first and in the last digit; a credential that is a prefix of a key, and a key that is a prefix of the credential; the full table of 64 keys; zero keys; a credential of 0 and of 10,000 bytes (no panic); the
   challenge text for each rule.
2. **The generator** (`tests/generate_test.py`): each of the 15 rules of section 6 has one refusal test with the key and a line; the accepted forms; the generated table; the counts of that file updated.
3. **End to end** (`tests/auth_test.py`, the built gateway, a recording upstream): a valid key passes and **the credential is not in what the upstream recorded** (both sources); `auth_forward = true` keeps it; missing, empty,
   duplicate, another scheme, oversized and wrong credentials are each refused with the right status, the right rule, and `WWW-Authenticate` where section 7.2 says; **an unknown key and a wrong key give byte-identical
   responses but for the id**; unauthenticated routes are unaffected; **a refused request never reaches the upstream**; **authentication happens before the rate limiter**: a flood of bad credentials on a route with a limit of one
   spends no token, and a good credential is still admitted afterwards; `rate_key = "auth"` gives each identity its own bucket and a third identity is untouched; a key valid but not allowed is 403; WebSocket upgrades are
   authenticated and a refused upgrade takes no tunnel place; the same on `tls_listen`; the access log carries `identity` for authenticated requests, and the line of any other request is unchanged; the counters agree with what clients were told.
4. **Metrics**: `tests/metrics_bound_test.cho` keeps its offsets and the worst-case bound within a tenth; `tests/admin_test.py`'s key lists are updated to match.
5. **Mutants** of the new code (`tests/auth_mutants.py`, the pattern of `tests/ratelimit_mutants.py`): copy the tree, one edit, run the targeted tests; each killed or explained.
6. **Nothing else moves**: `tests/problem_test.cho` pins every existing refusal's bytes; the access-log test pins the lines without `identity`; the whole existing suite passes unchanged; `scripts/authority.py --check`
   reports no change in any label (the module is pure; it adds `std.crypto` functions, which have no effect).

## 11. Not built, recorded; and the design of the next slice

### 11.1 Small follow-ups

- Key expiry or a "not before" per key. A deployment can already stage a rotation by overlap (add the new key, deploy; move clients; remove the old key, deploy): both are valid at once because a deployment holds up to 64.
- `SIGHUP` could re-read a file of digests, as it already re-reads certificates (`docs/tls.md` section 11). It would add a second path to the authority row (a read of a keys file) and a second table that must be swapped
  without a request seeing half of it; both are reviewable, neither is needed to meet the requirement of this slice (the digests are in the binary). **Not built.** Until then **a key change needs a restart**, which
  drops the connections in flight; the shutdown on `SIGTERM` (`docs/tls.md`) is the clean way.
- Passing the identity to the upstream (`X-Auth-Identity: alice`, always removed from the client's request first, as `docs/headers.md` does for forwarding claims). Small, but it makes the upstream trust a header;
  decided when a first user wants it.
- Per-key rate and burst; per-key method and path rules.

### 11.2 JWT (next slice)

Not built; a design to review before any code.

| decision | choice | why |
|---|---|---|
| algorithms | **one, named per route** (`auth_alg = "EdDSA"` or `"HS256"`), never read from the token to pick the verifier. `none` is not an accepted value, and a token whose `alg` differs from the route's is `auth.malformed` | algorithm confusion (a public key used as an HMAC secret; `alg: none`) comes from letting the token choose |
| which first | **EdDSA (Ed25519)**, verifying with a public key, `std.ed25519.verify` | a public key is not a secret: it may be compiled into the binary, so the requirement of section 1 (no usable secret in the binary) holds without any file. HS256 needs the secret itself to verify |
| HS256 | the HMAC secret cannot be a digest: it is read at start (and on `SIGHUP`) through the same directory handle the certificates use (`docs/tls.md` section 3), a second `narrow`ed path, which **widens `authority.toml`** by one `fs_read` label: a reviewable edit, and the secret lives in the process memory | compiling the secret in would contradict section 1; reading it is the honest alternative and it is visible in the report |
| comparison | `std.hmac.sha256` over `header.payload`, compared with the same constant-time shape as section 4.2 | |
| structure | three segments of base64url without padding, separated by exactly two dots; each segment and the whole bounded (for example 2 KiB); a segment outside the alphabet, a padded one, a fourth segment, an empty one: `auth.malformed`. The JSON of the header and payload is parsed with `std.json` into a bounded structure, duplicate members refused | the smuggling lesson again: refuse what two parsers could read differently |
| claims | `exp` required (a token without expiry is refused), `nbf` honoured, `iat` not trusted, `aud` and `iss` compared to configured literals if configured; leeway a configured constant, at most 60 s; `crit` present: refuse | |
| the clock | the gateway has a monotonic clock plus the wall clock at start (`docs/observability.md` section 1). A wall-clock step (NTP) after start is **not** followed: a token near its expiry may be accepted or refused by that much. Stated, and a reason to keep leeway small | there is no cheaper source of time; re-reading the wall clock per request is possible (`clock_unix_ms`) and would follow steps, at the price of letting a jumped clock extend or cut tokens; to decide with the first user |
| identity | the `sub` claim (bounded to 32 bytes of the key-name alphabet, else `auth.malformed`), usable as `rate_key = "auth"` | one more reason the name is bounded now |
| revocation | none before `exp`; short lifetimes are the design | |

## 12. As built

*To be filled in when built.*
