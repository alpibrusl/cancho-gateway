# JWT bearer tokens (task #8, slice 2)

Status: **design, written before the code (2026-10-12).** Section 13 (as built) is added when the code is done. The gates in section 11 are fixed here and must be able to fail. A claim found false later is
corrected in place and marked *(corrected)*. Claims about cancho are about the pinned compiler (`cancho.toml`, `2fcf4cd`). This is the "next slice" that `docs/auth.md` section 11.2 sketched; where this document
differs from that sketch it says so in section 12, and `docs/auth.md` points here.

`docs/auth.md` fixed the rules this slice keeps: the binary must not contain a usable secret; a credential the gateway checks is removed before the request is forwarded (`docs/headers.md` section 2); authentication
comes before the rate limiter, the WebSocket checks and the dial; a refusal has a rule tag and says nothing about which check failed. This slice adds a second credential kind to the same step: **a signed JWT
(RFC 7519) in `Authorization: Bearer`, verified with an Ed25519 public key compiled into the binary.**

## 1. What cancho gives (measured, before any design)

| wanted | found | consequence |
|---|---|---|
| Ed25519 verification | **`std.ed25519.verify(pk, msg, sig)`** (RFC 8032 5.1.7), pure, no effect; rejects a non-canonical `S`, a malformed `A` or `R`, a wrong length. `msg` is hashed by streaming (`sha512_update`), so a message of any length is fine inside a region | the verifier is `std`'s; nothing is copied into the repository for it |
| speed of that verify | **about 4.6 ms** per verification (400 verifications of one signature inside `cancho test` took 1.8 s more than one; the same machine hashes a SHA-256 in microseconds). The module's own header says it is "correctness first": bit-serial reduction, not constant time | **a verification is the most expensive thing the gateway does for a request, 1,000 times a plain refusal.** The pipeline therefore checks everything that does not need the key before the signature (section 6), and section 9 states the denial-of-service ceiling it leaves |
| constant time | `std.ed25519` says it is **not** constant time. Verification handles only public data (a public key, a message and a signature the client sent); a timing difference reveals nothing secret | no claim of constant time is made for tokens; section 9 |
| HMAC, SHA-256 | `std.hmac`, `std.crypto.sha256` exist | not used: HS256 is not built (section 3) |
| base64url | none (`src/b64.cho` encodes standard base64 only) | a strict decoder is written here (section 4) |
| JSON | **`std.json`**: strict RFC 8259 parser into a **tape** the caller provides, no allocation of its own beyond two ints, depth at most 128, UTF-8 checked, `get` takes the *first* of duplicate keys | used for the syntax; the duplicate-key, nesting, size and type rules are enforced by `src/json_claims.cho` around it (section 5) |
| a clock | `clock_ms` (monotonic) and `clock_unix_ms` (wall), both read by the loop; the gateway keeps `ids[2]`, the wall-clock offset taken once at start, which the access log's timestamps already use | section 7 |
| randomness, a private key | none, by design | keys are made **outside** the gateway (section 8); the gateway only ever holds public keys |

## 2. Scope

**Built:** per route, JWT verification with `EdDSA` (Ed25519); keys by name in the deployment file as public keys (a bounded, compiled-in set, selected by `kid`); a bounded compact-JWS parser; a bounded JSON claim reader;
`exp` (required), `nbf`, `iss` and `aud` (configured per route), a bounded leeway; one external answer for every invalid token and a distinct rule tag in the log; the verifying key's name as the logged identity;
per-route counters of failures by kind; routes that accept API keys, JWTs or both; the generator's rules; a helper to make keys and tokens (`scripts/mkjwt.py`); tests, a differential and mutants.

**Not built, said once**

| not done | why |
|---|---|
| **HS256 and every other algorithm** | an HMAC verifier needs the secret itself: it cannot be a digest, so either the secret is in the binary (the requirement of `docs/auth.md` section 1 forbids it) or it is read from a file (a new `fs_read` path in the authority row). Neither is needed to deliver the slice, so neither is done (section 3) |
| JWKS fetching, key discovery (`jku`, `jwk`, `x5u`, `x5c` headers) | the gateway opens no connection it was not configured to; those headers are **ignored**, never followed and never trusted |
| key rotation without a restart | the public keys are compiled in; rotation is by overlap (several keys in the file, `kid` picks), which needs only a restart. A `SIGHUP` re-read of a key file would add a file read to the authority row, as `docs/auth.md` section 11.1 already said |
| revocation | none before `exp`; short lifetimes are the design (section 12) |
| JWE (encrypted tokens), nested JWTs, unsecured JWS (`alg: none`), detached or unencoded payloads (RFC 7797) | refused (sections 4 and 5) |
| claims-based authorisation beyond `aud` and `iss` (roles, scopes, `sub` allow-lists) | the unit of authorisation is the route |
| passing claims or the subject upstream | the gateway injects nothing for an upstream to trust (`docs/auth.md` section 8, last rows) |
| the `sub` claim as the logged identity, or as a rate-limit key | a subject is unbounded and chosen by the issuer: logging it needs a per-connection byte area that the slot table does not have, and keying a table of fixed size on it is the failure of section 10. See there |
| per-subject rate limits (`rate_key = "auth"` on a route that accepts JWTs) | refused by the generator, section 10 |

## 3. Algorithms

**One: `EdDSA` with Ed25519 (RFC 8037).** Each route has a fixed allow-list of one algorithm; the generator accepts `jwt_alg = "EdDSA"` or nothing, and refuses every other value (`none`, `HS256`, `RS256`, ... each with
its own message; the rule is `config.auth`). **The verifier is never chosen from the token**: the code path for `EdDSA` is the only path, and a token whose header `alg` is anything else, absent, not a string, or
`none` in any case is refused (`jwt.alg`). That is the whole of the algorithm-confusion defence, and it has no moving parts:

- *the classic attack*, an HS256 token signed with the RSA/EC/Ed25519 **public key as the HMAC secret**, is refused at the header: there is no HMAC code to run, so there is nothing to confuse. The test makes exactly that
  token with the deployment's public key as the secret (`tests/jwt_test.py`) and expects `jwt.alg`;
- *`alg: none`* is refused in every spelling (`none`, `None`, `NONE`) by the same comparison, which is exact and case-sensitive: `"EdDSA"` and nothing else. `"eddsa"` is refused as well. RFC 7518 3.1 and RFC 8037 3.1 both spell it `EdDSA`;
- *a key that is not an Ed25519 key* cannot be configured: the deployment's key is 32 bytes decoded from base64url, validated as a curve point of the prime-order subgroup's coset family and **not of small order**
  (the generator multiplies by 8; section 8). A small-order public key is the one way a signature verifies for every message, and the gateway never holds one.

**Why not HS256.** It was the second algorithm of the `docs/auth.md` sketch, with a stated price: the secret read at start through the certificate directory handle, a second narrowed path, **one more `fs_read` label in
`authority.toml`**, and the secret in process memory. That price is real (the authority row is the thing this gateway is for) and the benefit is a verifier for tokens that a *shared* secret signs, which is the weaker
design: whoever can verify can forge. EdDSA gives the same feature with a public key, **no secret in the binary or in memory, and no change to the authority report**. If a first user needs HS256, the widening is
reviewable then; it is not paid speculatively.

`std.ed25519` does not need any capability: `cancho authority` reports no new label (checked in section 13).

## 4. The compact JWS

A token is `BASE64URL(header) "." BASE64URL(payload) "." BASE64URL(signature)` (RFC 7515 7.1). The parsing rules, each one with a refusal tag and a test:

1. The credential is the token of `Authorization: Bearer <token>`, parsed by `docs/auth.md` section 3 (one header, `Bearer`, exactly one space), except that the credential may be up to **2,048 bytes** on a route that
   accepts JWTs (256 on one that does not). The `token68` alphabet of that section already includes `.`. Anything else is `auth.missing` / `auth.malformed` exactly as for API keys.
2. **Exactly two dots, three non-empty segments** (`jwt.malformed`): zero or one dot, three or more dots (a JWE has four), an empty segment, a leading or trailing dot.
3. **Alphabet**: each segment is `[A-Za-z0-9_-]` only. `=` (padding), `+` and `/` (the standard alphabet) are refused. RFC 7515 2 defines the encoding without padding; accepting padding or the other alphabet would be a second
   spelling of the same token.
4. **Canonical**: a segment's length modulo 4 must not be 1, and the unused low bits of its last character must be zero (so `AB` and `AC` do not both decode to the same byte). One spelling per byte string.
5. **Size**: the header segment at most 256 characters (192 bytes decoded); the payload segment at most 1,366 characters (1,024 bytes decoded); the signature segment **exactly 86 characters** (64 bytes). The whole token at most 2,048.
   Each limit is a compiled constant; decoding writes into region buffers of exactly those sizes.
6. **Header**: the decoded bytes are a JSON object (section 5). Members:
   - `alg`: required, a string, exactly `EdDSA` (section 3), else `jwt.alg`.
   - `crit`: **refused if present, with any value** (`jwt.header`). RFC 7515 4.1.11 says a recipient that does not understand an extension listed in `crit` must reject the token; this gateway understands none,
     and a present-but-empty or malformed `crit` is itself invalid, so "present" is the rule.
   - `typ`: optional. If present it must be the string `JWT`, compared without regard to case (RFC 7515 4.1.9 media type names are case-insensitive); anything else (`at+jwt`, `JOSE`, a number) is `jwt.header`. Absent is accepted:
     many issuers omit it, and the audience and issuer checks are what bind a token to a use.
   - `kid`: optional string of 1 to 32 bytes; its use is section 6 step 4.
   - `jku`, `jwk`, `x5u`, `x5c`, `x5t`, `cty`, any other member: **ignored**. They are never dereferenced and never used to choose a key. (`cty` would announce a nested token; the payload is then not JSON claims and fails section 5.)
   - A repeated member: `jwt.malformed` (section 5).
7. **The signature** is the 64 bytes of Ed25519 over the ASCII bytes `header_segment "." payload_segment` exactly as received (RFC 7515 5.1): the verifier is handed that slice of the credential, no re-encoding.
   `std.ed25519.verify` rejects a non-canonical `S`.

## 5. The JSON reader (`src/json_claims.cho`)

`std.json.parse` is strict (RFC 8259, UTF-8, no trailing data) and allocation-free into a tape; what it does not do is what a token needs, and `json_claims` adds exactly that, all bounded:

| rule | tag | why |
|---|---|---|
| the document is at most 192 (header) or 1,024 (payload) bytes before it is parsed | `jwt.malformed` | the tape is `3 * (bytes + 1)` ints, at most 24 KiB for the payload: under the region limit |
| the root is an **object** | `jwt.malformed` | a token whose payload is an array or a string has no claims |
| nesting at most **4** levels (the root is level 1): `{"aud":["a"],"x":{"y":[1]}}` is level 4 | `jwt.malformed` | `std.json` allows 128; a claim set has no use for it, and a bound the gateway chose is one that a unit test can hit. The scan is a byte loop that tracks string state, so brackets inside strings do not count |
| at most **64** members at the root, a name at most **64** bytes decoded | `jwt.malformed` | the duplicate check below is quadratic in the members; 64 is 2,016 comparisons of at most 64 bytes |
| **no repeated name** at the root, compared **decoded** (so `"exp"` and `"exp"` are the same name) | `jwt.malformed` | `std.json.get` returns the first of two; another parser returns the last; a token must not say two things (the smuggling lesson of `docs/framing.md`). Names inside nested values are not read by anyone and are not checked |
| `exp`, `nbf`, `iat` are **JSON integers**: `fits_int`, so `1.0`, `1e3`, `-0.5` and numbers wider than 64 bits are not integers, and in `0 .. 253402300799` (the year 9999, RFC 7519 2 NumericDate bound to the integers) | `jwt.claims` | no float is ever compared with a time. A bound makes every sum below overflow-free |
| `exp` present | `jwt.claims` | a token that never expires is refused, not defaulted |
| `iss`, if the route configures one, is a string equal to it (decoded compare); `aud`, if the route configures one, is a string equal to it **or an array of at most 16 strings** one of which is | `jwt.iss`, `jwt.aud` | RFC 7519 4.1.1, 4.1.3. An array holding a non-string, or more than 16 elements, is refused as `jwt.aud`; a missing claim is a mismatch. There is no pattern, prefix or case folding |

The payload is parsed **before** the signature (section 6): everything it says is only ever used to refuse, so a forged payload can make the gateway refuse a token it might otherwise have verified but never accept one.

## 6. The order of checks

`jwt.verify(credential, ...)` does, in this order, stopping at the first failure; the **signature is last** because it is a thousand times the cost of everything else together (section 1):

1. shape and sizes (section 4, rules 2 to 5);
2. decode and parse the header; `alg`, `crit`, `typ`;
3. **`kid` and the key**: the route has an allowed set of public keys (all of the deployment's, or those it names with `jwt_keys`). A `kid` must equal the **name** of one of them exactly (`jwt.kid` otherwise); no `kid`
   is accepted **only if the route's set has exactly one key**, because then there is nothing to choose (a set of several and no `kid` is `jwt.kid`: the gateway does not try each key in turn, which would be a
   verification per key for a client's one request). The `kid` selects among a bounded compiled-in set; it is compared as bytes and never used as a path, a URL or a lookup in anything else;
4. decode and parse the payload (section 5), then the claims: `exp`, `nbf`, `iss`, `aud` and the clock floor (section 7);
5. **the signature**, with the key step 3 chose.

The result is the key's index (success) or the refusal. Acceptance is the conjunction of every step: the claims read in step 4 are the bytes the signature in step 5 covers, so the order costs nothing in
security, and it means that an **expired token retried in a loop by a buggy client costs one JSON parse, not 4.6 ms**.

**What the order reveals, honestly.** The response is the same for every failure (section 9) but its *time* is not: a token that fails before step 5 is answered in about 100 microseconds, one that reaches the
signature in about 5 ms. A client can therefore learn, by timing, that a token passed shape, `alg`, `kid`, `exp`, `nbf`, `iss` and `aud`. That tells a client nothing it did not choose, apart from the configured
`kid` names, `iss` and `aud` literals; **they are not secrets** (they are public identifiers in any token the issuer makes, and the log shows them) and the deployment file must not use them as such.

## 7. The clock, and what it can and cannot do

**Wall time at a request** is `(now_ms + ids[2]) / 1000` in whole seconds, integers throughout: `now_ms` is the loop's monotonic clock reading (`clock_ms`), `ids[2]` is `clock_unix_ms - clock_ms` read **once, at
start** (`docs/observability.md` section 2: the same offset that dates every access-log line). The reading is whole seconds with the milliseconds truncated: a token with `exp = T` is valid up to and including the
second before `T`.

Checks, with `L` the route's `jwt_leeway` in seconds (0 to 60, default **0**; the generator refuses more, and a unit test pins 60 and 61):

| claim | valid when | tag when not |
|---|---|---|
| `exp` | `now < exp + L` | `jwt.expired` (RFC 7519 4.1.4: "current date/time MUST be before the expiration"; leeway only ever *extends* it) |
| `nbf` | absent, or `now + L >= nbf` | `jwt.nbf` (RFC 7519 4.1.5: "after or equal to") |
| `iat` | absent, or an integer in range | `jwt.claims` only if not an integer. **`iat` is not trusted and not compared**: an issuer's clock is the issuer's. A token's age is bounded by `exp`; a deployment that wants a maximum lifetime makes the issuer sign short ones |
| the floor | `now >= clock_floor()` | `jwt.clock`: **every** token is refused |

**The floor.** The monotonic clock cannot step, but `ids[2]` is the wall clock *as read at start*. A host without a battery-backed clock that starts before time sync (an embedded charger, a VM from a snapshot) reads
1970 or a stale date; with that offset **every token whose `exp` is in the future of the wrong date would be valid, including tokens that expired years ago**. That is a fail-*open* error of the worst kind, so the
code compiles in `clock_floor()`, a date no earlier than the build (1,790,000,000 s, 2026-09-21) and refuses every token (`jwt.clock`, 401, counted) while the clock reads before it. The floor is a constant in
`src/jwt.cho` that a release raises; it is not read from the build machine's clock because the generated files must be reproducible (`generate.py --check`). It cannot detect a clock that is wrong but later than the
floor: nothing in the gateway can.

**What is not followed.** A step of the wall clock *after start* (NTP stepping, an operator setting the date) is not followed: the gateway keeps its start-time offset. Linux `CLOCK_MONOTONIC` stops counting while
a machine is suspended, so a suspended-and-resumed host's gateway runs behind real time by the suspension, and a token near its expiry is accepted that much too long. Between steps the monotonic clock is slewed by
NTP like the wall clock (at most 500 ppm, 43 seconds a day). So **the gateway's idea of "now" is the real time within the error of the host's clock at start, plus the host's clock drift since**, and can be
worse after a suspend. That is a reason to keep `jwt_leeway` small and token lifetimes minutes, not days; it is not a reason to re-read the wall clock per request: that would follow the host's steps in both
directions, and a clock that jumps backwards would extend every token. A restart re-reads it. The alternative is stated and not taken; it can be decided with a first user.

**Tested without sleeping.** The claim checks are pure functions of `now`, so `tests/jwt_test.cho` tests every boundary (`exp = now - L + 1`, `exp = now - L`, `nbf = now + L`, `nbf = now + L + 1`, `L = 0` and `L = 60`)
exactly. The end-to-end test cannot inject a clock into the built gateway, so it tests with margins of at least 3 seconds either side of the leeway; its sleep-free design is the reason no test waits for a token to expire.

## 8. Keys, the deployment file and the generator

    [[jwt_key]]
    name = "issuer-a"                       # [a-z0-9][a-z0-9._-]{0,31}: the key id (`kid`) and what the access log calls the caller
    public_key = "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"   # Ed25519 public key, 32 bytes, base64url without padding (RFC 8037's JWK "x")

    [[route]]
    name = "api"
    path_prefix = "/api"
    upstream = "api"
    auth = "jwt"                            # "api-key" (default kind of slice 1), "jwt", or ["api-key", "jwt"]
    jwt_alg = "EdDSA"                       # optional; the only value accepted
    jwt_keys = ["issuer-a"]                 # default: every [[jwt_key]]
    jwt_aud = "https://api.example.com"     # optional: the token's aud must be it (string, or one element of an array)
    jwt_iss = "https://issuer.example.com"  # optional: the token's iss must be it
    jwt_leeway = 5                          # seconds, 0 to 60, default 0
    auth_forward = false                    # as in slice 1: the Authorization header is removed before the upstream sees it

The public key is **not a secret**: it may be in the deployment file, in the repository and in the binary. `scripts/mkjwt.py` (section 14) makes a key pair and signs test tokens; it never writes a private key to disk by
default.

Refusals, all `config.auth` with the key and the line, each with one test in `tests/generate_test.py` (numbering continues `docs/auth.md` section 6, whose rules 6, 7, 11 and 12 are generalised as noted):

| # | rule |
|---|---|
| 17 | a `[[jwt_key]]` name that is missing or not `[a-z0-9][a-z0-9._-]{0,31}`; two `[[jwt_key]]` with one name; **a name that is also an `[[api_key]]` name** (the access log's `identity` is the name and must say which kind) |
| 18 | `public_key` that is not exactly 43 characters of `[A-Za-z0-9_-]` that decode canonically to 32 bytes (no padding, no standard alphabet, trailing bits zero) |
| 19 | `public_key` that is not a point on the curve, or is a point of **small order** (the eight points of order 1, 2, 4, 8; the generator computes `8 * A` and refuses the identity). A small-order key verifies a signature for *every* message |
| 20 | two keys with the same `public_key` (one verifier, two identities) |
| 21 | more than **8** `[[jwt_key]]` |
| 22 | `auth` that is not `"api-key"`, `"jwt"` or a non-empty list of distinct values of those two *(rule 6, generalised)* |
| 23 | `jwt_alg`, `jwt_keys`, `jwt_aud`, `jwt_iss` or `jwt_leeway` on a route whose `auth` has no `jwt`; or `auth_keys` on a route whose `auth` has no `api-key` *(rule 7, generalised)* |
| 24 | `jwt_alg` that is not the string `"EdDSA"`: `none`, `HS256`, `RS256`, `eddsa`, a non-string. Each is refused with its own message; HS256's says why (section 3) |
| 25 | `jwt_keys` that is not a non-empty list of distinct declared `[[jwt_key]]` names |
| 26 | `jwt_aud` or `jwt_iss` that is not a string of 1 to 96 bytes of printable ASCII (0x20 to 0x7e) without `"` and `\` |
| 27 | `jwt_leeway` that is not an integer from 0 to 60 (a float, a string, a boolean, 61, -1) |
| 28 | `[[jwt_key]]` and no route that accepts `jwt` (keys that protect nothing); a route that accepts `jwt` and no `[[jwt_key]]` (a route nobody can enter) *(rules 11 and 12, for JWTs)* |
| 29 | `auth_header` on a route that accepts `jwt`, unless it is `Authorization` (a JWT is a Bearer token; the challenge says so) |
| 30 | `rate_key = "auth"` on a route that accepts `jwt` (`config.ratelimit`, section 10) |

The plain-listener rule (13) and its flag apply to a route that accepts `jwt` exactly as to one that accepts API keys: a bearer token crossing a plain port can be replayed by anyone on the path until it expires.
The rule that `auth_forward` must be a boolean (10) is unchanged.

**How a key is checked, in Python, in the generator.** Decoding is strict (43 characters, canonical, so `decode(encode(x)) == x` is a test of the generator itself). The point check is RFC 8032 5.1.3 (decode `y`, `y < p`,
recover `x`, no square root means refusal) followed by `8 * A == identity` as the small-order test. The compiled form is one line per key, `name<TAB>43 characters`, in `generated/routes.cho` (`jwt_keys_blob()`); the
gateway decodes it with the same strict decoder as the token's segments, so a damaged table fails closed (a key that does not decode verifies nothing).

## 9. The refusal: one answer, many log tags

A token's content failing is always:

    HTTP/1.1 401 Unauthorized
    Content-Type: application/problem+json
    WWW-Authenticate: Bearer realm="cancho-gateway", error="invalid_token"
    ...
    {"type":"about:blank","title":"Unauthorized","status":401,"rule":"auth.invalid","request_id":"..."}

the **same bytes** (but for the request id) whichever check failed: shape, `alg`, `kid`, claims, audience, issuer, expiry, clock or signature. RFC 6750 3.1 gives `invalid_token` for "expired, revoked, malformed, or invalid"; nothing
finer is said to the client, so the response is not an oracle for which `kid`s exist or which audience is configured. Absent and badly-framed *headers* keep their slice-1 answers (`auth.missing`; `auth.malformed` with
`invalid_request`): they describe the HTTP request, not the token. The same answer for every token failure is a gate (an end-to-end test compares the bytes of fourteen causes).

The **log** and the **counters** are where the cause lives (the log is the operator's, the response is the attacker's). The access log's `rule` of a refused token is one of:

| log `rule` | counter `kind` | cause |
|---|---|---|
| `jwt.malformed` | `malformed` | shape, dots, alphabet, padding, non-canonical encoding, a size cap, JSON syntax, the root not an object, nesting, a repeated name, more than 64 members |
| `jwt.alg` | `alg` | `alg` absent, not a string, `none`, `HS256`, or anything but `EdDSA` |
| `jwt.header` | `header` | `crit` present, `typ` not `JWT` |
| `jwt.kid` | `kid` | a `kid` that names no key of the route's set, a `kid` that is not a string of 1 to 32 bytes, or no `kid` on a route with several keys |
| `jwt.claims` | `claims` | `exp` missing, `exp`, `nbf` or `iat` not an integer or out of range |
| `jwt.expired` | `expired` | `now >= exp + leeway` |
| `jwt.nbf` | `not_yet_valid` | `now + leeway < nbf` |
| `jwt.aud` | `audience` | the configured `aud` is not the token's |
| `jwt.iss` | `issuer` | the configured `iss` is not the token's |
| `jwt.clock` | `clock` | the gateway's clock reads before `clock_floor()` |
| `jwt.signature` | `signature` | the signature does not verify (including a `kid`-selected key that cannot be decoded) |

Because the signature is checked last (section 6), the tags other than `jwt.signature` describe **what the unverified token claimed**: a forged token with a past `exp` is logged `jwt.expired`. An operator reading
`jwt.expired` is therefore reading "someone sent an expired token", which is the diagnostic they want, and not "an authentic token expired". The counters are per route (`jwt_refused` in the metrics, section 12) and
sum with the existing `auth_refused` counters for slice 1's `missing` and `malformed` (the *header* causes), which are unchanged.

**Pipeline** (`docs/auth.md` section 7.1): the same step, after routing and before the WebSocket state, the body, the rate limiter and the dial, plain or TLS, an upgrade request or not. A request refused here consumes
no token of any bucket and does not touch an upstream. The refusal's log line has `outcome` and the route as any refusal does.

**What a flood costs.** A request refused at steps 1 to 4 costs one parse (tens of microseconds). A request that reaches the signature costs about 5 ms, and **the loop is single-threaded**: an unauthenticated client that
sends tokens of valid shape with a configured `kid`, a future `exp` and the right `aud` and `iss` (all of which it can write) makes the gateway verify at about 200 requests a second and starves every other connection.
That is the price of using `std.ed25519`, which this repository does not own and whose speed is measured (section 13) and not improved here. The checks that come first make *accidental* load (expired tokens,
wrong audiences, clients that retry) cheap; **they do not stop a deliberate flood of well-formed tokens**. The things that bound it are outside the gateway (a limit on connections or requests per second
in front of it: the peer address is not available to the gateway, `docs/headers.md` section 1) and the counters: `jwt_refused{kind="signature"}` growing faster than anything else *is* the alarm. This is stated, not
hidden; it is also the first reason the signature cost should be reduced upstream in cancho, or a verification budget added, if a deployment faces the internet with tokens on an unprotected port.

## 10. Identity, and `rate_key = "auth"`

**Logged identity.** For a verified token the access log's `identity` is the **name of the verifying key** (`issuer-a`): the issuer, not the subject. Names are unique across `[[api_key]]` and `[[jwt_key]]` (rule 17),
so `identity` says what kind of credential it was without a prefix. A request that did not authenticate carries no `identity` (as in slice 1). The `sub` claim is **not** logged and **not** read: it is unbounded
(an issuer may put anything of any length in it), it would need a byte area per connection that the slot table does not have, and it is the issuer's text, which a log line should not carry without an escaping rule
for each reader of the log. A first user who needs per-subject logs can have a bounded `sub` logged (section 12).

**`rate_key = "auth"` on a route that accepts JWTs is refused by the generator (rule 30).** The slice 1 rule that makes `rate_key = "auth"` safe is that the identities are **compiled-in names**, so the generator can prove that
the rate table (sets of four buckets) never has to refuse one (`docs/auth.md` section 9). For tokens the natural identity is `sub`, which is neither bounded nor known:

- *hash the subject into the table, like a header key:* then a client with a valid token can still not make new buckets (it cannot change its `sub`), but **the issuer's subjects fill the table**: more distinct
  subjects than buckets and a legitimate subject is answered `limit.rate-table`, which is exactly what slice 1 proved impossible and made a generator rule for. The failure would be a function of the *issuer's*
  user count, not of the deployment file;
- *key on the verifying key's name:* it is bounded and known, but it limits **all holders of one issuer's tokens together**, which is a route-wide rate limit under another name and surprising under the name "auth";
- *refuse:* a route that needs a rate limit uses `rate_key = "xff:last"` or a header key, or the route's own bucket (`rate_key = "route"`); authentication has already happened before the limiter either way.

The generator refuses (the third). The failure mode of not refusing would have been `limit.rate-table` for authentic callers; the refusal turns a latent run-time failure into a line-numbered configuration error. A
route that accepts `["api-key", "jwt"]` is also refused for `rate_key = "auth"`, since half of its callers would have no bounded identity. This is a decision to revisit if a user needs per-subject limits; the
design then is a bounded `sub` (1 to 32 bytes of the key-name alphabet, else `jwt.claims`) hashed into a *separate* table whose full state is a per-route counter, not an authentication failure.

## 11. Gates, fixed before the code

Each must be able to fail, with a mutant shown failing it (section 13 records them).

1. **The parser and the claims, a unit test** (`tests/jwt_test.cho`, `[[test]] jwt`): base64url against `base64.urlsafe_b64decode` for every length from 0 to 130 and for hostile input (padding, `+`, `/`, `-_`, a length of 1 mod 4, non-zero trailing
   bits, a byte above 0x7f, 0x00); the JSON reader against every row of section 5 (duplicates plain and escaped, nesting at 4 and 5, 64 and 65 members, a 64 and a 65 byte name, a float `exp`, `1e3`, `-0`, a 20-digit
   integer, `exp` at 0 and at 253402300799 and one above, an array `aud` of 16 and 17 and with a number in it, an empty document, a document of one million `[`); the claim checks at every boundary of section 7; the
   RFC 8037 Appendix A.4 / A.5 vectors (an Ed25519 key and the signature of the JWS `eyJhbGciOiJFZERTQSJ9.RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmc`) and the Wycheproof-style cases `std.ed25519` already carries (we do not repeat them);
   the extremes: a credential of 0, 1, 2,047, 2,048 and 2,049 bytes, 10,000 bytes, every byte value, never a panic.
2. **The generator** (`tests/generate_test.py`): each of rules 17 to 30 one refusal test with the key and a line; the accepted forms; the generated tables; the counts of that file updated.
3. **End to end** (`tests/jwt_test.py`: the built gateway, a recording upstream, tokens made in memory): a valid token passes **and the credential is not in what the upstream recorded**; `auth_forward = true` keeps it;
   fourteen causes (expired, not yet valid, wrong audience, wrong issuer, wrong signature, `alg: none`, `alg` mismatch with the HS256-signed-with-the-public-key token, tampered payload, duplicate claims,
   oversize, malformed base64url, wrong segment count, missing `exp`, unknown `kid`) each refused with **401 and a byte-identical external response but for the request id**, the right tag in the log and the right counter;
   a token valid on one route refused on another route that has a different `aud`; leeway margins; unauthenticated routes unaffected; **authentication before the rate limiter**; WebSocket upgrades; TLS; a route
   that accepts both kinds, with the shape rule of section 12.1 tested in both directions; the access log's `identity`; counters agree with what clients were told.
4. **Metrics**: `tests/metrics_bound_test.cho` keeps the worst case within a tenth of the largest answer; `tests/admin_test.py`'s key lists are updated.
5. **Differential**: tokens signed by an independent implementation (Python `cryptography`, OpenSSL) accepted, their corruptions refused, over a fuzzed corpus; and the RFC vectors.
6. **Mutants** of the new code, each in a copy of the tree, killed or argued (section 13).
7. **Nothing else moves**: `tests/problem_test.cho`, the access-log test and the whole existing suite unchanged but where section 13 lists a change; `scripts/authority.py --check` reports no change in any label.

## 12. Two kinds on one route, and the decisions that differ from `docs/auth.md` 11.2

### 12.1 `auth = ["api-key", "jwt"]`

Both kinds read the **same** credential: `Authorization: Bearer <credential>` (rule 29). The route decides **once, from the shape of the credential, which verifier runs, and the other never runs**:

| the credential | verifier | on failure |
|---|---|---|
| contains **exactly two `.`** | JWT (section 6) | the token's refusal (section 9), 401 |
| anything else | API key (`docs/auth.md` section 4), at most 256 bytes (longer is `auth.malformed`) | the key's refusal (slice 1) |

There is **no fallback**: a credential with two dots that fails as a JWT is **not** then looked up as an API key, and one without is never parsed as a JWT. That removes the downgrade: an attacker cannot make a token
that fails verification be accepted as a key, nor make the gateway try the cheaper check after the stronger one failed. The price: **an API key containing two dots cannot be used on a route that accepts JWTs**.
`scripts/mkkey.py` keys (`ck_` and 43 characters of base64url) contain none, and the generator cannot know a digest's preimage, so `docs/auth.md` section 3's advice (keys come from the tool) is now a requirement, and the doc says so there.
On a route that accepts only `api-key` nothing changes (a dot is in the `token68` alphabet); on a route that accepts only `jwt`, a credential that is not of JWT shape is `jwt.malformed`.

Order of errors for the header: absent (`auth.missing`), twice or another scheme (`auth.malformed`) are decided **before** the shape, as in slice 1, since they are about the request.

### 12.2 What this document decided differently from `docs/auth.md` 11.2 *(corrected there, in place)*

| `docs/auth.md` 11.2 said | decided here | why |
|---|---|---|
| `auth_alg = "EdDSA"` or `"HS256"` per route | `jwt_alg`, **only `"EdDSA"`** | HS256 widens the authority row for a weaker design (section 3) |
| a token whose `alg` differs from the route's is `auth.malformed` | **`jwt.alg` in the log, and the external answer is `auth.invalid` / `invalid_token`** like every token failure | RFC 6750 and "nothing leaks": a client must not learn which header member was wrong (section 9). `auth.malformed` remains for the HTTP header |
| one `exp` check "required" | required, **integer only**, in a bound, with the floor of section 7 | no floats; the floor closes the fail-open clock |
| identity = `sub` bounded to 32 bytes of the key-name alphabet, usable as `rate_key = "auth"` | **identity = the verifying key's name; `rate_key = "auth"` refused for JWT routes** | the table-sizing rule of slice 1 does not hold for unbounded subjects (section 10) |
| structure bounded "for example 2 KiB" | exact caps (section 4), strict canonical base64url, JSON through `std.json` plus the rules of section 5 | |
| clock "to decide with the first user" | decided: start-time offset plus the floor; the per-request wall clock is the alternative, not taken (section 7) | |
| revocation "none before exp" | unchanged | |

### 12.3 What a later slice would do

- a bounded `sub` as a second log key (`subject`), the issuer's text escaped by the existing JSON escaper and capped at 32 bytes, held in the slot's meta area;
- `jwt_max_age` using `iat` (a maximum token lifetime enforced by the gateway rather than trusted from `exp`);
- a second algorithm, if a user needs one, as a separate reviewable widening;
- a verification budget (a token bucket of verifications per second, global) as a bound on section 9's flood, at the price of letting a flood deny legitimate tokens;
- `SIGHUP` re-read of keys.

## 13. As built

*(written after the code)*
