# Rate limiting (task #9)

Status: **design, written before the code (2026-10-12); section 12 is filled in as the code lands.** The gates in section 10 are fixed here
and must be able to fail. A claim found false later is corrected in place and marked *(corrected)*. Claims about cancho are about the pinned
compiler (`cancho.toml`, `2fcf4cd`).

`docs/design.md` section 4 reserved a row for this, "rate-limit keys, 65,536, policy in #9, 429", and `docs/proxy.md` listed "rate limits (#9)"
among what was not built. This document is the policy. Its first job is to say what a limiter built **without the client's address** can and
cannot do, because that decides every other choice.

## 1. What cancho gives and does not give (measured, before any design)

| wanted | found | consequence |
|---|---|---|
| the client's address, to limit per client IP | **not available.** `conn_peer` is not built (`docs/headers.md` section 1: `grep conn_peer` over `std/` and the builtins at the pinned commit, no match). The gateway does not know who connected | **a per-IP limit is impossible**, not merely unbuilt. Nothing here emulates it. When `conn_peer` exists, `rate_key = "peer"` is the natural addition and the table, the arithmetic and the refusal below are unchanged: only `key_of` gains a case |
| the TLS server name, as a key | not available as a *client identity*: the engine picks an identity by SNI (`docs/tls.md`) and the gateway keeps the identity's index, not the name; and an SNI is chosen by the client, so it is worth no more than any other header | not offered |
| a clock | present. The loop reads `clock_ms` once a turn and keeps it in `ids[3]`, the monotonic clock of the turn; `head_ready` already receives it as `now` | the limiter reads **no clock of its own** and adds no effect: it is a pure module like `route` and `metrics`. The authority report does not change |
| 64-bit integers that trap on overflow | measured in `docs/design.md`'s probes and in every module since: an overflowing `+` or `*` traps (the process dies) | every product in section 5 is bounded by a stated constant, and the unit test runs the extremes |
| randomness | none beyond the TLS seed (`docs/headers.md` section 1) | the hash is **not secret** (section 6 says what that allows an attacker) |

## 2. Scope

**Built in this task:** one limiter per route, a token bucket; its key is the whole route or the value of a request header (including the last or
first element of `X-Forwarded-For` on a route that believes forwarding claims); a fixed table of buckets sized at start; a refusal
`429` as `application/problem+json` with `Retry-After`; counters; keys in the deployment file; generator rules; tests; mutants.

**Not in this task, said once**

| not done | why |
|---|---|
| a limit per client address | impossible (section 1) |
| a route-wide ceiling *above* per-key buckets (two limits on one route) | would close the rotation evasion of section 3.3, at the price of a second table and a second refusal rule. A header key rotated per request is unprotected until it exists (section 3.3). Recorded in section 11 as the first follow-up |
| limits on bytes, on connection rate, on concurrent requests | this limits **requests started**, one token each |
| a shared limit across several gateways | one process, one table |
| a limit on the admin listener | it is bounded already (`docs/observability.md` section 7) |
| limiting responses, or a global limit across routes | per route only: a deployment that wants a global limit puts the same upstream behind one route |
| IPv6 prefix aggregation of an `X-Forwarded-For` key | the key is the text of the element (section 3.3) |

## 3. The key

A bucket belongs to a *key*; two requests with the same key spend the same tokens. The candidates, and what was decided:

| `rate_key` | the bucket is | needs | decision |
|---|---|---|---|
| `"route"` (default) | one for the whole route: every request to it | nothing | **built.** The only key a client cannot choose |
| `"header:<Name>"` | one per distinct value of that request header (an API key, a tenant id, an `Authorization`) | a header name (a token of at most 64 bytes; not a hop-by-hop or framing header: section 4) | **built** |
| `"xff:last"` | one per distinct last element of the last `X-Forwarded-For` header: the address the party in front of the gateway appended | `trust_forwarded = true` on the route | **built** |
| `"xff:first"` | one per distinct first element of the first `X-Forwarded-For` header: the address the *originating* client claimed | `trust_forwarded = true` | **built**, with the warning of 3.3 |
| `"peer"` | one per client address | `conn_peer` | **impossible** (section 1) |
| the TLS server name | one per SNI | the name | **not offered** (section 1) |

`xff:*` and a `header:` key naming a forwarding claim (`Forwarded`, `X-Forwarded-*`, `X-Real-IP`) are refused unless the route sets
`trust_forwarded = true` (`docs/headers.md` section 2): on an untrusted route those headers are *removed* before the upstream sees them, and a
limit keyed on a claim the gateway itself declines to believe is a limit the client sets for itself.

### 3.1 A request without its key

When the key is a header: **a request with no such header, with an empty value, with the header twice or more (for `header:` keys), or with an
empty `X-Forwarded-For` element, shares one bucket, "the absent bucket", with every other such request** (it is the bucket of the empty key; the
table has no other special case). It is limited like any key, at the route's rate and burst.

Why this and not the two alternatives:

- *Admit it unlimited* is a hole the size of the feature: omitting the header would be the way to switch the limit off.
- *Refuse it (400)* turns a limiter into an authentication rule it was not asked to be and breaks health checks that carry no key.
- *The shared bucket* fails towards **limiting**: the worst it does to a legitimate client without a key is share a budget with the other clients without one, which is
  visible (a 429 with a rule and a counter) and fixable (give them a key, or put them on a route of their own).
- A header sent **twice** is ambiguous between the gateway and the upstream (which one does the upstream read?). Keying on either would let a client
  rotate the one the gateway reads while the upstream reads the other. It is the absent bucket instead.

For `key = "route"` there is exactly one key, so every request is in the one bucket.

### 3.2 What is not protected, plainly

- **A single abusive client behind no distinguishing header.** With `route` it is indistinguishable from everyone else: it can spend the whole budget and the legitimate
  clients get the 429s. A route-wide limit protects the **upstream**, not the other clients.
- **Many connections from one host** cannot be told apart from many hosts. Without `conn_peer` there is nothing to tell them apart by except what the client sends.
- **Anything before the route is known**: a head that fails framing (`framing.*`), a request with no route (`route.*`), a connection that never finishes its head. Those are refused
  cheaply by their own rules and spend no token. Flooding them is not stopped here (`limit.connections`, the header deadline and the 256 slots are what bound it).
- **A refused client still costs a slot for up to three seconds** (`docs/proxy.md` section 3: a refusal is read and discarded until the client has been quiet for 500 ms). Limiting protects the
  upstream; it does not make the refusal path free. A flood of limited requests can still fill the slot table and be answered by `limit.connections` or a closed socket.
- **Bytes and duration**: one request is one token, a 10 GiB upload and a `GET` cost the same, and a slow response holds its slot as before.
- **WebSocket traffic after the upgrade.** The upgrade is one request, one token; the frames in the tunnel are not requests (section 7).

### 3.3 What an attacker can do to each key, and what remains

| key | evasion | what stays true |
|---|---|---|
| `route` | none: the client chooses nothing | one client can exhaust the shared budget (3.2). The limit is a ceiling for the upstream |
| `header:<Name>` | **rotate the value per request**: each new value is a fresh bucket with a full burst. Unless something in front of the gateway or behind it validates the header, this is the end of the protection | it is a limit **per credential**, useful when the credential is checked (by the upstream, which answers `401` to a forged key without doing the real work, or by a front that signs it). A client that omits the header, repeats it or sends it empty lands in the shared absent bucket (3.1). A client that knows another client's value can spend that client's budget (inherent to any shared-secret key) |
| `xff:last` | none from the client **if the gateway is reachable only through the front** and the front *appends* the peer it saw: the last element is the front's observation, not the client's claim. A client that reaches the gateway directly (a port that is not firewalled) writes any element it likes | the left of the list is the client's; only the right is the front's. With two trusted fronts in a chain, the last element is the first front's address, not the client's |
| `xff:first` | **prepend**: if the front appends instead of replacing, the first element is whatever the client sent. Only sound where the front *replaces* the header with the one address it saw | a route that sets it believes the client's own claim in the one deployment shape where the claim is true |
| both `xff:*` | an IPv6 client rotates inside its /64 (2^64 distinct texts); the text of the element is the key, `::1` and `0:0:0:0:0:0:0:1` are two keys | no address parsing or prefix aggregation is done (section 2) |
| any | **fill the table with junk keys** so that new keys are refused (section 6.4): a denial of service to *new* keys of the same route, at a cost of about one request per bucket per refill window. Existing keys keep their buckets | it is a failure of availability for new keys, never of the upstream: nothing reaches the upstream that was not admitted |

The honest summary: **`route` is a hard ceiling on one route; `header:` and `xff:` are fairness between keys, only as strong as the key.** Neither stops a hostile client
that controls its key, which is why `route` is the default and why the header forms say what they trust.

## 4. Deployment keys

Per route, in the deployment file (`scripts/generate.py`; refusal tag `config.ratelimit`, one rule each, one test each):

    [[route]]
    name = "api"
    path_prefix = "/api"
    upstream = "api"
    rate_limit = "100/s"          # tokens added per period: "<N>/s", "<N>/m" or "<N>/h"
    rate_burst = 200              # the bucket's size: requests admitted at once after an idle time (default: N)
    rate_key = "header:X-Api-Key" # "route" (default), "header:<Name>", "xff:last", "xff:first"
    rate_buckets = 4096           # the table's size for this route (default 1024; not with "route")

| key | value | default |
|---|---|---|
| `rate_limit` | a string `N/s`, `N/m` or `N/h`; `N` an integer in 1..1,000,000 with no sign, space or leading zero | none: the route is not limited |
| `rate_burst` | an integer in 1..1,000,000 | `N` |
| `rate_key` | `route`, `xff:last`, `xff:first`, or `header:` and a name | `route` |
| `rate_buckets` | an integer, a multiple of 4, in 4..65,536 | 1024 (a `route` key has one bucket and takes no `rate_buckets`) |

The refusals, each `config.ratelimit` with the key and the line of the file:

| # | rule |
|---|---|
| 1 | `rate_limit` is not `N/s`, `N/m` or `N/h` with `N` in 1..1,000,000 |
| 2 | `rate_burst`, `rate_key` or `rate_buckets` without `rate_limit` on the same route |
| 3 | `rate_burst` is not an integer in 1..1,000,000 |
| 4 | `rate_key` is not `route`, `xff:last`, `xff:first` or `header:<Name>`, or the name is not a token of 1 to 64 bytes |
| 5 | the name is one the gateway removes or owns: `Connection`, `Keep-Alive`, `Proxy-Connection`, `Proxy-Authorization`, `TE`, `Trailer`, `Upgrade` (hop-by-hop), `Content-Length`, `Transfer-Encoding`, `Host` (framing and routing) |
| 6 | `xff:last`, `xff:first`, or a `header:` key naming `Forwarded`, `X-Forwarded-For`, `X-Forwarded-Host`, `X-Forwarded-Proto`, `X-Forwarded-Port` or `X-Real-IP`, without `trust_forwarded = true` |
| 7 | `rate_buckets` with `rate_key = "route"`, or not an integer that is a multiple of 4 in 4..65,536 |
| 8 | the routes' buckets add up to more than 65,536 (`route` keys count one each) |

The totals fix the memory: at most **65,536 buckets of three 8-byte integers: 1.5 MiB**, allocated once at start (`design.md` section 4's row). The names are
lowercased when generated (`generated/routes.cho` carries them), so `header:X-API-Key` and `x-api-key` are one key.

## 5. The bucket (integer arithmetic only, no trap reachable)

A token bucket measured in **units**: one token is `P` units, where `P` is the period in milliseconds (1,000, 60,000 or 3,600,000). The bucket gains `N` units
per millisecond (so `N` tokens per period, exactly, with no fraction lost: `N` units per ms times `P` ms is `N * P` units, `N` tokens) and holds at most
`burst * P` units. A request costs `P` units.

    gained  = N * min(elapsed, 2_592_000_000)          elapsed = now - last, at least 0
    units   = min(units + gained, burst * P)
    admit   : units >= P  ->  units - P
    refuse  : units <  P  ->  retry = ceil(ceil((P - units) / N) / 1000) seconds, at least 1

**Every product is bounded by a constant**, so the largest value any expression takes is known:

| expression | bound | largest |
|---|---|---|
| `N * min(elapsed, 30 days in ms)` | N <= 1,000,000, elapsed <= 2,592,000,000 | 2.6 x 10^15 |
| `burst * P` | burst <= 1,000,000, P <= 3,600,000 | 3.6 x 10^12 |
| `units + gained` | the sum of the two lines above | < 2.7 x 10^15 |
| `(P - units) + N - 1` | <= 3,600,000 + 1,000,000 | 4.6 x 10^6 |
| the hash products (section 6) | a state below 2^31 times a multiplier below 2^16 | 2^47 |

(The 64-bit signed limit is 9.2 x 10^18.) The clamp on `elapsed` is the only place a huge reading is cut: a clock reading is trusted for 30 days of refill at most. For the
rates the generator allows a bucket from empty to full takes at most `burst * P / N`, which a clamp of 30 days cuts only for a burst above 720 tokens at 1 per hour or an
equivalent; the cut then refills less than the true amount, towards **limiting**.

**The clock.** `now` is the loop's monotonic millisecond. It cannot go backwards; the code does not trust that. If `now < last` the elapsed time is **0** (no tokens are
gained) and `last` is set to `now` (re-anchored, so that a clock that jumped back is not waited for: the bucket refills from the new time on). If `now == last` nothing is gained
and the bucket only spends. A clock that stops makes the limiter a counter of the burst, never a source of free tokens.

**`Retry-After`** is an integer number of seconds, **rounded up** from the milliseconds until the bucket holds a whole token, and **at least 1**: a `0` invites an immediate retry that fails
again, and the header's grammar (RFC 9110 10.2.3) is whole seconds. A client that waits that long and sends one request, with no other request of its key in between, is admitted: the test
sleeps exactly that and checks it. The largest value is 3,600 (a `1/h` limit with an empty bucket). For `limit.rate-table` (6.4) it is the seconds until the soonest of the four candidate
buckets is full, at least 1 and at most 86,400.

## 6. The table

### 6.1 Layout and size

One `Box[[int]]` in `Core`, sized at start: three ints per bucket, **`fingerprint`, `units`, `last`**, for `total_buckets` buckets (all the routes' tables one after the other; each
route has a generated `base`, so a route's table is `[base, base + buckets)`). A fingerprint of 0 is an empty bucket. A table is a sequence of **sets of four** buckets (a `route` key's table is one set of one).
Nothing is allocated afterwards: a request neither grows nor shrinks anything.

### 6.2 The key's hash

Two polynomial hashes of the key's bytes, each kept below 2^31, over different primes:

    h1 = (h1 * 48271 + byte + 1) mod 2147483647     h2 = (h2 * 16807 + byte + 1) mod 2147483629
    fingerprint = h1 * 2^31 + h2 + 1                (a 62-bit number, never 0)      set = ((h1 + h2) mod 2147483647) mod number_of_sets

Both start at 0, so the empty key (absent) has the fingerprint 1: a constant, the absent bucket's. (2147483647 and 2147483629 are prime: checked.)

The whole value is hashed, however long: a head is at most 16 KiB, so a key is too; the work is bounded by the head limit.

**What the hash is not:** it is not keyed (there is no randomness to key it with: section 1) and it is linear, so an attacker can *construct* a key with a chosen fingerprint or a chosen set. This allows
exactly two things and no more, both of which they could do anyway:

- *A key with another key's fingerprint* spends that key's budget. It needs the other key's value or its fingerprint, and **a value you know can be used directly**. Nothing is gained.
- *Keys that land in one set* fill that set (6.4). They could fill every set with random keys at the same cost: the table has no structure to aim at that random keys do not also reach.

A 62-bit fingerprint match with a different key is a collision: the two share a bucket. By chance it is 2^-62 per pair; by construction, see above.

### 6.3 Finding a bucket: the set, in four steps

Given the fingerprint and the set (four buckets):

1. a bucket in the set whose fingerprint is equal: **use it**;
2. else the first bucket that is **empty or fully refilled** (`units + gained >= burst * P` at `now`): **take it** (`fingerprint`, `units = burst * P`, `last = now`). A fully refilled bucket is
   exactly a new bucket: nothing is lost by taking it, which is why it is the only thing ever evicted;
3. else the set is full of buckets that are still recovering: **table full** (6.4).

### 6.4 When the table is full

**The request is refused: `429`, rule `limit.rate-table`, `Retry-After` as in section 5.** Never an allocation, never a panic, never an eviction of a bucket that has not recovered.

The choice, against the two others:

- *Admit it unlimited* ("fail open"): filling the table with junk would switch the limit off for any key not yet seen. The limiter's job is to protect the upstream; failing open fails that job exactly when it is attacked.
- *Evict a recovering bucket*: a client that is being limited gets a full bucket back by having its set crowded, and an attacker can choose which victim by crowding the set with keys they pick.
- *Refuse* is what nginx's `limit_req` does when its zone is exhausted (it answers 503); the status here is 429 because the cause is the *number of distinct keys the clients sent*, which they can change, and `Retry-After` says when a slot will free.

The cost, stated: an attacker who sends keys faster than they recover denies service to **new** keys on that route, as in the table of 3.3. A bucket is occupied from a request until it has refilled
(`burst / N` periods), so the sizing rule is: **`rate_buckets` at least twice the number of distinct keys that can be active within one refill window** (`burst * P / N` ms). The counters of section 9 show
a table that is too small (`rate_table_full` rising with `rate_limited` flat). What the load factor does is measured in section 12.

## 7. Where in the pipeline

`head_ready` (`src/proxy.cho`), in this order, the new step in bold:

1. framing (`framing.judge`), routing (`route.select`): refusals as before; **none spends a token**;
2. WebSocket: `websocket.judge`, then the tunnel cap `ws_max_tunnels`;
3. the body: `limit.body` on a declared length over the route's `max_body`;
4. **the rate limit: one token from the bucket of the route and key; `limit.rate` or `limit.rate-table`, 429**;
5. the circuit's admission (`proxy.circuit-open`) and everything after: the dial, the pool, the retry.

So: **a refused request never reaches the upstream**, because the refusal is decided before the dial and the dial is not started; a request that was refused for another reason (a bad head, a body too large, no
tunnel place) did not spend a token; a request that passes the limit and is then refused by the circuit has spent one (it is a request the gateway admitted: charging it keeps a client from retrying its way
past a limit during an outage). The limit comes **before** the circuit so that a limited request never takes the circuit's one half-open trial (`docs/health.md`).

- **TLS.** The same code: `head_ready` sees plaintext, whichever listener the bytes came from. The key of a request that arrived over `tls_listen` is computed from the same headers.
- **Retries.** A request sent again on a fresh connection after its pooled connection turned out dead (`design.md` section 6) is **not** charged again: it was admitted once.
- **WebSocket upgrades.** The limit **applies to upgrades**: an upgrade is a request on the route, and a route with `websocket = true` and a `rate_limit` limits how fast clients may *open* tunnels
  (a charger that reconnects in a loop, the thing an OCPP back office most wants to slow). It is checked **after** the tunnel cap, so that over the cap the answer stays `ws.limit` (503, the more specific
  truth) and spends nothing; and a limited upgrade **never occupies a tunnel place**: the refused client's record is cleared of its upgrade state before the refusal, so a flood of limited upgrades cannot
  fill `ws_max_tunnels`. The limit says nothing about an open tunnel: the frames in it are not requests, and `ws_idle_timeout_ms` and `ws_max_lifetime_ms` are what bound it.
- **The refusal.** Through `refuse` like every other: the upstream half, if any, is closed, the response is `429 Too Many Requests` as `application/problem+json`, `Connection: close`, with the request's id in the
  header and the body, and, new, `Retry-After`:

      HTTP/1.1 429 Too Many Requests
      Content-Type: application/problem+json
      Content-Length: 115
      Retry-After: 1
      X-Request-Id: 19b3c2a1f00-1f90-0000002a
      Connection: close

      {"type":"about:blank","title":"Too Many Requests","status":429,"rule":"limit.rate","request_id":"19b3c2a1f00-1f90-0000002a"}

  `Retry-After` goes between `Content-Length` and `X-Request-Id`; no other response changes by a byte (`tests/problem_test.cho` pins every existing one).

| rule | status | when |
|---|---|---|
| `limit.rate` | 429 | the key's bucket holds less than one token |
| `limit.rate-table` | 429 | the key has no bucket and its set has none to give (6.4) |

## 8. Per-request cost

The key is found in at most 64 headers (the head's bound) and hashed in one pass over its value; the table lookup touches at most four buckets (12 ints); the route's parameters are read from the generated
table as the other per-route keys are. A route without `rate_limit` pays one table read (`route.rate`, 0). Nothing is measured here as a throughput claim: `docs/bench.md` is where the gateway's numbers are,
and this is not in them.

## 9. Observability

- **Access log**: a limited request is an ordinary refusal line: `status` 429, `rule` `limit.rate` or `limit.rate-table`, `outcome` `refused`, the route's name, and no `upstream_ms` (it was never dialed). The line's keys
  and their order are those of every other line (`docs/observability.md` section 2): this task adds no key to it. (As for every refusal after routing, `upstream` names the upstream the route *would* have used.)
- **Metrics** (`docs/observability.md` section 6): per route, two counters, in the route's block of the stats array (slots 23 and 24 of its 32; no array grows): `rate_limited` (`limit.rate`) and `rate_table_full`
  (`limit.rate-table`). In JSON, two members at the end of each route's object, `"rate_limited"` and `"rate_table_full"`; in the Prometheus text, two families,
  `cancho_gateway_rate_limited_total{route=...}` and `cancho_gateway_rate_table_full_total{route=...}`, before `refusals_total`. The refusals map also counts both rules by name, as for every rule. `metrics.worst_case()`
  grows by the two families' lines and is tested to stay within a tenth of the largest answer (`tests/metrics_bound_test.cho`).

## 10. Gates, fixed before the code

Each must be able to fail, with a mutant shown failing it (section 12 records them).

1. **The bucket's arithmetic, a unit test** (`tests/ratelimit_test.cho`, `[[test]] ratelimit` in `cancho.toml`): the refill, the cap, the cost, `Retry-After`'s rounding, at the extremes: the
   largest rate and the largest burst at the longest period; zero elapsed; a clock that goes backwards; an elapsed time of 10^18 ms (and of the largest `int`); an empty bucket and a full one; a rate of 1 per hour. No input
   may reach an overflow.
2. **The table, a unit test** (same file): a new key gets a full burst; keys do not share buckets; the absent bucket; a set filled with recovering buckets refuses a new key and still serves the old ones; a recovered
   bucket is taken; `Retry-After` for the full table; the whole table at its largest size; a sweep of random keys at several load factors (the figures of section 12).
3. **The key, a unit test** (same file): `header:`, `xff:last` and `xff:first` over parsed heads, in every shape that matters: absent, empty, twice, several `X-Forwarded-For` lines, a trailing comma, spaces, mixed case names.
4. **The generator** (`tests/generate_test.py`): each of the eight rules of section 4 has one refusal test, with the key and a line; the accepted forms; the generated table; the counts of that file updated.
5. **End to end** (`tests/ratelimit_test.py`, the built gateway, a recording upstream): under the limit everything passes; over it, 429 with `Retry-After`, and **the upstream's record shows only the admitted
   requests**; a burst, then a refill after sleeping exactly `Retry-After`; two header keys limited independently; the header absent, empty and doubled land in the absent bucket; `xff:last` and `xff:first`; a
   full table refuses a new key with `limit.rate-table` and still serves an old one; a limit on one route does not touch another; the same on `tls_listen`; a WebSocket upgrade is limited, does not take a tunnel place,
   and `ws_max_tunnels` keeps its own answer; the log line and the counters agree with what the client saw.
6. **Mutants** of the new code (`tests/ratelimit_mutants.py`, the pattern of `tests/websocket_mutants.py`): copy the tree, one edit, run the targeted tests; each killed or explained.
7. **Nothing else moves**: `tests/problem_test.cho` pins every existing refusal's bytes; the whole existing suite passes unchanged; `scripts/authority.py --check` reports no change (the module is pure).

## 11. Not built, recorded

- A route-wide ceiling above per-key buckets (the rotation evasion of 3.3).
- `rate_key = "peer"` when `conn_peer` exists.
- IPv6 prefix aggregation for `xff:*`.
- A cost other than one token per request (by method, by body size).
- Sharing a table between routes, or between gateways.

## 12. As built

*(filled in as the code lands)*
