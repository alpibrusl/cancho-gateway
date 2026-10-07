# cancho-gateway: design (task #1)

Status: **design; nothing built.** Written before any code. Measured claims are marked *measured* and point at the
probe that reproduces them; everything else is a decision or an open item. A claim here found false is corrected in
place.

## 1. The claim, and what it has to survive

The README's headline was: *`cancho authority` names the exact upstream `host:port`s the program can reach.* Section 2
measures it and **it does not hold, for any number of upstreams**, in a program that also listens: the first version of
this section (one prefix for several upstreams) was itself wrong and is corrected in 2.1. The claim that survives is in
section 3.

## 2. How the upstream set becomes a literal (measured)

`probes/upstream-literal/run.sh <cancho>` reproduces every line below (compiler built from cancho `main` of
2026-10-06).

| probe | result |
|---|---|
| `tcp_connect` on an unnarrowed `Net` | report row `net_out("")`: any host |
| `narrow(net, "127.0.0.1:9001")`, then connect | row `net_out("127.0.0.1:9001")`: the literal, exactly |
| same, host taken from `argv` | row unchanged; connect to the literal host succeeds, **to any other host the process dies with SIGILL (exit 132)**, `localhost` included (the check compares names, before resolving) |
| `narrow(net, "127.0.0.")` | row `net_out("127.0.0.")`; the bound is a **plain prefix** (`net.md`'s "narrowing by prefix"): `127.0.0.2` passes the check (and fails normally, exit 2), `10.0.0.1` traps |
| two `narrow` calls | refused at compile time: `net` is consumed by the first |
| `narrow(net, "9001")`, then `tcp_listen` on 9001 **and** `tcp_connect` | row `net_in("9001")` **and** `net_out("9001")`: the one string labels both; the listen passes, the connect to `127.0.0.1` **traps** |
| `narrow(net, "127.0.0.")`, then `tcp_listen` on 9001 | row `net_in("127.0.0.")`; the listen **traps** |

Consequences, each of which shapes the design:

1. A program has **one `Net`, hence one bound**. The report can name one literal, which is a prefix. A set of upstreams
   that do not share a prefix cannot be expressed as an exact set at all. This is stronger than #1's "narrow takes a
   literal": even with a generator, N unrelated upstreams cannot each get a label.
2. The bound is checked at connect time and a violation is a **trap, not a refusal**. The repo's rule is that no input
   reaches a panic, so the gateway must check the upstream against the same prefix **itself, before `tcp_connect`**, and
   treat the compiler's check as the backstop it is. A mutant that removes our check must be killed by a test that
   observes the refusal (task #11).
3. A prefix has no boundary rule: `10.0.0.1:80` also admits `10.0.0.1:8080` and `10.0.0.12:80`. The generator must
   emit a prefix that cannot over-admit (see decision).

### 2.1 Correction: one bound serves both directions, so a proxy cannot narrow either

The last two probe rows decide it. `Net` carries one string and uses it for both checks: `tcp_listen` requires it to
equal the port, `tcp_connect` requires it to be a prefix of the host. A program that listens **and** connects (a proxy,
by definition) has no string that passes both, so narrowing either direction makes the other trap. **A proxy's honest
report is `net_in("")` and `net_out("")`**: any port, any host. The earlier "longest common prefix" decision is withdrawn
as a *proof*; the prefix computation is kept as metadata (below).

### Options, revised

| | (a) compiled-in set, enforced in code | (b) the same, plus a split of the proxy into a listen-only and a connect-only program | (c) ask cancho for separate bounds |
|---|---|---|---|
| report | `net_in("")`, `net_out("")` | each program narrowed, but they must pass bytes between them, which needs a socket or an fd, i.e. another `Net` use | `net_in("8080")`, `net_out("10.0.1.")` |
| what proves the upstream set | our check and the tests/mutants on it, **not the compiler** | the compiler, for each half | the compiler |
| cost | none | a design of its own; probably reintroduces unnarrowed `net` in one half | a cancho change (`narrow` per direction, or `Net.split`) |

### Decision

**(a) for v1, and (c) recorded as the cancho request that would restore the headline.** The upstream set is a deployment
file compiled in by `scripts/generate.py` (task #11): `generated/deploy.cho` holds the listen port and the allowed
`host:port`s. `gateway.egress.allowed` checks an upstream by **exact equality** before every connect (never by prefix, so
`10.0.1.5:9000` does not admit `10.0.1.50:9000`), which is also what keeps the compiler's trap unreachable. The generator
still computes `intended_egress_prefix` (longest common prefix cut at a delimiter, empty if none) and prints it, so the day
cancho has separate bounds the literal is already derived and tested.

What is proved, and by what: the compiler proves **no files, no ffi, bounded, only network and clock** (the ceiling gate,
`authority.toml`). The tests prove the upstream set (`tests/egress_test.cho`, the generator's tests, and the mutants listed in
section 9). Nothing proves the set *to the compiler*, and the README says so.

Rejected: narrowing in v1 (traps). (b) is recorded in #16 as the open way to get a compiler-proved set without a
cancho change; it is not obviously possible.

## 3. Authority row (v1)

`args`, `heap`, `net_in("")` (as in `cancho-cache`; the listen port is a generated constant, not a bound),
`net_out("")` (section 2.1: the compiler cannot carry the set), `conn_accept`, `conn_read`, `conn_write`, `poll`, `clock`, `io_write` (log to stdout,
stderr only for startup refusals), **no `fs_*`, no `ffi`**. CI fails if a derived label is outside the committed ceiling
file (task #11) and if `fs`/`ffi` ever appear.

- **Secrets without files:** keys arrive in `argv`/environment at start. `args` is the effect; the open question is whether
  the environment is reachable without a new effect. **To settle in #8's first commit** by probe; if not, keys come in
  `argv` only (visible in `ps`, a documented limitation) or on a stdin read at start (`io_read`, a new row to ceiling).
- **Randomness for request ids:** settled by probe in #7 (`docs/headers.md` section 1): the pinned compiler has no random-bytes
  facility (entropy is read from `/dev/urandom` through a file capability, which the gateway deliberately lacks), so ids are a start
  stamp, the listen port and a counter: unique, **predictable**, correlation ids and not secrets. The same probe found no peer
  address on an accepted connection (`conn_peer` is not built), so the gateway cannot write `X-Forwarded-For` or `Forwarded: for=`.

## 4. Memory model: every bound has a rule

Everything is sized at start from the config; nothing is allocated afterwards (the `cancho-cache` model).

| bound | default | refusal (rule tag) | status |
|---|---|---|---|
| client connections | 1024 | `limit.connections` | 503, close |
| request head | 16 KiB (`std.http.max_head` is 64 KiB: the gateway's is lower) | `limit.head` | 431, close |
| headers per request | 64 | `limit.headers` | 431, close |
| request body (per route) | per route | `limit.body` | 413, close |
| upstream connections per upstream | 64 | `limit.pool` | 503 |
| route table entries | 256 | `config.routes` | startup |
| rate-limit keys | 65,536 | policy in #9 | 429 |

Per-connection buffers are slabs from one arena; the arena size is `connections * (head + buffer)` plus pool buffers, printed
by `check` (§8). Defaults are starting points, fixed by the first measurement in #5, not claims.

## 5. Timeouts (all from the clock, one rule each)

header read (408 `timeout.header`), upstream connect (504 `timeout.connect`), upstream first byte (504 `timeout.upstream`),
idle keep-alive (close, no response), total request (504 `timeout.total`). The poller wait is the minimum over the
earliest deadline; no timer thread.

## 6. Framing, bodies, retries

`std.http.parse` is the head parser (strict, offset table, no copies; refusals carry position and code 1-12). The gateway
adds what a proxy needs and a server does not: exactly one body length, `Content-Length` + `Transfer-Encoding` refused,
TE other than `chunked` refused (501), bounded chunk-size parsing, `Expect` and `Upgrade` answered explicitly (the first
refused or handled per route, the second 501 until #15), absolute-form and `CONNECT` refused. **Which of these `std.http`
already refuses is not assumed here: task #3 starts by running its corpus against `std.http` alone and records the gaps.**

Bodies stream through one bounded buffer per direction with backpressure: a side that cannot write stops being read.

**Retries:** only a request that has sent **zero bytes of body to an upstream connection that was idle-closed by the
upstream, and whose method is idempotent** (`GET`, `HEAD`, `OPTIONS`, `PUT`, `DELETE`), is retried, once, on a fresh
connection. Nothing else, ever.

## 7. Not in v1

Recorded one by one in #16. TLS (**corrected 2026-10-07:** the reason first recorded here, that TLS needs foreign code and would make the
authority report unbounded, no longer holds: cancho has a TLS 1.3 server in pure cancho, `packages/tls`, cancho #338 and #339, example #346.
Integrating it is undecided and would add file reads (one certificate directory, `/dev/urandom`) to the report; until it is built, a front terminates TLS),
HTTP/2/gRPC, caching, response rewriting, dynamic discovery, clustering. Dynamic
discovery additionally contradicts section 2 (a mutable set cannot be bounded by a compile-time literal).

## 8. Agent-friendly operation (task #18): what carries over from cancho-tools

Applies unchanged: `introspect` and `skill` from one table (D11), errors as `{code, rule, message, hint, repair, detail}`
with stable rule tags (D5, D6), schema-checked outputs, deterministic JSON, `check`/`explain`/`diff` as the no-state
commands (D10's dry-run semantics), the authority report embedded and printed (D12), one binary per deployment (D17, which
coincides with section 2's decision).

Does **not** carry over, and why: D2's single JSON document per invocation (a server is long-running; its stream is the
access log, one JSON object per line, and `introspect`/`check`/`explain`/`diff` are the document-per-invocation commands);
D9 paths-as-capabilities (no file access exists); D8 large inputs (the bounds in section 4 replace it). Gateway-generated
HTTP errors are `application/problem+json` with the same `rule`. The MCP front is deferred to after #18's CLI half, since
`check`/`explain`/`diff` are the only parts worth calling without a shell.

Boundary with other tasks, to stop the overlap: problem+json is **produced by #5** and **specified by #18**; the admin
listener and `/readyz` are **built in #10** and **specified in #18**; #18 owns `introspect`, `skill`, schemas, `check`,
`explain`, `diff`.

## 9. Gates, fixed before the code

Each must be able to fail, with a mutant shown failing it.

1. **Smuggling corpus** (#3): known cases, each with an expected outcome and the source listed; split-at-any-byte
   delivery decodes identically; 1,000+ fuzzed heads reach no panic.
2. **Differential vs nginx** (#12 owns the harness; #3 and #7 supply cases): same scenario, compare what the client and
   the upstream observe; deliberate divergences asserted so the list cannot go stale.
3. **Authority ceiling** (#11): any label outside `authority.toml`, or any `fs`/`ffi`, fails CI. Because the compiler
   cannot see the upstream set (2.1), "adding an upstream changes the report" is **not** a gate we can have; it is replaced
   by: the deployment file and `generated/deploy.cho` must agree (`generate.py --check`), so an upstream cannot be added
   without a regenerated, reviewed diff.
4. **Egress check before connect** (#11): `tests/egress_test.cho` and the generator's tests. Mutants, each shown killed
   (2026-10-06): `starts_with` instead of equality in `egress.allowed` (killed by the over-admit test); no delimiter cut in
   the prefix (killed by 3 prefix cases); an upstream added to the deployment file without regenerating (killed by
   `--check`).
5. **Memory flat** (#5, #13): RSS after warm-up vs. after N=1,000,000 requests of churn within a stated tolerance (set
   from the first measurement, then fixed); every bound tested at its edge.
6. **Fuzz** (#13): random byte streams split at random points into the whole connection state machine, with a fixed
   iteration budget recorded in the repo; a trap is a bug.

## 10. Benchmark (pre-registered, #14)

Required cells, one worker, same machine, pinned versions, configs published: nginx and HAProxy. Envoy, Caddy and Traefik
are **optional** (reported if set up; what was left out is stated). Cells: requests/s and latency percentiles
(coordinated-omission-corrected load generator, plus a second as cross-check) through the proxy to a trivial upstream, for
small and large bodies; many idle keep-alive connections; memory at N connections; behaviour under a slow upstream. Per-core
and pinned-to-one-worker numbers for competitors. Losses reported as plainly as wins; what each competitor does beyond the
gateway is listed. The criterion for "not meaningfully slower" is set after the first #5 measurement and committed
**before** the comparison runs.

## 11. Order of work (corrected)

#1 → #2 (scaffold; its ceiling depends on §2-3) → #11 (generator and ceiling gate; built, §2.1) → #3 → #4 (config
parser, consuming the generator's table format) → #5 → #7 → #6 → #8 → #9 → #10 → #12/#13 (grow throughout) → #18 → #14 →
#15 → #16. The epic had #11 "early" and #4 before it; both depend on #11's table format.

## 12. Cross-references checked against the sources (2026-10-06)

All of cancho `docs/{http,listen,native-sockets,tls-nonblocking,websocket-spike,http-server,atomics,agent-toolbox}.md` and
`packages/http-server/` exist. `websocket-spike.md` §10 is "What cancho lacks to write the equivalent service" (the
catalogue #15 cites). `agent-toolbox.md` has decisions **D1 to D18** (§3's own text still says "D1 to D11"; D17 is real).
cancho-cache has `docs/design.md` and `src/session.cho`; cancho-tools has `server/mcp.cho`, `scripts/manifest.py`,
`docs/mcp.md`. **Not found:** `docs/agent-bench.md` in cancho-tools `main` (cited by that repo's own `docs/mcp.md` §10 and a
test, so it may live on a branch). #18's benchmark task should cite `docs/mcp.md` until it is found. cancho-tools#28 was not
checked (outside this session's repository scope).

## 13. cancho gaps found so far

- One `Net` per program, one prefix bound: no exact multi-upstream report (section 2).
- One bound string serves `tcp_listen` (equality with the port) and `tcp_connect` (prefix of the host): a program doing
  both cannot narrow either. **Request:** separate bounds per direction (`narrow` per direction, or `Net.split`).
- A bound violation traps (SIGILL), with no refusal result to branch on.
- `narrow`'s prefix has no boundary rule.
- `agent-toolbox.md` §3 header says D1 to D11 while D12-D18 exist.
