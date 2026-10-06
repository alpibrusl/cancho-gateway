# lexsys-gateway: design (task #1)

Status: **design; nothing built.** Written before any code. Measured claims are marked *measured* and point at the
probe that reproduces them; everything else is a decision or an open item. A claim here found false is corrected in
place.

## 1. The claim, and what it has to survive

The README's headline was: *`lex-sys authority` names the exact upstream `host:port`s the program can reach.* Section 2
measures it and **it does not hold as written for more than one upstream**. The corrected claim is in section 3.

## 2. How the upstream set becomes a literal (measured)

`probes/upstream-literal/run.sh <lex-sys>` reproduces every line below (compiler built from lex-sys `main` of
2026-10-06).

| probe | result |
|---|---|
| `tcp_connect` on an unnarrowed `Net` | report row `net_out("")`: any host |
| `narrow(net, "127.0.0.1:9001")`, then connect | row `net_out("127.0.0.1:9001")`: the literal, exactly |
| same, host taken from `argv` | row unchanged; connect to the literal host succeeds, **to any other host the process dies with SIGILL (exit 132)**, `localhost` included (the check compares names, before resolving) |
| `narrow(net, "127.0.0.")` | row `net_out("127.0.0.")`; the bound is a **plain prefix** (`net.md`'s "narrowing by prefix"): `127.0.0.2` passes the check (and fails normally, exit 2), `10.0.0.1` traps |
| two `narrow` calls | refused at compile time: `net` is consumed by the first |

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

### Options

| | (a) generator, one binary per deployment | (b) `net_out("")`, list enforced in code | (c) hybrid |
|---|---|---|---|
| report | the deployment's literal | any host | same as (a) for the compiled-in prefix |
| run-time table | none needed for the bound | whole | selects among hosts under the prefix |
| what an auditor learns from the report | the bound; exact only when one upstream or one shared prefix | nothing about egress | as (a) |
| cost | a build per deployment | none | a build when the prefix changes |

### Decision

**(a), generated, with the literal defined as the longest common prefix of the deployment's `host:port` strings, cut at
a delimiter so it cannot over-admit.** Concretely the generator emits `narrow(net, P)` where `P` is the longest common
prefix of the upstream strings truncated back to the last `.` or `:`; a single upstream is `host:port` in full (exact), and
the generator **refuses** a table whose common prefix is empty (it would be `net_out("")`, option (b) by another name)
unless the operator passes `--allow-any-egress`, which is printed in the report. Run-time config selects among upstreams
that already satisfy `P`; it cannot widen `P`.

What the report may therefore say, and what the README now says: *for a single-upstream deployment, the exact
`host:port`; for several, the shared prefix, which the generator prints with the list of upstreams it admits.* The
headline is conditional on the deployment and is stated per deployment, not as a property of the program.

Rejected: (b) loses the claim entirely; (c) adds a run-time table that the report cannot see, with no more proof than (a).
**Open:** whether a second process per upstream (a front process with no egress, workers with one literal each) is worth
its cost to get exact sets for unrelated upstreams. Not in v1; recorded in #16.

## 3. Authority row (v1)

`args`, `heap`, `net_in("<port>")` (the listener port is also a generated literal, as in `lexsys-cache`),
`net_out("<P>")` from section 2, `conn_accept`, `conn_read`, `conn_write`, `poll`, `clock`, `io_write` (log to stdout,
stderr only for startup refusals), **no `fs_*`, no `ffi`**. CI fails if a derived label is outside the committed ceiling
file (task #11) and if `fs`/`ffi` ever appear.

- **Secrets without files:** keys arrive in `argv`/environment at start. `args` is the effect; the open question is whether
  the environment is reachable without a new effect. **To settle in #8's first commit** by probe; if not, keys come in
  `argv` only (visible in `ps`, a documented limitation) or on a stdin read at start (`io_read`, a new row to ceiling).
- **Randomness for request ids:** to settle by probe in #7 (std facility vs. a clock-seeded generator, which would be
  predictable and must be called that).

## 4. Memory model: every bound has a rule

Everything is sized at start from the config; nothing is allocated afterwards (the `lexsys-cache` model).

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

Recorded one by one in #16. TLS, HTTP/2/gRPC, caching, response rewriting, dynamic discovery, clustering. Dynamic
discovery additionally contradicts section 2 (a mutable set cannot be bounded by a compile-time literal).

## 8. Agent-friendly operation (task #18): what carries over from lexsys-tools

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
3. **Authority ceiling** (#11): a new upstream outside `P` or any `fs`/`ffi` fails CI.
4. **Bound check before connect** (#11): a mutant removing the gateway's own prefix check must be killed by observing a
   refusal, not a SIGILL.
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

#1 → #2 (scaffold; its ceiling depends on §2-3) → #11 (generator and report; §2's decision lands here) → #3 → #4 (config
parser, consuming the generator's table format) → #5 → #7 → #6 → #8 → #9 → #10 → #12/#13 (grow throughout) → #18 → #14 →
#15 → #16. The epic had #11 "early" and #4 before it; both depend on #11's table format.

## 12. Cross-references checked against the sources (2026-10-06)

All of lex-sys `docs/{http,listen,native-sockets,tls-nonblocking,websocket-spike,http-server,atomics,agent-toolbox}.md` and
`packages/http-server/` exist. `websocket-spike.md` §10 is "What lex-sys lacks to write the equivalent service" (the
catalogue #15 cites). `agent-toolbox.md` has decisions **D1 to D18** (§3's own text still says "D1 to D11"; D17 is real).
lexsys-cache has `docs/design.md` and `src/session.ls`; lexsys-tools has `server/mcp.ls`, `scripts/manifest.py`,
`docs/mcp.md`. **Not found:** `docs/agent-bench.md` in lexsys-tools `main` (cited by that repo's own `docs/mcp.md` §10 and a
test, so it may live on a branch). #18's benchmark task should cite `docs/mcp.md` until it is found. lexsys-tools#28 was not
checked (outside this session's repository scope).

## 13. lex-sys gaps found so far

- One `Net` per program, one prefix bound: no exact multi-upstream report (section 2).
- A bound violation traps (SIGILL), with no refusal result to branch on.
- `narrow`'s prefix has no boundary rule.
- `agent-toolbox.md` §3 header says D1 to D11 while D12-D18 exist.
