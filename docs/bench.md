# Benchmark against the top open-source proxies (task #14)

> **Names.** Everything below was written and measured while the project was `lexsys-gateway`, built with `lex-sys`. The harness now calls the gateway `cancho`
> (and its baseline `cancho-base`) and the compiler `cancho`; `bench/results/*.json` keep the old keys (`lexsys`, `lexsys-base`) and the sections below keep the old names,
> because they say what was measured. `--baseline-rev` can only build a revision from after the rename: an older one needs the old compiler.

Status: **protocol fixed in this commit, before any number was measured.** Results are added in a later commit, under section 8,
without changing sections 1 to 7; if a result shows the protocol was wrong, the protocol is corrected in place and says so.

## 1. What is compared

Each of these is configured as a **plain reverse proxy** (one listener, one route to one upstream, keep-alive to the upstream where it
supports it, no TLS, no access log, no authentication, no rate limit, no metrics) and given **one core**:

| proxy | version | how obtained | configuration |
|---|---|---|---|
| lexsys-gateway | this repository's `main` at the commit recorded with the results | built with the pinned lex-sys compiler | `bench/run.py` generates a deployment, `pool_idle_max = 64` |
| nginx | 1.24.0 (Ubuntu 24.04 package) | `apt` | `bench/conf/nginx.conf` |
| HAProxy | 2.8.16 (Ubuntu 24.04 package) | `apt` | `bench/conf/haproxy.cfg` |
| Envoy | 1.39.3 | the `envoyproxy/envoy:v1.39-latest` image, `usr/local/bin/envoy` extracted from its layer (the GitHub release download was denied by the sandbox's egress policy) | `bench/conf/envoy.yaml`, `--concurrency 1` |
| Caddy | 2.6.2 (Ubuntu 24.04 package) | `apt` | `bench/conf/Caddyfile`, `GOMAXPROCS=1`. **Older than current Caddy**: a newer build was not obtainable here |
| Traefik | 3.6.0 | built from the Go module source, `go build ./cmd/traefik`, **without the web UI** (`go install` of the latest, 3.7.14, is refused by its own `replace` directives and its module archive omits a nested module) | `bench/conf/traefik.yml`, `GOMAXPROCS=1` |

**Left out, and why:** Pingora (a library, not a proxy to configure) and Kong (needs a database or its own runtime; not set up here).

## 2. The machine and how it is divided

One virtual machine (Firecracker, 4 vCPU, 16 GiB, Linux 6.18), **shared with other tenants: absolute numbers are bounds, not
the machine's capacity, and run-to-run noise is real.** Everything runs on this one machine over loopback, pinned with `taskset`:

- the proxy under test: **core 0** (every thread it has, so "one core" is one core);
- the upstream (an nginx with two workers serving fixed answers, `bench/conf/nginx-upstream.conf`): **core 1**;
- the load generator: **cores 2 and 3**.

## 3. The cells (fixed now)

Load generator: **wrk 4.1.0**, 2 threads, 64 connections unless stated, **10 s** per run after a discarded **3 s** warm-up.
wrk does **not** correct for coordinated omission, so its latency percentiles are optimistic under saturation; cell C1 is repeated with
**oha 1.16.0 `--latency-correction`** as a cross-check.

| cell | what | upstream answer |
|---|---|---|
| C1 | `GET /`, keep-alive clients, 64 connections | 2 bytes |
| C1b | the same with 8 connections (latency under light load) | 2 bytes |
| C2 | `GET /` with `Connection: close`: a new client connection per request | 2 bytes |
| C3 | `GET /big`, keep-alive, 64 connections | 65,536 bytes |
| C4 | `POST /post` with a 16 KiB body, keep-alive, 64 connections | 2 bytes |
| C5 | `GET /` against an upstream that waits 100 ms before answering, keep-alive, 64 connections (the ideal is 640 requests/s) | 2 bytes after 100 ms |
| C6 | memory: resident set of the proxy before and after **100 connections are opened and left without a request** for 3 s (lexsys-gateway closes a connection that has not sent a head after 10 s, so 3 s is inside its window) | none |

C5 uses a Go upstream (`bench/slow_upstream.go`, `GOMAXPROCS=1`, core 1) instead of nginx.

**Runs:** 5 per cell per proxy, **interleaved** (proxy order rotated each round, so drift hits every proxy alike); the **median** is
reported with the min and max. wrk's 5 runs of one cell on one proxy are not a statistical sample of anything beyond this machine.

## 4. Validity rules, applied before a number is reported

- Before measuring, each proxy must answer one `GET /` and one `GET /big` and one `POST /post` correctly (status 200, exact body
  length) through itself; otherwise it is reported as **not working in this setup**.
- A cell whose run has any **non-2xx response or socket error** is reported with that count, and the cell is marked **invalid** for
  that proxy; it is not averaged in silently.
- The CPU used by wrk (as a fraction of its two cores) and by the upstream (of its one) is sampled for every run. **A run in which wrk
  used more than 90% of its cores is marked CLIENT-BOUND and a run in which the upstream used more than 90% of core 1 is marked
  UPSTREAM-BOUND**; no ratio is quoted from such a cell.
- The proxy's own CPU is sampled too, so "the proxy was saturated" is a measurement and not an assumption.

## 5. What is reported, and how

Requests per second, p50 and p99 latency (as measured, see section 3), and the proxy's CPU fraction, as medians with min and max;
ratios to **nginx** and to **HAProxy**; and **losses are reported as plainly as wins**. No pass or fail criterion is set: the gate
`docs/design.md` section 10 deferred ("not meaningfully slower") is not adopted before the data exists; if one is proposed, it is
proposed after the results and marked as such.

## 6. What the comparison does not mean

- lexsys-gateway does **less** than every other proxy here: no TLS, no HTTP/2, no client keep-alive (its client connections close after
  each response, so C1, C3, C4 and C5 force it to accept and close a connection per request while the others do not), no load balancing,
  no health checks beyond a passive circuit, no hot reload, no metrics. A number in its favour is not a claim that it is a better proxy.
- Each competitor does **more** beyond the plain reverse proxy it is configured as; their feature sets are not part of this table.
- One machine, one run of 5, a shared VM, loopback only, tiny bodies: it measures per-request overhead on one core, not production
  behaviour under real networks, TLS, many upstreams or long-lived connections.
- Versions differ in age (Caddy 2.6.2 is old; Traefik is 3.6.0, not the newest).

## 7. Reproducing

`python3 bench/run.py --help`. It needs the tools above on `PATH` (or `--bin NAME=PATH`), builds the gateway with `cancho` (`CANCHO`; before the rename of 2026-10-07, `lex-sys` and `LEX_SYS`), writes
the configs from `bench/conf/` into a scratch directory, and writes `results.json` and a markdown table.


## 8. Results (measured 2026-10-06; sections 1 to 7 above are unchanged)

**Measured code:** `main` at `fad47dc` plus `eef8636` (TCP_NODELAY on both sides, found by this benchmark's first quick run, see 8.4) and
nothing else in `src/`. Harness: `bench/run.py` at the commits on this branch; raw numbers: `bench/results/2026-10-06.json`.
5 interleaved runs per cell, 10 s after a 3 s warm-up, medians with (min–max), as section 3 fixed.

**Deviations from, and details the protocol left open:** each run starts the proxy afresh and stops it afterwards; the proxy is
sanity-checked (section 4) each time. The first launch of the full run died after 28 runs (the sandbox stopped the process between
turns); it was continued with `--resume`, which keeps the 28 recorded runs and does the rest, so round 0 of C4 and the later rounds were
measured at a different time of day than the first 28 runs. Configs changed before the run, not after any result of the full run:
nginx needs `backlog=` (not `backlog `) and `user root` for the scratch directory, and `client_body_buffer_size 64k` (with the default 16k a
16 KiB POST is spooled to a temp file and nginx showed a 23 ms stall per request in the quick run). The oha cross-check needs an
open-loop rate for `--latency-correction` to mean anything; it was run at **6,000 requests/s**, about half of what the slowest proxy
sustained in C1.

### 8.1 Throughput relative to the others (lexsys-gateway ÷ other, median requests/s; below 1 is a loss)

| cell | ÷ nginx | ÷ HAProxy | ÷ Envoy | ÷ Caddy | ÷ Traefik |
|---|---|---|---|---|---|
| C1 keep-alive, 64 conns | 0.80 | 0.61 | 2.00 | 2.70 | 2.68 |
| C1b keep-alive, 8 conns | 0.70 | 0.63 | 1.71 | 1.81 | 1.95 |
| C2 `Connection: close` | 1.49 | 1.11 | 2.98 | 4.03 | 4.06 |
| C3 64 KiB response | 0.83 | 0.53 | 1.00 | 1.15 | 1.23 |
| C4 16 KiB POST | 0.42 | 0.54 | 1.03 | 1.65 | 1.67 |

**Plainly:** lexsys-gateway is **slower than nginx and HAProxy in C1, C1b, C3 and C4** (by 17 to 58%), faster than both in C2, where
it is the only one of these that has no client keep-alive to lose, and ahead of Envoy, Caddy and Traefik in most cells (level with Envoy
in C3 and C4). C5 (a 100 ms upstream) shows no difference between any of them: 618 to 625 requests/s against an ideal 640.

### 8.2 The tables


#### C1

| proxy | req/s median (min–max) | p50 ms | p99 ms | proxy CPU | upstream CPU | load CPU | marks |
|---|---|---|---|---|---|---|---|
| lexsys | 34,361 (32,642–35,313) | 1.72 | 4.54 | 96% | 31% | 57% |  |
| nginx | 42,958 (40,227–44,300) | 1.42 | 2.95 | 99% | 47% | 22% |  |
| haproxy | 56,666 (55,092–58,401) | 1.05 | 2.67 | 98% | 42% | 26% |  |
| envoy | 17,168 (15,796–17,723) | 3.50 | 7.36 | 98% | 20% | 11% |  |
| caddy | 12,719 (12,155–13,094) | 4.25 | 12.51 | 98% | 20% | 10% |  |
| traefik | 12,801 (12,529–13,282) | 4.44 | 14.92 | 99% | 19% | 10% |  |

#### C1b

| proxy | req/s median (min–max) | p50 ms | p99 ms | proxy CPU | upstream CPU | load CPU | marks |
|---|---|---|---|---|---|---|---|
| lexsys | 26,033 (25,324–26,952) | 0.26 | 1.15 | 96% | 27% | 47% |  |
| nginx | 37,384 (36,455–37,861) | 0.21 | 0.89 | 98% | 38% | 20% |  |
| haproxy | 41,375 (39,435–43,198) | 0.18 | 0.89 | 98% | 38% | 21% |  |
| envoy | 15,186 (14,034–15,547) | 0.48 | 3.62 | 93% | 17% | 10% |  |
| caddy | 14,392 (13,899–14,474) | 0.43 | 4.14 | 97% | 19% | 10% |  |
| traefik | 13,372 (12,955–13,794) | 0.47 | 2.41 | 98% | 18% | 10% |  |

#### C2

| proxy | req/s median (min–max) | p50 ms | p99 ms | proxy CPU | upstream CPU | load CPU | marks |
|---|---|---|---|---|---|---|---|
| lexsys | 36,132 (33,910–36,795) | 1.67 | 3.59 | 97% | 31% | 58% |  |
| nginx | 24,172 (23,421–24,701) | 2.52 | 4.68 | 98% | 30% | 43% |  |
| haproxy | 32,635 (30,852–33,619) | 1.83 | 4.01 | 97% | 28% | 52% |  |
| envoy | 12,110 (11,528–12,699) | 4.96 | 8.87 | 98% | 12% | 23% |  |
| caddy | 8,966 (8,749–9,026) | 6.66 | 16.68 | 99% | 19% | 18% |  |
| traefik | 8,907 (8,521–9,264) | 6.51 | 20.85 | 98% | 14% | 17% |  |

#### C3

| proxy | req/s median (min–max) | p50 ms | p99 ms | proxy CPU | upstream CPU | load CPU | marks |
|---|---|---|---|---|---|---|---|
| lexsys | 10,194 (9,866–10,327) | 5.95 | 10.10 | 98% | 25% | 33% |  |
| nginx | 12,215 (11,667–12,582) | 5.14 | 8.06 | 99% | 38% | 24% |  |
| haproxy | 19,291 (18,622–19,685) | 3.23 | 5.97 | 98% | 45% | 23% |  |
| envoy | 10,181 (9,898–10,347) | 5.99 | 11.26 | 98% | 28% | 14% |  |
| caddy | 8,888 (8,782–9,439) | 6.48 | 16.15 | 99% | 32% | 16% |  |
| traefik | 8,277 (7,906–8,455) | 6.91 | 20.23 | 99% | 29% | 15% |  |

#### C4

| proxy | req/s median (min–max) | p50 ms | p99 ms | proxy CPU | upstream CPU | load CPU | marks |
|---|---|---|---|---|---|---|---|
| lexsys | 14,004 (13,680–14,520) | 4.49 | 8.86 | 98% | 45% | 28% |  |
| nginx | 33,312 (31,550–35,920) | 1.87 | 3.54 | 98% | 50% | 20% |  |
| haproxy | 25,867 (25,304–27,106) | 2.35 | 5.64 | 98% | 43% | 14% |  |
| envoy | 13,615 (12,932–13,876) | 4.49 | 10.78 | 98% | 22% | 11% |  |
| caddy | 8,503 (8,318–9,001) | 6.61 | 16.43 | 99% | 22% | 9% |  |
| traefik | 8,410 (8,211–8,612) | 6.61 | 20.34 | 98% | 22% | 9% |  |

#### C5

| proxy | req/s median (min–max) | p50 ms | p99 ms | proxy CPU | upstream CPU | load CPU | marks |
|---|---|---|---|---|---|---|---|
| lexsys | 625 (623–625) | 101.50 | 104.60 | 2% | 3% | 1% |  |
| nginx | 624 (622–625) | 101.38 | 111.77 | 2% | 3% | 1% |  |
| haproxy | 625 (621–625) | 101.72 | 106.27 | 2% | 3% | 1% |  |
| envoy | 618 (607–620) | 102.50 | 108.28 | 7% | 4% | 1% |  |
| caddy | 624 (618–625) | 101.36 | 107.06 | 8% | 4% | 1% |  |
| traefik | 625 (625–625) | 101.39 | 109.11 | 7% | 4% | 1% |  |

#### C6 memory

| proxy | RSS before (MiB) | RSS with 100 idle connections (MiB) | connections still open |
|---|---|---|---|
| lexsys | 1.9 | 1.9 | 100 |
| nginx | 11.8 | 11.8 | 100 |
| haproxy | 14.9 | 14.9 | 100 |
| envoy | 58.9 | 59.6 | 100 |
| caddy | 32.2 | 32.7 | 100 |
| traefik | 83.5 | 83.9 | 100 |

Every proxy had 0 non-2xx responses and 0 wrk socket errors in every run. **No run was CLIENT-BOUND or UPSTREAM-BOUND** (wrk used at most
60% of its two cores, the upstream at most 51% of its core), and the proxy used 92 to 99% of its core in every throughput cell, so those
cells measure the proxy. C5 and the open-loop cell are not throughput-bound by design.

### 8.3 The open-loop cross-check (oha 1.16.0, `--latency-correction`, 6,000 requests/s, C1)

All six held the rate (5,997 to 5,999 requests/s). Latency, corrected for coordinated omission:

| proxy | p50 ms | p99 ms median | p99 min–max | proxy CPU |
|---|---|---|---|---|
| lexsys | 0.54 | 4.51 | 2.19–5.42 | 24% |
| nginx | 0.40 | 1.91 | 1.32–3.57 | 18% |
| haproxy | 0.41 | 1.36 | 1.15–3.43 | 19% |
| envoy | 0.86 | 5.98 | 4.01–40.71 | 49% |
| caddy | 0.73 | 14.07 | 12.06–36.19 | 57% |
| traefik | 0.68 | 13.70 | 9.41–25.86 | 54% |

oha reports requests still in flight when its deadline arrives as errors ("aborted due to deadline", 0 to 25 per run, on every proxy
including nginx and HAProxy, never a refusal or a reset); they are not counted against validity here. At a rate every proxy sustains,
the ordering of the tails is the same as the throughput order: nginx and HAProxy lowest, lexsys-gateway next, Envoy, Caddy and Traefik
highest.

### 8.4 What the benchmark found in lexsys-gateway

- **A real bug, fixed (`eef8636`).** The first quick run showed 2,835 requests/s and a 24 ms p50 for the 16 KiB POST. `strace` showed the
  body forwarded as a 16,384-byte write and a 96-byte write on a pooled upstream connection; without TCP_NODELAY the second write waited
  for the upstream's delayed ACK (about 43 ms, on 38 of 40 requests). With the fix C4 went from 2,835 to 14,004 requests/s. The
  regression test fails without the upstream-side call; the client-side call is not pinned by a test.
- **Where the remaining gap probably is (not measured, no profile taken yet):** the response head and the response body leave in two
  writes (151 and 2 bytes in the strace); request bodies move in 16 KiB steps through 32 KiB queues; client connections are accepted and closed
  per request. These are hypotheses to profile, not findings.
- **No client keep-alive** is a design limit, not a tuning gap: C1, C1b, C3 and C4 make it accept and close a connection per request
  while all others reuse one.

### 8.5 Memory (C6)

Resident set before and with 100 idle connections held for 3 s: lexsys-gateway 1.9 MiB (no change), nginx 11.8, HAProxy 14.9, Caddy
32.2 to 32.7, Envoy 58.9 to 59.6, Traefik 83.5 to 83.9 MiB. All 100 connections stayed open. The gateway's number is small because it
allocates its slab and queues at start and touches few pages; this cell does **not** show memory under load, and the gateway's session
limit is about 127 (design.md), so 100 is near its ceiling while the others are far from theirs.

### 8.6 What this does and does not say

- It says that on this machine, one core, loopback, tiny bodies, lexsys-gateway sits between nginx/HAProxy and Envoy/Caddy/Traefik, and
  that its worst cell against nginx is the 16 KiB POST (0.42×).
- It does not say anything about TLS, HTTP/2, many upstreams, real networks, long-lived connections, or the gateway under the
  200+ concurrent connections it cannot hold. Caddy is 2.6.2 and Traefik 3.6.0, both older than current.
- No pass or fail criterion is adopted here (section 5). If one is proposed from these data it must be marked as proposed after them.

## 9. Amendment of 2026-10-07, fixed before the second run (sections 1 to 8 are unchanged)

The first run (section 8) left Kong out as "not set up here". Two things change for the second run, and nothing else in the protocol:

- **Kong is added.** Kong Gateway open source **3.9.3** (the `library/kong:3.9` image from Docker Hub, extracted from its layers and run in a `chroot` of the extracted tree with `/dev` and `/proc` bind-mounted; the GitHub release and the vendor's package repository are not reachable from the sandbox). DB-less, from `bench/conf/kong.yml` (one service, one route, no plugins), one nginx worker, no access log, no admin API or status listener, keep-alive to the upstream (Kong's default), `nginx_http_client_body_buffer_size 64k` as for nginx (the default 8k spools a 16 KiB POST to a temp file and shows the 23 ms stall the nginx config showed). Kong's other settings are in `bench/run.py` (`proxy_cmd`). Kong adds `Via` and three `X-Kong-*` headers to every response and runs more than a proxy (a Lua runtime, a router, a plugin chain that is empty here): this is the "does more" caveat of section 6, stated for it too. Kong runs on core 0 with the rest.
- **The gateway is measured against its own earlier build in the same rounds.** The first run's numbers cannot be compared with a later run's: between the first run and a quick second one every proxy was 12 to 31% slower (a shared machine). So the second run includes `lexsys-base`, the gateway built from `376e640` (what section 8 measured), as a seventh competitor, interleaved with the others; a change to the gateway is judged by `lexsys` ÷ `lexsys-base` in the same run, and by the ratios to the other proxies in the same run, never by absolute numbers across runs.
- **A harness fix:** a proxy that is still shutting down keeps its port, and the next proxy in the rotation could see it "listening" and then lose the bind (found with Kong). The harness now waits for the port to be free after stopping a proxy.

The second run is reported in section 10, added after it, without changing this section. **Left out:** Pingora (a library). The `lexsys` of the second run is `main` plus the commit that cut its syscalls per request from 15 to 11 (a single send for a response head and the body that came with it; no arm and disarm of write interest around a pooled write).


## 10. Second run (measured 2026-10-07, after section 9's amendment; sections 1 to 9 are unchanged)

**Measured:** `lexsys` = `main` (`376e640`) plus `2818de3` (15 to 11 syscalls per request); `lexsys-base` = `376e640`; seven others as in section 1 plus Kong 3.9.3
(section 9). 5 interleaved rounds, 10 s after a 3 s warm-up, as before; raw numbers `bench/results/2026-10-07.json`. Every proxy answered the
sanity requests; **0 non-2xx and 0 wrk socket errors in every run; no run CLIENT-BOUND (wrk used at most 78% of its two cores) or UPSTREAM-BOUND (at most 54%);
the proxy used 95 to 99% of its core in every throughput cell.**

### 10.1 What the change did (the gateway against its own earlier build, same rounds; per-round ratios, median and (min–max))

| cell | `lexsys` ÷ `lexsys-base` |
|---|---|
| C1 | 1.26 (1.23–1.30) |
| C1b | 1.17 (1.09–1.23) |
| C2 | 1.24 (1.12–1.27) |
| C3 | 1.16 (1.09–1.23) |
| C4 | 1.10 (1.08–1.19) |

The change is a gain in every cell, 10 to 26%, and every one of the 25 paired rounds is above 1. The largest gains are where there is most per-connection work to
remove (C1, C2); the POST cell, bound by copying a 16 KiB body, gains least.

### 10.2 Against the others (paired per-round ratios, `lexsys` ÷ other; below 1 is a loss)

| cell | ÷ nginx | ÷ HAProxy | ÷ Envoy | ÷ Caddy | ÷ Traefik | ÷ Kong |
|---|---|---|---|---|---|---|
| C1 keep-alive 64 | 1.15 (1.10–1.21) | 0.92 (0.84–0.96) | 3.12 | 3.96 | 3.87 | 2.61 |
| C1b keep-alive 8 | 0.85 (0.80–0.86) | 0.73 (0.70–0.76) | 2.17 | 2.35 | 2.36 | 1.61 |
| C2 `Connection: close` | 2.08 (1.99–2.09) | 1.47 (1.40–1.48) | 3.73 | 5.70 | 5.34 | 2.69 |
| C3 64 KiB response | 0.99 (0.94–1.02) | 0.54 (0.54–0.56) | 1.23 | 1.38 | 1.45 | 1.39 |
| C4 16 KiB POST | **0.47 (0.45–0.48)** | **0.55 (0.50–0.55)** | 1.17 | 1.86 | 1.74 | **0.91 (0.87–0.95)** |

**Read this with the drift in mind.** The machine was slower than in the first run (nginx's own C1 median went from 43k to 30k requests/s, HAProxy's from 57k to 38k), and
the gateway's did not fall as far (34k to 34k). That is a larger swing than the gateway's gain, and it is **not explained**: so "the gateway is ahead of nginx on C1" is
**not a stable finding** (it was 0.80 in the first run and 1.15 here), and no ratio to nginx on C1, C1b or C3 should be quoted without both runs. What is the same in both runs:
**C4 is the gateway's worst cell against nginx and HAProxy** (0.42 then 0.47 and 0.55); **HAProxy is ahead on C3 by about 2×** (0.53 then 0.54); **the gateway is ahead of nginx and
HAProxy on C2**; and it is ahead of Envoy, Caddy and Traefik on every cell.

**Kong** (3.9.3, DB-less, one worker, no plugins): behind the gateway on every cell except **C4, where it is about 10% ahead** (0.91), at 6 to 13k requests/s elsewhere,
the range of Envoy and Caddy, and it uses 160 MiB resident. It does more than a proxy (section 9).

### 10.3 The tables


#### C1

| proxy | req/s median (min–max) | p50 ms | p99 ms | proxy CPU | upstream CPU | load CPU | marks |
|---|---|---|---|---|---|---|---|
| lexsys | 34,451 (32,909–35,351) | 1.64 | 4.03 | 96% | 36% | 76% |  |
| nginx | 29,903 (29,065–29,991) | 2.10 | 3.88 | 99% | 43% | 21% |  |
| haproxy | 38,426 (35,779–39,069) | 1.60 | 3.36 | 98% | 38% | 23% |  |
| envoy | 11,312 (10,430–12,073) | 5.47 | 8.99 | 99% | 18% | 9% |  |
| caddy | 8,416 (8,088–9,226) | 6.70 | 17.33 | 99% | 19% | 9% |  |
| traefik | 8,939 (8,361–9,374) | 6.64 | 17.70 | 99% | 20% | 9% |  |
| kong | 13,231 (13,117–13,562) | 4.56 | 9.12 | 98% | 27% | 12% |  |
| lexsys-base | 27,070 (26,214–28,820) | 2.10 | 5.44 | 96% | 30% | 66% |  |

#### C1b

| proxy | req/s median (min–max) | p50 ms | p99 ms | proxy CPU | upstream CPU | load CPU | marks |
|---|---|---|---|---|---|---|---|
| lexsys | 21,924 (20,865–22,828) | 0.29 | 0.93 | 96% | 30% | 54% |  |
| nginx | 26,396 (25,811–26,869) | 0.29 | 0.75 | 99% | 37% | 20% |  |
| haproxy | 30,090 (29,570–30,562) | 0.25 | 0.72 | 98% | 36% | 20% |  |
| envoy | 10,178 (10,089–10,426) | 0.72 | 1.93 | 98% | 15% | 8% |  |
| caddy | 9,357 (9,239–9,707) | 0.67 | 2.87 | 99% | 20% | 9% |  |
| traefik | 9,250 (9,025–9,655) | 0.70 | 2.61 | 99% | 19% | 9% |  |
| kong | 13,615 (13,321–13,822) | 0.55 | 1.87 | 98% | 26% | 11% |  |
| lexsys-base | 18,780 (18,066–19,923) | 0.34 | 1.16 | 96% | 28% | 51% |  |

#### C2

| proxy | req/s median (min–max) | p50 ms | p99 ms | proxy CPU | upstream CPU | load CPU | marks |
|---|---|---|---|---|---|---|---|
| lexsys | 33,230 (31,440–34,234) | 1.66 | 3.89 | 96% | 35% | 76% |  |
| nginx | 16,124 (15,815–16,423) | 3.83 | 6.24 | 98% | 30% | 43% |  |
| haproxy | 22,997 (22,356–23,188) | 2.62 | 4.83 | 98% | 28% | 55% |  |
| envoy | 8,975 (8,304–9,167) | 6.76 | 11.44 | 99% | 11% | 23% |  |
| caddy | 6,002 (5,375–6,576) | 10.11 | 22.88 | 99% | 18% | 17% |  |
| traefik | 6,173 (5,470–6,540) | 9.73 | 22.17 | 99% | 14% | 18% |  |
| kong | 12,657 (12,374–13,113) | 4.61 | 9.25 | 98% | 26% | 32% |  |
| lexsys-base | 26,835 (26,716–27,965) | 2.16 | 5.05 | 97% | 29% | 65% |  |

#### C3

| proxy | req/s median (min–max) | p50 ms | p99 ms | proxy CPU | upstream CPU | load CPU | marks |
|---|---|---|---|---|---|---|---|
| lexsys | 8,754 (8,598–9,098) | 6.95 | 11.73 | 98% | 30% | 37% |  |
| nginx | 8,939 (8,575–9,379) | 6.97 | 12.30 | 99% | 39% | 23% |  |
| haproxy | 16,077 (15,885–16,227) | 3.85 | 6.96 | 99% | 52% | 25% |  |
| envoy | 7,106 (7,020–8,181) | 8.52 | 15.57 | 99% | 28% | 13% |  |
| caddy | 6,297 (5,960–6,630) | 9.57 | 22.00 | 99% | 31% | 15% |  |
| traefik | 6,040 (5,714–6,254) | 10.01 | 24.74 | 99% | 29% | 14% |  |
| kong | 6,329 (5,987–6,660) | 9.64 | 17.04 | 99% | 30% | 17% |  |
| lexsys-base | 7,486 (7,110–8,003) | 8.02 | 14.43 | 98% | 25% | 33% |  |

#### C4

| proxy | req/s median (min–max) | p50 ms | p99 ms | proxy CPU | upstream CPU | load CPU | marks |
|---|---|---|---|---|---|---|---|
| lexsys | 10,839 (10,640–11,499) | 5.75 | 10.57 | 98% | 47% | 28% |  |
| nginx | 23,459 (23,076–23,903) | 2.64 | 4.91 | 99% | 47% | 20% |  |
| haproxy | 20,667 (19,234–21,384) | 3.02 | 5.62 | 98% | 44% | 14% |  |
| envoy | 9,326 (8,888–9,961) | 6.50 | 11.54 | 99% | 20% | 10% |  |
| caddy | 5,826 (5,797–6,131) | 9.85 | 23.56 | 99% | 22% | 8% |  |
| traefik | 6,306 (6,017–6,370) | 9.44 | 23.77 | 99% | 23% | 8% |  |
| kong | 12,002 (11,706–12,492) | 5.09 | 9.22 | 99% | 31% | 11% |  |
| lexsys-base | 9,803 (9,337–10,196) | 6.47 | 11.81 | 98% | 42% | 27% |  |

#### C5

| proxy | req/s median (min–max) | p50 ms | p99 ms | proxy CPU | upstream CPU | load CPU | marks |
|---|---|---|---|---|---|---|---|
| lexsys | 625 (624–626) | 101.25 | 104.02 | 3% | 5% | 2% |  |
| nginx | 625 (624–626) | 101.36 | 105.09 | 3% | 4% | 1% |  |
| haproxy | 625 (621–625) | 101.57 | 105.57 | 3% | 4% | 1% |  |
| envoy | 618 (615–620) | 102.43 | 110.85 | 9% | 5% | 1% |  |
| caddy | 625 (624–626) | 101.28 | 111.15 | 10% | 7% | 1% |  |
| traefik | 625 (624–625) | 101.37 | 111.94 | 11% | 7% | 1% |  |
| kong | 625 (623–625) | 101.49 | 105.24 | 7% | 5% | 1% |  |
| lexsys-base | 625 (624–625) | 101.22 | 103.53 | 3% | 5% | 2% |  |

#### C6 memory

| proxy | RSS before (MiB) | RSS with 100 idle connections (MiB) | connections still open |
|---|---|---|---|
| lexsys | 1.9 | 1.9 | 100 |
| nginx | 11.8 | 11.8 | 100 |
| haproxy | 14.9 | 14.9 | 100 |
| envoy | 58.2 | 58.9 | 100 |
| caddy | 31.9 | 32.4 | 100 |
| traefik | 82.8 | 83.2 | 100 |
| kong | 156.4 | 156.4 | 100 |
| lexsys-base | 1.9 | 1.9 | 100 |

### 10.4 Open-loop cross-check (oha, 6,000 requests/s, C1; all held the rate)

| proxy | p50 ms | p99 ms median | p99 min–max |
|---|---|---|---|
| lexsys | 0.54 | 2.44 | 1.67–3.91 |
| nginx | 0.35 | 1.78 | 1.29–1.96 |
| haproxy | 0.39 | 1.44 | 1.03–2.46 |
| envoy | 0.92 | 6.83 | 3.99–20.91 |
| caddy | 1.27 | 22.13 | 13.49–48.30 |
| traefik | 0.95 | 16.31 | 14.20–18.33 |
| kong | 0.65 | 7.08 | 3.94–10.44 |
| lexsys-base | 0.55 | 1.47 | 1.36–2.18 |

At a rate every proxy sustains, nginx and HAProxy have the lowest p99 (about 1.4 to 1.8 ms), `lexsys-base` is level with them (1.5) and `lexsys` is at 2.4 (its range overlaps theirs; this cell
was not repeated enough to rank them); Kong 7, Envoy 7, Traefik 16 and Caddy 22 ms. "Aborted due to deadline" counts (requests in flight when oha stopped) are not errors, as in 8.3.

### 10.5 What is still open

- **The remaining gap is per-connection work.** After the change the gateway makes 11 syscalls per request on C1 (accept4, setsockopt, fcntl ×2, epoll_ctl ×2, recvfrom ×2, sendto ×2, close),
  against about 5 for nginx and 4 for HAProxy, which reuse the client connection. What is left is client keep-alive, which is a design decision (smuggling and framing across requests), not tuning.
- **C4 (0.47 of nginx):** not yet profiled; the 16 KiB body moves through 16 KiB reads and 32 KiB queues and is copied twice; whether that explains a 2× gap is a hypothesis.
- **The nginx and HAProxy swings between the two runs are unexplained**; a third run on a quieter machine would say whether they are the neighbours or the harness.
- Memory (C6), unchanged by the change: gateway 1.9 MiB, nginx 11.8, HAProxy 14.9, Caddy 32, Envoy 59, Traefik 83, **Kong 156 MiB**, with 100 idle connections.
