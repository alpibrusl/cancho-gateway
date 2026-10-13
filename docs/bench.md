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

- lexsys-gateway does **less** than every other proxy here: no TLS (*corrected 2026-10-12: TLS 1.3 was built on 2026-10-08, and its cost is section 11; every cell of sections 8 to 10 is plain HTTP*), no HTTP/2, no client keep-alive (its client connections close after
  each response, so C1, C3, C4 and C5 force it to accept and close a connection per request while the others do not), no load balancing,
  no health checks beyond a passive circuit, no hot reload, no metrics. A number in its favour is not a claim that it is a better proxy.
- Each competitor does **more** beyond the plain reverse proxy it is configured as; their feature sets are not part of this table.
- One machine, one run of 5, a shared VM, loopback only, tiny bodies: it measures per-request overhead on one core, not production
  behaviour under real networks, TLS, many upstreams or long-lived connections.
- Versions differ in age (Caddy 2.6.2 is old; Traefik is 3.6.0, not the newest).

## 7. Reproducing

`python3 bench/run.py --help`. It needs the tools above on `PATH` (or `--bin NAME=PATH`), builds the gateway with `cancho` (`CANCHO`; before the rename of 2026-10-07, `lex-sys` and `LEX_SYS`), writes
the configs from `bench/conf/` into a scratch directory, and writes `results.json` and a markdown table.
Section 11's run: `python3 bench/run.py --proxies cancho,cancho-tlsplain,cancho-tls --cells C1,C3,C4,C6,C7,C8 --runs 5` (also needs `openssl` and `curl`), then `python3 bench/tls_lowrate.py --work <the same directory>`.


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

Resident set before and with 100 idle connections held for 3 s (*the gateway's figure is 2.6 MiB on `main` of 2026-10-12, section 11.5*): lexsys-gateway 1.9 MiB (no change), nginx 11.8, HAProxy 14.9, Caddy
32.2 to 32.7, Envoy 58.9 to 59.6, Traefik 83.5 to 83.9 MiB. All 100 connections stayed open. The gateway's number is small because it
allocates its slab and queues at start and touches few pages; this cell does **not** show memory under load, and the gateway's session
limit is about 127 (design.md), so 100 is near its ceiling while the others are far from theirs.

### 8.6 What this does and does not say

- It says that on this machine, one core, loopback, tiny bodies, lexsys-gateway sits between nginx/HAProxy and Envoy/Caddy/Traefik, and
  that its worst cell against nginx is the 16 KiB POST (0.42×).
- It does not say anything about TLS (section 11 measures it: the gateway serves about a 170th of its plain rate over TLS, because every request is a handshake), HTTP/2, many upstreams, real networks, long-lived connections, or the gateway under the
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
- Memory (C6), unchanged by the change: gateway 1.9 MiB, nginx 11.8, HAProxy 14.9, Caddy 32, Envoy 59, Traefik 83, **Kong 156 MiB**, with 100 idle connections. *(Corrected 2026-10-12, section 11.5: the gateway's figure on `main` is now 2.6 MiB; the others were not measured again.)*

## 11. Gate 9: what TLS costs (measured 2026-10-12; sections 1 to 10 above are unchanged except for the corrections marked in 6, 8.5, 8.6 and 10.5)

`docs/tls.md` section 8, gate 9, asked for the cost against the plain gateway in the same rounds. The protocol below was written with the harness change and before the recorded run; trial runs
changed four things in it, each named where it applies (the handshake cell, the client-bound mark, the bulk cell's length, the rate limits). The raw results are `bench/results/2026-10-12-tls.json`
(its `commit` is the harness commit the run started from; `src/` is `3560c05`'s, unchanged, and the harness changed after it only by lengthening C8, 11.2). The tables on `docs/evidence.html` are drawn from it by `scripts/figures.py`.

### 11.1 What is compared

Three proxies, one core each, started afresh for every run and rotated through the rounds like every other proxy here:

| name | what it is |
|---|---|
| `cancho` | the gateway as in section 1: one plain listener, no TLS configured |
| `cancho-tlsplain` | the **TLS build**: the same sources with `tls_listen`, one identity, and `listen`; measured on its **plain** port |
| `cancho-tls` | the same process as `cancho-tlsplain`, measured on its **TLS** port |

The same upstream (nginx, core 1), the same pinning, the same sanity requests (over TLS for the last), the same wrk on cores 2 and 3. In the TLS build `tls_rate` and `tls_handshakes` are set to their ceilings (100,000 a second
and 1,000): the defaults (50 a second, 32 at once) are a bound for a public edge and would hold every TLS cell to 50 requests/s, which is a finding (11.5), not a measurement of cost. A first trial printed the plain
gateway's number for the TLS proxy, because wrk was handed no scheme or port of the proxy's own; the harness passes both now.

### 11.2 The cells

- **C1, C3, C4 over TLS:** as in section 3 (`GET /`, a 64 KiB `GET /big`, a 16 KiB `POST /post`; 64 connections; 10 s after a 3 s warm-up; 5 interleaved rounds), with wrk given `https://`.
  **The gateway has no client keep-alive** (it closes after each response), so wrk's keep-alive connections are closed after every request and these cells are "a new connection, and over TLS a full handshake, per
  request" by construction, the same as C2. **The steady-state, per-request cost of an established TLS connection cannot be measured here**: there is no such request. What can be measured is the per-byte cost of an
  established connection: C8.
- **C6 over TLS:** 100 connections that have each *completed a TLS handshake* (Python's `ssl`, no verification), held 3 s, as C6 holds 100 plain ones. A bare TCP connection to the TLS port would sit in the handshake
  queue, not in a session.
- **C7, handshakes only (new):** `openssl s_time -new -time 10 -tls1_3`, four processes at once on the two load cores (3 s warm-up discarded), no request sent: how many full handshakes a second the gateway
  completes and how much of its CPU each costs (`/proc` ticks over the run, divided by the handshakes counted). *(The first version ran one `s_time`, which connects one at a time and so measured a round trip, 132 a second with
  the gateway at 79% of its core; four at once saturate it.)* **C7b:** the time of one handshake, one at a time, to an idle gateway, 300 of them from Python's `ssl` (so it includes Python's own work).
  `bench/tls_lowrate.py` measures the gateway's CPU per handshake at paced rates of 20, 50 and 100 a second (`bench/results/2026-10-12-tls-lowrate.txt`).
- **C8, steady state per byte (new):** one connection, one 64 MiB response (`/huge` on the upstream, one more `location` in `bench/conf/nginx-upstream.conf` that no other cell asks for), by `curl` on a load core, 20
  transfers one after another in each round (the first version took 5, and the CPU, counted in 10 ms ticks, was too coarse); the gateway's CPU is read per GiB moved. Plain and TLS, same build. The upstream's and curl's CPU are
  not sampled in this cell; the gateway's CPU over the run was about 95% of its core over TLS and 88% plain, so it is the limit in both.
- **RSS under load (new, every cell):** the resident set of the proxy's process at the end of the timed run (`rss_kib` in each record).

### 11.3 The machine, the certificate, the cipher

One shared Firecracker VM: Intel Xeon @ 2.8 GHz (AES-NI and AVX2 present), 4 vCPU, 16 GiB, Linux 6.18.44; proxy on core 0, upstream on core 1, clients on cores 2 and 3 (section 2). wrk 4.1.0, curl 8.5.0 and
`openssl s_time` all use OpenSSL 3.0.13. Certificate: ECDSA P-256 (`prime256v1`), self-signed, `CN=bench.example`, `ecdsa-with-SHA256`, one identity (the only type the gateway's TLS engine has); nobody verifies it
(wrk, `curl -k`); no session resumption (the engine has none). What a default OpenSSL client negotiates with the running listener (`openssl s_client -tls1_3`, recorded in the JSON): **TLS 1.3,
`TLS_AES_128_GCM_SHA256`, key exchange X25519, signature ECDSA with SHA-256**. The engine chooses, so the other two suites it has (AES-256-GCM, ChaCha20-Poly1305) were not measured; wrk's and curl's own negotiated suites are
not printed by them and are assumed to be `s_client`'s, which links the same library. The shared machine drifted during the run as it did in section 9: in rounds 2 and 3 the plain gateway's own C1 fell to
25 and 27 thousand and its CPU to 85%, which is why every ratio below is **paired within a round**.

### 11.4 Validity

No run of any cell had a non-2xx response or a socket error. Over TLS wrk used 71% to 98% of its two cores, and the CLIENT-BOUND rule of section 4 would have marked most of the runs; **it is replaced for `https://` by a
mark called WRK-SPIN, and the numbers are quoted**, because the rule's premise is false there: wrk polls a connection that is still handshaking. Measured by hand once during this work (not recorded in `bench/results`):
`wrk -t1 -c1` over TLS made 126 requests/s and used 3.81 s of CPU in 4 s (95% of a core), while one client handshake costs about 1 ms of CPU (`s_time`: 1.92 s for 1,806 handshakes), about 13% of that. What bounds
the TLS cells is the gateway: its CPU was 98 to 100% in every one, the upstream's at most 1%.

### 11.5 Results (medians of 5 rounds, min and max in brackets; the same figures are in the JSON and on `docs/evidence.html`)

| cell | plain build | TLS build, plain port | TLS build, **TLS port** | TLS ÷ plain build (paired per round) |
|---|---|---|---|---|
| C1 requests/s | 26,991 (25,150–29,687) | 23,412 (22,240–27,482) | **157** (150–160) | **0.0059** (0.0054–0.0063), 1 in 170 |
| C1 p50 / p99 ms | 1.94 / 5.94 | 1.79 / 7.65 | **192 / 377** | |
| C1 gateway CPU per request | 34 µs | 36 µs | **6.2 ms** | |
| C3 requests/s (64 KiB) | 8,548 (8,049–9,688) | 8,202 (7,827–8,225) | **149** (145–158) | **0.0176** (0.0154–0.0187), 1 in 57 |
| C3 p50 / p99 ms | 7.11 / 13.20 | 7.28 / 15.14 | **280 / 447** | |
| C4 requests/s (16 KiB POST) | 10,865 (10,353–11,085) | 10,493 (9,844–11,296) | **159** (152–161) | **0.0147** (0.0139–0.0155), 1 in 68 |
| C4 p50 / p99 ms | 5.53 / 11.74 | 5.87 / 11.89 | **190 / 377** | |
| C7 handshakes/s, flat out | | | **167** (164–172), gateway at 98% | |
| C7 gateway CPU per handshake | | | **5.9 ms** (5.75–5.97) | |
| C7b one handshake, idle gateway | | | p50 7.5, p99 13.5 ms (Python client) | |
| `tls_lowrate.py`, CPU per handshake | | | 7.0 ms at 20/s (14% of the core), 6.9 at 50/s (34%), 6.9 at 100/s (69%) | |
| C8 one connection, 64 MiB, MiB/s | 695 (668–739) | 673 (628–761) | **199** (196–200) | 0.29 |
| C8 gateway CPU per GiB | 1.41 s | 1.47 s | **5.01 s** | 3.6× |
| C6 RSS idle / with 100 idle connections, MiB | 2.6 / 2.6 | 2.9 / 2.9 | **3.1 / 13.9** (100 completed handshakes) | |
| RSS after the load, MiB (C1 / C3 / C4) | 3.6 / 5.4 / 7.8 | 3.9 / 5.7 / 8.4 | **20.7 / 27.0 / 36.2** | |

**Plainly.**

- **Over TLS the gateway serves about 157 requests a second from a core: a 170th of what it serves plain on C1, a 57th on C3 and a 68th on C4.** The cost is the handshake, 5.9 to 7 ms of the gateway's CPU each, and
  because it keeps no client connection open **every request is a handshake**. Of the 6.2 ms a request costs on C1, 5.9 is the handshake; the 64 KiB response of C3 adds 0.36 ms, about what C8's 5.0 s a GiB gives for
  64 KiB (0.31 ms), and the 16 KiB body of C4 adds nothing the noise does not hide.
- **The latency is queueing, not a slow handshake:** with 64 clients and 157 requests a second each waits about 64 ÷ 157 = 0.4 s for its turn and the median is about half that. One client alone, to an idle gateway,
  sees a handshake in 7.5 ms (p99 13.5, Python's client included).
- **An established connection, by the byte (C8):** TLS moves 199 MiB/s against 695 plain and costs 3.6 times the CPU for the bytes (5.0 against 1.4 s a GiB). That agrees with the 3.6 to 4.2 times `docs/tls.md`
  section 1 quotes for cancho's own server and with the informal "about three" of its section 10; it is only the part of the cost that a connection which stayed open would pay, and **this gateway's connections do
  not stay open**.
- **The default `tls_rate = 50` is below the gateway's ceiling, on purpose:** it allows 34% of the core to handshakes at this machine's 6.9 ms; the flat-out ceiling is 167 a second. A deployment at the default
  serves at most 50 new HTTPS connections, so at most 50 requests, a second.
- **The TLS build's plain port is not clearly different from the plain build:** paired, 0.90 (0.80–1.02) on C1, 0.93 (0.85–1.02) on C3, 0.99 (0.91–1.06) on C4, and 0.3 MiB more at idle. Two of the three are inside the
  VM's drift; whether C1 carries a real cost of up to 10% for what a TLS-capable build keeps on the plain path is **not resolved** by this run.
- **Memory:** 0.3 MiB more at idle for a build that can serve TLS (2.6 against 2.9) and 3.1 after one TLS request; 110 KiB for each established TLS connection (100 of them: 13.9 MiB, the figure section 10 of
  `docs/tls.md` gave informally); and **17 to 28 MiB more than the plain build after a 64-connection load** (C1 to C4). `docs/tls.md` section 4 estimated about 23 MiB more with all 256 slots touched; the C4 figure is above
  it by 5 MiB. The cause was not investigated.
- **The plain build's idle memory is 2.6 MiB on this commit, not the 1.9 MiB of sections 8 and 10:** the slices since (TLS, WebSocket, rate limiting, authentication) grew it. The others' figures were not measured again.
- **The handshake is 5.9 ms here (7 ms at low rates), not the 12.0 ms of `docs/tls.md` section 10's informal measurement,** which this run does not reproduce and which is not explained (that run's machine and
  clients were different). The informal figure had set the default `tls_rate` and its "60% of a core" comment; both are corrected in `docs/tls.md` and `scripts/generate.py`, the default value is not changed.

### 11.6 What this does not say

- Nothing about how nginx, HAProxy or Caddy do the same: no other proxy was run with TLS here, so "slow for a TLS terminator" is not established; what is is the 170 times against the gateway's own plain port.
- One cipher suite, one key type, one core, loopback, no verification, no resumption (none exists), no client certificates, no network latency, no failure paths (a refused or aborted handshake costs differently).
- Not measured: several cores (the gateway has one thread), TLS to the upstreams (there is none), the by-client index of `docs/tls.md` question 5, and what the memory excess over 23 MiB is.
- The p99 values over TLS rest on about 1,500 requests a run.
- **Whether a client keep-alive would change this is the obvious next measurement, and it is a design decision** (`docs/proxy.md`: framing across requests): with it the cost of a request would approach C8's
  per-byte figure and the 3.6 to 4.2 times of cancho's own server, instead of 170.
