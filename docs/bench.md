# Benchmark against the top open-source proxies (task #14)

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

`python3 bench/run.py --help`. It needs the tools above on `PATH` (or `--bin NAME=PATH`), builds the gateway with `lex-sys` (`LEX_SYS`), writes
the configs from `bench/conf/` into a scratch directory, and writes `results.json` and a markdown table.
