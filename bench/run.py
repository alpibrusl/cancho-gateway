#!/usr/bin/env python3
"""The benchmark harness (task #14, docs/bench.md). The protocol there is fixed; this file only carries it out.

    python3 bench/run.py --work /tmp/bench --runs 5            # every proxy, every cell
    python3 bench/run.py --proxies nginx,cancho --cells C1 --runs 1 --duration 3 --warmup 1   # a quick check
    python3 bench/run.py --oha-rate 3000 ...                   # also the open-loop oha cross-check on C1, at 3000 requests/s

    python3 bench/run.py --proxies cancho,cancho-tlsplain,cancho-tls --cells C1,C3,C4,C6,C7,C8   # gate 9, the cost of TLS (docs/tls.md, docs/bench.md section 11)

Needs on PATH (or --bin NAME=PATH): nginx haproxy envoy caddy traefik wrk oha slow_upstream cancho taskset (and openssl, curl for the TLS cells).
Writes RESULTS.json and RESULTS.md into --work. One proxy at a time is started afresh for each run and stopped after it.
"""

import argparse
import http.client
import json
import os
import pathlib
import re
import shutil
import signal
import socket
import ssl
import statistics
import subprocess
import sys
import time

ROOT = pathlib.Path(__file__).resolve().parent.parent
CONF = ROOT / "bench" / "conf"
PORT, UP, TLS_PORT = 18080, 19090, 18443
TLS_PROXIES = ("cancho-tls", "cancho-tlsplain")  # one build with both listeners: the first is measured on the TLS port, the second on the plain port
PROXY_CORE, UP_CORE, LOAD_CORES = "0", "1", "2,3"
TICKS = os.sysconf("SC_CLK_TCK")
ALL_PROXIES = ["cancho", "nginx", "haproxy", "envoy", "caddy", "traefik", "kong"]
CELLS = {
    "C1": dict(path="/", conns=64, extra=[], want=2),
    "C1b": dict(path="/", conns=8, extra=[], want=2),
    "C2": dict(path="/", conns=64, extra=["-H", "Connection: close"], want=2),
    "C3": dict(path="/big", conns=64, extra=[], want=65536),
    "C4": dict(path="/post", conns=64, extra=["-s", str(ROOT / "bench" / "post.lua")], want=2),
    "C5": dict(path="/", conns=64, extra=[], want=2, slow=True),
}
BULK_MIB = 64  # C8: one connection, one response of this many MiB (/huge on the upstream)


def endpoint(name):
    """(scheme, port) a proxy is reached on. Only the TLS build's TLS listener speaks https."""
    return ("https", TLS_PORT) if name == "cancho-tls" else ("http", PORT)


def which(args, name):
    return args.bins.get(name) or shutil.which(name) or sys.exit(f"{name}: not found (use --bin {name}=PATH)")


def stat_fields(pid):
    try:
        raw = pathlib.Path(f"/proc/{pid}/stat").read_text()
    except OSError:
        return None
    return raw[raw.rindex(")") + 2:].split()  # field 3 (state) is index 0


def group_ticks(pgid):
    """CPU ticks (user + system) of every live process in the process group."""
    total = 0
    for entry in os.listdir("/proc"):
        if entry.isdigit():
            f = stat_fields(entry)
            if f and int(f[2]) == pgid:
                total += int(f[11]) + int(f[12])
    return total


def rss_kib(pgid):
    total = 0
    for entry in os.listdir("/proc"):
        if entry.isdigit():
            f = stat_fields(entry)
            if f and int(f[2]) == pgid:
                try:
                    for line in pathlib.Path(f"/proc/{entry}/status").read_text().splitlines():
                        if line.startswith("VmRSS:"):
                            total += int(line.split()[1])
                except OSError:
                    pass
    return total


class Proc:
    def __init__(self, argv, core, env=None, log=None, port=None):
        self.port = port
        e = dict(os.environ, **(env or {}))
        self.p = subprocess.Popen(["taskset", "-c", core] + argv, env=e, start_new_session=True,
                                  stdout=open(log or os.devnull, "wb"), stderr=subprocess.STDOUT)
        self.pgid = self.p.pid

    def stop(self):
        try:
            os.killpg(self.pgid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            self.p.wait(5)
        except subprocess.TimeoutExpired:
            pass
        try:
            os.killpg(self.pgid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        self.p.wait()
        # A proxy that is still shutting down keeps its port: the next one would see it "listening" and then lose the bind.
        end = time.time() + 20
        while self.port and time.time() < end:
            try:
                socket.create_connection(("127.0.0.1", self.port), 0.2).close()
                time.sleep(0.2)
            except OSError:
                break


def wait_port(port, seconds=20):
    end = time.time() + seconds
    while time.time() < end:
        try:
            socket.create_connection(("127.0.0.1", port), 0.5).close()
            return True
        except OSError:
            time.sleep(0.1)
    return False


def request(method, path, body=None, ep=("http", PORT)):
    if ep[0] == "https":
        ctx = ssl.create_default_context()
        ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE  # the measurement's own sanity check, not a trust decision (wrk does not verify either)
        c = http.client.HTTPSConnection("127.0.0.1", ep[1], timeout=10, context=ctx)
    else:
        c = http.client.HTTPConnection("127.0.0.1", ep[1], timeout=10)
    try:
        c.request(method, path, body=body, headers={"Connection": "close"})
        r = c.getresponse()
        data = r.read()
        return r.status, len(data)
    finally:
        c.close()


def sanity(slow=False, ep=("http", PORT)):
    """The three requests of section 4 (only GET / against the slow upstream of C5, which has no /big). Returns None when right, else a reason."""
    checks = [("GET", "/", None, 2), ("GET", "/big", None, 65536), ("POST", "/post", b"x" * 16384, 2)]
    for method, path, body, want in checks[:1] if slow else checks:
        deadline, last = time.time() + 15, None
        while time.time() < deadline:
            try:
                got = request(method, path, body, ep)
            except (OSError, http.client.HTTPException) as e:
                got = repr(e)
            if got == (200, want):
                last = None
                break
            last = f"{method} {path}: expected (200, {want}), got {got}"
            time.sleep(0.3)
        if last:
            return last
    return None


def prepare(args):
    work = args.work
    work.mkdir(parents=True, exist_ok=True)
    (work / "www").mkdir(exist_ok=True)
    (work / "www" / "big.bin").write_bytes(b"\0" * 65536)
    if not (work / "www" / "huge.bin").exists():
        (work / "www" / "huge.bin").write_bytes(b"\0" * (BULK_MIB << 20))
    subs = {"@PORT@": str(PORT), "@UP@": str(UP), "@DIR@": str(work)}
    for src in CONF.iterdir():
        text = src.read_text()
        for k, v in subs.items():
            text = text.replace(k, v)
        (work / src.name).write_text(text)
    # The gateway: this repository, copied, with a deployment of one route to the one upstream. With --baseline-rev, the same
    # from that revision as well (proxy "cancho-base"), so that a change to the gateway is measured against its own earlier build
    # in the same interleaved rounds, not against numbers from another time of day.
    if any(n not in TLS_PROXIES for n in args.proxies.split(",")):
        build_gateway(args, ROOT, work / "gw", from_rev=None)
    if any(n in args.proxies.split(",") for n in TLS_PROXIES):
        make_certificate(work / "certs" / "bench")
        build_gateway(args, ROOT, work / "gw-tls", from_rev=None, tls_dir=work / "certs")
    if args.baseline_rev:
        build_gateway(args, ROOT, work / "gw-base", from_rev=args.baseline_rev)
    if "kong" in args.proxies.split(","):
        if not args.kong_root:
            sys.exit("kong needs --kong-root (an extracted kong image, with /dev and /proc mounted in it; docs/bench.md section 9)")
        (args.kong_root / "bench").mkdir(exist_ok=True)
        (args.kong_root / "bench" / "kong.yml").write_text((work / "kong.yml").read_text())
    for d in ["nginx-body", "nginx-proxy", "nginx-fcgi", "nginx-uwsgi", "nginx-scgi", "up-body", "up-proxy", "up-fcgi", "up-uwsgi", "up-scgi"]:
        (work / d).mkdir(exist_ok=True)


def make_certificate(d):
    """The one identity the TLS build serves: an ECDSA P-256 key and a self-signed certificate (the only type the gateway's TLS engine has), 30 days."""
    d.mkdir(parents=True, exist_ok=True)
    subprocess.run(f"openssl ecparam -name prime256v1 -genkey -noout | openssl pkcs8 -topk8 -nocrypt -out {d / 'key.pem'}", shell=True, check=True,
                   capture_output=True)
    subprocess.run(["openssl", "req", "-new", "-x509", "-key", str(d / "key.pem"), "-out", str(d / "chain.pem"), "-days", "30", "-subj", "/CN=bench.example",
                    "-addext", "subjectAltName=DNS:bench.example"], check=True, capture_output=True)
    (d / "names").write_text("bench.example\n")


def build_gateway(args, root, dest, from_rev, tls_dir=None):
    if dest.exists():
        shutil.rmtree(dest)
    dest.mkdir(parents=True)
    if from_rev:
        tar = subprocess.run(["git", "archive", from_rev, "src", "scripts", "generated", "cancho.toml", "authority.toml"], cwd=root,
                             check=True, capture_output=True).stdout
        subprocess.run(["tar", "-x", "-C", str(dest)], input=tar, check=True)
    else:
        for d in ["src", "scripts", "generated"]:
            shutil.copytree(root / d, dest / d)
        for f in ["cancho.toml", "authority.toml"]:
            shutil.copy(root / f, dest / f)
    # The TLS build serves the plain port and the TLS port from one process. tls_rate and tls_handshakes are raised to their ceilings: the defaults
    # (50 handshakes a second, 32 at once) are a safety bound for a public edge and would cap every TLS cell here at 50 requests/s (docs/bench.md section 11).
    tls = (f'tls_listen = {TLS_PORT}\ntls_dir = "{tls_dir}"\ntls_identities = ["bench"]\ntls_handshakes = 1000\ntls_rate = 100000\n') if tls_dir else ""
    (dest / "deploy.toml").write_text(
        f'listen = {PORT}\n{tls}pool_idle_max = 64\n\n[[upstream]]\nname = "u"\naddr = "127.0.0.1:{UP}"\n\n'
        '[[route]]\nname = "all"\npath_prefix = "/"\nupstream = "u"\n')
    subprocess.run([sys.executable, str(dest / "scripts" / "generate.py"), str(dest / "deploy.toml")], check=True, cwd=dest)
    # CANCHO_IGNORE_REV=1: build with a compiler other than the pinned one (a local check only; recorded runs use the pinned compiler).
    subprocess.run([which(args, "cancho"), "build"] + (["--ignore-compiler-rev"] if os.environ.get("CANCHO_IGNORE_REV") else []), check=True, cwd=dest)


def proxy_cmd(args, name):
    w = args.work
    if name == "cancho":
        return [str(w / "gw" / "build" / "gateway")], {}
    if name in TLS_PROXIES:
        return [str(w / "gw-tls" / "build" / "gateway")], {}
    if name == "cancho-base":
        return [str(w / "gw-base" / "build" / "gateway")], {}
    if name == "kong":
        shutil.rmtree(args.kong_root / "tmp" / "kong-prefix", ignore_errors=True)
        env = dict(KONG_DATABASE="off", KONG_DECLARATIVE_CONFIG="/bench/kong.yml", KONG_PROXY_LISTEN=f"127.0.0.1:{PORT}",
                   KONG_ADMIN_LISTEN="off", KONG_STATUS_LISTEN="off", KONG_NGINX_WORKER_PROCESSES="1", KONG_NGINX_DAEMON="off",
                   KONG_PROXY_ACCESS_LOG="off", KONG_ADMIN_ACCESS_LOG="off", KONG_PROXY_ERROR_LOG="/dev/null", KONG_LOG_LEVEL="error",
                   KONG_PLUGINS="off", KONG_PREFIX="/tmp/kong-prefix", KONG_ANONYMOUS_REPORTS="off",
                   KONG_NGINX_HTTP_CLIENT_BODY_BUFFER_SIZE="64k", KONG_DNS_RESOLVER="127.0.0.1", KONG_NGINX_MAIN_USER="root")
        return ["chroot", str(args.kong_root), "/usr/local/bin/kong", "start"], env
    if name == "nginx":
        return [which(args, "nginx"), "-c", str(w / "nginx.conf"), "-g", "daemon off;"], {}
    if name == "haproxy":
        return [which(args, "haproxy"), "-f", str(w / "haproxy.cfg")], {}
    if name == "envoy":
        return [which(args, "envoy"), "-c", str(w / "envoy.yaml"), "--concurrency", "1", "--log-level", "error",
                "--base-id", "77"], {}
    if name == "caddy":
        return [which(args, "caddy"), "run", "--config", str(w / "Caddyfile"), "--adapter", "caddyfile"], {"GOMAXPROCS": "1"}
    if name == "traefik":
        return [which(args, "traefik"), "--configfile", str(w / "traefik.yml")], {"GOMAXPROCS": "1"}
    sys.exit(f"unknown proxy {name}")


def start_upstream(args, slow):
    if slow:
        return Proc([which(args, "slow_upstream"), "-port", str(UP)], UP_CORE, {"GOMAXPROCS": "1"})
    return Proc([which(args, "nginx"), "-c", str(args.work / "nginx-upstream.conf"), "-g", "daemon off;"], UP_CORE)


def seconds(text):
    m = re.fullmatch(r"([\d.]+)(us|ms|s|m)", text)
    return float(m.group(1)) * {"us": 1e-6, "ms": 1e-3, "s": 1, "m": 60}[m.group(2)]


def run_wrk(args, cell, duration, proxy, upstream, ep=("http", PORT)):
    c = CELLS[cell]
    url = f"{ep[0]}://127.0.0.1:{ep[1]}{c['path']}"
    out = args.work / "wrk.out"
    argv = ["taskset", "-c", LOAD_CORES, which(args, "wrk"), "-t2", f"-c{c['conns']}", f"-d{duration}s", "--latency"] + c["extra"] + [url]
    pt0, ut0, t0 = group_ticks(proxy.pgid), group_ticks(upstream.pgid), time.time()
    p = subprocess.Popen(argv, stdout=open(out, "wb"), stderr=subprocess.STDOUT)
    _, _, ru = os.wait4(p.pid, 0)
    p.returncode = 0
    wall = time.time() - t0
    pt1, ut1 = group_ticks(proxy.pgid), group_ticks(upstream.pgid)
    rss = rss_kib(proxy.pgid)  # the proxy's resident set at the end of the load (docs/bench.md section 11)
    return parse_wrk(out.read_text()), dict(
        wall=wall, rss_kib=rss, load_cpu=(ru.ru_utime + ru.ru_stime) / (2 * wall),
        proxy_cpu=(pt1 - pt0) / TICKS / wall, up_cpu=(ut1 - ut0) / TICKS / wall)


def parse_wrk(text):
    r = {"rps": None, "p50": None, "p99": None, "non2xx": 0, "errors": 0, "raw_errors": ""}
    m = re.search(r"Requests/sec:\s+([\d.]+)", text)
    if m:
        r["rps"] = float(m.group(1))
    for key, label in (("p50", "50%"), ("p99", "99%")):
        m = re.search(rf"^\s+{re.escape(label)}\s+([\d.]+(?:us|ms|s|m))", text, re.M)
        if m:
            r[key] = seconds(m.group(1)) * 1000  # ms
    m = re.search(r"Non-2xx or 3xx responses:\s+(\d+)", text)
    if m:
        r["non2xx"] = int(m.group(1))
    m = re.search(r"Socket errors: (.*)", text)
    if m:
        r["raw_errors"] = m.group(1)
        r["errors"] = sum(int(n) for n in re.findall(r"\d+", m.group(1)))
    return r


def run_oha(args, rate, duration, proxy, upstream):
    argv = ["taskset", "-c", LOAD_CORES, which(args, "oha"), "-z", f"{duration}s", "-c", "64", "-q", str(rate),
            "--latency-correction", "--no-tui", "--output-format", "json", f"http://127.0.0.1:{PORT}/"]
    pt0, ut0, t0 = group_ticks(proxy.pgid), group_ticks(upstream.pgid), time.time()
    p = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err = p.communicate()
    wall = time.time() - t0
    pt1, ut1 = group_ticks(proxy.pgid), group_ticks(upstream.pgid)
    j = json.loads(out)
    codes = j.get("statusCodeDistribution", {})
    bad = sum(n for k, n in codes.items() if not k.startswith("2"))
    pct = j["latencyPercentiles"]
    return dict(rps=j["summary"]["requestsPerSec"], p50=pct["p50"] * 1000, p99=pct["p99"] * 1000, non2xx=bad,
                errors=sum(j.get("errorDistribution", {}).values()), raw_errors=json.dumps(j.get("errorDistribution", {})),
                success=j["summary"]["successRate"]), dict(wall=wall, proxy_cpu=(pt1 - pt0) / TICKS / wall,
                                                           up_cpu=(ut1 - ut0) / TICKS / wall, load_cpu=None)


def start_proxy(args, name, slow=False):
    argv, env = proxy_cmd(args, name)
    ep = endpoint(name)
    proxy = Proc(argv, PROXY_CORE, env, args.work / f"{name}.log", ep[1])
    if not wait_port(ep[1]):
        proxy.stop()
        return None, f"{name} did not listen on port {ep[1]} within 20 s (see {name}.log)"
    bad = sanity(slow, ep)
    if bad:
        proxy.stop()
        return None, bad
    return proxy, None


def measure_memory(args, name):
    proxy, bad = start_proxy(args, name)
    if not proxy:
        return {"error": bad}
    time.sleep(1)
    before = rss_kib(proxy.pgid)
    socks = []
    scheme, port = endpoint(name)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
    try:
        for _ in range(100):
            s = socket.create_connection(("127.0.0.1", port), 2)
            # Over TLS the 100 connections are 100 completed handshakes (a bare TCP connection would sit in the handshake queue, not in a session).
            socks.append(ctx.wrap_socket(s, server_hostname="bench.example") if scheme == "https" else s)
    except OSError as e:
        proxy.stop()
        return {"error": f"could not hold 100 connections: {e!r}", "before_kib": before}
    time.sleep(3)
    after = rss_kib(proxy.pgid)
    alive = 0
    for s in socks:
        s.settimeout(0.01)
        try:
            alive += 0 if s.recv(1) == b"" else 1
        except socket.timeout:
            alive += 1
        except OSError:
            pass
    for s in socks:
        s.close()
    proxy.stop()
    return {"before_kib": before, "after_kib": after, "still_open": alive}


def machine_info():
    """What the numbers were measured on, recorded with them (docs/bench.md section 11)."""
    def first(argv):
        try:
            return subprocess.run(argv, capture_output=True, text=True).stdout.splitlines()[0].strip()
        except (OSError, IndexError):
            return ""
    cpuinfo = pathlib.Path("/proc/cpuinfo").read_text().splitlines()
    cpu = next((l.split(":", 1)[1].strip() for l in cpuinfo if l.startswith("model name")), "")
    mem = next((int(l.split()[1]) // 1024 for l in pathlib.Path("/proc/meminfo").read_text().splitlines() if l.startswith("MemTotal")), 0)
    flag_line = " " + next((l for l in cpuinfo if l.startswith("flags")), "") + " "
    return dict(cpu=cpu, cpus=os.cpu_count(), mem_mib=mem, kernel=first(["uname", "-r"]), openssl=first(["openssl", "version"]), curl=first(["curl", "--version"]),
                wrk=first(["wrk", "--version"]), nginx=subprocess.run(["nginx", "-v"], capture_output=True, text=True).stderr.strip(),
                aes_ni=" aes " in flag_line, avx2=" avx2 " in flag_line)


def tls_info(args):
    """The certificate and what a default OpenSSL client negotiates with the running TLS listener (wrk and curl are OpenSSL clients too)."""
    out = subprocess.run(["openssl", "s_client", "-connect", f"127.0.0.1:{TLS_PORT}", "-tls1_3", "-brief"], input="", capture_output=True, text=True, timeout=10)
    got = {k.strip(): v.strip() for k, _, v in (l.partition(":") for l in (out.stdout + out.stderr).splitlines()) if k.strip() in
           ("Protocol version", "Ciphersuite", "Hash used", "Signature type", "Server Temp Key")}
    cert = subprocess.run(["openssl", "x509", "-in", str(args.work / "certs" / "bench" / "chain.pem"), "-noout", "-text"], capture_output=True, text=True).stdout
    got["certificate"] = ", ".join(l.strip() for l in cert.splitlines() if "Signature Algorithm" in l or "Public-Key" in l or "ASN1 OID" in l)[:300]
    return got


def run_handshakes(args, duration, proxy):
    """C7: full handshakes only, as fast as the gateway takes them: `openssl s_time -new` connects, handshakes, closes. No request is sent."""
    # One s_time makes its connections one after another, so it measures a round trip, not what the gateway can do: four run at once, two on each load core.
    argv = ["taskset", "-c", LOAD_CORES, "openssl", "s_time", "-connect", f"127.0.0.1:{TLS_PORT}", "-new", "-time", str(duration), "-tls1_3"]
    pt0, t0 = group_ticks(proxy.pgid), time.time()
    procs = [subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True) for _ in range(4)]
    outs = [p.communicate(timeout=duration + 60)[0] for p in procs]
    wall = time.time() - t0
    pt1 = group_ticks(proxy.pgid)
    ms = [re.search(r"(\d+) connections in ([\d.]+)s", o) for o in outs]
    n = sum(int(m.group(1)) for m in ms if m)
    cpu = (pt1 - pt0) / TICKS
    return dict(handshakes=n, wall=wall, rate=n / wall if n else 0, proxy_cpu=cpu / wall, cpu_ms_per_handshake=cpu / n * 1000 if n else None,
                client_cpu_s=sum(float(m.group(2)) for m in ms if m), rss_kib=rss_kib(proxy.pgid), marks=[] if n and all(ms) else ["INVALID"])


def handshake_latency(count=300):
    """C7b: the time of one full handshake to an otherwise idle gateway, one at a time, from Python's ssl (so it includes Python's own client work)."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ts = []
    old = os.sched_getaffinity(0)
    os.sched_setaffinity(0, {int(c) for c in LOAD_CORES.split(",")})
    try:
        for _ in range(count):
            t = time.perf_counter()
            with socket.create_connection(("127.0.0.1", TLS_PORT), 5) as s:
                ctx.wrap_socket(s, server_hostname="bench.example").close()
            ts.append((time.perf_counter() - t) * 1000)
            time.sleep(0.02)  # well under tls_rate, and the gateway idle between handshakes
    finally:
        os.sched_setaffinity(0, old)
    ts.sort()
    return dict(p50=ts[len(ts) // 2], p99=ts[int(len(ts) * 0.99) - 1], n=len(ts))


def run_bulk(args, proxy, name, transfers=20):
    """C8: the steady state, one connection moving a 64 MiB response (the 16 KiB records of TLS against plain bytes). curl, one transfer at a time."""
    scheme, port = endpoint(name)
    argv = ["taskset", "-c", LOAD_CORES, "curl", "-sk", "-o", "/dev/null", "-w", "%{size_download} %{time_total} %{http_code}", f"{scheme}://127.0.0.1:{port}/huge"]
    subprocess.run(argv, capture_output=True, timeout=60)  # warm-up, discarded
    secs, bad = [], 0
    pt0, t0 = group_ticks(proxy.pgid), time.time()
    for _ in range(transfers):
        out = subprocess.run(argv, capture_output=True, text=True, timeout=60).stdout.split()
        if len(out) != 3 or out[0] != str(BULK_MIB << 20) or out[2] != "200":
            bad += 1
        else:
            secs.append(float(out[1]))
    wall = time.time() - t0
    cpu = (group_ticks(proxy.pgid) - pt0) / TICKS
    n = len(secs)
    return dict(transfers=n, bad=bad, mib_s=BULK_MIB * n / sum(secs) if n else 0, ms_each=1000 * sum(secs) / n if n else None,
                cpu_s_per_gib=cpu / (BULK_MIB * transfers / 1024), rss_kib=rss_kib(proxy.pgid), wall=wall, marks=["INVALID"] if bad or not n else [])


def flags(cell, wrk, load, tls=False):
    marks = []
    if wrk["non2xx"] or wrk["errors"]:
        marks.append("INVALID")
    if load.get("load_cpu") is not None and load["load_cpu"] > 0.9:
        # wrk polls a connection that is still handshaking: one thread, one connection, 126 requests/s measured 95% of a core, of which about 13% is
        # the handshake's own work (docs/bench.md section 11). Over TLS a high figure here is not a bound; the proxy's CPU and the upstream's are the evidence.
        marks.append("WRK-SPIN" if tls else "CLIENT-BOUND")
    if load["up_cpu"] > 0.9:
        marks.append("UPSTREAM-BOUND")
    return marks


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--work", type=pathlib.Path, default=pathlib.Path("/tmp/cancho-bench"))
    ap.add_argument("--runs", type=int, default=5)
    ap.add_argument("--duration", type=int, default=10)
    ap.add_argument("--warmup", type=int, default=3)
    ap.add_argument("--proxies", default=",".join(ALL_PROXIES))
    ap.add_argument("--cells", default="C1,C1b,C2,C3,C4,C5,C6")
    ap.add_argument("--oha-rate", type=int, default=0, help="also run oha at this open-loop rate on C1 (requests/s)")
    ap.add_argument("--resume", action="store_true", help="continue from RESULTS.json in --work: runs already recorded are not repeated")
    ap.add_argument("--baseline-rev", help="also build and measure this git revision of the gateway, as the proxy cancho-base")
    ap.add_argument("--kong-root", type=pathlib.Path, help="an extracted Kong image (chroot), with /dev and /proc bind-mounted into it")
    ap.add_argument("--bin", action="append", default=[], metavar="NAME=PATH")
    args = ap.parse_args()
    args.bins = dict(b.split("=", 1) for b in args.bin)
    args.work = args.work.resolve()
    if args.baseline_rev and "cancho-base" not in args.proxies:
        args.proxies += ",cancho-base"
    proxies = args.proxies.split(",")
    cells = args.cells.split(",")
    prepare(args)
    results = {"commit": subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True, text=True).stdout.strip(),
               "runs": args.runs, "duration": args.duration, "warmup": args.warmup, "cells": {}, "memory": {}, "notworking": {},
               "machine": machine_info()}
    out_json = args.work / "RESULTS.json"
    if args.resume and out_json.exists():
        results = json.loads(out_json.read_text())
    done = lambda cell, name, rnd: any(r["run"] == rnd for r in results["cells"].get(cell, {}).get(name, []))
    upstream = None
    upstream_slow = None

    def ensure_upstream(slow):
        nonlocal upstream, upstream_slow
        if upstream is not None and upstream_slow == slow:
            return
        if upstream is not None:
            upstream.stop()
        upstream, upstream_slow = start_upstream(args, slow), slow
        if not wait_port(UP):
            sys.exit("the upstream did not start")

    try:
        timed = [c for c in cells if c in CELLS]
        timed.sort(key=lambda c: bool(CELLS[c].get("slow")))  # the slow upstream last, so it is started once a round
        for rnd in range(args.runs):
            rot = proxies[rnd % len(proxies):] + proxies[:rnd % len(proxies)]
            for cell in timed:
                ensure_upstream(bool(CELLS[cell].get("slow")))
                for name in rot:
                    if name in results["notworking"] or done(cell, name, rnd):
                        continue
                    proxy, bad = start_proxy(args, name, bool(CELLS[cell].get("slow")))
                    if not proxy:
                        results["notworking"][name] = bad
                        print(f"[{name}] not working in this setup: {bad}", flush=True)
                        continue
                    try:
                        run_wrk(args, cell, args.warmup, proxy, upstream, endpoint(name))  # discarded
                        wrk, load = run_wrk(args, cell, args.duration, proxy, upstream, endpoint(name))
                        if cell == "C1" and args.oha_rate:
                            run_oha_result = run_oha(args, args.oha_rate, args.duration, proxy, upstream)
                            results["cells"].setdefault("C1-oha", {}).setdefault(name, []).append(
                                dict(run=rnd, **run_oha_result[0], **{"cpu_" + k: v for k, v in run_oha_result[1].items()}))
                    finally:
                        proxy.stop()
                    rec = dict(run=rnd, **wrk, **load, marks=flags(cell, wrk, load, endpoint(name)[0] == "https"))
                    results["cells"].setdefault(cell, {}).setdefault(name, []).append(rec)
                    print(f"[{rnd}] {cell:3} {name:8} rps={wrk['rps']} p50={wrk['p50']} p99={wrk['p99']} "
                          f"n2xx={wrk['non2xx']} err={wrk['errors']} proxy={load['proxy_cpu']:.2f} up={load['up_cpu']:.2f} "
                          f"load={load['load_cpu']:.2f} {rec['marks']}", flush=True)
                    out_json.write_text(json.dumps(results, indent=1))
        special = [c for c in ("C7", "C8") if c in cells]
        if special:
            ensure_upstream(False)
        for rnd in range(args.runs if special else 0):
            rot = proxies[rnd % len(proxies):] + proxies[:rnd % len(proxies)]
            for cell in special:
                for name in rot:
                    if name in results["notworking"] or done(cell, name, rnd) or (cell == "C7" and name != "cancho-tls"):
                        continue
                    proxy, bad = start_proxy(args, name)
                    if not proxy:
                        results["notworking"][name] = bad
                        print(f"[{name}] not working in this setup: {bad}", flush=True)
                        continue
                    try:
                        if name == "cancho-tls" and "tls" not in results:
                            results["tls"] = tls_info(args)
                        if cell == "C7":
                            if rnd == 0:
                                results["handshake_latency"] = handshake_latency()
                            run_handshakes(args, args.warmup, proxy)  # discarded
                            rec = run_handshakes(args, args.duration, proxy)
                        else:
                            rec = run_bulk(args, proxy, name)
                    finally:
                        proxy.stop()
                    results["cells"].setdefault(cell, {}).setdefault(name, []).append(dict(run=rnd, **rec))
                    print(f"[{rnd}] {cell:3} {name:16} {rec}", flush=True)
                    out_json.write_text(json.dumps(results, indent=1))
        if "C6" in cells:
            ensure_upstream(False)
            for name in proxies:
                if name not in results["notworking"] and name not in results["memory"]:
                    results["memory"][name] = measure_memory(args, name)
                    print(f"[mem] {name} {results['memory'][name]}", flush=True)
    finally:
        if upstream is not None:
            upstream.stop()
        out_json.write_text(json.dumps(results, indent=1))
    (args.work / "RESULTS.md").write_text(table(results))
    print(f"wrote {out_json} and RESULTS.md")


def med(values):
    return statistics.median(values)


def special_table(cell, by):
    if cell == "C7":
        lines = ["", "### C7 full handshakes only (openssl s_time -new, TLS 1.3, no request)", "",
                 "| proxy | handshakes/s median (min–max) | gateway CPU ms per handshake | proxy CPU | RSS MiB at end | marks |", "|---|---|---|---|---|---|"]
        for name, recs in by.items():
            r = [x["rate"] for x in recs]
            lines.append(f"| {name} | {med(r):,.0f} ({min(r):,.0f}–{max(r):,.0f}) | {med([x['cpu_ms_per_handshake'] for x in recs if x['cpu_ms_per_handshake']]):.2f} | "
                         f"{med([x['proxy_cpu'] for x in recs]):.0%} | {med([x['rss_kib'] for x in recs]) / 1024:.1f} | {', '.join(sorted({m for x in recs for m in x['marks']}))} |")
        return lines
    lines = ["", f"### C8 one connection, one {BULK_MIB} MiB response (curl)", "",
             "| proxy | MiB/s median (min–max) | gateway CPU s per GiB | RSS MiB at end | marks |", "|---|---|---|---|---|"]
    for name, recs in by.items():
        r = [x["mib_s"] for x in recs]
        lines.append(f"| {name} | {med(r):,.0f} ({min(r):,.0f}–{max(r):,.0f}) | {med([x['cpu_s_per_gib'] for x in recs]):.2f} | "
                     f"{med([x['rss_kib'] for x in recs]) / 1024:.1f} | {', '.join(sorted({m for x in recs for m in x['marks']}))} |")
    return lines


def table(res):
    lines = []
    for cell, by in res["cells"].items():
        if cell in ("C7", "C8"):
            lines += special_table(cell, by)
            continue
        rss = [x["rss_kib"] for recs in by.values() for x in recs if "rss_kib" in x]
        lines += ["", f"### {cell}", "", "| proxy | req/s median (min–max) | p50 ms | p99 ms | proxy CPU | upstream CPU | load CPU | RSS MiB at end |  marks |", "|---|---|---|---|---|---|---|---|---|"] if rss else \
                 ["", f"### {cell}", "", "| proxy | req/s median (min–max) | p50 ms | p99 ms | proxy CPU | upstream CPU | load CPU | marks |", "|---|---|---|---|---|---|---|---|"]
        for name, recs in by.items():
            r = [x["rps"] for x in recs if x["rps"] is not None]
            marks = sorted({m for x in recs for m in x.get("marks", [])})
            n2 = sum(x["non2xx"] for x in recs)
            er = sum(x["errors"] for x in recs)
            extra = ([f"non-2xx {n2}"] if n2 else []) + ([f"socket errors {er}"] if er else [])
            lc = [x.get("load_cpu") for x in recs if x.get("load_cpu") is not None]
            rs = [x["rss_kib"] for x in recs if "rss_kib" in x]
            lines.append(f"| {name} | {med(r):,.0f} ({min(r):,.0f}–{max(r):,.0f}) | {med([x['p50'] for x in recs]):.2f} | "
                         f"{med([x['p99'] for x in recs]):.2f} | {med([x.get('proxy_cpu', x.get('cpu_proxy_cpu', 0)) for x in recs]):.0%} | "
                         f"{med([x.get('up_cpu', x.get('cpu_up_cpu', 0)) for x in recs]):.0%} | {(f'{med(lc):.0%}' if lc else '')} | "
                         + (f"{med(rs) / 1024:.1f} | " if rss else "") + f"{', '.join(marks + extra)} |")
    if res["memory"]:
        lines += ["", "### C6 memory", "", "| proxy | RSS before (MiB) | RSS with 100 idle connections (MiB) | connections still open |", "|---|---|---|---|"]
        for name, m in res["memory"].items():
            if "error" in m:
                lines.append(f"| {name} | {m.get('before_kib', 0) / 1024:.1f} | – | {m['error']} |")
            else:
                lines.append(f"| {name} | {m['before_kib'] / 1024:.1f} | {m['after_kib'] / 1024:.1f} | {m['still_open']} |")
    if res.get("handshake_latency"):
        h = res["handshake_latency"]
        lines += ["", f"### C7b one full handshake to an idle gateway: p50 {h['p50']:.2f} ms, p99 {h['p99']:.2f} ms ({h['n']} handshakes, Python's ssl as the client)"]
    if res.get("tls"):
        lines += ["", "### TLS as negotiated by a default OpenSSL client", ""] + [f"- {k}: {v}" for k, v in res["tls"].items()]
    if res.get("machine"):
        lines += ["", "### Machine", ""] + [f"- {k}: {v}" for k, v in res["machine"].items()]
    for name, why in res["notworking"].items():
        lines += ["", f"**{name}: not working in this setup** — {why}"]
    return "\n".join(lines) + "\n"


if __name__ == "__main__":
    main()
