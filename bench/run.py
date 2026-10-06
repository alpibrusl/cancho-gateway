#!/usr/bin/env python3
"""The benchmark harness (task #14, docs/bench.md). The protocol there is fixed; this file only carries it out.

    python3 bench/run.py --work /tmp/bench --runs 5            # every proxy, every cell
    python3 bench/run.py --proxies nginx,lexsys --cells C1 --runs 1 --duration 3 --warmup 1   # a quick check
    python3 bench/run.py --oha-rate 3000 ...                   # also the open-loop oha cross-check on C1, at 3000 requests/s

Needs on PATH (or --bin NAME=PATH): nginx haproxy envoy caddy traefik wrk oha slow_upstream lex-sys taskset.
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
import statistics
import subprocess
import sys
import time

ROOT = pathlib.Path(__file__).resolve().parent.parent
CONF = ROOT / "bench" / "conf"
PORT, UP = 18080, 19090
PROXY_CORE, UP_CORE, LOAD_CORES = "0", "1", "2,3"
TICKS = os.sysconf("SC_CLK_TCK")
ALL_PROXIES = ["lexsys", "nginx", "haproxy", "envoy", "caddy", "traefik"]
CELLS = {
    "C1": dict(path="/", conns=64, extra=[], want=2),
    "C1b": dict(path="/", conns=8, extra=[], want=2),
    "C2": dict(path="/", conns=64, extra=["-H", "Connection: close"], want=2),
    "C3": dict(path="/big", conns=64, extra=[], want=65536),
    "C4": dict(path="/post", conns=64, extra=["-s", str(ROOT / "bench" / "post.lua")], want=2),
    "C5": dict(path="/", conns=64, extra=[], want=2, slow=True),
}


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
    def __init__(self, argv, core, env=None, log=None):
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


def wait_port(port, seconds=20):
    end = time.time() + seconds
    while time.time() < end:
        try:
            socket.create_connection(("127.0.0.1", port), 0.5).close()
            return True
        except OSError:
            time.sleep(0.1)
    return False


def request(method, path, body=None):
    c = http.client.HTTPConnection("127.0.0.1", PORT, timeout=10)
    try:
        c.request(method, path, body=body, headers={"Connection": "close"})
        r = c.getresponse()
        data = r.read()
        return r.status, len(data)
    finally:
        c.close()


def sanity(slow=False):
    """The three requests of section 4 (only GET / against the slow upstream of C5, which has no /big). Returns None when right, else a reason."""
    checks = [("GET", "/", None, 2), ("GET", "/big", None, 65536), ("POST", "/post", b"x" * 16384, 2)]
    for method, path, body, want in checks[:1] if slow else checks:
        deadline, last = time.time() + 15, None
        while time.time() < deadline:
            try:
                got = request(method, path, body)
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
    subs = {"@PORT@": str(PORT), "@UP@": str(UP), "@DIR@": str(work)}
    for src in CONF.iterdir():
        text = src.read_text()
        for k, v in subs.items():
            text = text.replace(k, v)
        (work / src.name).write_text(text)
    # The gateway: this repository, copied, with a deployment of one route to the one upstream.
    gw = work / "gw"
    if gw.exists():
        shutil.rmtree(gw)
    for d in ["src", "scripts", "generated"]:
        shutil.copytree(ROOT / d, gw / d)
    for f in ["lex-sys.toml", "authority.toml"]:
        shutil.copy(ROOT / f, gw / f)
    (gw / "deploy.toml").write_text(
        f'listen = {PORT}\npool_idle_max = 64\n\n[[upstream]]\nname = "u"\naddr = "127.0.0.1:{UP}"\n\n'
        '[[route]]\nname = "all"\npath_prefix = "/"\nupstream = "u"\n')
    subprocess.run([sys.executable, str(gw / "scripts" / "generate.py"), str(gw / "deploy.toml")], check=True, cwd=gw)
    subprocess.run([which(args, "lex-sys"), "build"], check=True, cwd=gw)
    for d in ["nginx-body", "nginx-proxy", "nginx-fcgi", "nginx-uwsgi", "nginx-scgi", "up-body", "up-proxy", "up-fcgi", "up-uwsgi", "up-scgi"]:
        (work / d).mkdir(exist_ok=True)


def proxy_cmd(args, name):
    w = args.work
    if name == "lexsys":
        return [str(w / "gw" / "build" / "gateway")], {}
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


def run_wrk(args, cell, duration, proxy, upstream):
    c = CELLS[cell]
    url = f"http://127.0.0.1:{PORT}{c['path']}"
    out = args.work / "wrk.out"
    argv = ["taskset", "-c", LOAD_CORES, which(args, "wrk"), "-t2", f"-c{c['conns']}", f"-d{duration}s", "--latency"] + c["extra"] + [url]
    pt0, ut0, t0 = group_ticks(proxy.pgid), group_ticks(upstream.pgid), time.time()
    p = subprocess.Popen(argv, stdout=open(out, "wb"), stderr=subprocess.STDOUT)
    _, _, ru = os.wait4(p.pid, 0)
    p.returncode = 0
    wall = time.time() - t0
    pt1, ut1 = group_ticks(proxy.pgid), group_ticks(upstream.pgid)
    return parse_wrk(out.read_text()), dict(
        wall=wall, load_cpu=(ru.ru_utime + ru.ru_stime) / (2 * wall),
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
    proxy = Proc(argv, PROXY_CORE, env, args.work / f"{name}.log")
    if not wait_port(PORT):
        proxy.stop()
        return None, f"{name} did not listen on port {PORT} within 20 s (see {name}.log)"
    bad = sanity(slow)
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
    try:
        for _ in range(100):
            socks.append(socket.create_connection(("127.0.0.1", PORT), 2))
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


def flags(cell, wrk, load):
    marks = []
    if wrk["non2xx"] or wrk["errors"]:
        marks.append("INVALID")
    if load.get("load_cpu") is not None and load["load_cpu"] > 0.9:
        marks.append("CLIENT-BOUND")
    if load["up_cpu"] > 0.9:
        marks.append("UPSTREAM-BOUND")
    return marks


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--work", type=pathlib.Path, default=pathlib.Path("/tmp/lexsys-bench"))
    ap.add_argument("--runs", type=int, default=5)
    ap.add_argument("--duration", type=int, default=10)
    ap.add_argument("--warmup", type=int, default=3)
    ap.add_argument("--proxies", default=",".join(ALL_PROXIES))
    ap.add_argument("--cells", default="C1,C1b,C2,C3,C4,C5,C6")
    ap.add_argument("--oha-rate", type=int, default=0, help="also run oha at this open-loop rate on C1 (requests/s)")
    ap.add_argument("--resume", action="store_true", help="continue from RESULTS.json in --work: runs already recorded are not repeated")
    ap.add_argument("--bin", action="append", default=[], metavar="NAME=PATH")
    args = ap.parse_args()
    args.bins = dict(b.split("=", 1) for b in args.bin)
    args.work = args.work.resolve()
    proxies = args.proxies.split(",")
    cells = args.cells.split(",")
    prepare(args)
    results = {"commit": subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True, text=True).stdout.strip(),
               "runs": args.runs, "duration": args.duration, "warmup": args.warmup, "cells": {}, "memory": {}, "notworking": {}}
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
        timed = [c for c in cells if c != "C6"]
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
                        run_wrk(args, cell, args.warmup, proxy, upstream)  # discarded
                        wrk, load = run_wrk(args, cell, args.duration, proxy, upstream)
                        if cell == "C1" and args.oha_rate:
                            run_oha_result = run_oha(args, args.oha_rate, args.duration, proxy, upstream)
                            results["cells"].setdefault("C1-oha", {}).setdefault(name, []).append(
                                dict(run=rnd, **run_oha_result[0], **{"cpu_" + k: v for k, v in run_oha_result[1].items()}))
                    finally:
                        proxy.stop()
                    rec = dict(run=rnd, **wrk, **load, marks=flags(cell, wrk, load))
                    results["cells"].setdefault(cell, {}).setdefault(name, []).append(rec)
                    print(f"[{rnd}] {cell:3} {name:8} rps={wrk['rps']} p50={wrk['p50']} p99={wrk['p99']} "
                          f"n2xx={wrk['non2xx']} err={wrk['errors']} proxy={load['proxy_cpu']:.2f} up={load['up_cpu']:.2f} "
                          f"load={load['load_cpu']:.2f} {rec['marks']}", flush=True)
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


def table(res):
    lines = []
    for cell, by in res["cells"].items():
        lines += ["", f"### {cell}", "", "| proxy | req/s median (min–max) | p50 ms | p99 ms | proxy CPU | upstream CPU | load CPU | marks |", "|---|---|---|---|---|---|---|---|"]
        for name, recs in by.items():
            r = [x["rps"] for x in recs if x["rps"] is not None]
            marks = sorted({m for x in recs for m in x.get("marks", [])})
            n2 = sum(x["non2xx"] for x in recs)
            er = sum(x["errors"] for x in recs)
            extra = ([f"non-2xx {n2}"] if n2 else []) + ([f"socket errors {er}"] if er else [])
            lc = [x.get("load_cpu") for x in recs if x.get("load_cpu") is not None]
            lines.append(f"| {name} | {med(r):,.0f} ({min(r):,.0f}–{max(r):,.0f}) | {med([x['p50'] for x in recs]):.2f} | "
                         f"{med([x['p99'] for x in recs]):.2f} | {med([x.get('proxy_cpu', x.get('cpu_proxy_cpu', 0)) for x in recs]):.0%} | "
                         f"{med([x.get('up_cpu', x.get('cpu_up_cpu', 0)) for x in recs]):.0%} | {(f'{med(lc):.0%}' if lc else '')} | {', '.join(marks + extra)} |")
    if res["memory"]:
        lines += ["", "### C6 memory", "", "| proxy | RSS before (MiB) | RSS with 100 idle connections (MiB) | connections still open |", "|---|---|---|---|"]
        for name, m in res["memory"].items():
            if "error" in m:
                lines.append(f"| {name} | {m.get('before_kib', 0) / 1024:.1f} | – | {m['error']} |")
            else:
                lines.append(f"| {name} | {m['before_kib'] / 1024:.1f} | {m['after_kib'] / 1024:.1f} | {m['still_open']} |")
    for name, why in res["notworking"].items():
        lines += ["", f"**{name}: not working in this setup** — {why}"]
    return "\n".join(lines) + "\n"


if __name__ == "__main__":
    main()
