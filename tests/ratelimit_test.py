#!/usr/bin/env python3
"""Rate limiting end to end (docs/ratelimit.md section 10, gate 5): a built gateway, a recording upstream, and clients that count what they were told.

    python3 tests/ratelimit_test.py [test_name ...]       # all tests, or the named ones
    RL_TREE=/path/to/copy python3 tests/ratelimit_test.py ...   # build the gateway from another copy of the tree (tests/ratelimit_mutants.py)

Two gateways are built from loose files, as tests/proxy_test.py does: `main` (many routes, each with its own limit; plain, TLS and WebSocket listeners
and an admin one) and `big` (one route with the largest table the generator allows). Every limit is "1 an hour" unless the test is about a refill, so that
what a test counts does not depend on how fast the machine is. Needs `build/deps` filled by one `cancho build`, and `openssl` for the TLS certificates.
"""

import json
import os
import pathlib
import re
import socket
import subprocess
import sys
import tempfile
import threading
import time
import traceback

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import proxy_test as pt  # noqa: E402
import tls_test as tt  # noqa: E402
import websocket_test as wt  # noqa: E402

TREE = pathlib.Path(os.environ.get("RL_TREE", str(pt.ROOT)))
LEX = pt.LEX

ROUTES = """
[[route]]
name = "open"
path_prefix = "/open"
upstream = "up"

[[route]]
name = "rroute"
path_prefix = "/r"
upstream = "up"
rate_limit = "1/h"
rate_burst = 5

[[route]]
name = "fill"
path_prefix = "/fill"
upstream = "up"
rate_limit = "2/s"
rate_burst = 2

[[route]]
name = "rkey"
path_prefix = "/k"
upstream = "up"
rate_limit = "1/h"
rate_burst = 2
rate_key = "header:X-Api-Key"

[[route]]
name = "absent"
path_prefix = "/abs"
upstream = "up"
rate_limit = "1/h"
rate_burst = 2
rate_key = "header:X-Api-Key"
rate_buckets = 64

[[route]]
name = "xl"
path_prefix = "/xl"
upstream = "up"
trust_forwarded = true
rate_limit = "1/h"
rate_burst = 1
rate_key = "xff:last"
rate_buckets = 64

[[route]]
name = "xf"
path_prefix = "/xf"
upstream = "up"
trust_forwarded = true
rate_limit = "1/h"
rate_burst = 1
rate_key = "xff:first"
rate_buckets = 64

[[route]]
name = "small"
path_prefix = "/small"
upstream = "up"
rate_limit = "1/h"
rate_burst = 1
rate_key = "header:X-Api-Key"
rate_buckets = 4

[[route]]
name = "other"
path_prefix = "/other"
upstream = "up"
rate_limit = "1/h"
rate_burst = 1

[[route]]
name = "both"
path_prefix = "/both"
upstream = "up"
rate_limit = "1/h"
rate_burst = 2

[[route]]
name = "slow"
path_prefix = "/slow"
upstream = "up"
rate_limit = "6/m"
rate_burst = 1

[[route]]
name = "wsr"
path_prefix = "/wsr"
upstream = "ws"
websocket = true
rate_limit = "1/h"
rate_burst = 3

[[route]]
name = "wso"
path_prefix = "/wso"
upstream = "ws"
websocket = true
"""

BIG = """
[[route]]
name = "big"
path_prefix = "/"
upstream = "up"
rate_limit = "1/h"
rate_burst = 1
rate_key = "header:X-Api-Key"
rate_buckets = 65536
"""


class Gateway:
    def __init__(self, tmp, up_port, ws_port, routes, tls=True, top=""):
        self.tmp = pathlib.Path(tmp)
        self.port, self.admin = pt.free_port(), pt.free_port()
        self.tls_port = pt.free_port() if tls else None
        tlsconf = ""
        if tls:
            certs = self.tmp / "certs"
            self.chain_api = tt.make_identity(certs, "api", "api.example")
            tlsconf = 'tls_listen = %d\ntls_dir = "%s"\ntls_identities = ["api"]\n' % (self.tls_port, certs)
        tlsconf += top
        deploy = self.tmp / "deploy.toml"
        deploy.write_text("""listen = %d
admin_listen = %d
%sheader_timeout_ms = 1000
connect_timeout_ms = 1000
upstream_timeout_ms = 1500
total_timeout_ms = 4000
idle_timeout_ms = 500
%s
[[upstream]]
name = "up"
addr = "127.0.0.1:%d"

[[upstream]]
name = "ws"
addr = "127.0.0.1:%d"
%s""" % (self.port, self.admin, tlsconf, "ws_idle_timeout_ms = 20000\nws_max_tunnels = 2\n" if "websocket" in routes else "", up_port, ws_port, routes))
        out = self.tmp / "gen"
        subprocess.run([sys.executable, str(TREE / "scripts" / "generate.py"), str(deploy), "--out", str(out)], check=True)
        files = [str(out / n) for n in ("deploy.cho", "routes.cho", "tlsfiles.cho")] + pt.dependencies() + [str(TREE / "src" / (n + ".cho")) for n in pt.SOURCES]
        built = subprocess.run([LEX, "build", "--std", *files, "-o", str(self.tmp / "gateway")], capture_output=True, text=True)
        if built.returncode != 0:
            raise SystemExit("build failed: " + built.stderr[:800])
        self.proc = subprocess.Popen([str(self.tmp / "gateway")], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.log = []
        self.lock = threading.Lock()
        threading.Thread(target=self.read_log, daemon=True).start()
        for _ in range(100):
            try:
                socket.create_connection(("127.0.0.1", self.port), timeout=0.2).close()
                break
            except OSError:
                time.sleep(0.05)
        else:
            raise SystemExit("gateway did not start: %s" % self.proc.stderr.read()[:300])
        time.sleep(0.3)

    def read_log(self):
        for raw in self.proc.stdout:
            with self.lock:
                self.log.append(raw)

    def lines(self):
        with self.lock:
            out = []
            for raw in self.log:
                try:
                    out.append(json.loads(raw))
                except ValueError:
                    pass
            return out

    def find(self, n, wait=4, **want):
        """The first line after the first `n` whose keys have these values."""
        end = time.time() + wait
        while True:
            for l in self.lines()[n:]:
                if all(l.get(k) == v for k, v in want.items()):
                    return l
            if time.time() > end:
                raise AssertionError("no log line like %r among %r" % (want, self.lines()[n:][-4:]))
            time.sleep(0.05)

    def admin_get(self, path):
        c = socket.create_connection(("127.0.0.1", self.admin), timeout=5)
        c.sendall(b"GET %s HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n" % path.encode())
        data = b""
        while True:
            d = c.recv(65536)
            if not d:
                break
            data += d
        c.close()
        return data.partition(b"\r\n\r\n")[2]

    def metrics(self):
        return json.loads(self.admin_get("/metrics"))

    def route_metrics(self, name):
        return next(r for r in self.metrics()["routes"] if r["name"] == name)

    def alive(self):
        return self.proc.poll() is None

    def stop(self):
        self.proc.kill()
        self.proc.wait()


def get(gw, path, headers=(), tls=False, timeout=6):
    """One request on its own connection; answers (status, lowercase header dict, body bytes, raw response)."""
    raw = ("GET %s HTTP/1.1\r\nHost: a.example\r\n%sConnection: close\r\n\r\n" % (path, "".join(h + "\r\n" for h in headers))).encode()
    s = tt.connect(gw, timeout=timeout) if tls else socket.create_connection(("127.0.0.1", gw.port), timeout=timeout)
    s.sendall(raw)
    out = b""
    try:
        while not pt.complete(out):
            d = s.recv(65536)
            if not d:
                break
            out += d
    finally:
        s.close()
    status, head, body = pt.split(out)
    hdr = {}
    for line in head.split(b"\r\n")[1:]:
        k, _, v = line.partition(b":")
        hdr[k.strip().lower().decode()] = v.strip().decode()
    return status, hdr, body, out


def rule_of(body):
    try:
        return json.loads(body)["rule"]
    except (ValueError, KeyError):
        return None


def seen(up, prefix):
    """How many requests with this path prefix the upstream has seen."""
    with up.lock:
        return sum(1 for h in up.heads if h.split(b" ")[1].decode().startswith(prefix))


class Main:
    def under_the_limit_everything_passes(gw, up, ws):
        for i in range(30):
            assert get(gw, "/open/%d" % i)[0] == 200
        for i in range(3):
            s, h, b, _ = get(gw, "/r/under%d" % i)
            assert s == 200 and "retry-after" not in h, (i, s, h)
        assert seen(up, "/r/under") == 3

    def over_the_limit_is_a_429_with_a_retry_after_and_the_upstream_never_sees_it(gw, up, ws):
        n0 = len(gw.lines())
        for i in range(2):                      # the burst is 5: three went in the test before this one
            assert get(gw, "/r/over%d" % i)[0] == 200
        for i in range(8):
            s, h, b, raw = get(gw, "/r/refused%d" % i)
            assert s == 429, (i, s)
            assert rule_of(b) == "limit.rate", b
            assert h["content-type"] == "application/problem+json" and h["connection"] == "close", h
            # A token of a 1-an-hour limit takes 3,600 s; a few hundred ms into it the wait rounds up to 3,600 still.
            assert h["retry-after"] == "3600", h
            body = json.loads(b)
            assert body["status"] == 429 and body["title"] == "Too Many Requests" and body["request_id"] == h["x-request-id"], (body, h)
            assert raw.index(b"Content-Length") < raw.index(b"Retry-After") < raw.index(b"X-Request-Id"), raw[:200]
        assert seen(up, "/r/over") == 2 and seen(up, "/r/refused") == 0, (seen(up, "/r/over"), seen(up, "/r/refused"))
        e = gw.find(n0, path="/r/refused0")
        assert e["status"] == 429 and e["rule"] == "limit.rate" and e["route"] == "rroute" and e["outcome"] == "refused", e
        assert "upstream_ms" not in e or e["upstream_ms"] in (None, 0), e

    def a_burst_then_a_refill_after_the_wait_it_named(gw, up, ws):
        assert get(gw, "/fill/a")[0] == 200 and get(gw, "/fill/b")[0] == 200
        s, h, b, _ = get(gw, "/fill/c")
        assert s == 429 and h["retry-after"] == "1", (s, h)
        time.sleep(int(h["retry-after"]) + 0.05)
        # A second at 2 a second is two tokens: the wait it named was enough, and the bucket is back to its burst, not past it.
        assert get(gw, "/fill/d")[0] == 200 and get(gw, "/fill/e")[0] == 200
        assert get(gw, "/fill/f")[0] == 429
        time.sleep(2.2)
        assert get(gw, "/fill/g")[0] == 200 and get(gw, "/fill/h")[0] == 200
        assert get(gw, "/fill/i")[0] == 429
        assert seen(up, "/fill/") == 6

    def a_wait_in_minutes_is_named_in_seconds(gw, up, ws):
        assert get(gw, "/slow/a")[0] == 200
        s, h, b, _ = get(gw, "/slow/b")
        assert s == 429 and h["retry-after"] == "10", (s, h)

    def two_header_keys_are_limited_independently(gw, up, ws):
        a, b = ["X-Api-Key: alpha"], ["x-api-key: beta"]
        assert [get(gw, "/k/a%d" % i, a)[0] for i in range(3)] == [200, 200, 429]
        assert [get(gw, "/k/b%d" % i, b)[0] for i in range(3)] == [200, 200, 429]
        assert get(gw, "/k/a9", a)[0] == 429
        # The name is any case, the value is what counts: the same key under another spelling of the name is the same bucket.
        assert get(gw, "/k/a8", ["X-API-KEY: alpha"])[0] == 429
        assert get(gw, "/k/c0", ["X-Api-Key: gamma"])[0] == 200
        assert seen(up, "/k/") == 5

    def a_missing_empty_or_repeated_key_shares_the_absent_bucket(gw, up, ws):
        assert get(gw, "/abs/none")[0] == 200                                  # no header: the absent bucket's first token
        assert get(gw, "/abs/empty", ["X-Api-Key:"])[0] == 200                 # an empty value: its second
        s, h, b, _ = get(gw, "/abs/none2")
        assert s == 429 and rule_of(b) == "limit.rate", (s, b)
        assert get(gw, "/abs/twice", ["X-Api-Key: a", "X-Api-Key: b"])[0] == 429   # two of them is the absent bucket too, not a or b
        assert get(gw, "/abs/real", ["X-Api-Key: real"])[0] == 200            # a real key has a bucket of its own
        assert get(gw, "/abs/real2", ["X-Api-Key: real"])[0] == 200
        assert get(gw, "/abs/real3", ["X-Api-Key: real"])[0] == 429
        assert seen(up, "/abs/") == 4

    def the_last_forwarded_for_element_is_a_key_on_a_trusting_route(gw, up, ws):
        assert get(gw, "/xl/a", ["X-Forwarded-For: 9.9.9.9, 1.1.1.1"])[0] == 200
        assert get(gw, "/xl/b", ["X-Forwarded-For: 8.8.8.8, 1.1.1.1"])[0] == 429       # the client's own claim changed; the front's did not
        assert get(gw, "/xl/c", ["X-Forwarded-For: 1.1.1.1"])[0] == 429
        assert get(gw, "/xl/d", ["X-Forwarded-For: 9.9.9.9, 2.2.2.2"])[0] == 200
        assert get(gw, "/xl/e")[0] == 200 and get(gw, "/xl/f")[0] == 429               # no header: the absent bucket
        assert seen(up, "/xl/") == 3

    def the_first_forwarded_for_element_is_a_key_on_a_trusting_route(gw, up, ws):
        assert get(gw, "/xf/a", ["X-Forwarded-For: 9.9.9.9, 1.1.1.1"])[0] == 200
        assert get(gw, "/xf/b", ["X-Forwarded-For: 9.9.9.9, 2.2.2.2"])[0] == 429
        assert get(gw, "/xf/c", ["X-Forwarded-For: 8.8.8.8, 1.1.1.1"])[0] == 200
        assert seen(up, "/xf/") == 2

    def a_full_table_refuses_a_new_key_and_still_serves_an_old_one(gw, up, ws):
        n0 = len(gw.lines())
        m0 = gw.route_metrics("small")
        for k in range(4):
            assert get(gw, "/small/k%d" % k, ["X-Api-Key: key%d" % k])[0] == 200
        s, h, b, _ = get(gw, "/small/new", ["X-Api-Key: key4"])
        assert s == 429 and rule_of(b) == "limit.rate-table" and h["retry-after"] == "3600", (s, h, b)
        s, h, b, _ = get(gw, "/small/old", ["X-Api-Key: key0"])
        assert s == 429 and rule_of(b) == "limit.rate", (s, b)         # an old key is told its own bucket is empty, not that the table is full
        assert seen(up, "/small/") == 4
        e = gw.find(n0, path="/small/new")
        assert e["status"] == 429 and e["rule"] == "limit.rate-table" and e["route"] == "small", e
        m1 = gw.route_metrics("small")
        assert m1["rate_table_full"] == m0["rate_table_full"] + 1 and m1["rate_limited"] == m0["rate_limited"] + 1, (m0, m1)

    def a_limit_on_one_route_does_not_touch_another(gw, up, ws):
        assert get(gw, "/other/a")[0] == 200            # the first token of a route /r and /fill and /k have already used up theirs
        assert get(gw, "/other/b")[0] == 429
        assert get(gw, "/open/after")[0] == 200
        assert get(gw, "/r/leak")[0] == 429             # and /other's use did not give /r anything back
        assert get(gw, "/k/leak", ["X-Api-Key: delta"])[0] == 200

    def the_plain_and_the_tls_listener_spend_the_same_bucket(gw, up, ws):
        assert get(gw, "/both/plain")[0] == 200
        assert get(gw, "/both/tls", tls=True)[0] == 200
        s, h, b, _ = get(gw, "/both/tls2", tls=True)
        assert s == 429 and h["retry-after"] == "3600" and rule_of(b) == "limit.rate", (s, h)
        assert get(gw, "/both/plain2")[0] == 429
        assert seen(up, "/both/") == 2
        # Over TLS the log says so, and the limit is a refusal like any other.
        e = gw.find(0, path="/both/tls2")
        assert e["tls"] is True and e["status"] == 429, e

    def an_upgrade_is_limited_and_a_limited_upgrade_takes_no_tunnel_place(gw, up, ws):
        # wsr: 3 upgrades an hour; the tunnel cap is 2.
        a = wt.connect_ws(gw, "/wsr/a", protocols=())
        b = wt.connect_ws(gw, "/wsr/b", protocols=())
        # Over the cap the answer is the cap's, and it costs no token (otherwise the next upgrade would be the fourth).
        raw, _ = wt.request_bytes("/wsr/c", protocols=())
        got = wt.refused(wt.raw_exchange(gw, raw))
        assert got == (503, "ws.limit"), got
        b.close()
        end = time.time() + 5
        while gw.metrics()["ws"]["tunnels_active"] != 1 and time.time() < end:
            time.sleep(0.05)
        c = wt.connect_ws(gw, "/wsr/c", protocols=())          # the third and last token
        c.close()
        end = time.time() + 5
        while gw.metrics()["ws"]["tunnels_active"] != 1 and time.time() < end:
            time.sleep(0.05)
        # The fourth is limited, however many times it comes; with `a` open and a cap of 2, a flood of limited upgrades that are still lingering
        # must not fill the other place: an upgrade on the route that is not limited still gets it.
        socks = []
        for i in range(6):
            raw, _ = wt.request_bytes("/wsr/d%d" % i, protocols=())
            s = wt.open_socket(gw)
            s.sendall(raw)
            socks.append(s)
        heads = []
        for s in socks:
            head, _ = wt.read_head(s)
            heads.append(pt.refusal(head + b"\r\n\r\n" + b"x" * 0))
        n0 = len(gw.lines())
        o = wt.connect_ws(gw, "/wso/a", protocols=())
        assert o.status == 101
        o.close()
        for s in socks:
            s.close()
        a.close()
        assert all(st == 429 for st, _ in heads), heads
        e = gw.find(0, path="/wsr/d0")
        assert e["status"] == 429 and e["rule"] == "limit.rate" and e["route"] == "wsr", e
        assert seen(ws, "/wsr/d") == 0

    def the_counters_agree_with_what_the_clients_were_told(gw, up, ws):
        # Counted here from the log, which was written from the same record the client's answer was.
        lines = gw.lines()
        for name in ("rroute", "fill", "rkey", "absent", "xl", "xf", "small", "other", "both", "slow", "wsr", "open"):
            mine = [l for l in lines if l.get("route") == name and l.get("rule") == "limit.rate"]
            full = [l for l in lines if l.get("route") == name and l.get("rule") == "limit.rate-table"]
            m = gw.route_metrics(name)
            assert m["rate_limited"] == len(mine) and m["rate_table_full"] == len(full), (name, m["rate_limited"], len(mine), m["rate_table_full"], len(full))
            assert m["requests"]["4xx"] >= len(mine) + len(full), (name, m["requests"])
        assert gw.route_metrics("rroute")["rate_limited"] >= 9
        m = gw.metrics()
        assert m["refusals"]["limit.rate"] >= 20 and m["refusals"]["limit.rate-table"] == 1, m["refusals"]
        assert list(gw.route_metrics("rroute"))[-2:] == ["rate_limited", "rate_table_full"]
        prom = gw.admin_get("/metrics?format=prometheus").decode()
        assert '# TYPE cancho_gateway_rate_limited_total counter' in prom and '# TYPE cancho_gateway_rate_table_full_total counter' in prom
        assert 'cancho_gateway_rate_limited_total{route="rroute"} %d' % gw.route_metrics("rroute")["rate_limited"] in prom
        assert 'cancho_gateway_rate_table_full_total{route="small"} 1' in prom

    def the_log_lines_of_a_limited_request_have_the_keys_of_every_other_refusal(gw, up, ws):
        lines = gw.lines()
        limited = next(l for l in lines if l.get("rule") == "limit.rate")
        other = next(l for l in lines if l.get("rule") == "route.none" or l.get("rule") == "limit.body") if any(l.get("rule") in ("route.none", "limit.body") for l in lines) else None
        refusal = next(l for l in lines if l.get("outcome") == "refused" and l.get("rule") not in ("limit.rate", "limit.rate-table"))
        assert list(limited) == list(refusal), (list(limited), list(refusal))
        assert other is None or list(limited) == list(other)

    def a_refusal_leaves_nothing_behind(gw, up, ws):
        time.sleep(0.8)
        m = gw.metrics()
        assert m["sessions_active"] <= 1 and m["ws"]["tunnels_active"] == 0, m["sessions_active"]
        assert gw.alive()


class Big:
    def the_largest_table_holds_its_keys_and_limits_each(gw, up, ws):
        for i in range(300):
            assert get(gw, "/tenantx%d" % i, ["X-Api-Key: tenant-%d" % i])[0] == 200
        for i in range(0, 300, 7):
            s, h, b, _ = get(gw, "/tenanty%d" % i, ["X-Api-Key: tenant-%d" % i])
            assert s == 429 and rule_of(b) == "limit.rate", (i, s)
        assert seen(up, "/tenanty") == 0 and seen(up, "/tenantx") == 300
        assert gw.alive()


def main():
    groups = {"Main": Main, "Big": Big}
    wanted = sys.argv[1:]
    todo = [(g, c, n) for g, c in groups.items() for n in vars(c) if not n.startswith("_") and (not wanted or n in wanted)]
    unknown = [w for w in wanted if not any(w == t[2] for t in todo)]
    if unknown:
        print("no such test: %s" % ", ".join(unknown))
        return 2
    needed = {g for g, _, _ in todo}
    failures = 0
    with tempfile.TemporaryDirectory() as t1, tempfile.TemporaryDirectory() as t2:
        up = pt.Upstream(pt.free_port())
        ws = wt.WsUpstream(pt.free_port())
        gws = {}
        try:
            if "Main" in needed:
                gws["Main"] = Gateway(t1, up.port, ws.port, ROUTES)
            if "Big" in needed:
                gws["Big"] = Gateway(t2, up.port, ws.port, BIG, tls=False)
            for gname, cls, name in todo:
                gw = gws[gname]
                t0 = time.time()
                try:
                    getattr(cls, name)(gw, up, ws)
                    if not gw.alive():
                        raise AssertionError("the gateway died")
                    print("ok    %-80s %.1fs" % (name, time.time() - t0))
                except (AssertionError, OSError, EOFError, KeyError, IndexError, ValueError, StopIteration) as e:
                    failures += 1
                    print("FAIL  %-80s %s: %s (line %d)" % (name, type(e).__name__, e, traceback.extract_tb(e.__traceback__)[-1].lineno))
                    if not gw.alive():
                        print("      the gateway died: exit %s %s" % (gw.proc.returncode, gw.proc.stderr.read()[:300]))
                        break
        finally:
            for gw in {id(g): g for g in gws.values()}.values():
                gw.stop()
    print("%d tests, %d failures" % (len(todo), failures))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
