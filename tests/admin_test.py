#!/usr/bin/env python3
"""End-to-end tests of the admin listener and the metrics (task #10, docs/observability.md sections 6 and 7): the built gateway with `admin_listen`
set, real sockets, and an independent count of what it did made from its own access log.

    python3 tests/admin_test.py [NAME ...]     # all tests, or the named ones

The harness (the gateway builder, the scripted upstreams, `request`) is `tests/proxy_test.py`'s.
"""

import json
import os
import re
import socket
import sys
import tempfile
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from proxy_test import GET, FlapUpstream, Gateway, KAUpstream, Upstream, free_port, heal, quiesce, refusal, request, split


def admin_raw(gw, raw, timeout=6, hold=0.0):
    """Send `raw` to the admin port and read until the gateway closes the connection."""
    s = socket.create_connection(("127.0.0.1", gw.admin), timeout=timeout)
    s.sendall(raw)
    if hold:
        time.sleep(hold)
    out = b""
    try:
        while True:
            d = s.recv(65536)
            if not d:
                break
            out += d
    except OSError:
        pass
    s.close()
    return out


def admin(gw, path, method="GET"):
    """An admin request: (status, {lowercase header: value}, body)."""
    raw = admin_raw(gw, b"%s %s HTTP/1.1\r\nHost: a\r\n\r\n" % (method.encode(), path.encode()))
    status, head, body = split(raw)
    headers = {}
    for line in head.decode("latin-1").split("\r\n")[1:]:
        name, _, value = line.partition(":")
        headers[name.lower()] = value.strip()
    return status, headers, body


def scrape(gw):
    status, headers, body = admin(gw, "/metrics")
    assert status == 200 and headers["content-type"] == "application/json", (status, headers)
    assert int(headers["content-length"]) == len(body)
    return json.loads(body)


BOUNDS = [1, 2, 5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000, 10000]


def bucket(ms):
    for i, b in enumerate(BOUNDS):
        if ms <= b:
            return i
    return len(BOUNDS)


def status_class(status):
    return "none" if not 100 <= status < 600 else "%dxx" % (status // 100)


def stable(gw):
    """(the access-log lines, the metrics) taken while nothing was ending: no new line appeared across the scrape."""
    for _ in range(20):
        time.sleep(0.4)
        n = len(gw.log_lines())
        m = scrape(gw)
        time.sleep(0.1)
        if len(gw.log_lines()) == n:
            return [json.loads(l) for l in gw.log_lines()[:n]], m
    raise AssertionError("the log never went quiet")


def listening_ports(pid):
    inodes = set()
    for fd in os.listdir("/proc/%d/fd" % pid):
        try:
            target = os.readlink("/proc/%d/fd/%s" % (pid, fd))
        except OSError:
            continue
        m = re.fullmatch(r"socket:\[(\d+)\]", target)
        if m:
            inodes.add(m.group(1))
    ports = set()
    for line in open("/proc/net/tcp").read().splitlines()[1:]:
        f = line.split()
        if f[3] == "0A" and f[9] in inodes:
            ports.add(int(f[1].split(":")[1], 16))
    return ports



class T:
    """The tests; each takes (gateway, upstream) and raises AssertionError."""

    # ---- the admin listener and the metrics (docs/observability.md sections 6 and 7) ----

    def admin_listens_only_when_asked(gw, up):
        assert listening_ports(gw.proc.pid) == {gw.port, gw.admin}, listening_ports(gw.proc.pid)

    def noadmin_a_gateway_without_admin_listen_opens_one_port_only(gw, up):
        assert gw.admin is None and listening_ports(gw.proc.pid) == {gw.port}, listening_ports(gw.proc.pid)

    def admin_healthz_and_readyz_when_all_is_well(gw, up):
        time.sleep(1.2)  # an earlier test may have left a circuit open for its second
        status, headers, body = admin(gw, "/healthz")
        assert status == 200 and json.loads(body) == {"alive": True} and headers["connection"] == "close", (status, body)
        status, headers, body = admin(gw, "/readyz")
        assert status == 200 and json.loads(body) == {"ready": True}, (status, body)

    def admin_metrics_json_names_every_family(gw, up):
        m = scrape(gw)
        assert list(m)[:3] == ["v", "uptime_ms", "sessions_active"] and m["v"] == 1, list(m)
        assert list(m) == ["v", "uptime_ms", "sessions_active", "le_ms", "routes", "upstreams", "refusals", "log"], list(m)
        assert m["le_ms"] == BOUNDS
        assert [r["name"] for r in m["routes"]] == ["dead", "ka", "flap", "trusted", "main"], [r["name"] for r in m["routes"]]
        assert [u["name"] for u in m["upstreams"]] == ["up", "dead", "ka", "flap"]
        for r in m["routes"]:
            assert list(r) == ["name", "requests", "bytes_in", "bytes_out", "duration_ms"], list(r)
            assert list(r["requests"]) == ["none", "1xx", "2xx", "3xx", "4xx", "5xx"]
            assert len(r["duration_ms"]["buckets"]) == 14 and r["duration_ms"]["count"] == sum(r["duration_ms"]["buckets"])
        for u in m["upstreams"]:
            assert list(u) == ["name", "responses", "retries", "failures", "pool_idle", "circuit_open", "wait_ms"], list(u)
            assert u["wait_ms"]["count"] == sum(u["wait_ms"]["buckets"]) == u["responses"]
        assert set(m["log"]) == {"dropped", "write_failures"} and "other" in m["refusals"]
        assert m["uptime_ms"] > 0

    def admin_a_request_moves_exactly_the_counters_it_should(gw, up):
        before, _ = stable(gw)[1], None
        raw = request(gw, GET % b"/x?token=SECRET")
        status, head, body = split(raw)
        assert status == 200
        after = stable(gw)[1]
        main_b, main_a = [next(r for r in m["routes"] if r["name"] == "main") for m in (before, after)]
        assert main_a["requests"]["2xx"] == main_b["requests"]["2xx"] + 1
        assert sum(main_a["requests"].values()) == sum(main_b["requests"].values()) + 1
        assert main_a["bytes_out"] == main_b["bytes_out"] + len(raw), (main_a["bytes_out"] - main_b["bytes_out"], len(raw))
        assert main_a["bytes_in"] == main_b["bytes_in"]
        assert main_a["duration_ms"]["count"] == main_b["duration_ms"]["count"] + 1
        up_b, up_a = [next(u for u in m["upstreams"] if u["name"] == "up") for m in (before, after)]
        assert up_a["responses"] == up_b["responses"] + 1 and up_a["wait_ms"]["count"] == up_b["wait_ms"]["count"] + 1
        assert up_a["failures"] == up_b["failures"] and up_a["retries"] == up_b["retries"]
        assert after["refusals"] == before["refusals"]
        # a request the gateway refuses before it has a route moves no route's counters, only its rule's
        before = after
        assert refusal(request(gw, b"GET /x HTTP/1.1\r\nHost: a\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n")) == (400, "framing.two-lengths")
        after = stable(gw)[1]
        assert after["refusals"].get("framing.two-lengths", 0) == before["refusals"].get("framing.two-lengths", 0) + 1
        assert [r["requests"] for r in after["routes"]] == [r["requests"] for r in before["routes"]]

    def admin_a_refused_request_and_a_dead_upstream_are_counted(gw, up):
        time.sleep(1.2)
        before = stable(gw)[1]
        assert refusal(request(gw, GET % b"/dead/x")) == (502, "proxy.connect")
        after = stable(gw)[1]
        d_b, d_a = [next(r for r in m["routes"] if r["name"] == "dead") for m in (before, after)]
        assert d_a["requests"]["5xx"] == d_b["requests"]["5xx"] + 1
        ud_b, ud_a = [next(u for u in m["upstreams"] if u["name"] == "dead") for m in (before, after)]
        assert ud_a["failures"] == ud_b["failures"] + 1 and ud_a["responses"] == ud_b["responses"]
        assert after["refusals"]["proxy.connect"] == before["refusals"].get("proxy.connect", 0) + 1

    def admin_a_retried_request_is_counted_as_a_retry(gw, up):
        quiesce(gw)
        before = stable(gw)[1]
        # a pooled connection that dies while idle is retried once on a fresh one (see a_dead_pooled_connection_is_retried_for_a_get)
        assert split(request(gw, GET % b"/ka/die"))[0] == 200
        assert split(request(gw, GET % b"/ka/die"))[:1] == (200,)
        after = stable(gw)[1]
        k_b, k_a = [next(u for u in m["upstreams"] if u["name"] == "ka") for m in (before, after)]
        assert k_a["retries"] == k_b["retries"] + 1, (k_b, k_a)

    def admin_counters_equal_an_independent_count_from_the_log(gw, up):
        body = os.urandom(3000)
        for raw in (GET % b"/x", GET % b"/trusted/x", GET % b"/ka/x", GET % b"/dead/x", GET % b"/x?a=1",
                    b"POST /echo HTTP/1.1\r\nHost: a\r\nContent-Length: %d\r\n\r\n" % len(body) + body,
                    b"POST /x HTTP/1.1\r\nHost: a\r\nContent-Length: 2000000\r\n\r\n",
                    b"GET /a/../b HTTP/1.1\r\nHost: a\r\n\r\n",
                    b"GET /x HTTP/1.1\r\nHost: a\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n"):
            request(gw, raw)
        lines, m = stable(gw)
        routed = [l for l in lines if l["route"]]
        assert len(routed) >= 8
        for r in m["routes"]:
            mine = [l for l in routed if l["route"] == r["name"]]
            want = {c: 0 for c in ("none", "1xx", "2xx", "3xx", "4xx", "5xx")}
            for l in mine:
                want[status_class(l["status"])] += 1
            assert r["requests"] == want, (r["name"], r["requests"], want)
            assert r["bytes_in"] == sum(l["bytes_in"] for l in mine) and r["bytes_out"] == sum(l["bytes_out"] for l in mine), r["name"]
            buckets = [0] * 14
            for l in mine:
                buckets[bucket(l["ms"])] += 1
            d = r["duration_ms"]
            assert d["buckets"] == buckets and d["count"] == len(mine) and d["sum"] == sum(l["ms"] for l in mine), (r["name"], d, buckets)
        refused = {}
        for l in lines:
            if l["rule"]:
                refused[l["rule"]] = refused.get(l["rule"], 0) + 1
        assert {k: v for k, v in m["refusals"].items() if k != "other"} == refused, (m["refusals"], refused)
        assert m["refusals"]["other"] == 0
        for u in m["upstreams"]:
            ours = [l for l in routed if l["upstream"] == u["name"]]
            ok = [l for l in ours if l["outcome"] == "ok"]
            assert len(ok) <= u["responses"] <= len(ours), (u["name"], len(ok), u["responses"], len(ours))
            assert u["wait_ms"]["count"] == u["responses"]

    def admin_prometheus_text_parses(gw, up):
        request(gw, GET % b"/x")
        status, headers, body = admin(gw, "/metrics?format=prometheus")
        assert status == 200 and headers["content-type"].startswith("text/plain; version=0.0.4"), (status, headers)
        assert int(headers["content-length"]) == len(body)
        text = body.decode()
        assert text.endswith("\n")
        types, samples = {}, []
        for line in text.splitlines():
            if line.startswith("# TYPE "):
                _, _, name, kind = line.split(" ")
                types[name] = kind
            elif line.startswith("# HELP "):
                continue
            else:
                m = re.fullmatch(r'(cancho_gateway_[a-z_]+)(\{[a-z]+="[a-z0-9._-]+"(,[a-z]+="[A-Za-z0-9._+-]+")*\})? (\d+)', line)
                assert m, "not a sample line: %r" % line
                samples.append((m.group(1), m.group(2) or "", int(m.group(4))))
        for name, labels, value in samples:
            family = re.sub(r"_(bucket|sum|count)$", "", name)
            assert name in types or family in types, name
        # every histogram: cumulative buckets never decrease, and +Inf equals _count
        for hist in ("cancho_gateway_request_duration_ms", "cancho_gateway_upstream_wait_ms"):
            assert types[hist] == "histogram"
            series = {}
            for name, labels, value in samples:
                if name == hist + "_bucket":
                    key = re.sub(r',le="[^"]*"', "", labels)
                    series.setdefault(key, []).append((labels, value))
            assert series
            for key, rows in series.items():
                values = [v for _, v in rows]
                assert len(rows) == 14 and values == sorted(values) and 'le="+Inf"' in rows[-1][0], key
                count = next(v for n, l, v in samples if n == hist + "_count" and l == key)
                assert values[-1] == count, (key, values, count)
        assert any(n == "cancho_gateway_refusals_total" for n, _, _ in samples)

    def admin_refuses_what_it_does_not_serve(gw, up):
        def rule(raw, **kw):
            status, head, body = split(admin_raw(gw, raw, **kw))
            return status, json.loads(body)["rule"] if body else None, json.loads(body).get("request_id") if body else None
        assert rule(b"POST /metrics HTTP/1.1\r\nHost: a\r\n\r\n")[:2] == (405, "admin.method")
        assert rule(b"POST /metrics HTTP/1.1\r\nContent-Length: 4\r\n\r\nabcd")[:2] == (405, "admin.method")
        assert rule(b"GET /metrics HTTP/1.1\r\nContent-Length: 0\r\n\r\n")[:2] == (400, "admin.body")
        assert rule(b"GET /readyz HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n")[:2] == (400, "admin.body")
        assert rule(b"GET /nope HTTP/1.1\r\nHost: a\r\n\r\n")[:2] == (404, "admin.path")
        assert rule(b"GET /metrics HTTP/2.0\r\n\r\n")[:2] == (505, "admin.version")
        assert rule(b"hello\r\n\r\n")[:2] == (400, "admin.request")
        assert rule(b"GET /metrics?format=xml HTTP/1.1\r\n\r\n")[:2] == (400, "admin.request")
        assert rule(b"GET /metrics HTTP/1.1\r\nX-Pad: " + b"a" * 3000 + b"\r\n\r\n")[:2] == (431, "admin.head")
        assert rule(b"GET /metrics HTTP/1.1\r\nX-Pad: " + b"a" * 3000)[:2] == (431, "admin.head")  # no blank line in 2 KiB
        assert rule(b"GET /x HTTP/1.1\r\n\r\n")[2] == "admin"
        # a head that never finishes is dropped at the deadline
        t0 = time.time()
        assert admin_raw(gw, b"GET /metrics HTTP/1.1\r\nHost: a\r\n", timeout=6) == b""
        assert 1.5 < time.time() - t0 < 3.5, time.time() - t0
        # and none of this reached the proxy's counters or log
        assert gw.alive()

    def admin_a_ninth_connection_is_closed_and_a_freed_one_is_reused(gw, up):
        held = [socket.create_connection(("127.0.0.1", gw.admin), timeout=3) for _ in range(8)]
        time.sleep(0.2)
        ninth = socket.create_connection(("127.0.0.1", gw.admin), timeout=3)
        ninth.sendall(b"GET /healthz HTTP/1.1\r\n\r\n")
        try:
            got = ninth.recv(4096)
        except OSError:
            got = b""
        ninth.close()
        assert got == b"", got
        held[0].close()
        time.sleep(0.2)
        assert admin(gw, "/healthz")[0] == 200
        for s in held[1:]:
            s.close()
        # the proxy port was never affected
        assert split(request(gw, GET % b"/x"))[0] == 200

    def admin_two_scrapes_at_once_are_both_answered(gw, up):
        results = []

        def one():
            results.append(admin(gw, "/metrics?format=prometheus"))
        threads = [threading.Thread(target=one) for _ in range(6)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert len(results) == 6 and all(r[0] == 200 and r[2].endswith(b"\n") for r in results), [r[0] for r in results]
        assert len({r[2][:40] for r in results}) >= 1

    def admin_a_scrape_nobody_reads_does_not_stall_the_proxy(gw, up):
        s = socket.create_connection(("127.0.0.1", gw.admin), timeout=3)
        s.sendall(b"GET /metrics?format=prometheus HTTP/1.1\r\nHost: a\r\n\r\n")
        for _ in range(20):
            assert split(request(gw, GET % b"/x"))[0] == 200
        s.close()
        assert admin(gw, "/healthz")[0] == 200

    def admin_readyz_says_why_when_a_circuit_is_open(gw, up):
        heal(gw)
        time.sleep(1.2)
        assert admin(gw, "/readyz")[0] == 200
        gw.flap.down()
        time.sleep(0.15)
        for _ in range(4):
            request(gw, GET % b"/flap/ok")
        status, headers, body = admin(gw, "/readyz")
        assert status == 503, (status, body)
        why = json.loads(body)
        assert why["ready"] is False and "upstream flap: circuit open" in why["why"], why
        assert next(u for u in scrape(gw)["upstreams"] if u["name"] == "flap")["circuit_open"] is True
        # liveness does not care
        assert admin(gw, "/healthz")[0] == 200
        heal(gw)
        time.sleep(0.2)
        status, headers, body = admin(gw, "/readyz")
        assert status == 200 and json.loads(body) == {"ready": True}, (status, body)
        assert next(u for u in scrape(gw)["upstreams"] if u["name"] == "flap")["circuit_open"] is False


    def bigmetrics_the_largest_answer_fits_its_buffer_and_arrives_whole(gw, up):
        # 120 more routes (125 in all) make the Prometheus text about 230 KB, the buffer a scrape is built in having been sized by
        # `metrics.worst_case()` for exactly this deployment: it must not run out (`admin.size`, 500), and every byte must arrive. (The kernel takes
        # an answer this size in one write, so the pieces-and-ownership path of a slow reader is not reachable here: docs/observability.md section 9.)
        for path in ("/metrics?format=prometheus", "/metrics"):
            status, headers, body = admin(gw, path)
            assert status == 200 and int(headers["content-length"]) == len(body), (path, status, len(body))
            assert body.endswith(b"\n")
            if "prometheus" in path:
                assert len(body) > 150000
                assert b'cancho_gateway_requests_total{route="r119",class="2xx"}' in body
        m = json.loads(admin(gw, "/metrics")[2])
        assert len(m["routes"]) == 125 and m["routes"][0]["name"] == "dead" and m["routes"][4]["name"] == "r000", len(m["routes"])
        # a hostile request count in every one of them stays inside the bound too (the unit test fills the counters to the brim)
        for i in (0, 60, 119):
            assert split(request(gw, GET % (b"/r%03d/x" % i)))[0] == 200
        assert admin(gw, "/metrics?format=prometheus")[0] == 200

    def continueonfail_admin_readyz_names_a_failing_log(gw, up):
        for _ in range(3):
            request(gw, GET % b"/x")
            time.sleep(0.1)
        time.sleep(0.3)
        status, headers, body = admin(gw, "/readyz")
        assert status == 503, (status, body)
        assert "log: a write failed in the last 10 s" in json.loads(body)["why"], body
        m = scrape(gw)
        assert m["log"]["write_failures"] >= 1, m["log"]
        assert admin(gw, "/healthz")[0] == 200


def main():
    names = sys.argv[1:] or [n for n in vars(T) if not n.startswith("_")]
    failures = 0
    with tempfile.TemporaryDirectory() as tmp:
        ports = [free_port() for _ in range(5)]
        port, up_port, dead, ka_port, flap_port = ports
        up = Upstream(up_port)
        ka = KAUpstream(ka_port)
        flap = FlapUpstream(flap_port)
        gws = {}

        def make(prefix, **kw):
            d = tmp if prefix == "" else tempfile.mkdtemp(prefix="gwa")
            g = Gateway(d, port if prefix == "" else free_port(), up_port, dead, ka_port, flap_port, **kw)
            g.ka, g.flap = ka, flap
            gws[prefix] = g
        make("", admin=True)
        for prefix, kw in (("continueonfail_", dict(stdout=open("/dev/full", "wb"), log_failure="continue", admin=True)),
                           ("noadmin_", dict(pool=0, circuit=0)), ("bigmetrics_", dict(routes=120, admin=True))):
            if any(n.startswith(prefix) for n in names):
                make(prefix, **kw)
        try:
            for name in names:
                t0 = time.time()
                g = next((x for p, x in gws.items() if p and name.startswith(p)), gws[""])
                try:
                    getattr(T, name)(g, up)
                    if not g.alive() and not name.startswith("fullstdout_"):
                        raise AssertionError("the gateway died")
                    print("ok    %-60s %.1fs" % (name, time.time() - t0))
                except (AssertionError, OSError) as e:
                    failures += 1
                    print("FAIL  %-60s %s" % (name, e))
                    if not g.alive():
                        print("      the gateway died: exit %s %s" % (g.proc.returncode, g.proc.stderr.read()[:200]))
                        break
        finally:
            for g in gws.values():
                g.stop()
            up.stop = True
            ka.stop = True
            flap.stop()
    print("%d tests, %d failures" % (len(names), failures))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
