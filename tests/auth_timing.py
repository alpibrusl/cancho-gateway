#!/usr/bin/env python3
"""A measurement, not a gate (docs/auth.md section 4.3 and 12.3): does the time of a refusal depend on how much of a key was right?

    python3 tests/auth_timing.py [samples]        # default 4000 requests per case, interleaved

A gateway is built as tests/auth_test.py builds it. The same refused request (a credential that is no key) is sent with credentials that share
nothing with a key, share all but the last character of one, or are a key of another route's set; the cases are interleaved so that drift in the machine
hits them equally. The median, the quartiles and the difference of the medians are printed. This is not in CI: a CI machine's noise is larger than any
difference this could show, and a test that passed there would prove nothing (the comparison is of digests: docs/auth.md section 4.3 says why).
"""

import statistics
import socket
import sys
import tempfile
import time

import auth_test as at
import proxy_test as pt
import ratelimit_test as rt
import websocket_test as wt


def one(gw, credential):
    raw = ("GET /b/t HTTP/1.1\r\nHost: a.example\r\nAuthorization: Bearer %s\r\nConnection: close\r\n\r\n" % credential).encode()
    t0 = time.perf_counter()
    s = socket.create_connection(("127.0.0.1", gw.port), timeout=5)
    s.sendall(raw)
    out = b""
    while not pt.complete(out):
        d = s.recv(65536)
        if not d:
            break
        out += d
    dt = time.perf_counter() - t0
    s.close()
    assert out.startswith(b"HTTP/1.1 401"), out[:80]
    return dt * 1e6


def main():
    samples = int(sys.argv[1]) if len(sys.argv) > 1 else 4000
    cases = {
        "no resemblance": lambda i: "x" * len(at.KEYS["alice"]),
        "all but the last character of a key": lambda i: at.KEYS["alice"][:-1] + "Z",
        "the first character wrong": lambda i: "Z" + at.KEYS["alice"][1:],
        "a prefix of a key": lambda i: at.KEYS["alice"][:10],
        "256 characters": lambda i: "k" * 256,
    }
    with tempfile.TemporaryDirectory() as t:
        up = pt.Upstream(pt.free_port())
        ws = wt.WsUpstream(pt.free_port())
        gw = rt.Gateway(t, up.port, ws.port, at.ROUTES, tls=False, top=at.TOP)
        try:
            for _ in range(300):
                one(gw, "warm")
            got = {k: [] for k in cases}
            for i in range(samples):
                for k, make in cases.items():
                    got[k].append(one(gw, make(i)))
        finally:
            gw.stop()
    base = statistics.median(got["no resemblance"])
    print("%d interleaved samples per case; microseconds for connect, request and the whole 401 on loopback" % samples)
    print("%-40s %8s %8s %8s %12s" % ("credential", "median", "p25", "p75", "vs first"))
    for k, v in got.items():
        q = statistics.quantiles(v, n=4)
        print("%-40s %8.0f %8.0f %8.0f %+11.1f%%" % (k, statistics.median(v), q[0], q[2], 100.0 * (statistics.median(v) - base) / base))
    return 0


if __name__ == "__main__":
    sys.exit(main())
