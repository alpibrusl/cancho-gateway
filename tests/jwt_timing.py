#!/usr/bin/env python3
"""What a token costs the gateway, measured (docs/jwt.md sections 6 and 9; not a gate).

    python3 tests/jwt_timing.py [N]     # N interleaved requests per case, default 300

Through the built gateway over loopback: the time of connect, request and the whole `401` for tokens refused before the signature (an expired one, a wrong audience) and for one that
reaches it (a wrong signature), and the rate at which one client can make the gateway verify. The difference between the cases is what `std.ed25519.verify` costs on this machine; the
single-threaded loop means that cost is taken from every other connection (docs/jwt.md section 9).
"""
import statistics
import sys
import tempfile
import time

import jwt_test as jt
import proxy_test as pt
import ratelimit_test as rt
import websocket_test as wt
from jwt_test import auth, claims, get, header, now, parts, tok


def micros(gw, path, headers):
    t = time.perf_counter()
    s, *_ = get(gw, path, headers)
    return (time.perf_counter() - t) * 1e6, s


def main():
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 300
    with tempfile.TemporaryDirectory() as tmp:
        up = pt.Upstream(pt.free_port())
        ws = wt.WsUpstream(pt.free_port())
        gw = rt.Gateway(tmp, up.port, ws.port, jt.ROUTES, top=jt.TOP)
        try:
            good = tok()
            h, p, s = parts(good)
            cases = {
                "expired (refused before the signature)": (lambda: auth(tok(p=claims(exp=now() - 30))), 401),
                "wrong audience (refused before the signature)": (lambda: auth(tok(p=claims(aud="other"))), 401),
                "wrong signature (reaches the signature)": (lambda: auth(h + "." + p + "." + s[:20] + ("B" if s[20] != "B" else "C") + s[21:]), 401),
                "valid token (verified, then forwarded)": (lambda: auth(good), 200),
            }
            tokens = {k: f() for k, (f, _) in cases.items()}
            samples = {k: [] for k in cases}
            for _ in range(20):
                for k in cases:
                    micros(gw, "/j/warm", [tokens[k]])
            for _ in range(n):
                for k, (_, want) in cases.items():
                    us, status = micros(gw, "/j/t", [tokens[k]])
                    assert status == want, (k, status)
                    samples[k].append(us)
            base = statistics.median(samples["expired (refused before the signature)"])
            print("%d interleaved requests per case; microseconds for connect, request and the whole answer" % n)
            print("%-52s %8s %8s %8s %10s" % ("case", "median", "p25", "p75", "vs expired"))
            for k, v in samples.items():
                q = statistics.quantiles(v, n=4)
                print("%-52s %8.0f %8.0f %8.0f %+9.0f" % (k, statistics.median(v), q[0], q[2], statistics.median(v) - base))
            # What one client can make the gateway verify: sequential wrong-signature requests, as fast as they are answered.
            t0, count = time.perf_counter(), 0
            while time.perf_counter() - t0 < 3:
                get(gw, "/j/rate", [tokens["wrong signature (reaches the signature)"]])
                count += 1
            print("one client, sequential, wrong signatures: %.0f requests a second (%.2f ms each)" % (count / (time.perf_counter() - t0), 1000 * (time.perf_counter() - t0) / count))
        finally:
            gw.stop()


if __name__ == "__main__":
    main()
