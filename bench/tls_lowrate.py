#!/usr/bin/env python3
"""The gateway's CPU for one full TLS handshake at low, paced rates (docs/bench.md section 11.4): the saturation figure of C7 (5.9 ms) is a rate the gateway
can only reach flat out, and docs/tls.md section 10's informal 12 ms was taken at 50 a second. Needs the --work directory a `bench/run.py --proxies cancho-tls` left.

    python3 bench/tls_lowrate.py --work /tmp/bench
"""

import argparse
import pathlib
import socket
import ssl
import sys
import time
import types

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import run  # noqa: E402


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--work", type=pathlib.Path, default=pathlib.Path("/tmp/cancho-bench"))
    ap.add_argument("--seconds", type=int, default=5)
    ap.add_argument("--rates", default="20,50,100")
    ns = ap.parse_args()
    args = types.SimpleNamespace(work=ns.work.resolve(), bins={})
    up = run.start_upstream(args, False)
    run.wait_port(run.UP)
    proxy, bad = run.start_proxy(args, "cancho-tls")
    if not proxy:
        sys.exit(bad)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
    try:
        time.sleep(1)
        t0 = run.group_ticks(proxy.pgid)
        time.sleep(4)
        print("idle: gateway CPU over 4 s: %.0f ms" % ((run.group_ticks(proxy.pgid) - t0) / run.TICKS * 1000))
        for rate in (int(r) for r in ns.rates.split(",")):
            n = rate * ns.seconds
            a, start = run.group_ticks(proxy.pgid), time.time()
            for i in range(n):
                while time.time() < start + i / rate:
                    time.sleep(0.0005)
                with socket.create_connection(("127.0.0.1", run.TLS_PORT), 5) as s:
                    ctx.wrap_socket(s, server_hostname="bench.example").close()
            wall = time.time() - start
            cpu = (run.group_ticks(proxy.pgid) - a) / run.TICKS
            print("%d handshakes a second: %d in %.1f s, gateway CPU %.2f s = %.2f ms a handshake (%.0f%% of its core)" % (rate, n, wall, cpu, cpu / n * 1000, 100 * cpu / wall))
    finally:
        proxy.stop()
        up.stop()


if __name__ == "__main__":
    main()
