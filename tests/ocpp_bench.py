#!/usr/bin/env python3
"""The CPU cost of validating OCPP-J frames (docs/ocpp.md section 11): the same text traffic through a route without `ws_ocpp` and a route with it, on one built gateway, and the gateway's CPU from /proc.

    python3 tests/ocpp_bench.py [rounds] [MiB]

Traffic (valid OCPP-J messages, JSON with numbers, strings and nesting; one tunnel each time, `MiB` MiB in all, default 64):
  small  a 300-byte CALL (a BootNotification-shaped message), one per frame        meter  a 4,000-byte CALLRESULT (a MeterValues-shaped message), one per frame
Both directions: the upstream sends them to the client (down), the client sends them masked (up). Answers the median CPU milliseconds per MiB of each over the rounds, for the
plain route and the validated one, and the ratio.
"""

import base64
import hashlib
import json
import os
import socket
import statistics
import sys
import tempfile
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import proxy_test as pt  # noqa: E402
import websocket_test as wt  # noqa: E402
import wsframes_bench as wb  # noqa: E402

ROUTES = """
[[route]]
name = "plain"
path_prefix = "/b"
websocket = true
subprotocols = ["ocpp1.6"]
ws_max_message_bytes = 65536
upstream = "up"

[[route]]
name = "ocpp"
path_prefix = "/o"
websocket = true
subprotocols = ["ocpp1.6"]
ws_ocpp = "1.6"
ws_max_message_bytes = 65536
upstream = "up"

[[route]]
name = "other"
path_prefix = "/"
upstream = "up"
"""


def message(kind):
    if kind == "small":
        body = {"chargePointVendor": "VendorX", "chargePointModel": "SingleSocketCharger", "chargePointSerialNumber": "gir.vat.mx.000e48", "firmwareVersion": "1.0.49",
                "iccid": "89490200001234567890", "imsi": "310150123456789", "meterType": "DZMV", "meterSerialNumber": "gir.vat.mx.000e48", "extra": [1, -2.5, True, None, "xé"]}
        m = json.dumps([2, "19223201", "BootNotification", body], separators=(",", ":"))
    else:
        values = [{"timestamp": "2013-03-07T16:52:16Z", "sampledValue": [{"value": "%d.%d" % (i, j), "unit": "kWh", "measurand": "Energy.Active.Import.Register"} for j in range(3)]} for i in range(18)]
        m = json.dumps([3, "19223202", {"transactionId": 12345, "meterValue": values}], separators=(",", ":"))
    return m.encode()


class Upstream(wb.Upstream):
    def __init__(self, port):
        self.kind = "small"
        self.port = port
        super().__init__(port)

    def serve(self, c):
        try:
            head, rest = wb.read_head(c)
            key = [l.split(b":", 1)[1].strip() for l in head.split(b"\r\n") if l.lower().startswith(b"sec-websocket-key")][0]
            acc = base64.b64encode(hashlib.sha1(key + wb.GUID).digest())
            c.sendall(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: " + acc + b"\r\nSec-WebSocket-Protocol: ocpp1.6\r\n\r\n")
            if self.mode.startswith("down"):
                one = wb.frame(1, message(self.kind), False)
                batch = one * max(1, (1 << 20) // len(one))
                sent = 0
                while sent < self.total:
                    c.sendall(batch)
                    sent += len(batch)
                c.sendall(wb.frame(8, b"\x03\xe8", False))
            while c.recv(1 << 20):
                pass
        except (OSError, EOFError):
            pass
        finally:
            c.close()


def run(port, up, direction, kind, path, total):
    up.mode, up.kind, up.total = direction, kind, total
    s = socket.create_connection(("127.0.0.1", port))
    key = base64.b64encode(os.urandom(16))
    s.sendall(("GET %s/x HTTP/1.1\r\nHost: a\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: " % path).encode() + key +
              b"\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Protocol: ocpp1.6\r\n\r\n")
    head, rest = wb.read_head(s)
    assert head.startswith(b"HTTP/1.1 101"), head
    if direction == "down":
        while True:
            d = s.recv(1 << 20)
            if not d or d.endswith(b"\x88\x02\x03\xe8"):
                break
    else:
        payload = message(kind)
        key = b"\x01\x02\x03\x04"
        masked = bytes(b ^ key[i % 4] for i, b in enumerate(payload))     # wsframes_bench.frame writes the key but does not apply it: fine for a byte-agnostic gateway, not for this one
        one = wb.frame(1, masked, True)
        batch = one * max(1, (1 << 20) // len(one))
        sent = 0
        while sent < total:
            s.sendall(batch)
            sent += len(batch)
        s.sendall(wb.frame(8, b"\x03\xe8", True))
        s.settimeout(30)
        try:
            while s.recv(65536):
                pass
        except OSError:
            pass
    s.close()


def main():
    rounds = int(sys.argv[1]) if len(sys.argv) > 1 else 3
    total = (int(sys.argv[2]) if len(sys.argv) > 2 else 64) << 20
    up = Upstream(pt.free_port())
    with tempfile.TemporaryDirectory() as tmp:
        gw = wt.Gateway(tmp, up.port, pt.free_port(), idle=120000, lifetime=600000, close_ms=1000, routes=ROUTES)
        try:
            for direction in ("down", "up"):
                for kind in ("small", "meter"):
                    res = {}
                    for name, path in (("plain", "/b"), ("ocpp", "/o")):
                        vals = []
                        for _ in range(rounds):
                            c0 = wb.cpu(gw.proc.pid)
                            run(gw.port, up, direction, kind, path, total)
                            time.sleep(0.3)
                            vals.append((wb.cpu(gw.proc.pid) - c0) / (total / (1 << 20)) * 1000)
                        res[name] = statistics.median(vals)
                    print("%-4s %-5s (%4d-byte messages)  plain %6.2f ms/MiB   ws_ocpp %6.2f ms/MiB   (x%.2f)" % (
                        direction, kind, len(message(kind)), res["plain"], res["ocpp"], res["ocpp"] / res["plain"] if res["plain"] else 0))
        finally:
            gw.stop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
