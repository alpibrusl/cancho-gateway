#!/usr/bin/env python3
"""The CPU cost of reading frames (docs/websocket-frames.md section 12): the same traffic through two gateways, the slice-1 byte tunnel and this one, and the gateway's CPU from /proc.

    python3 tests/wsframes_bench.py BASELINE_GATEWAY NEW_GATEWAY [rounds]

Each is a built gateway from a deployment with a route `/b` (websocket, the new one with ws_max_message_bytes = 268435456) listening on the ports in the environment
BENCH_BASE_PORT and BENCH_NEW_PORT, and its upstream on 127.0.0.1:BENCH_UP_PORT (this script serves it). Traffic, 256 MiB each time, one tunnel:
down-bin   the upstream sends 8 MiB binary frames to the client          down-text  the upstream sends 64 KiB text frames (ASCII) to the client
up-bin     the client sends 8 MiB masked binary frames                   up-text    the client sends 64 KiB masked text frames
down-small the upstream sends 100-byte text frames (OCPP-sized)          up-small   the client sends 100-byte masked text frames
Answers the median CPU seconds per MiB of each over the rounds, for each gateway.
"""

import base64
import hashlib
import os
import socket
import statistics
import struct
import subprocess
import sys
import threading
import time

TOTAL = 256 << 20
GUID = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


def frame(op, payload, mask):
    n = len(payload)
    if n < 126:
        head = bytes([0x80 | op, (0x80 if mask else 0) | n])
    elif n < 65536:
        head = bytes([0x80 | op, (0x80 if mask else 0) | 126]) + struct.pack(">H", n)
    else:
        head = bytes([0x80 | op, (0x80 if mask else 0) | 127]) + struct.pack(">Q", n)
    return head + (b"\x01\x02\x03\x04" if mask else b"") + payload


def cpu(pid):
    f = open("/proc/%d/stat" % pid).read().rsplit(")", 1)[1].split()
    return (int(f[11]) + int(f[12])) / os.sysconf("SC_CLK_TCK")


def read_head(s):
    d = b""
    while b"\r\n\r\n" not in d:
        c = s.recv(65536)
        if not c:
            raise EOFError
        d += c
    h, _, rest = d.partition(b"\r\n\r\n")
    return h, rest


class Upstream:
    def __init__(self, port):
        self.mode = "down-bin"
        self.sock = socket.socket()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", port))
        self.sock.listen(8)
        threading.Thread(target=self.accept, daemon=True).start()

    def accept(self):
        while True:
            c, _ = self.sock.accept()
            threading.Thread(target=self.serve, args=(c,), daemon=True).start()

    def serve(self, c):
        try:
            head, rest = read_head(c)
            key = [l.split(b":", 1)[1].strip() for l in head.split(b"\r\n") if l.lower().startswith(b"sec-websocket-key")][0]
            acc = base64.b64encode(hashlib.sha1(key + GUID).digest())
            c.sendall(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: " + acc + b"\r\n\r\n")
            if self.mode.startswith("down"):
                size = {"bin": 8 << 20, "text": 65536, "small": 100}[self.mode.split("-")[1]]
                op = 2 if self.mode.endswith("bin") else 1
                reps = max(1, (4 << 20) // (size + 14))
                data = frame(op, b"a" * size, False) * reps
                sent = 0
                while sent < TOTAL:
                    c.sendall(data)
                    sent += reps * size
                c.sendall(frame(8, b"\x03\xe8", False))
            while c.recv(1 << 20):
                pass
        except (OSError, EOFError):
            pass
        finally:
            c.close()


def one(port, up, mode):
    up.mode = mode
    s = socket.create_connection(("127.0.0.1", port))
    key = base64.b64encode(os.urandom(16))
    s.sendall(b"GET /b/x HTTP/1.1\r\nHost: a\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: " + key + b"\r\nSec-WebSocket-Version: 13\r\n\r\n")
    head, rest = read_head(s)
    assert head.startswith(b"HTTP/1.1 101"), head
    moved = len(rest)
    t0 = time.time()
    if mode.startswith("down"):
        while True:
            d = s.recv(1 << 20)
            if not d:
                break
            moved += len(d)
            if d.endswith(b"\x88\x02\x03\xe8"):
                break
    else:
        size = {"bin": 8 << 20, "text": 65536, "small": 100}[mode.split("-")[1]]
        op = 2 if mode.endswith("bin") else 1
        data = frame(op, b"a" * size, True)
        batch = data * max(1, (4 << 20) // len(data))
        sent = 0
        while sent < TOTAL:
            s.sendall(batch)
            sent += len(batch) * size // len(data)
        s.sendall(frame(8, b"\x03\xe8", True))
        s.settimeout(30)
        try:
            while s.recv(65536):
                pass
        except OSError:
            pass
    s.close()
    return time.time() - t0


def main():
    base, new = sys.argv[1], sys.argv[2]
    rounds = int(sys.argv[3]) if len(sys.argv) > 3 else 3
    up = Upstream(int(os.environ["BENCH_UP_PORT"]))
    procs = {"slice 1": (subprocess.Popen([base], stdout=subprocess.DEVNULL), int(os.environ["BENCH_BASE_PORT"])),
             "slice 2": (subprocess.Popen([new], stdout=subprocess.DEVNULL), int(os.environ["BENCH_NEW_PORT"]))}
    time.sleep(1)
    results = {}
    try:
        for mode in ("down-bin", "down-text", "down-small", "up-bin", "up-text", "up-small"):
            for name, (p, port) in procs.items():
                vals = []
                for _ in range(rounds):
                    c0 = cpu(p.pid)
                    secs = one(port, up, mode)
                    time.sleep(0.3)
                    vals.append((cpu(p.pid) - c0) / (TOTAL / (1 << 20)) * 1000)
                results[(mode, name)] = statistics.median(vals)
            a, b = results[(mode, "slice 1")], results[(mode, "slice 2")]
            print("%-11s slice 1 %6.2f ms/MiB   slice 2 %6.2f ms/MiB   (x%.2f)" % (mode, a, b, b / a if a else 0))
    finally:
        for p, _ in procs.values():
            p.kill()
    return 0


if __name__ == "__main__":
    sys.exit(main())
