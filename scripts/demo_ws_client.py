#!/usr/bin/env python3
"""A small OCPP-J charger for trying the gateway's WebSocket support (docs/examples.html, example 8). Standard library only.

    python3 scripts/demo_ws_client.py localhost:8080 /ocpp/CP001 [ocpp1.6]

It opens a WebSocket through the gateway offering the given subprotocol, prints the response head, sends a BootNotification and a Heartbeat, prints what
comes back, and closes. Give it a subprotocol the route does not serve, or no path the route serves, to see a refusal.
"""

import base64
import hashlib
import json
import os
import socket
import struct
import sys

GUID = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


def frame(opcode, payload):
    key = os.urandom(4)
    n = len(payload)
    head = bytes([0x80 | opcode, 128 | n]) if n < 126 else bytes([0x80 | opcode, 128 | 126]) + struct.pack(">H", n)
    return head + key + bytes(b ^ key[i % 4] for i, b in enumerate(payload))


def read_exact(sock, n):
    data = b""
    while len(data) < n:
        d = sock.recv(n - len(data))
        if not d:
            raise EOFError("the connection closed")
        data += d
    return data


def read_frame(sock):
    head = read_exact(sock, 2)
    n = head[1] & 127
    if n == 126:
        n = struct.unpack(">H", read_exact(sock, 2))[0]
    return head[0] & 15, read_exact(sock, n)


def main():
    host, path = sys.argv[1], sys.argv[2]
    proto = sys.argv[3] if len(sys.argv) > 3 else "ocpp1.6"
    key = base64.b64encode(os.urandom(16)).decode()
    sock = socket.create_connection((host.split(":")[0], int(host.split(":")[1])), timeout=10)
    sock.sendall(("GET %s HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: %s\r\nSec-WebSocket-Version: 13\r\n"
                  "Sec-WebSocket-Protocol: %s\r\n\r\n" % (path, host, key, proto)).encode())
    data = b""
    while b"\r\n\r\n" not in data:
        d = sock.recv(4096)
        if not d:
            break
        data += d
    head, _, rest = data.partition(b"\r\n\r\n")
    print(head.decode("latin-1") + ("\r\n\r\n" + rest.decode("latin-1") if rest else ""))
    if not head.startswith(b"HTTP/1.1 101"):
        return 1
    want = base64.b64encode(hashlib.sha1(key.encode() + GUID).digest()).decode()
    print("accept value correct:", ("Sec-WebSocket-Accept: " + want) in head.decode("latin-1"))
    for call in ([2, "1", "BootNotification", {"chargePointVendor": "demo", "chargePointModel": "d1"}], [2, "2", "Heartbeat", {}]):
        sock.sendall(frame(1, json.dumps(call).encode()))
        print("sent    ", json.dumps(call))
        print("received", read_frame(sock)[1].decode())
    sock.sendall(frame(8, struct.pack(">H", 1000)))
    print("closed with", struct.unpack(">H", read_frame(sock)[1][:2])[0])
    return 0


if __name__ == "__main__":
    sys.exit(main())
