#!/usr/bin/env python3
"""A small OCPP-J charger for trying the gateway's WebSocket support (docs/examples.html, example 8). Standard library only.

    python3 scripts/demo_ws_client.py localhost:8080 /ocpp/CP001 [ocpp1.6 [MODE]]

It opens a WebSocket through the gateway offering the given subprotocol, prints the response head, and then does what MODE says (default `normal`):

    normal     send a BootNotification and a Heartbeat, print what comes back, close with 1000
    oversize   send the header of a text frame of 70,000 bytes (the example's route allows 65,536): the gateway answers Close 1009 and never forwards it
    utf8       send a text message that is not UTF-8: the gateway answers Close 1007
    unmasked   send a frame without the mask a client must use: the gateway answers Close 1002
    vanish     send a BootNotification, then say nothing and answer no Ping, like a charger whose power or NAT went away: the gateway Pings it and closes it

Give it a subprotocol the route does not serve, or no path the route serves, to see a refusal.
"""

import base64
import hashlib
import json
import os
import socket
import struct
import sys
import time

GUID = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


def frame(opcode, payload, mask=True):
    key = os.urandom(4)
    n = len(payload)
    m = 128 if mask else 0
    head = bytes([0x80 | opcode, m | n]) if n < 126 else bytes([0x80 | opcode, m | 126]) + struct.pack(">H", n)
    if not mask:
        return head + payload
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


def until_closed(sock, show_ping=False):
    """Read what the gateway sends until it closes: print each control frame, answer a Close (and a Ping, if asked to), and return."""
    t0 = time.time()
    try:
        while True:
            opcode, payload = read_frame(sock)
            if opcode == 9:
                print("received a Ping of %d bytes after %.0f s" % (len(payload), time.time() - t0))
                if show_ping:
                    sock.sendall(frame(10, payload))
            elif opcode == 8:
                print("the gateway closed the tunnel with code %d after %.0f s" % (struct.unpack(">H", payload[:2])[0], time.time() - t0))
                sock.sendall(frame(8, payload[:2]))
                return
            else:
                print("received opcode %d, %d bytes" % (opcode, len(payload)))
    except EOFError:
        print("the connection ended after %.0f s" % (time.time() - t0))


def main():
    host, path = sys.argv[1], sys.argv[2]
    proto = sys.argv[3] if len(sys.argv) > 3 else "ocpp1.6"
    mode = sys.argv[4] if len(sys.argv) > 4 else "normal"
    key = base64.b64encode(os.urandom(16)).decode()
    sock = socket.create_connection((host.split(":")[0], int(host.split(":")[1])), timeout=120)
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
    boot = [2, "1", "BootNotification", {"chargePointVendor": "demo", "chargePointModel": "d1"}]
    if mode == "normal":
        for call in (boot, [2, "2", "Heartbeat", {}]):
            sock.sendall(frame(1, json.dumps(call).encode()))
            print("sent    ", json.dumps(call))
            print("received", read_frame(sock)[1].decode())
        sock.sendall(frame(8, struct.pack(">H", 1000)))
        print("closed with", struct.unpack(">H", read_frame(sock)[1][:2])[0])
    elif mode == "oversize":
        key4 = os.urandom(4)
        sock.sendall(bytes([0x81, 0xFF]) + struct.pack(">Q", 70000) + key4 + b"x" * 100)
        print("sent     the header of a text frame of 70000 bytes and 100 bytes of it")
        until_closed(sock)
    elif mode == "utf8":
        sock.sendall(frame(1, b"[2,\"1\",\"Heartbeat\",{\"x\":\"\xc3\x28\"}]"))
        print("sent     a text message with the bytes c3 28 in it")
        until_closed(sock)
    elif mode == "unmasked":
        sock.sendall(frame(1, b"[2,\"1\",\"Heartbeat\",{}]", mask=False))
        print("sent     a text frame without a mask")
        until_closed(sock)
    elif mode == "vanish":
        sock.sendall(frame(1, json.dumps(boot).encode()))
        print("sent    ", json.dumps(boot))
        print("received", read_frame(sock)[1].decode())
        print("now silent: no answer to any Ping")
        until_closed(sock)
    else:
        print("unknown mode", mode)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
