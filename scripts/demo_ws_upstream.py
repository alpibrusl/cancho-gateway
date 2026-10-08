#!/usr/bin/env python3
"""A small OCPP-J back office for trying the gateway's WebSocket support (docs/examples.html, example 8). Standard library only.

    python3 scripts/demo_ws_upstream.py 9000

It accepts a WebSocket with the subprotocol `ocpp1.6` or `ocpp2.0.1`, answers BootNotification and Heartbeat calls (OCPP-J: `[2, id, action, payload]`
is answered `[3, id, payload]`), answers anything else with a CALLERROR, and answers an ordinary HTTP request with `csms: ok`. It prints the head of every
request it receives, so you can see what the gateway forwarded. Nothing here is part of the gateway, and it is not an OCPP implementation.
"""

import base64
import datetime
import hashlib
import json
import socketserver
import struct
import sys

GUID = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


def frame(opcode, payload):
    n = len(payload)
    head = bytes([0x80 | opcode, n]) if n < 126 else bytes([0x80 | opcode, 126]) + struct.pack(">H", n)
    return head + payload


def read_frame(rfile):
    head = rfile.read(2)
    if len(head) < 2:
        return None, b""
    n = head[1] & 127
    if n == 126:
        n = struct.unpack(">H", rfile.read(2))[0]
    elif n == 127:
        n = struct.unpack(">Q", rfile.read(8))[0]
    key = rfile.read(4) if head[1] & 128 else b"\0\0\0\0"
    data = bytearray(rfile.read(n))
    for i in range(len(data)):
        data[i] ^= key[i % 4]
    return head[0] & 15, bytes(data)


def now():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class Handler(socketserver.StreamRequestHandler):
    def handle(self):
        lines = []
        while True:
            line = self.rfile.readline().decode("latin-1").rstrip("\r\n")
            if not line:
                break
            lines.append(line)
        headers = {l.partition(":")[0].lower(): l.partition(":")[2].strip() for l in lines[1:]}
        print("upstream :%d saw\n%s" % (self.server.server_address[1], "\n".join(lines)), flush=True)
        if headers.get("upgrade", "").lower() != "websocket":
            body = b"csms: ok\n"
            self.wfile.write(b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n" % len(body) + body)
            return
        offered = [t.strip() for t in headers.get("sec-websocket-protocol", "").split(",")]
        chosen = next((t for t in offered if t in ("ocpp1.6", "ocpp2.0.1")), None)
        accept = base64.b64encode(hashlib.sha1(headers["sec-websocket-key"].encode() + GUID).digest()).decode()
        out = "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n" % accept
        if chosen:
            out += "Sec-WebSocket-Protocol: %s\r\n" % chosen
        self.wfile.write((out + "\r\n").encode())
        while True:
            opcode, data = read_frame(self.rfile)
            if opcode is None or opcode == 8:
                self.wfile.write(frame(8, data[:2]))
                return
            if opcode == 9:
                self.wfile.write(frame(10, data))
            elif opcode == 1:
                self.wfile.write(frame(1, self.answer(data)))

    def answer(self, data):
        try:
            kind, uid, action, payload = json.loads(data)
        except (ValueError, TypeError):
            return json.dumps([4, "", "FormationViolation", "", {}]).encode()
        if action == "BootNotification":
            return json.dumps([3, uid, {"currentTime": now(), "interval": 300, "status": "Accepted"}]).encode()
        if action == "Heartbeat":
            return json.dumps([3, uid, {"currentTime": now()}]).encode()
        return json.dumps([4, uid, "NotImplemented", "", {}]).encode()


class Server(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 9000
    print("listening on 127.0.0.1:%d" % port, flush=True)
    Server(("127.0.0.1", port), Handler).serve_forever()
