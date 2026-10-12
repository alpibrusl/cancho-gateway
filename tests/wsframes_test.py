#!/usr/bin/env python3
"""WebSocket frames end to end (docs/websocket-frames.md section 13): a built gateway, a Python RFC 6455 client and a recording RFC 6455 upstream, both written here from the RFC.

    python3 tests/wsframes_test.py [test_name ...]      # all tests, or the named ones
    WS_TREE=/path/to/copy python3 tests/wsframes_test.py ...   # build the gateway from another copy of the tree (tests/wsframes_mutants.py)

Four gateways are built from loose files, as tests/websocket_test.py does: `Frames` (small, default and large message limits, a 1.5 s close wait), `Keep` (a Ping after 1 s of silence, 0.8 s
to answer, an idle time of 2.5 s), `Life` (a lifetime of 3 s, 20 s to answer a Close: for the Close that must not split a frame) and `Tls` (the routes of `Frames` over `tls_listen`).
The upstream records, byte for byte, what the gateway sent it, so "nothing of the offending frame reaches the other side" is an equality, not an impression.
Needs `build/deps` filled by one `cancho build`; the interop tests need `pip install websockets` and are skipped without it.
"""

import hashlib
import json
import os
import pathlib
import random
import socket
import struct
import sys
import tempfile
import threading
import time
import traceback

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import proxy_test as pt  # noqa: E402
import tls_test as tt  # noqa: E402
import websocket_test as wt  # noqa: E402

KEY = b"\x01\x02\x03\x04"

# ---------------------------------------------------------------------------------------------------------------------- frames, as bytes


def masked(payload, key=KEY):
    return wt.mask_bytes(payload, key)


def cframe(op, payload=b"", fin=True, key=KEY):
    """A client frame, masked with `key` (deterministic: the bytes are compared)."""
    n = len(payload)
    b0 = (0x80 if fin else 0) | op
    if n < 126:
        head = bytes([b0, 0x80 | n])
    elif n < 65536:
        head = bytes([b0, 0x80 | 126]) + struct.pack(">H", n)
    else:
        head = bytes([b0, 0x80 | 127]) + struct.pack(">Q", n)
    return head + key + masked(payload, key)


def sframe(op, payload=b"", fin=True):
    return wt.encode_frame(op, payload, fin, mask=False)


def close_payload(code, reason=b""):
    return struct.pack(">H", code) + reason


def parse_one(buf, pos):
    """The frame at buf[pos:], as (fin, op, payload, used), or None if it is not all there. Never copies a payload that is not complete."""
    if len(buf) - pos < 2:
        return None
    b0, b1 = buf[pos], buf[pos + 1]
    n = b1 & 127
    at = pos + 2
    if n == 126:
        if len(buf) - at < 2:
            return None
        n = struct.unpack(">H", bytes(buf[at:at + 2]))[0]
        at += 2
    elif n == 127:
        if len(buf) - at < 8:
            return None
        n = struct.unpack(">Q", bytes(buf[at:at + 8]))[0]
        at += 8
    key = None
    if b1 & 0x80:
        if len(buf) - at < 4:
            return None
        key = bytes(buf[at:at + 4])
        at += 4
    if len(buf) - at < n:
        return None
    payload = bytes(buf[at:at + n])
    if key:
        payload = masked(payload, key)
    return bool(b0 & 0x80), b0 & 15, payload, at + n - pos


def frames_of(data):
    out, pos = [], 0
    while pos < len(data):
        r = parse_one(data, pos)
        if r is None:
            break
        out.append(r[:3])
        pos += r[3]
    return out, data[pos:]


def code_of(payload):
    return struct.unpack(">H", payload[:2])[0]


# ---------------------------------------------------------------------------------------------------------------------- the recording upstream


class Conn:
    def __init__(self, sock, rest, path):
        self.sock, self.raw, self.pos, self.path = sock, bytearray(rest), 0, path
        self.eof = threading.Event()
        self.done = threading.Event()
        self.total = len(rest)

    def fill(self):
        d = self.sock.recv(1 << 20)
        if not d:
            self.eof.set()
            return False
        self.raw += d
        self.total += len(d)
        return True

    def frame(self):
        """The next whole frame, or None at the end of the stream (what is left is in `raw[pos:]`)."""
        while True:
            r = parse_one(self.raw, self.pos)
            if r:
                fin, op, payload, used = r
                self.pos += used
                return fin, op, payload
            if not self.fill():
                return None

    def send(self, data):
        self.sock.sendall(data)


def serve_echo(up, c):
    while True:
        f = c.frame()
        if f is None:
            return
        fin, op, payload = f
        if op in (0, 1, 2):
            c.send(sframe(op, payload, fin))
        elif op == 9:
            c.send(sframe(10, payload))
        elif op == 8:
            c.send(sframe(8, payload[:2]))
            return


def serve_noecho(up, c):
    while c.fill():
        pass


def serve_sink(up, c):
    while c.fill():
        pass


def serve_script(up, c):
    c.send(up.script.get(c.path, b""))
    serve_echo(up, c)


def serve_pieces(up, c):
    data, rng = up.script.get(c.path, b""), random.Random(5)
    i = 0
    while i < len(data):
        k = 1 if c.path.endswith("1byte/pieces") else rng.randrange(1, 40)
        c.send(data[i:i + k])
        i += k
        time.sleep(0.0004)
    while c.fill():
        pass


def serve_big(size):
    def f(up, c):
        c.send(sframe(2, wt.big_payload(size)))
        serve_echo(up, c)
    return f


def serve_slowdrain(up, c):
    """Reads about 1 MiB every 0.1 s until one whole frame is there, then echoes."""
    while parse_one(c.raw, c.pos) is None:
        if not c.fill():
            return
        time.sleep(0.1)
    fin, op, payload, used = parse_one(c.raw, c.pos)
    c.pos += used
    up.sunk[c.path] = (hashlib.sha256(payload).hexdigest(), len(payload))
    serve_echo(up, c)


def serve_pinger(up, c):
    c.send(sframe(9, b"srv"))
    serve_echo(up, c)


def serve_closer(up, c):
    c.send(sframe(8, close_payload(1001, b"restart")))
    while True:
        f = c.frame()
        if f is None or f[1] == 8:
            return


def serve_partial(up, c):
    c.send(up.script.get(c.path, b""))


def serve_lateecho(up, c):
    time.sleep(0.5)
    serve_echo(up, c)


MODES = {"echo": serve_echo, "noecho": serve_noecho, "sink": serve_sink, "script": serve_script, "pieces": serve_pieces, "down8": serve_big(8 << 20), "down32": serve_big(32 << 20),
         "slowdrain": serve_slowdrain, "pinger": serve_pinger, "closer": serve_closer, "partial": serve_partial, "lateecho": serve_lateecho}


class Upstream:
    """A WebSocket server whose behaviour is the last segment of the path (`MODES`), and which keeps, for every path, the connection it served: every byte it received."""

    def __init__(self, port):
        self.port = port
        self.conns = {}
        self.script = {}
        self.sunk = {}
        self.lock = threading.Lock()
        self.stop = False
        self.sock = socket.socket()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", port))
        self.sock.listen(100)
        threading.Thread(target=self.accept, daemon=True).start()

    def accept(self):
        while not self.stop:
            try:
                c, _ = self.sock.accept()
            except OSError:
                return
            threading.Thread(target=self.serve, args=(c,), daemon=True).start()

    def serve(self, s):
        conn = None
        try:
            head, rest = wt.read_head(s)
            if not head:
                return
            path = head.split(b" ")[1].decode()
            h = pt.heads_of(head)
            key = h["sec-websocket-key"][0].encode()
            offered = [t.strip() for v in h.get("sec-websocket-protocol", []) for t in v.split(",") if t.strip()]
            response = "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n" % wt.accept_for(key).decode()
            if "ocpp1.6" in offered:
                response += "Sec-WebSocket-Protocol: ocpp1.6\r\n"
            s.sendall((response + "\r\n").encode())
            conn = Conn(s, rest, path)
            with self.lock:
                self.conns[path] = conn
            s.settimeout(60)
            MODES[path.rstrip("/").split("/")[-1].split("?")[0]](self, conn)
        except (OSError, EOFError, ValueError, KeyError, IndexError):
            pass
        finally:
            if conn:
                conn.done.set()
            try:
                s.close()
            except OSError:
                pass

    def conn(self, path, wait=6):
        end = time.time() + wait
        while time.time() < end:
            with self.lock:
                c = self.conns.get(path)
            if c and c.done.wait(0.05):
                return c
        raise AssertionError("the upstream connection %s did not end" % path)

    def shutdown(self):
        self.stop = True
        try:
            self.sock.close()
        except OSError:
            pass


# ---------------------------------------------------------------------------------------------------------------------- the client


def drain(ws, timeout=8):
    """Everything the gateway sends from now on until it closes the connection (what the reader already holds first)."""
    data = bytes(ws.reader.buf)
    ws.reader.buf.clear()
    ws.sock.settimeout(timeout)
    try:
        while True:
            d = ws.sock.recv(1 << 20)
            if not d:
                return data
            data += d
    except (ConnectionResetError, BrokenPipeError):
        return data
    except socket.timeout:
        raise AssertionError("the connection was still open after %.1fs (read %d bytes)" % (timeout, len(data)))


def expect_close(ws, code, echo=True):
    op, payload = ws.recv()
    while op in (0, 1, 2, 9, 10):        # what the upstream answered before the Close was decided is delivered first, or not at all
        op, payload = ws.recv()
    assert op == 8 and len(payload) >= 2 and code_of(payload) == code, "wanted a Close %d, got opcode %d %r" % (code, op, payload[:20])
    if echo:
        try:
            ws.sock.sendall(cframe(8, payload[:2]))
        except OSError:
            pass
    return payload


def up_frames(c):
    frames, rest = frames_of(bytes(c.raw))
    return frames, rest


CLOSE_1001_MASKED = bytes([0x88, 0x82, 0, 0, 0, 0, 0x03, 0xE9])


def close_masked(code):
    return bytes([0x88, 0x82, 0, 0, 0, 0]) + struct.pack(">H", code)


# ---------------------------------------------------------------------------------------------------------------------- the gateways

FROUTES = """
[[route]]
name = "small"
path_prefix = "/small"
websocket = true
subprotocols = ["ocpp1.6"]
ws_max_message_bytes = 4096
upstream = "up"

[[route]]
name = "big"
path_prefix = "/big"
websocket = true
subprotocols = ["ocpp1.6"]
ws_max_message_bytes = 268435456
upstream = "up"

[[route]]
name = "dflt"
path_prefix = "/dflt"
websocket = true
subprotocols = ["ocpp1.6"]
upstream = "up"

[[route]]
name = "libsmall"
path_prefix = "/libsmall"
websocket = true
subprotocols = ["ocpp1.6"]
ws_max_message_bytes = 4096
upstream = "lib"

[[route]]
name = "libbig"
path_prefix = "/libbig"
websocket = true
subprotocols = ["ocpp1.6"]
ws_max_message_bytes = 268435456
upstream = "lib"

[[route]]
name = "plain"
path_prefix = "/"
upstream = "up"
"""


def gateway(tmp, up, lib_port, **kw):
    return wt.Gateway(tmp, up.port, lib_port, routes=FROUTES, **kw)


def go(gw, path, **kw):
    return wt.connect_ws(gw, path, **kw)


def log_of(gw, n0, path, **want):
    return gw.find(n0, 6, path=path, **want)


# ---------------------------------------------------------------------------------------------------------------------- the tests

HELLO = cframe(1, b"hello")


class Frames:
    """On the gateway with the small (4096), default (1 MiB) and large (256 MiB) routes and a 1.5 s wait for a Close."""

    # (name, valid frames sent first and forwarded, the offending bytes, the tag, the code the client is sent)
    CLIENT_CASES = [
        ("rsv1", b"", bytes([0xC1, 0x82]) + KEY + masked(b"hi"), "ws.frame-rsv", 1002),
        ("rsv2", b"", bytes([0xA1, 0x82]) + KEY + masked(b"hi"), "ws.frame-rsv", 1002),
        ("rsv3", b"", bytes([0x91, 0x82]) + KEY + masked(b"hi"), "ws.frame-rsv", 1002),
        ("op3", b"", bytes([0x83, 0x80]) + KEY, "ws.frame-opcode", 1002),
        ("op7", b"", bytes([0x87, 0x80]) + KEY, "ws.frame-opcode", 1002),
        ("op11", b"", bytes([0x8B, 0x80]) + KEY, "ws.frame-opcode", 1002),
        ("op15", b"", bytes([0x8F, 0x80]) + KEY, "ws.frame-opcode", 1002),
        ("pingfrag", b"", bytes([0x09, 0x80]) + KEY, "ws.frame-control", 1002),
        ("pongfrag", b"", bytes([0x0A, 0x80]) + KEY, "ws.frame-control", 1002),
        ("closefrag", b"", bytes([0x08, 0x80]) + KEY, "ws.frame-control", 1002),
        ("ping126", b"", bytes([0x89, 0xFE, 0, 126]) + KEY + masked(bytes(126)), "ws.frame-control", 1002),
        ("close127", b"", bytes([0x88, 0xFF]) + struct.pack(">Q", 70000) + KEY, "ws.frame-control", 1002),
        ("close1", b"", bytes([0x88, 0x81]) + KEY + masked(b"\x03"), "ws.frame-close", 1002),
        ("unmasked", b"", bytes([0x81, 0x02]) + b"hi", "ws.frame-mask", 1002),
        ("nonmin16", b"", bytes([0x82, 0xFE, 0, 5]) + KEY + masked(b"abcde"), "ws.frame-length", 1002),
        ("nonmin16b", b"", bytes([0x82, 0xFE, 0, 125]) + KEY + masked(bytes(125)), "ws.frame-length", 1002),
        ("nonmin64", b"", bytes([0x82, 0xFF]) + struct.pack(">Q", 256) + KEY + masked(bytes(256)), "ws.frame-length", 1002),
        ("nonmin64b", b"", bytes([0x82, 0xFF]) + struct.pack(">Q", 65535) + KEY + masked(bytes(100)), "ws.frame-length", 1002),
        ("msb64", b"", bytes([0x82, 0xFF, 0x80, 0, 0, 0, 0, 0, 0, 0]) + KEY, "ws.frame-length", 1002),
        ("msb64max", b"", bytes([0x82, 0xFF]) + b"\xff" * 8 + KEY, "ws.frame-length", 1002),
        ("contfirst", b"", cframe(0, b"x"), "ws.frame-continuation", 1002),
        ("contfirstfin0", b"", cframe(0, b"x", fin=False), "ws.frame-continuation", 1002),
        ("newtextmid", cframe(1, b"a", fin=False), cframe(1, b"b"), "ws.frame-sequence", 1002),
        ("newbinmid", cframe(2, b"a", fin=False), cframe(2, b"b", fin=False), "ws.frame-sequence", 1002),
        ("bintextmid", cframe(2, b"a", fin=False), cframe(1, b"b"), "ws.frame-sequence", 1002),
        ("big", b"", bytes([0x82, 0xFE, 0x10, 0x01]) + KEY + masked(bytes(100)), "ws.message-too-big", 1009),
        ("huge", b"", bytes([0x82, 0xFF, 0x7F]) + b"\xff" * 7 + KEY, "ws.message-too-big", 1009),
        ("bigfrag", cframe(2, bytes(3000), fin=False), cframe(0, bytes(1097)), "ws.message-too-big", 1009),
        ("bigfrag3", cframe(2, bytes(2000), fin=False) + cframe(0, bytes(2000), fin=False), cframe(0, bytes(97)), "ws.message-too-big", 1009),
        ("u8overlong", b"", cframe(1, b"\xc0\x80"), "ws.frame-utf8", 1007),
        ("u8overlong3", b"", cframe(1, b"ab\xe0\x9f\xbf"), "ws.frame-utf8", 1007),
        ("u8surrogate", b"", cframe(1, b"\xed\xa0\x80"), "ws.frame-utf8", 1007),
        ("u8toobig", b"", cframe(1, b"\xf4\x90\x80\x80"), "ws.frame-utf8", 1007),
        ("u8f5", b"", cframe(1, b"x\xf5\x80\x80\x80"), "ws.frame-utf8", 1007),
        ("u8stray", b"", cframe(1, b"ok\x80"), "ws.frame-utf8", 1007),
        ("u8nocont", b"", cframe(1, b"\xc3A"), "ws.frame-utf8", 1007),
        ("u8truncated", b"", cframe(1, b"ab\xe2\x82"), "ws.frame-utf8", 1007),
        ("u8fragbad", cframe(1, b"\xe2\x82", fin=False), cframe(0, b"a"), "ws.frame-utf8", 1007),
        ("u8fragend", cframe(1, b"ab", fin=False), cframe(0, b"\xe2", fin=True), "ws.frame-utf8", 1007),
        ("u8emptyend", cframe(1, b"\xe2\x82", fin=False), cframe(0, b""), "ws.frame-utf8", 1007),
    ]

    def every_violation_by_the_client_is_closed_with_its_code_and_stays_off_the_upstream(gw, up):
        for name, valid, bad, tag, code in Frames.CLIENT_CASES:
            path = "/small/c-%s/echo" % name
            n0 = len(gw.lines())
            ws = go(gw, path)
            ws.sock.sendall(HELLO + valid + bad)
            try:
                payload = expect_close(ws, code, echo=False)
            except AssertionError as e:
                raise AssertionError("%s: %s" % (name, e))
            assert len(payload) == 2, (name, payload)
            tail = drain(ws)
            assert tail == b"", (name, "nothing but the end after the Close", tail[:40])
            e = log_of(gw, n0, path)
            assert e["rule"] == tag and e["outcome"] == "aborted" and e["status"] == 101 and e["ws_close"] == code, (name, e)
            c = up.conn(path)
            want = HELLO + valid + CLOSE_1001_MASKED
            assert bytes(c.raw) == want, "%s: the upstream received %r, wanted %r" % (name, bytes(c.raw)[:80], want[:80])

    def every_violation_by_the_upstream_is_closed_1011_and_stays_off_the_client(gw, up):
        good = sframe(1, b"from-up")
        cases = [
            ("masked", b"", cframe(1, b"hi"), "ws.frame-mask", 1002),
            ("rsv1", b"", bytes([0xC1, 0x02]) + b"hi", "ws.frame-rsv", 1002),
            ("op3", b"", bytes([0x83, 0x00]), "ws.frame-opcode", 1002),
            ("op12", b"", bytes([0x8C, 0x00]), "ws.frame-opcode", 1002),
            ("pingfrag", b"", bytes([0x09, 0x00]), "ws.frame-control", 1002),
            ("ping126", b"", bytes([0x89, 0x7E, 0, 126]) + bytes(126), "ws.frame-control", 1002),
            ("close1", b"", bytes([0x88, 0x01, 0x03]), "ws.frame-close", 1002),
            ("nonmin16", b"", bytes([0x82, 0x7E, 0, 5]) + b"abcde", "ws.frame-length", 1002),
            ("nonmin64", b"", bytes([0x82, 0x7F]) + struct.pack(">Q", 300) + bytes(300), "ws.frame-length", 1002),
            ("msb64", b"", bytes([0x82, 0x7F, 0x80, 0, 0, 0, 0, 0, 0, 0]), "ws.frame-length", 1002),
            ("contfirst", b"", sframe(0, b"x"), "ws.frame-continuation", 1002),
            ("textmid", sframe(1, b"a", fin=False), sframe(1, b"b"), "ws.frame-sequence", 1002),
            ("big", b"", bytes([0x82, 0x7E, 0x10, 0x01]) + bytes(100), "ws.message-too-big", 1009),
            ("bigfrag", sframe(2, bytes(3000), fin=False), sframe(0, bytes(1097)), "ws.message-too-big", 1009),
            ("u8overlong", b"", sframe(1, b"\xc0\x80"), "ws.frame-utf8", 1007),
            ("u8surrogate", b"", sframe(1, b"a\xed\xa0\x80"), "ws.frame-utf8", 1007),
            ("u8truncated", b"", sframe(1, b"ab\xe2\x82"), "ws.frame-utf8", 1007),
            ("u8fragbad", sframe(1, b"\xe2\x82", fin=False), sframe(0, b"a"), "ws.frame-utf8", 1007),
        ]
        for name, valid, bad, tag, code in cases:
            path = "/small/u-%s/script" % name
            up.script[path] = good + valid + bad
            n0 = len(gw.lines())
            ws = go(gw, path)
            # exactly what was valid, then the gateway's Close 1011 (88 02 03 f3), and nothing of the offending bytes
            want = good + valid + bytes([0x88, 0x02, 0x03, 0xF3])
            got = bytes(ws.reader.buf)
            ws.reader.buf.clear()
            while len(got) < len(want):
                d = ws.sock.recv(65536)
                assert d, "%s: the connection ended after %r" % (name, got[:60])
                got += d
            assert got == want, "%s: the client received %r, wanted %r" % (name, got[:80], want[:80])
            ws.sock.sendall(cframe(8, close_payload(1011)))
            assert drain(ws) == b"", name
            e = log_of(gw, n0, path)
            assert e["rule"] == tag and e["outcome"] == "aborted" and e["ws_close"] == 1011, (name, e)
            c = up.conn(path)
            frames, rest = up_frames(c)
            assert rest == b"" and frames[-1][1] == 8 and code_of(frames[-1][2]) == code, (name, frames[-3:], "the upstream is sent the code of its own fault")

    def a_violation_inside_a_payload_closes_the_client_but_cannot_close_the_upstream(gw, up):
        path = "/small/mid/echo"
        n0 = len(gw.lines())
        ws = go(gw, path)
        frame = cframe(1, b"abc\xffdef")
        ws.sock.sendall(HELLO + frame[:6 + 3])      # the header and "abc": forwarded, the frame is inside its payload
        ws.expect(1, b"hello")
        time.sleep(0.3)
        ws.sock.sendall(frame[6 + 3:])
        expect_close(ws, 1007, echo=False)
        assert drain(ws) == b""
        e = log_of(gw, n0, path)
        assert e["rule"] == "ws.frame-utf8" and e["ws_close"] == 1007, e
        c = up.conn(path)
        assert bytes(c.raw) == HELLO + frame[:6 + 3], "no Close can follow half a frame: the upstream got the bytes that were valid and then the end"
        assert c.eof.is_set()

    def truncated_frames_then_the_end_of_the_stream(gw, up):
        cases = [("t-payload", cframe(1, b"0123456789")[:6 + 4], "the header and four bytes of the payload"), ("t-header", cframe(1, b"x")[:1], "one byte of a header"),
                 ("t-header5", cframe(1, b"x")[:5], "a header without its whole key"), ("t-ext", bytes([0x82, 0xFE, 0x01]), "half a 16-bit length")]
        for name, partial, why in cases:
            path = "/small/%s/sink" % name
            n0 = len(gw.lines())
            ws = go(gw, path)
            ws.sock.sendall(HELLO + partial)
            time.sleep(0.2)
            ws.sock.shutdown(socket.SHUT_WR)
            ws.close()
            e = log_of(gw, n0, path)
            assert e["rule"] == "ws.frame-truncated" and e["outcome"] == "aborted" and "ws_close" not in e, (why, e)
            c = up.conn(path)
            held = len(partial) if name == "t-payload" else 0
            assert bytes(c.raw) == HELLO + partial[:held], (why, bytes(c.raw)[-20:])
        # from the upstream
        path = "/small/t-up/partial"
        up.script[path] = sframe(1, b"whole") + sframe(1, b"0123456789")[:5]
        n0 = len(gw.lines())
        ws = go(gw, path)
        assert drain(ws) == up.script[path], "the whole frame, and the header and three bytes of the next: what the upstream sent, then the end"
        e = log_of(gw, n0, path)
        assert e["rule"] == "ws.frame-truncated", e
        path = "/small/t-up2/partial"
        up.script[path] = sframe(1, b"whole") + bytes([0x82, 0x7E, 0x01])
        n0 = len(gw.lines())
        ws = go(gw, path)
        assert drain(ws) == sframe(1, b"whole")
        e = log_of(gw, n0, path)
        assert e["rule"] == "ws.frame-truncated", e
        # the end of a stream at a boundary is not a truncation
        path = "/small/t-clean/sink"
        n0 = len(gw.lines())
        ws = go(gw, path)
        ws.sock.sendall(HELLO)
        ws.close()
        e = log_of(gw, n0, path)
        assert e["rule"] == "" and e["outcome"] == "ok", e

    def a_message_of_exactly_the_limit_passes_and_one_byte_more_does_not(gw, up):
        ws = go(gw, "/small/limit/echo")
        for n in (4095, 4096):
            p = os.urandom(n)
            ws.send(2, p)
            ws.expect(2, p)
        fragments = [os.urandom(1000) for _ in range(4)] + [os.urandom(96)]
        for i, f in enumerate(fragments):
            ws.send(2 if i == 0 else 0, f, fin=i == len(fragments) - 1)
        for i, f in enumerate(fragments):
            op, payload = ws.recv()
            assert op == (2 if i == 0 else 0) and payload == f
        n0 = len(gw.lines())
        for i, f in enumerate(fragments + [b"x"]):
            ws.sock.sendall(cframe(2 if i == 0 else 0, f, fin=False))
        expect_close(ws, 1009, echo=False)
        e = log_of(gw, n0, "/small/limit/echo")
        assert e["rule"] == "ws.message-too-big", e
        c = up.conn("/small/limit/echo")
        frames, rest = up_frames(c)
        assert frames[-1][1] == 8 and code_of(frames[-1][2]) == 1001, frames[-1]
        assert sum(len(p) for _, op, p in frames[-6:-1]) == 4096, "the fragments up to the limit went, the one that crossed it did not"
        ws.close()

    def valid_traffic_is_unchanged_in_any_delivery(gw, up):
        multibyte = "é€😀 ocpp ünï".encode()
        stream = b"".join([
            cframe(1, b"hello"), cframe(2, b""), cframe(1, b""), cframe(2, bytes(range(125))), cframe(2, bytes(range(126))), cframe(2, bytes(range(127))),
            cframe(2, os.urandom(300)), cframe(1, multibyte[:3], fin=False), cframe(9, b"p"), cframe(0, multibyte[3:8], fin=False), cframe(10, b""),
            cframe(0, multibyte[8:], fin=True), cframe(1, multibyte), cframe(10, b"unsolicited"), cframe(2, os.urandom(1000)), cframe(2, os.urandom(3000)),
            cframe(9, b""), cframe(1, b"last"),
        ])
        small = stream[:700]
        frames, rest = frames_of(small)
        small = small[:len(small) - len(rest)]
        rng = random.Random(8)
        for label, data in (("whole", stream), ("one byte at a time", small), ("random pieces", stream)):
            path = "/small/valid-%s/sink" % label.replace(" ", "-")
            n0 = len(gw.lines())
            ws = go(gw, path)
            ws.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            if label == "whole":
                ws.sock.sendall(data)
            elif label == "one byte at a time":
                for i in range(len(data)):
                    ws.sock.sendall(data[i:i + 1])
                    time.sleep(0.0004)
            else:
                i = 0
                while i < len(data):
                    k = rng.randrange(1, 60)
                    ws.sock.sendall(data[i:i + k])
                    i += k
                    time.sleep(0.0006)
            time.sleep(0.3)
            ws.close()
            e = log_of(gw, n0, path)
            assert e["rule"] == "" and e["outcome"] == "ok" and e["bytes_in"] == len(data), (label, e)
            c = up.conn(path)
            assert bytes(c.raw) == data, "%s: the upstream received %d bytes, wanted %d, and they differ" % (label, len(c.raw), len(data))
        # the same, from the upstream to the client
        for label, mode in (("one-byte", "1byte"), ("pieces", "x")):
            path = "/small/down-%s/pieces" % mode
            data = b"".join(sframe(*a) for a in [(1, b"hello"), (2, bytes(range(200))), (1, multibyte[:3], False), (9, b"p"), (0, multibyte[3:], True), (10, b"unsolicited"), (2, os.urandom(130))])
            if mode == "1byte":
                path = "/small/down-1byte/pieces"
                data = data[:300]
                data = data[:len(data) - len(frames_of(data)[1])]
            up.script[path] = data
            ws = go(gw, path)
            got = bytes(ws.reader.buf)      # what came with the head
            ws.reader.buf.clear()
            while len(got) < len(data):
                d = ws.sock.recv(65536)
                assert d, "the stream ended early"
                got += d
            assert got == data, label
            ws.close()

    def fragmented_messages_with_pings_between_the_fragments(gw, up):
        ws = go(gw, "/small/frag/echo")
        parts = [b"alpha ", b"beta ", "gamma é".encode()[:7], "gamma é".encode()[7:]]
        ws.send(1, parts[0], fin=False)
        ws.send(9, b"mid")
        ws.send(0, parts[1], fin=False)
        ws.send(10, b"un")
        ws.send(0, parts[2], fin=False)
        ws.send(9, b"")
        ws.send(0, parts[3], fin=True)
        want = [(1, False, parts[0]), (10, True, b"mid"), (0, False, parts[1]), (0, False, parts[2]), (10, True, b""), (0, True, parts[3])]  # (opcode, fin, payload)
        got = []
        for _ in range(len(want)):
            fin, op, payload = ws.reader.frame()
            got.append((op, fin, payload))
        assert got == want, got
        ws.close()

    def a_message_through_the_default_limit_and_the_largest_ones_with_slow_readers(gw, up):
        ws = go(gw, "/dflt/one/echo", timeout=30)
        p = os.urandom(1 << 20)
        ws.send(2, p)
        ws.expect(2, p)
        n0 = len(gw.lines())
        ws.sock.sendall(cframe(2, bytes(1 << 20 | 1)))
        expect_close(ws, 1009, echo=False)
        e = log_of(gw, n0, "/dflt/one/echo")
        assert e["rule"] == "ws.message-too-big", e
        for size in (1 << 20, 8 << 20, 32 << 20):
            path = "/big/m%d/echo" % size
            ws = go(gw, path, timeout=60, rcvbuf=65536)
            p = wt.big_payload(size)
            sender = threading.Thread(target=lambda: ws.sock.sendall(wt.encode_frame(2, p)), daemon=True)
            sender.start()
            time.sleep(1.0)                  # the reader reads late: the echo has to wait for it
            got = ws.expect(2)
            assert hashlib.sha256(got).digest() == hashlib.sha256(p).digest() and len(got) == size, size
            sender.join(20)
            ws.close()
        # fragments of 64 KiB, 8 MiB in all, with the reader a second late
        ws = go(gw, "/big/frags/echo", timeout=60, rcvbuf=65536)
        p = wt.big_payload(8 << 20)

        def send_fragments():
            for i in range(0, len(p), 65536):
                ws.sock.sendall(wt.encode_frame(2 if i == 0 else 0, p[i:i + 65536], fin=i + 65536 >= len(p)))

        threading.Thread(target=send_fragments, daemon=True).start()
        time.sleep(1.0)
        got = b""
        while len(got) < len(p):
            op, payload = ws.recv()
            got += payload
        assert got == p
        ws.close()

    def a_client_that_is_still_sending_when_it_is_refused_still_gets_its_close(gw, up):
        path = "/small/flood/sink"
        n0 = len(gw.lines())
        ws = go(gw, path, timeout=30)
        flood = bytes([0x82, 0xFE, 0x10, 0x01]) + KEY + os.urandom(6 << 20)

        def send():
            try:
                ws.sock.sendall(flood)
            except OSError:
                pass

        t = threading.Thread(target=send, daemon=True)
        t.start()
        payload = expect_close(ws, 1009, echo=False)
        assert code_of(payload) == 1009
        t.join(20)
        e = log_of(gw, n0, path)
        assert e["rule"] == "ws.message-too-big" and e["ws_close"] == 1009, e

    def a_close_from_either_peer_is_passed_through_and_answered(gw, up):
        path = "/small/cc/echo"
        n0 = len(gw.lines())
        ws = go(gw, path)
        ws.sock.sendall(cframe(8, close_payload(1000, b"bye")))
        op, payload = ws.recv()
        assert op == 8 and code_of(payload) == 1000, payload       # the upstream (this one) answers with the code alone
        assert drain(ws) == b""
        e = log_of(gw, n0, path)
        assert e["rule"] == "" and e["outcome"] == "ok" and e["ws_close"] == 1000, e
        c = up.conn(path)
        assert bytes(c.raw) == cframe(8, close_payload(1000, b"bye")), "the upstream saw the client's Close exactly, and nothing of the gateway's"
        # from the upstream
        path = "/small/cu/closer"
        n0 = len(gw.lines())
        ws = go(gw, path)
        op, payload = ws.recv()
        assert op == 8 and payload == close_payload(1001, b"restart"), payload
        ws.sock.sendall(cframe(8, close_payload(1001)))
        assert drain(ws) == b""
        e = log_of(gw, n0, path)
        assert e["rule"] == "" and e["outcome"] == "ok" and e["ws_close"] == 1001, e
        # a Close with no code is 1005 in the log
        path = "/small/c0/echo"
        n0 = len(gw.lines())
        ws = go(gw, path)
        ws.sock.sendall(cframe(8, b""))
        op, payload = ws.recv()
        assert op == 8
        drain(ws)
        assert log_of(gw, n0, path)["ws_close"] == 1005
        # a frame after a Close from the same peer is refused
        path = "/small/cx/echo"
        n0 = len(gw.lines())
        ws = go(gw, path)
        ws.sock.sendall(cframe(8, close_payload(1000)) + cframe(1, b"late"))
        data = drain(ws)
        e = log_of(gw, n0, path)
        assert e["rule"] == "ws.frame-after-close", e
        c = up.conn(path)
        frames, rest = up_frames(c)
        assert [f[1] for f in frames][:1] == [8] and not any(f[1] == 1 for f in frames), frames

    def a_peer_that_never_answers_a_close_is_closed_at_the_wait(gw, up):
        path = "/small/cn/noecho"
        n0 = len(gw.lines())
        ws = go(gw, path)
        t0 = time.time()
        ws.sock.sendall(cframe(8, close_payload(1000)))
        data = drain(ws, 6)
        took = time.time() - t0
        assert 1.3 < took < 2.6, took
        e = log_of(gw, n0, path)
        assert e["rule"] == "ws.close-timeout" and e["outcome"] == "aborted" and e["ws_close"] == 1000, e

    def the_counters(gw, up):
        gw.wait_active(0)
        m0 = gw.metrics()["ws"]
        refusals0 = gw.metrics()["refusals"].get("ws.frame-rsv", 0)
        ws = go(gw, "/small/count/echo")
        for i in range(3):
            ws.text("m%d" % i)
            ws.expect(1, b"m%d" % i)
        ws.send(8, close_payload(1000))
        ws.expect(8)
        drain(ws)
        gw.wait_active(0)
        m1 = gw.metrics()["ws"]
        assert m1["messages"] == m0["messages"] + 6, (m0, m1)
        assert m1["closes"]["1000"] == m0["closes"]["1000"] + 1 and set(m1["closes"]) == {"1000", "1001", "1002", "1007", "1008", "1009", "1011", "other"}, m1
        assert m1["pings"] == m0["pings"] and m1["pong_timeouts"] == m0["pong_timeouts"]
        ws = go(gw, "/small/count2/echo")
        ws.sock.sendall(bytes([0xC1, 0x80]) + KEY)
        expect_close(ws, 1002, echo=False)
        drain(ws)
        gw.wait_active(0)
        refusals = gw.metrics()["refusals"]
        assert refusals.get("ws.frame-rsv", 0) == refusals0 + 1, refusals
        assert gw.metrics()["ws"]["closes"]["1002"] == m1["closes"]["1002"] + 1
        text = socket.create_connection(("127.0.0.1", gw.admin), timeout=5)
        text.sendall(b"GET /metrics?format=prometheus HTTP/1.1\r\nHost: a\r\nAccept: text/plain\r\nConnection: close\r\n\r\n")
        data = b""
        while True:
            d = text.recv(65536)
            if not d:
                break
            data += d
        text.close()
        for name in (b"ws_messages_total", b"ws_pings_total", b"ws_pong_timeouts_total"):
            assert b"cancho_gateway_" + name + b" " in data, name
        assert b'cancho_gateway_ws_closes_total{code="1011"} ' in data and b'cancho_gateway_ws_closes_total{code="other"} ' in data


class Keep:
    """On the gateway with a Ping after 1 s of silence, 0.8 s to answer it, an idle time of 2.5 s and a 1 s wait for a Close."""

    def a_client_that_does_not_answer_is_closed_at_the_pong_deadline(gw, up):
        path = "/small/dead/echo"
        n0 = len(gw.lines())
        m0 = gw.metrics()["ws"]
        ws = go(gw, path)
        t0 = time.time()
        data = drain(ws, 8)            # never reads, never answers: the Ping, the Close and the end
        took = time.time() - t0
        assert 1.5 < took < 3.2, "closed after %.2fs (a Ping at 1.0 s, 0.8 s to answer)" % took
        frames, rest = frames_of(data)
        assert rest == b"" and [f[1] for f in frames] == [9, 8] and len(frames[0][2]) == 8 and code_of(frames[1][2]) == 1001, frames
        e = log_of(gw, n0, path)
        assert e["rule"] == "ws.pong-timeout" and e["outcome"] == "aborted" and e["ws_close"] == 1001, e
        c = up.conn(path)
        assert bytes(c.raw) == CLOSE_1001_MASKED, "the upstream never saw the Ping, and is told 1001: %r" % bytes(c.raw)
        m1 = gw.metrics()["ws"]
        assert m1["pings"] == m0["pings"] + 1 and m1["pong_timeouts"] == m0["pong_timeouts"] + 1, (m0, m1)

    def a_client_that_answers_stays_past_the_idle_time_and_the_upstream_never_sees_the_pings(gw, up):
        path = "/small/live/echo"
        n0 = len(gw.lines())
        m0 = gw.metrics()["ws"]
        ws = go(gw, path)
        stop = threading.Event()
        seen = []

        def answer():
            ws.sock.settimeout(0.2)
            while not stop.is_set():
                try:
                    fin, op, payload = ws.reader.frame()
                except socket.timeout:
                    continue
                except (EOFError, OSError):
                    seen.append("closed")
                    return
                seen.append(op)
                if op == 9:
                    ws.sock.sendall(cframe(10, payload))

        t = threading.Thread(target=answer, daemon=True)
        t0 = time.time()
        t.start()
        time.sleep(6.5)                 # idle time 2.5 s, ping every second of silence: it is not idle, it answers
        stop.set()
        t.join(3)
        assert "closed" not in seen and seen.count(9) >= 4, seen
        assert time.time() - t0 > 6
        ws.sock.settimeout(5)
        ws.send(1, b"still here")
        op, payload = ws.recv()
        while op in (9,):
            ws.sock.sendall(cframe(10, payload))
            op, payload = ws.recv()
        assert (op, payload) == (1, b"still here")
        ws.send(8, close_payload(1000))
        assert drain(ws) is not None
        e = log_of(gw, n0, path)
        assert e["rule"] == "" and e["outcome"] == "ok", e
        c = up.conn(path)
        frames, rest = up_frames(c)
        assert [(f[1], f[2]) for f in frames] == [(1, b"still here"), (8, close_payload(1000))], frames
        m1 = gw.metrics()["ws"]
        assert m1["pings"] >= m0["pings"] + 4 and m1["pong_timeouts"] == m0["pong_timeouts"], (m0, m1)

    def a_client_that_is_sending_is_not_pinged_and_one_that_ignores_pings_while_sending_is_not_closed(gw, up):
        path = "/small/busy/sink"
        n0 = len(gw.lines())
        m0 = gw.metrics()["ws"]
        ws = go(gw, path)
        t0 = time.time()
        sent = b""
        while time.time() - t0 < 3.5:       # a message every 0.3 s: the client is never silent for a second
            f = cframe(1, b"chatter")
            ws.sock.sendall(f)
            sent += f
            time.sleep(0.3)
        assert gw.metrics()["ws"]["pings"] == m0["pings"], "a chatty client is not pinged"
        # ... and one that is silent for the ping time and ignores the Ping, but then keeps sending (a Pong would be behind its own data), is alive: the deadline counts from the last byte
        time.sleep(1.5)
        ws.sock.settimeout(1)
        ping = ws.sock.recv(100)
        assert len(ping) == 10 and ping[0] == 0x89, ping
        t0 = time.time()
        while time.time() - t0 < 2.5:
            f = cframe(1, b"slow")
            ws.sock.sendall(f)
            sent += f
            time.sleep(0.3)
        ws.close()
        e = log_of(gw, n0, path)
        assert e["rule"] == "" and e["outcome"] == "ok", e
        assert bytes(up.conn(path).raw) == sent

    def user_pings_and_pongs_pass_both_ways_and_the_gateways_own_does_not(gw, up):
        path = "/small/user/pinger"
        ws = go(gw, path)
        op, payload = ws.recv()
        assert (op, payload) == (9, b"srv"), (op, payload)      # the upstream's Ping reaches the client
        ws.sock.sendall(cframe(10, b"srv"))                       # its Pong reaches the upstream
        ws.send(9, b"abc")                                        # the client's Ping reaches the upstream, whose Pong comes back
        ws.expect(10, b"abc")
        ws.send(10, b"unsolicited")
        ws.text("x")
        ws.expect(1, b"x")
        time.sleep(1.6)                                           # the gateway's own Ping goes out and is answered
        ws.sock.settimeout(3)
        op, payload = ws.recv()
        assert op == 9 and len(payload) == 8 and payload != b"srv", (op, payload)
        ws.sock.sendall(cframe(10, payload))
        ws.send(8, close_payload(1000))
        drain(ws)
        c = up.conn(path)
        frames, rest = up_frames(c)
        assert [(f[1], f[2]) for f in frames] == [(10, b"srv"), (9, b"abc"), (10, b"unsolicited"), (1, b"x"), (8, close_payload(1000))], frames

    def the_ping_waits_for_the_end_of_a_frame_in_flight(gw, up):
        path = "/big/pingwait/down8"
        ws = go(gw, path, timeout=30, rcvbuf=4096)
        time.sleep(1.8)                   # the 8 MiB frame cannot be delivered; a Ping is due and must not be put inside it
        ws.sock.settimeout(20)
        fin, op, payload = ws.reader.frame()
        assert (op, len(payload)) == (2, 8 << 20) and payload == wt.big_payload(8 << 20)
        ws.sock.settimeout(5)
        fin, op, payload = ws.reader.frame()
        assert op == 9 and len(payload) == 8, (op, payload)
        ws.sock.sendall(cframe(10, payload))
        ws.send(8, close_payload(1000))
        drain(ws)


class Life:
    """On the gateway with a lifetime of 3 s and 20 s to answer a Close: the Close must wait for the frame in flight."""

    def a_close_from_the_lifetime_waits_for_the_frame_the_upstream_is_sending(gw, up):
        path = "/big/life-down/down32"
        n0 = len(gw.lines())
        ws = go(gw, path, timeout=60, rcvbuf=65536)
        t0 = time.time()
        got = bytearray()
        ws.sock.settimeout(30)
        # read the 32 MiB frame slowly, 2 MiB every 0.25 s: it is still arriving when the lifetime ends at 3 s
        raw = bytearray()
        want = 10 + (32 << 20)
        pause = 2 << 20
        while len(raw) < want:
            d = ws.sock.recv(1 << 21)
            assert d, "ended early"
            raw += d
            if len(raw) >= pause:
                pause += 2 << 20
                time.sleep(0.25)
        assert time.time() - t0 > 3.2, "the frame was delivered before the lifetime ended: the test measures nothing"
        frame_bytes = bytes(raw[:want])
        r = parse_one(frame_bytes, 0)
        assert r and r[1] == 2 and r[2] == wt.big_payload(32 << 20), "the 32 MiB frame arrived whole and intact (the Close did not split it)"
        rest = bytes(raw[want:])
        ws.sock.settimeout(10)
        while len(rest) < 4:
            d = ws.sock.recv(100)
            assert d
            rest += d
        assert rest[:4] == bytes([0x88, 0x02, 0x03, 0xE9]), "then the Close, 1001: %r" % rest[:10]
        ws.sock.sendall(cframe(8, rest[2:4]))
        drain(ws)
        e = log_of(gw, n0, path)
        assert e["rule"] == "ws.lifetime" and e["outcome"] == "aborted" and e["ws_close"] == 1001, e
        assert e["ms"] >= 3000, e

    def a_close_from_the_lifetime_waits_for_the_frame_the_client_is_sending(gw, up):
        path = "/big/life-up/slowdrain"
        n0 = len(gw.lines())
        ws = go(gw, path, timeout=60)
        payload = wt.big_payload(32 << 20)
        frame = wt.encode_frame(2, payload)
        sender = threading.Thread(target=lambda: ws.sock.sendall(frame), daemon=True)
        t0 = time.time()
        sender.start()
        # the client is told at the end of its lifetime (the downstream is at a frame boundary), while its own frame is still going up
        ws.sock.settimeout(20)
        op, p = ws.recv()
        took = time.time() - t0
        assert op == 8 and code_of(p) == 1001 and 2.8 < took < 4.5, (op, p[:10], took)
        sender.join(30)
        assert not sender.is_alive(), "the client's frame was cut off by the Close"
        ws.sock.sendall(cframe(8, p[:2]))
        drain(ws, 20)
        c = up.conn(path, 20)
        assert up.sunk[path] == (hashlib.sha256(payload).hexdigest(), len(payload)), "the upstream got the whole frame"
        frames, rest = up_frames(c)
        assert rest == b"" and frames and frames[-1][1] == 8 and code_of(frames[-1][2]) == 1001, "... and then the Close, whole"
        e = log_of(gw, n0, path)
        assert e["rule"] == "ws.lifetime" and e["ws_close"] == 1001, e


class Tls:
    """The routes of `Frames` over `tls_listen`."""

    def a_violation_and_a_close_over_wss(gw, up):
        path = "/small/wss-v/echo"
        n0 = len(gw.lines())
        ws = go(gw, path, tls=True, host="api.example")
        ws.sock.sendall(HELLO + bytes([0xC1, 0x82]) + KEY + masked(b"hi"))
        expect_close(ws, 1002, echo=False)
        e = log_of(gw, n0, path)
        assert e["rule"] == "ws.frame-rsv" and e["tls"] is True and e["ws_close"] == 1002, e
        assert bytes(up.conn(path).raw) == HELLO + CLOSE_1001_MASKED
        # invalid UTF-8 and a message over the limit
        for name, bad, tag, code in (("u8", cframe(1, b"\xed\xa0\x80"), "ws.frame-utf8", 1007), ("big", bytes([0x82, 0xFE, 0x10, 0x01]) + KEY + bytes(50), "ws.message-too-big", 1009)):
            path = "/small/wss-%s/echo" % name
            n0 = len(gw.lines())
            ws = go(gw, path, tls=True, host="api.example")
            ws.sock.sendall(bad)
            expect_close(ws, code, echo=False)
            assert log_of(gw, n0, path)["rule"] == tag
        # valid traffic of every kind, a Close that is passed through
        path = "/small/wss-ok/echo"
        n0 = len(gw.lines())
        ws = go(gw, path, tls=True, host="api.example")
        for n in (0, 1, 125, 126, 4000):
            p = os.urandom(n)
            ws.send(2, p)
            ws.expect(2, p)
        ws.send(9, b"ping")
        ws.expect(10, b"ping")
        ws.send(8, close_payload(1000))
        ws.expect(8)
        drain(ws)
        assert log_of(gw, n0, path)["ws_close"] == 1000

    def big_messages_over_wss_with_a_late_reader(gw, up):
        ws = go(gw, "/big/wss-big/echo", tls=True, host="api.example", timeout=60)
        p = wt.big_payload(8 << 20)
        sender = threading.Thread(target=lambda: ws.sock.sendall(wt.encode_frame(2, p)), daemon=True)
        sender.start()
        time.sleep(1.0)
        assert ws.expect(2) == p
        ws.close()

    def a_timer_close_over_wss(gw, up):
        path = "/small/wss-idle/echo"
        n0 = len(gw.lines())
        ws = go(gw, path, tls=True, host="api.example")
        op, payload = ws.recv()
        assert op == 8 and code_of(payload) == 1001, (op, payload)
        ws.sock.sendall(cframe(8, payload[:2]))
        e = log_of(gw, n0, path)
        assert e["rule"] == "ws.idle-timeout" and e["tls"] is True and e["ws_close"] == 1001, e

    def a_websockets_client_over_wss(gw, up):
        websockets, asyncio = wt.third_party()
        ctx = tt.context(gw, None, ("http/1.1",))
        n0 = len(gw.lines())

        async def run():
            async with websockets.connect("wss://127.0.0.1:%d/libbig/wlc" % gw.tls_port, subprotocols=["ocpp1.6"], ssl=ctx, server_hostname="api.example", max_size=None, open_timeout=10,
                                          ping_interval=None) as c:
                await c.send("wss é")
                assert await c.recv() == "wss é"
                blob = os.urandom(1 << 20)
                await c.send(blob)
                assert await c.recv() == blob
                await c.close(1000)
            async with websockets.connect("wss://127.0.0.1:%d/libsmall/wlc2" % gw.tls_port, subprotocols=["ocpp1.6"], ssl=ctx, server_hostname="api.example", max_size=None, open_timeout=10,
                                          ping_interval=None) as c:
                await c.send(b"z" * 9000)
                try:
                    await asyncio.wait_for(c.recv(), 5)
                    raise AssertionError("echoed")
                except websockets.ConnectionClosed:
                    pass
                assert c.close_code == 1009

        asyncio.run(run())
        assert log_of(gw, n0, "/libsmall/wlc2")["rule"] == "ws.message-too-big"


class Interop:
    """The `websockets` library (17.2) as a client and as an upstream, plain and over TLS (skipped without it)."""

    def a_websockets_client_valid_traffic_a_message_over_the_limit_and_a_close(gw, up):
        websockets, asyncio = wt.third_party()
        n0 = len(gw.lines())

        async def run():
            async with websockets.connect("ws://127.0.0.1:%d/libbig/lc" % gw.port, subprotocols=["ocpp1.6"], max_size=None, open_timeout=10, ping_interval=None) as c:
                await c.send("héllo €")
                assert await c.recv() == "héllo €"
                blob = os.urandom(300000)
                await c.send(blob)
                assert await c.recv() == blob
                await asyncio.wait_for(await c.ping(b"abc"), 5)
                await c.close(1000, "bye")
                assert c.close_code == 1000, c.close_code
            async with websockets.connect("ws://127.0.0.1:%d/libsmall/lc2" % gw.port, subprotocols=["ocpp1.6"], max_size=None, open_timeout=10, ping_interval=None) as c:
                await c.send("x" * 5000)
                try:
                    await asyncio.wait_for(c.recv(), 5)
                    raise AssertionError("a message over the limit was echoed")
                except websockets.ConnectionClosed:
                    pass
                assert c.close_code == 1009, c.close_code

        asyncio.run(run())
        assert log_of(gw, n0, "/libbig/lc")["ws_close"] == 1000
        e = log_of(gw, n0, "/libsmall/lc2")
        assert e["rule"] == "ws.message-too-big" and e["ws_close"] == 1009, e

    def a_websockets_client_at_the_limit_text_and_binary(gw, up):
        websockets, asyncio = wt.third_party()

        async def run():
            async with websockets.connect("ws://127.0.0.1:%d/libsmall/at-limit" % gw.port, subprotocols=["ocpp1.6"], max_size=None, open_timeout=10, ping_interval=None) as c:
                await c.send("y" * 4096)
                assert await c.recv() == "y" * 4096
                await c.send(b"\xff" * 4096)
                assert await c.recv() == b"\xff" * 4096

        asyncio.run(run())

# ---------------------------------------------------------------------------------------------------------------------- the runner


def main():
    groups = {"Frames": Frames, "Keep": Keep, "Life": Life, "Tls": Tls, "Interop": Interop}
    wanted = sys.argv[1:]
    todo = []
    for gname, cls in groups.items():
        for name in vars(cls):
            if name.startswith("_") or not callable(getattr(cls, name)) or name.isupper():
                continue
            if not wanted or name in wanted or gname in wanted:
                todo.append((gname, cls, name))
    unknown = [w for w in wanted if not any(w == t[2] or w == t[0] for t in todo)]
    if unknown:
        print("no such test: %s" % ", ".join(unknown))
        return 2
    failures = skipped = 0
    needed = {g for g, _, _ in todo}
    with tempfile.TemporaryDirectory() as t1, tempfile.TemporaryDirectory() as t2, tempfile.TemporaryDirectory() as t3, tempfile.TemporaryDirectory() as t4:
        up = Upstream(pt.free_port())
        lib_port = pt.free_port()
        lib = None
        try:
            lib = wt.LibServer(*wt.third_party(), lib_port)
        except wt.Skip:
            pass
        gws = {}
        try:
            if needed & {"Frames", "Interop"}:
                gws["Frames"] = gateway(t1, up, lib_port, close_ms=1500)
                gws["Interop"] = gws["Frames"]
            if "Keep" in needed:
                gws["Keep"] = gateway(t2, up, lib_port, idle=2500, close_ms=1000, extra="ws_ping_ms = 1000\nws_pong_ms = 800\n")
            if "Life" in needed:
                gws["Life"] = gateway(t3, up, lib_port, lifetime=3000, close_ms=20000)
            if "Tls" in needed:
                gws["Tls"] = gateway(t4, up, lib_port, idle=2000, tls=True, close_ms=800)
            for gname, cls, name in todo:
                gw = gws[gname]
                t0 = time.time()
                try:
                    getattr(cls, name)(gw, up)
                    if not gw.alive():
                        raise AssertionError("the gateway died")
                    print("ok    %-90s %.1fs" % (name, time.time() - t0))
                except wt.Skip as e:
                    skipped += 1
                    print("skip  %-90s %s" % (name, e))
                except (AssertionError, OSError, EOFError, KeyError, IndexError, ValueError) as e:
                    failures += 1
                    print("FAIL  %-90s %s: %s" % (name, type(e).__name__, e))
                    if os.environ.get("WS_TRACE"):
                        traceback.print_exc()
                    if not gw.alive():
                        print("      the gateway died: exit %s %s" % (gw.proc.returncode, gw.proc.stderr.read()[:300]))
                        break
        finally:
            for gw in {id(g): g for g in gws.values()}.values():
                gw.stop()
            up.shutdown()
            if lib:
                lib.stop()
    print("%d tests, %d failures%s" % (len(todo), failures, ", %d skipped" % skipped if skipped else ""))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
