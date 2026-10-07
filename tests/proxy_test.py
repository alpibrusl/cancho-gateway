#!/usr/bin/env python3
"""End-to-end tests of the proxy core (task #5, docs/proxy.md): the built gateway, real sockets, a scripted upstream that
misbehaves on purpose.

    python3 tests/proxy_test.py [NAME ...]     # all tests, or the named ones

A deployment with short timeouts is generated, the gateway built from it, and each test drives it with raw sockets.
"""

import hashlib
import json
import os
import pathlib
import random
import re
import socket
import subprocess
import sys
import tempfile
import threading
import time

ROOT = pathlib.Path(__file__).resolve().parent.parent
LEX = os.environ.get("LEX_SYS", "lex-sys")
SOURCES = ["out", "problem", "framing", "chunked", "route", "response", "forward", "egress", "proxy", "version", "gateway"]


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class Upstream:
    """Behaviour is chosen by the request path; every connection and every request head is recorded."""

    def __init__(self, port):
        self.port = port
        self.lock = threading.Lock()
        self.connections = 0
        self.heads = []
        self.eof_seen = []        # paths whose connection the gateway closed on us
        self.stop = False
        self.sock = socket.socket()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", port))
        self.sock.listen(200)
        threading.Thread(target=self.accept, daemon=True).start()

    def accept(self):
        while not self.stop:
            try:
                c, _ = self.sock.accept()
            except OSError:
                return
            with self.lock:
                self.connections += 1
            threading.Thread(target=self.serve, args=(c,), daemon=True).start()

    def read_head(self, c):
        data = b""
        while b"\r\n\r\n" not in data:
            d = c.recv(65536)
            if not d:
                return None, b""
            data += d
        head, _, rest = data.partition(b"\r\n\r\n")
        return head, rest

    def read_body(self, c, head, rest):
        m = re.search(rb"(?i)\r\ncontent-length: *(\d+)", head)
        if m:
            n = int(m.group(1))
            body = rest
            while len(body) < n:
                d = c.recv(65536)
                if not d:
                    break
                body += d
            return body[:n]
        if re.search(rb"(?i)\r\ntransfer-encoding: *chunked", head):
            raw = rest
            while not raw.endswith(b"0\r\n\r\n"):
                d = c.recv(65536)
                if not d:
                    break
                raw += d
            out, i = b"", 0
            while True:
                j = raw.index(b"\r\n", i)
                size = int(raw[i:j], 16)
                if size == 0:
                    return out
                out += raw[j + 2:j + 2 + size]
                i = j + 2 + size + 2
        return b""

    def serve(self, c):
        try:
            head, rest = self.read_head(c)
            if head is None:
                return
            with self.lock:
                self.heads.append(head)
            path = head.split(b" ")[1].decode()
            if path.startswith("/echo"):
                body = self.read_body(c, head, rest)
                c.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n" % len(body) + body)
            elif path.startswith("/big"):
                n = int(path.split("n=")[1])
                c.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n" % n)
                block = bytes(range(256)) * 256
                sent = 0
                while sent < n:
                    chunk = block[: min(len(block), n - sent)]
                    c.sendall(chunk)
                    sent += len(chunk)
            elif path.startswith("/slow"):
                c.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 30\r\nConnection: close\r\n\r\n")
                for _ in range(30):
                    c.sendall(b"x")
                    time.sleep(0.01)
            elif path.startswith("/stall"):
                c.settimeout(8)
                try:
                    while c.recv(4096):
                        pass
                    with self.lock:
                        self.eof_seen.append(path)
                except OSError:
                    pass
            elif path.startswith("/cut"):
                c.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 1000\r\nConnection: close\r\n\r\n" + b"y" * 10)
            elif path.startswith("/silent"):
                pass
            elif path.startswith("/sink"):
                c.settimeout(8)
                try:
                    while c.recv(65536):
                        pass
                    with self.lock:
                        self.eof_seen.append(path)
                except OSError:
                    pass
            elif path.startswith("/trickle"):
                # Sends the response head, then data for ever until the client side goes away.
                c.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 100000000\r\nConnection: close\r\n\r\n")
                c.settimeout(8)
                try:
                    while True:
                        c.sendall(b"z" * 8192)
                except OSError:
                    with self.lock:
                        self.eof_seen.append(path)
            else:
                c.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
        except OSError:
            pass
        finally:
            try:
                c.close()
            except OSError:
                pass


class KAUpstream:
    """An upstream that keeps connections open and answers many requests on each; behaviour is chosen by the request path.
    Records every connection (how many requests it served, whether it is still open, whether it was closed by the peer) and every
    request head, so a test can say exactly how the gateway used its connections."""

    def __init__(self, port):
        self.port = port
        self.lock = threading.Lock()
        self.stop = False
        self.next_id = 0
        self.conns = {}          # id -> {"requests": n, "open": bool, "peer_closed": bool}
        self.heads = []          # (conn id, head)
        self.sock = socket.socket()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", port))
        self.sock.listen(200)
        threading.Thread(target=self.accept, daemon=True).start()

    def accept(self):
        while not self.stop:
            try:
                c, _ = self.sock.accept()
            except OSError:
                return
            with self.lock:
                cid = self.next_id
                self.next_id += 1
                self.conns[cid] = {"requests": 0, "open": True, "peer_closed": False}
            threading.Thread(target=self.serve, args=(cid, c), daemon=True).start()

    def open_count(self):
        with self.lock:
            return sum(1 for v in self.conns.values() if v["open"])

    def connections(self):
        with self.lock:
            return len(self.conns)

    def requests_for(self, prefix):
        with self.lock:
            return [(cid, h) for cid, h in self.heads if h.split(b" ")[1].decode().startswith(prefix)]

    def serve(self, cid, c):
        buf = b""
        try:
            while True:
                while b"\r\n\r\n" not in buf:
                    d = c.recv(65536)
                    if not d:
                        with self.lock:
                            self.conns[cid]["peer_closed"] = True
                        return
                    buf += d
                head, _, buf = buf.partition(b"\r\n\r\n")
                method, path = head.split(b" ")[0], head.split(b" ")[1].decode()
                with self.lock:
                    self.heads.append((cid, head))
                    self.conns[cid]["requests"] += 1
                    nth = self.conns[cid]["requests"]
                if path.startswith("/ka/413"):
                    c.sendall(b"HTTP/1.1 413 Content Too Large\r\nContent-Length: 0\r\n\r\n")
                    time.sleep(1.5)
                    return
                body, buf = self.take_body(c, head, buf)
                ok = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"
                if path.startswith("/ka/echo"):
                    c.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n" % len(body) + body)
                elif path.startswith("/ka/chunked"):
                    c.sendall(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n")
                elif path.startswith("/ka/204"):
                    c.sendall(b"HTTP/1.1 204 No Content\r\n\r\n")
                elif path.startswith("/ka/head"):
                    if method == b"HEAD":
                        c.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n")
                    else:
                        c.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n" + b"h" * 100)
                elif path.startswith("/ka/interim"):
                    c.sendall(b"HTTP/1.1 100 Continue\r\n\r\n" + ok)
                elif path.startswith("/ka/http10"):
                    c.sendall(b"HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\nok")
                    return
                elif path.startswith("/ka/close"):
                    c.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
                    return
                elif path.startswith("/ka/eof"):
                    c.sendall(b"HTTP/1.1 200 OK\r\n\r\ntail")
                    return
                elif path.startswith("/ka/leftover"):
                    c.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nokEXTRA")
                elif path.startswith("/ka/slow"):
                    time.sleep(0.4)
                    c.sendall(ok)
                elif path.startswith("/ka/lying"):
                    # Says nothing about closing, then closes: a pooled connection that has silently died.
                    c.sendall(ok)
                    time.sleep(0.05)
                    return
                elif path.startswith("/ka/dieslow"):
                    # Like /ka/die, but the dead connection takes its time, so that other requests are routed meanwhile.
                    if nth > 1:
                        time.sleep(0.4)
                        return
                    c.sendall(ok)
                elif path.startswith("/ka/die"):
                    if nth > 1:
                        return
                    c.sendall(ok)
                elif path.startswith("/ka/badlen"):
                    c.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nTransfer-Encoding: chunked\r\n\r\nok")
                elif path.startswith("/ka/hop"):
                    c.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nKeep-Alive: timeout=5\r\nConnection: keep-alive, X-Secret\r\nX-Secret: 1\r\nX-Kept: 2\r\n\r\nok")
                else:
                    c.sendall(ok)
        except OSError:
            pass
        finally:
            with self.lock:
                self.conns[cid]["open"] = False
            try:
                c.close()
            except OSError:
                pass

    def take_body(self, c, head, buf):
        m = re.search(rb"(?i)\r\ncontent-length: *(\d+)", head)
        if m:
            n = int(m.group(1))
            while len(buf) < n:
                d = c.recv(65536)
                if not d:
                    break
                buf += d
            return buf[:n], buf[n:]
        if re.search(rb"(?i)\r\ntransfer-encoding: *chunked", head):
            out = b""
            while True:
                while b"\r\n" not in buf:
                    buf += c.recv(65536)
                line, _, buf = buf.partition(b"\r\n")
                size = int(line, 16)
                while len(buf) < size + 2:
                    buf += c.recv(65536)
                out += buf[:size]
                buf = buf[size + 2:]
                if size == 0:
                    return out, buf
        return b"", buf


class FlapUpstream:
    """An upstream the test can take down and bring back: `down()` closes the listening socket (and, by default, every open
    connection), `up()` listens again on the same port. Keep-alive; behaviour by path: /flap/ok, /flap/slow (0.6 s),
    /flap/stall (never answers), /flap/garbage (an answer that is not HTTP)."""

    def __init__(self, port):
        self.port = port
        self.lock = threading.Lock()
        self.accepted = 0
        self.live = {}
        self.sock = None
        self.next_id = 0

    def up(self):
        if self.sock:
            return
        s = socket.socket()
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("127.0.0.1", self.port))
        s.listen(100)
        self.sock = s
        threading.Thread(target=self.accept, args=(s,), daemon=True).start()

    def down(self, kill=True):
        if self.sock:
            # A thread blocked in accept() keeps a closed listening socket alive: shut it down first so the port really refuses.
            try:
                self.sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            self.sock.close()
            self.sock = None
        if kill:
            with self.lock:
                conns = list(self.live.values())
            for c in conns:
                try:
                    c.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass

    def stop(self):
        self.down()

    def open_count(self):
        with self.lock:
            return len(self.live)

    def accept(self, s):
        while True:
            try:
                c, _ = s.accept()
            except OSError:
                return
            with self.lock:
                self.accepted += 1
                cid = self.next_id
                self.next_id += 1
                self.live[cid] = c
            threading.Thread(target=self.serve, args=(cid, c), daemon=True).start()

    def serve(self, cid, c):
        buf = b""
        try:
            while True:
                while b"\r\n\r\n" not in buf:
                    d = c.recv(65536)
                    if not d:
                        return
                    buf += d
                head, _, buf = buf.partition(b"\r\n\r\n")
                path = head.split(b" ")[1].decode()
                if path.startswith("/flap/stall"):
                    c.settimeout(8)
                    while c.recv(4096):
                        pass
                    return
                if path.startswith("/flap/garbage"):
                    c.sendall(b"NOT HTTP AT ALL\r\n\r\n")
                    c.settimeout(8)
                    while c.recv(4096):
                        pass
                    return
                if path.startswith("/flap/slow"):
                    time.sleep(0.6)
                c.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
        except OSError:
            pass
        finally:
            with self.lock:
                self.live.pop(cid, None)
            try:
                c.close()
            except OSError:
                pass


class Gateway:
    def __init__(self, tmp, port, up_port, dead_port, ka_port, flap_port, pool=4, circuit=3):
        deploy = pathlib.Path(tmp) / "deploy.toml"
        deploy.write_text("""listen = %d
header_timeout_ms = 1000
connect_timeout_ms = 1000
upstream_timeout_ms = 1500
total_timeout_ms = 4000
idle_timeout_ms = 500
pool_idle_max = %d
circuit_threshold = %d
circuit_open_ms = 1000

[[upstream]]
name = "up"
addr = "127.0.0.1:%d"

[[upstream]]
name = "dead"
addr = "127.0.0.1:%d"

[[upstream]]
name = "ka"
addr = "127.0.0.1:%d"

[[upstream]]
name = "flap"
addr = "127.0.0.1:%d"

[[route]]
path_prefix = "/dead"
upstream = "dead"

[[route]]
path_prefix = "/ka"
upstream = "ka"
max_body = 1048576

[[route]]
path_prefix = "/flap"
upstream = "flap"

[[route]]
path_prefix = "/trusted"
upstream = "up"
trust_forwarded = true

[[route]]
path_prefix = "/"
upstream = "up"
max_body = 1048576
""" % (port, pool, circuit, up_port, dead_port, ka_port, flap_port))
        subprocess.run([sys.executable, str(ROOT / "scripts" / "generate.py"), str(deploy), "--out", tmp], check=True)
        files = [os.path.join(tmp, "deploy.ls"), os.path.join(tmp, "routes.ls")] + [str(ROOT / "src" / (n + ".ls")) for n in SOURCES]
        built = subprocess.run([LEX, "build", "--std", *files, "-o", os.path.join(tmp, "gateway")], capture_output=True, text=True)
        if built.returncode != 0:
            raise SystemExit("build failed: " + built.stderr[:400])
        self.port = port
        self.proc = subprocess.Popen([os.path.join(tmp, "gateway")], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        for _ in range(100):
            try:
                socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
                return
            except OSError:
                time.sleep(0.05)
        raise SystemExit("gateway did not start")

    def alive(self):
        return self.proc.poll() is None

    def fds(self):
        return len(os.listdir("/proc/%d/fd" % self.proc.pid))

    def rss_kb(self):
        for line in open("/proc/%d/status" % self.proc.pid):
            if line.startswith("VmRSS"):
                return int(line.split()[1])

    def stop(self):
        self.proc.kill()
        self.proc.wait()


def request(gw, raw, read=True, timeout=6, trickle=0.0, pause=0.0):
    s = socket.create_connection(("127.0.0.1", gw.port), timeout=timeout)
    if trickle:
        for i in range(0, len(raw), 1):
            s.sendall(raw[i:i + 1])
            time.sleep(trickle)
    else:
        s.sendall(raw)
    if pause:
        time.sleep(pause)
    out = b""
    if read:
        try:
            while True:
                d = s.recv(65536)
                if not d:
                    break
                out += d
                if complete(out):
                    break
        except OSError as e:
            out += b"[%s]" % str(e).encode()
    s.close()
    return out


def heads_of(head):
    """A recorded request head as {lowercase name: [values]}."""
    out = {}
    for line in head.decode("latin-1").split("\r\n")[1:]:
        name, _, value = line.partition(":")
        out.setdefault(name.lower(), []).append(value.strip())
    return out


def complete(response):
    """What a real client does: stop at the end of a Content-Length body instead of waiting for the connection to close."""
    head, sep, body = response.partition(b"\r\n\r\n")
    m = re.search(rb"(?i)\r\ncontent-length: *(\d+)", head)
    return bool(sep and m and len(body) >= int(m.group(1)))


def split(response):
    head, _, body = response.partition(b"\r\n\r\n")
    status = int(head.split(b" ")[1]) if head.startswith(b"HTTP/") else None
    return status, head, body


def refusal(response):
    status, head, body = split(response)
    try:
        return status, json.loads(body)["rule"]
    except (ValueError, KeyError):
        return status, None


GET = b"GET %s HTTP/1.1\r\nHost: a.example\r\n\r\n"


class T:
    """The tests; each takes (gateway, upstream) and raises AssertionError."""

    def basic(gw, up):
        status, head, body = split(request(gw, GET % b"/x"))
        assert status == 200 and body == b"ok", (status, body)

    def headers_forwarded(gw, up):
        n = len(up.heads)
        request(gw, b"GET /x HTTP/1.1\r\nHost: a.example\r\nConnection: keep-alive, X-Drop\r\nX-Drop: 1\r\nKeep-Alive: 5\r\nAccept: */*\r\n\r\n")
        head = up.heads[n].decode()
        lines = head.split("\r\n")
        assert lines[:3] == ["GET /x HTTP/1.1", "Host: a.example", "Accept: */*"], head
        assert lines[3:5] == ["Via: 1.1 lexsys-gateway", "X-Forwarded-Host: a.example"] and lines[5] == "X-Forwarded-Proto: http", head
        assert re.fullmatch(r"X-Request-Id: [0-9a-f]+-[0-9a-f]+-[0-9a-f]{8,}", lines[6]) and len(lines) == 7, head

    def forwarding_claims_are_not_believed_on_a_default_route(gw, up):
        n = len(up.heads)
        request(gw, b"GET /x HTTP/1.1\r\nHost: h.example\r\nForwarded: for=6.6.6.6\r\nX-Forwarded-For: 6.6.6.6\r\nx-forwarded-host: evil\r\n"
                    b"X-Forwarded-Proto: https\r\nX-Forwarded-Port: 443\r\nX-Real-IP: 6.6.6.6\r\nX-Request-Id: client-chosen\r\n\r\n")
        h = heads_of(up.heads[n])
        assert h.get("x-forwarded-for") is None and h.get("forwarded") is None and h.get("x-real-ip") is None and h.get("x-forwarded-port") is None, h
        assert h["x-forwarded-host"] == ["h.example"] and h["x-forwarded-proto"] == ["http"], h
        assert len(h["x-request-id"]) == 1 and h["x-request-id"][0] != "client-chosen", h

    def forwarding_claims_pass_through_a_trusted_route(gw, up):
        n = len(up.heads)
        request(gw, b"GET /trusted/x HTTP/1.1\r\nHost: h.example\r\nForwarded: for=1.2.3.4\r\nX-Forwarded-For: 1.2.3.4\r\nX-Forwarded-Host: front.example\r\n"
                    b"X-Forwarded-Proto: https\r\nX-Real-IP: 1.2.3.4\r\nX-Request-Id: edge-42\r\n\r\n")
        h = heads_of(up.heads[n])
        assert h["forwarded"] == ["for=1.2.3.4"] and h["x-forwarded-for"] == ["1.2.3.4"] and h["x-real-ip"] == ["1.2.3.4"], h
        assert h["x-forwarded-host"] == ["front.example"] and h["x-forwarded-proto"] == ["https"], h
        assert h["x-request-id"] == ["edge-42"], h
        assert h["via"] == ["1.1 lexsys-gateway"], h

    def a_trusted_route_replaces_a_bad_request_id(gw, up):
        for bad in (b"a,b", b"a b", b"x" * 65, b"", b"a/b"):
            n = len(up.heads)
            request(gw, b"GET /trusted/x HTTP/1.1\r\nHost: h\r\nX-Request-Id: " + bad + b"\r\n\r\n")
            ids = heads_of(up.heads[n])["x-request-id"]
            assert len(ids) == 1 and re.fullmatch(r"[0-9a-f]+-[0-9a-f]+-[0-9a-f]{8,}", ids[0]), (bad, ids)
        n = len(up.heads)
        request(gw, b"GET /trusted/x HTTP/1.1\r\nHost: h\r\nX-Request-Id: one\r\nX-Request-Id: two\r\n\r\n")
        ids = heads_of(up.heads[n])["x-request-id"]
        assert len(ids) == 1 and ids[0] not in ("one", "two"), ids

    def request_ids_are_unique_and_count_up(gw, up):
        n = len(up.heads)
        for _ in range(5):
            request(gw, GET % b"/x")
        ids = [heads_of(h)["x-request-id"][0] for h in up.heads[n:]]
        assert len(set(ids)) == 5, ids
        stamps = {i.rsplit("-", 1)[0] for i in ids}
        seqs = [int(i.rsplit("-", 1)[1], 16) for i in ids]
        assert len(stamps) == 1 and seqs == sorted(seqs) and seqs[-1] - seqs[0] == 4, (stamps, seqs)
        port = ids[0].split("-")[1]
        assert int(port, 16) == gw.port, (port, gw.port)

    def the_response_gets_a_via(gw, up):
        raw = request(gw, GET % b"/x")
        head = raw.split(b"\r\n\r\n")[0].decode()
        assert head.count("Via: 1.1 lexsys-gateway") == 1, head

    def crafted_header_values_add_no_header_the_gateway_did_not_write(gw, up):
        # Whatever the client sends, every head the upstream sees has no stray control byte and carries only the client's own header names
        # plus the four the gateway writes. Refused requests never reach it at all.
        # (A CRLF inside a value is the client writing another header line, not an injection: the head's own syntax allows it.)
        crafted = [b"a\nX-Injected: 1", b"a\rX-Injected: 1", b"a\x00b", b"a\x7fb", b"a, b", b"a\"b", b"%0d%0aX-Injected: 1", b"\xc3\xa9"]
        sent = 0
        for value in crafted:
            for name in (b"X-Request-Id", b"X-Forwarded-For", b"Via", b"X-Custom", b"Host"):
                for path in (b"/x", b"/trusted/x"):
                    n = len(up.heads)
                    raw = b"GET " + path + b" HTTP/1.1\r\nHost: a\r\n" + (b"" if name == b"Host" else name + b": " + value + b"\r\n") + b"\r\n"
                    if name == b"Host":
                        raw = b"GET " + path + b" HTTP/1.1\r\nHost: " + value + b"\r\n\r\n"
                    request(gw, raw)
                    for head in up.heads[n:]:
                        sent += 1
                        # Values pass as received, so obs-text (0x80 and up) may appear; no control byte may, and CR and LF only as CRLF.
                        assert all(c >= 32 and c != 127 or c in (13, 10) for c in head) and b"\r" not in head.replace(b"\r\n", b"") and b"\n" not in head.replace(b"\r\n", b""), head
                        names = {l.split(b":")[0].lower() for l in head.split(b"\r\n")[1:]}
                        assert names <= {b"host", b"via", b"x-forwarded-host", b"x-forwarded-proto", b"x-request-id", b"x-forwarded-for", b"x-custom", b"connection"}, (raw, head)
                        assert b"x-injected" not in head.lower().replace(b"%0d%0ax-injected", b""), (raw, head)
        assert sent > 0

    def one_upstream_connection_per_request(gw, up):
        before = up.connections
        for _ in range(7):
            request(gw, GET % b"/x")
        assert up.connections - before == 7, up.connections - before

    def content_length_body_echo(gw, up):
        body = os.urandom(600000)
        status, _, got = split(request(gw, b"POST /echo HTTP/1.1\r\nHost: a\r\nContent-Length: %d\r\n\r\n" % len(body) + body, timeout=15))
        assert status == 200 and hashlib.sha256(got).digest() == hashlib.sha256(body).digest(), (status, len(got))

    def small_trailing_write_is_not_delayed(gw, up):
        # Found by the benchmark (docs/bench.md): a 16 KiB body arrives as a 16,384-byte read and a 96-byte read, and without
        # TCP_NODELAY the second, small write waited for the peer's delayed acknowledgement, about 40 ms, on every other request.
        body = b"x" * 16384
        slow = 0
        for _ in range(40):
            t0 = time.time()
            status, _, got = split(request(gw, b"POST /ka/echo HTTP/1.1\r\nHost: a\r\nContent-Length: %d\r\n\r\n" % len(body) + body))
            assert status == 200 and got == body, (status, len(got))
            slow += time.time() - t0 > 0.03
        assert slow <= 3, "%d of 40 requests took more than 30 ms" % slow

    def chunked_body_echo(gw, up):
        parts = [os.urandom(random.randint(1, 20000)) for _ in range(12)]
        raw = b"".join(b"%x\r\n" % len(p) + p + b"\r\n" for p in parts) + b"0\r\n\r\n"
        status, _, got = split(request(gw, b"POST /echo HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n" + raw, timeout=15))
        assert status == 200 and got == b"".join(parts), (status, len(got))

    def request_split_at_every_few_bytes(gw, up):
        raw = b"POST /echo HTTP/1.1\r\nHost: a\r\nContent-Length: 11\r\n\r\nhello world"
        status, _, got = split(request(gw, raw, trickle=0.002))
        assert status == 200 and got == b"hello world", (status, got)

    def large_response_slow_reader(gw, up):
        # 6 MiB through a gateway whose queues hold 32 KiB, to a client that starts reading late and then reads in dribbles:
        # the relay must apply backpressure to the upstream and lose nothing.
        n = 6 * 1024 * 1024
        s = socket.create_connection(("127.0.0.1", gw.port), timeout=30)
        s.sendall(GET % (b"/big?n=%d" % n))
        time.sleep(0.5)
        got = b""
        while True:
            d = s.recv(4096 if len(got) < 300000 else 65536)
            if not d:
                break
            got += d
            if len(got) < 300000:
                time.sleep(0.002)
        s.close()
        status, _, body = split(got)
        block = bytes(range(256)) * 256
        want = (block * (n // len(block) + 1))[:n]
        assert status == 200 and len(body) == n and hashlib.sha256(body).digest() == hashlib.sha256(want).digest(), (status, len(body))

    def concurrent_large_responses(gw, up):
        # Several sessions at once, each downloading 12 MiB through a tiny receive window and starting to read late, so that the
        # kernel's buffers and then the gateway's own queues fill: a queue that overran its slot would corrupt a neighbour's bytes.
        n = 12 * 1024 * 1024
        block = bytes(range(256)) * 256
        want = hashlib.sha256((block * (n // len(block) + 1))[:n]).digest()
        results = {}

        def download(i):
            s = socket.socket()
            s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
            s.settimeout(60)
            s.connect(("127.0.0.1", gw.port))
            s.sendall(GET % (b"/big?n=%d" % n))
            time.sleep(0.5 + 0.2 * i)
            got = bytearray()
            while True:
                d = s.recv(65536)
                if not d:
                    break
                got += d
            s.close()
            results[i] = bytes(got)

        threads = [threading.Thread(target=download, args=(i,)) for i in range(6)]
        for th in threads:
            th.start()
        for th in threads:
            th.join()
        for i, got in sorted(results.items()):
            status, _, body = split(got)
            assert status == 200 and len(body) == n and hashlib.sha256(body).digest() == want, (i, status, len(body))

    def refusals(gw, up):
        cases = [
            (b"GET /x HTTP/1.1\r\nHost: a\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n", 400, "framing.two-lengths"),
            (b"GET / HTTP/1.1\r\n\r\n", 400, "framing.host"),
            (b"GET http://evil/ HTTP/1.1\r\nHost: a\r\n\r\n", 400, "framing.target-form"),
            (b"CONNECT a:443 HTTP/1.1\r\nHost: a\r\n\r\n", 501, "framing.method-unsupported"),
            (b"GET / HTTP/2.0\r\nHost: a\r\n\r\n", 505, "framing.version"),
            (b"GET /a/../b HTTP/1.1\r\nHost: a\r\n\r\n", 400, "route.path"),
            (b"GET /x HTTP/1.1\r\nHost: bad host\r\n\r\n", 400, "route.host"),
            (b"FETCH /x HTTP/1.1\r\nHost: a\r\n\r\n", 405, None),
            (b"POST /x HTTP/1.1\r\nHost: a\r\nContent-Length: 2000000\r\n\r\n", 413, "limit.body"),
            (b"GET /x HTTP/1.1\r\nHost: a\r\nConnection: Content-Length\r\n\r\n", 400, "forward.connection-token"),
            (b"GET /x HTTP/1.1\nHost: a\n\n", 400, "framing.line-ending"),
        ]
        for raw, status, rule in cases:
            got_status, got_rule = refusal(request(gw, raw))
            assert got_status == status, (raw, got_status, got_rule)
            if rule:
                assert got_rule == rule, (raw, got_rule)

    def refusals_never_reach_the_upstream(gw, up):
        before = up.connections
        request(gw, b"GET /a/../b HTTP/1.1\r\nHost: a\r\n\r\n")
        request(gw, b"POST /x HTTP/1.1\r\nHost: a\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n")
        time.sleep(0.2)
        assert up.connections == before

    def chunked_body_over_limit(gw, up):
        big = b"%x\r\n" % 600000 + b"a" * 600000 + b"\r\n"
        raw = b"POST /sink HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n" + big + big
        response = request(gw, raw, timeout=10, pause=0.4)
        status, rule = refusal(response)
        assert status == 413 and rule == "limit.body", (status, rule, response[:100])

    def a_refusal_survives_unread_request_bytes(gw, up):
        # The client keeps sending after it has been refused and reads the answer late: closing at once would send a reset
        # that destroys the answer (RFC 9112 9.6), so the gateway lingers.
        for _ in range(5):
            response = request(gw, b"POST /x HTTP/1.1\r\nHost: a\r\nContent-Length: 2000000\r\n\r\n" + b"a" * 1500000, timeout=10, pause=0.4)
            assert refusal(response) == (413, "limit.body"), response[:120]

    def slowloris_does_not_stall_others(gw, up):
        stalled = [socket.create_connection(("127.0.0.1", gw.port)) for _ in range(20)]
        for s in stalled:
            s.sendall(b"GET /x HTTP/1.1\r\nHost: a\r\nX-Slow: ")
        t0 = time.time()
        for _ in range(5):
            status, _, body = split(request(gw, GET % b"/x"))
            assert status == 200, status
        assert time.time() - t0 < 1.0, "other clients were delayed by stalled ones"
        time.sleep(1.4)
        for s in stalled:
            s.settimeout(2)
            data = s.recv(4096)
            assert b"408" in data and b"timeout.header" in data, data
            s.close()

    def stalled_upstream_times_out(gw, up):
        t0 = time.time()
        status, rule = refusal(request(gw, GET % b"/stall", timeout=8))
        assert (status, rule) == (504, "timeout.upstream"), (status, rule)
        assert 1.2 < time.time() - t0 < 3.5, time.time() - t0
        time.sleep(0.3)
        assert "/stall" in up.eof_seen, "the upstream connection was not closed"

    def connect_refused(gw, up):
        assert refusal(request(gw, GET % b"/dead/x")) == (502, "proxy.connect")

    def upstream_closes_without_answering(gw, up):
        assert refusal(request(gw, GET % b"/silent")) == (502, "proxy.upstream-closed")

    def upstream_cuts_the_response(gw, up):
        response = request(gw, GET % b"/cut")
        status, head, body = split(response)
        assert status == 200 and body == b"y" * 10, (status, body)

    def client_leaves_mid_body(gw, up):
        fds = gw.fds()
        s = socket.create_connection(("127.0.0.1", gw.port))
        s.sendall(b"POST /sink HTTP/1.1\r\nHost: a\r\nContent-Length: 100000\r\n\r\n" + b"a" * 5000)
        time.sleep(0.4)
        s.close()
        time.sleep(0.6)
        assert "/sink" in up.eof_seen, "the upstream connection outlived the client"
        assert gw.fds() == fds, ("file descriptors", fds, gw.fds())

    def client_leaves_mid_response(gw, up):
        fds = gw.fds()
        s = socket.create_connection(("127.0.0.1", gw.port))
        s.sendall(GET % b"/trickle")
        s.recv(1000)
        s.close()
        time.sleep(1.5)
        assert "/trickle" in up.eof_seen, "the upstream connection outlived the client"
        assert gw.fds() == fds, ("file descriptors", fds, gw.fds())

    def slow_upstream_response_is_relayed(gw, up):
        status, _, body = split(request(gw, GET % b"/slow"))
        assert status == 200 and body == b"x" * 30, (status, body)

    def total_deadline(gw, up):
        t0 = time.time()
        response = request(gw, b"POST /sink HTTP/1.1\r\nHost: a\r\nContent-Length: 100\r\n\r\n", read=True, timeout=8)
        assert refusal(response)[0] == 504, response[:100]
        assert time.time() - t0 < 5, time.time() - t0

    def too_many_connections(gw, up):
        socks = []
        for _ in range(300):
            try:
                socks.append(socket.create_connection(("127.0.0.1", gw.port), timeout=2))
            except OSError:
                break
        time.sleep(0.3)
        assert gw.alive()
        for s in socks:
            s.close()
        time.sleep(0.5)
        status, _, body = split(request(gw, GET % b"/x"))
        assert status == 200, status

    def hostile_bytes_do_not_stop_it(gw, up):
        rng = random.Random(9)
        seeds = [GET % b"/x", b"POST /echo HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n"]
        for i in range(300):
            data = bytearray(rng.choice(seeds))
            for _ in range(rng.randint(0, 4)):
                if data:
                    data[rng.randrange(len(data))] = rng.randrange(256)
            if rng.random() < 0.3:
                data = bytearray(os.urandom(rng.randint(1, 3000)))
            s = socket.create_connection(("127.0.0.1", gw.port), timeout=3)
            try:
                s.sendall(bytes(data))
                if rng.random() < 0.5:
                    s.settimeout(0.05)
                    try:
                        s.recv(4096)
                    except OSError:
                        pass
            except OSError:
                pass
            s.close()
        assert gw.alive()
        status, _, body = split(request(gw, GET % b"/x"))
        assert status == 200, status

    def blocked_sessions_do_not_spin(gw, up):
        # Level-triggered readiness: a session that is waiting must be watched for nothing, or the loop spins. CPU time
        # while sessions are stalled in each way must be (nearly) nothing.
        def cpu():
            f = open("/proc/%d/stat" % gw.proc.pid).read().split()
            return (int(f[13]) + int(f[14])) / os.sysconf("SC_CLK_TCK")

        held = []
        for _ in range(10):
            s = socket.create_connection(("127.0.0.1", gw.port))
            s.sendall(GET % b"/stall")
            held.append(s)
        s = socket.create_connection(("127.0.0.1", gw.port))
        s.sendall(b"POST /stall HTTP/1.1\r\nHost: a\r\nContent-Length: 900000\r\n\r\n" + b"a" * 500000)
        held.append(s)
        s = socket.socket()
        s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
        s.connect(("127.0.0.1", gw.port))
        s.sendall(GET % b"/big?n=20000000")
        held.append(s)
        time.sleep(0.4)
        before = cpu()
        time.sleep(0.8)
        used = cpu() - before
        for s in held:
            s.close()
        assert used < 0.05, ("cpu seconds used by the gateway while sessions were blocked", used)

    def churn_leaks_nothing(gw, up):
        for _ in range(300):
            request(gw, GET % b"/x")
            request(gw, b"POST /echo HTTP/1.1\r\nHost: a\r\nContent-Length: 3\r\n\r\nabc")
            request(gw, b"GET /a/../x HTTP/1.1\r\nHost: a\r\n\r\n")
        time.sleep(0.3)
        fds, rss = gw.fds(), gw.rss_kb()
        for _ in range(1500):
            request(gw, GET % b"/x")
            request(gw, b"POST /echo HTTP/1.1\r\nHost: a\r\nContent-Length: 3\r\n\r\nabc")
            request(gw, b"GET /a/../x HTTP/1.1\r\nHost: a\r\n\r\n")
        time.sleep(0.3)
        assert gw.fds() == fds, ("file descriptors", fds, gw.fds())
        assert gw.rss_kb() - rss < 512, ("resident memory grew by kB", gw.rss_kb() - rss)

    # ---- keep-alive upstream connections (task #6, docs/pool.md) ----

    def keepalive_reuses_the_upstream_connection(gw, up):
        quiesce(gw)
        ka = gw.ka
        before = ka.connections()
        for _ in range(10):
            status, _, body = split(request(gw, GET % b"/ka"))
            assert (status, body) == (200, b"ok"), (status, body)
        assert ka.connections() - before == 1, ("upstream connections for ten requests", ka.connections() - before)
        assert [n for n in ka.conns.values()][-1]["requests"] == 10

    def keepalive_carries_bodies_both_ways(gw, up):
        quiesce(gw)
        ka = gw.ka
        before = ka.connections()
        body = os.urandom(50000)
        status, _, got = split(request(gw, b"POST /ka/echo HTTP/1.1\r\nHost: a\r\nContent-Length: %d\r\n\r\n" % len(body) + body, timeout=15))
        assert status == 200 and got == body, (status, len(got))
        parts = [os.urandom(random.randint(1, 3000)) for _ in range(8)]
        raw = b"".join(b"%x\r\n" % len(p) + p + b"\r\n" for p in parts) + b"0\r\n\r\n"
        status, _, got = split(request(gw, b"POST /ka/echo HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n" + raw, timeout=15))
        assert status == 200 and got == b"".join(parts), (status, len(got))
        assert split(request(gw, GET % b"/ka"))[0] == 200
        assert ka.connections() - before == 1, ("the same connection should have served all three", ka.connections() - before)

    def response_framings_leave_the_connection_clean(gw, up):
        # After each kind of response a plain request must work on the same pooled connection.
        quiesce(gw)
        ka = gw.ka
        before = ka.connections()
        status, head, body = split(request(gw, GET % b"/ka/chunked"))
        assert status == 200 and b"Transfer-Encoding: chunked" in head and body == b"5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n", (status, body)
        assert split(request(gw, GET % b"/ka"))[0] == 200
        status, head, body = split(request(gw, GET % b"/ka/204"))
        assert status == 204 and body == b"", (status, body)
        assert split(request(gw, GET % b"/ka"))[0] == 200
        status, head, body = split(request(gw, b"HEAD /ka/head HTTP/1.1\r\nHost: a\r\n\r\n", timeout=3))
        assert status == 200 and b"Content-Length: 100" in head and body == b"", (status, body)
        assert split(request(gw, GET % b"/ka"))[0] == 200
        response = request(gw, GET % b"/ka/interim")
        assert response.startswith(b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\n") and response.endswith(b"ok"), response
        assert split(request(gw, GET % b"/ka"))[0] == 200
        assert ka.connections() - before == 1, ("every response above should have left its connection reusable", ka.connections() - before)

    def connections_that_must_not_be_reused_are_not(gw, up):
        quiesce(gw)
        ka = gw.ka
        for path, want in [(b"/ka/http10", b"ok"), (b"/ka/close", b"ok"), (b"/ka/eof", b"tail")]:
            before = ka.connections()
            for _ in range(2):
                status, _, body = split(request(gw, GET % path))
                assert (status, body) == (200, want), (path, status, body)
            assert ka.connections() - before == 2, (path, "was reused", ka.connections() - before)

    def leftover_bytes_after_a_response_prevent_reuse(gw, up):
        quiesce(gw)
        ka = gw.ka
        before = ka.connections()
        status, _, body = split(request(gw, GET % b"/ka/leftover"))
        assert (status, body) == (200, b"ok"), (status, body)
        time.sleep(0.3)
        status, _, body = split(request(gw, GET % b"/ka/leftover"))
        assert (status, body) == (200, b"ok"), (status, body)
        assert ka.connections() - before == 2, "a connection with unread bytes on it was reused"
        assert all(v["peer_closed"] for k, v in list(ka.conns.items())[before:]), "the gateway should have closed them"

    def hop_by_hop_headers_do_not_reach_the_client(gw, up):
        status, head, body = split(request(gw, GET % b"/ka/hop"))
        text = head.decode()
        assert status == 200 and "X-Kept: 2" in text and "Connection: close" in text, text
        assert "Keep-Alive" not in text and "X-Secret" not in text and "keep-alive" not in text, text

    def upstream_framing_errors_are_502(gw, up):
        assert refusal(request(gw, GET % b"/ka/badlen")) == (502, "response.two-lengths")

    def a_dead_pooled_connection_is_retried_for_a_get(gw, up):
        quiesce(gw)
        ka = gw.ka
        n0 = len(ka.requests_for("/ka/die"))
        assert split(request(gw, GET % b"/ka/die"))[0] == 200
        status, _, body = split(request(gw, GET % b"/ka/die"))
        assert (status, body) == (200, b"ok"), (status, body)
        seen = ka.requests_for("/ka/die")[n0:]
        assert [c for c, _ in seen][0] == [c for c, _ in seen][1] and [c for c, _ in seen][2] != [c for c, _ in seen][0], ("connections", [c for c, _ in seen])
        ids = [heads_of(h)["x-request-id"][0] for _, h in seen]
        assert ids[1] == ids[2] and ids[0] != ids[1], ("the request sent again keeps its id, a new request has a new one", ids)

    def a_retried_request_keeps_its_id_while_others_are_routed(gw, up):
        # The id is fixed when the request is routed: a request that is sent again 0.4 s later, after two others were given ids, still
        # carries its own (a counter read at the retry would give it a later one).
        quiesce(gw)
        ka = gw.ka
        n0 = len(ka.requests_for("/ka/dieslow"))
        assert split(request(gw, GET % b"/ka/dieslow"))[0] == 200
        result = {}
        t = threading.Thread(target=lambda: result.update(r=split(request(gw, GET % b"/ka/dieslow", timeout=10))))
        t.start()
        time.sleep(0.15)
        n1 = len(up.heads)
        request(gw, GET % b"/x")
        request(gw, GET % b"/x")
        t.join()
        assert result["r"][0] == 200, result
        seen = ka.requests_for("/ka/dieslow")[n0:]
        ids = [heads_of(h)["x-request-id"][0] for _, h in seen]
        assert len(ids) == 3 and ids[1] == ids[2] and ids[0] != ids[1], ids
        others = [heads_of(h)["x-request-id"][0] for h in up.heads[n1:]]
        assert len(others) == 2 and ids[1] not in others, (ids, others)

    def a_dead_pooled_connection_is_not_retried_for_a_post(gw, up):
        quiesce(gw)
        ka = gw.ka
        n0 = len(ka.requests_for("/ka/die"))
        post = b"POST /ka/die HTTP/1.1\r\nHost: a\r\nContent-Length: 3\r\n\r\nabc"
        assert split(request(gw, post))[0] == 200
        assert refusal(request(gw, post)) == (502, "proxy.upstream-closed")
        time.sleep(0.2)
        assert len(ka.requests_for("/ka/die")) - n0 == 2, "the POST was sent again"

    def a_hung_up_idle_connection_is_dropped_before_reuse(gw, up):
        # The upstream closes a connection the gateway has pooled. The gateway sees the hang-up while the connection is idle, so
        # even a POST (never retried) finds a good connection next time.
        quiesce(gw)
        post = b"POST /ka/lying HTTP/1.1\r\nHost: a\r\nContent-Length: 3\r\n\r\nabc"
        for _ in range(4):
            assert split(request(gw, post))[0] == 200
            time.sleep(0.2)

    def the_pool_is_bounded_and_idle_connections_expire(gw, up):
        quiesce(gw)
        ka = gw.ka
        before = ka.connections()
        threads = [threading.Thread(target=lambda: request(gw, GET % b"/ka/slow", timeout=10)) for _ in range(10)]
        for th in threads:
            th.start()
        for th in threads:
            th.join()
        time.sleep(0.15)
        assert ka.connections() - before == 10, ka.connections() - before
        assert ka.open_count() == 4, ("the pool should keep four idle connections, not", ka.open_count())
        time.sleep(0.8)
        assert ka.open_count() == 0, ("idle connections should have expired", ka.open_count())

    def an_early_response_does_not_make_its_connection_reusable(gw, up):
        # The upstream answers 413 without reading the body, and keeps the connection open. The gateway has half a request on
        # that connection, so it must not hand it to the next client (which would otherwise wait for an answer that never comes).
        quiesce(gw)
        ka = gw.ka
        raw = b"POST /ka/413 HTTP/1.1\r\nHost: a\r\nContent-Length: 900000\r\n\r\n" + b"a" * 700000
        assert split(request(gw, raw, timeout=10))[0] == 413
        t0 = time.time()
        status, _, body = split(request(gw, GET % b"/ka"))
        assert status == 200 and time.time() - t0 < 1.0, (status, time.time() - t0)
        first = ka.requests_for("/ka/413")[-1][0]
        second = [cid for cid, h in ka.requests_for("/ka") if h.split(b" ")[1] == b"/ka"][-1]
        assert first != second, "the connection that had an unfinished request on it was reused"

    def an_early_response_reaches_a_client_that_is_still_sending(gw, up):
        # The upstream answers before the client has finished its upload. Closing then would reset the connection under the
        # client while it is still sending; the gateway lingers, so the upload completes and the answer is read.
        quiesce(gw)
        for _ in range(3):
            s = socket.create_connection(("127.0.0.1", gw.port), timeout=10)
            body = b"a" * 700000
            s.sendall(b"POST /ka/413 HTTP/1.1\r\nHost: a\r\nContent-Length: %d\r\n\r\n" % len(body))
            for i in range(0, len(body), 8192):
                s.sendall(body[i:i + 8192])
                time.sleep(0.001)
            response = b""
            while not complete(response):
                d = s.recv(65536)
                if not d:
                    break
                response += d
            s.close()
            assert split(response)[0] == 413, response[:100]

    def keepalive_churn_leaks_nothing(gw, up):
        quiesce(gw)

        def burst(n):
            for _ in range(n):
                request(gw, GET % b"/ka")
                request(gw, b"POST /ka/echo HTTP/1.1\r\nHost: a\r\nContent-Length: 3\r\n\r\nabc")
                request(gw, b"GET /a/../x HTTP/1.1\r\nHost: a\r\n\r\n")

        burst(200)
        time.sleep(0.7)
        fds, rss = gw.fds(), gw.rss_kb()
        before = gw.ka.connections()
        burst(800)
        time.sleep(0.7)
        assert gw.fds() == fds, ("file descriptors", fds, gw.fds())
        assert gw.rss_kb() - rss < 512, ("resident memory grew by kB", gw.rss_kb() - rss)
        assert gw.ka.connections() - before < 20, ("2,400 requests used this many upstream connections", gw.ka.connections() - before)

    def nopool_every_request_opens_its_own_connection(gw, up):
        before = gw.ka.connections()
        for _ in range(5):
            assert split(request(gw, GET % b"/ka"))[0] == 200
        assert gw.ka.connections() - before == 5, gw.ka.connections() - before
        assert all(b"Connection: close" in h for _, h in gw.ka.requests_for("/ka")[-5:]), "the upstream must be told to close"

    # ---- the passive circuit (task #6, docs/health.md): 3 consecutive failures open it for 1 s ----

    def circuit_opens_after_consecutive_failures(gw, up):
        heal(gw)
        flap = gw.flap
        flap.down()
        time.sleep(0.15)
        for _ in range(3):
            assert refusal(request(gw, GET % b"/flap/ok")) == (502, "proxy.connect")
        # Open: the fourth is refused without trying the upstream, even though it is back.
        flap.up()
        accepted = flap.accepted
        t0 = time.time()
        assert refusal(request(gw, GET % b"/flap/ok")) == (503, "proxy.circuit-open")
        assert time.time() - t0 < 0.5
        assert flap.accepted == accepted, "the open circuit still let a connection through"

    def circuit_recovers_after_the_open_period(gw, up):
        heal(gw)
        flap = gw.flap
        flap.down()
        time.sleep(0.15)
        for _ in range(3):
            request(gw, GET % b"/flap/ok")
        flap.up()
        assert refusal(request(gw, GET % b"/flap/ok")) == (503, "proxy.circuit-open")
        time.sleep(1.1)
        for _ in range(4):
            assert split(request(gw, GET % b"/flap/ok"))[0] == 200

    def a_failed_trial_reopens_the_circuit(gw, up):
        heal(gw)
        flap = gw.flap
        flap.down()
        time.sleep(0.15)
        for _ in range(3):
            request(gw, GET % b"/flap/ok")
        time.sleep(1.1)
        assert refusal(request(gw, GET % b"/flap/ok")) == (502, "proxy.connect"), "the trial should have been tried"
        assert refusal(request(gw, GET % b"/flap/ok")) == (503, "proxy.circuit-open"), "a failed trial should reopen the circuit"

    def only_one_trial_goes_through_at_a_time(gw, up):
        heal(gw)
        flap = gw.flap
        flap.down()
        time.sleep(0.15)
        for _ in range(3):
            request(gw, GET % b"/flap/ok")
        flap.up()
        time.sleep(1.1)
        accepted = flap.accepted
        results = []
        threads = [threading.Thread(target=lambda: results.append(refusal(request(gw, GET % b"/flap/slow"))[0] if True else 0)) for _ in range(5)]
        for th in threads:
            th.start()
        for th in threads:
            th.join()
        assert sorted(results).count(503) == 4 and flap.accepted - accepted == 1, (sorted(results), flap.accepted - accepted)
        assert split(request(gw, GET % b"/flap/ok"))[0] == 200, "the trial's success should have closed the circuit"

    def a_trial_abandoned_by_its_client_is_handed_back(gw, up):
        # The half-open trial is a request whose client leaves in the middle of its upload: the gateway drops the session and no
        # success or failure is ever recorded for it. The circuit must offer the trial to the next request at once.
        heal(gw)
        flap = gw.flap
        flap.down()
        time.sleep(0.15)
        for _ in range(3):
            request(gw, GET % b"/flap/ok")
        flap.up()
        time.sleep(1.1)
        s = socket.create_connection(("127.0.0.1", gw.port))
        s.sendall(b"POST /flap/stall HTTP/1.1\r\nHost: a\r\nContent-Length: 100\r\n\r\n" + b"x" * 10)
        time.sleep(0.2)
        s.close()
        time.sleep(0.2)
        assert split(request(gw, GET % b"/flap/ok"))[0] == 200, "the abandoned trial was not handed back"

    def a_trial_refused_locally_is_handed_back(gw, up):
        # A request that the gateway itself refuses after the circuit admitted it (here, a Connection header naming the framing
        # headers) must not use up the half-open trial, or anyone could keep an upstream shut out by sending bad requests.
        heal(gw)
        flap = gw.flap
        flap.down()
        time.sleep(0.15)
        for _ in range(3):
            request(gw, GET % b"/flap/ok")
        flap.up()
        time.sleep(1.1)
        bad = b"GET /flap/ok HTTP/1.1\r\nHost: a\r\nConnection: Content-Length\r\n\r\n"
        # The refused client keeps its connection open (the gateway lingers on it), so only the refusal itself can hand the trial back.
        s = socket.create_connection(("127.0.0.1", gw.port), timeout=5)
        s.sendall(bad)
        response = b""
        while not complete(response):
            response += s.recv(65536)
        assert refusal(response) == (400, "forward.connection-token"), response[:100]
        assert split(request(gw, GET % b"/flap/ok"))[0] == 200, "the locally refused request used up the trial"
        s.close()

    def a_success_resets_the_count(gw, up):
        heal(gw)
        flap = gw.flap
        flap.down()
        time.sleep(0.15)
        assert refusal(request(gw, GET % b"/flap/ok"))[0] == 502
        assert refusal(request(gw, GET % b"/flap/ok"))[0] == 502
        flap.up()
        assert split(request(gw, GET % b"/flap/ok"))[0] == 200
        flap.down()
        time.sleep(0.15)
        assert refusal(request(gw, GET % b"/flap/ok")) == (502, "proxy.connect")
        assert refusal(request(gw, GET % b"/flap/ok")) == (502, "proxy.connect"), "two failures after a success must not open a circuit of three"

    def other_upstreams_are_unaffected(gw, up):
        heal(gw)
        flap = gw.flap
        flap.down()
        time.sleep(0.15)
        for _ in range(3):
            request(gw, GET % b"/flap/ok")
        assert refusal(request(gw, GET % b"/flap/ok")) == (503, "proxy.circuit-open")
        assert split(request(gw, GET % b"/x"))[0] == 200
        assert split(request(gw, GET % b"/ka"))[0] == 200

    def stale_pooled_connections_do_not_trip_the_circuit(gw, up):
        quiesce(gw)
        for _ in range(12):
            for _ in range(2):
                status, _, body = split(request(gw, GET % b"/ka/die"))
                assert status == 200, ("a pooled connection that went stale was counted as a failure", status, body)

    def several_stale_connections_in_a_row_do_not_trip_the_circuit(gw, up):
        # Four idle pooled connections that each die when used again: four requests in a row get a 502 with no success between
        # them. They are pooled connections going stale, not an upstream failing, so none of them counts.
        quiesce(gw)
        threads = [threading.Thread(target=lambda: request(gw, GET % b"/ka/slow", timeout=10)) for _ in range(4)]
        for th in threads:
            th.start()
        for th in threads:
            th.join()
        post = b"POST /ka/die HTTP/1.1\r\nHost: a\r\nContent-Length: 3\r\n\r\nabc"
        for _ in range(4):
            assert refusal(request(gw, post)) == (502, "proxy.upstream-closed")
        assert split(request(gw, GET % b"/ka"))[0] == 200, "the circuit opened on stale pooled connections"

    def opening_the_circuit_closes_the_idle_pooled_connections(gw, up):
        heal(gw)
        flap = gw.flap
        time.sleep(0.75)
        threads = [threading.Thread(target=lambda: request(gw, GET % b"/flap/slow", timeout=10)) for _ in range(4)]
        for th in threads:
            th.start()
        for th in threads:
            th.join()
        time.sleep(0.05)
        assert flap.open_count() == 4, flap.open_count()
        # Three unreadable answers in a row: each takes one of the idle connections; the circuit opens; the fourth goes with it.
        for _ in range(3):
            assert refusal(request(gw, GET % b"/flap/garbage"))[0] == 502
        time.sleep(0.1)
        assert flap.open_count() == 0, ("idle connections to an upstream whose circuit is open should be closed", flap.open_count())
        assert refusal(request(gw, GET % b"/flap/ok")) == (503, "proxy.circuit-open")

    def an_unanswering_upstream_trips_the_circuit(gw, up):
        heal(gw)
        for _ in range(3):
            assert refusal(request(gw, GET % b"/flap/stall", timeout=8)) == (504, "timeout.upstream")
        assert refusal(request(gw, GET % b"/flap/ok")) == (503, "proxy.circuit-open")

    def nopool_the_circuit_never_opens_when_its_threshold_is_zero(gw, up):
        flap = gw.flap
        flap.down()
        time.sleep(0.15)
        for _ in range(8):
            assert refusal(request(gw, GET % b"/flap/ok")) == (502, "proxy.connect")
        flap.up()
        assert split(request(gw, GET % b"/flap/ok"))[0] == 200


def heal(gw):
    """Bring the flapping upstream back and wait until its circuit is closed again (it opens for a second at most)."""
    gw.flap.up()
    time.sleep(0.2)
    for _ in range(40):
        if split(request(gw, GET % b"/flap/ok"))[0] == 200:
            return
        time.sleep(0.1)
    raise AssertionError("the circuit did not close")


def quiesce(gw):
    """Let every idle pooled connection expire, so a test starts with an empty pool."""
    time.sleep(0.75)
    for _ in range(40):
        if gw.ka.open_count() == 0:
            return
        time.sleep(0.1)
    raise AssertionError("idle connections did not expire")


def main():
    names = sys.argv[1:] or [n for n in vars(T) if not n.startswith("_")]
    failures = 0
    with tempfile.TemporaryDirectory() as tmp, tempfile.TemporaryDirectory() as tmp0:
        port, up_port, dead, ka_port, flap_port = free_port(), free_port(), free_port(), free_port(), free_port()
        up = Upstream(up_port)
        ka = KAUpstream(ka_port)
        flap = FlapUpstream(flap_port)
        gw = Gateway(tmp, port, up_port, dead, ka_port, flap_port)
        gw.ka = ka
        gw.flap = flap
        gw0 = None
        if any(n.startswith("nopool_") for n in names):
            gw0 = Gateway(tmp0, free_port(), up_port, dead, ka_port, flap_port, pool=0, circuit=0)
            gw0.ka = ka
            gw0.flap = flap
        try:
            for name in names:
                t0 = time.time()
                g = gw0 if name.startswith("nopool_") else gw
                try:
                    getattr(T, name)(g, up)
                    if not g.alive():
                        raise AssertionError("the gateway died")
                    print("ok    %-52s %.1fs" % (name, time.time() - t0))
                except (AssertionError, OSError) as e:
                    failures += 1
                    print("FAIL  %-52s %s" % (name, e))
                    if not g.alive():
                        print("      the gateway died: exit %s %s" % (g.proc.returncode, g.proc.stderr.read()[:200]))
                        break
        finally:
            gw.stop()
            if gw0:
                gw0.stop()
            up.stop = True
            ka.stop = True
            flap.stop()
    print("%d tests, %d failures" % (len(names), failures))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
