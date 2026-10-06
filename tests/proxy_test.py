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
SOURCES = ["out", "problem", "framing", "chunked", "route", "forward", "egress", "proxy", "version", "gateway"]


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


class Gateway:
    def __init__(self, tmp, port, up_port, dead_port):
        deploy = pathlib.Path(tmp) / "deploy.toml"
        deploy.write_text("""listen = %d
header_timeout_ms = 1000
connect_timeout_ms = 1000
upstream_timeout_ms = 1500
total_timeout_ms = 4000

[[upstream]]
name = "up"
addr = "127.0.0.1:%d"

[[upstream]]
name = "dead"
addr = "127.0.0.1:%d"

[[route]]
path_prefix = "/dead"
upstream = "dead"

[[route]]
path_prefix = "/"
upstream = "up"
max_body = 1048576
""" % (port, up_port, dead_port))
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
        assert head == "GET /x HTTP/1.1\r\nHost: a.example\r\nAccept: */*\r\nConnection: close", head

    def one_upstream_connection_per_request(gw, up):
        before = up.connections
        for _ in range(7):
            request(gw, GET % b"/x")
        assert up.connections - before == 7, up.connections - before

    def content_length_body_echo(gw, up):
        body = os.urandom(600000)
        status, _, got = split(request(gw, b"POST /echo HTTP/1.1\r\nHost: a\r\nContent-Length: %d\r\n\r\n" % len(body) + body, timeout=15))
        assert status == 200 and hashlib.sha256(got).digest() == hashlib.sha256(body).digest(), (status, len(got))

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


def main():
    names = sys.argv[1:] or [n for n in vars(T) if not n.startswith("_")]
    failures = 0
    with tempfile.TemporaryDirectory() as tmp:
        port, up_port, dead = free_port(), free_port(), free_port()
        up = Upstream(up_port)
        gw = Gateway(tmp, port, up_port, dead)
        try:
            for name in names:
                t0 = time.time()
                try:
                    getattr(T, name)(gw, up)
                    if not gw.alive():
                        raise AssertionError("the gateway died")
                    print("ok    %-40s %.1fs" % (name, time.time() - t0))
                except (AssertionError, OSError) as e:
                    failures += 1
                    print("FAIL  %-40s %s" % (name, e))
                    if not gw.alive():
                        print("      the gateway died: exit %s %s" % (gw.proc.returncode, gw.proc.stderr.read()[:200]))
                        break
        finally:
            gw.stop()
            up.stop = True
    print("%d tests, %d failures" % (len(names), failures))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
