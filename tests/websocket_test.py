#!/usr/bin/env python3
"""WebSocket end to end (docs/websocket.md section 12): a built gateway, a Python RFC 6455 client and a Python RFC 6455 upstream, both written
here from the RFC and not from the gateway, plus peers that are not WebSocket at all.

    python3 tests/websocket_test.py [test_name ...]      # all tests, or the named ones
    WS_TREE=/path/to/copy python3 tests/websocket_test.py ...   # build the gateway from another copy of the tree (tests/websocket_mutants.py)

Three gateways are built from loose files, as tests/proxy_test.py does: `main` (many tunnels, long timers, the circuit off), `timers` (a short idle
time and lifetime, three tunnels at most, the circuit on) and `tls` (the same routes on `tls_listen`; needs `openssl` for the certificates).
Needs `build/deps` filled by one `cancho build`.
"""

import base64
import hashlib
import json
import os
import pathlib
import re
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import proxy_test as pt  # noqa: E402
import tls_test as tt  # noqa: E402

TREE = pathlib.Path(os.environ.get("WS_TREE", str(pt.ROOT)))
LEX = pt.LEX
GUID = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
SUPPORTED = ["ocpp1.6", "ocpp2.0.1", "chat"]

# ---------------------------------------------------------------------------------------------------------------------- RFC 6455 (the test's own)


def accept_for(key):
    return base64.b64encode(hashlib.sha1(key + GUID).digest())


def new_key():
    return base64.b64encode(os.urandom(16))


def mask_bytes(data, key):
    n = len(data)
    if n == 0:
        return b""
    k = (key * (n // 4 + 1))[:n]
    return (int.from_bytes(data, "little") ^ int.from_bytes(k, "little")).to_bytes(n, "little")


def encode_frame(opcode, payload=b"", fin=True, mask=True):
    b0 = (0x80 if fin else 0) | opcode
    m = 0x80 if mask else 0
    n = len(payload)
    if n < 126:
        head = bytes([b0, m | n])
    elif n < 65536:
        head = bytes([b0, m | 126]) + struct.pack(">H", n)
    else:
        head = bytes([b0, m | 127]) + struct.pack(">Q", n)
    if mask:
        key = os.urandom(4)
        return head + key + mask_bytes(payload, key)
    return head + payload


class Reader:
    """Bytes from a socket with a push-back buffer, counting what it hands out."""

    def __init__(self, sock, buf=b""):
        self.sock = sock
        self.buf = bytearray(buf)
        self.consumed = 0

    def read(self, n):
        while len(self.buf) < n:
            d = self.sock.recv(max(1 << 16, min(n - len(self.buf), 1 << 22)))
            if not d:
                raise EOFError("closed after %d of %d bytes" % (len(self.buf), n))
            self.buf += d
        out = bytes(self.buf[:n])
        del self.buf[:n]
        self.consumed += n
        return out

    def frame(self):
        b0, b1 = self.read(2)
        n = b1 & 127
        if n == 126:
            n = struct.unpack(">H", self.read(2))[0]
        elif n == 127:
            n = struct.unpack(">Q", self.read(8))[0]
        key = self.read(4) if b1 & 0x80 else None
        payload = self.read(n)
        if key:
            payload = mask_bytes(payload, key)
        return bool(b0 & 0x80), b0 & 15, payload


def read_head(sock, limit=65536):
    """Read up to the blank line; answers (head bytes with the blank line, what came after it)."""
    data = b""
    while b"\r\n\r\n" not in data:
        d = sock.recv(65536)
        if not d:
            return data, b""
        data += d
        if len(data) > limit:
            break
    head, sep, rest = data.partition(b"\r\n\r\n")
    return head + sep, rest


def parse_head(head):
    lines = head.decode("latin-1").split("\r\n")
    status = int(lines[0].split(" ")[1])
    headers = {}
    for line in lines[1:]:
        if line:
            k, _, v = line.partition(":")
            headers.setdefault(k.lower(), []).append(v.strip())
    return status, headers


def request_bytes(path="/v16/CP1", key=None, protocols=("ocpp1.6",), origin=None, extra=(), version="13", host="csms.example", method="GET", upgrade="websocket",
                  connection="Upgrade", http="HTTP/1.1"):
    key = key or new_key()
    lines = ["%s %s %s" % (method, path, http), "Host: " + host]
    if upgrade is not None:
        lines.append("Upgrade: " + upgrade)
    if connection is not None:
        lines.append("Connection: " + connection)
    lines.append("Sec-WebSocket-Key: " + key.decode())
    if version is not None:
        lines.append("Sec-WebSocket-Version: " + version)
    if protocols:
        lines.append("Sec-WebSocket-Protocol: " + ", ".join(protocols))
    if origin:
        lines.append("Origin: " + origin)
    lines += list(extra)
    return ("\r\n".join(lines) + "\r\n\r\n").encode(), key


class Ws:
    """An open WebSocket, client side."""

    def __init__(self, sock, head, rest, key):
        self.sock = sock
        self.head = head
        self.head_len = len(head)
        self.status, self.headers = parse_head(head)
        self.reader = Reader(sock, rest)
        self.key = key
        self.sent = 0
        self.protocol = (self.headers.get("sec-websocket-protocol") or [None])[0]

    def send(self, opcode, payload=b"", fin=True):
        data = encode_frame(opcode, payload, fin)
        self.sock.sendall(data)
        self.sent += len(data)

    def text(self, s):
        self.send(1, s.encode())

    def recv(self):
        fin, op, payload = self.reader.frame()
        return op, payload

    def expect(self, opcode, payload=None):
        op, got = self.recv()
        assert op == opcode, "expected opcode %d, got %d (%r)" % (opcode, op, got[:60])
        if payload is not None:
            assert got == payload, "payload differs: %d bytes, wanted %d" % (len(got), len(payload))
        return got

    @property
    def received(self):
        return self.reader.consumed

    def eof(self, timeout=8):
        """Wait for the connection to end; answers the seconds it took, or raises if it did not."""
        t0 = time.time()
        self.sock.settimeout(timeout)
        try:
            while True:
                d = self.sock.recv(65536)
                if not d:
                    return time.time() - t0
        except (ConnectionResetError, BrokenPipeError):
            return time.time() - t0
        except socket.timeout:
            raise AssertionError("the connection was still open after %.1fs" % timeout)

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass


def connect_ws(gw, path="/v16/CP1", tls=False, rcvbuf=None, timeout=10, **kw):
    """Open a WebSocket through the gateway; asserts a 101 with the right accept value."""
    raw, key = request_bytes(path, **kw)
    sock = open_socket(gw, tls, rcvbuf, timeout)
    sock.sendall(raw)
    head, rest = read_head(sock)
    ws = Ws(sock, head, rest, key)
    assert ws.status == 101, "not upgraded: %r" % head[:200]
    assert ws.headers["sec-websocket-accept"] == [accept_for(key).decode()], ws.headers
    return ws


def open_socket(gw, tls=False, rcvbuf=None, timeout=10):
    if tls:
        return tt.connect(gw, timeout=timeout)
    s = socket.socket()
    if rcvbuf:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, rcvbuf)
    s.settimeout(timeout)
    s.connect(("127.0.0.1", gw.port))
    return s


def raw_exchange(gw, raw, tls=False, timeout=6, tail=0.0):
    """Send raw bytes, answer the response (read until the connection closes or a Content-Length body is complete)."""
    s = open_socket(gw, tls, None, timeout)
    s.sendall(raw)
    out = b""
    try:
        while True:
            d = s.recv(65536)
            if not d:
                break
            out += d
            if pt.complete(out):
                break
    except OSError as e:
        out += b"[%s]" % str(e).encode()
    s.close()
    return out


def refused(response):
    status, head, body = pt.split(response)
    try:
        return status, json.loads(body)["rule"]
    except (ValueError, KeyError):
        return status, None


# ---------------------------------------------------------------------------------------------------------------------- the upstream


def big_payload(n):
    return (bytes(range(256)) * (n // 256 + 1))[:n]


class WsUpstream:
    """A WebSocket server. What it does is chosen by the last segment of the request path: echo (default), bigdown, slowsink, silent, speakfirst, closeafter,
    and the misbehaviours badaccept, noaccept, twoaccept, noupgrade, noconn, cl, te, badproto, noproto, ext, 401, plain101. `/plain/ka` is a keep-alive HTTP
    server for the pool test, `/plain/x` an ordinary HTTP answer."""

    def __init__(self, port):
        self.port = port
        self.lock = threading.Lock()
        self.conns = 0
        self.live = 0
        self.heads = []
        self.ended = []        # (path, how) when a connection ended
        self.sunk = []         # (path, sha256 hex, length) of what a slowsink received
        self.stop = False
        self.sock = socket.socket()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", port))
        self.sock.listen(300)
        threading.Thread(target=self.accept, daemon=True).start()

    def accept(self):
        while not self.stop:
            try:
                c, _ = self.sock.accept()
            except OSError:
                return
            with self.lock:
                self.conns += 1
                self.live += 1
            threading.Thread(target=self.serve, args=(c,), daemon=True).start()

    def note(self, path, how):
        with self.lock:
            self.ended.append((path, how))

    def serve(self, c):
        path = "?"
        try:
            head, rest = read_head(c)
            if not head:
                return
            with self.lock:
                self.heads.append(head)
            path = head.split(b" ")[1].decode()
            mode = path.rstrip("/").split("/")[-1].split("?")[0]
            if path.startswith("/plain/"):
                self.plain(c, head, rest, path)
                return
            if mode == "plain101":
                c.sendall(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
                return
            if mode == "401":
                c.sendall(b"HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic\r\nContent-Length: 5\r\nConnection: close\r\n\r\nnope!")
                return
            self.websocket(c, head, rest, path, mode)
        except (OSError, EOFError, ValueError, IndexError):
            self.note(path, "error")
        finally:
            with self.lock:
                self.live -= 1
            try:
                c.close()
            except OSError:
                pass

    def plain(self, c, head, rest, path):
        if path.startswith("/plain/ka"):
            while True:
                c.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                h, rest = read_head(c)
                if not h:
                    return
        else:
            c.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")

    def websocket(self, c, head, rest, path, mode):
        h = pt.heads_of(head)
        if "sec-websocket-key" not in h:
            c.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nplain")
            return
        key = h["sec-websocket-key"][0].encode()
        offered = [t.strip() for v in h.get("sec-websocket-protocol", []) for t in v.split(",") if t.strip()]
        chosen = next((t for t in offered if t in SUPPORTED), None)
        accept = accept_for(key).decode()
        lines = ["HTTP/1.1 101 Switching Protocols", "Upgrade: websocket", "Connection: Upgrade", "Sec-WebSocket-Accept: " + accept, "Server: ws-test", "Set-Cookie: s=1"]
        if mode == "badaccept":
            lines[3] = "Sec-WebSocket-Accept: " + accept_for(key + b"x").decode()
        elif mode == "noaccept":
            del lines[3]
        elif mode == "twoaccept":
            lines.insert(4, "Sec-WebSocket-Accept: " + accept)
        elif mode == "noupgrade":
            del lines[1]
        elif mode == "noconn":
            del lines[2]
        elif mode == "cl":
            lines.append("Content-Length: 0")
        elif mode == "te":
            lines.append("Transfer-Encoding: chunked")
        elif mode == "ext":
            lines.append("Sec-WebSocket-Extensions: permessage-deflate")
        if mode == "badproto":
            lines.append("Sec-WebSocket-Protocol: mqtt")
        elif mode == "noproto":
            pass
        elif chosen:
            lines.append("Sec-WebSocket-Protocol: " + chosen)
        response = ("\r\n".join(lines) + "\r\n\r\n").encode()
        reader = Reader(c, rest)
        if mode == "speakfirst":
            c.sendall(response + encode_frame(1, b"hello first", mask=False))
        else:
            c.sendall(response)
        if mode == "silent":
            c.settimeout(60)
            while c.recv(4096):
                pass
            self.note(path, "eof")
            return
        if mode == "closeafter":
            c.sendall(encode_frame(1, b"bye", mask=False))
            self.note(path, "closed-by-us")
            return
        if mode == "bigdown":
            c.sendall(encode_frame(2, big_payload(8 << 20), mask=False))
        if mode == "slowsink":
            time.sleep(1.5)
            fin, op, payload = reader.frame()
            with self.lock:
                self.sunk.append((path, hashlib.sha256(payload).hexdigest(), len(payload)))
            c.sendall(encode_frame(1, hashlib.sha256(payload).hexdigest().encode(), mask=False))
        c.settimeout(120)
        while True:
            try:
                fin, op, payload = reader.frame()
            except EOFError:
                self.note(path, "eof")
                return
            if op in (0, 1, 2):
                c.sendall(encode_frame(op, payload, fin, mask=False))
            elif op == 9:
                c.sendall(encode_frame(10, payload, mask=False))
            elif op == 8:
                c.sendall(encode_frame(8, payload[:2], mask=False))
                self.note(path, "close-handshake")
                return

    def wait_ended(self, n, timeout=6):
        end = time.time() + timeout
        while time.time() < end:
            with self.lock:
                if len(self.ended) >= n:
                    return list(self.ended)
            time.sleep(0.02)
        with self.lock:
            return list(self.ended)

    def shutdown(self):
        self.stop = True
        try:
            self.sock.close()
        except OSError:
            pass


# ---------------------------------------------------------------------------------------------------------------------- the gateways

ROUTES = """
[[route]]
name = "v16"
path_prefix = "/v16"
websocket = true
subprotocols = ["ocpp1.6"]
upstream = "up"

[[route]]
name = "v201"
path_prefix = "/v201"
websocket = true
subprotocols = ["ocpp1.6", "ocpp2.0.1"]
upstream = "up"

[[route]]
name = "bare"
path_prefix = "/bare"
websocket = true
upstream = "up"

[[route]]
name = "browser"
path_prefix = "/browser"
websocket = true
subprotocols = ["chat"]
origins = ["https://app.example", "http://localhost:3000"]
upstream = "up"

[[route]]
name = "bad"
path_prefix = "/bad"
websocket = true
subprotocols = ["ocpp1.6"]
upstream = "up"

[[route]]
name = "circ"
path_prefix = "/circ"
websocket = true
subprotocols = ["ocpp1.6"]
upstream = "up"

[[route]]
name = "plain"
path_prefix = "/"
upstream = "up"
"""


class Gateway:
    def __init__(self, tmp, up_port, idle=20000, lifetime=60000, max_tunnels=120, circuit=0, tls=False, pool=4):
        self.tmp = pathlib.Path(tmp)
        self.port, self.admin = pt.free_port(), pt.free_port()
        self.tls_port = pt.free_port() if tls else None
        tlsconf = ""
        if tls:
            certs = self.tmp / "certs"
            self.chain_api = tt.make_identity(certs, "api", "api.example")
            self.chain_second = self.chain_api
            tlsconf = 'tls_listen = %d\ntls_dir = "%s"\ntls_identities = ["api"]\n' % (self.tls_port, certs)
        deploy = self.tmp / "deploy.toml"
        deploy.write_text("""listen = %d
admin_listen = %d
%sheader_timeout_ms = 1000
connect_timeout_ms = 1000
upstream_timeout_ms = 1500
total_timeout_ms = 4000
idle_timeout_ms = 500
pool_idle_max = %d
circuit_threshold = %d
circuit_open_ms = 1000
ws_idle_timeout_ms = %d
ws_max_lifetime_ms = %d
ws_max_tunnels = %d

[[upstream]]
name = "up"
addr = "127.0.0.1:%d"
%s""" % (self.port, self.admin, tlsconf, pool, circuit, idle, lifetime, max_tunnels, up_port, ROUTES))
        out = self.tmp / "gen"
        subprocess.run([sys.executable, str(TREE / "scripts" / "generate.py"), str(deploy), "--out", str(out)], check=True)
        files = [str(out / n) for n in ("deploy.cho", "routes.cho", "tlsfiles.cho")] + pt.dependencies() + [str(TREE / "src" / (n + ".cho")) for n in pt.SOURCES]
        built = subprocess.run([LEX, "build", "--std", *files, "-o", str(self.tmp / "gateway")], capture_output=True, text=True)
        if built.returncode != 0:
            raise SystemExit("build failed: " + built.stderr[:800])
        self.proc = subprocess.Popen([str(self.tmp / "gateway")], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.log = []
        self.lock = threading.Lock()
        threading.Thread(target=self.read_log, daemon=True).start()
        for _ in range(100):
            try:
                socket.create_connection(("127.0.0.1", self.tls_port or self.port), timeout=0.2).close()
                break
            except OSError:
                time.sleep(0.05)
        else:
            raise SystemExit("gateway did not start: %s" % self.proc.stderr.read()[:300])
        time.sleep(0.4)

    def read_log(self):
        for raw in self.proc.stdout:
            with self.lock:
                self.log.append(raw)

    def lines(self):
        with self.lock:
            out = []
            for raw in self.log:
                try:
                    out.append(json.loads(raw))
                except ValueError:
                    pass
            return out

    def find(self, n, wait=4, **want):
        """The first line after the first `n` whose keys have these values (`None`: the key is absent)."""
        end = time.time() + wait
        while True:
            for l in self.lines()[n:]:
                if all((k not in l) if v is None else l.get(k) == v for k, v in want.items()):
                    return l
            if time.time() > end:
                raise AssertionError("no log line like %r among %r" % (want, self.lines()[n:][-4:]))
            time.sleep(0.05)

    def metrics(self):
        c = socket.create_connection(("127.0.0.1", self.admin), timeout=5)
        c.sendall(b"GET /metrics HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n")
        data = b""
        while True:
            d = c.recv(65536)
            if not d:
                break
            data += d
        c.close()
        return json.loads(data.partition(b"\r\n\r\n")[2])

    def wait_active(self, n, wait=5):
        end = time.time() + wait
        while time.time() < end:
            if self.metrics()["ws"]["tunnels_active"] == n:
                return
            time.sleep(0.05)
        raise AssertionError("tunnels_active is %d, wanted %d" % (self.metrics()["ws"]["tunnels_active"], n))

    def fds(self):
        return len(os.listdir("/proc/%d/fd" % self.proc.pid))

    def rss_kib(self):
        for line in open("/proc/%d/status" % self.proc.pid):
            if line.startswith("VmRSS:"):
                return int(line.split()[1])

    def cpu(self):
        f = open("/proc/%d/stat" % self.proc.pid).read().rsplit(")", 1)[1].split()
        return (int(f[11]) + int(f[12])) / os.sysconf("SC_CLK_TCK")

    def alive(self):
        return self.proc.poll() is None

    def stop(self):
        self.proc.kill()
        self.proc.wait()


def settle_down(gw, wait=4):
    """Wait until the gateway holds no tunnel and no session but the metrics scrape's own."""
    end = time.time() + wait
    while time.time() < end:
        m = gw.metrics()
        if m["ws"]["tunnels_active"] == 0 and m["sessions_active"] <= 1:
            return m
        time.sleep(0.05)
    raise AssertionError("sessions did not end: %r" % gw.metrics())


# ---------------------------------------------------------------------------------------------------------------------- the tests


def echo_roundtrip(ws):
    ws.text("hello")
    ws.expect(1, b"hello")
    ws.send(2, b"\x00\x01\x02")
    ws.expect(2, b"\x00\x01\x02")


class Main:
    """On the gateway with many tunnels and long timers."""

    def handshake_selects_the_subprotocol_and_the_head_has_only_checked_fields(gw, up):
        ws = connect_ws(gw, "/v16/CP001")
        assert ws.protocol == "ocpp1.6", ws.headers
        got = sorted(ws.headers)
        assert got == ["connection", "sec-websocket-accept", "sec-websocket-protocol", "upgrade", "via", "x-request-id"], got
        assert ws.headers["upgrade"] == ["websocket"] and ws.headers["connection"] == ["Upgrade"], ws.headers
        assert ws.headers["via"] == ["1.1 cancho-gateway"] and re.fullmatch(r"[0-9a-f]+-[0-9a-f]+-[0-9a-f]{8,}", ws.headers["x-request-id"][0])
        assert ws.head.startswith(b"HTTP/1.1 101 Switching Protocols\r\n"), ws.head
        ws.close()

    def text_binary_ping_and_close_frames_go_both_ways(gw, up):
        ws = connect_ws(gw, "/v16/CP002")
        echo_roundtrip(ws)
        ws.send(9, b"are you there")
        ws.expect(10, b"are you there")
        ws.send(9, b"")
        ws.expect(10, b"")
        ws.send(8, struct.pack(">H", 1000) + b"normal")
        ws.expect(8, struct.pack(">H", 1000))
        assert ws.eof() < 3
        ws.close()

    def message_sizes_across_the_length_encodings(gw, up):
        ws = connect_ws(gw, "/v16/CP003")
        for n in (0, 1, 125, 126, 127, 65535, 65536, 70000):
            payload = os.urandom(n)
            ws.send(2, payload)
            ws.expect(2, payload)
        # a fragmented message passes as the frames it is made of: the gateway does not reassemble
        ws.send(1, b"frag", fin=False)
        ws.send(0, b"men", fin=False)
        ws.send(0, b"ted")
        for part, fin in ((b"frag", False), (b"men", False), (b"ted", True)):
            fin_got, op, payload = ws.reader.frame()
            assert payload == part and fin_got == fin, (payload, fin_got)
        ws.close()

    def both_ocpp_subprotocols_are_selected_on_the_route_that_serves_them(gw, up):
        ws = connect_ws(gw, "/v201/CP1", protocols=("ocpp2.0.1", "ocpp1.6"))
        assert ws.protocol == "ocpp2.0.1"
        echo_roundtrip(ws)
        ws.close()
        ws = connect_ws(gw, "/v201/CP2", protocols=("ocpp1.6",))
        assert ws.protocol == "ocpp1.6"
        ws.close()

    def a_route_with_no_subprotocol_answers_none(gw, up):
        ws = connect_ws(gw, "/bare/x", protocols=())
        assert ws.protocol is None and "sec-websocket-protocol" not in ws.headers, ws.headers
        echo_roundtrip(ws)
        ws.close()

    def the_upstream_is_sent_the_checked_request_and_no_extensions(gw, up):
        n = len(up.heads)
        ws = connect_ws(gw, "/v16/CP004", extra=["Sec-WebSocket-Extensions: permessage-deflate", "X-Custom: kept"], origin=None)
        ws.close()
        h = pt.heads_of(up.heads[n])
        lines = up.heads[n].decode().split("\r\n")
        assert lines[0] == "GET /v16/CP004 HTTP/1.1", lines[0]
        assert h["upgrade"] == ["websocket"] and h["connection"] == ["Upgrade"], h
        assert h["sec-websocket-key"] == [ws.key.decode()] and h["sec-websocket-version"] == ["13"] and h["sec-websocket-protocol"] == ["ocpp1.6"], h
        assert "sec-websocket-extensions" not in h, h
        assert h["x-custom"] == ["kept"] and h["via"] == ["1.1 cancho-gateway"] and h["x-forwarded-host"] == ["csms.example"], h
        assert lines[-4:-2] == ["Connection: Upgrade", "Upgrade: websocket"], lines
        assert "Connection: close" not in up.heads[n].decode(), "Connection: close must not be written on an upgrade"

    def the_access_log_line_of_a_tunnel(gw, up):
        n0 = len(gw.lines())
        ws = connect_ws(gw, "/v16/CP005")
        msgs = [os.urandom(100), os.urandom(3000)]
        for m in msgs:
            ws.send(2, m)
            ws.expect(2, m)
        ws.send(8, struct.pack(">H", 1000))
        ws.expect(8)
        ws.eof()
        e = gw.find(n0, path="/v16/CP005")
        assert e["status"] == 101 and e["outcome"] == "ok" and e["rule"] == "" and e["route"] == "v16" and e["upstream"] == "up" and e["method"] == "GET", e
        assert e["bytes_in"] == ws.sent, (e["bytes_in"], ws.sent)
        assert e["bytes_out"] == ws.head_len + ws.received, (e["bytes_out"], ws.head_len, ws.received)
        assert list(e)[-1] == "upgrade" and e["upgrade"] == "websocket" and "tls" not in e, list(e)
        assert list(e)[:-1] == ["t", "id", "method", "path", "route", "upstream", "status", "rule", "outcome", "ms", "upstream_ms", "bytes_in", "bytes_out"], list(e)
        assert e["ms"] >= 0 and e["upstream_ms"] >= 0
        # an ordinary request on the same gateway writes the line it always wrote
        n1 = len(gw.lines())
        pt.request(gw, b"GET /plain/x HTTP/1.1\r\nHost: a\r\n\r\n")
        e2 = gw.find(n1, path="/plain/x")
        assert "upgrade" not in e2 and list(e2)[-1] == "bytes_out", list(e2)
        ws.close()

    def metrics_count_the_tunnel_and_return_to_zero(gw, up):
        before = gw.metrics()["ws"]["tunnels_total"]
        wss = [connect_ws(gw, "/v16/CP1%02d" % i) for i in range(5)]
        for w in wss:
            echo_roundtrip(w)
        m = gw.metrics()
        assert m["ws"]["tunnels_total"] == before + 5 and m["ws"]["tunnels_active"] == 5, m["ws"]
        text = socket.create_connection(("127.0.0.1", gw.admin), timeout=5)
        text.sendall(b"GET /metrics?format=prometheus HTTP/1.1\r\nHost: a\r\nAccept: text/plain\r\nConnection: close\r\n\r\n")
        data = b""
        while True:
            d = text.recv(65536)
            if not d:
                break
            data += d
        text.close()
        assert re.search(rb"cancho_gateway_ws_tunnels_active 5\n", data) and re.search(rb"cancho_gateway_ws_tunnels_total %d\n" % (before + 5), data), data[-500:]
        for w in wss:
            w.close()
        m = settle_down(gw)
        assert m["ws"]["tunnels_total"] == before + 5 and m["ws"]["tunnels_active"] == 0, m["ws"]

    def a_hundred_and_twenty_tunnels_at_once_and_the_next_is_refused(gw, up):
        before = gw.metrics()["ws"]["tunnels_total"]
        fds0 = gw.fds()
        wss = []
        for i in range(120):
            w = connect_ws(gw, "/v16/CAP%03d" % i, timeout=15)
            wss.append(w)
        for i, w in enumerate(wss):
            w.text("m%d" % i)
        for i, w in enumerate(wss):
            w.expect(1, b"m%d" % i)
        m = gw.metrics()
        assert m["ws"]["tunnels_active"] == 120, m["ws"]
        # one more upgrade is refused, an ordinary request is still served, and the tunnels go on
        raw, _ = request_bytes("/v16/CAP999")
        assert refused(raw_exchange(gw, raw)) == (503, "ws.limit")
        status, head, body = pt.split(pt.request(gw, b"GET /plain/x HTTP/1.1\r\nHost: a\r\n\r\n"))
        assert status == 200 and body == b"ok", (status, body)
        for w in wss[:5]:
            echo_roundtrip(w)
        # closing one makes room for another
        wss[0].close()
        gw.wait_active(119)
        extra = connect_ws(gw, "/v16/CAP120")
        echo_roundtrip(extra)
        extra.close()
        for w in wss:
            w.close()
        m = settle_down(gw, wait=8)
        assert m["ws"]["tunnels_total"] == before + 121, m["ws"]
        assert gw.alive()
        time.sleep(0.3)
        assert gw.fds() <= fds0 + 2, "descriptors leaked: %d -> %d" % (fds0, gw.fds())

    def one_mebibyte_each_way_byte_for_byte(gw, up):
        ws = connect_ws(gw, "/v16/CP010", timeout=30)
        up_msg = os.urandom(1 << 20)
        ws.send(2, up_msg)
        ws.expect(2, up_msg)
        ws.text("again")
        ws.expect(1, b"again")
        ws.close()

    def a_client_that_reads_late_gets_eight_mebibytes_intact_with_the_queues_bounded(gw, up):
        rss0 = gw.rss_kib()
        ws = connect_ws(gw, "/v16/bigdown", rcvbuf=4096, timeout=60)
        time.sleep(1.5)      # the upstream's 8 MiB is now stuck in the kernel's buffers and the gateway's: the client has not read a byte
        grown = gw.rss_kib() - rss0
        assert grown < 4096, "the gateway grew %d KiB while the client did not read" % grown
        got = ws.expect(2)
        assert len(got) == 8 << 20 and got == big_payload(8 << 20), len(got)
        ws.text("still alive")
        ws.expect(1, b"still alive")
        ws.close()

    def an_upstream_that_reads_late_receives_thirty_two_mebibytes_intact(gw, up):
        ws = connect_ws(gw, "/v16/slowsink", timeout=60)
        payload = os.urandom(32 << 20)
        t0 = time.time()
        ws.send(2, payload)        # blocks until the upstream, which sleeps 1.5 s, starts to read: the gateway's queues and the kernel's are full by then
        assert time.time() - t0 > 1.0, "the send finished at once: nothing pushed back"
        ack = ws.expect(1)
        assert ack == hashlib.sha256(payload).hexdigest().encode(), ack
        ws.close()

    def both_directions_at_once_with_a_slow_reader(gw, up):
        ws = connect_ws(gw, "/v16/CP011", rcvbuf=4096, timeout=60)
        payloads = [os.urandom(600000) for _ in range(6)]
        errors = []

        def writer():
            try:
                for p in payloads:
                    ws.send(2, p)
            except OSError as e:
                errors.append(e)

        t = threading.Thread(target=writer)
        t.start()
        time.sleep(1.0)        # reads nothing for a second while writing: the echoes pile up behind it
        for p in payloads:
            ws.expect(2, p)
        t.join()
        assert not errors, errors
        ws.close()

    def a_server_that_speaks_first_is_heard(gw, up):
        ws = connect_ws(gw, "/v16/speakfirst")
        ws.expect(1, b"hello first")
        echo_roundtrip(ws)
        ws.close()

    def the_client_closing_ends_the_upstream_connection_and_frees_the_slots(gw, up):
        n = len(up.ended)
        ws = connect_ws(gw, "/v16/CP020")
        echo_roundtrip(ws)
        ws.close()
        ended = up.wait_ended(n + 1)
        assert ended[n][1] == "eof", ended[n:]
        settle_down(gw)

    def the_upstream_closing_ends_the_client_side(gw, up):
        n0 = len(gw.lines())
        ws = connect_ws(gw, "/v16/closeafter")
        ws.expect(1, b"bye")
        assert ws.eof() < 3
        e = gw.find(n0, path="/v16/closeafter")
        assert e["outcome"] == "ok" and e["status"] == 101 and e["upgrade"] == "websocket", e
        ws.close()
        settle_down(gw)

    def a_client_reset_mid_tunnel_is_an_ordinary_end(gw, up):
        n = len(up.ended)
        ws = connect_ws(gw, "/v16/CP021")
        echo_roundtrip(ws)
        ws.sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
        ws.close()     # RST
        up.wait_ended(n + 1)
        settle_down(gw)
        assert gw.alive()

    # ----------------------------------------------------------- refusals before the dial: the upstream never hears of them

    def refusals_before_the_dial_each_have_their_tag_and_never_reach_the_upstream(gw, up):
        key = new_key()
        good, _ = request_bytes("/v16/CP1", key=key)
        cases = [
            ("ws.method", 400, request_bytes("/v16/CP1", method="POST")[0]),
            ("ws.http-version", 400, request_bytes("/v16/CP1", http="HTTP/1.0")[0]),
            ("ws.upgrade", 400, request_bytes("/v16/CP1", upgrade="h2c")[0]),
            ("ws.upgrade", 400, request_bytes("/v16/CP1", upgrade="websocket, h2c")[0]),
            ("ws.upgrade", 400, request_bytes("/v16/CP1", connection="close")[0]),
            ("ws.upgrade", 400, request_bytes("/v16/CP1", connection="Upgrade, sec-websocket-key")[0]),
            ("ws.upgrade", 400, request_bytes("/v16/CP1", connection="Upgrade, close")[0]),
            ("ws.upgrade", 400, request_bytes("/v16/CP1", extra=["Upgrade: websocket"])[0]),
            ("ws.upgrade", 400, request_bytes("/v16/CP1", extra=["Connection: Upgrade"])[0]),
            ("ws.upgrade", 400, request_bytes("/v16/CP1", upgrade=None)[0]),
            ("ws.body", 400, request_bytes("/v16/CP1", extra=["Content-Length: 0"])[0]),
            ("ws.body", 400, request_bytes("/v16/CP1", extra=["Content-Length: 5"])[0] + b"hello"),
            ("ws.body", 400, request_bytes("/v16/CP1", extra=["Transfer-Encoding: chunked"])[0] + b"0\r\n\r\n"),
            ("ws.early-data", 400, good + encode_frame(1, b"too early")),
            ("ws.early-data", 400, good + b"GET /plain/x HTTP/1.1\r\nHost: a\r\n\r\n"),
            ("ws.version", 426, request_bytes("/v16/CP1", version="8")[0]),
            ("ws.version", 426, request_bytes("/v16/CP1", version="13, 8")[0]),
            ("ws.version", 426, request_bytes("/v16/CP1", version=None)[0]),
            ("ws.key", 400, request_bytes("/v16/CP1", key=base64.b64encode(os.urandom(15)))[0]),
            ("ws.key", 400, request_bytes("/v16/CP1", key=base64.b64encode(os.urandom(18)))[0]),
            ("ws.key", 400, request_bytes("/v16/CP1", key=b"!" * 24)[0]),
            ("ws.key", 400, request_bytes("/v16/CP1", key=b"dGhlIHNhbXBsZSBub25jZR==")[0]),
            ("ws.key", 400, request_bytes("/v16/CP1", extra=["Sec-WebSocket-Key: " + new_key().decode()])[0]),
            ("ws.subprotocol", 400, request_bytes("/v16/CP1", protocols=("ocpp2.0.1",))[0]),
            ("ws.subprotocol", 400, request_bytes("/v16/CP1", protocols=())[0]),
            ("ws.subprotocol", 400, request_bytes("/v16/CP1", protocols=("ocpp1.6", "", "x"))[0]),
            ("ws.subprotocol", 400, request_bytes("/v16/CP1", extra=["Sec-WebSocket-Protocol: ocpp1.6"])[0]),
            ("ws.subprotocol", 400, request_bytes("/bare/x", protocols=("ocpp1.6",))[0]),
            ("ws.origin", 403, request_bytes("/v16/CP1", origin="https://evil.example")[0]),
            ("ws.origin", 403, request_bytes("/browser/x", protocols=("chat",), origin="https://evil.example")[0]),
            ("ws.origin", 403, request_bytes("/browser/x", protocols=("chat",), origin="null")[0]),
            ("ws.origin", 403, request_bytes("/browser/x", protocols=("chat",), origin="HTTPS://app.example")[0]),
            ("ws.origin", 403, request_bytes("/browser/x", protocols=("chat",), origin="https://app.example/")[0]),
            ("ws.origin", 403, request_bytes("/browser/x", protocols=("chat",), origin="https://app.example", extra=["Origin: https://app.example"])[0]),
        ]
        n0 = up.conns
        l0 = len(gw.lines())
        for tag, status, raw in cases:
            got = refused(raw_exchange(gw, raw))
            assert got == (status, tag), "%s: wanted %s, got %s for %r" % (tag, (status, tag), got, raw[:120])
        assert up.conns == n0, "a refused upgrade reached the upstream"
        lines = gw.lines()[l0:]
        for _ in range(40):
            if len(lines) >= len(cases):
                break
            time.sleep(0.05)
            lines = gw.lines()[l0:]
        assert all(l["outcome"] == "refused" and "upgrade" not in l and l["rule"].startswith("ws.") for l in lines[:len(cases)]), lines[:3]
        assert sorted(set(l["rule"] for l in lines)) == sorted(set(c[0] for c in cases))

    def a_426_names_the_version_the_gateway_speaks(gw, up):
        response = raw_exchange(gw, request_bytes("/v16/CP1", version="8")[0])
        assert response.startswith(b"HTTP/1.1 426 Upgrade Required\r\n") and b"\r\nSec-WebSocket-Version: 13\r\n" in response, response[:200]

    def browser_origins_are_admitted_only_when_listed(gw, up):
        for origin in ("https://app.example", "http://localhost:3000", None):
            ws = connect_ws(gw, "/browser/x", protocols=("chat",), origin=origin)
            assert ws.protocol == "chat"
            ws.close()
        raw = request_bytes("/v16/CP1", origin="https://app.example")[0]
        assert refused(raw_exchange(gw, raw)) == (403, "ws.origin"), "a route that lists no origin admits no browser"

    def the_smuggling_corpus_of_upgrade_requests(gw, up):
        key = new_key()
        base = lambda **kw: request_bytes("/v16/CP1", key=key, **kw)[0]
        head = base()
        corpus = [
            # (a name, the bytes, the rule the refusal must carry: a prefix)
            ("upgrade with both framing headers", base(extra=["Content-Length: 4", "Transfer-Encoding: chunked"]) + b"0\r\n\r\n", "framing."),
            ("upgrade with two lengths", base(extra=["Content-Length: 4", "Content-Length: 5"]), "framing."),
            ("space before the colon", head.replace(b"Upgrade: websocket", b"Upgrade : websocket"), "framing."),
            ("obs-fold in the upgrade header", head.replace(b"Upgrade: websocket\r\n", b"Upgrade: websocket\r\n x\r\n"), "framing."),
            ("bare LF line ends", head.replace(b"\r\n", b"\n"), "framing."),
            ("absolute-form target", head.replace(b"GET /v16/CP1", b"GET http://csms.example/v16/CP1"), "framing."),
            ("a NUL in the key", head.replace(b"Sec-WebSocket-Key: ", b"Sec-WebSocket-Key: \x00"), "framing."),
            ("a tab before the colon", head.replace(b"Connection: Upgrade", b"Connection\t: Upgrade"), "framing."),
            ("chunked and an upgrade, body present", base(extra=["Transfer-Encoding: chunked"]) + b"5\r\nhello\r\n0\r\n\r\n", "ws.body"),
            ("a length of zero is still a body header", base(extra=["Content-Length: 0"]), "ws.body"),
            ("a Connection header naming Content-Length", base(connection="Upgrade, Content-Length", extra=["Content-Length: 0"]), "ws.upgrade"),
            ("a second request pipelined behind the upgrade", head + head, "ws.early-data"),
            ("a frame pipelined behind the upgrade", head + encode_frame(1, b"x"), "ws.early-data"),
            ("a header named by upper case still counts", head.replace(b"Upgrade: websocket", b"UPGRADE: websocket\r\nupgrade: websocket"), "ws.upgrade"),
            ("Upgrade list with a second protocol", head.replace(b"Upgrade: websocket", b"Upgrade: websocket, tls/1.2"), "ws.upgrade"),
            ("a key one character too long", head.replace(b"Sec-WebSocket-Key: " + key, b"Sec-WebSocket-Key: " + key + b"A"), "ws.key"),
            ("a Connection list that hides the Upgrade", head.replace(b"Connection: Upgrade", b"Connection: close\r\nConnection: Upgrade"), "ws.upgrade"),
        ]
        n0 = up.conns
        for name, raw, prefix in corpus:
            r = refused(raw_exchange(gw, raw))
            assert r[1] and r[1].startswith(prefix) and r[0] >= 400, "%s: got %r, wanted a refusal starting %r" % (name, r, prefix)
        assert up.conns == n0, "a hostile upgrade reached the upstream"
        assert gw.alive()

    # ----------------------------------------------------------- what the upstream may answer

    def the_upstreams_refusals_of_the_upgrade_each_have_their_tag(gw, up):
        cases = [("badaccept", "ws.upstream-accept"), ("noaccept", "ws.upstream-accept"), ("twoaccept", "ws.upstream-accept"),
                 ("noupgrade", "ws.upstream-upgrade"), ("noconn", "ws.upstream-upgrade"), ("cl", "ws.upstream-upgrade"), ("te", "ws.upstream-upgrade"),
                 ("badproto", "ws.upstream-subprotocol"), ("noproto", "ws.upstream-subprotocol"), ("ext", "ws.upstream-extensions")]
        for mode, tag in cases:
            raw, _ = request_bytes("/bad/" + mode)
            got = refused(raw_exchange(gw, raw))
            assert got == (502, tag), "%s: %s" % (mode, got)
        m = gw.metrics()["refusals"]
        for _, tag in cases:
            assert m.get(tag, 0) >= 1, tag

    def an_upstream_that_refuses_the_upgrade_is_relayed_as_it_answered(gw, up):
        raw, _ = request_bytes("/v16/401")
        response = raw_exchange(gw, raw)
        status, head, body = pt.split(response)
        assert status == 401 and body == b"nope!" and b"WWW-Authenticate: Basic" in head, response[:400]
        assert head.endswith(b"\r\nConnection: close") and b"Via: 1.1 cancho-gateway" in head, head

    def a_101_for_a_request_that_did_not_ask_for_an_upgrade_is_refused(gw, up):
        got = refused(raw_exchange(gw, b"GET /bad/plain101 HTTP/1.1\r\nHost: a\r\n\r\n"))
        assert got == (502, "response.status"), got
        got = refused(raw_exchange(gw, b"GET /plain101 HTTP/1.1\r\nHost: a\r\n\r\n"))
        assert got == (502, "response.status"), got

    def a_route_without_websocket_ignores_the_upgrade(gw, up):
        n = len(up.heads)
        raw, _ = request_bytes("/plain/x")
        status, head, body = pt.split(raw_exchange(gw, raw))
        assert status == 200 and body == b"ok", (status, body)
        h = pt.heads_of(up.heads[n])
        assert "upgrade" not in h and "connection" not in h and "sec-websocket-extensions" not in h, h

    def a_websocket_route_serves_an_ordinary_request_too(gw, up):
        n = len(up.heads)
        status, head, body = pt.split(raw_exchange(gw, b"GET /bare/status HTTP/1.1\r\nHost: a\r\n\r\n"))
        assert status == 200 and body == b"plain", (status, body)
        h = pt.heads_of(up.heads[n])
        assert "upgrade" not in h and "connection" not in h, h

    def a_tunnel_connection_is_never_pooled(gw, up):
        c0 = up.conns
        status, head, body = pt.split(raw_exchange(gw, b"GET /plain/ka HTTP/1.1\r\nHost: a\r\n\r\n"))
        assert status == 200 and body == b"ok"
        deadline = time.time() + 2
        while time.time() < deadline and gw.metrics()["upstreams"][0]["pool_idle"] != 1:
            time.sleep(0.05)
        assert gw.metrics()["upstreams"][0]["pool_idle"] == 1, "the keep-alive connection was not pooled"
        ws = connect_ws(gw, "/v16/CP030")
        assert up.conns == c0 + 2, "the upgrade must use a fresh connection, not the pooled one (%d new)" % (up.conns - c0)
        echo_roundtrip(ws)
        n = len(up.ended)
        ws.close()
        # a pooled connection would stay open for the idle time (0.5 s); a closed one is seen to end at once
        ended = up.wait_ended(n + 1, timeout=0.3)
        assert len(ended) > n and ended[n][1] == "eof", "the tunnel's upstream connection was not closed when it ended: %r" % (ended[n:],)
        settle_down(gw)

    def a_silent_tunnel_and_a_stuck_one_use_no_cpu(gw, up):
        quiet = [connect_ws(gw, "/v16/silent") for _ in range(10)]
        reader = connect_ws(gw, "/v16/bigdown", rcvbuf=4096)   # its 8 MiB cannot be delivered: the client is not reading
        time.sleep(1.5)
        c0, t0 = gw.cpu(), time.time()
        time.sleep(1.0)
        used = gw.cpu() - c0
        assert used < 0.05, "%.3fs of CPU in 1s with 11 tunnels at rest" % used
        for w in quiet + [reader]:
            w.close()
        settle_down(gw)


class Timers:
    """On the gateway with an idle time of 1 s, a lifetime of 4 s, three tunnels at most, and the circuit on (3 failures, open for 1 s)."""

    def an_idle_tunnel_is_closed_at_the_idle_time(gw, up):
        n0 = len(gw.lines())
        ws = connect_ws(gw, "/v16/silent")
        took = ws.eof(6)
        assert 0.8 < took < 2.6, "closed after %.2fs" % took
        e = gw.find(n0, path="/v16/silent")
        assert e["rule"] == "ws.idle-timeout" and e["outcome"] == "aborted" and e["status"] == 101 and e["upgrade"] == "websocket", e
        assert gw.metrics()["refusals"].get("ws.idle-timeout", 0) >= 1
        ws.close()

    def traffic_keeps_a_tunnel_open_past_the_idle_time(gw, up):
        n0 = len(gw.lines())
        ws = connect_ws(gw, "/v16/CP040")
        t0 = time.time()
        while time.time() - t0 < 2.4:        # more than two idle times, a ping every 0.4 s
            ws.send(9, b"k")
            ws.expect(10, b"k")
            time.sleep(0.4)
        ws.text("still here")
        ws.expect(1, b"still here")
        took = ws.eof(6)
        assert 0.8 < took < 2.6, took
        e = gw.find(n0, path="/v16/CP040")
        assert e["rule"] == "ws.idle-timeout", e
        ws.close()

    def a_busy_tunnel_is_closed_at_the_lifetime(gw, up):
        n0 = len(gw.lines())
        ws = connect_ws(gw, "/v16/CP041")
        t0 = time.time()
        try:
            while time.time() - t0 < 8:
                ws.send(9, b"k")
                ws.expect(10, b"k")
                time.sleep(0.3)
        except (EOFError, OSError):
            pass
        took = time.time() - t0
        assert 3.7 < took < 5.0, "closed after %.2fs" % took
        e = gw.find(n0, path="/v16/CP041")
        assert e["rule"] == "ws.lifetime" and e["outcome"] == "aborted" and e["ms"] >= 3900, e
        ws.close()

    def the_limit_refuses_the_fourth_and_frees_with_a_close(gw, up):
        wss = [connect_ws(gw, "/v16/CP05%d" % i) for i in range(3)]
        raw, _ = request_bytes("/v16/CP054")
        assert refused(raw_exchange(gw, raw)) == (503, "ws.limit")
        wss[0].close()
        gw.wait_active(2)
        again = connect_ws(gw, "/v16/CP055")
        echo_roundtrip(again)
        for w in wss[1:] + [again]:
            w.close()
        settle_down(gw)
        # a refused upgrade did not hold a place
        wss = [connect_ws(gw, "/v16/CP06%d" % i) for i in range(3)]
        for w in wss:
            w.close()
        settle_down(gw)

    def an_upgrade_refused_by_the_upstream_holds_no_place(gw, up):
        for _ in range(2):
            raw, _ = request_bytes("/bad/badaccept")
            assert refused(raw_exchange(gw, raw))[0] == 502
        wss = [connect_ws(gw, "/v16/CP07%d" % i) for i in range(3)]
        for w in wss:
            w.close()
        settle_down(gw)
        time.sleep(1.2)

    def the_circuit_counts_a_bad_101_and_closes_on_a_good_one(gw, up):
        time.sleep(1.2)      # whatever the earlier tests left open has run out
        for i in range(3):
            raw, _ = request_bytes("/circ/badaccept")
            assert refused(raw_exchange(gw, raw)) == (502, "ws.upstream-accept"), i
        raw, _ = request_bytes("/circ/CP1")
        assert refused(raw_exchange(gw, raw)) == (503, "proxy.circuit-open")
        # a request the gateway refuses itself before dialling does not use the half-open trial
        time.sleep(1.2)
        bad, _ = request_bytes("/circ/CP1", version="8")
        assert refused(raw_exchange(gw, bad)) == (426, "ws.version")
        ws = connect_ws(gw, "/circ/CP2")
        echo_roundtrip(ws)
        ws.close()
        ws = connect_ws(gw, "/circ/CP3")
        ws.close()
        settle_down(gw)


class Wss:
    """On the gateway with `tls_listen`: the same routes over TLS (idle 1.5 s, lifetime 4 s)."""

    def a_wss_handshake_and_every_frame_type(gw, up):
        n0 = len(gw.lines())
        ws = connect_ws(gw, "/v16/CP100", tls=True, host="api.example")
        assert ws.protocol == "ocpp1.6"
        echo_roundtrip(ws)
        ws.send(9, b"ping")
        ws.expect(10, b"ping")
        for n in (0, 126, 65536):
            p = os.urandom(n)
            ws.send(2, p)
            ws.expect(2, p)
        ws.send(8, struct.pack(">H", 1000))
        ws.expect(8)
        ws.eof()
        e = gw.find(n0, path="/v16/CP100")
        assert e["tls"] is True and e["upgrade"] == "websocket" and e["status"] == 101 and e["outcome"] == "ok", e
        assert list(e)[-2:] == ["tls", "upgrade"], list(e)
        assert e["bytes_in"] == ws.sent
        ws.close()

    def the_upstream_sees_the_scheme_as_https(gw, up):
        n = len(up.heads)
        ws = connect_ws(gw, "/v16/CP101", tls=True, host="api.example")
        ws.close()
        assert "X-Forwarded-Proto: https" in up.heads[n].decode(), up.heads[n]

    def one_mebibyte_each_way_over_tls(gw, up):
        ws = connect_ws(gw, "/v16/CP102", tls=True, host="api.example", timeout=30)
        p = os.urandom(1 << 20)
        ws.send(2, p)
        ws.expect(2, p)
        ws.close()

    def eight_mebibytes_to_a_late_reader_over_tls(gw, up):
        ws = connect_ws(gw, "/v16/bigdown", tls=True, host="api.example", timeout=60)
        time.sleep(1.5)
        got = ws.expect(2)
        assert got == big_payload(8 << 20), len(got)
        ws.close()

    def refusals_over_tls(gw, up):
        n0 = up.conns
        for tag, status, kw in (("ws.key", 400, dict(key=b"x" * 24)), ("ws.origin", 403, dict(origin="https://evil.example")),
                                ("ws.subprotocol", 400, dict(protocols=("mqtt",))), ("ws.version", 426, dict(version="12"))):
            raw, _ = request_bytes("/v16/CP1", **kw)
            assert refused(raw_exchange(gw, raw, tls=True)) == (status, tag), tag
        raw, key = request_bytes("/v16/CP1")
        assert refused(raw_exchange(gw, raw + encode_frame(1, b"x"), tls=True)) == (400, "ws.early-data")
        assert up.conns == n0

    def an_idle_wss_tunnel_is_closed_and_a_busy_one_at_the_lifetime(gw, up):
        n0 = len(gw.lines())
        ws = connect_ws(gw, "/v16/silent", tls=True, host="api.example")
        took = ws.eof(8)
        assert 1.2 < took < 3.5, took
        e = gw.find(n0, path="/v16/silent")
        assert e["rule"] == "ws.idle-timeout" and e["tls"] is True, e
        n1 = len(gw.lines())
        ws = connect_ws(gw, "/v16/CP103", tls=True, host="api.example")
        t0 = time.time()
        try:
            while time.time() - t0 < 8:
                ws.send(9, b"k")
                ws.expect(10, b"k")
                time.sleep(0.4)
        except (EOFError, OSError):
            pass
        took = time.time() - t0
        assert 3.5 < took < 5.5, took
        e = gw.find(n1, path="/v16/CP103")
        assert e["rule"] == "ws.lifetime" and e["tls"] is True, e

    def a_wss_client_that_vanishes_leaves_nothing_behind(gw, up):
        ws = connect_ws(gw, "/v16/CP104", tls=True, host="api.example")
        echo_roundtrip(ws)
        os.close(ws.sock.detach())      # no close_notify
        settle_down(gw)


# ---------------------------------------------------------------------------------------------------------------------- the runner


def main():
    groups = {"Main": Main, "Timers": Timers, "Wss": Wss}
    wanted = sys.argv[1:]
    todo = []
    for gname, cls in groups.items():
        for name in vars(cls):
            if name.startswith("_"):
                continue
            if not wanted or name in wanted:
                todo.append((gname, cls, name))
    unknown = [w for w in wanted if not any(w == t[2] for t in todo)]
    if unknown:
        print("no such test: %s" % ", ".join(unknown))
        return 2
    failures = 0
    with tempfile.TemporaryDirectory() as t1, tempfile.TemporaryDirectory() as t2, tempfile.TemporaryDirectory() as t3:
        up = WsUpstream(pt.free_port())
        needed = {g for g, _, _ in todo}
        gws = {}
        try:
            if "Main" in needed:
                gws["Main"] = Gateway(t1, up.port)
            if "Timers" in needed:
                gws["Timers"] = Gateway(t2, up.port, idle=1000, lifetime=4000, max_tunnels=3, circuit=3)
            if "Wss" in needed:
                gws["Wss"] = Gateway(t3, up.port, idle=1500, lifetime=4000, max_tunnels=100, tls=True)
            for gname, cls, name in todo:
                gw = gws[gname]
                t0 = time.time()
                try:
                    getattr(cls, name)(gw, up)
                    if not gw.alive():
                        raise AssertionError("the gateway died")
                    print("ok    %-70s %.1fs" % (name, time.time() - t0))
                except (AssertionError, OSError, EOFError, KeyError, IndexError) as e:
                    failures += 1
                    print("FAIL  %-70s %s: %s" % (name, type(e).__name__, e))
                    if not gw.alive():
                        print("      the gateway died: exit %s %s" % (gw.proc.returncode, gw.proc.stderr.read()[:300]))
                        break
        finally:
            for gw in gws.values():
                gw.stop()
            up.shutdown()
    print("%d tests, %d failures" % (len(todo), failures))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
