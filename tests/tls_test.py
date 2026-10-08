#!/usr/bin/env python3
"""TLS end to end (docs/tls.md section 8, gates 1, 3, 4 and 5): a gateway built with `tls_listen`, certificates made here, clients that are
Python's `ssl`, `openssl s_client` and curl, and peers that are not clients at all.

    python3 tests/tls_test.py [test_name ...]

Needs the `openssl` command to make the (P-256) certificates, and `build/deps` filled by one `cancho build`. The upstream is the recording
upstream of tests/proxy_test.py.
"""

import hashlib
import json
import os
import pathlib
import re
import shutil
import signal
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import admin_test as ad  # noqa: E402
import proxy_test as pt  # noqa: E402

ROOT = pt.ROOT
LEX = pt.LEX
SOURCES = pt.SOURCES
HANDSHAKES = 4
HANDSHAKE_MS = 1500
RATE = 50


def make_identity(directory, name, host):
    d = pathlib.Path(directory) / name
    d.mkdir(parents=True)
    subprocess.run("openssl ecparam -name prime256v1 -genkey -noout | openssl pkcs8 -topk8 -nocrypt -out %s" % (d / "key.pem"), shell=True, check=True,
                   capture_output=True)
    subprocess.run(["openssl", "req", "-new", "-x509", "-key", str(d / "key.pem"), "-out", str(d / "chain.pem"), "-days", "30", "-subj", "/CN=" + host,
                    "-addext", "subjectAltName=DNS:" + host], check=True, capture_output=True)
    (d / "names").write_text(host + "\n")
    return d / "chain.pem"


class Gateway:
    def __init__(self, tmp, up_port, plain=True):
        self.tmp = pathlib.Path(tmp)
        self.certs = pathlib.Path(tmp) / "certs"
        self.chain_api = make_identity(self.certs, "api", "api.example")
        self.chain_second = make_identity(self.certs, "second", "second.example")
        self.port, self.tls_port, self.admin = (pt.free_port() if plain else None), pt.free_port(), pt.free_port()
        deploy = pathlib.Path(tmp) / "deploy.toml"
        deploy.write_text("""%stls_listen = %d
admin_listen = %d
tls_dir = "%s"
tls_identities = ["api", "second"]
tls_handshakes = %d
tls_handshake_ms = %d
tls_rate = %d
header_timeout_ms = 1000
connect_timeout_ms = 1000
upstream_timeout_ms = 1500
total_timeout_ms = 4000
idle_timeout_ms = 500

[[upstream]]
name = "up"
addr = "127.0.0.1:%d"

[[route]]
name = "main"
path_prefix = "/"
upstream = "up"
max_body = 16777216
""" % ("listen = %d\n" % self.port if plain else "", self.tls_port, self.admin, self.certs, HANDSHAKES, HANDSHAKE_MS, RATE, up_port))
        out = pathlib.Path(tmp) / "gen"
        subprocess.run([sys.executable, str(ROOT / "scripts" / "generate.py"), str(deploy), "--out", str(out)], check=True)
        files = [str(out / n) for n in ("deploy.cho", "routes.cho", "tlsfiles.cho")] + pt.dependencies() + [str(ROOT / "src" / (n + ".cho")) for n in SOURCES]
        built = subprocess.run([LEX, "build", "--std", *files, "-o", str(pathlib.Path(tmp) / "gateway")], capture_output=True, text=True)
        if built.returncode != 0:
            raise SystemExit("build failed: " + built.stderr[:600])
        self.log = []
        self.err = []
        self.lock = threading.Lock()
        self.start()

    def start(self):
        """Run the built binary (again, after a stop: the ports are compiled in, so a restart serves the same ones)."""
        self.proc = subprocess.Popen([str(self.tmp / "gateway")], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        threading.Thread(target=self.read_log, args=(self.proc.stdout, self.log), daemon=True).start()
        threading.Thread(target=self.read_log, args=(self.proc.stderr, self.err), daemon=True).start()
        for _ in range(100):
            try:
                socket.create_connection(("127.0.0.1", self.tls_port), timeout=0.2).close()
                break
            except OSError:
                time.sleep(0.05)
        else:
            raise SystemExit("gateway did not start: %s" % b"".join(self.err)[:300])
        time.sleep(0.3)

    def read_log(self, stream, into):
        for raw in stream:
            with self.lock:
                into.append(raw)

    def errors(self, n=0):
        """The lines the gateway wrote to standard error after the first `n` (a reload's report goes there, never to the access log)."""
        with self.lock:
            return [raw.decode(errors="replace").rstrip("\n") for raw in self.err[n:]]

    def err_find(self, n, text, wait=4):
        end = time.time() + wait
        while True:
            for l in self.errors(n):
                if text in l:
                    return l
            if time.time() > end:
                raise AssertionError("no stderr line with %r among %r" % (text, self.errors(n)))
            time.sleep(0.05)

    def hup(self):
        os.kill(self.proc.pid, signal.SIGHUP)

    def reloaded(self, ok, failed, before, wait=4):
        """Wait until the reload counters have moved by exactly `ok` and `failed` since `before` (the `tls` object of an earlier scrape)."""
        end = time.time() + wait
        while True:
            t = self.metrics()["tls"]
            if t["reloads"] - before["reloads"] >= ok and t["reload_failures"] - before["reload_failures"] >= failed:
                assert (t["reloads"] - before["reloads"], t["reload_failures"] - before["reload_failures"]) == (ok, failed), (before, t)
                return t
            if time.time() > end:
                raise AssertionError("reload counters %r after %r, wanted +%d ok +%d failed" % (t, before, ok, failed))
            time.sleep(0.05)

    def lines(self):
        with self.lock:
            out = []
            for raw in self.log:
                try:
                    out.append(json.loads(raw))
                except ValueError:
                    pass
            return out

    def since(self, n, want=1, wait=4):
        end = time.time() + wait
        while time.time() < end:
            got = self.lines()[n:]
            if len(got) >= want:
                return got
            time.sleep(0.05)
        return self.lines()[n:]

    def find(self, n, wait=4, **want):
        """The first line after the first `n` whose keys have these values (`None`: the key is absent). Sessions of an earlier test can still be
        ending, so the last line is not necessarily this test's."""
        end = time.time() + wait
        while True:
            for l in self.lines()[n:]:
                if all((k not in l) if v is None else l.get(k) == v for k, v in want.items()):
                    return l
            if time.time() > end:
                raise AssertionError("no log line like %r among %r" % (want, self.lines()[n:][-3:]))
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

    def rss_kib(self):
        for line in open("/proc/%d/status" % self.proc.pid):
            if line.startswith("VmRSS:"):
                return int(line.split()[1])
        return 0

    def alive(self):
        return self.proc.poll() is None

    def stop(self, sig=signal.SIGTERM):
        """Ask it to stop as an operator would; answers its exit status (0: stopped cleanly by the signal; `None`: it had to be killed)."""
        if self.proc.poll() is None:
            self.proc.send_signal(sig)
        try:
            return self.proc.wait(3)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait()
            return None


def context(gw, cafile=None, alpn=("http/1.1",)):
    c = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    c.minimum_version = ssl.TLSVersion.TLSv1_3
    c.load_verify_locations(str(cafile or gw.chain_api))
    if alpn:
        c.set_alpn_protocols(list(alpn))
    return c


def connect(gw, host="api.example", cafile=None, alpn=("http/1.1",), timeout=8):
    raw = socket.create_connection(("127.0.0.1", gw.tls_port), timeout=timeout)
    return context(gw, cafile, alpn).wrap_socket(raw, server_hostname=host)


def read_response(s):
    data = b""
    while b"\r\n\r\n" not in data:
        d = s.recv(65536)
        if not d:
            return data, b""
        data += d
    head, _, rest = data.partition(b"\r\n\r\n")
    body = bytearray(rest)  # appended to in place: a bytes object copied at every record would make the client the slow end
    length = None
    for line in head.split(b"\r\n")[1:]:
        k, _, v = line.partition(b":")
        if k.strip().lower() == b"content-length":
            length = int(v)
    while length is not None and len(body) < length:
        d = s.recv(1 << 20)
        if not d:
            break
        body += d
    return head, bytes(body)


def honest_client_hello():
    """The first write of the vectors' case `honest: P-256 share only, AES-128-GCM`: a ClientHello any server can answer."""
    for line in open(ROOT / "tests" / "vectors" / "tls" / "client_bytes.txt"):
        if line.startswith("ok honest: P-256 share only, AES-128-GCM\t"):
            return bytes.fromhex(line.rstrip("\n").partition("\t")[2].split(",")[0])
    raise AssertionError("the vector is not in client_bytes.txt")


def get(gw, path="/", host="api.example", **kw):
    s = connect(gw, host, **kw)
    s.sendall(b"GET %s HTTP/1.1\r\nHost: %s\r\n\r\n" % (path.encode(), host.encode()))
    head, body = read_response(s)
    s.close()
    return head, body


class T:
    def get_over_tls_reaches_the_upstream_as_https(gw, up):
        n0, h0, m0 = len(gw.lines()), len(up.heads), gw.metrics()["tls"]["handshakes"]
        head, body = get(gw)
        assert head.startswith(b"HTTP/1.1 200") and body == b"ok", (head, body)
        assert gw.metrics()["tls"]["handshakes"] == m0 + 1, "the handshake was not counted"
        e = gw.find(n0, path="/", status=200, tls=True)
        assert e["tls"] is True and e["status"] == 200 and e["outcome"] == "ok", e
        sent = up.heads[h0].decode()
        assert "X-Forwarded-Proto: https" in sent and "X-Forwarded-Proto: http\r" not in sent, sent

    def plain_listener_is_unchanged_beside_it(gw, up):
        n0, h0 = len(gw.lines()), len(up.heads)
        s = socket.create_connection(("127.0.0.1", gw.port), timeout=5)
        s.sendall(b"GET / HTTP/1.1\r\nHost: a\r\n\r\n")
        head, body = read_response(s)
        s.close()
        assert head.startswith(b"HTTP/1.1 200") and body == b"ok"
        e = gw.find(n0, path="/", status=200, tls=None)
        assert "tls" not in e, e
        assert "X-Forwarded-Proto: http\r" in up.heads[h0].decode()

    def post_3mb_and_6mb_response_byte_for_byte(gw, up):
        body = os.urandom(3 << 20)
        s = connect(gw, timeout=20)
        s.sendall(b"POST /echo HTTP/1.1\r\nHost: api.example\r\nContent-Length: %d\r\n\r\n" % len(body) + body)
        head, got = read_response(s)
        s.close()
        assert head.startswith(b"HTTP/1.1 200") and hashlib.sha256(got).digest() == hashlib.sha256(body).digest() and len(got) == len(body), (head, len(got))
        n = 6 << 20
        s = connect(gw, timeout=20)
        s.sendall(b"GET /big?n=%d HTTP/1.1\r\nHost: api.example\r\n\r\n" % n)
        head, got = read_response(s)
        s.close()
        want = (bytes(range(256)) * 256 * (n // 65536 + 1))[:n]
        assert head.startswith(b"HTTP/1.1 200") and got == want, (head, len(got))

    def a_hundred_requests_each_on_its_own_connection(gw, up):
        n0 = len(gw.lines())
        for i in range(100):
            head, body = get(gw, "/?i=%d" % i)
            assert body == b"ok", (i, head)
        got = gw.since(n0, 100, wait=8)
        assert len(got) >= 100 and all(l.get("tls") is True for l in got[:100]), len(got)

    def sni_selects_the_identity_and_an_unknown_name_gets_the_default(gw, up):
        for host, chain in (("second.example", gw.chain_second), ("api.example", gw.chain_api)):
            s = connect(gw, host, cafile=chain)
            der = s.getpeercert(binary_form=True)
            s.close()
            want = ssl.PEM_cert_to_DER_cert(pathlib.Path(chain).read_text())
            assert der == want, host
        raw = socket.create_connection(("127.0.0.1", gw.tls_port), timeout=5)
        c = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        c.check_hostname = False
        c.verify_mode = ssl.CERT_NONE
        s = c.wrap_socket(raw, server_hostname="nobody.example")
        der = s.getpeercert(binary_form=True)
        s.close()
        assert der == ssl.PEM_cert_to_DER_cert(pathlib.Path(gw.chain_api).read_text()), "the default is the first identity"

    def alpn_http11_is_accepted_and_h2_alone_is_refused(gw, up):
        s = connect(gw, alpn=("h2", "http/1.1"))
        assert s.selected_alpn_protocol() == "http/1.1"
        s.close()
        try:
            connect(gw, alpn=("h2",)).close()
        except (ssl.SSLError, OSError):
            return
        raise AssertionError("h2 alone must be refused")

    def openssl_s_client_and_curl_interoperate(gw, up):
        if shutil.which("openssl"):
            out = subprocess.run(["openssl", "s_client", "-connect", "127.0.0.1:%d" % gw.tls_port, "-servername", "api.example", "-CAfile", str(gw.chain_api),
                                  "-verify_hostname", "api.example", "-alpn", "http/1.1", "-tls1_3", "-quiet"],
                                 input=b"GET / HTTP/1.1\r\nHost: api.example\r\nConnection: close\r\n\r\n", capture_output=True, timeout=15).stdout
            assert out.startswith(b"HTTP/1.1 200") and out.endswith(b"ok"), out
        if shutil.which("curl"):
            out = subprocess.run(["curl", "-sS", "--noproxy", "*", "--cacert", str(gw.chain_api), "--resolve", "api.example:%d:127.0.0.1" % gw.tls_port,
                                  "https://api.example:%d/" % gw.tls_port], capture_output=True, timeout=15)
            assert out.stdout == b"ok", out

    def a_client_that_closes_without_close_notify_mid_body_is_an_aborted_request(gw, up):
        n0 = len(gw.lines())
        s = connect(gw)
        s.sendall(b"POST /echo HTTP/1.1\r\nHost: api.example\r\nContent-Length: 100000\r\n\r\n" + b"x" * 4000)
        time.sleep(0.2)
        os.close(s.detach())  # the TCP connection ends with no close_notify
        e = gw.find(n0, outcome="aborted", tls=True)
        assert e["outcome"] == "aborted" and e["tls"] is True, e

    def silent_peers_delay_an_honest_one_and_are_dropped_at_the_handshake_deadline(gw, up):
        timed_out = gw.metrics()["refusals"].get("tls.handshake-timeout", 0)
        silent = [socket.create_connection(("127.0.0.1", gw.tls_port), timeout=10) for _ in range(HANDSHAKES)]
        time.sleep(0.2)
        t0 = time.time()
        head, body = get(gw)
        waited = time.time() - t0
        assert body == b"ok", head
        assert waited > HANDSHAKE_MS / 1000.0 * 0.5, "the honest peer was served at once: the bound did not hold (%.2fs)" % waited
        assert waited < HANDSHAKE_MS / 1000.0 + 3, waited
        counted = gw.metrics()["refusals"].get("tls.handshake-timeout", 0) - timed_out
        assert counted == HANDSHAKES, "the %d silent peers dropped at the deadline were counted %d times" % (HANDSHAKES, counted)
        for s in silent:
            s.settimeout(3)
            try:
                assert s.recv(10) == b"", "a silent peer is dropped without a word"
            except OSError:
                pass
            s.close()

    def a_burst_of_handshakes_is_held_to_tls_rate_and_every_one_is_served(gw, up):
        # The honest ClientHello of cancho's vectors is all the client needs to send for the server to start (and pay for) a handshake, so the
        # clients cost nothing and the rate is the server's. `tls_rate` is 50 a second, in windows of a second: 250 handshakes take five windows.
        hello = honest_client_hello()
        started, errors = [], []
        lock = threading.Lock()
        todo = list(range(250))

        def worker():
            while True:
                with lock:
                    if not todo:
                        return
                    todo.pop()
                try:
                    s = socket.create_connection(("127.0.0.1", gw.tls_port), timeout=20)
                    s.sendall(hello)
                    first = s.recv(5)
                    s.close()
                    with lock:
                        (started if first[:3] == b"\x16\x03\x03" else errors).append(time.time())
                except OSError as e:
                    with lock:
                        errors.append(str(e))

        t0 = time.time()
        threads = [threading.Thread(target=worker) for _ in range(110)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(60)
        elapsed = time.time() - t0
        # 110 at once: the last waits 2.2 s for its turn, longer than tls_handshake_ms (1.5 s), and must not be dropped for it.
        assert len(started) == 250 and not errors, (len(started), errors[:3])
        assert elapsed >= 3.0, "250 handshakes in %.2fs: tls_rate did not hold" % elapsed
        assert elapsed < 12, elapsed

    def a_session_waits_for_the_ciphertext_still_queued_when_the_relay_is_done(gw, up):
        # A client that does not read lets the kernel's buffers fill (X bytes, whatever the kernel made them) and then the gateway's own queues. A
        # response of up to X bytes is all in the kernel and the session ends at once; a longer one cannot end until the client reads. Find the
        # largest size that ends without a read, then read it: a gateway that ended a session while ciphertext was still queued would have lost
        # those bytes, and the body would be short.
        def probe(n):
            n0 = len(gw.lines())
            s = connect(gw, timeout=20)
            s.sendall(b"GET /big?n=%d HTTP/1.1\r\nHost: api.example\r\n\r\n" % n)
            time.sleep(0.35)
            ended = len(gw.lines()) > n0
            head, body = read_response(s)
            s.close()
            want = (bytes(range(256)) * 256 * (n // 65536 + 1))[:n]
            return ended, head.startswith(b"HTTP/1.1 200") and body == want

        lo, hi = 0, 65536
        while True:
            ended, whole = probe(hi)
            assert whole, "a response of %d bytes arrived short" % hi
            if not ended:
                break
            lo, hi = hi, hi * 2
            assert hi <= 64 << 20, "the kernel buffered 32 MB?"
        while hi - lo > 16384:
            mid = (lo + hi) // 2
            ended, whole = probe(mid)
            assert whole, "a response of %d bytes arrived short" % mid
            if ended:
                lo = mid
            else:
                hi = mid

    def a_slow_handshake_is_not_held_to_the_header_deadline(gw, up):
        # Half a ClientHello, a pause longer than header_timeout_ms (1000) and shorter than tls_handshake_ms (1500), then the rest: the clock that
        # applies until the handshake is done is the handshake's.
        hello = honest_client_hello()
        s = socket.create_connection(("127.0.0.1", gw.tls_port), timeout=5)
        s.sendall(hello[:20])
        time.sleep(1.25)
        s.sendall(hello[20:])
        s.settimeout(3)
        assert s.recv(5)[:3] == b"\x16\x03\x03", "the handshake was cut by the header deadline"
        s.close()

    def a_client_that_stops_reading_is_ended_at_its_deadline(gw, up):
        n0 = len(gw.lines())
        rss0 = gw.rss_kib()
        s = connect(gw)
        s.sendall(b"GET /big?n=50000000 HTTP/1.1\r\nHost: api.example\r\n\r\n")
        time.sleep(5.5)
        e = gw.find(n0, outcome="aborted")
        assert e["outcome"] == "aborted", e
        s.close()
        grown = gw.rss_kib() - rss0
        assert grown < 4096, "the gateway grew by %d KiB serving a client that did not read (the slot's buffers are 100 KiB)" % grown
        assert get(gw)[1] == b"ok"

    def garbage_and_old_versions_are_refused_and_nothing_leaks(gw, up):
        junk = [b"GET / HTTP/1.1\r\n\r\n", b"\x16\x03\x01\x00\x05hello", b"\x16\x03\x03\xff\xff" + os.urandom(100), os.urandom(5000), b"\x00" * 100]
        for i in range(300):
            s = socket.create_connection(("127.0.0.1", gw.tls_port), timeout=5)
            try:
                s.sendall(junk[i % len(junk)])
                s.settimeout(2)
                s.recv(4096)
            except OSError:
                pass
            s.close()
        # TLS 1.2 only: refused.
        raw = socket.create_connection(("127.0.0.1", gw.tls_port), timeout=5)
        c = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        c.check_hostname = False
        c.verify_mode = ssl.CERT_NONE
        c.maximum_version = ssl.TLSVersion.TLSv1_2
        try:
            c.wrap_socket(raw, server_hostname="api.example")
            raise AssertionError("TLS 1.2 must be refused")
        except (ssl.SSLError, OSError):
            pass
        time.sleep(0.5)
        assert gw.alive()
        for _ in range(5):
            assert get(gw)[1] == b"ok"
        # No slot leaked: 300 refused connections did not leave the table full (256 slots).
        for _ in range(20):
            assert get(gw)[1] == b"ok"

    def cancho_liar_client_vectors_leave_the_gateway_up_and_every_refusal_is_a_tag(gw, up):
        cases = []
        for line in open(ROOT / "tests" / "vectors" / "tls" / "client_bytes.txt"):
            if not line.startswith("#"):
                name, _, feeds = line.rstrip("\n").partition("\t")
                cases.append((name, [bytes.fromhex(f) for f in feeds.split(",")]))
        assert len(cases) >= 90, len(cases)
        before = gw.metrics()
        for name, feeds in cases:
            s = socket.create_connection(("127.0.0.1", gw.tls_port), timeout=5)
            try:
                for f in feeds:
                    s.sendall(f)
                    s.settimeout(0.05)
                    try:
                        s.recv(65536)
                    except OSError:
                        pass
            except OSError:
                pass
            s.close()
        time.sleep(1.0)
        assert gw.alive()
        after = gw.metrics()
        assert after["tls"]["failures"] > before["tls"]["failures"], after["tls"]
        tags = {k: v for k, v in after["refusals"].items() if k.startswith("tls")}
        assert tags and all(k.startswith("tls-") or k.startswith("tls.") for k in tags), tags
        assert any(k.startswith("tls-server-") for k in tags), tags
        assert get(gw)[1] == b"ok"
        # No slot leaks: the gauge of sessions in the table is back to the honest one.
        time.sleep(0.5)
        assert gw.metrics()["sessions_active"] <= 1, gw.metrics()["sessions_active"]

    def the_smuggling_corpus_gets_the_same_verdict_over_tls_as_in_the_clear(gw, up):
        sys.path.insert(0, str(ROOT / "tests" / "smuggling"))
        from corpus import CASES
        from chunked_corpus import CASES as CHUNKED

        def verdict(sock, raw):
            try:
                sock.sendall(raw)
            except OSError:
                return "closed"
            sock.settimeout(0.7)
            got = b""
            try:
                while True:
                    d = sock.recv(65536)
                    if not d:
                        break
                    got += d
                    if b"\r\n\r\n" in got and len(got) > 20 and b"HTTP/1.1 200" not in got[:12]:
                        break
                    if got.startswith(b"HTTP/1.1 200") and got.endswith(b"ok"):
                        break
            except (TimeoutError, socket.timeout):
                return "waiting" if not got else got.split(b"\r\n")[0].decode("latin-1")
            except (OSError, ssl.SSLError):
                return "closed" if not got else got.split(b"\r\n")[0].decode("latin-1")
            return got.split(b"\r\n")[0].decode("latin-1") if got else "closed"

        def both(raw):
            plain = socket.create_connection(("127.0.0.1", gw.port), timeout=5)
            a = verdict(plain, raw)
            plain.close()
            secure = connect(gw)
            b = verdict(secure, raw)
            try:
                secure.close()
            except OSError:
                pass
            return a, b

        n = 0
        for cid, request, headers, must, status, source in CASES:
            a, b = both(request)
            assert a == b, "%s: plain %r, tls %r" % (cid, a, b)
            n += 1
        for case in CHUNKED:
            cid, body = case[0], case[1]
            a, b = both(b"POST /echo HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n" + body)
            assert a == b, "%s: plain %r, tls %r" % (cid, a, b)
            n += 1
        assert n == len(CASES) + len(CHUNKED) and n >= 99, n

    def a_client_that_handshakes_and_sends_nothing_gets_408_at_the_header_deadline(gw, up):
        # header_timeout_ms is 1000 and tls_handshake_ms 1500: the clock that applies after the handshake is the header's.
        n0 = len(gw.lines())
        s = connect(gw)
        t0 = time.time()
        head, body = read_response(s)
        waited = time.time() - t0
        s.close()
        assert head.startswith(b"HTTP/1.1 408"), head
        assert 0.7 < waited < 1.4, waited
        e = gw.find(n0, rule="timeout.header", tls=True)
        assert e["status"] == 408 and e["rule"] == "timeout.header" and e["tls"] is True, e

    def the_server_closes_with_close_notify(gw, up):
        raw = socket.create_connection(("127.0.0.1", gw.tls_port), timeout=8)
        c = context(gw)
        s = c.wrap_socket(raw, server_hostname="api.example", suppress_ragged_eofs=False)
        s.sendall(b"GET / HTTP/1.1\r\nHost: api.example\r\n\r\n")
        data = b""
        while True:
            d = s.recv(65536)  # SSLEOFError here if the TCP connection ended without close_notify
            if not d:
                break
            data += d
        assert data.endswith(b"ok"), data
        s.close()

    # ---- reload and stop (docs/tls.md section 11) ----

    def sighup_replaces_the_certificate_new_connections_get_it_and_an_open_one_keeps_working(gw, up):
        old = gw.chain_api.read_text()
        old_der = ssl.PEM_cert_to_DER_cert(old)
        held = connect(gw)  # established before the reload, request not yet sent
        assert held.getpeercert(binary_form=True) == old_der
        before, n_err = gw.metrics()["tls"], len(gw.errors())
        (gw.certs / "old.pem").write_text(old)
        new_chain = renew(gw, "api", "api.example")
        assert new_chain != old
        gw.hup()
        gw.reloaded(2, 0, before)  # both identities are read again; the unchanged one is replaced by itself
        assert gw.err_find(n_err, "gateway: tls reload api ok") and gw.err_find(n_err, "gateway: tls reload second ok")
        # A new connection is sent the new certificate (and it verifies against the new chain, not the old one).
        s = connect(gw, cafile=gw.chain_api)
        assert s.getpeercert(binary_form=True) == ssl.PEM_cert_to_DER_cert(new_chain) != old_der
        s.close()
        try:
            connect(gw, cafile=gw.certs / "old.pem").close()
            raise AssertionError("the old chain still verifies the server")
        except ssl.SSLCertVerificationError:
            pass
        # The connection that was open keeps working, with the certificate it was sent.
        assert held.getpeercert(binary_form=True) == old_der
        held.sendall(b"GET / HTTP/1.1\r\nHost: api.example\r\n\r\n")
        head, body = read_response(held)
        held.close()
        assert head.startswith(b"HTTP/1.1 200") and body == b"ok", (head, body)

    def a_refused_or_unreadable_replacement_leaves_the_old_identity_serving_and_is_counted(gw, up):
        serving = ssl.PEM_cert_to_DER_cert(gw.chain_api.read_text())
        key, chain = gw.certs / "api" / "key.pem", gw.chain_api
        good_key, good_chain = key.read_text(), chain.read_text()
        trusted = gw.certs / "serving.pem"  # the client's copy: the chain file itself is about to be damaged
        trusted.write_text(good_chain)

        def serves_the_same():
            s = connect(gw, cafile=trusted)
            try:
                assert s.getpeercert(binary_form=True) == serving
            finally:
                s.close()

        def attempt(label, expect, ok=1, failed=1):
            before, n_err = gw.metrics()["tls"], len(gw.errors())
            gw.hup()
            gw.reloaded(ok, failed, before)
            line = gw.err_find(n_err, "gateway: tls reload api ")
            assert expect in line, (label, line)
            assert gw.err_find(n_err, "gateway: tls reload second ok")
            serves_the_same()
            return line

        try:
            # 1. a key that is not a key
            key.write_text("-----BEGIN PRIVATE KEY-----\nnot a key\n-----END PRIVATE KEY-----\n")
            attempt("garbage key", " refused tls-server-")
            # 2. a key that is not this certificate's (the pair the engine refuses mid-renewal)
            other = pathlib.Path(gw.certs) / "second"
            key.write_text((other / "key.pem").read_text())
            attempt("mismatched pair", " refused tls-server-key-mismatch")
            # 3. a file that is not there
            key.unlink()
            attempt("missing key", " unreadable key.pem errno=2")
            # 4. an empty chain
            key.write_text(good_key)
            chain.write_text("")
            attempt("empty chain", " refused tls-server-")
        finally:
            key.write_text(good_key)
            chain.write_text(good_chain)
        # Put back, it reloads, and the counters say so.
        before = gw.metrics()["tls"]
        gw.hup()
        gw.reloaded(2, 0, before)
        serves_the_same()

    def reload_counters_are_in_the_prometheus_text_too(gw, up):
        c = socket.create_connection(("127.0.0.1", gw.admin), timeout=5)
        c.sendall(b"GET /metrics?format=prometheus HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n")
        data = b""
        while True:
            d = c.recv(65536)
            if not d:
                break
            data += d
        c.close()
        text = data.decode()
        t = gw.metrics()["tls"]
        assert "\ncancho_gateway_tls_reloads_total %d\n" % t["reloads"] in text, text[-600:]
        assert "\ncancho_gateway_tls_reload_failures_total %d\n" % t["reload_failures"] in text
        assert "# TYPE cancho_gateway_tls_reloads_total counter" in text and "# TYPE cancho_gateway_tls_reload_failures_total counter" in text

    def a_tls_only_deployment_listens_on_the_tls_port_alone_and_stops_cleanly_on_sigterm_and_sigint(gw, up):
        with tempfile.TemporaryDirectory() as tmp:
            only = Gateway(tmp, up.port, plain=False)
            try:
                assert only.port is None
                assert ad.listening_ports(only.proc.pid) == {only.tls_port, only.admin}, ad.listening_ports(only.proc.pid)
                h0, n0 = len(up.heads), len(only.lines())
                head, body = get(only)
                assert head.startswith(b"HTTP/1.1 200") and body == b"ok", (head, body)
                assert "X-Forwarded-Proto: https" in up.heads[h0].decode()
                # The request id names the port the request came in on: with no plain listener, the TLS one.
                rid = re.search(r"X-Request-Id: ([0-9a-f]+)-([0-9a-f]+)-([0-9a-f]+)", up.heads[h0].decode())
                assert rid and int(rid.group(2), 16) == only.tls_port, up.heads[h0]
                e = only.find(n0, status=200, tls=True)
                assert e["tls"] is True and e["outcome"] == "ok", e
                # A reload works here too, and an open connection is told close_notify when the process is asked to stop.
                before = only.metrics()["tls"]
                only.hup()
                only.reloaded(2, 0, before)
                raw = socket.create_connection(("127.0.0.1", only.tls_port), timeout=8)
                s = context(only).wrap_socket(raw, server_hostname="api.example", suppress_ragged_eofs=False)
                t0 = time.time()
                assert only.stop(signal.SIGTERM) == 0, "SIGTERM did not stop it with status 0"
                assert time.time() - t0 < 2.5
                assert s.recv(10) == b""  # close_notify, not a reset (SSLEOFError would be raised here)
                s.close()
                assert only.errors()[-1] == "gateway: stopping", only.errors()
                # Again, with SIGINT, on a fresh process of the same binary.
                only.start()
                head, body = get(only)
                assert head.startswith(b"HTTP/1.1 200"), head
                assert only.stop(signal.SIGINT) == 0, "SIGINT did not stop it with status 0"
            finally:
                only.stop(signal.SIGKILL)


def renew(gw, name, host):
    """A new certificate and key for identity `name`, put in place the way a deploy hook does (each file replaced whole, the pair complete before the
    signal is sent); answers the new chain as PEM text."""
    with tempfile.TemporaryDirectory() as tmp:
        fresh = make_identity(tmp, name, host).parent
        for f in ("key.pem", "chain.pem"):
            shutil.copy(fresh / f, gw.certs / name / (f + ".new"))
            os.replace(gw.certs / name / (f + ".new"), gw.certs / name / f)
    return (gw.certs / name / "chain.pem").read_text()


def main():
    names = sys.argv[1:] or [n for n in vars(T) if not n.startswith("_")]
    failures = 0
    with tempfile.TemporaryDirectory() as tmp:
        up = pt.Upstream(pt.free_port())
        gw = Gateway(tmp, up.port)
        try:
            for name in names:
                t0 = time.time()
                try:
                    getattr(T, name)(gw, up)
                    if not gw.alive():
                        raise AssertionError("the gateway died")
                    print("ok    %-70s %.1fs" % (name, time.time() - t0))
                except (AssertionError, OSError, ssl.SSLError) as e:
                    failures += 1
                    print("FAIL  %-70s %s" % (name, e))
                    if not gw.alive():
                        print("      the gateway died: exit %s %s" % (gw.proc.returncode, gw.errors()[-3:]))
                        break
        finally:
            status = gw.stop()
        if status != 0:
            failures += 1
            print("FAIL  %-70s exit status %r" % ("sigterm_stops_the_gateway_cleanly_with_status_0", status))
    print("%d tests, %d failures" % (len(names), failures))
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
