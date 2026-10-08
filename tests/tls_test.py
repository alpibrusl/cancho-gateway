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
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import proxy_test as pt  # noqa: E402

ROOT = pt.ROOT
LEX = pt.LEX
SOURCES = pt.SOURCES
HANDSHAKES = 4
HANDSHAKE_MS = 1500


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
    def __init__(self, tmp, up_port):
        self.certs = pathlib.Path(tmp) / "certs"
        self.chain_api = make_identity(self.certs, "api", "api.example")
        self.chain_second = make_identity(self.certs, "second", "second.example")
        self.port, self.tls_port, self.admin = pt.free_port(), pt.free_port(), pt.free_port()
        deploy = pathlib.Path(tmp) / "deploy.toml"
        deploy.write_text("""listen = %d
tls_listen = %d
admin_listen = %d
tls_dir = "%s"
tls_identities = ["api", "second"]
tls_handshakes = %d
tls_handshake_ms = %d
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
""" % (self.port, self.tls_port, self.admin, self.certs, HANDSHAKES, HANDSHAKE_MS, up_port))
        out = pathlib.Path(tmp) / "gen"
        subprocess.run([sys.executable, str(ROOT / "scripts" / "generate.py"), str(deploy), "--out", str(out)], check=True)
        files = [str(out / n) for n in ("deploy.cho", "routes.cho", "tlsfiles.cho")] + pt.dependencies() + [str(ROOT / "src" / (n + ".cho")) for n in SOURCES]
        built = subprocess.run([LEX, "build", "--std", *files, "-o", str(pathlib.Path(tmp) / "gateway")], capture_output=True, text=True)
        if built.returncode != 0:
            raise SystemExit("build failed: " + built.stderr[:600])
        self.proc = subprocess.Popen([str(pathlib.Path(tmp) / "gateway")], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.log = []
        self.lock = threading.Lock()
        threading.Thread(target=self.read_log, daemon=True).start()
        for _ in range(100):
            try:
                socket.create_connection(("127.0.0.1", self.tls_port), timeout=0.2).close()
                break
            except OSError:
                time.sleep(0.05)
        else:
            raise SystemExit("gateway did not start: %s" % self.proc.stderr.read()[:300])
        time.sleep(0.3)

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

    def since(self, n, want=1, wait=4):
        end = time.time() + wait
        while time.time() < end:
            got = self.lines()[n:]
            if len(got) >= want:
                return got
            time.sleep(0.05)
        return self.lines()[n:]

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

    def alive(self):
        return self.proc.poll() is None

    def stop(self):
        self.proc.terminate()
        try:
            self.proc.wait(3)
        except subprocess.TimeoutExpired:
            self.proc.kill()


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
    head, _, body = data.partition(b"\r\n\r\n")
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
    return head, body


def get(gw, path="/", host="api.example", **kw):
    s = connect(gw, host, **kw)
    s.sendall(b"GET %s HTTP/1.1\r\nHost: %s\r\n\r\n" % (path.encode(), host.encode()))
    head, body = read_response(s)
    s.close()
    return head, body


class T:
    def get_over_tls_reaches_the_upstream_as_https(gw, up):
        n0, h0 = len(gw.lines()), len(up.heads)
        head, body = get(gw)
        assert head.startswith(b"HTTP/1.1 200") and body == b"ok", (head, body)
        e = gw.since(n0)[-1]
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
        e = gw.since(n0)[-1]
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
        e = gw.since(n0)[-1]
        assert e["outcome"] == "aborted" and e["tls"] is True, e

    def silent_peers_delay_an_honest_one_and_are_dropped_at_the_handshake_deadline(gw, up):
        silent = [socket.create_connection(("127.0.0.1", gw.tls_port), timeout=10) for _ in range(HANDSHAKES)]
        time.sleep(0.2)
        t0 = time.time()
        head, body = get(gw)
        waited = time.time() - t0
        assert body == b"ok", head
        assert waited > HANDSHAKE_MS / 1000.0 * 0.5, "the honest peer was served at once: the bound did not hold (%.2fs)" % waited
        assert waited < HANDSHAKE_MS / 1000.0 + 3, waited
        for s in silent:
            s.settimeout(3)
            try:
                assert s.recv(10) == b"", "a silent peer is dropped without a word"
            except OSError:
                pass
            s.close()

    def a_burst_of_handshakes_is_all_served(gw, up):
        results = []

        def one():
            try:
                head, body = get(gw)
                results.append(body == b"ok")
            except Exception as e:  # noqa: BLE001
                results.append(str(e))

        threads = [threading.Thread(target=one) for _ in range(60)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(30)
        assert results.count(True) == 60, [r for r in results if r is not True][:5]

    def a_client_that_stops_reading_is_ended_at_its_deadline(gw, up):
        n0 = len(gw.lines())
        s = connect(gw)
        s.sendall(b"GET /big?n=50000000 HTTP/1.1\r\nHost: api.example\r\n\r\n")
        time.sleep(5.5)
        e = gw.since(n0)[-1]
        assert e["outcome"] == "aborted", e
        s.close()
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
                        print("      the gateway died: exit %s %s" % (gw.proc.returncode, gw.proc.stderr.read()[:300]))
                        break
        finally:
            gw.stop()
    print("%d tests, %d failures" % (len(names), failures))
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
