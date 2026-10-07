#!/usr/bin/env python3
"""Header behaviour against nginx (docs/headers.md section 6, gate 4).

The same raw requests go to nginx and to the gateway, each in front of the same recording upstream, and what the upstream received
is compared header by header. The gateway's own additions (Via, X-Forwarded-Host, X-Forwarded-Proto, X-Request-Id) and the
connection management headers are removed from both views before comparing; the request line is compared whole. Two modes: a
default route (/p) and a route with trust_forwarded (/trusted/p), where the forwarding headers must pass exactly as nginx passes them.

A difference must be listed in EXPECTED with its reason; an unlisted difference fails, and so does a listed one that has gone away
(the table cannot go stale). Needs nginx on PATH (or NGINX=...), lex-sys (LEX_SYS), and runs from any directory.
"""

import os
import pathlib
import shutil
import socket
import subprocess
import sys
import tempfile
import time

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import proxy_test as pt  # noqa: E402  (the fixtures: a recording upstream and a gateway built from a deployment)

ADDED = {"via", "x-forwarded-host", "x-forwarded-proto", "x-request-id"}  # what the gateway writes; nginx, as configured here, writes none
MANAGED = {"connection"}
FORWARDING = {"forwarded", "x-forwarded-for", "x-forwarded-host", "x-forwarded-proto", "x-forwarded-port", "x-real-ip"}

# (case name, the header lines after Host; each case ends with "Connection: close")
CASES = [
    ("plain", [b"Accept: */*", b"User-Agent: t/1"]),
    ("order-and-case", [b"X-A: 1", b"x-b: 2", b"X-C: 3", b"x-lower: 4"]),
    ("duplicates", [b"X-D: 1", b"X-D: 2", b"Cookie: a=1", b"Cookie: b=2"]),
    ("inner-spaces", [b"X-S: a  b   c"]),
    ("surrounding-space", [b"X-T:    padded   "]),
    ("empty-value", [b"X-E:"]),
    ("obs-text", [b"X-U: \xc3\xa9\xff"]),
    ("long-value", [b"X-L: " + b"v" * 4000]),
    ("authorization", [b"Authorization: Bearer abc.def", b"Cookie: s=1"]),
    ("keep-alive-header", [b"Keep-Alive: timeout=5"]),
    ("te-trailers", [b"TE: trailers"]),
    ("trailer-header", [b"Trailer: X-Sum"]),
    ("proxy-connection", [b"Proxy-Connection: keep-alive"]),
    ("upgrade", [b"Upgrade: websocket"]),
    ("proxy-authorization", [b"Proxy-Authorization: Basic eDp5"]),
    ("connection-names-a-header", [b"Connection: close, X-Drop", b"X-Drop: 1", b"X-Keep: 2"]),
    ("forwarded-family", [b"Forwarded: for=1.2.3.4;proto=https", b"X-Forwarded-For: 1.2.3.4", b"X-Forwarded-Host: front", b"X-Forwarded-Proto: https",
                          b"X-Forwarded-Port: 443", b"X-Real-IP: 1.2.3.4"]),
    ("request-id-valid", [b"X-Request-Id: edge-42"]),
    ("via-from-client", [b"Via: 1.1 front"]),
]
TARGETS = [b"%s", b"%s?a=1&b=%%2F&c=%%20", b"%s/x%%20y"]

# (case, mode) -> why the gateway differs from nginx 1.24 on purpose. The mode is "default" or "trusted". Measured, not assumed: nginx
# also removes Keep-Alive, TE and Upgrade and forwards an empty-valued header, exactly as the gateway does, so those cases agree and are not listed.
HOP = "{} is hop-by-hop or the first proxy's alone (RFC 9110 7.6.1, 11.7.2): nginx 1.24 forwards it, the gateway removes it"
EXPECTED = {
    ("proxy-authorization", "default"): HOP.format("Proxy-Authorization"),
    ("proxy-authorization", "trusted"): HOP.format("Proxy-Authorization"),
    ("trailer-header", "default"): HOP.format("Trailer"),
    ("trailer-header", "trusted"): HOP.format("Trailer"),
    ("proxy-connection", "default"): HOP.format("Proxy-Connection"),
    ("proxy-connection", "trusted"): HOP.format("Proxy-Connection"),
    ("connection-names-a-header", "default"): "a header named by Connection belongs to the connection (RFC 9110 7.6.1): nginx forwards it, the gateway removes it",
    ("connection-names-a-header", "trusted"): "same",
    ("forwarded-family", "default"): "an untrusted route does not believe forwarding claims (docs/headers.md section 2); nginx passes them on",
    ("request-id-valid", "default"): "an untrusted route generates its own request id; the client's X-Request-Id is not kept",
    ("via-from-client", "default"): "the gateway appends its own Via after the client's (RFC 9110 7.6.3); nginx adds none",
    ("via-from-client", "trusted"): "same",
}


def nginx_config(tmp, port, up):
    return f"""worker_processes 1;
user root;
pid {tmp}/nginx.pid;
error_log /dev/null crit;
events {{ worker_connections 256; }}
http {{
    access_log off;
    client_body_temp_path {tmp}/b; proxy_temp_path {tmp}/p; fastcgi_temp_path {tmp}/f; uwsgi_temp_path {tmp}/u; scgi_temp_path {tmp}/s;
    large_client_header_buffers 4 16k;
    server {{
        listen 127.0.0.1:{port};
        location / {{
            proxy_pass http://127.0.0.1:{up};
            proxy_http_version 1.1;
            proxy_set_header Host $http_host;
            proxy_set_header Connection "close";
        }}
    }}
}}
"""


def send(port, raw):
    s = socket.create_connection(("127.0.0.1", port), timeout=5)
    s.sendall(raw)
    data = b""
    try:
        while True:
            d = s.recv(65536)
            if not d:
                break
            data += d
    except OSError:
        pass
    s.close()
    return data


def view(head, sent):
    """The recorded head as (request line, [(name, value-as-bytes)]) without the connection headers and without the headers the
    gateway writes and nginx does not, unless the case itself sent one of that name (`sent`, lowercase names)."""
    lines = head.split(b"\r\n")
    out = []
    for line in lines[1:]:
        name, _, value = line.partition(b":")
        lname = name.lower().decode("latin-1")
        if lname in MANAGED or (lname in ADDED and lname not in sent):
            continue
        out.append((name, value.strip()))
    return lines[0], out


def main():
    nginx = os.environ.get("NGINX") or shutil.which("nginx")
    if not nginx:
        print("nginx not found: set NGINX or put it on PATH", file=sys.stderr)
        return 2
    failures, compared, differed = 0, 0, 0
    seen_expected = set()
    with tempfile.TemporaryDirectory() as tmp, tempfile.TemporaryDirectory() as tmp2:
        up_port, gw_port, ng_port = pt.free_port(), pt.free_port(), pt.free_port()
        dead, ka, flap = pt.free_port(), pt.free_port(), pt.free_port()
        up = pt.Upstream(up_port)
        gw = pt.Gateway(tmp, gw_port, up_port, dead, ka, flap)
        (pathlib.Path(tmp2) / "nginx.conf").write_text(nginx_config(tmp2, ng_port, up_port))
        proc = subprocess.Popen([nginx, "-c", f"{tmp2}/nginx.conf", "-g", "daemon off;"], stderr=subprocess.DEVNULL)
        try:
            for _ in range(100):
                try:
                    socket.create_connection(("127.0.0.1", ng_port), 0.2).close()
                    break
                except OSError:
                    time.sleep(0.05)
            for mode, base in (("default", b"/p"), ("trusted", b"/trusted/p")):
                for name, headers in CASES:
                    for target in TARGETS:
                        path = target % base
                        raw = b"GET " + path + b" HTTP/1.1\r\nHost: h.example\r\n" + b"\r\n".join(headers) + b"\r\nConnection: close\r\n\r\n"
                        views = []
                        for port in (ng_port, gw_port):
                            n = len(up.heads)
                            send(port, raw)
                            time.sleep(0.02)
                            views.append(view(up.heads[n], {h.split(b":")[0].lower().decode() for h in headers}) if len(up.heads) > n else None)
                        compared += 1
                        key = (name, mode)
                        if os.environ.get("SHOW") == name and path == base:
                            print("%s %s\n  nginx   %r\n  gateway %r" % (name, mode, views[0], views[1]))
                        if views[0] is None or views[1] is None:
                            failures += 1
                            print("FAIL %s %s %r: one side did not reach the upstream (nginx %s, gateway %s)" % (name, mode, path, views[0] is not None, views[1] is not None))
                            continue
                        if views[0] == views[1]:
                            if key in EXPECTED:
                                print("note: %s %s %r agrees although listed as different" % (name, mode, path))
                            continue
                        differed += 1
                        if key in EXPECTED:
                            seen_expected.add(key)
                            continue
                        failures += 1
                        print("FAIL %s %s %r: an unlisted difference\n  nginx   %r\n  gateway %r" % (name, mode, path, views[0], views[1]))
            for key in sorted(set(EXPECTED) - seen_expected):
                failures += 1
                print("FAIL %s %s is listed as different but never differed (the table is stale)" % key)
        finally:
            proc.terminate()
            proc.wait()
            gw.stop()
            up.stop = True
    print("%d comparisons, %d differences (all listed: %s), %d failures" % (compared, differed, "yes" if not failures else "no", failures))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
