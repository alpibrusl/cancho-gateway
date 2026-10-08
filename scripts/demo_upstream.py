#!/usr/bin/env python3
"""A small upstream for trying the gateway (docs/examples.html). Standard library only.

    python3 scripts/demo_upstream.py 9000 9001

Each port answers every request with a plain-text report of the request line, the headers and the body length it received,
so you can see exactly what the gateway forwarded. Nothing here is part of the gateway.
"""

import http.server
import socketserver
import sys


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def handle_any(self):
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else b""
        lines = ["upstream :%d saw" % self.server.server_address[1], "%s %s" % (self.command, self.path)]
        lines += ["%s: %s" % (k, v) for k, v in self.headers.items()]
        lines.append("body bytes: %d" % len(body))
        out = ("\n".join(lines) + "\n").encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(out)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(out)

    do_GET = do_POST = do_PUT = do_DELETE = do_PATCH = do_HEAD = do_OPTIONS = handle_any

    def log_message(self, *args):
        pass


class Server(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


if __name__ == "__main__":
    ports = [int(a) for a in sys.argv[1:]] or [9000]
    servers = [Server(("127.0.0.1", p), Handler) for p in ports]
    for s in servers[1:]:
        import threading
        threading.Thread(target=s.serve_forever, daemon=True).start()
    print("listening on " + ", ".join("127.0.0.1:%d" % p for p in ports), flush=True)
    servers[0].serve_forever()
