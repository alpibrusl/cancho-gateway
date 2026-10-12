#!/usr/bin/env python3
"""Table tests of scripts/generate.py: the prefix rule, and one refusal per rule tag."""

import json
import pathlib
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
import generate  # noqa: E402

PREFIX = [
    (["10.0.1.5:9000"], "10.0.1.5:9000"),                       # one upstream: exact
    (["10.0.1.5:9000", "10.0.1.6:9000"], "10.0.1."),
    (["10.0.1.5:9000", "10.0.1.50:9000"], "10.0.1."),           # shares '10.0.1.5', which would over-admit
    (["10.0.1.5:9000", "10.0.1.5:9001"], "10.0.1.5:"),   # cut at the colon
    (["10.0.1.5:9000", "192.168.0.1:9000"], ""),                # nothing shared: reported, not hidden
    (["a.internal:80", "b.internal:80"], ""),
    (["api.internal:80", "api.internal:81"], "api.internal:"),
]

UP = 'listen = 80\n[[upstream]]\nname = "a"\naddr = "10.0.0.1:1"\n'
R = '[[route]]\nupstream = "a"\n'
# A deployment with one websocket route, in two parts so that a deployment-wide key can be put between them (line 2).
WS = 'listen = 80\n'
WSR = '[[upstream]]\nname = "a"\naddr = "10.0.0.1:1"\n[[route]]\nupstream = "a"\npath_prefix = "/"\nwebsocket = true\n'

# (rule, line the refusal must name or None, deployment text)
REFUSALS = [
    ("config.listen", 1, 'listen = 0\n[[upstream]]\nname="a"\naddr="10.0.0.1:1"\n'),
    ("config.listen", 1, 'listen = "80"\n[[upstream]]\nname="a"\naddr="10.0.0.1:1"\n'),
    ("config.listen", 1, 'listen = true\n[[upstream]]\nname="a"\naddr="10.0.0.1:1"\n'),
    ("config.upstream", 1, "listen = 80\n"),
    ("config.upstream", 4, 'listen = 80\n[[upstream]]\nname="a"\naddr="10.0.0.1"\n'),
    ("config.upstream", 4, 'listen = 80\n[[upstream]]\nname="a"\naddr="10.0.0.1:70000"\n'),
    ("config.upstream", 3, 'listen = 80\n[[upstream]]\nname="A"\naddr="10.0.0.1:1"\n'),
    ("config.upstream", 4, 'listen = 80\n[[upstream]]\nname="a"\naddr="evil\\"host:1"\n'),
    ("config.duplicate", 6, 'listen = 80\n[[upstream]]\nname="a"\naddr="10.0.0.1:1"\n[[upstream]]\nname="a"\naddr="10.0.0.2:1"\n'),
    ("config.duplicate", 7, 'listen = 80\n[[upstream]]\nname="a"\naddr="10.0.0.1:1"\n[[upstream]]\nname="b"\naddr="10.0.0.1:1"\n'),
    ("config.count", None, "listen = 80\n" + "".join('[[upstream]]\nname="u%d"\naddr="10.0.%d.%d:1"\n' % (i, i // 250, i % 250 + 1) for i in range(257))),
    ("config.read", 1, "listen = [unterminated\n"),
    ("config.timeout", 2, 'listen = 80\nheader_timeout_ms = 5\n[[upstream]]\nname="a"\naddr="10.0.0.1:1"\n'),
    ("config.timeout", 2, 'listen = 80\nconnect_timeout_ms = "5s"\n[[upstream]]\nname="a"\naddr="10.0.0.1:1"\n'),
    ("config.timeout", 2, 'listen = 80\ntotal_timeout_ms = 600001\n[[upstream]]\nname="a"\naddr="10.0.0.1:1"\n'),
    ("config.timeout", 2, 'listen = 80\nidle_timeout_ms = 50\n[[upstream]]\nname="a"\naddr="10.0.0.1:1"\n'),
    ("config.pool", 2, 'listen = 80\npool_idle_max = 65\n[[upstream]]\nname="a"\naddr="10.0.0.1:1"\n'),
    ("config.pool", 2, 'listen = 80\npool_idle_max = -1\n[[upstream]]\nname="a"\naddr="10.0.0.1:1"\n'),
    ("config.pool", 2, 'listen = 80\npool_idle_max = "4"\n[[upstream]]\nname="a"\naddr="10.0.0.1:1"\n'),
    ("config.circuit", 2, 'listen = 80\ncircuit_threshold = 1001\n[[upstream]]\nname="a"\naddr="10.0.0.1:1"\n'),
    ("config.circuit", 2, 'listen = 80\ncircuit_threshold = -1\n[[upstream]]\nname="a"\naddr="10.0.0.1:1"\n'),
    ("config.circuit", 2, 'listen = 80\ncircuit_open_ms = 50\n[[upstream]]\nname="a"\naddr="10.0.0.1:1"\n'),
    ("config.circuit", 2, 'listen = 80\ncircuit_open_ms = "10s"\n[[upstream]]\nname="a"\naddr="10.0.0.1:1"\n'),
    ("config.log", 2, 'listen = 80\nlog_failure = "ignore"\n[[upstream]]\nname="a"\naddr="10.0.0.1:1"\n'),
    ("config.admin", 2, 'listen = 80\nadmin_listen = 80\n[[upstream]]\nname="a"\naddr="10.0.0.1:1"\n'),
    ("config.admin", 2, 'listen = 80\nadmin_listen = 70000\n[[upstream]]\nname="a"\naddr="10.0.0.1:1"\n'),
    ("config.admin", 2, 'listen = 80\nadmin_listen = -1\n[[upstream]]\nname="a"\naddr="10.0.0.1:1"\n'),
    ("config.admin", 2, 'listen = 80\nadmin_listen = "9090"\n[[upstream]]\nname="a"\naddr="10.0.0.1:1"\n'),
    ("config.admin", 2, 'listen = 80\nadmin_listen = true\n[[upstream]]\nname="a"\naddr="10.0.0.1:1"\n'),
    ("config.tls", None, 'listen = 80\ntls_dir = "/etc/tls"\n' + '[[upstream]]\nname="a"\naddr="10.0.0.1:1"\n'),
    ("config.tls", None, 'listen = 80\ntls_listen = 443\n' + '[[upstream]]\nname="a"\naddr="10.0.0.1:1"\n'),
    ("config.tls", None, 'listen = 80\ntls_listen = 80\ntls_dir = "/etc/tls"\n' + '[[upstream]]\nname="a"\naddr="10.0.0.1:1"\n'),
    ("config.tls", None, 'listen = 80\nadmin_listen = 9090\ntls_listen = 9090\ntls_dir = "/etc/tls"\n' + '[[upstream]]\nname="a"\naddr="10.0.0.1:1"\n'),
    ("config.tls", None, 'listen = 80\ntls_listen = 0\ntls_dir = "/etc/tls"\n' + '[[upstream]]\nname="a"\naddr="10.0.0.1:1"\n'),
    ("config.tls", None, 'listen = 80\ntls_listen = 70000\ntls_dir = "/etc/tls"\n' + '[[upstream]]\nname="a"\naddr="10.0.0.1:1"\n'),
    ("config.tls", None, 'listen = 80\ntls_listen = 443\ntls_dir = "etc/tls"\n' + '[[upstream]]\nname="a"\naddr="10.0.0.1:1"\n'),
    ("config.tls", None, 'listen = 80\ntls_listen = 443\ntls_dir = "/"\n' + '[[upstream]]\nname="a"\naddr="10.0.0.1:1"\n'),
    ("config.tls", None, 'listen = 80\ntls_listen = 443\ntls_dir = "/etc/../tls"\n' + '[[upstream]]\nname="a"\naddr="10.0.0.1:1"\n'),
    ("config.tls", None, 'listen = 80\ntls_listen = 443\ntls_dir = "/etc/tls/"\n' + '[[upstream]]\nname="a"\naddr="10.0.0.1:1"\n'),
    ("config.tls", None, 'listen = 80\ntls_listen = 443\ntls_dir = "/etc//tls"\n' + '[[upstream]]\nname="a"\naddr="10.0.0.1:1"\n'),
    ("config.tls", None, 'listen = 80\ntls_listen = 443\ntls_dir = "/etc/t ls"\n' + '[[upstream]]\nname="a"\naddr="10.0.0.1:1"\n'),
    ("config.tls", None, 'listen = 80\ntls_listen = 443\ntls_dir = "/dev"\n' + '[[upstream]]\nname="a"\naddr="10.0.0.1:1"\n'),
    ("config.tls", None, 'listen = 80\ntls_listen = 443\ntls_dir = "/dev/urandom"\n' + '[[upstream]]\nname="a"\naddr="10.0.0.1:1"\n'),
    ("config.tls", None, 'listen = 80\ntls_listen = 443\ntls_dir = "/dev/urandom/x"\n' + '[[upstream]]\nname="a"\naddr="10.0.0.1:1"\n'),
    ("config.tls", None, 'listen = 80\ntls_listen = 443\ntls_dir = 5\n' + '[[upstream]]\nname="a"\naddr="10.0.0.1:1"\n'),
    ("config.tls", None, 'listen = 80\ntls_listen = 443\ntls_dir = "/etc/tls"\ntls_identities = []\n' + '[[upstream]]\nname="a"\naddr="10.0.0.1:1"\n'),
    ("config.tls", None, 'listen = 80\ntls_listen = 443\ntls_dir = "/etc/tls"\ntls_identities = ["a", "a"]\n' + '[[upstream]]\nname="a"\naddr="10.0.0.1:1"\n'),
    ("config.tls", None, 'listen = 80\ntls_listen = 443\ntls_dir = "/etc/tls"\ntls_identities = ["../x"]\n' + '[[upstream]]\nname="a"\naddr="10.0.0.1:1"\n'),
    ("config.tls", None, 'listen = 80\ntls_listen = 443\ntls_dir = "/etc/tls"\ntls_identities = [".."]\n' + '[[upstream]]\nname="a"\naddr="10.0.0.1:1"\n'),
    ("config.tls", None, 'listen = 80\ntls_listen = 443\ntls_dir = "/etc/tls"\ntls_identities = ["a"] \ntls_handshakes = 0\n' + '[[upstream]]\nname="a"\naddr="10.0.0.1:1"\n'),
    ("config.tls", None, 'listen = 80\ntls_listen = 443\ntls_dir = "/etc/tls"\ntls_rate = 100001\n' + '[[upstream]]\nname="a"\naddr="10.0.0.1:1"\n'),
    ("config.tls", None, 'listen = 80\ntls_listen = 443\ntls_dir = "/etc/tls"\ntls_handshake_ms = 5\n' + '[[upstream]]\nname="a"\naddr="10.0.0.1:1"\n'),
    ("config.tls", None, 'listen = 80\ntls_listen = 443\ntls_dir = "/etc/tls"\ntls_handshakes = true\n' + '[[upstream]]\nname="a"\naddr="10.0.0.1:1"\n'),
    # --- at least one of listen and tls_listen (docs/tls.md section 11)
    ("config.listeners", None, '[[upstream]]\nname="a"\naddr="10.0.0.1:1"\n'),
    ("config.listeners", None, 'admin_listen = 9090\n[[upstream]]\nname="a"\naddr="10.0.0.1:1"\n'),
    ("config.listeners", None, 'header_timeout_ms = 2000\n[[upstream]]\nname="a"\naddr="10.0.0.1:1"\n'),
    ("config.tls", None, 'tls_listen = 443\n[[upstream]]\nname="a"\naddr="10.0.0.1:1"\n'),
    ("config.tls", None, 'tls_listen = 443\nadmin_listen = 443\ntls_dir = "/etc/tls"\n[[upstream]]\nname="a"\naddr="10.0.0.1:1"\n'),
    ("config.tls", None, 'tls_dir = "/etc/tls"\n[[upstream]]\nname="a"\naddr="10.0.0.1:1"\n'),
    ("config.listen", 1, 'listen = 70000\ntls_listen = 443\ntls_dir = "/etc/tls"\n[[upstream]]\nname="a"\naddr="10.0.0.1:1"\n'),
    ("config.listen", 1, 'listen = 0\ntls_listen = 443\ntls_dir = "/etc/tls"\n[[upstream]]\nname="a"\naddr="10.0.0.1:1"\n'),
    ("config.log", 2, 'listen = 80\nlog_failure = true\n[[upstream]]\nname="a"\naddr="10.0.0.1:1"\n'),
    ("config.timeout", 3, 'listen = 80\nheader_timeout_ms = 5000\ntotal_timeout_ms = 1000\n[[upstream]]\nname="a"\naddr="10.0.0.1:1"\n'),
    # --- routes, with the line they must name
    ("config.unknown-key", 7, UP + R + 'path_pref = "/"\n'),
    ("config.unknown-key", 2, 'listen = 80\nlisten_port = 1\n[[upstream]]\nname="a"\naddr="10.0.0.1:1"\n'),
    ("config.unknown-key", 3, 'listen = 80\n[[upstream]]\naddress = "10.0.0.1:1"\nname = "a"\n'),
    ("config.route", 7, UP + R + 'path_prefix = "api"\n'),
    ("config.route", 7, UP + R + 'path_prefix = "/api/"\n'),
    ("config.route", 7, UP + R + 'path_prefix = "/a//b"\n'),
    ("config.route", 7, UP + R + 'path_prefix = "/a/../b"\n'),
    ("config.route", 7, UP + R + 'path_prefix = "/a%2fb"\n'),
    ("config.route", 7, UP + R + 'path_prefix = "/a b"\n'),
    ("config.route", 7, UP + R + 'path_prefix = "/a\\\\b"\n'),
    ("config.route", 5, UP + R),
    ("config.route", 8, UP + R + 'path_prefix = "/"\nhost = "Example.com"\n'),
    ("config.route", 8, UP + R + 'path_prefix = "/"\nhost = "example.com:80"\n'),
    ("config.route", 8, UP + R + 'path_prefix = "/"\nmethods = ["GET", "FETCH"]\n'),
    ("config.route", 8, UP + R + 'path_prefix = "/"\nmethods = []\n'),
    ("config.route", 8, UP + R + 'path_prefix = "/"\nmethods = ["GET", "GET"]\n'),
    ("config.route", 8, UP + R + 'path_prefix = "/"\nmax_body = -1\n'),
    ("config.route", 8, UP + R + 'path_prefix = "/"\ntrust_forwarded = "yes"\n'),
    ("config.route", 8, UP + R + 'path_prefix = "/"\nname = "Has Space"\n'),
    ("config.route", 8, UP + R + 'path_prefix = "/"\nname = "' + "a" * 33 + '"\n'),
    ("config.route", 8, UP + R + 'path_prefix = "/"\nname = 7\n'),
    ("config.route", 8, UP + R + 'path_prefix = "/"\ntrust_forwarded = 1\n'),
    ("config.route", 8, UP + R + 'path_prefix = "/"\nmax_body = 1073741825\n'),
    ("config.route-upstream", 7, UP + '[[route]]\npath_prefix = "/"\nupstream = "b"\n'),
    ("config.route-conflict", 10, UP + R + 'path_prefix = "/x"\n' + R + 'path_prefix = "/x"\n'),
    ("config.route-conflict", 11, UP + R + 'path_prefix = "/x"\nmethods = ["GET", "POST"]\n' + R + 'path_prefix = "/x"\nmethods = ["POST"]\n'),
    # --- WebSocket (docs/websocket.md section 3)
    ("config.websocket", 8, UP + R + 'path_prefix = "/"\nwebsocket = "yes"\n'),
    ("config.websocket", 8, UP + R + 'path_prefix = "/"\nwebsocket = 1\n'),
    ("config.websocket", 8, UP + R + 'path_prefix = "/"\nsubprotocols = ["ocpp1.6"]\n'),
    ("config.websocket", 8, UP + R + 'path_prefix = "/"\norigins = ["https://a.example"]\n'),
    ("config.websocket", 9, UP + R + 'path_prefix = "/"\nwebsocket = true\nmethods = ["POST"]\n'),
    ("config.websocket", 9, UP + R + 'path_prefix = "/"\nwebsocket = true\nsubprotocols = "ocpp1.6"\n'),
    ("config.websocket", 9, UP + R + 'path_prefix = "/"\nwebsocket = true\nsubprotocols = ["a b"]\n'),
    ("config.websocket", 9, UP + R + 'path_prefix = "/"\nwebsocket = true\nsubprotocols = ["a,b"]\n'),
    ("config.websocket", 9, UP + R + 'path_prefix = "/"\nwebsocket = true\nsubprotocols = [""]\n'),
    ("config.websocket", 9, UP + R + 'path_prefix = "/"\nwebsocket = true\nsubprotocols = ["a", "a"]\n'),
    ("config.websocket", 9, UP + R + 'path_prefix = "/"\nwebsocket = true\nsubprotocols = [1]\n'),
    ("config.websocket", 9, UP + R + 'path_prefix = "/"\nwebsocket = true\nsubprotocols = [%s]\n' % ", ".join('"p%d"' % i for i in range(9))),
    ("config.websocket", 9, UP + R + 'path_prefix = "/"\nwebsocket = true\nsubprotocols = ["%s"]\n' % ("x" * 65)),
    ("config.websocket", 9, UP + R + 'path_prefix = "/"\nwebsocket = true\norigins = "https://a.example"\n'),
    ("config.websocket", 9, UP + R + 'path_prefix = "/"\nwebsocket = true\norigins = ["https://a.example/"]\n'),
    ("config.websocket", 9, UP + R + 'path_prefix = "/"\nwebsocket = true\norigins = ["https://a.example/x"]\n'),
    ("config.websocket", 9, UP + R + 'path_prefix = "/"\nwebsocket = true\norigins = ["HTTPS://a.example"]\n'),
    ("config.websocket", 9, UP + R + 'path_prefix = "/"\nwebsocket = true\norigins = ["https://A.example"]\n'),
    ("config.websocket", 9, UP + R + 'path_prefix = "/"\nwebsocket = true\norigins = ["a.example"]\n'),
    ("config.websocket", 9, UP + R + 'path_prefix = "/"\nwebsocket = true\norigins = ["*"]\n'),
    ("config.websocket", 9, UP + R + 'path_prefix = "/"\nwebsocket = true\norigins = ["https://a.example", "https://a.example"]\n'),
    ("config.websocket", 9, UP + R + 'path_prefix = "/"\nwebsocket = true\norigins = [%s]\n' % ", ".join('"https://h%d.example"' % i for i in range(17))),
    ("config.websocket", 2, 'listen = 80\nws_idle_timeout_ms = 5000\n[[upstream]]\nname="a"\naddr="10.0.0.1:1"\n' + R + 'path_prefix = "/"\n'),
    ("config.websocket", 2, 'listen = 80\nws_max_tunnels = 5\n[[upstream]]\nname="a"\naddr="10.0.0.1:1"\n' + R + 'path_prefix = "/"\n'),
    ("config.websocket", 2, 'listen = 80\nws_max_lifetime_ms = 5000\n[[upstream]]\nname="a"\naddr="10.0.0.1:1"\n' + R + 'path_prefix = "/"\n'),
    ("config.websocket", 2, WS + 'ws_idle_timeout_ms = 99\n' + WSR),
    ("config.websocket", 2, WS + 'ws_idle_timeout_ms = 86400001\n' + WSR),
    ("config.websocket", 2, WS + 'ws_idle_timeout_ms = "10m"\n' + WSR),
    ("config.websocket", 2, WS + 'ws_max_lifetime_ms = 99\n' + WSR),
    ("config.websocket", 2, WS + 'ws_max_lifetime_ms = 2592000001\n' + WSR),
    ("config.websocket", 2, WS + 'ws_max_lifetime_ms = true\n' + WSR),
    ("config.websocket", 2, WS + 'ws_max_tunnels = 0\n' + WSR),
    ("config.websocket", 2, WS + 'ws_max_tunnels = 128\n' + WSR),
    ("config.websocket", 2, WS + 'ws_max_tunnels = -1\n' + WSR),
    ("config.websocket", 2, WS + 'ws_max_tunnels = "64"\n' + WSR),
    # --- rate limiting (docs/ratelimit.md section 4): one refusal per rule, plus the variants of each
    ("config.ratelimit", 8, UP + R + 'path_prefix = "/"\nrate_limit = 100\n'),
    ("config.ratelimit", 8, UP + R + 'path_prefix = "/"\nrate_limit = "100"\n'),
    ("config.ratelimit", 8, UP + R + 'path_prefix = "/"\nrate_limit = "100/d"\n'),
    ("config.ratelimit", 8, UP + R + 'path_prefix = "/"\nrate_limit = "0/s"\n'),
    ("config.ratelimit", 8, UP + R + 'path_prefix = "/"\nrate_limit = "007/s"\n'),
    ("config.ratelimit", 8, UP + R + 'path_prefix = "/"\nrate_limit = "1000001/s"\n'),
    ("config.ratelimit", 8, UP + R + 'path_prefix = "/"\nrate_limit = " 5/s"\n'),
    ("config.ratelimit", 8, UP + R + 'path_prefix = "/"\nrate_limit = "-5/s"\n'),
    ("config.ratelimit", 8, UP + R + 'path_prefix = "/"\nrate_burst = 5\n'),
    ("config.ratelimit", 8, UP + R + 'path_prefix = "/"\nrate_key = "route"\n'),
    ("config.ratelimit", 8, UP + R + 'path_prefix = "/"\nrate_buckets = 64\n'),
    ("config.ratelimit", 9, UP + R + 'path_prefix = "/"\nrate_limit = "5/s"\nrate_burst = 0\n'),
    ("config.ratelimit", 9, UP + R + 'path_prefix = "/"\nrate_limit = "5/s"\nrate_burst = 1000001\n'),
    ("config.ratelimit", 9, UP + R + 'path_prefix = "/"\nrate_limit = "5/s"\nrate_burst = "5"\n'),
    ("config.ratelimit", 9, UP + R + 'path_prefix = "/"\nrate_limit = "5/s"\nrate_burst = true\n'),
    ("config.ratelimit", 9, UP + R + 'path_prefix = "/"\nrate_limit = "5/s"\nrate_key = "ip"\n'),
    ("config.ratelimit", 9, UP + R + 'path_prefix = "/"\nrate_limit = "5/s"\nrate_key = "peer"\n'),
    ("config.ratelimit", 9, UP + R + 'path_prefix = "/"\nrate_limit = "5/s"\nrate_key = "header:"\n'),
    ("config.ratelimit", 9, UP + R + 'path_prefix = "/"\nrate_limit = "5/s"\nrate_key = "header:X Key"\n'),
    ("config.ratelimit", 9, UP + R + 'path_prefix = "/"\nrate_limit = "5/s"\nrate_key = "header:%s"\n' % ("x" * 65)),
    ("config.ratelimit", 9, UP + R + 'path_prefix = "/"\nrate_limit = "5/s"\nrate_key = 5\n'),
    ("config.ratelimit", 9, UP + R + 'path_prefix = "/"\nrate_limit = "5/s"\nrate_key = "xff:middle"\n'),
    ("config.ratelimit", 9, UP + R + 'path_prefix = "/"\nrate_limit = "5/s"\nrate_key = "header:Host"\n'),
    ("config.ratelimit", 9, UP + R + 'path_prefix = "/"\nrate_limit = "5/s"\nrate_key = "header:content-length"\n'),
    ("config.ratelimit", 9, UP + R + 'path_prefix = "/"\nrate_limit = "5/s"\nrate_key = "header:Transfer-Encoding"\n'),
    ("config.ratelimit", 9, UP + R + 'path_prefix = "/"\nrate_limit = "5/s"\nrate_key = "header:Connection"\n'),
    ("config.ratelimit", 9, UP + R + 'path_prefix = "/"\nrate_limit = "5/s"\nrate_key = "header:Upgrade"\n'),
    ("config.ratelimit", 9, UP + R + 'path_prefix = "/"\nrate_limit = "5/s"\nrate_key = "header:Proxy-Authorization"\n'),
    ("config.ratelimit", 9, UP + R + 'path_prefix = "/"\nrate_limit = "5/s"\nrate_key = "xff:last"\n'),
    ("config.ratelimit", 9, UP + R + 'path_prefix = "/"\nrate_limit = "5/s"\nrate_key = "xff:first"\n'),
    ("config.ratelimit", 9, UP + R + 'path_prefix = "/"\nrate_limit = "5/s"\nrate_key = "header:X-Forwarded-For"\n'),
    ("config.ratelimit", 9, UP + R + 'path_prefix = "/"\nrate_limit = "5/s"\nrate_key = "header:x-real-ip"\n'),
    ("config.ratelimit", 9, UP + R + 'path_prefix = "/"\nrate_limit = "5/s"\nrate_key = "header:Forwarded"\n'),
    ("config.ratelimit", 10, UP + R + 'path_prefix = "/"\nrate_limit = "5/s"\nrate_key = "route"\nrate_buckets = 4\n'),
    ("config.ratelimit", 10, UP + R + 'path_prefix = "/"\nrate_limit = "5/s"\nrate_key = "header:X-Key"\nrate_buckets = 3\n'),
    ("config.ratelimit", 10, UP + R + 'path_prefix = "/"\nrate_limit = "5/s"\nrate_key = "header:X-Key"\nrate_buckets = 0\n'),
    ("config.ratelimit", 10, UP + R + 'path_prefix = "/"\nrate_limit = "5/s"\nrate_key = "header:X-Key"\nrate_buckets = 65540\n'),
    ("config.ratelimit", 10, UP + R + 'path_prefix = "/"\nrate_limit = "5/s"\nrate_key = "header:X-Key"\nrate_buckets = "64"\n'),
    ("config.ratelimit", 10, UP + R + 'path_prefix = "/"\nrate_limit = "5/s"\nrate_key = "header:X-Key"\nrate_buckets = 6\n'),
    # the routes' tables add up to more than 65,536 buckets (the second route is the one named)
    ("config.ratelimit", 14, UP + R + 'path_prefix = "/a"\nrate_limit = "5/s"\nrate_key = "header:X-Key"\nrate_buckets = 65536\n' + R + 'path_prefix = "/b"\nrate_limit = "5/s"\n'),
    ("config.ratelimit", 16, UP + R + 'path_prefix = "/a"\nrate_limit = "5/s"\nrate_key = "header:X-Key"\nrate_buckets = 65532\n' + R + 'path_prefix = "/b"\nrate_limit = "5/s"\nrate_key = "header:X-Key"\nrate_buckets = 8\n'),
    ("config.routes", None, UP + "".join('[[route]]\nupstream = "a"\npath_prefix = "/r%d"\n' % i for i in range(257))),
]

# Accepted: a host-specific route beside a host-less one on the same prefix, and the same prefix with disjoint methods.
ACCEPTED = [
    UP + R + 'path_prefix = "/"\nhost = "a.example"\n' + R + 'path_prefix = "/"\n',
    UP + R + 'path_prefix = "/x"\nmethods = ["GET"]\n' + R + 'path_prefix = "/x"\nmethods = ["POST"]\n',
    UP + R + 'path_prefix = "/x"\nhost = "a.example"\n' + R + 'path_prefix = "/x"\nhost = "b.example"\n',
    # WebSocket: the flag alone, then every key and every bound
    WS + WSR,
    WS + 'ws_idle_timeout_ms = 100\nws_max_lifetime_ms = 100\nws_max_tunnels = 1\n' + WSR,
    WS + 'ws_idle_timeout_ms = 86400000\nws_max_lifetime_ms = 2592000000\nws_max_tunnels = 127\n' + WSR,
    UP + R + 'path_prefix = "/ocpp"\nwebsocket = true\nmethods = ["GET", "POST"]\nsubprotocols = ["ocpp1.6", "ocpp2.0.1"]\norigins = []\n',
    UP + R + 'path_prefix = "/ws"\nwebsocket = true\nsubprotocols = [%s]\norigins = [%s]\n' % (", ".join('"p%d"' % i for i in range(8)), ", ".join('"http://h%d.example:3000"' % i for i in range(16))),
    UP + R + 'path_prefix = "/ws"\nwebsocket = false\n',
    # rate limiting: the shortest form, every unit, every bound, every key
    UP + R + 'path_prefix = "/"\nrate_limit = "1/s"\n',
    UP + R + 'path_prefix = "/"\nrate_limit = "10/m"\nrate_burst = 2\n',
    UP + R + 'path_prefix = "/"\nrate_limit = "1000000/h"\nrate_burst = 1000000\nrate_key = "route"\n',
    UP + R + 'path_prefix = "/"\nrate_limit = "5/s"\nrate_key = "header:X-Api-Key"\n',
    UP + R + 'path_prefix = "/"\nrate_limit = "5/s"\nrate_key = "header:Authorization"\nrate_buckets = 4\n',
    UP + R + 'path_prefix = "/"\nrate_limit = "5/s"\nrate_key = "header:X-Api-Key"\nrate_buckets = 65536\n',
    UP + R + 'path_prefix = "/"\ntrust_forwarded = true\nrate_limit = "5/s"\nrate_key = "xff:last"\n',
    UP + R + 'path_prefix = "/"\ntrust_forwarded = true\nrate_limit = "5/s"\nrate_key = "xff:first"\nrate_buckets = 2048\n',
    UP + R + 'path_prefix = "/"\ntrust_forwarded = true\nrate_limit = "5/s"\nrate_key = "header:X-Real-IP"\n',
    UP + R + 'path_prefix = "/a"\nrate_limit = "5/s"\nrate_key = "header:X-Key"\nrate_buckets = 65532\n' + R + 'path_prefix = "/b"\nrate_limit = "5/s"\nrate_key = "route"\n',
    # TLS: the directory alone, then identities and every bound
    'listen = 80\ntls_listen = 443\ntls_dir = "/etc/cancho/tls"\n[[upstream]]\nname = "a"\naddr = "10.0.0.1:1"\n[[route]]\nupstream = "a"\npath_prefix = "/"\n',
    # TLS only: no plain listener at all, with and without the admin one
    'tls_listen = 443\ntls_dir = "/etc/cancho/tls"\n[[upstream]]\nname = "a"\naddr = "10.0.0.1:1"\n[[route]]\nupstream = "a"\npath_prefix = "/"\n',
    'tls_listen = 443\nadmin_listen = 9090\ntls_dir = "/etc/cancho/tls"\ntls_identities = ["api"]\n[[upstream]]\nname = "a"\naddr = "10.0.0.1:1"\n[[route]]\nupstream = "a"\npath_prefix = "/"\n',
    'listen = 80\nadmin_listen = 9090\ntls_listen = 443\ntls_dir = "/srv/tls-1.2_x"\ntls_identities = ["a.example", "b-2"]\ntls_handshakes = 1000\ntls_rate = 100000\ntls_handshake_ms = 100\n[[upstream]]\nname = "a"\naddr = "10.0.0.1:1"\n[[route]]\nupstream = "a"\npath_prefix = "/"\n',
]


def run(text, *extra):
    with tempfile.NamedTemporaryFile("w", suffix=".toml", delete=False) as f:
        f.write(text)
    out = subprocess.run([sys.executable, str(ROOT / "scripts" / "generate.py"), f.name, "--explain", *extra],
                         capture_output=True, text=True)
    pathlib.Path(f.name).unlink()
    return out


def main():
    failures = 0
    for addrs, want in PREFIX:
        got = generate.intended_prefix(addrs)
        if got != want:
            print("FAIL prefix %s: got %r, want %r" % (addrs, got, want))
            failures += 1
    for rule, line, text in REFUSALS:
        out = run(text)
        try:
            answer = json.loads(out.stderr)
        except ValueError:
            answer = {}
        if out.returncode != 2 or answer.get("rule") != rule or (line is not None and answer.get("line") != line):
            print("FAIL refusal %s at line %s: exit %d, %r" % (rule, line, out.returncode, out.stderr.strip()[:140]))
            failures += 1
    for text in ACCEPTED:
        out = run(text)
        if out.returncode != 0:
            print("FAIL accepted deployment refused: %r" % out.stderr.strip()[:140])
            failures += 1
    # The hint for a misspelt key, and byte-stable refusal output (the same file, twice).
    with tempfile.NamedTemporaryFile("w", suffix=".toml", delete=False) as f:
        f.write(UP + R + 'path_pref = "/"\n')
    cmd = [sys.executable, str(ROOT / "scripts" / "generate.py"), f.name, "--explain"]
    first, second = (subprocess.run(cmd, capture_output=True, text=True).stderr for _ in range(2))
    pathlib.Path(f.name).unlink()
    if json.loads(first).get("hint") != "did you mean 'path_prefix'?" or first != second:
        print("FAIL the hint for a misspelt key, or the refusal is not byte-stable: %r" % first.strip())
        failures += 1
    # What a TLS-only deployment compiles: no plain port (0), the TLS port, and a report that says so.
    tls_only = 'tls_listen = 8443\ntls_dir = "/etc/cancho/tls"\n[[upstream]]\nname = "a"\naddr = "10.0.0.1:1"\n[[route]]\nupstream = "a"\npath_prefix = "/"\n'
    with tempfile.TemporaryDirectory() as tmp:
        f = pathlib.Path(tmp) / "d.toml"
        f.write_text(tls_only)
        subprocess.run([sys.executable, str(ROOT / "scripts" / "generate.py"), str(f), "--out", tmp], check=True)
        deploy = (pathlib.Path(tmp) / "deploy.cho").read_text()
        explained = run(tls_only).stdout
    if "pub fn listen_port() -> [] int {\n    return 0;\n}" not in deploy or "pub fn tls_port() -> [] int {\n    return 8443;\n}" not in deploy:
        print("FAIL a TLS-only deployment must compile listen_port() = 0 and tls_port() = 8443")
        failures += 1
    if not explained.startswith("listen none (TLS only);"):
        print("FAIL --explain must say a TLS-only deployment has no plain listener: %r" % explained[:60])
        failures += 1
    # What a rate limit compiles (docs/ratelimit.md section 4): the record's six fields, the lowercased header name, the bases of the tables, the total.
    limited = (UP + R + 'path_prefix = "/a"\nrate_limit = "10/m"\nrate_burst = 3\nrate_key = "header:X-API-Key"\nrate_buckets = 64\n' + R + 'path_prefix = "/b"\n' + R +
               'path_prefix = "/c"\ntrust_forwarded = true\nrate_limit = "7/s"\nrate_key = "xff:last"\n' + R + 'path_prefix = "/d"\nrate_limit = "2/h"\n')
    with tempfile.TemporaryDirectory() as tmp:
        f = pathlib.Path(tmp) / "d.toml"
        f.write_text(limited)
        subprocess.run([sys.executable, str(ROOT / "scripts" / "generate.py"), str(f), "--out", tmp], check=True)
        table = (pathlib.Path(tmp) / "routes.cho").read_text()
        explained = run(limited).stdout
    for want in ("\\t10\\t60000\\t3\\th:x-api-key\\t64\\t0\\n", "\\t0\\t0\\t0\\t\\t0\\t64\\n", "\\t7\\t1000\\t7\\tx:l\\t1024\\t64\\n", "\\t2\\t3600000\\t2\\tr\\t1\\t1088\\n",
                 "pub fn rate_buckets_total() -> [] int {\n    return 1089;"):
        if want not in table:
            print("FAIL the routes table must contain %r" % want)
            failures += 1
    if "limit 10 per 60000 ms, burst 3, key h:x-api-key, 64 bucket(s)" not in explained:
        print("FAIL --explain must say what a route's limit is: %r" % explained[-300:])
        failures += 1
    print("%d prefix cases, %d refusal cases, %d accepted, %d failures" % (len(PREFIX), len(REFUSALS), len(ACCEPTED), failures))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
