#!/usr/bin/env python3
"""Table tests of scripts/generate.py: the prefix rule, and one refusal per rule tag."""

import hashlib
import json
import pathlib
import re
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
    # --- WebSocket frames (docs/websocket-frames.md section 10): the message limit per route, and the keepalive and close keys
    ("config.websocket", 8, UP + R + 'path_prefix = "/"\nws_max_message_bytes = 65536\n'),
    ("config.websocket", 9, UP + R + 'path_prefix = "/"\nwebsocket = true\nws_max_message_bytes = 1023\n'),
    ("config.websocket", 9, UP + R + 'path_prefix = "/"\nwebsocket = true\nws_max_message_bytes = 268435457\n'),
    ("config.websocket", 9, UP + R + 'path_prefix = "/"\nwebsocket = true\nws_max_message_bytes = 0\n'),
    ("config.websocket", 9, UP + R + 'path_prefix = "/"\nwebsocket = true\nws_max_message_bytes = -5\n'),
    ("config.websocket", 9, UP + R + 'path_prefix = "/"\nwebsocket = true\nws_max_message_bytes = "64k"\n'),
    ("config.websocket", 9, UP + R + 'path_prefix = "/"\nwebsocket = true\nws_max_message_bytes = true\n'),
    ("config.websocket", 9, UP + R + 'path_prefix = "/"\nwebsocket = true\nws_max_message_bytes = 65536.5\n'),
    ("config.websocket", 2, 'listen = 80\nws_ping_ms = 5000\n[[upstream]]\nname="a"\naddr="10.0.0.1:1"\n' + R + 'path_prefix = "/"\n'),
    ("config.websocket", 2, 'listen = 80\nws_close_ms = 5000\n[[upstream]]\nname="a"\naddr="10.0.0.1:1"\n' + R + 'path_prefix = "/"\n'),
    ("config.websocket", 2, 'listen = 80\nws_pong_ms = 5000\n[[upstream]]\nname="a"\naddr="10.0.0.1:1"\n' + R + 'path_prefix = "/"\n'),
    ("config.websocket", 2, WS + 'ws_ping_ms = 999\n' + WSR),
    ("config.websocket", 2, WS + 'ws_ping_ms = 86400001\n' + WSR),
    ("config.websocket", 2, WS + 'ws_ping_ms = -1\n' + WSR),
    ("config.websocket", 2, WS + 'ws_ping_ms = "30s"\n' + WSR),
    ("config.websocket", 2, WS + 'ws_ping_ms = true\n' + WSR),
    ("config.websocket", 2, WS + 'ws_pong_ms = 5000\n' + WSR),
    ("config.websocket", 3, WS + 'ws_ping_ms = 5000\nws_pong_ms = 99\n' + WSR),
    ("config.websocket", 3, WS + 'ws_ping_ms = 5000\nws_pong_ms = 600001\n' + WSR),
    ("config.websocket", 3, WS + 'ws_ping_ms = 5000\nws_pong_ms = "10s"\n' + WSR),
    ("config.websocket", 2, WS + 'ws_close_ms = 99\n' + WSR),
    ("config.websocket", 2, WS + 'ws_close_ms = 60001\n' + WSR),
    ("config.websocket", 2, WS + 'ws_close_ms = "5s"\n' + WSR),
    ("config.websocket", 2, WS + 'ws_close_ms = false\n' + WSR),
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

# --- rate limiting, slice 2 (docs/ratelimit.md section 13, rules 9 to 14, and rule 8 with the ceiling's bucket): (key the answer names, line, deployment text). The route's keys begin at line 8.
RK = UP + R + 'path_prefix = "/"\nrate_limit = "5/s"\nrate_key = "header:X-Key"\n'
RX = UP + R + 'path_prefix = "/"\ntrust_forwarded = true\nrate_limit = "5/s"\nrate_key = "xff:last"\n'
RATE2 = [
    # 9: rate_route_limit is not N/s, N/m or N/h with N in 1..1,000,000
    ("rate_route_limit", 10, RK + 'rate_route_limit = 100\n'),
    ("rate_route_limit", 10, RK + 'rate_route_limit = "100"\n'),
    ("rate_route_limit", 10, RK + 'rate_route_limit = "100/d"\n'),
    ("rate_route_limit", 10, RK + 'rate_route_limit = "0/s"\n'),
    ("rate_route_limit", 10, RK + 'rate_route_limit = "007/s"\n'),
    ("rate_route_limit", 10, RK + 'rate_route_limit = "1000001/s"\n'),
    ("rate_route_limit", 10, RK + 'rate_route_limit = " 5/s"\n'),
    ("rate_route_limit", 10, RK + 'rate_route_limit = "-5/s"\n'),
    ("rate_route_limit", 10, RK + 'rate_route_limit = true\n'),
    ("rate_route_limit", 10, RK + 'rate_route_limit = ""\n'),
    # 10: rate_route_burst is not an integer in 1..1,000,000
    ("rate_route_burst", 11, RK + 'rate_route_limit = "50/s"\nrate_route_burst = 0\n'),
    ("rate_route_burst", 11, RK + 'rate_route_limit = "50/s"\nrate_route_burst = 1000001\n'),
    ("rate_route_burst", 11, RK + 'rate_route_limit = "50/s"\nrate_route_burst = -1\n'),
    ("rate_route_burst", 11, RK + 'rate_route_limit = "50/s"\nrate_route_burst = "5"\n'),
    ("rate_route_burst", 11, RK + 'rate_route_limit = "50/s"\nrate_route_burst = true\n'),
    ("rate_route_burst", 11, RK + 'rate_route_limit = "50/s"\nrate_route_burst = 5.0\n'),
    # 11: rate_route_burst without rate_route_limit, or either without rate_limit
    ("rate_route_burst", 10, RK + 'rate_route_burst = 5\n'),
    ("rate_route_limit", 8, UP + R + 'path_prefix = "/"\nrate_route_limit = "5/s"\n'),
    ("rate_route_burst", 8, UP + R + 'path_prefix = "/"\nrate_route_burst = 5\n'),
    ("rate_route_limit", 8, UP + R + 'path_prefix = "/"\nrate_route_limit = "5/s"\nrate_route_burst = 5\n'),
    # 12: rate_route_limit with a route key (the default, or written): the one bucket already is the ceiling
    ("rate_route_limit", 9, UP + R + 'path_prefix = "/"\nrate_limit = "5/s"\nrate_route_limit = "50/s"\n'),
    ("rate_route_limit", 10, UP + R + 'path_prefix = "/"\nrate_limit = "5/s"\nrate_key = "route"\nrate_route_limit = "50/s"\n'),
    ("rate_route_limit", 10, UP + R + 'path_prefix = "/"\nrate_limit = "5/s"\nrate_burst = 9\nrate_route_limit = "50/s"\n'),
    # 13: rate_xff_prefix is not an integer in 1..128
    ("rate_xff_prefix", 11, RX + 'rate_xff_prefix = 0\n'),
    ("rate_xff_prefix", 11, RX + 'rate_xff_prefix = 129\n'),
    ("rate_xff_prefix", 11, RX + 'rate_xff_prefix = -1\n'),
    ("rate_xff_prefix", 11, RX + 'rate_xff_prefix = "64"\n'),
    ("rate_xff_prefix", 11, RX + 'rate_xff_prefix = true\n'),
    ("rate_xff_prefix", 11, RX + 'rate_xff_prefix = 64.0\n'),
    ("rate_xff_prefix", 11, RX + 'rate_xff_prefix = 4294967296\n'),
    # 14: rate_xff_prefix without an xff key
    ("rate_xff_prefix", 10, RK + 'rate_xff_prefix = 64\n'),
    ("rate_xff_prefix", 9, UP + R + 'path_prefix = "/"\nrate_limit = "5/s"\nrate_xff_prefix = 64\n'),
    ("rate_xff_prefix", 10, UP + R + 'path_prefix = "/"\nrate_limit = "5/s"\nrate_key = "route"\nrate_xff_prefix = 64\n'),
    ("rate_xff_prefix", 8, UP + R + 'path_prefix = "/"\nrate_xff_prefix = 64\n'),
    ("rate_xff_prefix", 11, UP + R + 'path_prefix = "/"\ntrust_forwarded = true\nrate_limit = "5/s"\nrate_key = "header:X-Real-IP"\nrate_xff_prefix = 64\n'),
    # 8, with the ceiling's bucket: 65,532 and one is 65,533, and a second route of 4 and its ceiling is 5 more
    ("rate_route_limit", 18, UP + R + 'path_prefix = "/a"\nrate_limit = "5/s"\nrate_key = "header:X-Key"\nrate_buckets = 65532\nrate_route_limit = "50/s"\n' +
     R + 'path_prefix = "/b"\nrate_limit = "5/s"\nrate_key = "header:X-Key"\nrate_buckets = 4\nrate_route_limit = "50/s"\n'),
    ("rate_route_limit", 11, UP + R + 'path_prefix = "/a"\nrate_limit = "5/s"\nrate_key = "header:X-Key"\nrate_buckets = 65536\nrate_route_limit = "50/s"\n'),
    # 65,528 and a ceiling is 65,529 and seven route keys make exactly 65,536 (accepted, in RATE2_ACCEPTED); an eighth makes 65,537, and is the route named
    ("rate_limit", 43, UP + R + 'path_prefix = "/a"\nrate_limit = "5/s"\nrate_key = "header:X-Key"\nrate_buckets = 65528\nrate_route_limit = "50/s"\n' +
     "".join(R + 'path_prefix = "/r%d"\nrate_limit = "5/s"\n' % i for i in range(8))),
]
RATE2_ACCEPTED = [
    # the ceiling beside every key form, with and without its burst
    RK + 'rate_route_limit = "50/s"\n',
    RK + 'rate_route_limit = "1/h"\nrate_route_burst = 1\n',
    RK + 'rate_route_limit = "1000000/h"\nrate_route_burst = 1000000\n',
    RK + 'rate_route_limit = "50/m"\nrate_route_burst = 3\nrate_buckets = 4\n',
    RX + 'rate_route_limit = "50/s"\n',
    UP + R + 'path_prefix = "/"\ntrust_forwarded = true\nrate_limit = "5/s"\nrate_key = "xff:first"\nrate_route_limit = "50/s"\nrate_route_burst = 9\nrate_xff_prefix = 48\n',
    # every bound of the prefix
    RX + 'rate_xff_prefix = 1\n',
    RX + 'rate_xff_prefix = 64\n',
    RX + 'rate_xff_prefix = 128\n',
    UP + R + 'path_prefix = "/"\ntrust_forwarded = true\nrate_limit = "5/s"\nrate_key = "xff:first"\nrate_xff_prefix = 56\n',
    # exactly 65,536 buckets in all: 65,528 and the ceiling's, and seven route keys
    UP + R + 'path_prefix = "/a"\nrate_limit = "5/s"\nrate_key = "header:X-Key"\nrate_buckets = 65528\nrate_route_limit = "50/s"\n' +
    "".join(R + 'path_prefix = "/r%d"\nrate_limit = "5/s"\n' % i for i in range(7)),
    UP + R + 'path_prefix = "/a"\nrate_limit = "5/s"\nrate_key = "header:X-Key"\nrate_buckets = 65532\nrate_route_limit = "50/s"\n' +
    "".join(R + 'path_prefix = "/r%d"\nrate_limit = "5/s"\n' % i for i in range(3)),
]
REFUSALS += [("config.ratelimit", line, text) for _, line, text in RATE2]

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
    # WebSocket frames: the message limit at both bounds, the keepalive off, at both bounds, the pong and the close wait at theirs
    UP + R + 'path_prefix = "/ws"\nwebsocket = true\nws_max_message_bytes = 1024\n',
    UP + R + 'path_prefix = "/ws"\nwebsocket = true\nws_max_message_bytes = 268435456\n',
    WS + 'ws_ping_ms = 0\n' + WSR,
    WS + 'ws_ping_ms = 1000\nws_pong_ms = 100\nws_close_ms = 100\n' + WSR,
    WS + 'ws_ping_ms = 86400000\nws_pong_ms = 600000\nws_close_ms = 60000\n' + WSR,
    WS + 'ws_close_ms = 5000\n' + WSR,
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

ACCEPTED += RATE2_ACCEPTED


# --- authentication (docs/auth.md section 6): one refusal per rule, plus the variants of each
D1 = hashlib.sha256(b"ck_alpha").hexdigest()
D2 = hashlib.sha256(b"ck_bravo").hexdigest()
TOP = 'listen = 80\nauth_allow_plain = true\n'          # lines 1 and 2
ONE = '[[upstream]]\nname = "a"\naddr = "10.0.0.1:1"\n'
K1 = '[[api_key]]\nname = "alice"\nsha256 = "%s"\n' % D1
K2 = '[[api_key]]\nname = "bob"\nsha256 = "%s"\n' % D2
AR = '[[route]]\nupstream = "a"\npath_prefix = "/"\nauth = "api-key"\n'
BASE = TOP + ONE + K1 + K2          # keys at lines 6 to 8 (alice) and 9 to 11 (bob)


def at(text, marker, last=False):
    """The line of the first (or last) line of `text` that contains `marker`."""
    found = [n for n, line in enumerate(text.splitlines(), 1) if marker in line]
    return found[-1 if last else 0]


def auth_refusal(rule, marker, text, last=False):
    return (rule, at(text, marker, last), text)


def auth_cases():
    out = []
    # 1: the name
    for name in ('"Alice"', '""', '"%s"' % ("a" * 33), "5", '"al ice"', '"-alice"', '"alice@x"'):
        out.append(auth_refusal("config.auth", "name = ", TOP + ONE + '[[api_key]]\nname = %s\nsha256 = "%s"\n' % (name, D1) + AR, last=True))
    out.append(auth_refusal("config.auth", "[[api_key]]", TOP + ONE + '[[api_key]]\nsha256 = "%s"\n' % D1 + AR))
    # 2: a name twice
    out.append(auth_refusal("config.auth", 'name = "alice"', TOP + ONE + K1 + '[[api_key]]\nname = "alice"\nsha256 = "%s"\n' % D2 + AR, last=True))
    # 3: the digest
    for digest in ('"%s"' % D1[:63], '"%s"' % (D1 + "0"), '"%s"' % D1.upper(), '"%s"' % ("g" + D1[1:]), '""', "5", '"%s"' % ("0x" + D1[2:]), '"%s "' % D1, '[1]'):
        out.append(auth_refusal("config.auth", "sha256", TOP + ONE + '[[api_key]]\nname = "alice"\nsha256 = %s\n' % digest + AR))
    out.append(auth_refusal("config.auth", "[[api_key]]", TOP + ONE + '[[api_key]]\nname = "alice"\n' + AR))
    # 4: the same digest under two names
    out.append(auth_refusal("config.auth", "sha256", TOP + ONE + K1 + '[[api_key]]\nname = "bob"\nsha256 = "%s"\n' % D1 + AR, last=True))
    # 5: more than 64 keys (and exactly 64 is accepted, below)
    many = "".join('[[api_key]]\nname = "k%d"\nsha256 = "%s"\n' % (i, hashlib.sha256(b"ck_%d" % i).hexdigest()) for i in range(65))
    out.append(("config.auth", None, TOP + ONE + many + AR))
    # 6: the kind
    for kind in ('"jwt"', "true", '"API-KEY"', '""', "1"):
        out.append(auth_refusal("config.auth", "auth = ", TOP + ONE + K1 + '[[route]]\nupstream = "a"\npath_prefix = "/"\nauth = %s\n' % kind))
    # 7: auth_* without auth
    for extra in ('auth_header = "X-Api-Key"\n', 'auth_keys = ["alice"]\n', "auth_forward = true\n"):
        out.append(auth_refusal("config.auth", extra.split(" =")[0], TOP + ONE + K1 + '[[route]]\nupstream = "a"\npath_prefix = "/"\n' + extra))
    # 8: the header
    for header in ("Host", "Connection", "Content-Length", "Transfer-Encoding", "Proxy-Authorization", "Upgrade", "TE", "X-Forwarded-For", "Forwarded", "X-Real-IP", "X-Request-Id",
                   "X Key", "", "x" * 65, "Bad:Name", "naïve"):
        out.append(auth_refusal("config.auth", "auth_header", TOP + ONE + K1 + AR + 'auth_header = "%s"\n' % header))
    out.append(auth_refusal("config.auth", "auth_header", TOP + ONE + K1 + AR + "auth_header = 5\n"))
    # 9: the key list
    for keys in ("[]", '["nobody"]', '["alice", "alice"]', '"alice"', "[1]", '["alice", "nobody"]', '["Alice"]'):
        out.append(auth_refusal("config.auth", "auth_keys", TOP + ONE + K1 + AR + "auth_keys = %s\n" % keys))
    # 10: forwarding the credential
    for value in ('"yes"', "1", '"true"'):
        out.append(auth_refusal("config.auth", "auth_forward", TOP + ONE + K1 + AR + "auth_forward = %s\n" % value))
    # 11: auth and no key at all
    out.append(auth_refusal("config.auth", "auth = ", TOP + ONE + AR))
    # 12: keys and no route that authenticates
    out.append(auth_refusal("config.auth", "[[api_key]]", TOP + ONE + K1 + '[[route]]\nupstream = "a"\npath_prefix = "/"\n'))
    # 13: a key on a plain listener unless the deployment says a front terminates TLS
    out.append(auth_refusal("config.auth", "auth = ", 'listen = 80\n' + ONE + K1 + AR))
    out.append(auth_refusal("config.auth", "auth = ", 'listen = 80\nauth_allow_plain = false\n' + ONE + K1 + AR))
    out.append(auth_refusal("config.auth", "auth = ", 'listen = 80\ntls_listen = 443\ntls_dir = "/etc/cancho/tls"\n' + ONE + K1 + AR))
    # 14: the flag itself
    for value in ('"yes"', "1"):
        out.append(auth_refusal("config.auth", "auth_allow_plain", 'listen = 80\nauth_allow_plain = %s\n' % value + ONE + K1 + AR))
    out.append(auth_refusal("config.auth", "auth_allow_plain", 'tls_listen = 443\ntls_dir = "/etc/cancho/tls"\nauth_allow_plain = true\n' + ONE + K1 + AR))
    out.append(auth_refusal("config.auth", "auth_allow_plain", TOP + ONE + '[[route]]\nupstream = "a"\npath_prefix = "/"\n'))
    # 15: the identity as a rate-limit key needs an identity
    out.append(auth_refusal("config.ratelimit", "rate_key", TOP + ONE + K1 + '[[route]]\nupstream = "a"\npath_prefix = "/"\nrate_limit = "5/s"\nrate_key = "auth"\n'))
    # 16: the identities must fit the table: five keys cannot all have a bucket in a table of four, so one could be refused limit.rate-table
    five = "".join('[[api_key]]\nname = "k%d"\nsha256 = "%s"\n' % (i, hashlib.sha256(b"ck_%d" % i).hexdigest()) for i in range(5))
    out.append(auth_refusal("config.ratelimit", "rate_buckets", TOP + ONE + five + AR + 'rate_limit = "5/s"\nrate_key = "auth"\nrate_buckets = 4\n'))
    # (the same with the names that the gateway's hash puts together: five names in two sets of four, all in one; this pins the generator's copy of the hash)
    out.append(auth_refusal("config.ratelimit", "rate_buckets", TOP + ONE + five + AR + 'rate_limit = "5/s"\nrate_key = "auth"\nrate_buckets = 8\n'))
    # an unknown key of [[api_key]] is named like any other
    out.append(auth_refusal("config.unknown-key", "colour", TOP + ONE + K1 + 'colour = "red"\n' + AR))
    return out


def auth_accepted():
    sixty_four = "".join('[[api_key]]\nname = "k%d"\nsha256 = "%s"\n' % (i, hashlib.sha256(b"ck_%d" % i).hexdigest()) for i in range(64))
    tls = 'tls_listen = 443\ntls_dir = "/etc/cancho/tls"\n'
    return [
        TOP + ONE + K1 + AR,
        TOP + ONE + K1 + K2 + AR + 'auth_header = "X-Api-Key"\nauth_keys = ["bob"]\nauth_forward = true\n',
        TOP + ONE + K1 + K2 + AR + 'auth_header = "authorization"\nauth_keys = ["bob", "alice"]\nauth_forward = false\nrate_limit = "5/s"\nrate_key = "auth"\nrate_buckets = 4\n',
        TOP + ONE + K1 + K2 + AR + 'auth_header = "X-Custom_Key.1"\n',
        TOP + ONE + sixty_four + AR,
        TOP + ONE + K1 + AR + '[[route]]\nupstream = "a"\npath_prefix = "/open"\n',
        # an identity as the rate key: four keys fit a table of four, a route that admits four of five fits one too, and 64 keys fit a table of 4,096
        TOP + ONE + "".join('[[api_key]]\nname = "k%d"\nsha256 = "%s"\n' % (i, hashlib.sha256(b"ck_%d" % i).hexdigest()) for i in range(4)) + AR + 'rate_limit = "5/s"\nrate_key = "auth"\nrate_buckets = 4\n',
        TOP + ONE + "".join('[[api_key]]\nname = "k%d"\nsha256 = "%s"\n' % (i, hashlib.sha256(b"ck_%d" % i).hexdigest()) for i in range(5)) + AR + 'auth_keys = ["k0", "k1", "k2", "k3"]\nrate_limit = "5/s"\nrate_key = "auth"\nrate_buckets = 4\n',
        TOP + ONE + sixty_four + AR + 'rate_limit = "5/s"\nrate_key = "auth"\nrate_buckets = 4096\n',
        # TLS only: a key never crosses a plain listener, and no flag is needed (or allowed)
        tls + ONE + K1 + AR,
        'listen = 80\nauth_allow_plain = true\n' + tls + ONE + K1 + AR,
        TOP + ONE + K1 + AR + 'websocket = true\ntrust_forwarded = true\nrate_limit = "5/s"\nrate_key = "header:X-Real-IP"\n',
    ]


REFUSALS += auth_cases()
ACCEPTED += auth_accepted()


# --- JWT (docs/jwt.md section 8): rules 17 to 30, one refusal per rule plus the variants of each
import jwtkit  # noqa: E402

PKA = jwtkit.b64u(jwtkit.public_key(bytes(range(32))))
PKB = jwtkit.b64u(jwtkit.public_key(bytes(range(1, 33))))
JK1 = '[[jwt_key]]\nname = "ka"\npublic_key = "%s"\n' % PKA
JK2 = '[[jwt_key]]\nname = "kb"\npublic_key = "%s"\n' % PKB
JR = '[[route]]\nupstream = "a"\npath_prefix = "/"\nauth = "jwt"\n'


def curve_points():
    """The torsion points of Ed25519 (the eight whose order divides 8), found by clearing the prime-order part of points taken from small y's, and a y with no point."""
    torsion, off_curve = {}, None
    for y in range(2, 80):
        raw = y.to_bytes(32, "little")
        point = jwtkit.decompress(raw)
        if point is None:
            off_curve = off_curve or raw
            continue
        t = jwtkit.mul(jwtkit.Q, point)
        torsion[jwtkit.compress(t)] = True
    identity = jwtkit.compress(jwtkit.IDENTITY)
    torsion[identity] = True
    torsion[((1 << 255) - 20).to_bytes(32, "little")] = True       # y = -1: order 2
    torsion[bytes(32)] = True                                       # y = 0: order 4
    torsion[bytes(31) + b"\x80"] = True
    return sorted(torsion), off_curve


TORSION, OFF_CURVE = curve_points()


def jwt_refusal(rule, marker, text, last=False):
    return (rule, at(text, marker, last), text)


def jkey(name, key):
    return '[[jwt_key]]\nname = %s\npublic_key = %s\n' % (name, key)


def jwt_cases():
    out = []
    base = TOP + ONE
    # 17: the name (also not another key's name)
    for name in ('"Alice"', '"a b"', '""', '"-x"', "5", '"%s"' % ("x" * 33), '"k/1"'):
        out.append(jwt_refusal("config.auth", "name = ", base + jkey(name, '"%s"' % PKA) + JR, last=True))
    out.append(jwt_refusal("config.auth", "[[jwt_key]]", base + '[[jwt_key]]\npublic_key = "%s"\n' % PKA + JR))
    out.append(jwt_refusal("config.auth", 'name = "ka"', base + JK1 + jkey('"ka"', '"%s"' % PKB) + JR, last=True))
    out.append(jwt_refusal("config.auth", 'name = "alice"', base + K1 + jkey('"alice"', '"%s"' % PKA) + JR + AR, last=True))
    # 18: the encoding of the public key
    good = PKA
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    noncanon = good[:-1] + alphabet[alphabet.index(good[-1]) ^ 1]       # the same 32 bytes, spelt with a non-zero spare bit
    assert jwtkit.unb64u(noncanon) == jwtkit.unb64u(good) and noncanon != good
    for bad in ('"%s"' % good[:-1], '"%s"' % (good + "A"), '"%s="' % good[:-1], '"%s+"' % good[:-1], '"%s/"' % good[:-1], '"%s"' % noncanon, "5", '""',
                '"%s"' % ("A" * 43 + " "), '"%s"' % (good[:20] + " " + good[21:]), '"%s"' % jwtkit.b64u(bytes(range(31)))[:43]):
        out.append(jwt_refusal("config.auth", "public_key", base + jkey('"ka"', bad) + JR))
    out.append(jwt_refusal("config.auth", "[[jwt_key]]", base + '[[jwt_key]]\nname = "ka"\n' + JR))
    # 19: not a point, and the points of small order (a signature by them verifies for every message)
    out.append(jwt_refusal("config.auth", "public_key", base + jkey('"ka"', '"%s"' % jwtkit.b64u(OFF_CURVE)) + JR))
    for t in TORSION:
        assert jwtkit.decompress(t) is None or jwtkit.small_order(jwtkit.decompress(t)), t.hex()
        if jwtkit.decompress(t) is not None:
            out.append(jwt_refusal("config.auth", "public_key", base + jkey('"ka"', '"%s"' % jwtkit.b64u(t)) + JR))
    # 20: one verifier, two names
    out.append(jwt_refusal("config.auth", "public_key", base + JK1 + jkey('"kb"', '"%s"' % PKA) + JR, last=True))
    # 21: more than 8 keys
    many = "".join(jkey('"k%d"' % i, '"%s"' % jwtkit.b64u(jwtkit.public_key(bytes([i + 1]) * 32))) for i in range(9))
    out.append(("config.auth", None, base + many + JR))
    # 22: the kind
    for kind in ('"oauth"', '"JWT"', '"api_key"', "[]", '["jwt", "jwt"]', '["jwt", "x"]', "5", "true", '["api-key", "api-key"]'):
        out.append(jwt_refusal("config.auth", "auth = ", base + K1 + JK1 + '[[route]]\nupstream = "a"\npath_prefix = "/"\nauth = %s\n' % kind))
    # 23: jwt_* without jwt, auth_keys without api-key
    for extra in ('jwt_alg = "EdDSA"\n', 'jwt_keys = ["ka"]\n', 'jwt_aud = "api"\n', 'jwt_iss = "https://i.example"\n', "jwt_leeway = 5\n"):
        out.append(jwt_refusal("config.auth", extra.split(" =")[0], base + K1 + JK1 + AR + extra + JR.replace('path_prefix = "/"', 'path_prefix = "/j"')))
        out.append(jwt_refusal("config.auth", extra.split(" =")[0], base + K1 + JK1 + '[[route]]\nupstream = "a"\npath_prefix = "/"\n' + extra + JR.replace('path_prefix = "/"', 'path_prefix = "/j"')))
    out.append(jwt_refusal("config.auth", "auth_keys", base + K1 + JK1 + JR + 'auth_keys = ["alice"]\n' + AR.replace('path_prefix = "/"', 'path_prefix = "/a"')))
    # 24: the algorithm: one, EdDSA, never from the token
    for alg in ('"none"', '"None"', '"HS256"', '"hs256"', '"HS512"', '"RS256"', '"ES256"', '"eddsa"', '"EdDSA "', '"Ed25519"', "5", "true", '["EdDSA"]', '""'):
        out.append(jwt_refusal("config.auth", "jwt_alg", base + JK1 + JR + "jwt_alg = %s\n" % alg))
    # 25: the key list
    for keys in ("[]", '["nokey"]', '["ka", "ka"]', '"ka"', "[5]", '["KA"]'):
        out.append(jwt_refusal("config.auth", "jwt_keys", base + JK1 + JR + "jwt_keys = %s\n" % keys))
    # 26: the audience and the issuer
    for key in ("jwt_aud", "jwt_iss"):
        for value in ('""', "5", "true", '["a"]', "'a\"b'", "'a\\\\b'", '"%s"' % ("x" * 97), '"a\\tb"', '"café"', '"a\\nb"', '"\\u007f"'):
            out.append(jwt_refusal("config.auth", key, base + JK1 + JR + "%s = %s\n" % (key, value)))
    # 27: the leeway
    for value in ("61", "-1", "1.5", '"5"', "true", "1000000", "[5]"):
        out.append(jwt_refusal("config.auth", "jwt_leeway", base + JK1 + JR + "jwt_leeway = %s\n" % value))
    # 28: keys that protect nothing, and a route nobody can enter
    out.append(jwt_refusal("config.auth", "[[jwt_key]]", base + JK1 + '[[route]]\nupstream = "a"\npath_prefix = "/"\n'))
    out.append(jwt_refusal("config.auth", "[[jwt_key]]", base + K1 + JK1 + AR))
    out.append(jwt_refusal("config.auth", "auth = ", base + JR))
    out.append(jwt_refusal("config.auth", "auth = ", base + K1 + '[[route]]\nupstream = "a"\npath_prefix = "/"\nauth = ["api-key", "jwt"]\n'))
    out.append(jwt_refusal("config.auth", "auth = ", base + JK1 + '[[route]]\nupstream = "a"\npath_prefix = "/"\nauth = ["api-key", "jwt"]\n'))
    # 29: a token is a Bearer token
    for header in ("X-Token", "x-api-key", "Proxy-Authorization"):
        out.append(jwt_refusal("config.auth", "auth_header", base + JK1 + JR + 'auth_header = "%s"\n' % header))
    out.append(jwt_refusal("config.auth", "auth_header", base + K1 + JK1 + '[[route]]\nupstream = "a"\npath_prefix = "/"\nauth = ["api-key", "jwt"]\nauth_header = "X-Api-Key"\n'))
    # 30: no identity to key a rate limit on
    out.append(jwt_refusal("config.ratelimit", "rate_key", base + JK1 + JR + 'rate_limit = "5/s"\nrate_key = "auth"\n'))
    out.append(jwt_refusal("config.ratelimit", "rate_key", base + K1 + JK1 + '[[route]]\nupstream = "a"\npath_prefix = "/"\nauth = ["api-key", "jwt"]\nrate_limit = "5/s"\nrate_key = "auth"\n'))
    # the plain listener: a token crosses it as a key does (rule 13)
    out.append(jwt_refusal("config.auth", "auth = ", 'listen = 80\n' + ONE + JK1 + JR))
    out.append(jwt_refusal("config.auth", "auth = ", 'listen = 80\nauth_allow_plain = false\n' + ONE + JK1 + JR))
    # an unknown key of [[jwt_key]] is named like any other, and a misspelt table name too
    out.append(jwt_refusal("config.unknown-key", "colour", base + JK1 + 'colour = "red"\n' + JR))
    out.append(jwt_refusal("config.unknown-key", "jwt_alg_x", base + JK1 + JR + 'jwt_alg_x = "EdDSA"\n'))
    return out


def jwt_accepted():
    tls = 'tls_listen = 443\ntls_dir = "/etc/cancho/tls"\n'
    eight = "".join(jkey('"k%d"' % i, '"%s"' % jwtkit.b64u(jwtkit.public_key(bytes([i + 1]) * 32))) for i in range(8))
    return [
        TOP + ONE + JK1 + JR,
        TOP + ONE + JK1 + JK2 + JR + 'jwt_alg = "EdDSA"\njwt_keys = ["kb"]\njwt_aud = "https://api.example.com"\njwt_iss = "https://issuer.example.com"\njwt_leeway = 5\nauth_forward = true\n',
        TOP + ONE + JK1 + JR + 'jwt_leeway = 0\n',
        TOP + ONE + JK1 + JR + 'jwt_leeway = 60\n',
        TOP + ONE + JK1 + JR + 'auth_header = "authorization"\n',
        TOP + ONE + JK1 + JR + 'jwt_aud = "%s"\njwt_iss = " !#[]~"\n' % ("x" * 96),
        TOP + ONE + eight + JR,
        TOP + ONE + K1 + JK1 + '[[route]]\nupstream = "a"\npath_prefix = "/"\nauth = ["api-key", "jwt"]\njwt_aud = "api"\nauth_keys = ["alice"]\n',
        TOP + ONE + K1 + JK1 + '[[route]]\nupstream = "a"\npath_prefix = "/"\nauth = ["jwt", "api-key"]\n',
        TOP + ONE + K1 + JK1 + AR + JR.replace('path_prefix = "/"', 'path_prefix = "/j"'),
        TOP + ONE + JK1 + JR + 'rate_limit = "5/s"\nrate_key = "route"\n',
        TOP + ONE + JK1 + JR + 'trust_forwarded = true\nrate_limit = "5/s"\nrate_key = "xff:last"\n',
        TOP + ONE + JK1 + JR + 'websocket = true\n',
        tls + ONE + JK1 + JR,
        'listen = 80\nauth_allow_plain = true\n' + tls + ONE + JK1 + JR,
        TOP + ONE + JK1 + JR + '[[route]]\nupstream = "a"\npath_prefix = "/open"\n',
    ]


REFUSALS += jwt_cases()
ACCEPTED += jwt_accepted()


def jwt_compiled(run, failures):
    """What JWT acceptance compiles (docs/jwt.md section 8): the key table, the route's record, and what --explain says."""
    text = (TOP + ONE + K1 + JK1 + JK2 + JR + 'jwt_keys = ["kb"]\njwt_aud = "api"\njwt_iss = "https://i.example"\njwt_leeway = 7\n' +
            '[[route]]\nupstream = "a"\npath_prefix = "/both"\nauth = ["api-key", "jwt"]\n' + '[[route]]\nupstream = "a"\npath_prefix = "/key"\nauth = "api-key"\n' +
            '[[route]]\nupstream = "a"\npath_prefix = "/c"\n')
    with tempfile.TemporaryDirectory() as tmp:
        f = pathlib.Path(tmp) / "d.toml"
        f.write_text(text)
        subprocess.run([sys.executable, str(ROOT / "scripts" / "generate.py"), str(f), "--out", tmp], check=True)
        table = (pathlib.Path(tmp) / "routes.cho").read_text()
        explained = run(text).stdout
    wants = ["pub fn jwt_key_count() -> [] int {\n    return 2;", 'return "ka\\t%s\\nkb\\t%s\\n";' % (PKA, PKB),
             '\\t2\\tauthorization\\t0\\t\\tBearer realm=\\"cancho-gateway\\"\\t1\\tapi\\thttps://i.example\\t7\\t1048576\\t0\\t0\\t0\\t0\\t0\\n',
             '\\t3\\tauthorization\\t0\\t*\\tBearer realm=\\"cancho-gateway\\"\\t*\\t\\t\\t0\\t1048576\\t0\\t0\\t0\\t0\\t0\\n',
             '\\t1\\tauthorization\\t0\\t*\\tBearer realm=\\"cancho-gateway\\"\\t\\t\\t\\t0\\t1048576\\t0\\t0\\t0\\t0\\t0\\n',
             '\\t0\\t\\t0\\t\\t\\t\\t\\t\\t0\\t1048576\\t0\\t0\\t0\\t0\\t0\\n']
    for want in wants:
        if want not in table:
            print("FAIL the routes table must contain %r" % want)
            failures += 1
    for want in ("accepts jwt (EdDSA): keys kb, audience 'api', issuer 'https://i.example', leeway 7 s", "accepts jwt (EdDSA): keys all, audience not checked, issuer not checked, leeway 0 s; an API key too",
                 "jwt keys: ka, kb (public keys compiled in)", "jwt only"):
        if want not in explained:
            print("FAIL --explain must say %r: %r" % (want, explained[-500:]))
            failures += 1
    # The public keys are compiled in, and nothing else of a key is: there is no private half in the file to compile.
    seed = bytes(range(32))
    if jwtkit.b64u(seed) in table or seed.hex() in table:
        print("FAIL a seed must not be written")
        failures += 1
    return failures


def mkjwt_checks(failures):
    """scripts/mkjwt.py (docs/jwt.md section 8): the seed is on standard error only, the public key is the seed's, nothing is written, a token it signs verifies under jwtkit and
    under OpenSSL where `cryptography` is installed, and the output is a deployment the generator accepts."""
    script = str(ROOT / "scripts" / "mkjwt.py")
    with tempfile.TemporaryDirectory() as tmp:
        before = sorted(p.name for p in pathlib.Path(tmp).iterdir())
        made = subprocess.run([sys.executable, script, "keygen", "issuer-a"], capture_output=True, text=True, cwd=tmp)
        again = subprocess.run([sys.executable, script, "keygen", "issuer-a"], capture_output=True, text=True, cwd=tmp)
        after = sorted(p.name for p in pathlib.Path(tmp).iterdir())
    m = re.search(r"([A-Za-z0-9_-]{43})\s*$", made.stderr)
    if made.returncode != 0 or not m:
        print("FAIL mkjwt keygen must print the seed (43 characters of base64url) on standard error: %r" % made.stderr)
        return failures + 1
    seed_text = m.group(1)
    seed = jwtkit.unb64u(seed_text)
    want = '[[jwt_key]]\nname = "issuer-a"\npublic_key = "%s"\n' % jwtkit.b64u(jwtkit.public_key(seed))
    if made.stdout != want:
        print("FAIL mkjwt keygen must print the table with the public key on standard output: %r" % made.stdout)
        failures += 1
    if seed_text in made.stdout or before != after:
        print("FAIL mkjwt keygen must not put the seed on standard output nor write a file")
        failures += 1
    other = re.search(r"([A-Za-z0-9_-]{43})\s*$", again.stderr)
    if not other or other.group(1) == seed_text:
        print("FAIL two seeds must differ")
        failures += 1
    if seed[8:] == bytes(24) or len(seed) != 32:
        print("FAIL a seed must be 32 random bytes, not padded")
        failures += 1
    # The signer against the standard vectors: RFC 8032 section 7.1 test 1 (the empty message) and RFC 8037 appendix A.4 (the JWS of "Example of Ed25519 signing").
    rfc_seed = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
    rfc_jws = jwtkit.compact(None, None, rfc_seed, raw_header=b'{"alg":"EdDSA"}', raw_payload=b"Example of Ed25519 signing")
    if jwtkit.sign(rfc_seed, b"").hex()[:32] != "e5564300c360ac729086e2cc806e828a" or rfc_jws != ("eyJhbGciOiJFZERTQSJ9.RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmc."
                                                                                                "hgyY0il_MGCjP0JzlnLWG1PPOt7-09PGcvMg3AIbQR6dWbhijcNR4ki4iylGjg5BhVsPt9g7sVvpAr_MuM0KAg"):
        print("FAIL jwtkit must reproduce the RFC 8032 and RFC 8037 signatures")
        failures += 1
    signed = subprocess.run([sys.executable, script, "sign", "--kid", "issuer-a", "--aud", "api", "--iss", "https://i.example", "--ttl", "60"], input=seed_text + "\n", capture_output=True, text=True)
    token = signed.stdout.strip()
    if signed.returncode != 0 or signed.stderr or token.count(".") != 2:
        print("FAIL mkjwt sign must print a token and nothing on standard error: %r %r" % (signed.stdout, signed.stderr))
        return failures + 1
    h, p, s = token.split(".")
    header, payload = json.loads(jwtkit.unb64u(h)), json.loads(jwtkit.unb64u(p))
    if header != {"alg": "EdDSA", "typ": "JWT", "kid": "issuer-a"} or payload["aud"] != "api" or payload["iss"] != "https://i.example" or not 0 < payload["exp"] - __import__("time").time() <= 60:
        print("FAIL mkjwt sign made the wrong token: %r %r" % (header, payload))
        failures += 1
    if not jwtkit.verify(jwtkit.public_key(seed), (h + "." + p).encode(), jwtkit.unb64u(s)):
        print("FAIL a token mkjwt signs must verify")
        failures += 1
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        Ed25519PublicKey.from_public_bytes(jwtkit.public_key(seed)).verify(jwtkit.unb64u(s), (h + "." + p).encode())
    except ImportError:
        pass
    except Exception as e:   # noqa: BLE001
        print("FAIL OpenSSL must verify a token mkjwt signs: %r" % e)
        failures += 1
    for args, text in ((["keygen", "Issuer"], ""), (["keygen"], ""), (["sign"], "has space"), (["sign"], ""), (["sign", "--bogus"], seed_text), (["sign"], seed_text[:-1]), ([], ""), (["nope"], "")):
        bad = subprocess.run([sys.executable, script, *args], input=text, capture_output=True, text=True)
        if bad.returncode != 2 or bad.stdout:
            print("FAIL mkjwt %r must be refused with exit 2 and print nothing on standard output: %r" % (args, bad.stdout))
            failures += 1
    out = run(TOP + ONE + made.stdout + JR)
    if out.returncode != 0:
        print("FAIL a deployment with mkjwt's table must be accepted: %r" % out.stderr)
        failures += 1
    return failures


def frames_compiled(run, failures):
    """What the frame keys compile (docs/websocket-frames.md section 10): the route's message limit in the table, the three deployment-wide values, and what --explain says."""
    text = (WS + 'ws_ping_ms = 30000\nws_pong_ms = 5000\nws_close_ms = 2500\n' + WSR + 'ws_max_message_bytes = 65536\n' + '[[route]]\nupstream = "a"\npath_prefix = "/b"\nwebsocket = true\n' +
            '[[route]]\nupstream = "a"\npath_prefix = "/c"\n')
    with tempfile.TemporaryDirectory() as tmp:
        f = pathlib.Path(tmp) / "d.toml"
        f.write_text(text)
        subprocess.run([sys.executable, str(ROOT / "scripts" / "generate.py"), str(f), "--out", tmp], check=True)
        table = (pathlib.Path(tmp) / "routes.cho").read_text()
        deploy = (pathlib.Path(tmp) / "deploy.cho").read_text()
        explained = run(text).stdout
    for want in ("\\t65536\\t0\\t0\\t0\\t0\\t0\\n", "\\t1048576\\t0\\t0\\t0\\t0\\t0\\n"):
        if want not in table:
            print("FAIL the routes table must contain %r" % want)
            failures += 1
    for want in ("pub fn ws_ping_ms() -> [] int {\n    return 30000;", "pub fn ws_pong_ms() -> [] int {\n    return 5000;", "pub fn ws_close_ms() -> [] int {\n    return 2500;"):
        if want not in deploy:
            print("FAIL the deployment module must contain %r" % want)
            failures += 1
    for want in ("a silent client is pinged after 30000 ms and closed if no Pong in 5000 ms", "a Close is answered within 2500 ms", "messages up to 65536 bytes"):
        if want not in explained:
            print("FAIL --explain must say %r: %r" % (want, explained[:600]))
            failures += 1
    # the defaults: no keepalive, 10 s to answer one if it is turned on, 5 s for a Close
    plain = WS + WSR
    with tempfile.TemporaryDirectory() as tmp:
        f = pathlib.Path(tmp) / "d.toml"
        f.write_text(plain)
        subprocess.run([sys.executable, str(ROOT / "scripts" / "generate.py"), str(f), "--out", tmp], check=True)
        deploy = (pathlib.Path(tmp) / "deploy.cho").read_text()
        explained = run(plain).stdout
    for want in ("pub fn ws_ping_ms() -> [] int {\n    return 0;", "pub fn ws_pong_ms() -> [] int {\n    return 10000;", "pub fn ws_close_ms() -> [] int {\n    return 5000;"):
        if want not in deploy:
            print("FAIL the defaults must compile %r" % want)
            failures += 1
    if "no keepalive Ping" not in explained:
        print("FAIL --explain must say there is no keepalive by default: %r" % explained[:400])
        failures += 1
    return failures


def auth_compiled(run, failures):
    """What authentication compiles (docs/auth.md sections 4.1 and 6): the key table, the route's record, and what --explain says."""
    text = (TOP + ONE + K1 + K2 + AR + 'auth_header = "X-Api-Key"\nauth_keys = ["bob"]\n' + '[[route]]\nupstream = "a"\npath_prefix = "/b"\nauth = "api-key"\nrate_limit = "5/s"\nrate_key = "auth"\nrate_buckets = 8\n' +
            '[[route]]\nupstream = "a"\npath_prefix = "/c"\n')
    with tempfile.TemporaryDirectory() as tmp:
        f = pathlib.Path(tmp) / "d.toml"
        f.write_text(text)
        subprocess.run([sys.executable, str(ROOT / "scripts" / "generate.py"), str(f), "--out", tmp], check=True)
        table = (pathlib.Path(tmp) / "routes.cho").read_text()
        explained = run(text).stdout
    keys = '"alice\\t%s\\nbob\\t%s\\n"' % (D1, D2)
    wants = ["pub fn key_count() -> [] int {\n    return 2;", "return " + keys + ";",
             '\\t1\\tx-api-key\\t0\\t1\\tApiKey realm=\\"cancho-gateway\\", header=\\"x-api-key\\"\\t\\t\\t\\t0\\t1048576\\t0\\t0\\t0\\t0\\t0\\n',
             '\\ta\\t8\\t0\\t1\\tauthorization\\t0\\t*\\tBearer realm=\\"cancho-gateway\\"\\t\\t\\t\\t0\\t1048576\\t0\\t0\\t0\\t0\\t0\\n',
             '\\t0\\t\\t0\\t\\t\\t\\t\\t\\t0\\t1048576\\t0\\t0\\t0\\t0\\t0\\n']
    for want in wants:
        if want not in table:
            print("FAIL the routes table must contain %r" % want)
            failures += 1
    for want in ("authenticates with the x-api-key header, keys bob", "authenticates with the authorization header, keys all", "api keys: alice, bob (digests only compiled in)",
                 "auth_allow_plain"):
        if want not in explained:
            print("FAIL --explain must say %r: %r" % (want, explained[-400:]))
            failures += 1
    # A deployment without keys compiles an empty table, and the digests are the only trace of a key: no key, only its digest, is in what was written.
    if "ck_alpha" in table:
        print("FAIL a key must not be written")
        failures += 1
    return failures


def run(text, *extra):
    with tempfile.NamedTemporaryFile("w", suffix=".toml", delete=False) as f:
        f.write(text)
    out = subprocess.run([sys.executable, str(ROOT / "scripts" / "generate.py"), f.name, "--explain", *extra],
                         capture_output=True, text=True)
    pathlib.Path(f.name).unlink()
    return out


def mkkey_checks(failures):
    """scripts/mkkey.py (docs/auth.md section 5): the key is on standard error only, the digest is the key's, nothing is written, the output is a deployment the generator accepts."""
    script = str(ROOT / "scripts" / "mkkey.py")
    with tempfile.TemporaryDirectory() as tmp:
        before = sorted(p.name for p in pathlib.Path(tmp).iterdir())
        made = subprocess.run([sys.executable, script, "carol"], capture_output=True, text=True, cwd=tmp)
        again = subprocess.run([sys.executable, script, "carol"], capture_output=True, text=True, cwd=tmp)
        after = sorted(p.name for p in pathlib.Path(tmp).iterdir())
    m = re.search(r"(ck_[A-Za-z0-9_-]{43})\s*$", made.stderr)
    if made.returncode != 0 or not m:
        print("FAIL mkkey must print a ck_ key of 43 characters on standard error: %r" % made.stderr)
        return failures + 1
    key = m.group(1)
    want = '[[api_key]]\nname = "carol"\nsha256 = "%s"\n' % hashlib.sha256(key.encode()).hexdigest()
    if made.stdout != want:
        print("FAIL mkkey must print the table with the key's SHA-256 on standard output: %r" % made.stdout)
        failures += 1
    if key in made.stdout or before != after:
        print("FAIL mkkey must not put the key on standard output nor write a file")
        failures += 1
    other = re.search(r"(ck_[A-Za-z0-9_-]{43})\s*$", again.stderr)
    if not other or other.group(1) == key:
        print("FAIL two keys must differ")
        failures += 1
    hashed = subprocess.run([sys.executable, script, "carol", "--stdin"], input=key + "\n", capture_output=True, text=True)
    if hashed.returncode != 0 or hashed.stdout != want or hashed.stderr:
        print("FAIL mkkey --stdin must print the same table and nothing on standard error: %r %r" % (hashed.stdout, hashed.stderr))
        failures += 1
    for args, text in ((["Carol"], ""), (["carol", "--stdin"], "has space"), (["carol", "--stdin"], ""), (["carol", "--bogus"], ""), ([], "")):
        bad = subprocess.run([sys.executable, script, *args], input=text, capture_output=True, text=True)
        if bad.returncode != 2 or bad.stdout:
            print("FAIL mkkey %r must be refused with exit 2 and print nothing on standard output: %r" % (args, bad.stdout))
            failures += 1
    # The output goes into a deployment the generator accepts, and the gateway's credential rule accepts the key.
    out = run(TOP + ONE + made.stdout + AR)
    if out.returncode != 0:
        print("FAIL a deployment with mkkey's table must be accepted: %r" % out.stderr)
        failures += 1
    return failures


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
    for key, line, text in RATE2:
        out = run(text)
        try:
            answer = json.loads(out.stderr)
        except ValueError:
            answer = {}
        if out.returncode != 2 or answer.get("rule") != "config.ratelimit" or answer.get("key") != key or answer.get("line") != line:
            print("FAIL rate refusal naming %s at line %s: exit %d, %r" % (key, line, out.returncode, out.stderr.strip()[:200]))
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
               'path_prefix = "/c"\ntrust_forwarded = true\nrate_limit = "7/s"\nrate_key = "xff:last"\n' + R + 'path_prefix = "/d"\nrate_limit = "2/h"\n' + R +
               'path_prefix = "/e"\ntrust_forwarded = true\nrate_limit = "3/s"\nrate_key = "xff:first"\nrate_buckets = 8\nrate_route_limit = "30/m"\nrate_route_burst = 7\nrate_xff_prefix = 56\n')
    with tempfile.TemporaryDirectory() as tmp:
        f = pathlib.Path(tmp) / "d.toml"
        f.write_text(limited)
        subprocess.run([sys.executable, str(ROOT / "scripts" / "generate.py"), str(f), "--out", tmp], check=True)
        table = (pathlib.Path(tmp) / "routes.cho").read_text()
        explained = run(limited).stdout
    for want in ("\\t10\\t60000\\t3\\th:x-api-key\\t64\\t0\\t0\\t\\t0\\t\\t\\t\\t\\t\\t0\\t1048576\\t0\\t0\\t0\\t0\\t0\\n", "\\t0\\t0\\t0\\t\\t0\\t64\\t0\\t\\t0\\t\\t\\t\\t\\t\\t0\\t1048576\\t0\\t0\\t0\\t0\\t0\\n", "\\t7\\t1000\\t7\\tx:l\\t1024\\t64\\t0\\t\\t0\\t\\t\\t\\t\\t\\t0\\t1048576\\t0\\t0\\t0\\t0\\t64\\n", "\\t2\\t3600000\\t2\\tr\\t1\\t1088\\t0\\t\\t0\\t\\t\\t\\t\\t\\t0\\t1048576\\t0\\t0\\t0\\t0\\t0\\n",
                 # a ceiling of 30 a minute with room for 7, in the bucket after the route's 8 (1089 + 8), and a prefix of 56
                 "\\t3\\t1000\\t3\\tx:f\\t8\\t1089\\t0\\t\\t0\\t\\t\\t\\t\\t\\t0\\t1048576\\t30\\t60000\\t7\\t1097\\t56\\n",
                 "pub fn rate_buckets_total() -> [] int {\n    return 1098;"):
        if want not in table:
            print("FAIL the routes table must contain %r" % want)
            failures += 1
    if "ceiling 30 per 60000 ms, burst 7" not in explained or "ipv6 prefix /56" not in explained:
        print("FAIL --explain must say a route's ceiling and its IPv6 prefix: %r" % explained[-400:])
        failures += 1
    if "limit 10 per 60000 ms, burst 3, key h:x-api-key, 64 bucket(s)" not in explained:
        print("FAIL --explain must say what a route's limit is: %r" % explained[-300:])
        failures += 1
    failures = frames_compiled(run, failures)
    failures = auth_compiled(run, failures)
    failures = mkkey_checks(failures)
    failures = jwt_compiled(run, failures)
    failures = mkjwt_checks(failures)
    print("%d prefix cases, %d refusal cases, %d accepted, %d failures" % (len(PREFIX), len(REFUSALS), len(ACCEPTED), failures))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
