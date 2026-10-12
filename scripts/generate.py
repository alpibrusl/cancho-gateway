#!/usr/bin/env python3
"""The deployment generator (tasks #11 and #4, docs/design.md section 2, docs/routes.md).

    python3 scripts/generate.py deploy/example.toml            # write generated/deploy.cho and generated/routes.cho
    python3 scripts/generate.py deploy/example.toml --check    # change nothing; exit 1 if either is stale
    python3 scripts/generate.py deploy/example.toml --explain  # print what it admits, change nothing
    python3 scripts/generate.py deploy/example.toml --out DIR  # write the two modules into DIR instead

Every refusal is one line of JSON on stderr, {"file","hint","key","line","message","rule"} (sorted keys, so the output is
byte-stable), and exit code 2: a refused deployment is not a stale file. A refusal names the file, the line and the key
where it can, and offers the nearest valid key for a misspelt one.
"""

import difflib
import json
import pathlib
import re
import sys
import tomllib

ROOT = pathlib.Path(__file__).resolve().parent.parent
MAX_UPSTREAMS = 256
MAX_ROUTES = 256
MAX_PREFIX = 255
MAX_HOST = 253
MAX_BODY = 1 << 30
# Milliseconds: the head must arrive, the upstream must connect, the upstream must start answering, the whole request must end.
TIMEOUTS = {"header_timeout_ms": 10000, "connect_timeout_ms": 5000, "upstream_timeout_ms": 30000, "total_timeout_ms": 60000,
            "idle_timeout_ms": 5000}
# Idle upstream connections kept per upstream; 0 turns pooling off (every request then opens and closes its own connection).
POOL_IDLE_MAX = 4
POOL_RANGE = (0, 64)
# The passive circuit: this many consecutive failures to an upstream (0 turns the circuit off) stop requests to it for the open period.
CIRCUIT_THRESHOLD = 5
CIRCUIT_THRESHOLD_RANGE = (0, 1000)
CIRCUIT_OPEN_MS = 10000
TIMEOUT_RANGE = (100, 600000)
DEFAULT_BODY = 1 << 20
# TLS (docs/tls.md): handshakes in progress at once, handshakes started a second, milliseconds to finish one; up to 16 identities.
TLS_HANDSHAKES, TLS_HANDSHAKES_RANGE = 32, (1, 1000)
TLS_RATE, TLS_RATE_RANGE = 50, (1, 100000)  # a handshake measured 12 ms of this gateway's CPU on the development machine (docs/tls.md section 10): 50 a second is about 60% of a core
TLS_HANDSHAKE_MS = 10000
MAX_IDENTITIES = 16
ENTROPY_FILE = "/dev/urandom"
# WebSocket (docs/websocket.md section 3): idle and lifetime of a tunnel in milliseconds, and how many upgrades may be in progress or open at once
# (a session holds two of the table's 256 slots, so no more than 127 sessions exist).
WS_IDLE_MS, WS_IDLE_RANGE = 600000, (100, 86400000)
WS_LIFETIME_MS, WS_LIFETIME_RANGE = 86400000, (100, 2592000000)
WS_MAX_TUNNELS, WS_TUNNELS_RANGE = 64, (1, 127)
MAX_SUBPROTOCOLS = 8
# Rate limiting (docs/ratelimit.md section 4): tokens per period (N/s, N/m, N/h), bucket size, buckets per route and in all (three 8-byte ints each: at most 1.5 MiB).
RATE_MAX, BURST_MAX = 1000000, 1000000
RATE_PERIODS = {"s": 1000, "m": 60000, "h": 3600000}
BUCKETS, BUCKETS_RANGE, BUCKETS_TOTAL = 1024, (4, 65536), 65536
# Headers a rate_key may not name: the hop-by-hop ones and the framing and routing ones (the gateway removes or owns them), and, unless the route trusts
# forwarding claims, the claims themselves.
RATE_REFUSED_HEADERS = ["connection", "keep-alive", "proxy-connection", "proxy-authorization", "te", "trailer", "upgrade", "content-length", "transfer-encoding", "host"]
RATE_CLAIM_HEADERS = ["forwarded", "x-forwarded-for", "x-forwarded-host", "x-forwarded-proto", "x-forwarded-port", "x-real-ip"]
MAX_ORIGINS = 16
# Authentication (docs/auth.md section 6): at most this many API keys in a deployment, each a short name (what the access log calls the caller) and the SHA-256
# digest of the key as 64 lowercase hexadecimal digits; the credential header a route reads, and the headers it may not name.
MAX_KEYS = 64
KEY_NAME = re.compile(r"[a-z0-9][a-z0-9._-]{0,31}")
KEY_DIGEST = re.compile(r"[0-9a-f]{64}")
AUTH_REFUSED_HEADERS = RATE_REFUSED_HEADERS + RATE_CLAIM_HEADERS + ["x-request-id"]
TOKEN = re.compile(r"[!#$%&'*+.^_`|~0-9A-Za-z-]{1,64}")
ORIGIN = re.compile(r"[a-z][a-z0-9+.-]*://[a-z0-9.-]+(:[0-9]{1,5})?")
METHODS = ["GET", "HEAD", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"]
KEYS = {
    "": ["listen", "header_timeout_ms", "connect_timeout_ms", "upstream_timeout_ms", "total_timeout_ms", "idle_timeout_ms", "pool_idle_max", "circuit_threshold", "circuit_open_ms", "log_failure", "admin_listen",
           "tls_listen", "tls_dir", "tls_identities", "tls_handshakes", "tls_rate", "tls_handshake_ms",
           "ws_idle_timeout_ms", "ws_max_lifetime_ms", "ws_max_tunnels", "auth_allow_plain"],
    "upstream": ["name", "addr"],
    "api_key": ["name", "sha256"],
    "route": ["name", "host", "path_prefix", "methods", "upstream", "max_body", "trust_forwarded", "websocket", "subprotocols", "origins",
              "rate_limit", "rate_burst", "rate_key", "rate_buckets", "auth", "auth_header", "auth_keys", "auth_forward"],
}


class Refusal(Exception):
    def __init__(self, rule, message, line=None, key=None, hint=None):
        super().__init__(message)
        self.rule, self.line, self.key, self.hint = rule, line, key, hint


def scan(text):
    """Where each key is: {(section, index, key): line}, and where each table starts: {(section, index): line}."""
    keys, starts = {}, {}
    section, index = "", 0
    counts = {"upstream": 0, "route": 0, "api_key": 0}
    for number, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        m = re.fullmatch(r"\[\[([A-Za-z_][A-Za-z0-9_-]*)\]\]", line)
        if m:
            section = m.group(1)
            index = counts.get(section, 0)
            counts[section] = index + 1
            starts[(section, index)] = number
            continue
        m = re.match(r"([A-Za-z_][A-Za-z0-9_-]*)\s*=", line)
        if m and not raw.startswith((" ", "\t")):
            keys[(section, index, m.group(1))] = number
    return keys, starts


def host_port(addr):
    m = re.fullmatch(r"([A-Za-z0-9.-]+):([0-9]{1,5})", addr)
    if not m or not 1 <= int(m.group(2)) <= 65535 or m.group(1).startswith((".", "-")):
        return None
    return m.group(1), int(m.group(2))


def intended_prefix(addrs):
    """The longest common prefix of the addresses, cut back to the last '.' or ':' so that it cannot admit a host the
    addresses do not (10.0.1.5 and 10.0.1.50 share '10.0.1.5', which would admit 10.0.1.5x). A single upstream is its
    full host:port. The empty string means no shared prefix."""
    if len(addrs) == 1:
        return addrs[0]
    common = addrs[0]
    for a in addrs[1:]:
        n = 0
        while n < min(len(common), len(a)) and common[n] == a[n]:
            n += 1
        common = common[:n]
    cut = max(common.rfind("."), common.rfind(":"))
    return common[:cut + 1] if cut >= 0 else ""


def valid_prefix(p):
    """A route prefix: starts with '/', no trailing '/' except the root alone, no '//', no dot segments, no '%', no
    control or non-ASCII byte, no backslash. (A request path is judged by the same rules at run time: route.path.)"""
    if not 1 <= len(p) <= MAX_PREFIX or not p.startswith("/"):
        return False
    if p != "/" and p.endswith("/"):
        return False
    if "//" in p or "%" in p or "\\" in p or any(ord(c) <= 0x20 or ord(c) >= 0x7f for c in p):
        return False
    return not any(seg in (".", "..") for seg in p.split("/"))


def rate_options(r, trust, has_auth, refuse, i):
    """The rate-limit keys of one route (docs/ratelimit.md section 4), checked; answers the fields of its record. `refuse(rule, message, section,
    index, key)` raises."""
    none = {"rate": 0, "per_ms": 0, "burst": 0, "rate_key": "", "buckets": 0}
    if "rate_limit" not in r:
        for key in ("rate_burst", "rate_key", "rate_buckets"):
            if key in r:
                refuse("config.ratelimit", "%s needs rate_limit on the same route (docs/ratelimit.md section 4)" % key, "route", i, key)
        return none

    def bad(message, key):
        refuse("config.ratelimit", message, "route", i, key)

    limit = r["rate_limit"]
    m = re.fullmatch(r"([1-9][0-9]{0,6})/([smh])", limit) if isinstance(limit, str) else None
    if not m or int(m.group(1)) > RATE_MAX:
        bad('rate_limit must be a string "N/s", "N/m" or "N/h" with N an integer in 1..%d (docs/ratelimit.md section 4)' % RATE_MAX, "rate_limit")
    rate, per_ms = int(m.group(1)), RATE_PERIODS[m.group(2)]
    burst = r.get("rate_burst", rate)
    if not isinstance(burst, int) or isinstance(burst, bool) or not 1 <= burst <= BURST_MAX:
        bad("rate_burst must be an integer in 1..%d" % BURST_MAX, "rate_burst")
    spec = r.get("rate_key", "route")
    key = None
    if isinstance(spec, str):
        if spec == "route":
            key = "r"
        elif spec == "auth":
            key = "a"
        elif spec in ("xff:last", "xff:first"):
            key = "x:l" if spec == "xff:last" else "x:f"
        elif spec.startswith("header:") and TOKEN.fullmatch(spec[7:]):
            key = "h:" + spec[7:].lower()
    if key is None:
        bad('rate_key must be "route", "auth", "xff:last", "xff:first" or "header:<Name>" with a header name of 1 to 64 token bytes', "rate_key")
    if key == "a" and not has_auth:
        bad('rate_key = "auth" keys on the authenticated identity: the route needs auth (docs/auth.md section 9)', "rate_key")
    if key.startswith("h:") and key[2:] in RATE_REFUSED_HEADERS:
        bad("rate_key names %s, which the gateway removes or owns: a limit keyed on it is no limit" % spec[7:], "rate_key")
    if (key.startswith("x:") or key.startswith("h:") and key[2:] in RATE_CLAIM_HEADERS) and not trust:
        bad("rate_key %s keys on a forwarding claim: it needs trust_forwarded = true on the route (docs/headers.md section 2)" % spec, "rate_key")
    if key == "r":
        if "rate_buckets" in r:
            bad('rate_buckets has no meaning with rate_key = "route": a route key has exactly one bucket', "rate_buckets")
        buckets = 1
    else:
        buckets = r.get("rate_buckets", BUCKETS)
        if not isinstance(buckets, int) or isinstance(buckets, bool) or not BUCKETS_RANGE[0] <= buckets <= BUCKETS_RANGE[1] or buckets % 4:
            bad("rate_buckets must be an integer, a multiple of 4, in %d..%d" % BUCKETS_RANGE, "rate_buckets")
    return {"rate": rate, "per_ms": per_ms, "burst": burst, "rate_key": key, "buckets": buckets}


def auth_options(r, key_names, refuse, i):
    """The authentication keys of one route (docs/auth.md section 6), checked; answers the fields of its record. `refuse(rule, message, section, index, key)` raises."""
    none = {"auth": 0, "auth_header": "", "auth_forward": 0, "auth_keys": "", "challenge": ""}
    if "auth" not in r:
        for key in ("auth_header", "auth_keys", "auth_forward"):
            if key in r:
                refuse("config.auth", "%s needs auth on the same route (docs/auth.md section 6)" % key, "route", i, key)
        return none

    def bad(message, key):
        refuse("config.auth", message, "route", i, key)

    if r["auth"] != "api-key":
        bad('auth must be "api-key": the only kind in this slice (docs/auth.md section 6)', "auth")
    header = r.get("auth_header", "Authorization")
    if not isinstance(header, str) or not TOKEN.fullmatch(header):
        bad("auth_header must be a header name: a token of 1 to 64 bytes", "auth_header")
    if header.lower() in AUTH_REFUSED_HEADERS:
        bad("auth_header names %s, which the gateway removes, owns or replaces: it could never carry a key" % header, "auth_header")
    allowed = r.get("auth_keys")
    if allowed is not None:
        if not isinstance(allowed, list) or not allowed or len(set(map(str, allowed))) != len(allowed) or not all(isinstance(n, str) and n in key_names for n in allowed):
            bad("auth_keys must be a non-empty list of distinct [[api_key]] names" + (" (declared: %s)" % ", ".join(key_names) if key_names else ""), "auth_keys")
    forward = r.get("auth_forward", False)
    if not isinstance(forward, bool):
        bad("auth_forward must be true or false (docs/auth.md section 3)", "auth_forward")
    lower = header.lower()
    if lower == "authorization":
        challenge = 'Bearer realm="cancho-gateway"'
    else:
        challenge = 'ApiKey realm="cancho-gateway", header="%s"' % lower
    return {"auth": 1, "auth_header": lower, "auth_forward": 1 if forward else 0,
            "auth_keys": "*" if allowed is None else ",".join(str(key_names.index(n)) for n in allowed), "challenge": challenge}


def load(path):
    try:
        text = pathlib.Path(path).read_text()
        doc = tomllib.loads(text)
    except (OSError, UnicodeDecodeError) as e:
        raise Refusal("config.read", "cannot read %s: %s" % (path, e))
    except tomllib.TOMLDecodeError as e:
        m = re.search(r"\(at line (\d+)", str(e))
        raise Refusal("config.read", "cannot parse %s: %s" % (path, e), line=int(m.group(1)) if m else None)
    keys, starts = scan(text)

    def at(section, index, key=None):
        return keys.get((section, index, key)) if key else starts.get((section, index), 1)

    def refuse(rule, message, section="", index=0, key=None, hint=None):
        raise Refusal(rule, message, line=at(section, index, key) or at(section, index), key=key, hint=hint)

    def unknown_keys(section, index, table):
        for k in table:
            if k not in KEYS[section]:
                near = difflib.get_close_matches(k, KEYS[section], n=1)
                refuse("config.unknown-key", "unknown key %r%s" % (k, " in [[%s]]" % section if section else ""),
                       section, index, k, "did you mean %r?" % near[0] if near else "valid keys: " + ", ".join(KEYS[section]))

    for k, v in doc.items():
        if k not in KEYS[""] and k not in ("upstream", "route", "api_key"):
            near = difflib.get_close_matches(k, KEYS[""] + ["upstream", "route", "api_key"], n=1)
            raise Refusal("config.unknown-key", "unknown key or table %r" % k, line=keys.get(("", 0, k), 1), key=k,
                          hint="did you mean %r?" % near[0] if near else None)
    unknown_keys("", 0, {k: v for k, v in doc.items() if k not in ("upstream", "route", "api_key")})
    # `listen` is optional so that a deployment can serve TLS only (docs/tls.md section 11): 0 means no plain listener. At least one of `listen` and
    # `tls_listen` is required (checked once `tls_listen` is read, below).
    listen = doc.get("listen", 0)
    if "listen" in doc and (not isinstance(listen, int) or isinstance(listen, bool) or not 1 <= listen <= 65535):
        refuse("config.listen", "listen must be a port in 1..65535", key="listen")
    timeouts = {}
    for key, default in TIMEOUTS.items():
        v = doc.get(key, default)
        if not isinstance(v, int) or isinstance(v, bool) or not TIMEOUT_RANGE[0] <= v <= TIMEOUT_RANGE[1]:
            refuse("config.timeout", "%s must be an integer in %d..%d milliseconds" % ((key,) + TIMEOUT_RANGE), key=key)
        timeouts[key] = v
    pool = doc.get("pool_idle_max", POOL_IDLE_MAX)
    if not isinstance(pool, int) or isinstance(pool, bool) or not POOL_RANGE[0] <= pool <= POOL_RANGE[1]:
        refuse("config.pool", "pool_idle_max must be an integer in %d..%d (0 turns pooling off)" % POOL_RANGE, key="pool_idle_max")
    timeouts["pool_idle_max"] = pool
    threshold = doc.get("circuit_threshold", CIRCUIT_THRESHOLD)
    if not isinstance(threshold, int) or isinstance(threshold, bool) or not CIRCUIT_THRESHOLD_RANGE[0] <= threshold <= CIRCUIT_THRESHOLD_RANGE[1]:
        refuse("config.circuit", "circuit_threshold must be an integer in %d..%d (0 turns the circuit off)" % CIRCUIT_THRESHOLD_RANGE, key="circuit_threshold")
    timeouts["circuit_threshold"] = threshold
    open_ms = doc.get("circuit_open_ms", CIRCUIT_OPEN_MS)
    if not isinstance(open_ms, int) or isinstance(open_ms, bool) or not TIMEOUT_RANGE[0] <= open_ms <= TIMEOUT_RANGE[1]:
        refuse("config.circuit", "circuit_open_ms must be an integer in %d..%d milliseconds" % TIMEOUT_RANGE, key="circuit_open_ms")
    timeouts["circuit_open_ms"] = open_ms
    log_failure = doc.get("log_failure", "exit")
    if log_failure not in ("exit", "continue"):
        refuse("config.log", 'log_failure must be "exit" (stop when the access log cannot be written) or "continue" (docs/observability.md section 3)', key="log_failure")
    timeouts["log_failure_exit"] = 1 if log_failure == "exit" else 0
    admin = doc.get("admin_listen", 0)
    if not isinstance(admin, int) or isinstance(admin, bool) or not 0 <= admin <= 65535:
        refuse("config.admin", "admin_listen must be a port in 1..65535, or 0 for no admin listener (docs/observability.md section 7)", key="admin_listen")
    if admin != 0 and admin == listen:
        refuse("config.admin", "admin_listen must differ from listen: the proxy's port is the public one", key="admin_listen")
    timeouts["admin_port"] = admin
    tls = None
    tls_keys = [k for k in ("tls_listen", "tls_dir", "tls_identities", "tls_handshakes", "tls_rate", "tls_handshake_ms") if k in doc]
    if tls_keys and "tls_listen" not in doc:
        refuse("config.tls", "%s needs tls_listen (the port TLS is served on)" % tls_keys[0], key=tls_keys[0])
    if "tls_listen" in doc:
        port = doc["tls_listen"]
        if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
            refuse("config.tls", "tls_listen must be a port in 1..65535", key="tls_listen")
        if port == listen or port == admin:
            refuse("config.tls", "tls_listen must differ from listen and admin_listen", key="tls_listen")
        d = doc.get("tls_dir")
        if d is None:
            refuse("config.tls", "tls_listen needs tls_dir: the absolute directory the certificates are read from, compiled into the binary (docs/tls.md section 3)", key="tls_dir")
        if (not isinstance(d, str) or not re.fullmatch(r"/[A-Za-z0-9._/-]*[A-Za-z0-9._-]", d) or "//" in d or ".." in d.split("/") or len(d) > 200):
            refuse("config.tls", "tls_dir must be an absolute path of letters, digits and . _ - / (at most 200 bytes), with no .. component and no trailing /", key="tls_dir")
        if d == ENTROPY_FILE or d.startswith(ENTROPY_FILE + "/") or ENTROPY_FILE.startswith(d + "/"):
            refuse("config.tls", "tls_dir must be unrelated to %s: the program reads exactly those two paths and the compiler refuses nested ones" % ENTROPY_FILE, key="tls_dir")
        ids = doc.get("tls_identities", [""])
        if "tls_identities" in doc and (not isinstance(ids, list) or not 1 <= len(ids) <= MAX_IDENTITIES or len(set(ids)) != len(ids) or
                not all(isinstance(i, str) and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", i) for i in ids)):
            refuse("config.tls", "tls_identities must be 1 to %d distinct subdirectory names of tls_dir (letters, digits, . _ -; the first is the default for a name no identity has)" % MAX_IDENTITIES, key="tls_identities")
        tls = {"port": port, "dir": d, "identities": ids}
        for key, name, default, bounds in (("tls_handshakes", "handshakes", TLS_HANDSHAKES, TLS_HANDSHAKES_RANGE), ("tls_rate", "rate", TLS_RATE, TLS_RATE_RANGE),
                                           ("tls_handshake_ms", "handshake_ms", TLS_HANDSHAKE_MS, TIMEOUT_RANGE)):
            v = doc.get(key, default)
            if not isinstance(v, int) or isinstance(v, bool) or not bounds[0] <= v <= bounds[1]:
                refuse("config.tls", "%s must be an integer in %d..%d" % ((key,) + bounds), key=key)
            tls[name] = v
    timeouts["tls"] = tls
    if listen == 0 and tls is None:
        refuse("config.listeners", "a deployment needs a listener: set listen (plain HTTP), tls_listen (HTTPS), or both (docs/tls.md section 11)", key="listen")
    if not timeouts["header_timeout_ms"] <= timeouts["total_timeout_ms"] or not timeouts["connect_timeout_ms"] <= timeouts["total_timeout_ms"]:
        refuse("config.timeout", "total_timeout_ms must be at least the header and connect timeouts", key="total_timeout_ms")
    ups = doc.get("upstream", [])
    if not ups:
        raise Refusal("config.upstream", "at least one [[upstream]] is required", line=1)
    if len(ups) > MAX_UPSTREAMS:
        refuse("config.count", "%d upstreams; the bound is %d" % (len(ups), MAX_UPSTREAMS), "upstream", MAX_UPSTREAMS)
    names, addrs = {}, []
    for i, u in enumerate(ups):
        unknown_keys("upstream", i, u)
        name, addr = u.get("name"), u.get("addr")
        if not isinstance(name, str) or not re.fullmatch(r"[a-z][a-z0-9_-]{0,31}", name):
            refuse("config.upstream", "upstream name %r must match [a-z][a-z0-9_-]{0,31}" % (name,), "upstream", i, "name")
        if not isinstance(addr, str):
            refuse("config.upstream", "upstream %s has no addr" % name, "upstream", i)
        if host_port(addr) is None:
            refuse("config.upstream", "upstream address %r is not host:port with a port in 1..65535" % addr, "upstream", i, "addr")
        if name in names:
            refuse("config.duplicate", "upstream name %s is listed twice" % name, "upstream", i, "name")
        if addr in addrs:
            refuse("config.duplicate", "upstream address %s is listed twice" % addr, "upstream", i, "addr")
        names[name] = i
        addrs.append(addr)
    keys_in = doc.get("api_key", [])
    if len(keys_in) > MAX_KEYS:
        refuse("config.auth", "%d [[api_key]]; the bound is %d (docs/auth.md section 4.1)" % (len(keys_in), MAX_KEYS), "api_key", MAX_KEYS)
    api_keys = []
    for i, kk in enumerate(keys_in):
        unknown_keys("api_key", i, kk)
        kname, digest = kk.get("name"), kk.get("sha256")
        if not isinstance(kname, str) or not KEY_NAME.fullmatch(kname):
            refuse("config.auth", "api_key name %r must match [a-z0-9][a-z0-9._-]{0,31} (it is written into the access log)" % (kname,), "api_key", i, "name")
        if any(kname == n for n, _ in api_keys):
            refuse("config.auth", "api_key name %s is listed twice" % kname, "api_key", i, "name")
        if not isinstance(digest, str) or not KEY_DIGEST.fullmatch(digest):
            refuse("config.auth", "api_key %s: sha256 must be exactly 64 lowercase hexadecimal digits: the SHA-256 of the key (scripts/mkkey.py makes both)" % kname, "api_key", i, "sha256")
        if any(digest == d for _, d in api_keys):
            refuse("config.auth", "api_key %s has the same sha256 as another key: one credential cannot be two identities" % kname, "api_key", i, "sha256")
        api_keys.append((kname, digest))
    key_names = [n for n, _ in api_keys]
    routes_in = doc.get("route", [])
    if len(routes_in) > MAX_ROUTES:
        refuse("config.routes", "%d routes; the bound is %d" % (len(routes_in), MAX_ROUTES), "route", MAX_ROUTES)
    routes = []
    for i, r in enumerate(routes_in):
        unknown_keys("route", i, r)
        host = r.get("host")
        if host is not None and (not isinstance(host, str) or not re.fullmatch(r"[a-z0-9][a-z0-9.-]*", host) or len(host) > MAX_HOST):
            refuse("config.route", "host must be a lowercase DNS name (no port, no wildcard); omit it to match any host",
                   "route", i, "host")
        prefix = r.get("path_prefix")
        if not isinstance(prefix, str) or not valid_prefix(prefix):
            refuse("config.route", "path_prefix must start with '/', have no trailing '/' (except \"/\"), no '//', no '.' or '..' "
                   "segment, no '%%', no backslash or control byte, at most %d bytes" % MAX_PREFIX, "route", i, "path_prefix")
        methods = r.get("methods")
        if methods is not None:
            if not isinstance(methods, list) or not methods or any(m not in METHODS for m in methods) or len(set(methods)) != len(methods):
                refuse("config.route", "methods must be a non-empty list without repeats drawn from " + ", ".join(METHODS) +
                       "; omit it to allow all", "route", i, "methods")
        up = r.get("upstream")
        if up not in names:
            near = difflib.get_close_matches(str(up), list(names), n=1)
            refuse("config.route-upstream", "route refers to upstream %r, which is not declared" % (up,), "route", i, "upstream",
                   "did you mean %r?" % near[0] if near else "declared upstreams: " + ", ".join(names))
        body = r.get("max_body", DEFAULT_BODY)
        if not isinstance(body, int) or isinstance(body, bool) or not 0 <= body <= MAX_BODY:
            refuse("config.route", "max_body must be an integer in 0..%d" % MAX_BODY, "route", i, "max_body")
        label = r.get("name", "route%d" % i)
        if not isinstance(label, str) or not re.fullmatch(r"[a-z][a-z0-9_-]{0,31}", label):
            refuse("config.route", "route name %r must match [a-z][a-z0-9_-]{0,31} (it is written into the access log)" % (label,), "route", i, "name")
        trust = r.get("trust_forwarded", False)
        if not isinstance(trust, bool):
            refuse("config.route", "trust_forwarded must be true or false (docs/headers.md section 2)", "route", i, "trust_forwarded")
        mask = sum(1 << METHODS.index(m) for m in (methods or METHODS))
        ws = r.get("websocket", False)
        if not isinstance(ws, bool):
            refuse("config.websocket", "websocket must be true or false (docs/websocket.md section 3)", "route", i, "websocket")
        protocols, origins = r.get("subprotocols", []), r.get("origins", [])
        for key in ("subprotocols", "origins"):
            if key in r and not ws:
                refuse("config.websocket", "%s needs websocket = true on the same route" % key, "route", i, key)
        if ws and not mask & 1:
            refuse("config.websocket", "a websocket route must allow GET: an upgrade is a GET", "route", i, "methods")
        if not isinstance(protocols, list) or len(protocols) > MAX_SUBPROTOCOLS or len(set(map(str, protocols))) != len(protocols) or \
                not all(isinstance(t, str) and TOKEN.fullmatch(t) for t in protocols):
            refuse("config.websocket", "subprotocols must be at most %d distinct tokens of at most 64 bytes (letters, digits and !#$%%&'*+.^_`|~-)" % MAX_SUBPROTOCOLS,
                   "route", i, "subprotocols")
        if not isinstance(origins, list) or len(origins) > MAX_ORIGINS or len(set(map(str, origins))) != len(origins) or \
                not all(isinstance(o, str) and len(o) <= 200 and ORIGIN.fullmatch(o) for o in origins):
            refuse("config.websocket", "origins must be at most %d distinct strings of the form scheme://host[:port], lowercase, no path and no trailing slash" % MAX_ORIGINS,
                   "route", i, "origins")
        auth = auth_options(r, key_names, refuse, i)
        if auth["auth"] and not api_keys:
            refuse("config.auth", "auth needs at least one [[api_key]]: a route nobody can enter (docs/auth.md section 6)", "route", i, "auth")
        rate = rate_options(r, trust, bool(auth["auth"]), refuse, i)
        routes.append({"host": host, "prefix": prefix, "mask": mask, "upstream": names[up], "max_body": body,
                       "trust": 1 if trust else 0, "name": label, "ws": 1 if ws else 0, "protocols": protocols, "origins": origins, **rate, **auth})
    base = 0
    for j, r in enumerate(routes):
        r["base"] = base
        base += r["buckets"]
        if base > BUCKETS_TOTAL:
            refuse("config.ratelimit", "the routes' rate-limit tables add up to more than %d buckets (a route key counts one)" % BUCKETS_TOTAL, "route", j,
                   "rate_buckets" if "rate_buckets" in routes_in[j] else "rate_limit")
    timeouts["rate_total"] = base
    auth_routes = [j for j, r in enumerate(routes) if r["auth"]]
    if api_keys and not auth_routes:
        refuse("config.auth", "[[api_key]] and no route with auth: the digests would be in the binary and protect nothing", "api_key", 0)
    plain_ok = doc.get("auth_allow_plain", False)
    if not isinstance(plain_ok, bool):
        refuse("config.auth", "auth_allow_plain must be true or false (docs/auth.md section 7.3)", key="auth_allow_plain")
    if "auth_allow_plain" in doc and (not auth_routes or listen == 0):
        refuse("config.auth", "auth_allow_plain needs a plain listen and a route with auth", key="auth_allow_plain")
    if auth_routes and listen != 0 and not plain_ok:
        refuse("config.auth", "route %s has auth and the deployment has a plain listen: a key would cross the network in clear. Serve TLS (tls_listen) only, or set "
               "auth_allow_plain = true if the plain port is reachable only through a TLS-terminating front (docs/auth.md section 7.3)" % routes[auth_routes[0]]["name"],
               "route", auth_routes[0], "auth")
    timeouts["api_keys"] = api_keys
    timeouts["auth_plain"] = plain_ok
    ws_keys = [k for k in ("ws_idle_timeout_ms", "ws_max_lifetime_ms", "ws_max_tunnels") if k in doc]
    if ws_keys and not any(r["ws"] for r in routes):
        refuse("config.websocket", "%s needs a route with websocket = true" % ws_keys[0], key=ws_keys[0])
    wsopts = {}
    for key, name, default, bounds in (("ws_idle_timeout_ms", "idle_ms", WS_IDLE_MS, WS_IDLE_RANGE), ("ws_max_lifetime_ms", "lifetime_ms", WS_LIFETIME_MS, WS_LIFETIME_RANGE),
                                       ("ws_max_tunnels", "max_tunnels", WS_MAX_TUNNELS, WS_TUNNELS_RANGE)):
        v = doc.get(key, default)
        if not isinstance(v, int) or isinstance(v, bool) or not bounds[0] <= v <= bounds[1]:
            refuse("config.websocket", "%s must be an integer in %d..%d" % ((key,) + bounds), key=key)
        wsopts[name] = v
    timeouts["ws"] = wsopts
    for j, b in enumerate(routes):
        for i, a in enumerate(routes[:j]):
            if a["host"] == b["host"] and a["prefix"] == b["prefix"] and a["mask"] & b["mask"]:
                refuse("config.route-conflict", "routes %d and %d answer the same host, path_prefix and method: a tie is a "
                       "configuration error" % (i, j), "route", j, "path_prefix",
                       "give them different prefixes or hosts, or disjoint methods")
    return listen, [(u["name"], u["addr"]) for u in ups], routes, timeouts


def literal(text):
    return '"' + text.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n").replace("\t", "\\t") + '"'


def tls_identity_lines(tls):
    lines = []
    for n, name in enumerate(tls["identities"] if tls else []):
        lines += ["    if i == %d {" % n, "        return %s;" % literal(name), "    }"]
    return lines + ['    return "";']


def render_tlsfiles(tls):
    """The one module that holds the program's whole filesystem authority, written as data (docs/tls.md section 3, item 7)."""
    head = ["edition 6;", "", "module gateway.tlsfiles;", "",
            "// Generated by scripts/generate.py from a deployment file -- do not edit (docs/tls.md).", ""]
    if not tls:
        return "\n".join(head + [
            "// No `tls_listen`: this deployment reads no file, and the authority report says so. The capability is released unread.",
            "pub fn open_files[&e](fs: Fs(\"\"), entropy: &!e [byte]) -> [] DirOpened {", "    release(fs);", "    return DirOpened::Failed(2);", "}", ""])
    d = literal(tls["dir"])
    return "\n".join(head + [
        "// The whole of the filesystem this program touches, written once: 32 bytes of entropy from %s and the directory the certificates are" % ENTROPY_FILE,
        "// in. `narrow` takes literals, so the report names exactly these two paths and not `fs_read(\"\")` (cancho #364). Answers the directory handle",
        "// (everything read afterwards is read through it), `DirOpened::Failed(0 - 1)` if the entropy could not be read, or `Failed(errno)` for the directory.",
        "pub fn open_files[&e](fs: Fs(\"\"), entropy: &!e [byte]) -> [] DirOpened {",
        "    let (urandom, certs) = narrow(fs, %s, %s);" % (literal(ENTROPY_FILE), d),
        "    var got = 0;",
        "    borrow urandom as &uf in {",
        "        got = fs_read(uf, %s, entropy);" % literal(ENTROPY_FILE),
        "    }",
        "    var opened = DirOpened::Failed(2);",
        "    borrow certs as &cf in {",
        "        match opened {",
        "            DirOpened::Ok(unused) => {",
        "                dir_close(unused);",
        "            }",
        "            DirOpened::Failed(unused) => {",
        "            }",
        "        }",
        "        opened = open_dir(cf, %s);" % d,
        "    }",
        "    release(urandom);",
        "    release(certs);",
        "    if got != 32 {",
        "        match opened {",
        "            DirOpened::Ok(unused) => {",
        "                dir_close(unused);",
        "            }",
        "            DirOpened::Failed(unused) => {",
        "            }",
        "        }",
        "        return DirOpened::Failed(0 - 1);",
        "    }",
        "    return opened;",
        "}", ""])


def render_deploy(listen, ups, timeouts):
    addrs = [a for _, a in ups]
    prefix = intended_prefix(addrs)
    lines = [
        "edition 5;", "", "module gateway.deploy;", "",
        "// Generated by scripts/generate.py from a deployment file -- do not edit (docs/design.md section 2).",
        "// The allowed upstreams are data compiled into the binary; the compiler's authority report cannot see",
        "// them (one Net, one bound shared by listen and connect: design section 2.1), so the gateway enforces",
        "// this list in code before every connect and `authority.toml` states the report is `net_out(\"\")`.", "",
        "// The plain listener's port, 0 if the deployment is TLS only (docs/tls.md section 11).",
        "pub fn listen_port() -> [] int {", "    return %d;" % listen, "}", "",
        "pub fn upstream_count() -> [] int {", "    return %d;" % len(ups), "}", "",
        "// Milliseconds: the head must arrive, the upstream must connect, the upstream must start answering, the whole request",
        "// must end (docs/proxy.md section 3).",
        "pub fn header_ms() -> [] int {", "    return %d;" % timeouts["header_timeout_ms"], "}", "",
        "pub fn connect_ms() -> [] int {", "    return %d;" % timeouts["connect_timeout_ms"], "}", "",
        "pub fn upstream_ms() -> [] int {", "    return %d;" % timeouts["upstream_timeout_ms"], "}", "",
        "pub fn total_ms() -> [] int {", "    return %d;" % timeouts["total_timeout_ms"], "}", "",
        "// How long an idle upstream connection is kept, and how many per upstream (0: no pooling; docs/pool.md).",
        "pub fn idle_ms() -> [] int {", "    return %d;" % timeouts["idle_timeout_ms"], "}", "",
        "pub fn pool_idle_max() -> [] int {", "    return %d;" % timeouts["pool_idle_max"], "}", "",
        "// The passive circuit: consecutive failures to one upstream that open it (0: never), and for how long (docs/health.md).",
        "pub fn circuit_threshold() -> [] int {", "    return %d;" % timeouts["circuit_threshold"], "}", "",
        "pub fn circuit_open_ms() -> [] int {", "    return %d;" % timeouts["circuit_open_ms"], "}", "",
        "// 1 if the gateway stops when its access log cannot be written, 0 if it carries on (docs/observability.md section 3).",
        "pub fn log_failure_exit() -> [] int {", "    return %d;" % timeouts["log_failure_exit"], "}", "",
        "// The admin listener's port (metrics, health; docs/observability.md section 7), 0 if there is none.",
        "pub fn admin_port() -> [] int {", "    return %d;" % timeouts["admin_port"], "}", "",
        "// TLS (docs/tls.md): the port, the handshake bounds, and the identities (subdirectories of the directory compiled into `gateway.tlsfiles`; an empty",
        "// name is the directory itself). Port 0: no TLS.",
        "pub fn tls_port() -> [] int {", "    return %d;" % (timeouts["tls"]["port"] if timeouts["tls"] else 0), "}", "",
        "pub fn tls_handshakes() -> [] int {", "    return %d;" % (timeouts["tls"]["handshakes"] if timeouts["tls"] else TLS_HANDSHAKES), "}", "",
        "pub fn tls_rate() -> [] int {", "    return %d;" % (timeouts["tls"]["rate"] if timeouts["tls"] else TLS_RATE), "}", "",
        "pub fn tls_handshake_ms() -> [] int {", "    return %d;" % (timeouts["tls"]["handshake_ms"] if timeouts["tls"] else TLS_HANDSHAKE_MS), "}", "",
        "pub fn tls_identity_count() -> [] int {", "    return %d;" % (len(timeouts["tls"]["identities"]) if timeouts["tls"] else 0), "}", "",
        "pub fn tls_identity(i: int) -> [] &static [byte] {"] + tls_identity_lines(timeouts["tls"]) + ["}", "",
        "// WebSocket (docs/websocket.md): a tunnel is closed after this long without a byte moving, or this long after it opened; at most this many",
        "// upgrades are in progress or open at once.",
        "pub fn ws_idle_ms() -> [] int {", "    return %d;" % timeouts["ws"]["idle_ms"], "}", "",
        "pub fn ws_lifetime_ms() -> [] int {", "    return %d;" % timeouts["ws"]["lifetime_ms"], "}", "",
        "pub fn ws_max_tunnels() -> [] int {", "    return %d;" % timeouts["ws"]["max_tunnels"], "}", "",
        "// The longest common prefix of the addresses, cut at a delimiter: what `narrow` would be given once",
        "// cancho has separate listen and connect bounds. Empty means no shared prefix.",
        "pub fn intended_egress_prefix() -> [] &static [byte] {", "    return %s;" % literal(prefix), "}", "",
        "// Upstream `i` (0-based), as host:port; the empty string past the end.",
        "pub fn upstream_addr(i: int) -> [] &static [byte] {",
    ]
    for i, (_, a) in enumerate(ups):
        lines += ["    if i == %d {" % i, "        return %s;" % literal(a), "    }"]
    lines += ['    return "";', "}", "", "pub fn upstream_name(i: int) -> [] &static [byte] {"]
    for i, (n, _) in enumerate(ups):
        lines += ["    if i == %d {" % i, "        return %s;" % literal(n), "    }"]
    lines += ['    return "";', "}", ""]
    return "\n".join(lines)


def table_blob(routes):
    """One line per route: host (or *), prefix, method bitmask, upstream index, max body, trust_forwarded (0 or 1), name, websocket (0 or 1), subprotocols
    (comma-separated), origins (comma-separated), then the rate limit (docs/ratelimit.md): tokens per period (0: none), the period in ms, the burst, the key
    (empty, `r`, `a`, `x:l`, `x:f` or `h:<lowercase name>`), the buckets, and where the route's buckets begin; then authentication (docs/auth.md): 1 if the route
    authenticates, the lowercase header it reads, 1 if it forwards the credential, the allowed key indices (`*` for all, else comma-separated), and the
    `WWW-Authenticate` challenge; tab-separated, in file order."""
    return "".join("%s\t%s\t%d\t%d\t%d\t%d\t%s\t%d\t%s\t%s\t%d\t%d\t%d\t%s\t%d\t%d\t%d\t%s\t%d\t%s\t%s\n" % (
        r["host"] or "*", r["prefix"], r["mask"], r["upstream"], r["max_body"], r["trust"], r["name"], r["ws"], ",".join(r["protocols"]), ",".join(r["origins"]),
        r["rate"], r["per_ms"], r["burst"], r["rate_key"], r["buckets"], r["base"],
        r["auth"], r["auth_header"], r["auth_forward"], r["auth_keys"], r["challenge"]) for r in routes)


def render_routes(routes, rate_total, api_keys):
    return "\n".join([
        "edition 5;", "", "module gateway.routes_table;", "",
        "// Generated by scripts/generate.py from a deployment file -- do not edit (docs/routes.md).",
        "// One line per route: host (`*` for any), path_prefix, method bitmask (GET 1, HEAD 2, POST 4, PUT 8, DELETE 16,",
        "// PATCH 32, OPTIONS 64), upstream index, max body, trust_forwarded (0 or 1), name, websocket (0 or 1), subprotocols and origins (comma-separated, possibly",
        "// empty; docs/websocket.md), then the rate limit (docs/ratelimit.md): tokens per period (0: none), the period in ms, the burst, the key, the buckets, and the",
        "// first bucket of the route's table, then authentication (docs/auth.md): 1 if the route authenticates, the header it reads, 1 if it forwards the credential, the",
        "// allowed key indices (`*`: all) and the WWW-Authenticate challenge. Tab-separated, in file order; `gateway.route` reads it.", "",
        "pub fn count() -> [] int {", "    return %d;" % len(routes), "}", "",
        "// The buckets of every route's rate-limit table, added up (docs/ratelimit.md section 6): what the table is sized to.",
        "pub fn rate_buckets_total() -> [] int {", "    return %d;" % rate_total, "}", "",
        "// The API keys (docs/auth.md section 4.1): one line per key, `name<TAB>sha256 as 64 lowercase hex digits`, in file order. Digests only: the binary holds no key.",
        "pub fn key_count() -> [] int {", "    return %d;" % len(api_keys), "}", "",
        "pub fn keys_blob() -> [] &static [byte] {", "    return %s;" % literal("".join("%s\t%s\n" % k for k in api_keys)), "}", "",
        "pub fn blob() -> [] &static [byte] {", "    return %s;" % literal(table_blob(routes)), "}", ""])


def main():
    args, flags, out_dir = [], set(), None
    argv = sys.argv[1:]
    i = 0
    while i < len(argv):
        if argv[i] == "--out" and i + 1 < len(argv):
            out_dir = pathlib.Path(argv[i + 1])
            i += 1
        elif argv[i].startswith("--"):
            flags.add(argv[i])
        else:
            args.append(argv[i])
        i += 1
    if len(args) != 1:
        print("usage: generate.py DEPLOYMENT.toml [--check|--explain|--out DIR]", file=sys.stderr)
        return 2
    try:
        listen, ups, routes, timeouts = load(args[0])
    except Refusal as r:
        print(json.dumps({"file": args[0], "hint": r.hint, "key": r.key, "line": r.line, "message": str(r), "rule": r.rule},
                         sort_keys=True), file=sys.stderr)
        return 2
    outputs = {"deploy.cho": render_deploy(listen, ups, timeouts), "routes.cho": render_routes(routes, timeouts["rate_total"], timeouts["api_keys"]), "tlsfiles.cho": render_tlsfiles(timeouts["tls"])}
    if "--explain" in flags:
        prefix = intended_prefix([a for _, a in ups])
        print("listen %s; %d upstream(s): %s" % (listen or "none (TLS only)", len(ups), ", ".join(a for _, a in ups)))
        print("timeouts (ms): " + ", ".join("%s %d" % (k.replace("_timeout_ms", ""), v) for k, v in timeouts.items() if k.endswith("_ms")) +
              "; idle connections kept per upstream: %d; circuit: %d failures, open %d ms" % (timeouts["pool_idle_max"], timeouts["circuit_threshold"], timeouts["circuit_open_ms"]))
        if timeouts["tls"]:
            t = timeouts["tls"]
            print("tls on port %d: certificates beneath %s (identities: %s); reads exactly %s and that directory; %d handshakes at once, %d a second, %d ms each" % (
                t["port"], t["dir"], ", ".join(i or "(the directory itself)" for i in t["identities"]), ENTROPY_FILE, t["handshakes"], t["rate"], t["handshake_ms"]))
        if any(r["ws"] for r in routes):
            w = timeouts["ws"]
            print("websocket: tunnels close after %d ms idle or %d ms; at most %d at once" % (w["idle_ms"], w["lifetime_ms"], w["max_tunnels"]))
        print("intended egress prefix: %s" % (repr(prefix) if prefix else "none (no shared prefix)"))
        for n, r in enumerate(routes):
            print("route %d: %s %s -> %s (max body %d%s)" % (n, r["host"] or "*", r["prefix"], ups[r["upstream"]][0], r["max_body"], ", trusts forwarding headers" if r["trust"] else "") +
                  ("; websocket, subprotocols %s, origins %s" % (r["protocols"] or "none", r["origins"] or "none") if r["ws"] else "") +
                  ("; limit %d per %d ms, burst %d, key %s, %d bucket(s)" % (r["rate"], r["per_ms"], r["burst"], r["rate_key"], r["buckets"]) if r["rate"] else "") +
                  ("; authenticates with the %s header, keys %s%s" % (r["auth_header"], r["auth_keys"] if r["auth_keys"] != "*" else "all", ", forwards the credential" if r["auth_forward"] else "") if r["auth"] else ""))
        if timeouts["api_keys"]:
            print("api keys: %s (digests only compiled in)%s" % (", ".join(n for n, _ in timeouts["api_keys"]), "; the plain listener is allowed (auth_allow_plain): keys are protected by a front" if timeouts["auth_plain"] else ""))
        return 0
    target = out_dir or ROOT / "generated"
    if "--check" in flags:
        stale = [n for n, t in outputs.items() if not (target / n).exists() or (target / n).read_text() != t]
        for n in stale:
            print("FAIL %s is stale: run scripts/generate.py %s" % ((target / n).relative_to(ROOT), args[0]))
        return 1 if stale else 0
    target.mkdir(parents=True, exist_ok=True)
    for n, t in outputs.items():
        (target / n).write_text(t)
    return 0


if __name__ == "__main__":
    sys.exit(main())
