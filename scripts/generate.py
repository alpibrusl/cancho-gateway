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
TLS_RATE, TLS_RATE_RANGE = 100, (1, 100000)
TLS_HANDSHAKE_MS = 10000
MAX_IDENTITIES = 16
ENTROPY_FILE = "/dev/urandom"
METHODS = ["GET", "HEAD", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"]
KEYS = {
    "": ["listen", "header_timeout_ms", "connect_timeout_ms", "upstream_timeout_ms", "total_timeout_ms", "idle_timeout_ms", "pool_idle_max", "circuit_threshold", "circuit_open_ms", "log_failure", "admin_listen",
           "tls_listen", "tls_dir", "tls_identities", "tls_handshakes", "tls_rate", "tls_handshake_ms"],
    "upstream": ["name", "addr"],
    "route": ["name", "host", "path_prefix", "methods", "upstream", "max_body", "trust_forwarded"],
}


class Refusal(Exception):
    def __init__(self, rule, message, line=None, key=None, hint=None):
        super().__init__(message)
        self.rule, self.line, self.key, self.hint = rule, line, key, hint


def scan(text):
    """Where each key is: {(section, index, key): line}, and where each table starts: {(section, index): line}."""
    keys, starts = {}, {}
    section, index = "", 0
    counts = {"upstream": 0, "route": 0}
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
        if k not in KEYS[""] and k not in ("upstream", "route"):
            near = difflib.get_close_matches(k, KEYS[""] + ["upstream", "route"], n=1)
            raise Refusal("config.unknown-key", "unknown key or table %r" % k, line=keys.get(("", 0, k), 1), key=k,
                          hint="did you mean %r?" % near[0] if near else None)
    unknown_keys("", 0, {k: v for k, v in doc.items() if k not in ("upstream", "route")})
    listen = doc.get("listen")
    if not isinstance(listen, int) or isinstance(listen, bool) or not 1 <= listen <= 65535:
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
    if admin == listen:
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
        routes.append({"host": host, "prefix": prefix, "mask": mask, "upstream": names[up], "max_body": body,
                       "trust": 1 if trust else 0, "name": label})
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
    """One line per route: host (or *), prefix, method bitmask, upstream index, max body, trust_forwarded (0 or 1), name; tab-separated, in file order."""
    return "".join("%s\t%s\t%d\t%d\t%d\t%d\t%s\n" % (r["host"] or "*", r["prefix"], r["mask"], r["upstream"], r["max_body"], r["trust"], r["name"]) for r in routes)


def render_routes(routes):
    return "\n".join([
        "edition 5;", "", "module gateway.routes_table;", "",
        "// Generated by scripts/generate.py from a deployment file -- do not edit (docs/routes.md).",
        "// One line per route: host (`*` for any), path_prefix, method bitmask (GET 1, HEAD 2, POST 4, PUT 8, DELETE 16,",
        "// PATCH 32, OPTIONS 64), upstream index, max body, trust_forwarded (0 or 1), name. Tab-separated, in file order; `gateway.route` reads it.", "",
        "pub fn count() -> [] int {", "    return %d;" % len(routes), "}", "",
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
    outputs = {"deploy.cho": render_deploy(listen, ups, timeouts), "routes.cho": render_routes(routes), "tlsfiles.cho": render_tlsfiles(timeouts["tls"])}
    if "--explain" in flags:
        prefix = intended_prefix([a for _, a in ups])
        print("listen %d; %d upstream(s): %s" % (listen, len(ups), ", ".join(a for _, a in ups)))
        print("timeouts (ms): " + ", ".join("%s %d" % (k.replace("_timeout_ms", ""), v) for k, v in timeouts.items() if k.endswith("_ms")) +
              "; idle connections kept per upstream: %d; circuit: %d failures, open %d ms" % (timeouts["pool_idle_max"], timeouts["circuit_threshold"], timeouts["circuit_open_ms"]))
        if timeouts["tls"]:
            t = timeouts["tls"]
            print("tls on port %d: certificates beneath %s (identities: %s); reads exactly %s and that directory; %d handshakes at once, %d a second, %d ms each" % (
                t["port"], t["dir"], ", ".join(i or "(the directory itself)" for i in t["identities"]), ENTROPY_FILE, t["handshakes"], t["rate"], t["handshake_ms"]))
        print("intended egress prefix: %s" % (repr(prefix) if prefix else "none (no shared prefix)"))
        for n, r in enumerate(routes):
            print("route %d: %s %s -> %s (max body %d%s)" % (n, r["host"] or "*", r["prefix"], ups[r["upstream"]][0], r["max_body"], ", trusts forwarding headers" if r["trust"] else ""))
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
