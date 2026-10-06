#!/usr/bin/env python3
"""The deployment generator (tasks #11 and #4, docs/design.md section 2, docs/routes.md).

    python3 scripts/generate.py deploy/example.toml            # write generated/deploy.ls and generated/routes.ls
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
TIMEOUT_RANGE = (100, 600000)
DEFAULT_BODY = 1 << 20
METHODS = ["GET", "HEAD", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"]
KEYS = {
    "": ["listen", "header_timeout_ms", "connect_timeout_ms", "upstream_timeout_ms", "total_timeout_ms", "idle_timeout_ms", "pool_idle_max"],
    "upstream": ["name", "addr"],
    "route": ["name", "host", "path_prefix", "methods", "upstream", "max_body"],
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
        mask = sum(1 << METHODS.index(m) for m in (methods or METHODS))
        routes.append({"host": host, "prefix": prefix, "mask": mask, "upstream": names[up], "max_body": body,
                       "name": r.get("name", "route%d" % i)})
    for j, b in enumerate(routes):
        for i, a in enumerate(routes[:j]):
            if a["host"] == b["host"] and a["prefix"] == b["prefix"] and a["mask"] & b["mask"]:
                refuse("config.route-conflict", "routes %d and %d answer the same host, path_prefix and method: a tie is a "
                       "configuration error" % (i, j), "route", j, "path_prefix",
                       "give them different prefixes or hosts, or disjoint methods")
    return listen, [(u["name"], u["addr"]) for u in ups], routes, timeouts


def literal(text):
    return '"' + text.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n").replace("\t", "\\t") + '"'


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
        "// The longest common prefix of the addresses, cut at a delimiter: what `narrow` would be given once",
        "// lex-sys has separate listen and connect bounds. Empty means no shared prefix.",
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
    """One line per route: host (or *), prefix, method bitmask, upstream index, max body; tab-separated, in file order."""
    return "".join("%s\t%s\t%d\t%d\t%d\n" % (r["host"] or "*", r["prefix"], r["mask"], r["upstream"], r["max_body"]) for r in routes)


def render_routes(routes):
    return "\n".join([
        "edition 5;", "", "module gateway.routes_table;", "",
        "// Generated by scripts/generate.py from a deployment file -- do not edit (docs/routes.md).",
        "// One line per route: host (`*` for any), path_prefix, method bitmask (GET 1, HEAD 2, POST 4, PUT 8, DELETE 16,",
        "// PATCH 32, OPTIONS 64), upstream index, max body. Tab-separated, in file order; `gateway.route` reads it.", "",
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
    outputs = {"deploy.ls": render_deploy(listen, ups, timeouts), "routes.ls": render_routes(routes)}
    if "--explain" in flags:
        prefix = intended_prefix([a for _, a in ups])
        print("listen %d; %d upstream(s): %s" % (listen, len(ups), ", ".join(a for _, a in ups)))
        print("timeouts (ms): " + ", ".join("%s %d" % (k.replace("_timeout_ms", ""), v) for k, v in timeouts.items() if k.endswith("_ms")) +
              "; idle connections kept per upstream: %d" % timeouts["pool_idle_max"])
        print("intended egress prefix: %s" % (repr(prefix) if prefix else "none (no shared prefix)"))
        for n, r in enumerate(routes):
            print("route %d: %s %s -> %s (max body %d)" % (n, r["host"] or "*", r["prefix"], ups[r["upstream"]][0], r["max_body"]))
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
